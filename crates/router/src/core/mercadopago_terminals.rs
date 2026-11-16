//! Terminal setup for Mercado Pago Point (in-person card terminal).
//!
//! The seller's access token is only held here, so the terminals are listed and switched to
//! integrated mode with direct HTTP calls (no connector flow), through the same seller client
//! as the QR store and POS setup. The chosen terminal is saved in the connector account
//! metadata, where the connector reads the `terminal_id` of every Point order.

use std::collections::HashSet;

use api_models::mercadopago_terminals::{
    MercadopagoTerminalListResponse, MercadopagoTerminalSetupRequest,
    MercadopagoTerminalSetupResponse, MercadopagoTerminalSummary,
};
use common_utils::{id_type, request::Method};
use error_stack::{report, ResultExt};
use hyperswitch_connectors::connectors::mercadopago::orders::{
    MercadopagoPointTerminal, POINT_OPERATING_MODE_PDV, POINT_TERMINAL_METADATA_KEY,
};
use hyperswitch_domain_models::merchant_connector_account::MerchantConnectorAccountUpdate;
use hyperswitch_masking::{ExposeInterface, Secret};
use router_env::logger;
use serde_json::Value;
use storage_impl::behaviour::ForeignInto;

use crate::{
    core::{
        errors::{self, RouterResponse, RouterResult},
        mercadopago_pos::{
            id_to_string, load_account, merge_key_into_metadata, MpClient, MpFailure,
        },
    },
    routes::SessionState,
    services::ApplicationResponse,
};

const TERMINALS_LIST_PATH: &str = "/terminals/v1/list";
const TERMINALS_SETUP_PATH: &str = "/terminals/v1/setup";
/// Terminals per page of the list: the most Mercado Pago returns in one.
const TERMINALS_PAGE_SIZE: usize = 50;
/// Pages read at most (1000 terminals), so a seller with an endless list cannot hold a request.
const TERMINALS_MAX_PAGES: usize = 20;

// ============================================================================
// Pure logic
// ============================================================================

/// The terminal saved in the account metadata, if any.
pub(crate) fn saved_terminal(metadata: Option<&Value>) -> Option<MercadopagoPointTerminal> {
    metadata
        .and_then(|metadata| metadata.get(POINT_TERMINAL_METADATA_KEY))
        .and_then(|terminal| {
            serde_json::from_value::<MercadopagoPointTerminal>(terminal.clone()).ok()
        })
        .filter(|terminal| !terminal.terminal_id.is_empty())
}

/// The terminals of `GET /terminals/v1/list` (`data.terminals`); an entry without an id is
/// skipped. `selected_terminal_id` marks the one saved for the connector account.
pub(crate) fn parse_terminals(
    body: &Value,
    selected_terminal_id: Option<&str>,
) -> Vec<MercadopagoTerminalSummary> {
    let text = |value: Option<&Value>| {
        value
            .and_then(Value::as_str)
            .filter(|text| !text.is_empty())
            .map(str::to_string)
    };
    body.get("data")
        .and_then(|data| data.get("terminals"))
        .and_then(Value::as_array)
        .map(|terminals| {
            terminals
                .iter()
                .filter_map(|terminal| {
                    let terminal_id = terminal.get("id").and_then(id_to_string)?;
                    Some(MercadopagoTerminalSummary {
                        selected: selected_terminal_id == Some(terminal_id.as_str()),
                        terminal_id,
                        pos_id: terminal.get("pos_id").and_then(id_to_string),
                        store_id: terminal.get("store_id").and_then(id_to_string),
                        external_pos_id: text(terminal.get("external_pos_id")),
                        operating_mode: text(terminal.get("operating_mode")),
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

/// The path of one page of the list, starting at `offset`.
pub(crate) fn terminals_page_path(offset: usize) -> String {
    format!("{TERMINALS_LIST_PATH}?limit={TERMINALS_PAGE_SIZE}&offset={offset}")
}

/// How many entries a page of the list has, listed or not.
fn page_len(page: &Value) -> usize {
    page.get("data")
        .and_then(|data| data.get("terminals"))
        .and_then(Value::as_array)
        .map_or(0, Vec::len)
}

/// `paging.total`: how many terminals the seller has in all.
fn paging_total(page: &Value) -> Option<usize> {
    page.get("paging")
        .and_then(|paging| paging.get("total"))
        .and_then(Value::as_u64)
        .and_then(|total| usize::try_from(total).ok())
}

/// The terminals of a seller, read page by page.
#[derive(Debug, PartialEq)]
pub(crate) struct ListedTerminals {
    pub(crate) terminals: Vec<MercadopagoTerminalSummary>,
    /// `false` when the list was cut before its end: a terminal that is missing from it may
    /// still belong to the seller.
    pub(crate) complete: bool,
}

/// The id as it is compared and sent: trimmed, and never blank.
pub(crate) fn normalize_terminal_id(terminal_id: &str) -> Result<String, errors::ApiErrorResponse> {
    match terminal_id.trim() {
        "" => Err(errors::ApiErrorResponse::MissingRequiredField {
            field_name: "terminal_id".into(),
        }),
        id => Ok(id.to_string()),
    }
}

/// The seller's terminal with this id. One Mercado Pago does not list for the seller is
/// reported as not found, before anything is switched or saved.
pub(crate) fn find_terminal<'a>(
    terminals: &'a [MercadopagoTerminalSummary],
    terminal_id: &str,
) -> Result<&'a MercadopagoTerminalSummary, MpFailure> {
    terminals
        .iter()
        .find(|terminal| terminal.terminal_id == terminal_id)
        .ok_or_else(|| MpFailure {
            status: 404,
            code: "terminal_not_found".to_string(),
            message: "The terminal does not belong to this Mercado Pago account".to_string(),
            reason: None,
        })
}

/// The seller's terminal with this id among the ones that were read. When the list was cut,
/// a missing terminal is reported as such instead of as someone else's.
pub(crate) fn find_listed_terminal<'a>(
    listed: &'a ListedTerminals,
    terminal_id: &str,
) -> Result<&'a MercadopagoTerminalSummary, MpFailure> {
    find_terminal(&listed.terminals, terminal_id).map_err(|not_found| {
        if listed.complete {
            not_found
        } else {
            MpFailure {
                status: 404,
                code: "terminal_list_incomplete".to_string(),
                message: format!(
                    "The terminal is not among the first {} terminals Mercado Pago lists for \
                     this account",
                    listed.terminals.len()
                ),
                reason: None,
            }
        }
    })
}

/// `PATCH /terminals/v1/setup` body that switches one terminal to integrated mode.
pub(crate) fn integrated_mode_body(terminal_id: &str) -> Value {
    serde_json::json!({
        "terminals": [{ "id": terminal_id, "operating_mode": POINT_OPERATING_MODE_PDV }]
    })
}

/// Whether the device still has to be restarted. Mercado Pago answers the switch at once but
/// keeps listing the previous mode until the device restarts, so a terminal already listed
/// in integrated mode has nothing pending.
pub(crate) fn restart_required(listed_operating_mode: Option<&str>) -> bool {
    listed_operating_mode != Some(POINT_OPERATING_MODE_PDV)
}

/// Adds the terminal under one key and keeps every other key of the metadata (the QR POS
/// among them).
pub(crate) fn merge_terminal_into_metadata(
    existing: Option<Value>,
    terminal: &MercadopagoPointTerminal,
) -> Result<Value, errors::ApiErrorResponse> {
    merge_key_into_metadata(
        existing,
        POINT_TERMINAL_METADATA_KEY,
        serde_json::to_value(terminal)
            .map_err(|_| errors::ApiErrorResponse::InternalServerError)?,
    )
}

// ============================================================================
// Core
// ============================================================================

/// The Mercado Pago calls of the terminal setup, made as the seller.
#[async_trait::async_trait]
pub(crate) trait TerminalsApi {
    /// One page of `GET /terminals/v1/list`, starting at `offset`.
    async fn terminals_page(&self, offset: usize) -> RouterResult<Value>;

    /// `PATCH /terminals/v1/setup`: switches the terminal to integrated mode.
    async fn switch_to_integrated_mode(&self, terminal_id: &str) -> RouterResult<()>;
}

#[async_trait::async_trait]
impl TerminalsApi for MpClient<'_> {
    async fn terminals_page(&self, offset: usize) -> RouterResult<Value> {
        Self::success_or_failure(
            self.call(Method::Get, &terminals_page_path(offset), None, None)
                .await?,
        )
    }

    async fn switch_to_integrated_mode(&self, terminal_id: &str) -> RouterResult<()> {
        Self::success_or_failure(
            self.call(
                Method::Patch,
                TERMINALS_SETUP_PATH,
                None,
                Some(integrated_mode_body(terminal_id)),
            )
            .await?,
        )
        .map(|_| ())
    }
}

/// Every terminal of the seller: the list is read page by page until `paging.total` is
/// reached (or, when Mercado Pago sends no total, until a page comes short). A page that
/// fails fails the whole list: a partial one would hide terminals. The list is cut, and says
/// so, after `TERMINALS_MAX_PAGES` pages or when a page brings nothing new.
pub(crate) async fn list_all_terminals<A>(
    api: &A,
    selected_terminal_id: Option<&str>,
) -> RouterResult<ListedTerminals>
where
    A: TerminalsApi + Sync,
{
    let mut terminals: Vec<MercadopagoTerminalSummary> = Vec::new();
    let mut seen = HashSet::new();
    let mut offset = 0;
    for _ in 0..TERMINALS_MAX_PAGES {
        let page = api.terminals_page(offset).await?;
        let entries = page_len(&page);
        let listed_before = terminals.len();
        terminals.extend(
            parse_terminals(&page, selected_terminal_id)
                .into_iter()
                .filter(|terminal| seen.insert(terminal.terminal_id.clone())),
        );
        offset += entries;

        let is_last_page = match paging_total(&page) {
            Some(total) => offset >= total,
            None => entries < TERMINALS_PAGE_SIZE,
        };
        if entries == 0 || is_last_page {
            return Ok(ListedTerminals {
                terminals,
                complete: true,
            });
        }
        // The same terminals again: the offset is not being honoured, so asking for more
        // pages would only repeat them.
        if terminals.len() == listed_before {
            break;
        }
    }
    logger::warn!(
        listed = terminals.len(),
        "The Mercado Pago terminal list was cut before its end"
    );
    Ok(ListedTerminals {
        terminals,
        complete: false,
    })
}

/// What choosing a terminal leaves to save, once Mercado Pago accepted the switch.
#[derive(Debug)]
pub(crate) struct TerminalSetup {
    pub(crate) terminal: MercadopagoPointTerminal,
    /// The whole metadata of the connector account, with only the terminal changed.
    pub(crate) metadata: Value,
    pub(crate) restart_required: bool,
}

/// Chooses a terminal for a connector account: checks it is one of the seller's, switches it
/// to integrated mode and returns the metadata to save. Nothing is switched for a terminal
/// the seller does not have, and nothing is returned (so nothing is saved) unless Mercado
/// Pago accepted the switch.
pub(crate) async fn choose_terminal<A>(
    api: &A,
    terminal_id: &str,
    current_metadata: Option<Value>,
) -> RouterResult<TerminalSetup>
where
    A: TerminalsApi + Sync,
{
    // Only a terminal Mercado Pago lists for this seller can be chosen.
    let listed = list_all_terminals(api, None).await?;
    let needs_restart = find_listed_terminal(&listed, terminal_id)
        .map(|terminal| restart_required(terminal.operating_mode.as_deref()))
        .map_err(|failure| report!(failure.into_api_error()))?;

    // Switching a terminal that is already integrated changes nothing at Mercado Pago, so a
    // repeated call is safe.
    api.switch_to_integrated_mode(terminal_id).await?;

    let terminal = MercadopagoPointTerminal {
        terminal_id: terminal_id.to_string(),
        operating_mode: POINT_OPERATING_MODE_PDV.to_string(),
    };
    let metadata = merge_terminal_into_metadata(current_metadata, &terminal)?;
    Ok(TerminalSetup {
        terminal,
        metadata,
        restart_required: needs_restart,
    })
}

pub async fn list_mercadopago_terminals(
    state: SessionState,
    merchant_id: &id_type::MerchantId,
    profile_id: Option<id_type::ProfileId>,
    merchant_connector_id: &id_type::MerchantConnectorAccountId,
) -> RouterResponse<MercadopagoTerminalListResponse> {
    let (_, mca, token) =
        load_account(&state, merchant_id, profile_id, merchant_connector_id).await?;
    let client = MpClient {
        state: &state,
        base_url: state.conf.connectors.mercadopago.base_url.as_ref(),
        token,
    };
    let metadata = mca.get_metadata().map(ExposeInterface::expose);
    let selected_terminal_id =
        saved_terminal(metadata.as_ref()).map(|terminal| terminal.terminal_id);
    let listed = list_all_terminals(&client, selected_terminal_id.as_deref()).await?;

    Ok(ApplicationResponse::Json(MercadopagoTerminalListResponse {
        terminals: listed.terminals,
        selected_terminal_id,
    }))
}

/// The route holds a lock per connector account for this and for the QR POS setup (see
/// `mercadopago_pos::setup_lock`), so the metadata read here is the one that gets saved.
pub async fn setup_mercadopago_terminal(
    state: SessionState,
    merchant_id: &id_type::MerchantId,
    profile_id: Option<id_type::ProfileId>,
    merchant_connector_id: &id_type::MerchantConnectorAccountId,
    req: MercadopagoTerminalSetupRequest,
) -> RouterResponse<MercadopagoTerminalSetupResponse> {
    let db = state.store.as_ref();
    let terminal_id = normalize_terminal_id(&req.terminal_id).map_err(|error| report!(error))?;
    let (key_store, mca, token) =
        load_account(&state, merchant_id, profile_id, merchant_connector_id).await?;

    let client = MpClient {
        state: &state,
        base_url: state.conf.connectors.mercadopago.base_url.as_ref(),
        token,
    };
    let setup = choose_terminal(
        &client,
        &terminal_id,
        mca.get_metadata().map(ExposeInterface::expose),
    )
    .await?;

    // Only the metadata changes: the encrypted credentials are never rewritten.
    db.update_merchant_connector_account(
        mca,
        MerchantConnectorAccountUpdate::ConnectorWebhookRegisterationUpdate {
            connector_webhook_registration_details: None,
            connector_webhook_details: None,
            metadata: Some(Secret::new(setup.metadata)),
        }
        .foreign_into(),
        &key_store,
    )
    .await
    .change_context(errors::ApiErrorResponse::InternalServerError)
    .attach_printable("Failed to save the Mercado Pago terminal in the connector account")?;

    Ok(ApplicationResponse::Json(
        MercadopagoTerminalSetupResponse {
            terminal_id: setup.terminal.terminal_id,
            operating_mode: setup.terminal.operating_mode,
            restart_required: setup.restart_required,
        },
    ))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    const TERMINAL_ID: &str = "NEWLAND_N950__N950NCD600391917";

    /// `GET /terminals/v1/list` of the real seller, plus a second device.
    fn terminals_body() -> Value {
        json!({
            "data": {"terminals": [
                {
                    "id": TERMINAL_ID,
                    "pos_id": 86743668,
                    "store_id": "57817122",
                    "external_pos_id": "PXSOLFIXPOS844680",
                    "operating_mode": "STANDALONE"
                },
                {
                    "id": "NEWLAND_N950__N950NCB000000002",
                    "pos_id": 86743669,
                    "store_id": "57817122",
                    "external_pos_id": "",
                    "operating_mode": "PDV"
                }
            ]},
            "paging": {"total": 2, "offset": 0, "limit": 50}
        })
    }

    fn terminal() -> MercadopagoPointTerminal {
        MercadopagoPointTerminal {
            terminal_id: TERMINAL_ID.to_string(),
            operating_mode: "PDV".to_string(),
        }
    }

    #[test]
    fn terminals_are_listed_with_the_selected_one_marked() {
        let terminals = parse_terminals(&terminals_body(), Some(TERMINAL_ID));
        assert_eq!(
            terminals,
            vec![
                MercadopagoTerminalSummary {
                    terminal_id: TERMINAL_ID.to_string(),
                    pos_id: Some("86743668".to_string()),
                    store_id: Some("57817122".to_string()),
                    external_pos_id: Some("PXSOLFIXPOS844680".to_string()),
                    operating_mode: Some("STANDALONE".to_string()),
                    selected: true,
                },
                MercadopagoTerminalSummary {
                    terminal_id: "NEWLAND_N950__N950NCB000000002".to_string(),
                    pos_id: Some("86743669".to_string()),
                    store_id: Some("57817122".to_string()),
                    external_pos_id: None,
                    operating_mode: Some("PDV".to_string()),
                    selected: false,
                },
            ]
        );

        // Nothing saved, or a saved terminal the seller no longer has: none is marked.
        for selected in [None, Some("NEWLAND_N950__GONE")] {
            assert!(parse_terminals(&terminals_body(), selected)
                .iter()
                .all(|terminal| !terminal.selected));
        }
    }

    #[test]
    fn an_empty_or_unexpected_terminal_list_lists_nothing() {
        for body in [
            // The sandbox seller: no devices.
            json!({"data": {"terminals": []}, "paging": {"total": 0, "offset": 0, "limit": 50}}),
            json!({"data": {}}),
            json!({"terminals": [{"id": TERMINAL_ID}]}),
            json!({"data": {"terminals": "none"}}),
            Value::Null,
        ] {
            assert!(
                parse_terminals(&body, Some(TERMINAL_ID)).is_empty(),
                "{body}"
            );
        }
        // An entry without an id cannot be chosen, so it is not listed.
        let body = json!({"data": {"terminals": [
            {"pos_id": 1, "operating_mode": "PDV"},
            {"id": "", "operating_mode": "PDV"},
            {"id": TERMINAL_ID}
        ]}});
        let terminals = parse_terminals(&body, None);
        assert_eq!(terminals.len(), 1);
        assert_eq!(terminals[0].terminal_id, TERMINAL_ID);
        assert_eq!(terminals[0].operating_mode, None);
        assert_eq!(terminals[0].pos_id, None);
    }

    #[test]
    fn list_response_exposes_only_mercado_pago_data() {
        let response = MercadopagoTerminalListResponse {
            terminals: parse_terminals(&terminals_body(), Some(TERMINAL_ID)),
            selected_terminal_id: Some(TERMINAL_ID.to_string()),
        };
        let body = serde_json::to_value(response).unwrap();
        assert_eq!(body["selected_terminal_id"], TERMINAL_ID);
        assert_eq!(
            body["terminals"][0],
            json!({
                "terminal_id": TERMINAL_ID,
                "pos_id": "86743668",
                "store_id": "57817122",
                "external_pos_id": "PXSOLFIXPOS844680",
                "operating_mode": "STANDALONE",
                "selected": true
            })
        );
    }

    #[test]
    fn only_a_terminal_of_the_seller_can_be_chosen() {
        let terminals = parse_terminals(&terminals_body(), None);
        assert_eq!(
            find_terminal(&terminals, TERMINAL_ID).unwrap().terminal_id,
            TERMINAL_ID
        );

        for other in [
            "NEWLAND_N950__SBX0000001",
            "newland_n950__n950ncd600391917",
            "",
        ] {
            let failure = find_terminal(&terminals, other).unwrap_err();
            assert_eq!(failure.status, 404);
            assert_eq!(failure.code, "terminal_not_found");
            assert!(matches!(
                failure.into_api_error(),
                errors::ApiErrorResponse::ExternalConnectorError {
                    status_code: 404,
                    ref code,
                    ref message,
                    ref connector,
                    ..
                } if code == "terminal_not_found"
                    && message == "The terminal does not belong to this Mercado Pago account"
                    && connector == "mercadopago"
            ));
        }
        assert!(find_terminal(&[], TERMINAL_ID).is_err());
    }

    #[test]
    fn terminal_id_is_trimmed_and_required() {
        assert_eq!(
            normalize_terminal_id(&format!("  {TERMINAL_ID}\n")).unwrap(),
            TERMINAL_ID
        );
        for blank in ["", "   ", "\t\n"] {
            assert!(matches!(
                normalize_terminal_id(blank).unwrap_err(),
                errors::ApiErrorResponse::MissingRequiredField { field_name }
                    if field_name == "terminal_id"
            ));
        }
    }

    #[test]
    fn switching_to_integrated_mode_sends_the_terminal_in_pdv() {
        assert_eq!(
            integrated_mode_body(TERMINAL_ID),
            json!({"terminals": [{"id": TERMINAL_ID, "operating_mode": "PDV"}]})
        );
    }

    #[test]
    fn restart_is_needed_until_mercado_pago_lists_the_terminal_as_integrated() {
        // The switch answers 200 at once, but the list keeps STANDALONE until the restart.
        assert!(restart_required(Some("STANDALONE")));
        assert!(restart_required(None));
        assert!(restart_required(Some("pdv")));
        assert!(!restart_required(Some("PDV")));
    }

    #[test]
    fn saving_the_terminal_keeps_the_qr_pos_and_every_other_key() {
        let qr_pos = json!({
            "seller_id": "777", "store_id": "1001", "external_store_id": "PXSOLSTabc",
            "pos_id": "2002", "external_pos_id": "PXSOLPOSabc"
        });
        let existing = json!({"account_name": "hotel", "nested": {"a": 1}, "qr_pos": qr_pos});
        let merged = merge_terminal_into_metadata(Some(existing), &terminal()).unwrap();
        assert_eq!(
            merged,
            json!({
                "account_name": "hotel",
                "nested": {"a": 1},
                "qr_pos": qr_pos,
                "point_terminal": {"terminal_id": TERMINAL_ID, "operating_mode": "PDV"}
            })
        );
        assert_eq!(saved_terminal(Some(&merged)), Some(terminal()));

        // Choosing another terminal replaces only that key.
        let other = MercadopagoPointTerminal {
            terminal_id: "NEWLAND_N950__N950NCB000000002".to_string(),
            operating_mode: "PDV".to_string(),
        };
        let merged_again = merge_terminal_into_metadata(Some(merged), &other).unwrap();
        assert_eq!(merged_again["qr_pos"], qr_pos);
        assert_eq!(merged_again["account_name"], "hotel");
        assert_eq!(saved_terminal(Some(&merged_again)), Some(other));
    }

    #[test]
    fn saving_into_empty_metadata_creates_the_object_and_other_shapes_fail() {
        for empty in [None, Some(Value::Null)] {
            let merged = merge_terminal_into_metadata(empty, &terminal()).unwrap();
            assert_eq!(saved_terminal(Some(&merged)), Some(terminal()));
        }
        assert!(matches!(
            merge_terminal_into_metadata(Some(json!(["not", "an", "object"])), &terminal()),
            Err(errors::ApiErrorResponse::InvalidRequestData { .. })
        ));
    }

    #[test]
    fn no_terminal_is_saved_until_one_is_chosen() {
        for metadata in [
            None,
            Some(json!({})),
            Some(json!({"qr_pos": {"external_pos_id": "PXSOLPOSabc"}})),
            Some(json!({"point_terminal": {}})),
            Some(json!({"point_terminal": {"terminal_id": "", "operating_mode": "PDV"}})),
            Some(json!({"point_terminal": "NEWLAND_N950__N950NCD600391917"})),
        ] {
            assert_eq!(saved_terminal(metadata.as_ref()), None, "{metadata:?}");
        }
        // The id alone is what the connector charges on, so it already counts as chosen.
        let id_only = json!({"point_terminal": {"terminal_id": TERMINAL_ID}});
        assert_eq!(
            saved_terminal(Some(&id_only)).map(|terminal| terminal.terminal_id),
            Some(TERMINAL_ID.to_string())
        );
    }

    #[test]
    fn setup_response_tells_the_device_needs_a_restart() {
        let body = serde_json::to_value(MercadopagoTerminalSetupResponse {
            terminal_id: TERMINAL_ID.to_string(),
            operating_mode: "PDV".to_string(),
            restart_required: restart_required(Some("STANDALONE")),
        })
        .unwrap();
        assert_eq!(
            body,
            json!({"terminal_id": TERMINAL_ID, "operating_mode": "PDV", "restart_required": true})
        );
    }

    // ------------------------------------------------------------------------
    // The whole flows, with Mercado Pago replaced by a seller that has `terminals`
    // ------------------------------------------------------------------------

    /// Mercado Pago as one seller: answers the list in pages and records every call.
    struct FakeSeller {
        terminals: Vec<Value>,
        /// What `paging.total` says; `None` leaves the paging block out.
        total: Option<usize>,
        /// Answers every page from the start, whatever the offset.
        ignores_offset: bool,
        failing_offset: Option<usize>,
        refuses_switch: bool,
        calls: std::sync::Mutex<Vec<String>>,
    }

    impl FakeSeller {
        fn with(count: usize) -> Self {
            Self {
                terminals: (0..count)
                    .map(|index| json!({"id": device(index), "operating_mode": "STANDALONE"}))
                    .collect(),
                total: Some(count),
                ignores_offset: false,
                failing_offset: None,
                refuses_switch: false,
                calls: std::sync::Mutex::new(Vec::new()),
            }
        }

        fn calls(&self) -> Vec<String> {
            self.calls.lock().unwrap().clone()
        }

        fn refusal(status_code: u16, code: &str) -> error_stack::Report<errors::ApiErrorResponse> {
            report!(errors::ApiErrorResponse::ExternalConnectorError {
                status_code,
                code: code.to_string(),
                message: "refused".to_string(),
                connector: "mercadopago".to_string(),
                reason: None,
            })
        }
    }

    #[async_trait::async_trait]
    impl TerminalsApi for FakeSeller {
        async fn terminals_page(&self, offset: usize) -> RouterResult<Value> {
            self.calls.lock().unwrap().push(format!("GET {offset}"));
            if self.failing_offset == Some(offset) {
                return Err(Self::refusal(500, "internal_error"));
            }
            let start = if self.ignores_offset { 0 } else { offset };
            let page: Vec<Value> = self
                .terminals
                .iter()
                .skip(start)
                .take(TERMINALS_PAGE_SIZE)
                .cloned()
                .collect();
            let mut body = json!({"data": {"terminals": page}});
            if let Some(total) = self.total {
                body["paging"] =
                    json!({"total": total, "offset": offset, "limit": TERMINALS_PAGE_SIZE});
            }
            Ok(body)
        }

        async fn switch_to_integrated_mode(&self, terminal_id: &str) -> RouterResult<()> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("PATCH {terminal_id}"));
            if self.refuses_switch {
                return Err(Self::refusal(400, "invalid_terminal"));
            }
            Ok(())
        }
    }

    fn device(index: usize) -> String {
        format!("NEWLAND_N950__DEVICE{index:04}")
    }

    fn qr_pos() -> Value {
        json!({
            "seller_id": "777", "store_id": "1001", "external_store_id": "PXSOLSTabc",
            "pos_id": "2002", "external_pos_id": "PXSOLPOSabc"
        })
    }

    fn connector_error(error: &error_stack::Report<errors::ApiErrorResponse>) -> (u16, String) {
        match error.current_context() {
            errors::ApiErrorResponse::ExternalConnectorError {
                status_code, code, ..
            } => (*status_code, code.clone()),
            other => panic!("expected a Mercado Pago error, got {other:?}"),
        }
    }

    #[test]
    fn each_page_of_the_list_is_asked_with_the_limit_and_its_offset() {
        assert_eq!(
            terminals_page_path(0),
            "/terminals/v1/list?limit=50&offset=0"
        );
        assert_eq!(
            terminals_page_path(100),
            "/terminals/v1/list?limit=50&offset=100"
        );
    }

    #[tokio::test]
    async fn the_list_reads_every_page_of_a_seller_with_many_terminals() {
        let seller = FakeSeller::with(120);
        let listed = list_all_terminals(&seller, Some(&device(119)))
            .await
            .expect("the list is read");

        assert_eq!(seller.calls(), ["GET 0", "GET 50", "GET 100"]);
        assert!(listed.complete);
        assert_eq!(
            listed
                .terminals
                .iter()
                .map(|terminal| terminal.terminal_id.clone())
                .collect::<Vec<_>>(),
            (0..120).map(device).collect::<Vec<_>>()
        );
        // The saved terminal is marked wherever it is, here on the last page.
        assert_eq!(
            listed
                .terminals
                .iter()
                .filter(|terminal| terminal.selected)
                .map(|terminal| terminal.terminal_id.clone())
                .collect::<Vec<_>>(),
            [device(119)]
        );
    }

    #[tokio::test]
    async fn the_list_stops_at_the_total_without_asking_for_an_empty_page() {
        for (count, calls) in [
            (0, vec!["GET 0"]),
            (2, vec!["GET 0"]),
            (50, vec!["GET 0"]),
            (100, vec!["GET 0", "GET 50"]),
        ] {
            let seller = FakeSeller::with(count);
            let listed = list_all_terminals(&seller, None).await.unwrap();
            assert_eq!(seller.calls(), calls, "{count} terminals");
            assert_eq!(listed.terminals.len(), count);
            assert!(listed.complete);
        }
    }

    #[tokio::test]
    async fn without_a_total_the_list_ends_at_the_first_short_page() {
        for (count, calls) in [
            (7, vec!["GET 0"]),
            (60, vec!["GET 0", "GET 50"]),
            // A full last page cannot be told from a middle one: one more, empty, ends it.
            (50, vec!["GET 0", "GET 50"]),
        ] {
            let seller = FakeSeller {
                total: None,
                ..FakeSeller::with(count)
            };
            let listed = list_all_terminals(&seller, None).await.unwrap();
            assert_eq!(seller.calls(), calls, "{count} terminals");
            assert_eq!(listed.terminals.len(), count);
            assert!(listed.complete);
        }
    }

    #[tokio::test]
    async fn a_page_that_fails_fails_the_list_instead_of_listing_a_part() {
        let seller = FakeSeller {
            failing_offset: Some(50),
            ..FakeSeller::with(120)
        };
        let error = list_all_terminals(&seller, None).await.unwrap_err();
        assert_eq!(connector_error(&error), (500, "internal_error".to_string()));
        assert_eq!(seller.calls(), ["GET 0", "GET 50"]);
    }

    #[tokio::test]
    async fn an_endless_list_is_cut_and_says_so() {
        let seller = FakeSeller::with(TERMINALS_MAX_PAGES * TERMINALS_PAGE_SIZE + 30);
        let listed = list_all_terminals(&seller, None).await.unwrap();
        assert_eq!(seller.calls().len(), TERMINALS_MAX_PAGES);
        assert_eq!(
            listed.terminals.len(),
            TERMINALS_MAX_PAGES * TERMINALS_PAGE_SIZE
        );
        assert!(!listed.complete);

        // A terminal past the cut is not called someone else's, and nothing is switched.
        let beyond = device(TERMINALS_MAX_PAGES * TERMINALS_PAGE_SIZE + 5);
        let error = choose_terminal(&seller, &beyond, None).await.unwrap_err();
        assert_eq!(
            connector_error(&error),
            (404, "terminal_list_incomplete".to_string())
        );
        assert!(seller.calls().iter().all(|call| call.starts_with("GET ")));
    }

    #[tokio::test]
    async fn a_list_that_ignores_the_offset_is_cut_without_repeating_terminals() {
        let seller = FakeSeller {
            ignores_offset: true,
            ..FakeSeller::with(120)
        };
        let listed = list_all_terminals(&seller, None).await.unwrap();
        assert_eq!(seller.calls(), ["GET 0", "GET 50"]);
        assert_eq!(listed.terminals.len(), TERMINALS_PAGE_SIZE);
        assert!(!listed.complete);
    }

    #[tokio::test]
    async fn choosing_a_terminal_switches_it_and_writes_only_its_key() {
        // The terminal is on the third page: it is found because every page is read.
        let seller = FakeSeller::with(120);
        let existing = json!({"account_name": "hotel", "qr_pos": qr_pos()});
        let setup = choose_terminal(&seller, &device(110), Some(existing))
            .await
            .expect("the terminal is chosen");

        assert_eq!(
            seller.calls(),
            [
                "GET 0".to_string(),
                "GET 50".to_string(),
                "GET 100".to_string(),
                format!("PATCH {}", device(110)),
            ]
        );
        assert_eq!(
            setup.metadata,
            json!({
                "account_name": "hotel",
                "qr_pos": qr_pos(),
                "point_terminal": {"terminal_id": device(110), "operating_mode": "PDV"}
            })
        );
        assert_eq!(setup.terminal.terminal_id, device(110));
        assert_eq!(setup.terminal.operating_mode, "PDV");
        // It was listed as STANDALONE before the switch: the device has to be restarted.
        assert!(setup.restart_required);
    }

    #[tokio::test]
    async fn a_terminal_already_integrated_needs_no_restart() {
        let mut seller = FakeSeller::with(3);
        seller.terminals[1]["operating_mode"] = json!("PDV");
        let setup = choose_terminal(&seller, &device(1), None).await.unwrap();
        assert!(!setup.restart_required);
        // The switch is sent anyway: it changes nothing at Mercado Pago.
        assert_eq!(
            seller.calls(),
            ["GET 0".to_string(), format!("PATCH {}", device(1))]
        );
        assert_eq!(
            setup.metadata,
            json!({"point_terminal": {"terminal_id": device(1), "operating_mode": "PDV"}})
        );
    }

    #[tokio::test]
    async fn a_terminal_of_another_seller_is_refused_before_anything_is_switched() {
        let seller = FakeSeller::with(120);
        let error = choose_terminal(
            &seller,
            "NEWLAND_N950__SOMEONE_ELSE",
            Some(json!({"qr_pos": qr_pos()})),
        )
        .await
        .unwrap_err();

        assert_eq!(
            connector_error(&error),
            (404, "terminal_not_found".to_string())
        );
        // The whole list was read, no switch was sent, and there is no metadata to save.
        assert_eq!(seller.calls(), ["GET 0", "GET 50", "GET 100"]);
    }

    #[tokio::test]
    async fn a_switch_mercado_pago_refuses_leaves_nothing_to_save() {
        let seller = FakeSeller {
            refuses_switch: true,
            ..FakeSeller::with(2)
        };
        let error = choose_terminal(&seller, &device(0), Some(json!({"qr_pos": qr_pos()})))
            .await
            .unwrap_err();
        assert_eq!(
            connector_error(&error),
            (400, "invalid_terminal".to_string())
        );
        assert_eq!(
            seller.calls(),
            ["GET 0".to_string(), format!("PATCH {}", device(0))]
        );
    }

    #[tokio::test]
    async fn a_list_that_fails_stops_the_setup_before_the_switch() {
        let seller = FakeSeller {
            failing_offset: Some(0),
            ..FakeSeller::with(2)
        };
        let error = choose_terminal(&seller, &device(0), None)
            .await
            .unwrap_err();
        assert_eq!(connector_error(&error), (500, "internal_error".to_string()));
        assert_eq!(seller.calls(), ["GET 0"]);
    }

    #[tokio::test]
    async fn metadata_that_cannot_hold_the_terminal_fails_the_setup() {
        let seller = FakeSeller::with(1);
        let error = choose_terminal(&seller, &device(0), Some(json!(["not", "an", "object"])))
            .await
            .unwrap_err();
        assert!(matches!(
            error.current_context(),
            errors::ApiErrorResponse::InvalidRequestData { .. }
        ));
    }
}
