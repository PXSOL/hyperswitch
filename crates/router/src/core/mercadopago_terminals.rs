//! Terminal setup for Mercado Pago Point (in-person card terminal).
//!
//! The seller's access token is only held here, so the terminals are listed and switched to
//! integrated mode with direct HTTP calls (no connector flow), through the same seller client
//! as the QR store and POS setup. The chosen terminal is saved in the connector account
//! metadata, where the connector reads the `terminal_id` of every Point order.

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

async fn list_terminals(client: &MpClient<'_>) -> RouterResult<Value> {
    MpClient::success_or_failure(
        client
            .call(Method::Get, TERMINALS_LIST_PATH, None, None)
            .await?,
    )
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
    let terminals = list_terminals(&client).await?;

    let metadata = mca.get_metadata().map(ExposeInterface::expose);
    let selected_terminal_id =
        saved_terminal(metadata.as_ref()).map(|terminal| terminal.terminal_id);
    Ok(ApplicationResponse::Json(MercadopagoTerminalListResponse {
        terminals: parse_terminals(&terminals, selected_terminal_id.as_deref()),
        selected_terminal_id,
    }))
}

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

    // Only a terminal Mercado Pago lists for this seller can be chosen.
    let listed = parse_terminals(&list_terminals(&client).await?, None);
    let needs_restart = find_terminal(&listed, &terminal_id)
        .map(|terminal| restart_required(terminal.operating_mode.as_deref()))
        .map_err(|failure| report!(failure.into_api_error()))?;

    // Switching a terminal that is already integrated changes nothing at Mercado Pago, so a
    // repeated call is safe.
    MpClient::success_or_failure(
        client
            .call(
                Method::Patch,
                TERMINALS_SETUP_PATH,
                None,
                Some(integrated_mode_body(&terminal_id)),
            )
            .await?,
    )?;

    let terminal = MercadopagoPointTerminal {
        terminal_id,
        operating_mode: POINT_OPERATING_MODE_PDV.to_string(),
    };
    // Only the metadata changes: the encrypted credentials are never rewritten.
    let metadata =
        merge_terminal_into_metadata(mca.get_metadata().map(ExposeInterface::expose), &terminal)?;
    db.update_merchant_connector_account(
        mca,
        MerchantConnectorAccountUpdate::ConnectorWebhookRegisterationUpdate {
            connector_webhook_registration_details: None,
            connector_webhook_details: None,
            metadata: Some(Secret::new(metadata)),
        }
        .foreign_into(),
        &key_store,
    )
    .await
    .change_context(errors::ApiErrorResponse::InternalServerError)
    .attach_printable("Failed to save the Mercado Pago terminal in the connector account")?;

    Ok(ApplicationResponse::Json(
        MercadopagoTerminalSetupResponse {
            terminal_id: terminal.terminal_id,
            operating_mode: terminal.operating_mode,
            restart_required: needs_restart,
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
}
