//! Store and POS setup for Mercado Pago in-person QR.
//!
//! The seller's access token is only held here, so the store and POS are created with a
//! direct HTTP call (no connector flow) and saved in the connector account metadata, where
//! the connector reads the `external_pos_id` of every QR order.

use std::collections::HashMap;

use api_models::mercadopago_pos::{
    MercadopagoPosListResponse, MercadopagoPosLocation, MercadopagoPosSetupRequest,
    MercadopagoPosSetupResponse, MercadopagoPosSummary,
};
use common_utils::{
    id_type,
    request::{Method, Request, RequestBuilder, RequestContent},
};
use error_stack::{report, ResultExt};
use external_services::http_client;
use hyperswitch_connectors::connectors::mercadopago::orders::{
    MercadopagoQrPos, QR_POS_METADATA_KEY,
};
use hyperswitch_domain_models::{
    merchant_connector_account::MerchantConnectorAccountUpdate, router_data::ConnectorAuthType,
};
use hyperswitch_masking::{ExposeInterface, Mask, PeekInterface, Secret};
use serde::Serialize;
use serde_json::Value;
use storage_impl::behaviour::ForeignInto;

use crate::{
    core::{
        errors::{self, RouterResponse, RouterResult, StorageErrorExt},
        utils as core_utils,
    },
    routes::SessionState,
    services::ApplicationResponse,
};

const CONNECTOR_NAME: &str = "mercadopago";
/// A POS `external_id` takes at most 40 characters; the ids built here stay below it.
const MAX_EXTERNAL_ID_LENGTH: usize = 40;

// ============================================================================
// Pure logic
// ============================================================================

/// Keeps the alphanumeric characters of the connector account id, which is what makes the
/// external ids deterministic: the same account always maps to the same store and POS.
fn external_id_from(prefix: &str, merchant_connector_id: &str) -> String {
    prefix
        .chars()
        .chain(
            merchant_connector_id
                .chars()
                .filter(|c| c.is_ascii_alphanumeric()),
        )
        .take(MAX_EXTERNAL_ID_LENGTH)
        .collect()
}

pub(crate) fn external_store_id(merchant_connector_id: &str) -> String {
    external_id_from("PXSOLST", merchant_connector_id)
}

pub(crate) fn external_pos_id(merchant_connector_id: &str) -> String {
    external_id_from("PXSOLPOS", merchant_connector_id)
}

/// `POST /users/{id}/stores`. No category is sent.
#[derive(Debug, Serialize)]
pub(crate) struct StoreRequest<'a> {
    name: &'a str,
    external_id: String,
    location: &'a MercadopagoPosLocation,
}

impl<'a> StoreRequest<'a> {
    fn new(fields: &CreateFields<'a>, merchant_connector_id: &str) -> Self {
        Self {
            name: fields.store_name,
            external_id: external_store_id(merchant_connector_id),
            location: fields.location,
        }
    }
}

/// The fields a new store and POS need, all present and non-empty.
pub(crate) struct CreateFields<'a> {
    store_name: &'a str,
    pos_name: &'a str,
    location: &'a MercadopagoPosLocation,
}

impl<'a> CreateFields<'a> {
    pub(crate) fn from_request(req: &'a MercadopagoPosSetupRequest) -> RouterResult<Self> {
        let required = |value: &'a Option<String>, field_name: &'static str| {
            value
                .as_deref()
                .filter(|text| !text.trim().is_empty())
                .ok_or_else(|| {
                    report!(errors::ApiErrorResponse::MissingRequiredField {
                        field_name: field_name.into()
                    })
                })
        };
        Ok(Self {
            store_name: required(&req.store_name, "store_name")?,
            pos_name: required(&req.pos_name, "pos_name")?,
            location: req.location.as_ref().ok_or_else(|| {
                report!(errors::ApiErrorResponse::MissingRequiredField {
                    field_name: "location".into()
                })
            })?,
        })
    }
}

/// What a setup call does, decided before any call to Mercado Pago beyond `/users/me`.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum SetupPath {
    /// A POS of this seller is already saved and no other one was asked for.
    ReturnSaved(Box<MercadopagoQrPos>),
    /// Use the seller's own POS with this id, whatever is saved.
    Adopt(String),
    /// Create the store and POS.
    Create,
}

/// A blank `existing_pos_id` counts as absent. Anything else must be digits only, since it
/// goes into a Mercado Pago path.
pub(crate) fn normalize_existing_pos_id(
    existing_pos_id: Option<&str>,
) -> Result<Option<String>, errors::ApiErrorResponse> {
    match existing_pos_id.map(str::trim).filter(|id| !id.is_empty()) {
        None => Ok(None),
        Some(id) if id.chars().all(|c| c.is_ascii_digit()) => Ok(Some(id.to_string())),
        Some(_) => Err(errors::ApiErrorResponse::InvalidRequestData {
            message: "existing_pos_id must contain digits only".to_string(),
        }),
    }
}

pub(crate) fn choose_setup_path(
    metadata: Option<&Value>,
    seller_id: &str,
    existing_pos_id: Option<String>,
) -> SetupPath {
    match existing_pos_id {
        Some(id) => SetupPath::Adopt(id),
        None => match existing_pos(metadata, seller_id) {
            Some(pos) => SetupPath::ReturnSaved(Box::new(pos)),
            None => SetupPath::Create,
        },
    }
}

/// A POS of another Mercado Pago user is reported like one that does not exist. A body
/// without `user_id` passes: the seller's token only reads the seller's own POS.
pub(crate) fn check_pos_owner(pos: &Value, seller_id: &str) -> Result<(), MpFailure> {
    match pos.get("user_id").and_then(id_to_string) {
        Some(owner) if owner != seller_id => Err(MpFailure {
            status: 404,
            code: "pos_not_found".to_string(),
            message: "The point of sale does not belong to this Mercado Pago account".to_string(),
            reason: None,
        }),
        _ => Ok(()),
    }
}

/// The `external_id` the adopted POS ends up with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ExternalPosId {
    /// The POS has one: it is not touched.
    Keep(String),
    /// The POS has none: this deterministic id is set with `PUT /pos/{id}`.
    Assign(String),
}

impl ExternalPosId {
    pub(crate) fn choose(pos: &Value, merchant_connector_id: &str) -> Self {
        match pos
            .get("external_id")
            .and_then(Value::as_str)
            .filter(|id| !id.is_empty())
        {
            Some(existing) => Self::Keep(existing.to_string()),
            None => Self::Assign(external_pos_id(merchant_connector_id)),
        }
    }

    fn into_id(self) -> String {
        match self {
            Self::Keep(id) | Self::Assign(id) => id,
        }
    }
}

/// QR URLs of a POS: `qr_response` on `POST /v2/pos`, `qr` on the reads.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct PosQr {
    pub image: Option<String>,
    pub template_document: Option<String>,
    pub template_image: Option<String>,
}

impl PosQr {
    pub(crate) fn from_pos(pos: &Value) -> Self {
        let qr = pos
            .get("qr_response")
            .filter(|qr| qr.is_object())
            .or_else(|| pos.get("qr").filter(|qr| qr.is_object()));
        let url = |key: &str| {
            qr.and_then(|qr| qr.get(key))
                .and_then(Value::as_str)
                .filter(|url| !url.is_empty())
                .map(str::to_string)
        };
        Self {
            image: url("image"),
            template_document: url("template_document"),
            template_image: url("template_image"),
        }
    }
}

/// `external_id` of the store with this id, from a stores search.
pub(crate) fn store_external_id_of(stores: &Value, store_id: &str) -> Option<String> {
    stores
        .get("results")
        .and_then(Value::as_array)?
        .iter()
        .find(|store| store.get("id").and_then(id_to_string).as_deref() == Some(store_id))
        .and_then(|store| store.get("external_id"))
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty())
        .map(str::to_string)
}

/// Store names by store id, from a stores search.
pub(crate) fn store_names(stores: &Value) -> HashMap<String, String> {
    stores
        .get("results")
        .and_then(Value::as_array)
        .map(|results| {
            results
                .iter()
                .filter_map(|store| {
                    Some((
                        store.get("id").and_then(id_to_string)?,
                        store
                            .get("name")
                            .and_then(Value::as_str)
                            .filter(|name| !name.is_empty())?
                            .to_string(),
                    ))
                })
                .collect()
        })
        .unwrap_or_default()
}

/// The POS list of `GET /pos`; an entry without an id is skipped.
pub(crate) fn parse_pos_list(
    pos_list: &Value,
    store_names: &HashMap<String, String>,
) -> Vec<MercadopagoPosSummary> {
    pos_list
        .get("results")
        .and_then(Value::as_array)
        .map(|results| {
            results
                .iter()
                .filter_map(|pos| {
                    let store_id = pos.get("store_id").and_then(id_to_string);
                    Some(MercadopagoPosSummary {
                        pos_id: pos.get("id").and_then(id_to_string)?,
                        name: pos.get("name").and_then(Value::as_str).map(str::to_string),
                        store_name: store_id
                            .as_ref()
                            .and_then(|id| store_names.get(id))
                            .cloned(),
                        store_id,
                        has_external_id: pos
                            .get("external_id")
                            .and_then(Value::as_str)
                            .is_some_and(|id| !id.is_empty()),
                        qr_image: PosQr::from_pos(pos).image,
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

/// A POS as answered by `POST /v2/pos` or found by its `external_id`.
pub(crate) struct CreatedPos {
    id: String,
    qr: PosQr,
}

impl CreatedPos {
    fn from_body(body: &Value) -> Option<Self> {
        Some(Self {
            id: body.get("id").and_then(id_to_string)?,
            qr: PosQr::from_pos(body),
        })
    }
}

/// `POST /v2/pos`.
#[derive(Debug, Serialize)]
pub(crate) struct PosRequest<'a> {
    name: &'a str,
    store_id: &'a str,
    external_id: String,
}

/// `PUT /pos/{id}` body that adopts a POS: Mercado Pago's quality measurement requires every POS to
/// be closed-amount, so the flag travels with the `external_id`.
fn adoption_body(external_id: &str) -> Value {
    serde_json::json!({ "external_id": external_id, "fixed_amount": true })
}

/// `PUT /pos/{id}` body that closes the amount of a POS. `POST /v2/pos` rejects `fixed_amount`, so
/// it can only be applied after creation.
fn closed_amount_body() -> Value {
    serde_json::json!({ "fixed_amount": true })
}

/// The POS saved in the account metadata, if it belongs to this seller. An account reconnected
/// with another Mercado Pago user needs its own store and POS.
pub(crate) fn existing_pos(metadata: Option<&Value>, seller_id: &str) -> Option<MercadopagoQrPos> {
    metadata
        .and_then(|metadata| metadata.get(QR_POS_METADATA_KEY))
        .and_then(|pos| serde_json::from_value::<MercadopagoQrPos>(pos.clone()).ok())
        .filter(|pos| pos.seller_id == seller_id && !pos.external_pos_id.is_empty())
}

/// Adds the POS under one key and keeps every other key of the metadata.
pub(crate) fn merge_pos_into_metadata(
    existing: Option<Value>,
    pos: &MercadopagoQrPos,
) -> Result<Value, errors::ApiErrorResponse> {
    let mut metadata = match existing {
        None | Some(Value::Null) => serde_json::Map::new(),
        Some(Value::Object(map)) => map,
        Some(_) => {
            return Err(errors::ApiErrorResponse::InvalidRequestData {
                message: "The connector account metadata is not a JSON object".to_string(),
            })
        }
    };
    metadata.insert(
        QR_POS_METADATA_KEY.to_string(),
        serde_json::to_value(pos).map_err(|_| errors::ApiErrorResponse::InternalServerError)?,
    );
    Ok(Value::Object(metadata))
}

/// Mercado Pago ids come as numbers or text depending on the endpoint.
fn id_to_string(value: &Value) -> Option<String> {
    match value {
        Value::String(text) if !text.is_empty() => Some(text.clone()),
        Value::Number(number) => Some(number.to_string()),
        _ => None,
    }
}

/// What Mercado Pago answered with when it refused a call. Both of its error shapes are read:
/// `{error, message, status, causes[{code, description}]}` and `{errors[{code, message}]}`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MpFailure {
    pub status: u16,
    pub code: String,
    pub message: String,
    /// `causes[].description` joined: for an invalid city these list the valid values.
    pub reason: Option<String>,
}

impl MpFailure {
    pub(crate) fn from_response(status: u16, body: &Value) -> Self {
        let first_error = body
            .get("errors")
            .and_then(Value::as_array)
            .and_then(|errors| errors.first());
        let text = |value: Option<&Value>| {
            value
                .and_then(Value::as_str)
                .filter(|text| !text.is_empty())
                .map(str::to_string)
        };
        let code = text(body.get("error"))
            .or_else(|| text(first_error.and_then(|error| error.get("code"))))
            .unwrap_or_else(|| "mercadopago_error".to_string());
        let message = text(body.get("message"))
            .or_else(|| text(first_error.and_then(|error| error.get("message"))))
            .unwrap_or_else(|| format!("Mercado Pago answered with status {status}"));
        let descriptions: Vec<String> = body
            .get("causes")
            .and_then(Value::as_array)
            .map(|causes| {
                causes
                    .iter()
                    .filter_map(|cause| text(cause.get("description")))
                    .collect()
            })
            .unwrap_or_default();
        Self {
            status,
            code,
            message,
            reason: (!descriptions.is_empty()).then(|| descriptions.join("; ")),
        }
    }

    /// The status the caller sees: Mercado Pago's own 4xx (a retryable 423 included) so the
    /// UI can act on it, 424 when the seller's token was refused (our caller's auth is fine),
    /// and 502 for anything else.
    fn client_status(&self) -> u16 {
        match self.status {
            401 | 403 => 424,
            status @ 400..=499 => status,
            _ => 502,
        }
    }

    pub(crate) fn into_api_error(self) -> errors::ApiErrorResponse {
        errors::ApiErrorResponse::ExternalConnectorError {
            status_code: self.client_status(),
            code: self.code,
            message: self.message,
            connector: CONNECTOR_NAME.to_string(),
            reason: self.reason,
        }
    }

    /// 400 and 423 can mean the external id is already taken (423 while it is locked after a
    /// delete or a recent create), as opposed to an invalid field.
    fn may_be_existing_external_id(&self) -> bool {
        matches!(self.status, 400 | 423)
    }
}

/// The entry of a Mercado Pago `results` list with the given `external_id`.
fn find_by_external_id<'a>(results: &'a Value, external_id: &str) -> Option<&'a Value> {
    results
        .get("results")
        .and_then(Value::as_array)?
        .iter()
        .find(|entry| entry.get("external_id").and_then(Value::as_str) == Some(external_id))
}

// ============================================================================
// Mercado Pago HTTP
// ============================================================================

struct MpResponse {
    status: u16,
    body: Value,
}

struct MpClient<'a> {
    state: &'a SessionState,
    base_url: &'a str,
    token: Secret<String>,
}

impl MpClient<'_> {
    /// Never logs the token: it only travels in a masked header.
    async fn call(
        &self,
        method: Method,
        path: &str,
        idempotency_key: Option<&str>,
        body: Option<Value>,
    ) -> RouterResult<MpResponse> {
        let mut headers = vec![
            (
                "Authorization".to_string(),
                format!("Bearer {}", self.token.peek()).into_masked(),
            ),
            (
                "Content-Type".to_string(),
                "application/json".to_string().into(),
            ),
        ];
        if let Some(key) = idempotency_key {
            headers.push(("X-Idempotency-Key".to_string(), key.to_string().into()));
        }
        let request: Request = RequestBuilder::new()
            .method(method)
            .url(&format!("{}{}", self.base_url, path))
            .attach_default_headers()
            .headers(headers)
            .set_optional_body(body.map(|body| RequestContent::Json(Box::new(body))))
            .build();

        let response = http_client::send_request(&self.state.conf.proxy, request, None)
            .await
            .change_context(errors::ApiErrorResponse::InternalServerError)
            .attach_printable("Failed to send a request to Mercado Pago")?;
        let status = response.status().as_u16();
        let bytes = response
            .bytes()
            .await
            .change_context(errors::ApiErrorResponse::InternalServerError)
            .attach_printable("Failed to read the Mercado Pago response")?;
        // A body that is not JSON only loses its detail: the status still tells the outcome.
        let body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        Ok(MpResponse { status, body })
    }

    fn success_or_failure(response: MpResponse) -> RouterResult<Value> {
        if (200..300).contains(&response.status) {
            Ok(response.body)
        } else {
            Err(report!(MpFailure::from_response(
                response.status,
                &response.body
            )
            .into_api_error()))
        }
    }

    async fn seller_user_id(&self) -> RouterResult<String> {
        let body =
            Self::success_or_failure(self.call(Method::Get, "/users/me", None, None).await?)?;
        body.get("id").and_then(id_to_string).ok_or_else(|| {
            report!(errors::ApiErrorResponse::InternalServerError)
                .attach_printable("Mercado Pago /users/me answered without an id")
        })
    }

    async fn get_pos(&self, pos_id: &str) -> RouterResult<Value> {
        Self::success_or_failure(
            self.call(Method::Get, &format!("/pos/{pos_id}"), None, None)
                .await?,
        )
    }

    async fn list_pos(&self) -> RouterResult<Value> {
        Self::success_or_failure(self.call(Method::Get, "/pos?limit=50", None, None).await?)
    }

    async fn search_stores(&self, user_id: &str) -> RouterResult<Value> {
        Self::success_or_failure(
            self.call(
                Method::Get,
                &format!("/users/{user_id}/stores/search?limit=50"),
                None,
                None,
            )
            .await?,
        )
    }

    /// Adopts a POS made by hand. Mercado Pago does not clear the id afterwards.
    async fn assign_pos_external_id(&self, pos_id: &str, external_id: &str) -> RouterResult<()> {
        Self::success_or_failure(
            self.call(
                Method::Put,
                &format!("/pos/{pos_id}"),
                None,
                Some(adoption_body(external_id)),
            )
            .await?,
        )
        .map(|_| ())
    }

    /// Makes a POS closed-amount. Idempotent, so a retry after a partial failure can repeat it.
    async fn close_pos_amount(&self, pos_id: &str) -> RouterResult<()> {
        Self::success_or_failure(
            self.call(
                Method::Put,
                &format!("/pos/{pos_id}"),
                None,
                Some(closed_amount_body()),
            )
            .await?,
        )
        .map(|_| ())
    }

    /// Creates the store, or reuses the one that already has this `external_id` (a second call
    /// after a partial failure, or a store lock that has not expired yet).
    async fn ensure_store(
        &self,
        user_id: &str,
        request: &StoreRequest<'_>,
    ) -> RouterResult<String> {
        let body = serde_json::to_value(request)
            .change_context(errors::ApiErrorResponse::InternalServerError)?;
        let response = self
            .call(
                Method::Post,
                &format!("/users/{user_id}/stores"),
                None,
                Some(body),
            )
            .await?;
        if (200..300).contains(&response.status) {
            return response
                .body
                .get("id")
                .and_then(id_to_string)
                .ok_or_else(|| {
                    report!(errors::ApiErrorResponse::InternalServerError)
                        .attach_printable("Mercado Pago created a store without an id")
                });
        }

        let failure = MpFailure::from_response(response.status, &response.body);
        if failure.may_be_existing_external_id() {
            let search = self
                .call(
                    Method::Get,
                    &format!(
                        "/users/{user_id}/stores/search?external_id={}",
                        request.external_id
                    ),
                    None,
                    None,
                )
                .await?;
            if (200..300).contains(&search.status) {
                if let Some(id) = find_by_external_id(&search.body, &request.external_id)
                    .and_then(|store| store.get("id"))
                    .and_then(id_to_string)
                {
                    return Ok(id);
                }
            }
        }
        // Not found: an invalid field (the causes list the valid values), or an id that is
        // still locked, which the caller can retry (423).
        Err(report!(failure.into_api_error()))
    }

    /// Creates the POS, or reuses the one that already has this `external_id` in the store, and
    /// leaves it closed-amount either way. A failure closing it fails the setup; the retry finds
    /// the POS by its `external_id` and applies it again.
    async fn ensure_pos(&self, request: &PosRequest<'_>) -> RouterResult<CreatedPos> {
        let created = self.create_or_find_pos(request).await?;
        self.close_pos_amount(&created.id).await?;
        Ok(created)
    }

    async fn create_or_find_pos(&self, request: &PosRequest<'_>) -> RouterResult<CreatedPos> {
        let body = serde_json::to_value(request)
            .change_context(errors::ApiErrorResponse::InternalServerError)?;
        // A fresh key per call: a retry after a failure has to reach Mercado Pago again, and a
        // POS that did get created is found by the lookup below.
        let idempotency_key = uuid::Uuid::new_v4().to_string();
        let response = self
            .call(Method::Post, "/v2/pos", Some(&idempotency_key), Some(body))
            .await?;
        if (200..300).contains(&response.status) {
            return CreatedPos::from_body(&response.body).ok_or_else(|| {
                report!(errors::ApiErrorResponse::InternalServerError)
                    .attach_printable("Mercado Pago created a POS without an id")
            });
        }

        let failure = MpFailure::from_response(response.status, &response.body);
        if failure.may_be_existing_external_id() || failure.code == "pos_already_exists" {
            let search = self
                .call(
                    Method::Get,
                    &format!("/pos?external_id={}", request.external_id),
                    None,
                    None,
                )
                .await?;
            if (200..300).contains(&search.status) {
                if let Some(pos) = find_by_external_id(&search.body, &request.external_id) {
                    // Another store owning this external id is a real conflict, not a reuse.
                    let same_store = pos.get("store_id").and_then(id_to_string).as_deref()
                        == Some(request.store_id);
                    if same_store {
                        if let Some(created) = CreatedPos::from_body(pos) {
                            return Ok(created);
                        }
                    }
                }
            }
        }
        Err(report!(failure.into_api_error()))
    }
}

// ============================================================================
// Core
// ============================================================================

/// The connector account and the seller's token, after the checks every call needs.
async fn load_account(
    state: &SessionState,
    merchant_id: &id_type::MerchantId,
    profile_id: Option<id_type::ProfileId>,
    merchant_connector_id: &id_type::MerchantConnectorAccountId,
) -> RouterResult<(
    hyperswitch_domain_models::merchant_key_store::MerchantKeyStore,
    hyperswitch_domain_models::merchant_connector_account::MerchantConnectorAccount,
    Secret<String>,
)> {
    let db = state.store.as_ref();
    let key_store = db
        .get_merchant_key_store_by_merchant_id(merchant_id, &db.get_master_key().to_vec().into())
        .await
        .to_not_found_response(errors::ApiErrorResponse::MerchantAccountNotFound)?;

    let mca = db
        .find_by_merchant_connector_account_merchant_id_merchant_connector_id(
            merchant_id,
            merchant_connector_id,
            &key_store,
        )
        .await
        .to_not_found_response(errors::ApiErrorResponse::MerchantConnectorAccountNotFound {
            id: merchant_connector_id.get_string_repr().to_string(),
        })?;
    core_utils::validate_profile_id_from_auth_layer(profile_id, &mca)?;

    if mca.connector_name != CONNECTOR_NAME {
        return Err(report!(errors::ApiErrorResponse::InvalidRequestData {
            message: "The connector account is not a Mercado Pago account".to_string(),
        }));
    }

    let token = match mca
        .get_connector_account_details()
        .change_context(errors::ApiErrorResponse::InternalServerError)
        .attach_printable("Failed to read the connector account details")?
    {
        ConnectorAuthType::HeaderKey { api_key } => api_key,
        _ => {
            return Err(report!(errors::ApiErrorResponse::InvalidRequestData {
                message: "The Mercado Pago account has no access token".to_string(),
            }))
        }
    };
    Ok((key_store, mca, token))
}

pub async fn list_mercadopago_pos(
    state: SessionState,
    merchant_id: &id_type::MerchantId,
    profile_id: Option<id_type::ProfileId>,
    merchant_connector_id: &id_type::MerchantConnectorAccountId,
) -> RouterResponse<MercadopagoPosListResponse> {
    let (_, _, token) =
        load_account(&state, merchant_id, profile_id, merchant_connector_id).await?;
    let client = MpClient {
        state: &state,
        base_url: state.conf.connectors.mercadopago.base_url.as_ref(),
        token,
    };
    let user_id = client.seller_user_id().await?;
    let pos_list = client.list_pos().await?;
    // Store names are a convenience: without them the POS are still listed.
    let names = match client.search_stores(&user_id).await {
        Ok(stores) => store_names(&stores),
        Err(_) => HashMap::new(),
    };
    Ok(ApplicationResponse::Json(MercadopagoPosListResponse {
        pos: parse_pos_list(&pos_list, &names),
    }))
}

pub async fn setup_mercadopago_pos(
    state: SessionState,
    merchant_id: &id_type::MerchantId,
    profile_id: Option<id_type::ProfileId>,
    merchant_connector_id: &id_type::MerchantConnectorAccountId,
    req: MercadopagoPosSetupRequest,
) -> RouterResponse<MercadopagoPosSetupResponse> {
    let db = state.store.as_ref();
    let (key_store, mca, token) =
        load_account(&state, merchant_id, profile_id, merchant_connector_id).await?;

    let client = MpClient {
        state: &state,
        base_url: state.conf.connectors.mercadopago.base_url.as_ref(),
        token,
    };
    let connector_account_id = merchant_connector_id.get_string_repr();

    let existing_pos_id = normalize_existing_pos_id(req.existing_pos_id.as_deref())
        .map_err(|error| report!(error))?;
    let user_id = client.seller_user_id().await?;

    let current_metadata = mca.get_metadata().map(ExposeInterface::expose);
    let pos = match choose_setup_path(current_metadata.as_ref(), &user_id, existing_pos_id) {
        // Already set up for this seller: nothing to create.
        SetupPath::ReturnSaved(pos) => {
            return Ok(ApplicationResponse::Json(response_from(*pos)));
        }
        SetupPath::Adopt(pos_id) => {
            let body = client.get_pos(&pos_id).await?;
            check_pos_owner(&body, &user_id)
                .map_err(|failure| report!(failure.into_api_error()))?;
            let external_pos_id = ExternalPosId::choose(&body, connector_account_id);
            if let ExternalPosId::Assign(id) = &external_pos_id {
                client.assign_pos_external_id(&pos_id, id).await?;
            }
            let store_id = body.get("store_id").and_then(id_to_string).ok_or_else(|| {
                report!(errors::ApiErrorResponse::InternalServerError)
                    .attach_printable("The Mercado Pago POS has no store")
            })?;
            // A store without an external id is fine: the connector only reads the POS's.
            let external_store_id = client
                .search_stores(&user_id)
                .await
                .ok()
                .and_then(|stores| store_external_id_of(&stores, &store_id))
                .unwrap_or_default();
            let qr = PosQr::from_pos(&body);
            MercadopagoQrPos {
                seller_id: user_id,
                store_id,
                external_store_id,
                pos_id,
                external_pos_id: external_pos_id.into_id(),
                qr_image: qr.image,
                qr_template_document: qr.template_document,
                qr_template_image: qr.template_image,
            }
        }
        SetupPath::Create => {
            let fields = CreateFields::from_request(&req)?;
            let store_request = StoreRequest::new(&fields, connector_account_id);
            let external_store_id = store_request.external_id.clone();
            let store_id = client.ensure_store(&user_id, &store_request).await?;

            let pos_request = PosRequest {
                name: fields.pos_name,
                store_id: &store_id,
                external_id: external_pos_id(connector_account_id),
            };
            let external_pos_id = pos_request.external_id.clone();
            let created = client.ensure_pos(&pos_request).await?;
            MercadopagoQrPos {
                seller_id: user_id,
                store_id,
                external_store_id,
                pos_id: created.id,
                external_pos_id,
                qr_image: created.qr.image,
                qr_template_document: created.qr.template_document,
                qr_template_image: created.qr.template_image,
            }
        }
    };

    // Only the metadata changes: the encrypted credentials are never rewritten.
    let metadata = merge_pos_into_metadata(current_metadata, &pos)?;
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
    .attach_printable("Failed to save the Mercado Pago POS in the connector account")?;

    Ok(ApplicationResponse::Json(response_from(pos)))
}

fn response_from(pos: MercadopagoQrPos) -> MercadopagoPosSetupResponse {
    MercadopagoPosSetupResponse {
        store_id: pos.store_id,
        external_store_id: pos.external_store_id,
        pos_id: pos.pos_id,
        external_pos_id: pos.external_pos_id,
        qr_image: pos.qr_image,
        qr_template_document: pos.qr_template_document,
        qr_template_image: pos.qr_template_image,
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn location() -> MercadopagoPosLocation {
        MercadopagoPosLocation {
            street_number: "100".to_string(),
            street_name: "Av Corrientes".to_string(),
            city_name: "Iguazu".to_string(),
            state_name: "Misiones".to_string(),
            latitude: -25.6,
            longitude: -54.5,
            reference: None,
        }
    }

    fn setup_request() -> MercadopagoPosSetupRequest {
        MercadopagoPosSetupRequest {
            store_name: Some("Hotel Prueba".to_string()),
            pos_name: Some("Recepcion".to_string()),
            location: Some(location()),
            existing_pos_id: None,
        }
    }

    const SELLER: &str = "777";

    fn pos() -> MercadopagoQrPos {
        MercadopagoQrPos {
            seller_id: SELLER.to_string(),
            store_id: "1001".to_string(),
            external_store_id: "PXSOLSTabc".to_string(),
            pos_id: "2002".to_string(),
            external_pos_id: "PXSOLPOSabc".to_string(),
            qr_image: Some("https://mp.test/qr.png".to_string()),
            qr_template_document: None,
            qr_template_image: None,
        }
    }

    #[test]
    fn external_ids_are_alphanumeric_deterministic_and_bounded() {
        let id = "mca_Ab12-Cd_34";
        assert_eq!(external_store_id(id), "PXSOLSTmcaAb12Cd34");
        assert_eq!(external_pos_id(id), "PXSOLPOSmcaAb12Cd34");
        assert_eq!(external_store_id(id), external_store_id(id));
        assert_ne!(external_store_id(id), external_pos_id(id));
        assert_ne!(external_store_id("mca_one"), external_store_id("mca_two"));

        let long = format!("mca_{}", "x".repeat(200));
        for generated in [external_store_id(&long), external_pos_id(&long)] {
            assert!(generated.len() <= MAX_EXTERNAL_ID_LENGTH);
            assert!(generated.chars().all(|c| c.is_ascii_alphanumeric()));
        }
        assert!(external_store_id("")
            .chars()
            .all(|c| c.is_ascii_alphanumeric()));
    }

    #[test]
    fn store_request_has_no_category_and_omits_an_empty_reference() {
        let request = setup_request();
        let fields = CreateFields::from_request(&request).unwrap();
        let body = serde_json::to_value(StoreRequest::new(&fields, "mca_abc")).unwrap();
        assert_eq!(
            body,
            json!({
                "name": "Hotel Prueba",
                "external_id": "PXSOLSTmcaabc",
                "location": {
                    "street_number": "100",
                    "street_name": "Av Corrientes",
                    "city_name": "Iguazu",
                    "state_name": "Misiones",
                    "latitude": -25.6,
                    "longitude": -54.5
                }
            })
        );
        assert!(body.get("category").is_none());

        let mut with_reference = setup_request();
        with_reference.location.as_mut().unwrap().reference = Some("Lobby".to_string());
        let fields = CreateFields::from_request(&with_reference).unwrap();
        let body = serde_json::to_value(StoreRequest::new(&fields, "mca_abc")).unwrap();
        assert_eq!(body["location"]["reference"], "Lobby");
    }

    #[test]
    fn pos_request_links_the_store() {
        let body = serde_json::to_value(PosRequest {
            name: "Recepcion",
            store_id: "1001",
            external_id: external_pos_id("mca_abc"),
        })
        .unwrap();
        assert_eq!(
            body,
            json!({"name": "Recepcion", "store_id": "1001", "external_id": "PXSOLPOSmcaabc"})
        );
    }

    #[test]
    fn pos_request_does_not_send_fixed_amount() {
        let body = serde_json::to_value(PosRequest {
            name: "Recepcion",
            store_id: "1001",
            external_id: external_pos_id("mca_abc"),
        })
        .unwrap();
        assert!(body.get("fixed_amount").is_none());
    }

    #[test]
    fn adoption_sets_the_external_id_and_closes_the_amount() {
        assert_eq!(
            adoption_body("PXSOLPOSmcaabc"),
            json!({"external_id": "PXSOLPOSmcaabc", "fixed_amount": true})
        );
    }

    #[test]
    fn closing_the_amount_sends_only_fixed_amount() {
        assert_eq!(closed_amount_body(), json!({"fixed_amount": true}));
    }

    #[test]
    fn merging_the_pos_keeps_every_other_metadata_key() {
        let existing = json!({"account_name": "hotel", "nested": {"a": 1}});
        let merged = merge_pos_into_metadata(Some(existing), &pos()).unwrap();
        assert_eq!(merged["account_name"], "hotel");
        assert_eq!(merged["nested"]["a"], 1);
        assert_eq!(
            merged[QR_POS_METADATA_KEY]["external_pos_id"],
            "PXSOLPOSabc"
        );
        assert_eq!(existing_pos(Some(&merged), SELLER), Some(pos()));

        // Merging again replaces only the POS key.
        let mut other = pos();
        other.pos_id = "3003".to_string();
        let merged_again = merge_pos_into_metadata(Some(merged), &other).unwrap();
        assert_eq!(merged_again["account_name"], "hotel");
        assert_eq!(merged_again[QR_POS_METADATA_KEY]["pos_id"], "3003");
    }

    #[test]
    fn merging_into_empty_metadata_creates_the_object_and_other_shapes_fail() {
        for empty in [None, Some(Value::Null)] {
            let merged = merge_pos_into_metadata(empty, &pos()).unwrap();
            assert_eq!(existing_pos(Some(&merged), SELLER), Some(pos()));
        }
        assert!(merge_pos_into_metadata(Some(json!(["not", "an", "object"])), &pos()).is_err());
    }

    #[test]
    fn existing_pos_needs_a_usable_external_pos_id() {
        assert_eq!(existing_pos(None, SELLER), None);
        assert_eq!(existing_pos(Some(&json!({})), SELLER), None);
        assert_eq!(
            existing_pos(Some(&json!({QR_POS_METADATA_KEY: {}})), SELLER),
            None
        );
        assert_eq!(
            existing_pos(
                Some(&json!({QR_POS_METADATA_KEY: {
                    "seller_id": SELLER, "store_id": "1", "external_store_id": "S",
                    "pos_id": "2", "external_pos_id": ""
                }})),
                SELLER
            ),
            None
        );
    }

    #[test]
    fn a_pos_of_another_seller_is_not_reused() {
        let merged = merge_pos_into_metadata(None, &pos()).unwrap();
        assert_eq!(existing_pos(Some(&merged), SELLER), Some(pos()));
        assert_eq!(existing_pos(Some(&merged), "888"), None);
    }

    #[test]
    fn invalid_city_is_a_400_carrying_the_valid_values() {
        let body = json!({
            "error": "validation_error",
            "message": "location.city_name was invalid.",
            "status": 400,
            "causes": [{
                "code": 400,
                "description": "location.city_name was invalid. Valid values are: 2 de Abril, Iguazu"
            }]
        });
        let failure = MpFailure::from_response(400, &body);
        assert_eq!(failure.code, "validation_error");
        assert_eq!(failure.message, "location.city_name was invalid.");
        assert_eq!(
            failure.reason.as_deref(),
            Some("location.city_name was invalid. Valid values are: 2 de Abril, Iguazu")
        );
        assert_eq!(failure.client_status(), 400);
        assert!(matches!(
            failure.into_api_error(),
            errors::ApiErrorResponse::ExternalConnectorError { status_code: 400, reason: Some(reason), .. }
                if reason.contains("Valid values are")
        ));
    }

    #[test]
    fn locked_external_id_stays_a_retryable_4xx() {
        let failure = MpFailure::from_response(
            423,
            &json!({"error": "locked", "message": "external id is currently locked", "status": 423, "causes": []}),
        );
        assert_eq!(failure.code, "locked");
        assert_eq!(failure.reason, None);
        assert_eq!(failure.client_status(), 423);
        assert!(failure.may_be_existing_external_id());
    }

    #[test]
    fn the_errors_array_shape_is_read_too() {
        let failure = MpFailure::from_response(
            400,
            &json!({"errors": [{"message": "POS already exists for the external_id", "code": "pos_already_exists"}]}),
        );
        assert_eq!(failure.code, "pos_already_exists");
        assert_eq!(failure.message, "POS already exists for the external_id");
    }

    #[test]
    fn seller_token_refusals_and_server_errors_do_not_look_like_our_own() {
        assert_eq!(
            MpFailure::from_response(401, &Value::Null).client_status(),
            424
        );
        assert_eq!(
            MpFailure::from_response(403, &Value::Null).client_status(),
            424
        );
        assert_eq!(
            MpFailure::from_response(500, &Value::Null).client_status(),
            502
        );
        assert_eq!(
            MpFailure::from_response(404, &Value::Null).client_status(),
            404
        );
        let unknown = MpFailure::from_response(500, &Value::Null);
        assert_eq!(unknown.code, "mercadopago_error");
        assert!(!MpFailure::from_response(401, &Value::Null).may_be_existing_external_id());
    }

    #[test]
    fn lookups_match_the_external_id_exactly() {
        let results = json!({"paging": {"total": 2}, "results": [
            {"id": "1", "external_id": "OTHER"},
            {"id": 82800097, "external_id": "PXSOLSTabc"}
        ]});
        let found = find_by_external_id(&results, "PXSOLSTabc").unwrap();
        assert_eq!(
            found.get("id").and_then(id_to_string).as_deref(),
            Some("82800097")
        );
        assert!(find_by_external_id(&results, "MISSING").is_none());
        assert!(find_by_external_id(&json!({}), "PXSOLSTabc").is_none());
    }

    #[test]
    fn creating_needs_every_field_and_location() {
        assert!(CreateFields::from_request(&setup_request()).is_ok());
        let mut no_store = setup_request();
        no_store.store_name = Some("  ".to_string());
        let mut no_pos = setup_request();
        no_pos.pos_name = None;
        let mut no_location = setup_request();
        no_location.location = None;
        for (request, field) in [
            (no_store, "store_name"),
            (no_pos, "pos_name"),
            (no_location, "location"),
        ] {
            let error = CreateFields::from_request(&request)
                .err()
                .expect("rejected");
            assert!(matches!(
                error.current_context(),
                errors::ApiErrorResponse::MissingRequiredField { field_name } if field_name == field
            ));
        }
    }

    #[test]
    fn existing_pos_id_is_digits_only_and_blank_means_absent() {
        assert_eq!(normalize_existing_pos_id(None).unwrap(), None);
        assert_eq!(normalize_existing_pos_id(Some("  ")).unwrap(), None);
        assert_eq!(
            normalize_existing_pos_id(Some(" 123 ")).unwrap(),
            Some("123".to_string())
        );
        for bad in ["12/../3", "12a", "-1", "1 2"] {
            assert!(normalize_existing_pos_id(Some(bad)).is_err());
        }
    }

    #[test]
    fn the_setup_path_follows_the_request_and_the_saved_pos() {
        let saved = merge_pos_into_metadata(None, &pos()).unwrap();
        // Nothing asked: today's short-circuit for the same seller, a fresh create otherwise.
        assert_eq!(
            choose_setup_path(Some(&saved), SELLER, None),
            SetupPath::ReturnSaved(Box::new(pos()))
        );
        assert_eq!(
            choose_setup_path(Some(&saved), "888", None),
            SetupPath::Create
        );
        assert_eq!(choose_setup_path(None, SELLER, None), SetupPath::Create);
        // An existing POS wins over the saved one, including a different id for the same seller.
        for metadata in [Some(&saved), None] {
            assert_eq!(
                choose_setup_path(metadata, SELLER, Some("3003".to_string())),
                SetupPath::Adopt("3003".to_string())
            );
        }
    }

    #[test]
    fn a_pos_of_another_user_is_reported_as_not_found() {
        assert!(check_pos_owner(&json!({"user_id": 777}), SELLER).is_ok());
        assert!(check_pos_owner(&json!({"user_id": "777"}), SELLER).is_ok());
        assert!(check_pos_owner(&json!({"id": 1}), SELLER).is_ok());
        let failure = check_pos_owner(&json!({"user_id": 888}), SELLER).unwrap_err();
        assert_eq!(failure.client_status(), 404);
        assert_eq!(failure.code, "pos_not_found");
    }

    #[test]
    fn an_existing_external_id_is_kept_and_a_missing_one_is_assigned() {
        assert_eq!(
            ExternalPosId::choose(&json!({"external_id": "HANDMADE1"}), "mca_abc"),
            ExternalPosId::Keep("HANDMADE1".to_string())
        );
        for body in [
            json!({}),
            json!({"external_id": null}),
            json!({"external_id": ""}),
        ] {
            assert_eq!(
                ExternalPosId::choose(&body, "mca_abc"),
                ExternalPosId::Assign("PXSOLPOSmcaabc".to_string())
            );
        }
    }

    #[test]
    fn both_qr_keys_are_read() {
        let urls = json!({"image": "i", "template_document": "d", "template_image": "t"});
        let expected = PosQr {
            image: Some("i".to_string()),
            template_document: Some("d".to_string()),
            template_image: Some("t".to_string()),
        };
        assert_eq!(PosQr::from_pos(&json!({"id": 1, "qr": urls})), expected);
        assert_eq!(
            PosQr::from_pos(&json!({"id": 1, "qr_response": urls})),
            expected
        );
        assert_eq!(PosQr::from_pos(&json!({"id": 1})), PosQr::default());
        assert_eq!(PosQr::from_pos(&json!({"qr": null})), PosQr::default());
        let created = CreatedPos::from_body(&json!({"id": 5, "qr_response": urls})).unwrap();
        assert_eq!((created.id.as_str(), created.qr), ("5", expected));
    }

    #[test]
    fn the_pos_list_joins_store_names_and_flags_external_ids() {
        let stores = json!({"results": [
            {"id": 11, "name": "Hotel Uno", "external_id": "PXSOLSTx"},
            {"id": "12", "name": "Hotel Dos", "external_id": null}
        ]});
        let pos_list = json!({"results": [
            {"id": 1, "name": "Caja", "external_id": "A1", "store_id": 11,
             "qr": {"image": "https://mp.test/1.png"}},
            {"id": 2, "name": "Bar", "external_id": null, "store_id": "12"},
            {"id": 3, "store_id": 99},
            {"name": "no id"}
        ]});
        let names = store_names(&stores);
        let listed = parse_pos_list(&pos_list, &names);
        assert_eq!(listed.len(), 3);
        assert_eq!(
            listed[0],
            MercadopagoPosSummary {
                pos_id: "1".to_string(),
                name: Some("Caja".to_string()),
                store_id: Some("11".to_string()),
                store_name: Some("Hotel Uno".to_string()),
                has_external_id: true,
                qr_image: Some("https://mp.test/1.png".to_string()),
            }
        );
        assert!(!listed[1].has_external_id);
        assert_eq!(listed[1].store_name.as_deref(), Some("Hotel Dos"));
        assert_eq!(listed[2].store_name, None);
        assert!(parse_pos_list(&json!({}), &names).is_empty());

        assert_eq!(
            store_external_id_of(&stores, "11").as_deref(),
            Some("PXSOLSTx")
        );
        assert_eq!(store_external_id_of(&stores, "12"), None);
        assert_eq!(store_external_id_of(&stores, "99"), None);
    }

    #[test]
    fn a_pos_saved_without_qr_urls_still_loads_and_switching_replaces_it() {
        let old = json!({QR_POS_METADATA_KEY: {
            "seller_id": SELLER, "store_id": "1", "external_store_id": "S",
            "pos_id": "2", "external_pos_id": "P"
        }, "keep": true});
        let loaded = existing_pos(Some(&old), SELLER).expect("old metadata parses");
        assert_eq!(loaded.qr_image, None);

        let merged = merge_pos_into_metadata(Some(old), &pos()).unwrap();
        assert_eq!(merged["keep"], true);
        assert_eq!(merged[QR_POS_METADATA_KEY]["pos_id"], "2002");
        assert_eq!(
            merged[QR_POS_METADATA_KEY]["qr_image"],
            "https://mp.test/qr.png"
        );
    }
}
