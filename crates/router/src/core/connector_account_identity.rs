//! TEMPORARY: remove after the processor account identity backfill (odd/tasks/processor-account-identity.md)
//!
//! Reads the processor account a connector account is connected to, with the connector
//! account's own credentials. Only the display name and, for Mercado Pago, the account's
//! identity fields leave this module: never a credential or a processor body. The email and the
//! identification number are `Secret`s, so API events mask them, and the logs carry only the
//! connector name, the connector account id and the processor's status code.

use api_models::connector_account_identity::{
    ConnectorAccountIdentityError, ConnectorAccountIdentityResponse,
    ConnectorAccountIdentitySource, MercadopagoAccountIdentification, MercadopagoAccountIdentity,
};
use common_utils::{
    id_type,
    request::{Method, Request, RequestBuilder},
};
use external_services::http_client;
use hyperswitch_domain_models::router_data::ConnectorAuthType;
use hyperswitch_masking::{Mask, PeekInterface, Secret};
use router_env::logger;
use serde_json::Value;

use crate::{
    core::errors::{self, RouterResponse, StorageErrorExt},
    routes::SessionState,
    services::ApplicationResponse,
};

/// Processor calls give up after this many seconds and answer `unavailable`.
const PROCESSOR_TIMEOUT_SECS: u64 = 10;

// ============================================================================
// Pure logic
// ============================================================================

/// The identity source of a connector, by its name.
pub(crate) fn source_for(connector_name: &str) -> ConnectorAccountIdentitySource {
    match connector_name {
        "mercadopago" => ConnectorAccountIdentitySource::MercadopagoUsersMe,
        "stripe" => ConnectorAccountIdentitySource::StripeAccount,
        "wompi" => ConnectorAccountIdentitySource::WompiMerchant,
        "fiservemea" => ConnectorAccountIdentitySource::FiservStore,
        _ => ConnectorAccountIdentitySource::Unsupported,
    }
}

/// The one credential the source needs, when the connector account has the expected shape:
/// the access token (Mercado Pago) or secret key (Stripe), Wompi's public key (never the
/// private one) and Fiserv IPG's store id.
pub(crate) fn credential_for(
    source: ConnectorAccountIdentitySource,
    auth: &ConnectorAuthType,
) -> Option<Secret<String>> {
    match (source, auth) {
        (
            ConnectorAccountIdentitySource::MercadopagoUsersMe
            | ConnectorAccountIdentitySource::StripeAccount,
            ConnectorAuthType::HeaderKey { api_key },
        ) => Some(api_key.clone()),
        (
            ConnectorAccountIdentitySource::WompiMerchant,
            ConnectorAuthType::SignatureKey { api_key, .. },
        ) => Some(api_key.clone()),
        (
            ConnectorAccountIdentitySource::FiservStore,
            ConnectorAuthType::SignatureKey { key1, .. },
        ) => Some(key1.clone()),
        _ => None,
    }
}

/// The trimmed string at `pointer`, when there is a non-blank one.
fn text_at(body: &Value, pointer: &str) -> Option<String> {
    body.pointer(pointer)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .map(str::to_string)
}

/// Mercado Pago `/users/me`: `company.brand_name`, else the `nickname`; never the email or the
/// person's names.
pub(crate) fn mercadopago_display_name(body: &Value) -> Option<String> {
    text_at(body, "/company/brand_name").or_else(|| text_at(body, "/nickname"))
}

/// Mercado Pago `/users/me` identity fields; `None` without a numeric `id`. Each text field is
/// trimmed and `None` when blank.
pub(crate) fn mercadopago_account(body: &Value) -> Option<MercadopagoAccountIdentity> {
    let id = body.get("id").and_then(Value::as_u64)?;
    Some(MercadopagoAccountIdentity {
        id,
        nickname: text_at(body, "/nickname"),
        corporate_name: text_at(body, "/company/corporate_name"),
        email: text_at(body, "/email").map(Secret::new),
        identification: mercadopago_identification(body),
    })
}

/// `identification` `{type, number}`, `None` when either is missing or blank. The number is kept
/// exactly as Mercado Pago returns it.
fn mercadopago_identification(body: &Value) -> Option<MercadopagoAccountIdentification> {
    let identification_type = text_at(body, "/identification/type")?;
    let number = match body.pointer("/identification/number")? {
        Value::String(number) if !number.trim().is_empty() => number.clone(),
        Value::Number(number) => number.to_string(),
        _ => return None,
    };
    Some(MercadopagoAccountIdentification {
        identification_type,
        number: Secret::new(number),
    })
}

/// What the processor answered: the display name and, for Mercado Pago, the account.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct ProcessorIdentity {
    pub(crate) display_name: Option<String>,
    pub(crate) account: Option<MercadopagoAccountIdentity>,
}

impl ProcessorIdentity {
    fn named(display_name: Option<String>) -> Self {
        Self {
            display_name,
            account: None,
        }
    }
}

pub(crate) fn mercadopago_identity(body: &Value) -> ProcessorIdentity {
    ProcessorIdentity {
        display_name: mercadopago_display_name(body),
        account: mercadopago_account(body),
    }
}

/// Stripe `/v1/account`: the dashboard display name, else the business profile name.
pub(crate) fn stripe_display_name(body: &Value) -> Option<String> {
    text_at(body, "/settings/dashboard/display_name")
        .or_else(|| text_at(body, "/business_profile/name"))
}

/// Wompi `/merchants/{public_key}`: `data.name`, else `data.legal_name` (which can be a
/// person's name, so only when there is no merchant name).
pub(crate) fn wompi_display_name(body: &Value) -> Option<String> {
    text_at(body, "/data/name").or_else(|| text_at(body, "/data/legal_name"))
}

/// Fiserv IPG: the store id itself.
pub(crate) fn fiserv_display_name(store_id: &str) -> Option<String> {
    Some(store_id.trim())
        .filter(|store_id| !store_id.is_empty())
        .map(str::to_string)
}

pub(crate) fn stripe_account_url(base_url: &str) -> String {
    format!("{}/v1/account", base_url.trim_end_matches('/'))
}

/// Wompi's merchant URL on the host the public key belongs to (`pub_test_` sandbox,
/// `pub_prod_` production), like the Wompi connector. Any other key, or one with characters
/// that would change the path, gives no URL.
pub(crate) fn wompi_merchant_url(
    public_key: &str,
    production_base_url: &str,
    sandbox_base_url: &str,
) -> Option<String> {
    let (base_url, rest) = if let Some(rest) = public_key.strip_prefix("pub_test_") {
        (sandbox_base_url, rest)
    } else if let Some(rest) = public_key.strip_prefix("pub_prod_") {
        (production_base_url, rest)
    } else {
        return None;
    };
    let well_formed = !rest.is_empty()
        && rest
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || character == '_');
    well_formed.then(|| format!("{}/merchants/{public_key}", base_url.trim_end_matches('/')))
}

/// Without a display name a supported source answers `unavailable` with no account; an
/// unsupported connector has no name and no error. Only Mercado Pago carries an account.
pub(crate) fn identity_response(
    connector_name: &str,
    source: ConnectorAccountIdentitySource,
    identity: ProcessorIdentity,
) -> ConnectorAccountIdentityResponse {
    let ProcessorIdentity {
        display_name,
        account,
    } = identity;
    let (display_name, account, error) = match (source, display_name) {
        (ConnectorAccountIdentitySource::Unsupported, _) => (None, None, None),
        (_, None) => (None, None, Some(ConnectorAccountIdentityError::Unavailable)),
        (ConnectorAccountIdentitySource::MercadopagoUsersMe, Some(name)) => {
            (Some(name), account, None)
        }
        (_, Some(name)) => (Some(name), None, None),
    };
    ConnectorAccountIdentityResponse {
        connector_name: connector_name.to_string(),
        display_name,
        source,
        account,
        error,
    }
}

// ============================================================================
// Processor HTTP
// ============================================================================

/// Why a processor call gave no body. Holds only the status code, so it is safe to log.
#[derive(Debug)]
enum FetchFailure {
    Request,
    Status(u16),
    Body(u16),
}

impl FetchFailure {
    fn reason(&self) -> &'static str {
        match self {
            Self::Request => "request_failed",
            Self::Status(_) => "error_status",
            Self::Body(_) => "unreadable_body",
        }
    }

    fn status_code(&self) -> Option<u16> {
        match self {
            Self::Request => None,
            Self::Status(status) | Self::Body(status) => Some(*status),
        }
    }
}

/// A GET whose token only travels in a masked header; the body is never logged.
async fn fetch_json(
    state: &SessionState,
    url: &str,
    bearer_token: Option<&Secret<String>>,
) -> Result<Value, FetchFailure> {
    let mut headers = vec![("Accept".to_string(), "application/json".to_string().into())];
    if let Some(token) = bearer_token {
        headers.push((
            "Authorization".to_string(),
            format!("Bearer {}", token.peek()).into_masked(),
        ));
    }
    let request: Request = RequestBuilder::new()
        .method(Method::Get)
        .url(url)
        .attach_default_headers()
        .headers(headers)
        .build();

    let response =
        http_client::send_request(&state.conf.proxy, request, Some(PROCESSOR_TIMEOUT_SECS))
            .await
            .map_err(|_| FetchFailure::Request)?;
    let status = response.status().as_u16();
    if !(200..300).contains(&status) {
        return Err(FetchFailure::Status(status));
    }
    let bytes = response
        .bytes()
        .await
        .map_err(|_| FetchFailure::Body(status))?;
    serde_json::from_slice(&bytes).map_err(|_| FetchFailure::Body(status))
}

async fn lookup_identity(
    state: &SessionState,
    source: ConnectorAccountIdentitySource,
    credential: &Secret<String>,
) -> Result<ProcessorIdentity, FetchFailure> {
    let connectors = &state.conf.connectors;
    match source {
        ConnectorAccountIdentitySource::MercadopagoUsersMe => {
            let url = format!(
                "{}/users/me",
                connectors.mercadopago.base_url.trim_end_matches('/')
            );
            let body = fetch_json(state, &url, Some(credential)).await?;
            Ok(mercadopago_identity(&body))
        }
        ConnectorAccountIdentitySource::StripeAccount => {
            let url = stripe_account_url(&connectors.stripe.base_url);
            let body = fetch_json(state, &url, Some(credential)).await?;
            Ok(ProcessorIdentity::named(stripe_display_name(&body)))
        }
        ConnectorAccountIdentitySource::WompiMerchant => {
            // The merchant endpoint is public: the public key goes in the path, no token.
            let Some(url) = wompi_merchant_url(
                credential.peek(),
                &connectors.wompi.base_url,
                &connectors.wompi.secondary_base_url,
            ) else {
                return Ok(ProcessorIdentity::default());
            };
            let body = fetch_json(state, &url, None).await?;
            Ok(ProcessorIdentity::named(wompi_display_name(&body)))
        }
        ConnectorAccountIdentitySource::FiservStore => Ok(ProcessorIdentity::named(
            fiserv_display_name(credential.peek()),
        )),
        ConnectorAccountIdentitySource::Unsupported => Ok(ProcessorIdentity::default()),
    }
}

// ============================================================================
// Core
// ============================================================================

pub async fn retrieve_connector_account_identity(
    state: SessionState,
    merchant_id: &id_type::MerchantId,
    merchant_connector_id: &id_type::MerchantConnectorAccountId,
) -> RouterResponse<ConnectorAccountIdentityResponse> {
    let db = state.store.as_ref();
    let key_store = db
        .get_merchant_key_store_by_merchant_id(merchant_id, &db.get_master_key().to_vec().into())
        .await
        .to_not_found_response(errors::ApiErrorResponse::MerchantAccountNotFound)?;
    // Scoped to the merchant in the path: another merchant's connector account is not found.
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

    let connector_name = mca.connector_name.clone();
    let source = source_for(&connector_name);
    if source == ConnectorAccountIdentitySource::Unsupported {
        return Ok(ApplicationResponse::Json(identity_response(
            &connector_name,
            source,
            ProcessorIdentity::default(),
        )));
    }

    // Credentials that cannot be read, or of another shape, are an unavailable identity.
    let credential = mca
        .get_connector_account_details()
        .ok()
        .and_then(|auth| credential_for(source, &auth));
    let identity = match credential {
        None => {
            logger::warn!(
                connector = %connector_name,
                merchant_connector_id = %merchant_connector_id.get_string_repr(),
                "processor account identity unavailable: unexpected credentials"
            );
            ProcessorIdentity::default()
        }
        Some(credential) => match lookup_identity(&state, source, &credential).await {
            Ok(identity) => {
                if identity.display_name.is_none() {
                    logger::warn!(
                        connector = %connector_name,
                        merchant_connector_id = %merchant_connector_id.get_string_repr(),
                        "processor account identity unavailable: no name in the answer"
                    );
                } else if source == ConnectorAccountIdentitySource::MercadopagoUsersMe
                    && identity.account.is_none()
                {
                    logger::warn!(
                        connector = %connector_name,
                        merchant_connector_id = %merchant_connector_id.get_string_repr(),
                        "processor account identity without an account: no id in the answer"
                    );
                }
                identity
            }
            Err(failure) => {
                logger::warn!(
                    connector = %connector_name,
                    merchant_connector_id = %merchant_connector_id.get_string_repr(),
                    reason = failure.reason(),
                    status_code = ?failure.status_code(),
                    "processor account identity unavailable: processor call failed"
                );
                ProcessorIdentity::default()
            }
        },
    };

    Ok(ApplicationResponse::Json(identity_response(
        &connector_name,
        source,
        identity,
    )))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    const WOMPI_PRODUCTION: &str = "https://production.wompi.co/v1";
    const WOMPI_SANDBOX: &str = "https://sandbox.wompi.co/v1";

    fn header_key(api_key: &str) -> ConnectorAuthType {
        ConnectorAuthType::HeaderKey {
            api_key: Secret::new(api_key.to_string()),
        }
    }

    fn signature_key(api_key: &str, key1: &str, api_secret: &str) -> ConnectorAuthType {
        ConnectorAuthType::SignatureKey {
            api_key: Secret::new(api_key.to_string()),
            key1: Secret::new(key1.to_string()),
            api_secret: Secret::new(api_secret.to_string()),
        }
    }

    fn peeked(secret: Option<Secret<String>>) -> Option<String> {
        secret.map(|secret| secret.peek().clone())
    }

    // ---- source_for ------------------------------------------------------

    #[test]
    fn source_for_maps_each_supported_connector() {
        assert_eq!(
            source_for("mercadopago"),
            ConnectorAccountIdentitySource::MercadopagoUsersMe
        );
        assert_eq!(
            source_for("stripe"),
            ConnectorAccountIdentitySource::StripeAccount
        );
        assert_eq!(
            source_for("wompi"),
            ConnectorAccountIdentitySource::WompiMerchant
        );
        assert_eq!(
            source_for("fiservemea"),
            ConnectorAccountIdentitySource::FiservStore
        );
    }

    #[test]
    fn source_for_any_other_connector_is_unsupported() {
        for name in ["paypal", "payway", "izipay", "fiserv", "adyen", ""] {
            assert_eq!(
                source_for(name),
                ConnectorAccountIdentitySource::Unsupported,
                "{name}"
            );
        }
    }

    // ---- credential_for --------------------------------------------------

    #[test]
    fn credential_for_mercadopago_and_stripe_is_the_header_key() {
        assert_eq!(
            peeked(credential_for(
                ConnectorAccountIdentitySource::MercadopagoUsersMe,
                &header_key("APP_USR-token")
            )),
            Some("APP_USR-token".to_string())
        );
        assert_eq!(
            peeked(credential_for(
                ConnectorAccountIdentitySource::StripeAccount,
                &header_key("sk_test_123")
            )),
            Some("sk_test_123".to_string())
        );
    }

    #[test]
    fn credential_for_wompi_is_the_public_key_never_the_private_one() {
        assert_eq!(
            peeked(credential_for(
                ConnectorAccountIdentitySource::WompiMerchant,
                &signature_key("pub_prod_abc", "prv_prod_xyz", "prod_integrity_x")
            )),
            Some("pub_prod_abc".to_string())
        );
    }

    #[test]
    fn credential_for_fiserv_is_the_store_id() {
        assert_eq!(
            peeked(credential_for(
                ConnectorAccountIdentitySource::FiservStore,
                &signature_key("api-key", "4530042983", "api-secret")
            )),
            Some("4530042983".to_string())
        );
    }

    #[test]
    fn credential_for_an_unexpected_shape_is_none() {
        assert!(credential_for(
            ConnectorAccountIdentitySource::MercadopagoUsersMe,
            &signature_key("a", "b", "c")
        )
        .is_none());
        assert!(credential_for(
            ConnectorAccountIdentitySource::WompiMerchant,
            &header_key("pub_prod_abc")
        )
        .is_none());
        assert!(credential_for(
            ConnectorAccountIdentitySource::FiservStore,
            &header_key("4530042983")
        )
        .is_none());
        assert!(credential_for(
            ConnectorAccountIdentitySource::Unsupported,
            &header_key("anything")
        )
        .is_none());
    }

    // ---- Mercado Pago ----------------------------------------------------

    #[test]
    fn mercadopago_display_name_prefers_the_company_brand_name() {
        let body = json!({
            "id": 123456,
            "nickname": "TELEBITONLINE",
            "email": "owner@example.com",
            "first_name": "Owner",
            "last_name": "Person",
            "company": { "brand_name": "PXSOL S.A.S." }
        });
        assert_eq!(
            mercadopago_display_name(&body),
            Some("PXSOL S.A.S.".to_string())
        );
    }

    #[test]
    fn mercadopago_display_name_falls_back_to_the_nickname() {
        let empty_brand = json!({
            "nickname": "DOEN4430340",
            "company": { "brand_name": "  " }
        });
        assert_eq!(
            mercadopago_display_name(&empty_brand),
            Some("DOEN4430340".to_string())
        );
        let null_company = json!({ "nickname": "DOEN4430340", "company": null });
        assert_eq!(
            mercadopago_display_name(&null_company),
            Some("DOEN4430340".to_string())
        );
        let no_company = json!({ "nickname": "DOEN4430340" });
        assert_eq!(
            mercadopago_display_name(&no_company),
            Some("DOEN4430340".to_string())
        );
    }

    #[test]
    fn mercadopago_display_name_never_uses_email_or_person_names() {
        let body = json!({
            "id": 1,
            "email": "owner@example.com",
            "first_name": "Owner",
            "last_name": "Person",
            "nickname": "  ",
            "company": { "brand_name": "" }
        });
        assert_eq!(mercadopago_display_name(&body), None);
        assert_eq!(
            mercadopago_display_name(&json!({ "email": "owner@example.com" })),
            None
        );
        assert_eq!(mercadopago_display_name(&Value::Null), None);
    }

    #[test]
    fn mercadopago_display_name_trims() {
        assert_eq!(
            mercadopago_display_name(&json!({ "company": { "brand_name": " enzods " } })),
            Some("enzods".to_string())
        );
    }

    // ---- Stripe ----------------------------------------------------------

    #[test]
    fn stripe_display_name_prefers_the_dashboard_display_name() {
        let live_shape = json!({
            "id": "acct_1",
            "object": "account",
            "email": "owner@example.com",
            "business_profile": { "name": null },
            "settings": { "dashboard": { "display_name": "Atlas Account" } }
        });
        assert_eq!(
            stripe_display_name(&live_shape),
            Some("Atlas Account".to_string())
        );
        let both = json!({
            "business_profile": { "name": "Hotel Business" },
            "settings": { "dashboard": { "display_name": "Hotel Dashboard" } }
        });
        assert_eq!(
            stripe_display_name(&both),
            Some("Hotel Dashboard".to_string())
        );
    }

    #[test]
    fn stripe_display_name_falls_back_to_the_business_profile_name() {
        let null_dashboard = json!({
            "business_profile": { "name": "Hotel Business" },
            "settings": { "dashboard": { "display_name": null } }
        });
        assert_eq!(
            stripe_display_name(&null_dashboard),
            Some("Hotel Business".to_string())
        );
        let empty_dashboard = json!({
            "business_profile": { "name": "Hotel Business" },
            "settings": { "dashboard": { "display_name": "" } }
        });
        assert_eq!(
            stripe_display_name(&empty_dashboard),
            Some("Hotel Business".to_string())
        );
        let no_settings = json!({ "business_profile": { "name": "Hotel Business" } });
        assert_eq!(
            stripe_display_name(&no_settings),
            Some("Hotel Business".to_string())
        );
    }

    #[test]
    fn stripe_display_name_without_names_is_none_and_ignores_the_email() {
        let body = json!({
            "email": "owner@example.com",
            "business_profile": { "name": null },
            "settings": { "dashboard": {} }
        });
        assert_eq!(stripe_display_name(&body), None);
        assert_eq!(stripe_display_name(&Value::Null), None);
    }

    #[test]
    fn stripe_account_url_joins_the_configured_base() {
        assert_eq!(
            stripe_account_url("https://api.stripe.com/"),
            "https://api.stripe.com/v1/account"
        );
        assert_eq!(
            stripe_account_url("https://api.stripe.com"),
            "https://api.stripe.com/v1/account"
        );
    }

    // ---- Wompi -----------------------------------------------------------

    #[test]
    fn wompi_display_name_prefers_the_name() {
        let body = json!({
            "data": {
                "id": 1,
                "name": "ECOTERMALES SAN VICENTE SA",
                "legal_name": "Juan Perez",
                "email": "owner@example.com"
            }
        });
        assert_eq!(
            wompi_display_name(&body),
            Some("ECOTERMALES SAN VICENTE SA".to_string())
        );
        let other = json!({ "data": { "name": "Artesanias Paba", "legal_name": "Ana Paba" } });
        assert_eq!(
            wompi_display_name(&other),
            Some("Artesanias Paba".to_string())
        );
    }

    #[test]
    fn wompi_display_name_falls_back_to_the_legal_name_only_without_a_name() {
        let body = json!({ "data": { "name": " ", "legal_name": "Artesanias Paba SAS" } });
        assert_eq!(
            wompi_display_name(&body),
            Some("Artesanias Paba SAS".to_string())
        );
        let no_name = json!({ "data": { "legal_name": "Artesanias Paba SAS" } });
        assert_eq!(
            wompi_display_name(&no_name),
            Some("Artesanias Paba SAS".to_string())
        );
        // Top-level fields are not Wompi's merchant shape.
        assert_eq!(wompi_display_name(&json!({ "name": "Not data" })), None);
    }

    #[test]
    fn wompi_display_name_without_names_is_none() {
        assert_eq!(
            wompi_display_name(&json!({ "data": { "email": "owner@example.com" } })),
            None
        );
        assert_eq!(wompi_display_name(&json!({ "error": {} })), None);
    }

    #[test]
    fn wompi_merchant_url_uses_the_host_of_the_key_environment() {
        assert_eq!(
            wompi_merchant_url("pub_test_abc123", WOMPI_PRODUCTION, WOMPI_SANDBOX),
            Some("https://sandbox.wompi.co/v1/merchants/pub_test_abc123".to_string())
        );
        assert_eq!(
            wompi_merchant_url("pub_prod_abc123", WOMPI_PRODUCTION, WOMPI_SANDBOX),
            Some("https://production.wompi.co/v1/merchants/pub_prod_abc123".to_string())
        );
    }

    #[test]
    fn wompi_merchant_url_rejects_other_keys() {
        for key in [
            "prv_prod_abc",
            "abc",
            "",
            "pub_prod_",
            "pub_prod_abc/../x",
            "pub_test_a?b=c",
        ] {
            assert_eq!(
                wompi_merchant_url(key, WOMPI_PRODUCTION, WOMPI_SANDBOX),
                None,
                "{key}"
            );
        }
    }

    // ---- Fiserv ----------------------------------------------------------

    #[test]
    fn fiserv_display_name_is_the_bare_store_id() {
        assert_eq!(
            fiserv_display_name(" 4530042983 "),
            Some("4530042983".to_string())
        );
        assert_eq!(fiserv_display_name("  "), None);
    }

    // ---- Mercado Pago account ---------------------------------------------

    /// The shape of a real `/users/me` answer (values replaced where they identify someone).
    fn users_me_fixture() -> Value {
        json!({
            "id": 69260492,
            "nickname": "TELEBITONLINE",
            "first_name": "Owner",
            "last_name": "Person",
            "email": " owner@example.com ",
            "identification": { "type": "CUIT", "number": "30712345678" },
            "company": {
                "brand_name": "PXSOL S.A.S.",
                "corporate_name": "PXSOL  S.A.S.",
                "identification": "30712345678"
            },
            "site_id": "MLA"
        })
    }

    fn account_json(account: &Option<MercadopagoAccountIdentity>) -> Option<Value> {
        account
            .as_ref()
            .and_then(|account| serde_json::to_value(account).ok())
    }

    #[test]
    fn mercadopago_account_maps_every_field() {
        assert_eq!(
            account_json(&mercadopago_account(&users_me_fixture())),
            Some(json!({
                "id": 69260492,
                "nickname": "TELEBITONLINE",
                "corporate_name": "PXSOL  S.A.S.",
                "email": "owner@example.com",
                "identification": { "type": "CUIT", "number": "30712345678" }
            }))
        );
    }

    #[test]
    fn mercadopago_account_empty_or_missing_fields_are_null() {
        let empty = json!({
            "id": 1,
            "nickname": "  ",
            "email": "",
            "company": { "brand_name": "Brand", "corporate_name": " " },
            "identification": { "type": "", "number": "" }
        });
        assert_eq!(
            account_json(&mercadopago_account(&empty)),
            Some(json!({
                "id": 1,
                "nickname": null,
                "corporate_name": null,
                "email": null,
                "identification": null
            }))
        );
        let missing = json!({ "id": 2, "company": null, "identification": null });
        assert_eq!(
            account_json(&mercadopago_account(&missing)),
            Some(json!({
                "id": 2,
                "nickname": null,
                "corporate_name": null,
                "email": null,
                "identification": null
            }))
        );
    }

    #[test]
    fn mercadopago_identification_is_null_when_the_type_or_the_number_is_missing() {
        for identification in [
            json!({ "number": "30712345678" }),
            json!({ "type": "  ", "number": "30712345678" }),
            json!({ "type": "CUIT" }),
            json!({ "type": "CUIT", "number": null }),
            json!({ "type": "CUIT", "number": " " }),
            json!({ "type": "CUIT", "number": {} }),
        ] {
            let body = json!({ "id": 1, "identification": identification.clone() });
            assert_eq!(
                mercadopago_account(&body).map(|account| account.identification),
                Some(None),
                "{identification}"
            );
        }
    }

    #[test]
    fn mercadopago_identification_number_is_kept_as_mercadopago_returns_it() {
        let dashed = json!({
            "id": 1,
            "identification": { "type": " DNI ", "number": "20-12345678-9" }
        });
        assert_eq!(
            account_json(&mercadopago_account(&dashed))
                .and_then(|account| account.get("identification").cloned()),
            Some(json!({ "type": "DNI", "number": "20-12345678-9" }))
        );
        let numeric =
            json!({ "id": 1, "identification": { "type": "CUIT", "number": 30712345678_u64 } });
        assert_eq!(
            account_json(&mercadopago_account(&numeric))
                .and_then(|account| account.get("identification").cloned()),
            Some(json!({ "type": "CUIT", "number": "30712345678" }))
        );
    }

    #[test]
    fn mercadopago_account_without_a_numeric_id_is_none() {
        for body in [
            json!({ "nickname": "TELEBITONLINE" }),
            json!({ "id": null, "nickname": "TELEBITONLINE" }),
            json!({ "id": "69260492", "nickname": "TELEBITONLINE" }),
            json!({ "id": -1, "nickname": "TELEBITONLINE" }),
            Value::Null,
        ] {
            assert!(mercadopago_account(&body).is_none(), "{body}");
        }
    }

    #[test]
    fn mercadopago_identity_has_the_display_name_and_the_account() {
        let identity = mercadopago_identity(&users_me_fixture());
        assert_eq!(identity.display_name, Some("PXSOL S.A.S.".to_string()));
        assert_eq!(identity.account.map(|account| account.id), Some(69260492));
    }

    // ---- Response --------------------------------------------------------

    fn named(display_name: &str) -> ProcessorIdentity {
        ProcessorIdentity {
            display_name: Some(display_name.to_string()),
            account: None,
        }
    }

    #[test]
    fn identity_response_with_a_name_has_no_error() {
        let response = identity_response(
            "stripe",
            ConnectorAccountIdentitySource::StripeAccount,
            named("Hotel"),
        );
        assert_eq!(
            serde_json::to_value(&response).ok(),
            Some(json!({
                "connector_name": "stripe",
                "display_name": "Hotel",
                "source": "stripe_account",
                "account": null,
                "error": null
            }))
        );
    }

    #[test]
    fn identity_response_for_mercadopago_carries_the_account() {
        let response = identity_response(
            "mercadopago",
            ConnectorAccountIdentitySource::MercadopagoUsersMe,
            mercadopago_identity(&users_me_fixture()),
        );
        assert_eq!(
            serde_json::to_value(&response).ok(),
            Some(json!({
                "connector_name": "mercadopago",
                "display_name": "PXSOL S.A.S.",
                "source": "mercadopago_users_me",
                "account": {
                    "id": 69260492,
                    "nickname": "TELEBITONLINE",
                    "corporate_name": "PXSOL  S.A.S.",
                    "email": "owner@example.com",
                    "identification": { "type": "CUIT", "number": "30712345678" }
                },
                "error": null
            }))
        );
    }

    #[test]
    fn identity_response_masks_the_email_and_the_identification_number_in_api_events() {
        let response = identity_response(
            "mercadopago",
            ConnectorAccountIdentitySource::MercadopagoUsersMe,
            mercadopago_identity(&users_me_fixture()),
        );
        let masked = hyperswitch_masking::masked_serialize(&response)
            .map(|value| value.to_string())
            .unwrap_or_default();
        assert!(masked.contains("TELEBITONLINE"), "{masked}");
        assert!(!masked.contains("owner@example.com"), "{masked}");
        assert!(!masked.contains("30712345678"), "{masked}");
        let debug = format!("{response:?}");
        assert!(!debug.contains("owner@example.com"), "{debug}");
        assert!(!debug.contains("30712345678"), "{debug}");
    }

    #[test]
    fn identity_response_without_a_name_is_unavailable_and_drops_the_account() {
        let response = identity_response(
            "mercadopago",
            ConnectorAccountIdentitySource::MercadopagoUsersMe,
            mercadopago_identity(&json!({ "id": 1, "email": "owner@example.com" })),
        );
        assert_eq!(
            serde_json::to_value(&response).ok(),
            Some(json!({
                "connector_name": "mercadopago",
                "display_name": null,
                "source": "mercadopago_users_me",
                "account": null,
                "error": "unavailable"
            }))
        );
        let failed = identity_response(
            "wompi",
            ConnectorAccountIdentitySource::WompiMerchant,
            ProcessorIdentity::default(),
        );
        assert_eq!(
            serde_json::to_value(&failed).ok(),
            Some(json!({
                "connector_name": "wompi",
                "display_name": null,
                "source": "wompi_merchant",
                "account": null,
                "error": "unavailable"
            }))
        );
    }

    #[test]
    fn identity_response_carries_an_account_only_for_mercadopago() {
        let stray_account = mercadopago_identity(&users_me_fixture());
        for (connector, source) in [
            ("stripe", ConnectorAccountIdentitySource::StripeAccount),
            ("wompi", ConnectorAccountIdentitySource::WompiMerchant),
            ("fiservemea", ConnectorAccountIdentitySource::FiservStore),
        ] {
            let response = identity_response(connector, source, stray_account.clone());
            assert_eq!(response.account, None, "{connector}");
            assert_eq!(
                response.display_name,
                Some("PXSOL S.A.S.".to_string()),
                "{connector}"
            );
        }
    }

    #[test]
    fn identity_response_for_an_unsupported_connector_has_no_error() {
        let response = identity_response(
            "paypal",
            ConnectorAccountIdentitySource::Unsupported,
            mercadopago_identity(&users_me_fixture()),
        );
        assert_eq!(
            serde_json::to_value(&response).ok(),
            Some(json!({
                "connector_name": "paypal",
                "display_name": null,
                "source": "unsupported",
                "account": null,
                "error": null
            }))
        );
        let fiserv = identity_response(
            "fiservemea",
            ConnectorAccountIdentitySource::FiservStore,
            named("4530042983"),
        );
        assert_eq!(
            serde_json::to_value(&fiserv).ok(),
            Some(json!({
                "connector_name": "fiservemea",
                "display_name": "4530042983",
                "source": "fiserv_store",
                "account": null,
                "error": null
            }))
        );
    }
}
