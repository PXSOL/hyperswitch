use std::collections::HashMap;

use base64::Engine;
use common_enums::enums;
use common_utils::{
    crypto::{GenerateDigest, Sha256},
    errors::CustomResult,
    ext_traits::ByteSliceExt,
    request::Method,
    types::MinorUnit,
};
use error_stack::{report, ResultExt};
use hyperswitch_domain_models::{
    payment_method_data::{PaymentMethodData, WalletData},
    router_data::{AccessToken, ConnectorAuthType, ErrorResponse, RouterData},
    router_request_types::{PaymentsAuthorizeData, ResponseId},
    router_response_types::{PaymentsResponseData, RedirectForm},
    types::PaymentsAuthorizeRouterData,
};
use hyperswitch_interfaces::errors;
use masking::{ExposeInterface, PeekInterface, Secret};
use serde::{Deserialize, Serialize};

use crate::{
    types::ResponseRouterData,
    utils::{PaymentsAuthorizeRequestData, RouterData as _},
};

// Wompi documents a 3-minute buyer retry window for hosted-checkout payments
// (a DECLINED/ERROR attempt can be followed by an APPROVED one on the same
// `reference`). 5 minutes gives a safety margin above the documented window so
// a slow webhook/PSync race never reports a premature terminal failure.
pub(super) const HOSTED_RETRY_WINDOW_SECONDS: i64 = 5 * 60;

// Wompi's merchant `installments_config` caps installments at 36 (undocumented,
// observed against the live merchant during exploration).
const MAX_INSTALLMENTS: i32 = 36;

pub struct WompiRouterData<T> {
    pub amount: MinorUnit,
    pub router_data: T,
}

impl<T> From<(MinorUnit, T)> for WompiRouterData<T> {
    fn from((amount, router_data): (MinorUnit, T)) -> Self {
        Self {
            amount,
            router_data,
        }
    }
}

// ============================================================================
// Auth
// ============================================================================

pub struct WompiAuthType {
    pub public_key: Secret<String>,
    pub private_key: Secret<String>,
    pub integrity_secret: Secret<String>,
}

impl TryFrom<&ConnectorAuthType> for WompiAuthType {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::SignatureKey {
                api_key,
                key1,
                api_secret,
            } => Ok(Self {
                public_key: api_key.clone(),
                private_key: key1.clone(),
                integrity_secret: api_secret.clone(),
            }),
            _ => Err(errors::ConnectorError::FailedToObtainAuthType.into()),
        }
    }
}

/// Wompi environment, derived from the public key prefix (never from
/// `test_mode`): the sandbox and production hosts reject a key issued for the
/// other environment with a 401, so deriving the host from the key itself
/// makes that class of error impossible instead of merely detectable.
pub(super) enum WompiEnvironment {
    Sandbox,
    Production,
}

/// Resolves which host to call from the auth keys alone, and cross-checks the
/// private key's prefix against the public key's: a mismatched pair (e.g. a
/// sandbox public key with a production private key) is a merchant
/// configuration error, not a runtime error, so it is rejected up front
/// instead of surfacing as a confusing 401 from Wompi later.
pub(super) fn resolve_environment(
    auth: &WompiAuthType,
) -> CustomResult<WompiEnvironment, errors::ConnectorError> {
    let public_key = auth.public_key.clone().expose();
    let private_key = auth.private_key.clone().expose();

    let environment = if public_key.starts_with("pub_test_") {
        WompiEnvironment::Sandbox
    } else if public_key.starts_with("pub_prod_") {
        WompiEnvironment::Production
    } else {
        return Err(report!(errors::ConnectorError::InvalidConnectorConfig {
            config: "public key must start with pub_test_ or pub_prod_"
        }));
    };

    let private_key_matches = match environment {
        WompiEnvironment::Sandbox => private_key.starts_with("prv_test_"),
        WompiEnvironment::Production => private_key.starts_with("prv_prod_"),
    };

    if !private_key_matches {
        return Err(report!(errors::ConnectorError::InvalidConnectorConfig {
            config: "private key environment does not match the public key environment"
        }));
    }

    Ok(environment)
}

// ============================================================================
// Status mapping (shared by Authorize and PSync responses over flow `F`)
// ============================================================================

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "UPPERCASE")]
pub enum WompiTransactionStatus {
    Pending,
    Approved,
    Declined,
    Error,
    Voided,
    // Never map an unrecognized status to a terminal state (in particular
    // never to Charged): an unknown value from Wompi must keep the attempt
    // syncable, not silently mark it paid.
    #[serde(other)]
    #[default]
    Unknown,
}

pub(super) fn map_wompi_status(status: WompiTransactionStatus) -> enums::AttemptStatus {
    match status {
        WompiTransactionStatus::Pending | WompiTransactionStatus::Unknown => {
            enums::AttemptStatus::Pending
        }
        WompiTransactionStatus::Approved => enums::AttemptStatus::Charged,
        WompiTransactionStatus::Declined | WompiTransactionStatus::Error => {
            enums::AttemptStatus::Failure
        }
        WompiTransactionStatus::Voided => enums::AttemptStatus::Voided,
    }
}

// ============================================================================
// Installments (same tolerant contract as fiservemea's metadata extraction)
// ============================================================================

/// Extracts `installments` from `metadata`, tolerant of the value being a
/// JSON number or a numeric string. Defaults to 1, and rejects anything
/// outside 1..=36 (Wompi's observed `installments_config` ceiling) rather
/// than forwarding an invalid value to the connector.
pub(super) fn extract_installments(
    metadata: Option<&serde_json::Value>,
) -> CustomResult<i32, errors::ConnectorError> {
    let raw = metadata
        .and_then(|value| value.as_object())
        .and_then(|object| object.get("installments"));

    let installments = match raw {
        None => 1,
        Some(value) => value
            .as_i64()
            .or_else(|| value.as_str().and_then(|s| s.trim().parse::<i64>().ok()))
            .and_then(|n| i32::try_from(n).ok())
            .ok_or(errors::ConnectorError::InvalidDataFormat {
                field_name: "metadata.installments",
            })?,
    };

    if !(1..=MAX_INSTALLMENTS).contains(&installments) {
        return Err(errors::ConnectorError::InvalidDataFormat {
            field_name: "metadata.installments",
        }
        .into());
    }

    Ok(installments)
}

// ============================================================================
// Integrity signature (§5): sha256_hex(reference + amount_in_cents + currency
// [+ expiration_time] + integrity_secret). Wompi never sends `expiration_time`
// from this connector, so that optional segment is always empty.
// ============================================================================

pub(super) fn build_integrity_signature(
    reference: &str,
    amount_in_cents: MinorUnit,
    currency: &str,
    integrity_secret: &Secret<String>,
) -> CustomResult<String, errors::ConnectorError> {
    let amount_str = amount_in_cents.get_amount_as_i64().to_string();
    let message = format!(
        "{reference}{amount_str}{currency}{}",
        integrity_secret.clone().expose()
    );
    let digest = Sha256
        .generate_digest(message.as_bytes())
        .change_context(errors::ConnectorError::RequestEncodingFailed)?;
    Ok(hex::encode(digest))
}

// ============================================================================
// JWT `exp` claim (unpacked without signature verification: this connector
// only relays Wompi's own presigned tokens back to Wompi, it never trusts a
// third party with them, so verifying the signature buys nothing here beyond
// what `GET /merchants` already guaranteed by returning them).
// ============================================================================

fn decode_jwt_exp(token: &str) -> Option<i64> {
    let payload_segment = token.split('.').nth(1)?;
    let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload_segment)
        .ok()?;
    let payload: serde_json::Value = serde_json::from_slice(&payload_bytes).ok()?;
    payload.get("exp")?.as_i64()
}

const ACCESS_TOKEN_TTL_FALLBACK_SECONDS: i64 = 300;
const ACCESS_TOKEN_TTL_MIN_SECONDS: i64 = 60;
const ACCESS_TOKEN_TTL_MAX_SECONDS: i64 = 3600;

/// TTL for the packed access token: the minimum `exp` of the two presigned
/// JWTs minus now, clamped to a sane range. Falls back to a conservative 300s
/// when neither token's `exp` claim can be parsed, so a decoding hiccup never
/// caches the pair forever (max clamp) nor refetches on every request (an
/// unclamped near-zero/negative TTL).
fn access_token_ttl_seconds(acceptance_token: &str, personal_auth_token: &str) -> i64 {
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let min_exp = [
        decode_jwt_exp(acceptance_token),
        decode_jwt_exp(personal_auth_token),
    ]
    .into_iter()
    .flatten()
    .min();

    match min_exp {
        Some(exp) => (exp - now).clamp(ACCESS_TOKEN_TTL_MIN_SECONDS, ACCESS_TOKEN_TTL_MAX_SECONDS),
        None => ACCESS_TOKEN_TTL_FALLBACK_SECONDS,
    }
}

/// The two presigned tokens Wompi requires on every transaction, packed into
/// `AccessToken.token` (the only field the generic AccessTokenAuth cache
/// gives connectors) as compact JSON, and unpacked again in Authorize.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WompiPackedAcceptanceTokens {
    pub acceptance_token: Secret<String>,
    pub accept_personal_auth: Secret<String>,
}

pub(super) fn unpack_access_token(
    access_token: &AccessToken,
) -> CustomResult<WompiPackedAcceptanceTokens, errors::ConnectorError> {
    access_token
        .token
        .clone()
        .expose()
        .as_bytes()
        .parse_struct("WompiPackedAcceptanceTokens")
        .change_context(errors::ConnectorError::FailedToObtainAuthType)
}

// ============================================================================
// AccessTokenAuth — GET /merchants/{public_key}
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WompiMerchantResponse {
    pub data: WompiMerchantData,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WompiMerchantData {
    pub active: bool,
    pub presigned_acceptance: WompiPresignedToken,
    pub presigned_personal_data_auth: WompiPresignedToken,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WompiPresignedToken {
    pub acceptance_token: Secret<String>,
}

impl<F, T> TryFrom<ResponseRouterData<F, WompiMerchantResponse, T, AccessToken>>
    for RouterData<F, T, AccessToken>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<F, WompiMerchantResponse, T, AccessToken>,
    ) -> Result<Self, Self::Error> {
        let merchant = item.response.data;

        if !merchant.active {
            return Err(report!(errors::ConnectorError::InvalidConnectorConfig {
                config: "Wompi merchant is not active for this public key"
            }));
        }

        let acceptance_token = merchant.presigned_acceptance.acceptance_token.expose();
        let accept_personal_auth = merchant
            .presigned_personal_data_auth
            .acceptance_token
            .expose();

        let expires = access_token_ttl_seconds(&acceptance_token, &accept_personal_auth);

        let packed = WompiPackedAcceptanceTokens {
            acceptance_token: Secret::new(acceptance_token),
            accept_personal_auth: Secret::new(accept_personal_auth),
        };
        let packed_json = serde_json::to_string(&packed)
            .change_context(errors::ConnectorError::ResponseHandlingFailed)?;

        Ok(Self {
            response: Ok(AccessToken {
                token: Secret::new(packed_json),
                expires,
            }),
            ..item.data
        })
    }
}

// ============================================================================
// PaymentMethodToken — POST /tokens/cards
// ============================================================================

#[derive(Debug, Serialize)]
pub struct WompiCardTokenRequest {
    pub number: cards::CardNumber,
    pub cvc: Secret<String>,
    pub exp_month: Secret<String>,
    pub exp_year: Secret<String>,
    pub card_holder: Secret<String>,
}

impl TryFrom<&hyperswitch_domain_models::types::TokenizationRouterData> for WompiCardTokenRequest {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: &hyperswitch_domain_models::types::TokenizationRouterData,
    ) -> Result<Self, Self::Error> {
        let card = match &item.request.payment_method_data {
            PaymentMethodData::Card(card) => card,
            _ => {
                return Err(errors::ConnectorError::NotImplemented(
                    "payment method for Wompi tokenization".to_string(),
                )
                .into())
            }
        };

        let card_holder = card
            .card_holder_name
            .clone()
            .or_else(|| item.get_optional_billing_full_name())
            .ok_or(errors::ConnectorError::MissingRequiredField {
                field_name: "card_holder_name",
            })?;

        // Wompi rejects a card holder shorter than 5 characters.
        if card_holder.clone().expose().trim().chars().count() < 5 {
            return Err(errors::ConnectorError::MissingRequiredField {
                field_name: "card_holder_name (must be at least 5 characters)",
            }
            .into());
        }

        let exp_month = format_two_digits(card.card_exp_month.clone().expose());
        let exp_year = last_two_digits(card.card_exp_year.clone().expose());

        Ok(Self {
            number: card.card_number.clone(),
            cvc: card.card_cvc.clone(),
            exp_month: Secret::new(exp_month),
            exp_year: Secret::new(exp_year),
            card_holder,
        })
    }
}

fn format_two_digits(value: String) -> String {
    let trimmed = value.trim().to_string();
    if trimmed.len() == 1 {
        format!("0{trimmed}")
    } else {
        trimmed
    }
}

fn last_two_digits(value: String) -> String {
    let trimmed = value.trim();
    if trimmed.len() > 2 {
        trimmed[trimmed.len() - 2..].to_string()
    } else {
        trimmed.to_string()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WompiCardTokenResponse {
    pub data: WompiCardTokenData,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WompiCardTokenData {
    pub id: String,
}

impl<F, T> TryFrom<ResponseRouterData<F, WompiCardTokenResponse, T, PaymentsResponseData>>
    for RouterData<F, T, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<F, WompiCardTokenResponse, T, PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            response: Ok(PaymentsResponseData::TokenizationResponse {
                token: item.response.data.id,
            }),
            ..item.data
        })
    }
}

// ============================================================================
// Authorize — card: POST /transactions ; hosted checkout: GET /merchants/{key}
// ============================================================================

pub fn is_hosted_checkout(payment_method_data: &PaymentMethodData) -> bool {
    matches!(
        payment_method_data,
        PaymentMethodData::Wallet(WalletData::WompiCheckout {})
    )
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum WompiPaymentMethodType {
    Card,
}

#[derive(Debug, Serialize)]
pub struct WompiCardPaymentMethod {
    #[serde(rename = "type")]
    pub payment_method_type: WompiPaymentMethodType,
    pub token: Secret<String>,
    pub installments: i32,
}

#[derive(Debug, Serialize)]
pub struct WompiCustomerData {
    pub full_name: Secret<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone_number: Option<Secret<String>>,
}

#[derive(Debug, Serialize)]
pub struct WompiTransactionsRequest {
    pub amount_in_cents: MinorUnit,
    pub currency: String,
    pub signature: String,
    pub customer_email: common_utils::pii::Email,
    pub reference: String,
    pub payment_method: WompiCardPaymentMethod,
    pub acceptance_token: Secret<String>,
    pub accept_personal_auth: Secret<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub customer_data: Option<WompiCustomerData>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip: Option<Secret<String, common_utils::pii::IpAddress>>,
}

impl TryFrom<&WompiRouterData<&PaymentsAuthorizeRouterData>> for WompiTransactionsRequest {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(item: &WompiRouterData<&PaymentsAuthorizeRouterData>) -> Result<Self, Self::Error> {
        let router_data = item.router_data;

        if router_data.request.currency != enums::Currency::COP {
            return Err(errors::ConnectorError::CurrencyNotSupported {
                message: router_data.request.currency.to_string(),
                connector: "wompi",
            }
            .into());
        }

        // Manual capture would require a separate Capture call, which this
        // connector does not implement; auto-capture is the only mode Wompi
        // is wired for here (`get_supported_payment_methods` already declares
        // only `Automatic`, this is a defensive second gate).
        if !router_data.request.is_auto_capture()? {
            return Err(errors::ConnectorError::NotSupported {
                message: "manual capture".to_string(),
                connector: "wompi",
            }
            .into());
        }

        // Card 3DS (`is_three_ds`) is not implemented yet. Charging a `three_ds`
        // request without authentication would silently drop the liability shift
        // the caller asked for, so it is rejected instead of downgraded.
        if router_data.auth_type == enums::AuthenticationType::ThreeDs {
            return Err(errors::ConnectorError::NotSupported {
                message: "3DS card payments".to_string(),
                connector: "wompi",
            }
            .into());
        }

        let access_token = router_data
            .access_token
            .as_ref()
            .ok_or(errors::ConnectorError::FailedToObtainAuthType)?;
        let packed = unpack_access_token(access_token)?;

        let card_token = match router_data.payment_method_token.clone() {
            Some(hyperswitch_domain_models::router_data::PaymentMethodToken::Token(token)) => token,
            _ => {
                return Err(errors::ConnectorError::MissingRequiredField {
                    field_name: "payment_method_token",
                }
                .into())
            }
        };

        let installments = extract_installments(router_data.request.metadata.as_ref())?;

        let reference = router_data.connector_request_reference_id.clone();
        let amount_in_cents = item.amount;
        let signature = build_integrity_signature(
            &reference,
            amount_in_cents,
            "COP",
            &WompiAuthType::try_from(&router_data.connector_auth_type)?.integrity_secret,
        )?;

        let customer_email = router_data
            .request
            .get_optional_email()
            .or_else(|| router_data.get_optional_billing_email())
            .ok_or(errors::ConnectorError::MissingRequiredField {
                field_name: "email",
            })?;

        let full_name = router_data.get_optional_billing_full_name();
        let phone_number = router_data.get_optional_billing_phone_number();
        let customer_data = full_name.map(|full_name| WompiCustomerData {
            full_name,
            phone_number,
        });

        let ip = router_data.request.get_ip_address_as_optional();

        Ok(Self {
            amount_in_cents,
            currency: "COP".to_string(),
            signature,
            customer_email,
            reference,
            payment_method: WompiCardPaymentMethod {
                payment_method_type: WompiPaymentMethodType::Card,
                token: card_token,
                installments,
            },
            acceptance_token: packed.acceptance_token,
            accept_personal_auth: packed.accept_personal_auth,
            customer_data,
            ip,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WompiTransactionResponse {
    pub data: WompiTransactionData,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WompiTransactionData {
    pub id: String,
    pub reference: String,
    pub status: WompiTransactionStatus,
    pub status_message: Option<String>,
    #[serde(default)]
    pub created_at: Option<String>,
    #[serde(default)]
    pub finalized_at: Option<String>,
}

/// Shared by card Authorize and card PSync: both receive the same
/// `{"data": Transaction}` shape and map it identically.
impl<F, T> TryFrom<ResponseRouterData<F, WompiTransactionResponse, T, PaymentsResponseData>>
    for RouterData<F, T, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<F, WompiTransactionResponse, T, PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        let transaction = item.response.data;
        Ok(transaction_to_router_data(
            transaction,
            item.data,
            item.http_code,
        ))
    }
}

/// Builds the RouterData outcome for one Wompi transaction: Charged/Pending/
/// Voided become a `TransactionResponse`, DECLINED/ERROR become an `Err`
/// carrying the connector's own reason so it is never lost even though Wompi
/// answers a decline with HTTP 2xx.
fn transaction_to_router_data<F, T>(
    transaction: WompiTransactionData,
    data: RouterData<F, T, PaymentsResponseData>,
    http_code: u16,
) -> RouterData<F, T, PaymentsResponseData> {
    let status = map_wompi_status(transaction.status);
    let response = if matches!(status, enums::AttemptStatus::Failure) {
        Err(ErrorResponse {
            status_code: http_code,
            code: format!("{:?}", transaction.status).to_uppercase(),
            message: transaction
                .status_message
                .clone()
                .unwrap_or_else(|| "Transaction declined".to_string()),
            reason: transaction.status_message,
            attempt_status: Some(status),
            connector_transaction_id: Some(transaction.id),
            network_advice_code: None,
            network_decline_code: None,
            network_error_message: None,
            connector_metadata: None,
        })
    } else {
        Ok(PaymentsResponseData::TransactionResponse {
            resource_id: ResponseId::ConnectorTransactionId(transaction.id),
            redirection_data: Box::new(None),
            mandate_reference: Box::new(None),
            connector_metadata: None,
            network_txn_id: None,
            connector_response_reference_id: Some(transaction.reference),
            incremental_authorization_allowed: None,
            charges: None,
        })
    };

    RouterData {
        status,
        response,
        ..data
    }
}

// ============================================================================
// Authorize — hosted checkout redirect (GET https://checkout.wompi.co/p/)
// ============================================================================

pub const WOMPI_CHECKOUT_ENDPOINT: &str = "https://checkout.wompi.co/p/";

/// Authorize is the only flow that produces this response shape (a merchant
/// lookup used to build the hosted-checkout redirect), so this conversion is
/// written concretely against `PaymentsAuthorizeData` rather than behind a
/// speculative generic trait.
impl
    TryFrom<
        ResponseRouterData<
            hyperswitch_domain_models::router_flow_types::payments::Authorize,
            WompiMerchantResponse,
            PaymentsAuthorizeData,
            PaymentsResponseData,
        >,
    > for PaymentsAuthorizeRouterData
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            hyperswitch_domain_models::router_flow_types::payments::Authorize,
            WompiMerchantResponse,
            PaymentsAuthorizeData,
            PaymentsResponseData,
        >,
    ) -> Result<Self, Self::Error> {
        if !item.response.data.active {
            return Err(report!(errors::ConnectorError::InvalidConnectorConfig {
                config: "Wompi merchant is not active for this public key"
            }));
        }

        if item.data.request.currency != enums::Currency::COP {
            return Err(errors::ConnectorError::CurrencyNotSupported {
                message: item.data.request.currency.to_string(),
                connector: "wompi",
            }
            .into());
        }
        let currency = "COP".to_string();

        let reference = item.data.connector_request_reference_id.clone();
        let amount_in_cents = item.data.request.minor_amount;
        let integrity_secret =
            WompiAuthType::try_from(&item.data.connector_auth_type)?.integrity_secret;
        let signature =
            build_integrity_signature(&reference, amount_in_cents, &currency, &integrity_secret)?;

        let public_key = WompiAuthType::try_from(&item.data.connector_auth_type)?
            .public_key
            .expose();

        let mut form_fields = HashMap::new();
        form_fields.insert("public-key".to_string(), public_key);
        form_fields.insert("currency".to_string(), currency);
        form_fields.insert(
            "amount-in-cents".to_string(),
            amount_in_cents.get_amount_as_i64().to_string(),
        );
        form_fields.insert("reference".to_string(), reference.clone());
        form_fields.insert("signature:integrity".to_string(), signature);

        // The buyer returns to Hyperswitch's own redirect-response endpoint
        // (router_return_url) exactly as the MercadoPago Checkout Pro hosted
        // flow does: that endpoint triggers PSync before forwarding to the
        // merchant, so the payment is confirmed against Wompi's API rather
        // than trusted from the redirect's `?id=` query string.
        if let Some(redirect_url) = item.data.request.router_return_url.clone() {
            form_fields.insert("redirect-url".to_string(), redirect_url);
        }
        if let Some(email) = item.data.request.get_optional_email() {
            form_fields.insert("customer-data:email".to_string(), email.peek().to_string());
        }
        if let Some(full_name) = item.data.get_optional_billing_full_name() {
            form_fields.insert("customer-data:full-name".to_string(), full_name.expose());
        }
        if let Some(phone_number) = item.data.get_optional_billing_phone_number() {
            form_fields.insert(
                "customer-data:phone-number".to_string(),
                phone_number.expose(),
            );
        }

        let redirection_data = RedirectForm::Form {
            endpoint: WOMPI_CHECKOUT_ENDPOINT.to_string(),
            method: Method::Get,
            form_fields,
        };

        Ok(Self {
            status: enums::AttemptStatus::AuthenticationPending,
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::NoResponseId,
                redirection_data: Box::new(Some(redirection_data)),
                mandate_reference: Box::new(None),
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: Some(reference),
                incremental_authorization_allowed: None,
                charges: None,
            }),
            ..item.data
        })
    }
}

// ============================================================================
// PSync — card: GET /transactions/{id} ; hosted: GET /transactions?reference=
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WompiSearchResponse {
    #[serde(deserialize_with = "deserialize_one_or_many")]
    pub data: Vec<WompiTransactionData>,
}

/// `GET /transactions?reference=` answers `{"data": [..]}`, but a verified incoming
/// webhook hands PSync's `handle_response` the webhook's single transaction
/// (`{"data": {..}}`, see `get_webhook_resource_object`), so the hosted-checkout
/// parser must accept both shapes.
fn deserialize_one_or_many<'de, D>(deserializer: D) -> Result<Vec<WompiTransactionData>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum OneOrMany {
        Many(Vec<WompiTransactionData>),
        One(Box<WompiTransactionData>),
    }
    Ok(match OneOrMany::deserialize(deserializer)? {
        OneOrMany::Many(transactions) => transactions,
        OneOrMany::One(transaction) => vec![*transaction],
    })
}

/// Pure (testable) selection over the hosted-checkout search results: never
/// trusts anything about ordering from Wompi, always re-derives "newest" from
/// timestamps so the buyer-retry race (DECLINED then APPROVED, same
/// reference) resolves correctly regardless of array order.
pub(super) fn select_hosted_transaction(
    transactions: Vec<WompiTransactionData>,
    now: time::OffsetDateTime,
) -> HostedSyncOutcome {
    if let Some(approved) = transactions
        .iter()
        .find(|t| t.status == WompiTransactionStatus::Approved)
    {
        return HostedSyncOutcome::Charged {
            id: approved.id.clone(),
            reference: approved.reference.clone(),
        };
    }

    if let Some(pending) = transactions
        .iter()
        .find(|t| t.status == WompiTransactionStatus::Pending)
    {
        return HostedSyncOutcome::Pending {
            id: Some(pending.id.clone()),
        };
    }

    if let Some(voided) = transactions
        .iter()
        .find(|t| t.status == WompiTransactionStatus::Voided)
    {
        return HostedSyncOutcome::Voided {
            id: voided.id.clone(),
            reference: voided.reference.clone(),
        };
    }

    let mut terminal_failures: Vec<&WompiTransactionData> = transactions
        .iter()
        .filter(|t| {
            matches!(
                t.status,
                WompiTransactionStatus::Declined | WompiTransactionStatus::Error
            )
        })
        .collect();
    terminal_failures
        .sort_by_key(|t| parse_timestamp(t.finalized_at.as_deref().or(t.created_at.as_deref())));

    if let Some(newest) = terminal_failures.last() {
        let reference_time = parse_timestamp(
            newest
                .finalized_at
                .as_deref()
                .or(newest.created_at.as_deref()),
        );
        let is_final = match reference_time {
            Some(t) => (now.unix_timestamp() - t.unix_timestamp()) >= HOSTED_RETRY_WINDOW_SECONDS,
            // No parseable timestamp at all: cannot prove the retry window
            // has passed, so keep waiting rather than guessing a terminal
            // status.
            None => false,
        };
        if is_final {
            return HostedSyncOutcome::Failure {
                id: newest.id.clone(),
                status: newest.status,
                status_message: newest
                    .status_message
                    .clone()
                    .unwrap_or_else(|| "Transaction declined".to_string()),
            };
        }
    }

    HostedSyncOutcome::Pending { id: None }
}

fn parse_timestamp(value: Option<&str>) -> Option<time::OffsetDateTime> {
    time::OffsetDateTime::parse(value?, &time::format_description::well_known::Rfc3339).ok()
}

#[derive(Debug, Clone, PartialEq)]
pub(super) enum HostedSyncOutcome {
    Charged {
        id: String,
        reference: String,
    },
    Voided {
        id: String,
        reference: String,
    },
    Pending {
        id: Option<String>,
    },
    Failure {
        id: String,
        status: WompiTransactionStatus,
        status_message: String,
    },
}

impl<F, T> TryFrom<ResponseRouterData<F, WompiSearchResponse, T, PaymentsResponseData>>
    for RouterData<F, T, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<F, WompiSearchResponse, T, PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        let now = time::OffsetDateTime::now_utc();
        let outcome = select_hosted_transaction(item.response.data, now);

        let (status, response) = match outcome {
            HostedSyncOutcome::Charged { id, reference } => (
                enums::AttemptStatus::Charged,
                Ok(PaymentsResponseData::TransactionResponse {
                    resource_id: ResponseId::ConnectorTransactionId(id),
                    redirection_data: Box::new(None),
                    mandate_reference: Box::new(None),
                    connector_metadata: None,
                    network_txn_id: None,
                    connector_response_reference_id: Some(reference),
                    incremental_authorization_allowed: None,
                    charges: None,
                }),
            ),
            HostedSyncOutcome::Voided { id, reference } => (
                enums::AttemptStatus::Voided,
                Ok(PaymentsResponseData::TransactionResponse {
                    resource_id: ResponseId::ConnectorTransactionId(id),
                    redirection_data: Box::new(None),
                    mandate_reference: Box::new(None),
                    connector_metadata: None,
                    network_txn_id: None,
                    connector_response_reference_id: Some(reference),
                    incremental_authorization_allowed: None,
                    charges: None,
                }),
            ),
            HostedSyncOutcome::Pending { id } => (
                enums::AttemptStatus::AuthenticationPending,
                Ok(PaymentsResponseData::TransactionResponse {
                    resource_id: id
                        .map(ResponseId::ConnectorTransactionId)
                        .unwrap_or(ResponseId::NoResponseId),
                    redirection_data: Box::new(None),
                    mandate_reference: Box::new(None),
                    connector_metadata: None,
                    network_txn_id: None,
                    connector_response_reference_id: None,
                    incremental_authorization_allowed: None,
                    charges: None,
                }),
            ),
            HostedSyncOutcome::Failure {
                id,
                status,
                status_message,
            } => (
                enums::AttemptStatus::Failure,
                Err(ErrorResponse {
                    status_code: item.http_code,
                    code: format!("{status:?}").to_uppercase(),
                    message: status_message.clone(),
                    reason: Some(status_message),
                    attempt_status: Some(enums::AttemptStatus::Failure),
                    connector_transaction_id: Some(id),
                    network_advice_code: None,
                    network_decline_code: None,
                    network_error_message: None,
                    connector_metadata: None,
                }),
            ),
        };

        Ok(Self {
            status,
            response,
            ..item.data
        })
    }
}

// ============================================================================
// Errors
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WompiErrorResponse {
    pub error: WompiErrorBody,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WompiErrorBody {
    #[serde(rename = "type")]
    pub error_type: String,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub code: Option<String>,
    #[serde(default)]
    pub messages: Option<serde_json::Value>,
}

impl WompiErrorBody {
    /// Flattens `messages` (a field -> [message, ...] map, per the
    /// documented 422 shape) and combines it with `reason`/`code` so neither
    /// the documented nor the undocumented (NOT_FOUND/MERCHANT_NOT_FOUND)
    /// error shape loses information.
    pub fn combined_reason(&self) -> String {
        let mut parts: Vec<String> = Vec::new();
        if let Some(reason) = &self.reason {
            parts.push(reason.clone());
        }
        if let Some(code) = &self.code {
            parts.push(code.clone());
        }
        if let Some(messages) = &self.messages {
            if let Some(object) = messages.as_object() {
                for (field, value) in object {
                    let joined = value
                        .as_array()
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|v| v.as_str())
                                .collect::<Vec<_>>()
                                .join(", ")
                        })
                        .unwrap_or_default();
                    parts.push(format!("{field}: {joined}"));
                }
            }
        }
        if parts.is_empty() {
            self.error_type.clone()
        } else {
            parts.join("; ")
        }
    }
}

// ============================================================================
// Webhooks — transaction.updated
// ============================================================================

#[derive(Debug, Clone, Deserialize)]
pub struct WompiWebhookBody {
    pub event: String,
    pub data: serde_json::Value,
    pub signature: WompiWebhookSignature,
    pub timestamp: i64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct WompiWebhookSignature {
    pub properties: Vec<String>,
    pub checksum: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct WompiWebhookTransaction {
    pub id: String,
    pub reference: String,
    pub status: WompiTransactionStatus,
}

/// Extracts the value at a dot path (e.g. `transaction.status`) relative to
/// `data`, stringifying scalars the way they appear in Wompi's checksum
/// example (a number is its decimal digits, not JSON-quoted). Property paths
/// are never hardcoded elsewhere: the whole point of `signature.properties`
/// being dynamic is that Wompi may add/reorder them at any time.
pub(super) fn extract_property_value(data: &serde_json::Value, dot_path: &str) -> String {
    let mut current = data;
    for segment in dot_path.split('.') {
        match current.get(segment) {
            Some(next) => current = next,
            None => return String::new(),
        }
    }
    match current {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::Bool(b) => b.to_string(),
        _ => String::new(),
    }
}

/// Builds the checksum message: concatenated property values, in
/// `signature.properties` order, followed by the timestamp, followed by the
/// events secret. The secret is folded into the *message* rather than passed
/// separately: `common_utils::crypto::Sha256::verify_signature` ignores its
/// `secret` argument entirely (it only hashes `msg` and compares raw bytes),
/// so a plain SHA-256 webhook scheme only authenticates anything if the
/// secret is part of what gets hashed.
pub(super) fn build_webhook_message(webhook: &WompiWebhookBody, events_secret: &[u8]) -> Vec<u8> {
    let mut message = webhook
        .signature
        .properties
        .iter()
        .map(|path| extract_property_value(&webhook.data, path))
        .collect::<Vec<_>>()
        .join("");
    message.push_str(&webhook.timestamp.to_string());
    let mut message = message.into_bytes();
    message.extend_from_slice(events_secret);
    message
}

#[cfg(test)]
mod tests {
    use super::*;

    // ------------------------------------------------------------------
    // Integrity signature (§5)
    // ------------------------------------------------------------------

    // Wompi's public docs example (§5 truncates the secret when quoting it). The
    // expected digest is the `signature` of the docs' own `POST /transactions`
    // example, which was computed over this same input.
    #[test]
    fn integrity_signature_matches_official_example() {
        let secret = Secret::new("prod_integrity_Z5mMke9x0k8gpErbDqwrJXMqsI6SFli6".to_string());
        let signature = build_integrity_signature(
            "sk8-438k4-xmxm392-sn2m",
            MinorUnit::new(2490000),
            "COP",
            &secret,
        )
        .expect("signature computation must not fail");

        assert_eq!(
            signature,
            "37c8407747e595535433ef8f6a811d853cd943046624a0ec04662b17bbf33bf5"
        );
    }

    // ------------------------------------------------------------------
    // Webhook checksum (§13.4). The doc's events secret is truncated
    // ("prod_events_OcHn…"), so this uses a synthetic secret and an
    // independently computed expected checksum (`python3 -c "import
    // hashlib; print(hashlib.sha256(b'...').hexdigest())"`), stated in the
    // comment above the constant below.
    // ------------------------------------------------------------------

    // sha256("1234-1610641025-49201" + "APPROVED" + "4490000" + "1530291411"
    //        + "prod_events_test_synthetic_secret_0001")
    const SYNTHETIC_WEBHOOK_SECRET: &str = "prod_events_test_synthetic_secret_0001";
    const SYNTHETIC_WEBHOOK_CHECKSUM: &str =
        "310edcec6d424d1bf4715d17f5716e06f1291628075df8ac8180018c8e163566";

    fn sample_webhook_body() -> WompiWebhookBody {
        WompiWebhookBody {
            event: "transaction.updated".to_string(),
            data: serde_json::json!({
                "transaction": {
                    "id": "1234-1610641025-49201",
                    "amount_in_cents": 4490000,
                    "reference": "MZQ3X2DE2SMX",
                    "status": "APPROVED",
                }
            }),
            signature: WompiWebhookSignature {
                properties: vec![
                    "transaction.id".to_string(),
                    "transaction.status".to_string(),
                    "transaction.amount_in_cents".to_string(),
                ],
                checksum: SYNTHETIC_WEBHOOK_CHECKSUM.to_string(),
            },
            timestamp: 1530291411,
        }
    }

    #[test]
    fn webhook_checksum_matches_synthetic_example() {
        let webhook = sample_webhook_body();
        let message = build_webhook_message(&webhook, SYNTHETIC_WEBHOOK_SECRET.as_bytes());
        let digest = Sha256
            .generate_digest(&message)
            .expect("digest must succeed");
        assert_eq!(hex::encode(digest), SYNTHETIC_WEBHOOK_CHECKSUM);
    }

    #[test]
    fn webhook_checksum_rejects_tampered_amount() {
        let mut webhook = sample_webhook_body();
        webhook.data["transaction"]["amount_in_cents"] = serde_json::json!(1);
        let message = build_webhook_message(&webhook, SYNTHETIC_WEBHOOK_SECRET.as_bytes());
        let digest = Sha256
            .generate_digest(&message)
            .expect("digest must succeed");
        assert_ne!(hex::encode(digest), SYNTHETIC_WEBHOOK_CHECKSUM);
    }

    #[test]
    fn webhook_property_extraction_is_dynamic_not_hardcoded() {
        let data = serde_json::json!({"transaction": {"status": "DECLINED", "id": "abc"}});
        assert_eq!(
            extract_property_value(&data, "transaction.status"),
            "DECLINED"
        );
        assert_eq!(extract_property_value(&data, "transaction.id"), "abc");
        // A path that does not exist yields an empty string rather than panicking.
        assert_eq!(
            extract_property_value(&data, "transaction.missing.path"),
            ""
        );
    }

    // ------------------------------------------------------------------
    // Environment resolution by key prefix
    // ------------------------------------------------------------------

    fn auth(public: &str, private: &str) -> WompiAuthType {
        WompiAuthType {
            public_key: Secret::new(public.to_string()),
            private_key: Secret::new(private.to_string()),
            integrity_secret: Secret::new("test_integrity_secret".to_string()),
        }
    }

    #[test]
    fn environment_resolves_to_sandbox_for_test_keys() {
        let a = auth("pub_test_abc", "prv_test_xyz");
        assert!(matches!(
            resolve_environment(&a).unwrap(),
            WompiEnvironment::Sandbox
        ));
    }

    #[test]
    fn environment_resolves_to_production_for_prod_keys() {
        let a = auth("pub_prod_abc", "prv_prod_xyz");
        assert!(matches!(
            resolve_environment(&a).unwrap(),
            WompiEnvironment::Production
        ));
    }

    #[test]
    fn environment_rejects_mismatched_key_pair() {
        let a = auth("pub_test_abc", "prv_prod_xyz");
        assert!(resolve_environment(&a).is_err());
    }

    #[test]
    fn environment_rejects_garbage_public_key() {
        let a = auth("not_a_wompi_key", "prv_test_xyz");
        assert!(resolve_environment(&a).is_err());
    }

    // ------------------------------------------------------------------
    // Installments extraction
    // ------------------------------------------------------------------

    #[test]
    fn installments_default_to_one_when_absent() {
        assert_eq!(extract_installments(None).unwrap(), 1);
    }

    #[test]
    fn installments_accept_json_number() {
        let metadata = serde_json::json!({"installments": 6});
        assert_eq!(extract_installments(Some(&metadata)).unwrap(), 6);
    }

    #[test]
    fn installments_accept_numeric_string() {
        let metadata = serde_json::json!({"installments": "12"});
        assert_eq!(extract_installments(Some(&metadata)).unwrap(), 12);
    }

    #[test]
    fn installments_reject_out_of_range() {
        let metadata = serde_json::json!({"installments": 37});
        assert!(extract_installments(Some(&metadata)).is_err());

        let metadata_zero = serde_json::json!({"installments": 0});
        assert!(extract_installments(Some(&metadata_zero)).is_err());
    }

    #[test]
    fn installments_reject_unparsable_value() {
        let metadata = serde_json::json!({"installments": "not-a-number"});
        assert!(extract_installments(Some(&metadata)).is_err());
    }

    // ------------------------------------------------------------------
    // Status mapping
    // ------------------------------------------------------------------

    #[test]
    fn status_mapping_covers_every_terminal_and_nonterminal_state() {
        assert_eq!(
            map_wompi_status(WompiTransactionStatus::Pending),
            enums::AttemptStatus::Pending
        );
        assert_eq!(
            map_wompi_status(WompiTransactionStatus::Approved),
            enums::AttemptStatus::Charged
        );
        assert_eq!(
            map_wompi_status(WompiTransactionStatus::Declined),
            enums::AttemptStatus::Failure
        );
        assert_eq!(
            map_wompi_status(WompiTransactionStatus::Error),
            enums::AttemptStatus::Failure
        );
        assert_eq!(
            map_wompi_status(WompiTransactionStatus::Voided),
            enums::AttemptStatus::Voided
        );
        // An unrecognized status must never resolve to Charged.
        assert_eq!(
            map_wompi_status(WompiTransactionStatus::Unknown),
            enums::AttemptStatus::Pending
        );
    }

    #[test]
    fn unknown_status_value_falls_back_via_serde_other() {
        let parsed: WompiTransactionStatus = serde_json::from_str("\"SOME_NEW_STATUS\"").unwrap();
        assert_eq!(parsed, WompiTransactionStatus::Unknown);
    }

    // ------------------------------------------------------------------
    // Hosted PSync selection (pure function over an injected `now`)
    // ------------------------------------------------------------------

    fn tx(
        id: &str,
        status: WompiTransactionStatus,
        finalized_at: Option<&str>,
    ) -> WompiTransactionData {
        WompiTransactionData {
            id: id.to_string(),
            reference: "REF-1".to_string(),
            status,
            status_message: Some("declined by issuer".to_string()),
            created_at: finalized_at.map(|s| s.to_string()),
            finalized_at: finalized_at.map(|s| s.to_string()),
        }
    }

    fn now() -> time::OffsetDateTime {
        time::OffsetDateTime::parse(
            "2024-01-01T00:10:00.000Z",
            &time::format_description::well_known::Rfc3339,
        )
        .unwrap()
    }

    #[test]
    fn approved_wins_over_a_prior_declined_on_retry() {
        let transactions = vec![
            tx(
                "1",
                WompiTransactionStatus::Declined,
                Some("2024-01-01T00:01:00.000Z"),
            ),
            tx("2", WompiTransactionStatus::Approved, None),
        ];
        let outcome = select_hosted_transaction(transactions, now());
        assert_eq!(
            outcome,
            HostedSyncOutcome::Charged {
                id: "2".to_string(),
                reference: "REF-1".to_string(),
            }
        );
    }

    #[test]
    fn declined_inside_retry_window_stays_pending() {
        // now() is 00:10:00; this declined transaction finalized at 00:09:00,
        // only 60s ago — well inside the 5-minute retry window.
        let transactions = vec![tx(
            "1",
            WompiTransactionStatus::Declined,
            Some("2024-01-01T00:09:00.000Z"),
        )];
        let outcome = select_hosted_transaction(transactions, now());
        assert_eq!(outcome, HostedSyncOutcome::Pending { id: None });
    }

    #[test]
    fn declined_outside_retry_window_fails() {
        // finalized at 00:00:00, 10 minutes before now() — past the 5-minute
        // window, so this is treated as final.
        let transactions = vec![tx(
            "1",
            WompiTransactionStatus::Declined,
            Some("2024-01-01T00:00:00.000Z"),
        )];
        let outcome = select_hosted_transaction(transactions, now());
        assert_eq!(
            outcome,
            HostedSyncOutcome::Failure {
                id: "1".to_string(),
                status: WompiTransactionStatus::Declined,
                status_message: "declined by issuer".to_string(),
            }
        );
    }

    #[test]
    fn search_response_accepts_a_list_and_a_single_webhook_transaction() {
        let list: WompiSearchResponse = serde_json::from_value(serde_json::json!({
            "data": [
                {"id": "1", "reference": "ref_1", "status": "DECLINED"},
                {"id": "2", "reference": "ref_1", "status": "APPROVED"}
            ]
        }))
        .expect("search list must parse");
        assert_eq!(list.data.len(), 2);

        // Shape produced by `get_webhook_resource_object` for a verified webhook.
        let single: WompiSearchResponse = serde_json::from_value(serde_json::json!({
            "data": {"id": "3", "reference": "ref_1", "status": "APPROVED"}
        }))
        .expect("single webhook transaction must parse");
        assert_eq!(single.data.len(), 1);
        assert_eq!(single.data[0].status, WompiTransactionStatus::Approved);
    }

    #[test]
    fn wompi_checkout_wallet_maps_to_the_hosted_checkout_flow() {
        use api_models::payments::GetPaymentMethodType;

        let wallet: api_models::payments::WalletData =
            serde_json::from_value(serde_json::json!({ "wompi_checkout": {} }))
                .expect("wompi_checkout must deserialize");
        assert_eq!(
            wallet.get_payment_method_type(),
            enums::PaymentMethodType::Wompi
        );
        assert_eq!(
            enums::PaymentMethod::from(enums::PaymentMethodType::Wompi),
            enums::PaymentMethod::Wallet
        );
        assert!(is_hosted_checkout(&PaymentMethodData::Wallet(
            WalletData::from(wallet)
        )));
    }

    #[test]
    fn empty_search_result_stays_pending() {
        let outcome = select_hosted_transaction(vec![], now());
        assert_eq!(outcome, HostedSyncOutcome::Pending { id: None });
    }

    #[test]
    fn pending_transaction_is_reported_as_pending_with_its_id_promoted() {
        let transactions = vec![tx("1", WompiTransactionStatus::Pending, None)];
        let outcome = select_hosted_transaction(transactions, now());
        assert_eq!(
            outcome,
            HostedSyncOutcome::Pending {
                id: Some("1".to_string())
            }
        );
    }

    // ------------------------------------------------------------------
    // JWT `exp` parsing + TTL fallback
    // ------------------------------------------------------------------

    fn make_jwt(exp: i64) -> String {
        let payload = serde_json::json!({"exp": exp}).to_string();
        let payload_b64 =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload.as_bytes());
        format!("eyJhbGciOiJIUzI1NiJ9.{payload_b64}.deadbeef")
    }

    #[test]
    fn jwt_exp_claim_is_decoded() {
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let token = make_jwt(now + 1000);
        assert_eq!(decode_jwt_exp(&token), Some(now + 1000));
    }

    #[test]
    fn jwt_exp_parsing_falls_back_to_none_when_unparsable() {
        assert_eq!(decode_jwt_exp("not-a-jwt"), None);
    }

    #[test]
    fn access_token_ttl_uses_the_sooner_exp() {
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let far_future = make_jwt(now + 100_000);
        let sooner = make_jwt(now + 2000);
        let ttl = access_token_ttl_seconds(&far_future, &sooner);
        // The function reads the clock again, so allow a one-second tick.
        assert!((1999..=2000).contains(&ttl), "ttl = {ttl}");
    }

    #[test]
    fn access_token_ttl_clamps_down_to_maximum() {
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let far_future = make_jwt(now + 100_000);
        let ttl = access_token_ttl_seconds(&far_future, &far_future);
        assert_eq!(ttl, ACCESS_TOKEN_TTL_MAX_SECONDS);
    }

    #[test]
    fn access_token_ttl_clamps_up_to_minimum() {
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        // Already expired: raw TTL would be negative, clamped up to 60s.
        let expired = make_jwt(now - 500);
        let ttl = access_token_ttl_seconds(&expired, &expired);
        assert_eq!(ttl, ACCESS_TOKEN_TTL_MIN_SECONDS);
    }

    #[test]
    fn access_token_ttl_falls_back_when_both_tokens_unparsable() {
        let ttl = access_token_ttl_seconds("garbage", "also-garbage");
        assert_eq!(ttl, ACCESS_TOKEN_TTL_FALLBACK_SECONDS);
    }

    // ------------------------------------------------------------------
    // Error response parsing (both documented shapes)
    // ------------------------------------------------------------------

    #[test]
    fn error_response_parses_input_validation_shape() {
        let body = r#"{"error": {"type": "INPUT_VALIDATION_ERROR", "messages": {"reference": ["La referencia ya ha sido usada"]}}}"#;
        let parsed: WompiErrorResponse = serde_json::from_str(body).unwrap();
        assert_eq!(parsed.error.error_type, "INPUT_VALIDATION_ERROR");
        assert!(parsed
            .error
            .combined_reason()
            .contains("La referencia ya ha sido usada"));
    }

    #[test]
    fn error_response_parses_undocumented_not_found_shape() {
        let body = r#"{"error": {"type": "NOT_FOUND", "code": "MERCHANT_NOT_FOUND", "reason": "no such merchant"}}"#;
        let parsed: WompiErrorResponse = serde_json::from_str(body).unwrap();
        assert_eq!(parsed.error.error_type, "NOT_FOUND");
        let combined = parsed.error.combined_reason();
        assert!(combined.contains("no such merchant"));
        assert!(combined.contains("MERCHANT_NOT_FOUND"));
    }

    #[test]
    fn error_response_parses_invalid_access_token_shape() {
        let body = r#"{"error": {"type": "INVALID_ACCESS_TOKEN", "reason": "La llave proporcionada no corresponde a este ambiente."}}"#;
        let parsed: WompiErrorResponse = serde_json::from_str(body).unwrap();
        assert_eq!(parsed.error.error_type, "INVALID_ACCESS_TOKEN");
    }

    // ------------------------------------------------------------------
    // Checkout form fields carry a correct integrity signature
    // ------------------------------------------------------------------

    #[test]
    fn checkout_form_signature_matches_manual_computation() {
        let reference = "attempt_ref_123";
        let amount = MinorUnit::new(9500000);
        let secret = Secret::new("test_integrity_secret_value".to_string());
        let signature = build_integrity_signature(reference, amount, "COP", &secret).unwrap();

        let manual_message = format!(
            "{reference}{}{}{}",
            amount.get_amount_as_i64(),
            "COP",
            secret.clone().expose()
        );
        let manual_digest = Sha256.generate_digest(manual_message.as_bytes()).unwrap();
        assert_eq!(signature, hex::encode(manual_digest));
    }
}
