use std::collections::HashMap;

use api_models::webhooks::IncomingWebhookEvent;
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
    router_response_types::{PaymentsResponseData, RedirectForm, RefundsResponseData},
    types::{PaymentsAuthorizeRouterData, RefundsRouterData},
};
// Only used by the refund round-trip tests below (the non-test code only ever
// spells the flow-generic `RefundsRouterData<F>`, never `RefundsData` or the
// `Execute` flow directly), so these stay test-only to avoid unused-import
// warnings in a plain (non-test) build.
#[cfg(test)]
use hyperswitch_domain_models::{
    router_flow_types::refunds::Execute, router_request_types::RefundsData,
};
use hyperswitch_interfaces::errors;
use masking::{ExposeInterface, PeekInterface, Secret};
use serde::{Deserialize, Serialize};

use crate::{
    types::{RefundsResponseRouterData, ResponseRouterData},
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
const ACCESS_TOKEN_TTL_MAX_SECONDS: i64 = 3600;

/// TTL for the packed access token: the minimum `exp` of the two presigned
/// JWTs minus now, clamped to `[0, ACCESS_TOKEN_TTL_MAX_SECONDS]`. Falls back to a
/// conservative 300s when neither token's `exp` claim can be parsed, so a decoding
/// hiccup never caches the pair forever (max clamp) nor refetches on every request
/// (an unclamped near-zero/negative TTL). Never clamped UP to a minimum: an
/// already-expired or near-expired pair must not be cached — the generic
/// AccessTokenAuth cache subtracts its own margin (15s) before deciding whether to
/// reuse a cached token, so a non-positive TTL here simply is not cached, which is
/// the correct outcome for a pair that is already (nearly) dead.
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
        Some(exp) => (exp - now).clamp(0, ACCESS_TOKEN_TTL_MAX_SECONDS),
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

        // Wompi rejects a card holder shorter than 5 characters. This is a value
        // that IS present but malformed, not a missing one, so it is reported as
        // `InvalidDataFormat` rather than `MissingRequiredField`.
        if card_holder.clone().expose().trim().chars().count() < 5 {
            return Err(errors::ConnectorError::InvalidDataFormat {
                field_name: "card_holder_name",
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
        // `Automatic` and `SequentialAutomatic`, never `Manual`; this is a
        // defensive second gate).
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
    // Top-level on every transaction (e.g. "CARD", "NEQUI", "PSE",
    // "BANCOLOMBIA_TRANSFER"); defaulted so a response shape that predates this
    // field still parses. Carried into a Charged payment's `connector_metadata`
    // (see `charged_connector_metadata`) so refund Execute can later decide
    // whether this transaction is void-eligible without another Wompi call.
    #[serde(default)]
    pub payment_method_type: Option<String>,
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

/// What a Charged payment remembers about how it was paid, carried on
/// `PaymentsResponseData::TransactionResponse.connector_metadata` and handed
/// back unchanged as `RefundsData.connector_metadata` when a refund is later
/// requested (Hyperswitch persists `connector_metadata` on the payment
/// attempt for exactly this round trip). `validate_void_refund` reads it back
/// to decide whether a later refund of this payment is even void-eligible
/// (card only). Never populated for a non-charged outcome: a payment that
/// never settled can't be refunded either way.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WompiPaymentMetadata {
    pub payment_method_type: Option<String>,
    pub finalized_at: Option<String>,
}

/// Builds the `connector_metadata` for a Charged transaction. Effectively
/// infallible (a two-`Option<String>`-field struct always serializes), but
/// returns `Option` rather than panicking on the off chance it doesn't: a
/// missing metadata blob just means a later refund falls back to the V2
/// refunds API instead of void, never a hard failure of the payment itself.
fn charged_connector_metadata(transaction: &WompiTransactionData) -> Option<serde_json::Value> {
    serde_json::to_value(WompiPaymentMetadata {
        payment_method_type: transaction.payment_method_type.clone(),
        finalized_at: transaction.finalized_at.clone(),
    })
    .ok()
}

/// Builds the RouterData outcome for one Wompi transaction: Charged/Pending/
/// Voided become a `TransactionResponse`, DECLINED/ERROR become an `Err`
/// carrying the connector's own reason so it is never lost even though Wompi
/// answers a decline with HTTP 2xx. Shared with the card sync-by-reference path
/// in wompi.rs (`card_sync_by_reference_response` below), not just the two
/// `TryFrom` impls in this file.
pub(super) fn transaction_to_router_data<F, T>(
    transaction: WompiTransactionData,
    data: RouterData<F, T, PaymentsResponseData>,
    http_code: u16,
) -> RouterData<F, T, PaymentsResponseData> {
    let status = map_wompi_status(transaction.status);
    let connector_metadata = matches!(status, enums::AttemptStatus::Charged)
        .then(|| charged_connector_metadata(&transaction))
        .flatten();
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
            connector_metadata,
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
            connector_metadata: charged_connector_metadata(approved),
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

// ============================================================================
// PSync — CARD retried by reference (see `syncs_by_reference` in wompi.rs): a
// POST /transactions that timed out after Wompi accepted it leaves the attempt
// without a connector transaction id, so it is resolved by the same
// `GET /transactions?reference=` search as hosted checkout, but selected and
// mapped differently below.
// ============================================================================

/// Pure (testable) selection over a CARD sync-by-reference search. Unlike
/// `select_hosted_transaction` this never applies the buyer-retry window: there is
/// no buyer retry to wait out here, POST /transactions either created the charge or
/// it did not, so the strongest known outcome wins outright — an APPROVED
/// transaction if one exists, else a still-live PENDING one, else the most
/// recently finalized/created of whatever is left (declined/errored/voided).
pub(super) fn select_card_transaction(
    transactions: Vec<WompiTransactionData>,
) -> Option<WompiTransactionData> {
    if let Some(approved) = transactions
        .iter()
        .find(|t| t.status == WompiTransactionStatus::Approved)
    {
        return Some(approved.clone());
    }

    if let Some(pending) = transactions
        .iter()
        .find(|t| t.status == WompiTransactionStatus::Pending)
    {
        return Some(pending.clone());
    }

    transactions
        .iter()
        .max_by_key(|t| parse_timestamp(t.finalized_at.as_deref().or(t.created_at.as_deref())))
        .cloned()
}

/// Maps a CARD sync-by-reference search to a RouterData outcome: the selected
/// transaction (if any) goes through the same `transaction_to_router_data` as
/// every other card response, and an empty search result becomes `Pending` with
/// `NoResponseId` rather than an error — the charge may simply not exist at
/// Wompi yet.
pub(super) fn card_sync_by_reference_response<F, T>(
    transactions: Vec<WompiTransactionData>,
    data: RouterData<F, T, PaymentsResponseData>,
    http_code: u16,
) -> RouterData<F, T, PaymentsResponseData> {
    match select_card_transaction(transactions) {
        Some(transaction) => transaction_to_router_data(transaction, data, http_code),
        None => RouterData {
            status: enums::AttemptStatus::Pending,
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::NoResponseId,
                redirection_data: Box::new(None),
                mandate_reference: Box::new(None),
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: None,
                incremental_authorization_allowed: None,
                charges: None,
            }),
            ..data
        },
    }
}

#[derive(Debug, Clone, PartialEq)]
pub(super) enum HostedSyncOutcome {
    Charged {
        id: String,
        reference: String,
        connector_metadata: Option<serde_json::Value>,
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
            HostedSyncOutcome::Charged {
                id,
                reference,
                connector_metadata,
            } => (
                enums::AttemptStatus::Charged,
                Ok(PaymentsResponseData::TransactionResponse {
                    resource_id: ResponseId::ConnectorTransactionId(id),
                    redirection_data: Box::new(None),
                    mandate_reference: Box::new(None),
                    connector_metadata,
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
// Refunds Execute — POST /transactions/{id}/void ; RSync — GET
// /transactions/{id} (both private key, see `Wompi::private_key_headers` in
// wompi.rs)
//
// Wompi confirmed in writing that its API only supports VOIDING a card
// payment; it has no refund API a merchant can call. `POST
// /transactions/{id}/void` (private key, no body) always releases the FULL
// amount of the original transaction. Any partial or later reversal is a
// MANUAL request the merchant makes directly to Wompi support, outside this
// connector.
//
// Production evidence (2026-09-25) backs this up: `POST /v1/refunds` on an
// approved card transaction always answers 422 `transaction_id: La
// transacción no está aprobada` ("the transaction is not approved"), while
// voiding the very same transaction succeeds (201), and the transaction
// itself turns VOIDED moments later.
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum WompiRefundStatus {
    Approved,
    Pending,
    Declined,
    Error,
    Cancelled,
    // Never map an unrecognized status to Success: an unknown value from Wompi
    // must keep the refund syncable, not silently mark it paid out.
    #[serde(other)]
    Unknown,
}

pub(super) fn map_refund_status(status: WompiRefundStatus) -> enums::RefundStatus {
    match status {
        WompiRefundStatus::Approved => enums::RefundStatus::Success,
        WompiRefundStatus::Declined | WompiRefundStatus::Error | WompiRefundStatus::Cancelled => {
            enums::RefundStatus::Failure
        }
        WompiRefundStatus::Pending | WompiRefundStatus::Unknown => enums::RefundStatus::Pending,
    }
}

/// Rejects up front what Wompi's void endpoint can never do, so refund
/// Execute never sends a request Wompi is guaranteed to reject:
/// - a currency other than COP (the only currency Wompi processes here);
/// - a partial amount (void has no partial-amount mode: it always releases
///   the full original transaction);
/// - a payment remembered (via `charged_connector_metadata`) as something
///   other than a card (void only exists for card transactions; PSE, Nequi,
///   etc. have no equivalent).
///
/// Missing or unparsable `connector_metadata` is NOT rejected here: it just
/// means this payment predates `charged_connector_metadata`, or came through
/// a path that never set it, and Wompi itself remains the final authority on
/// whether a given transaction id can be voided. Whatever this function lets
/// through still goes to Wompi: a void Wompi itself rejects (e.g. because the
/// transaction has already settled, or was never a card payment) surfaces as
/// a failed refund carrying Wompi's own error code and message, never a
/// connector-side guess.
pub(super) fn validate_void_refund(
    connector_metadata: Option<&serde_json::Value>,
    refund_amount: MinorUnit,
    payment_amount: MinorUnit,
    currency: enums::Currency,
) -> Result<(), error_stack::Report<errors::ConnectorError>> {
    if currency != enums::Currency::COP {
        return Err(errors::ConnectorError::CurrencyNotSupported {
            message: currency.to_string(),
            connector: "wompi",
        }
        .into());
    }

    if refund_amount != payment_amount {
        return Err(errors::ConnectorError::NotSupported {
            message: "partial refund".to_string(),
            connector: "wompi",
        }
        .into());
    }

    let payment_method_type = connector_metadata
        .and_then(|value| serde_json::from_value::<WompiPaymentMetadata>(value.clone()).ok())
        .and_then(|metadata| metadata.payment_method_type);

    if let Some(payment_method_type) = payment_method_type {
        if payment_method_type != "CARD" {
            return Err(errors::ConnectorError::NotSupported {
                message: "refund of a non-card payment".to_string(),
                connector: "wompi",
            }
            .into());
        }
    }

    Ok(())
}

/// The connector refund id Wompi's void endpoint mints is not a refund id at
/// all (void has no refund object), so it is prefixed with this marker: strip
/// it (see `strip_void_refund_id`) to get back the original transaction id
/// RSync asks `GET /transactions/{id}` about.
pub(super) const VOID_REFUND_ID_PREFIX: &str = "void_";

/// Returns the transaction id inside a `connector_refund_id` minted by the
/// void endpoint (i.e. one carrying the `void_` prefix), else `None`. Every
/// refund this connector creates today is void-routed, so in practice `None`
/// only happens for an id minted before this connector moved to void-only
/// refunds.
pub(super) fn strip_void_refund_id(connector_refund_id: &str) -> Option<&str> {
    connector_refund_id.strip_prefix(VOID_REFUND_ID_PREFIX)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WompiVoidTransaction {
    pub id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WompiVoidData {
    pub status: WompiRefundStatus,
    pub status_message: Option<String>,
    pub transaction: WompiVoidTransaction,
}

/// `POST /transactions/{id}/void`'s response shape: `data.status` is the
/// VOID's own status (not the embedded transaction's — that still reads
/// APPROVED at response time, and only turns VOIDED itself moments later, per
/// the production evidence this connector was built against), reusing
/// `WompiRefundStatus` since Wompi's void statuses are the same vocabulary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WompiVoidResponse {
    pub data: WompiVoidData,
}

/// Converts a void response into `RefundsResponseData`. `connector_refund_id`
/// carries the `void_` prefix (see `strip_void_refund_id`) so RSync later
/// knows to ask the transaction, not a (nonexistent) refund object.
///
/// A rejected void still answers 201: once the network can no longer void
/// the charge (production, 2026-09-28, three days after the charge) Wompi
/// returns `data.status: ERROR` with `status_message: "Original no
/// Encontrado"`. That becomes an `ErrorResponse` carrying Wompi's message, so
/// the failed refund tells the merchant why instead of failing silently.
impl<F> TryFrom<RefundsResponseRouterData<F, WompiVoidResponse>> for RefundsRouterData<F> {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: RefundsResponseRouterData<F, WompiVoidResponse>,
    ) -> Result<Self, Self::Error> {
        let void = item.response.data;
        let refund_status = map_refund_status(void.status);
        let response = if refund_status == enums::RefundStatus::Failure {
            Err(ErrorResponse {
                status_code: item.http_code,
                code: format!("{:?}", void.status).to_uppercase(),
                message: void
                    .status_message
                    .clone()
                    .unwrap_or_else(|| "Void rejected by Wompi".to_string()),
                reason: void.status_message,
                attempt_status: None,
                connector_transaction_id: Some(void.transaction.id),
                network_advice_code: None,
                network_decline_code: None,
                network_error_message: None,
                connector_metadata: None,
            })
        } else {
            Ok(RefundsResponseData {
                connector_refund_id: format!("{VOID_REFUND_ID_PREFIX}{}", void.transaction.id),
                refund_status,
            })
        };
        Ok(Self {
            response,
            ..item.data
        })
    }
}

/// Maps the ORIGINAL transaction's status (from `GET /transactions/{id}`,
/// asked for every refund now that Execute is always void-routed — see
/// `strip_void_refund_id`) to a refund status: VOIDED is the void having
/// actually applied; APPROVED means it has not (yet) applied, or never will,
/// so this stays syncable rather than reporting a premature success;
/// PENDING/Unknown are the transaction's own not-yet-resolved states, kept
/// syncable for the same reason; DECLINED/ERROR are Wompi-side failures of
/// the original charge and can never turn into a successful void.
pub(super) fn map_void_status_to_refund_status(
    status: WompiTransactionStatus,
) -> enums::RefundStatus {
    match status {
        WompiTransactionStatus::Voided => enums::RefundStatus::Success,
        WompiTransactionStatus::Approved
        | WompiTransactionStatus::Pending
        | WompiTransactionStatus::Unknown => enums::RefundStatus::Pending,
        WompiTransactionStatus::Declined | WompiTransactionStatus::Error => {
            enums::RefundStatus::Failure
        }
    }
}

/// RSync always asks the original transaction now (`connector_refund_id`,
/// still `void_`-prefixed, is preserved unchanged so a later RSync call keeps
/// resolving the same way).
impl<F> TryFrom<RefundsResponseRouterData<F, WompiTransactionResponse>> for RefundsRouterData<F> {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: RefundsResponseRouterData<F, WompiTransactionResponse>,
    ) -> Result<Self, Self::Error> {
        let transaction = item.response.data;
        let connector_refund_id = item
            .data
            .request
            .connector_refund_id
            .clone()
            .ok_or(errors::ConnectorError::ResponseDeserializationFailed)?;

        Ok(Self {
            response: Ok(RefundsResponseData {
                connector_refund_id,
                refund_status: map_void_status_to_refund_status(transaction.status),
            }),
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

fn parse_webhook_transaction(
    webhook: &WompiWebhookBody,
) -> CustomResult<WompiWebhookTransaction, errors::ConnectorError> {
    serde_json::from_value(
        webhook
            .data
            .get("transaction")
            .cloned()
            .ok_or(errors::ConnectorError::WebhookReferenceIdNotFound)?,
    )
    .change_context(errors::ConnectorError::WebhookReferenceIdNotFound)
}

/// Which identifier a webhook's object reference should resolve to, decided from
/// SIGNED data only (security): see `webhook_payment_reference` below.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum WompiWebhookReference {
    AttemptReference(String),
    ConnectorTransactionId(String),
}

/// Picks the attempt lookup key from SIGNED data only. The checksum covers just the
/// paths listed in `signature.properties`, so an unlisted field (usually
/// `transaction.reference`) could be edited in a genuine signed payload to route it
/// to a different attempt. Prefer the signed reference (our attempt id), else the
/// signed `transaction.id` (Wompi's own id); if neither is signed the webhook is
/// rejected. A hosted-checkout attempt whose connector id isn't known yet is simply
/// not resolved by the webhook; the ordinary PSync poll resolves it instead.
pub(super) fn webhook_payment_reference(
    webhook: &WompiWebhookBody,
) -> CustomResult<WompiWebhookReference, errors::ConnectorError> {
    let transaction = parse_webhook_transaction(webhook)?;

    let is_signed = |property: &str| {
        webhook
            .signature
            .properties
            .iter()
            .any(|path| path == property)
    };

    if is_signed("transaction.reference") {
        Ok(WompiWebhookReference::AttemptReference(
            transaction.reference,
        ))
    } else if is_signed("transaction.id") {
        Ok(WompiWebhookReference::ConnectorTransactionId(
            transaction.id,
        ))
    } else {
        Err(errors::ConnectorError::WebhookReferenceIdNotFound.into())
    }
}

/// Maps a webhook payload to the router's event type. Checked in this order
/// (event first) because non-`transaction.updated` events (`nequi_token.updated`,
/// `bancolombia_transfer_token.updated`, and any future event Wompi's docs warn the
/// list "can grow") do not necessarily carry a `transaction` object at all, so they
/// must never reach the transaction parse below.
pub(super) fn map_webhook_event(
    webhook: &WompiWebhookBody,
) -> CustomResult<IncomingWebhookEvent, errors::ConnectorError> {
    if webhook.event != "transaction.updated" {
        return Ok(IncomingWebhookEvent::EventNotSupported);
    }

    let transaction: WompiWebhookTransaction = serde_json::from_value(
        webhook
            .data
            .get("transaction")
            .cloned()
            .ok_or(errors::ConnectorError::WebhookEventTypeNotFound)?,
    )
    .change_context(errors::ConnectorError::WebhookEventTypeNotFound)?;

    Ok(match transaction.status {
        WompiTransactionStatus::Approved => IncomingWebhookEvent::PaymentIntentSuccess,
        WompiTransactionStatus::Declined | WompiTransactionStatus::Error => {
            IncomingWebhookEvent::PaymentIntentFailure
        }
        WompiTransactionStatus::Pending => IncomingWebhookEvent::PaymentIntentProcessing,
        // A VOIDED transaction here is never a merchant-initiated cancellation:
        // this connector only ever voids a transaction itself, as its own
        // refund flow (see `validate_void_refund`), and refund RSync already
        // tracks that outcome. Mapping VOIDED to
        // `PaymentIntentCancelled` would flip an already succeeded-and-refunded
        // payment to cancelled when this webhook arrives.
        WompiTransactionStatus::Voided => IncomingWebhookEvent::EventNotSupported,
        WompiTransactionStatus::Unknown => IncomingWebhookEvent::EventNotSupported,
    })
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
    use std::str::FromStr;

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
            payment_method_type: None,
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
                connector_metadata: Some(serde_json::json!({
                    "payment_method_type": null,
                    "finalized_at": null
                })),
            }
        );
    }

    #[test]
    fn hosted_charged_transaction_carries_payment_metadata() {
        let mut approved = tx("h-1", WompiTransactionStatus::Approved, None);
        approved.payment_method_type = Some("CARD".to_string());
        approved.finalized_at = Some("2026-09-25T15:00:00Z".to_string());

        let outcome = select_hosted_transaction(vec![approved], now());
        match outcome {
            HostedSyncOutcome::Charged {
                connector_metadata, ..
            } => {
                assert_eq!(
                    connector_metadata,
                    Some(serde_json::json!({
                        "payment_method_type": "CARD",
                        "finalized_at": "2026-09-25T15:00:00Z"
                    }))
                );
            }
            other => panic!("expected Charged, got {other:?}"),
        }
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
    fn access_token_ttl_never_clamps_an_expired_pair_up() {
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        // Already expired: raw TTL would be negative, and must stay 0 (never
        // cached) rather than being clamped up to a minimum that would cache a
        // dead pair.
        let expired = make_jwt(now - 500);
        let ttl = access_token_ttl_seconds(&expired, &expired);
        assert_eq!(ttl, 0);
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

    // ------------------------------------------------------------------
    // Webhook object reference: SIGNED data only (see `webhook_payment_reference`)
    // ------------------------------------------------------------------

    #[test]
    fn webhook_payment_reference_falls_back_when_reference_is_unsigned() {
        // `sample_webhook_body()`'s `signature.properties` lists id/status/amount,
        // never `transaction.reference` — the common real-world case.
        let webhook = sample_webhook_body();
        assert_eq!(
            webhook_payment_reference(&webhook).unwrap(),
            WompiWebhookReference::ConnectorTransactionId("1234-1610641025-49201".to_string())
        );
    }

    #[test]
    fn webhook_payment_reference_trusts_a_signed_reference() {
        let mut webhook = sample_webhook_body();
        webhook
            .signature
            .properties
            .push("transaction.reference".to_string());
        assert_eq!(
            webhook_payment_reference(&webhook).unwrap(),
            WompiWebhookReference::AttemptReference("MZQ3X2DE2SMX".to_string())
        );
    }

    #[test]
    fn webhook_payment_reference_rejects_a_payload_that_signs_neither_key() {
        let mut webhook = sample_webhook_body();
        webhook.signature.properties = vec![
            "transaction.status".to_string(),
            "transaction.amount_in_cents".to_string(),
        ];
        assert!(webhook_payment_reference(&webhook).is_err());
    }

    // ------------------------------------------------------------------
    // Webhook event type mapping
    // ------------------------------------------------------------------

    #[test]
    fn map_webhook_event_covers_every_transaction_status() {
        let mut webhook = sample_webhook_body();

        webhook.data["transaction"]["status"] = serde_json::json!("APPROVED");
        assert_eq!(
            map_webhook_event(&webhook).unwrap(),
            IncomingWebhookEvent::PaymentIntentSuccess
        );

        webhook.data["transaction"]["status"] = serde_json::json!("DECLINED");
        assert_eq!(
            map_webhook_event(&webhook).unwrap(),
            IncomingWebhookEvent::PaymentIntentFailure
        );

        webhook.data["transaction"]["status"] = serde_json::json!("PENDING");
        assert_eq!(
            map_webhook_event(&webhook).unwrap(),
            IncomingWebhookEvent::PaymentIntentProcessing
        );

        webhook.data["transaction"]["status"] = serde_json::json!("ERROR");
        assert_eq!(
            map_webhook_event(&webhook).unwrap(),
            IncomingWebhookEvent::PaymentIntentFailure
        );

        // A VOIDED transaction is never a merchant-initiated cancellation here:
        // this connector only ever voids as its own refund flow, and refund
        // RSync (not this webhook) tracks that outcome — see
        // `validate_void_refund`.
        webhook.data["transaction"]["status"] = serde_json::json!("VOIDED");
        assert_eq!(
            map_webhook_event(&webhook).unwrap(),
            IncomingWebhookEvent::EventNotSupported
        );

        webhook.data["transaction"]["status"] = serde_json::json!("SOMETHING_NEW");
        assert_eq!(
            map_webhook_event(&webhook).unwrap(),
            IncomingWebhookEvent::EventNotSupported
        );
    }

    #[test]
    fn non_json_error_body_becomes_a_structured_error() {
        use hyperswitch_interfaces::api::ConnectorCommon;

        // An HTML page from Wompi's edge (e.g. a 502 during an outage) must not
        // surface as a deserialization failure that drops the status code.
        let error = crate::connectors::wompi::Wompi::new()
            .build_error_response(
                hyperswitch_interfaces::types::Response {
                    headers: None,
                    response: bytes::Bytes::from_static(b"<html>502 Bad Gateway</html>"),
                    status_code: 502,
                },
                None,
            )
            .expect("a non-JSON error body must still produce an ErrorResponse");
        assert_eq!(error.status_code, 502);
        assert!(error
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("502 Bad Gateway")));
    }

    #[test]
    fn map_webhook_event_ignores_non_transaction_events_before_parsing_data() {
        let mut webhook = sample_webhook_body();
        webhook.event = "nequi_token.updated".to_string();
        // Unlike `transaction.updated`, this event carries no `transaction` object
        // at all: if the event check ran after parsing `data`, this would error
        // instead of resolving to `EventNotSupported`.
        webhook.data = serde_json::json!({});
        assert_eq!(
            map_webhook_event(&webhook).unwrap(),
            IncomingWebhookEvent::EventNotSupported
        );
    }

    // ------------------------------------------------------------------
    // Card PSync-by-reference selection (see `select_card_transaction`)
    // ------------------------------------------------------------------

    #[test]
    fn select_card_transaction_prefers_approved_over_pending() {
        let transactions = vec![
            tx("1", WompiTransactionStatus::Pending, None),
            tx("2", WompiTransactionStatus::Approved, None),
        ];
        let selected = select_card_transaction(transactions).expect("must select one");
        assert_eq!(selected.id, "2");
    }

    #[test]
    fn select_card_transaction_falls_back_to_pending() {
        let transactions = vec![tx("1", WompiTransactionStatus::Pending, None)];
        let selected = select_card_transaction(transactions).expect("must select one");
        assert_eq!(selected.id, "1");
    }

    #[test]
    fn select_card_transaction_picks_the_newest_terminal_failure() {
        let transactions = vec![
            tx(
                "1",
                WompiTransactionStatus::Declined,
                Some("2024-01-01T00:00:00.000Z"),
            ),
            tx(
                "2",
                WompiTransactionStatus::Declined,
                Some("2024-01-01T00:05:00.000Z"),
            ),
        ];
        let selected = select_card_transaction(transactions).expect("must select one");
        assert_eq!(selected.id, "2");
    }

    #[test]
    fn select_card_transaction_empty_search_returns_none() {
        assert!(select_card_transaction(vec![]).is_none());
    }

    #[test]
    fn card_sync_by_reference_response_maps_the_selected_transaction() {
        let router_data = authorize_router_data(
            authorize_request_data(
                PaymentMethodData::Card(test_card()),
                enums::Currency::COP,
                100000,
                Some(common_utils::pii::Email::from_str("buyer@example.com").unwrap()),
                None,
            ),
            enums::AuthenticationType::NoThreeDs,
            Some(packed_access_token()),
            Some("tok_test_x".to_string()),
            "wompi-test-ref-8",
        );
        let transactions = vec![tx("txn-approved", WompiTransactionStatus::Approved, None)];
        let result = card_sync_by_reference_response(transactions, router_data, 200);
        assert_eq!(result.status, enums::AttemptStatus::Charged);
    }

    #[test]
    fn card_sync_by_reference_response_empty_search_stays_pending_with_no_response_id() {
        let router_data = authorize_router_data(
            authorize_request_data(
                PaymentMethodData::Card(test_card()),
                enums::Currency::COP,
                100000,
                Some(common_utils::pii::Email::from_str("buyer@example.com").unwrap()),
                None,
            ),
            enums::AuthenticationType::NoThreeDs,
            Some(packed_access_token()),
            Some("tok_test_x".to_string()),
            "wompi-test-ref-9",
        );
        let result = card_sync_by_reference_response(vec![], router_data, 200);
        assert_eq!(result.status, enums::AttemptStatus::Pending);
        match result.response.expect("empty search must not be an Err") {
            PaymentsResponseData::TransactionResponse { resource_id, .. } => {
                assert!(matches!(resource_id, ResponseId::NoResponseId));
            }
            other => panic!("expected a TransactionResponse, got {other:?}"),
        }
    }

    // ------------------------------------------------------------------
    // Authorize / PSync request-response conversions, built through a compact
    // local RouterData builder (mirrors the pattern in
    // `fiservemea::cert_payloads::router_data`).
    // ------------------------------------------------------------------

    fn test_auth() -> ConnectorAuthType {
        ConnectorAuthType::SignatureKey {
            api_key: Secret::new("pub_test_x".to_string()),
            key1: Secret::new("prv_test_x".to_string()),
            api_secret: Secret::new("test_integrity_x".to_string()),
        }
    }

    fn packed_access_token() -> AccessToken {
        let packed = WompiPackedAcceptanceTokens {
            acceptance_token: Secret::new("acc_test_x".to_string()),
            accept_personal_auth: Secret::new("pat_test_x".to_string()),
        };
        AccessToken {
            token: Secret::new(serde_json::to_string(&packed).unwrap()),
            expires: 300,
        }
    }

    fn test_card() -> hyperswitch_domain_models::payment_method_data::Card {
        hyperswitch_domain_models::payment_method_data::Card {
            card_number: cards::CardNumber::from_str("4242424242424242").unwrap(),
            card_exp_month: Secret::new("12".to_string()),
            card_exp_year: Secret::new("2030".to_string()),
            card_cvc: Secret::new("123".to_string()),
            card_issuer: None,
            card_network: None,
            card_type: None,
            card_issuing_country: None,
            bank_code: None,
            nick_name: None,
            card_holder_name: Some(Secret::new("PXSOL TEST".to_string())),
            co_badged_card_data: None,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn authorize_request_data(
        payment_method_data: PaymentMethodData,
        currency: enums::Currency,
        amount_minor: i64,
        email: Option<common_utils::pii::Email>,
        router_return_url: Option<String>,
    ) -> PaymentsAuthorizeData {
        PaymentsAuthorizeData {
            payment_method_data,
            amount: amount_minor,
            minor_amount: MinorUnit::new(amount_minor),
            order_tax_amount: None,
            email,
            customer_name: None,
            currency,
            confirm: true,
            statement_descriptor_suffix: None,
            statement_descriptor: None,
            capture_method: Some(enums::CaptureMethod::Automatic),
            router_return_url,
            webhook_url: None,
            complete_authorize_url: None,
            setup_future_usage: None,
            mandate_id: None,
            off_session: None,
            customer_acceptance: None,
            setup_mandate_details: None,
            browser_info: None,
            order_details: None,
            order_category: None,
            session_token: None,
            enrolled_for_3ds: false,
            related_transaction_id: None,
            payment_experience: None,
            payment_method_type: None,
            surcharge_details: None,
            customer_id: None,
            request_incremental_authorization: false,
            metadata: None,
            authentication_data: None,
            request_extended_authorization: None,
            split_payments: None,
            merchant_order_reference_id: None,
            integrity_object: None,
            shipping_cost: None,
            additional_payment_method_data: None,
            merchant_account_id: None,
            merchant_config_currency: None,
            connector_testing_data: None,
            order_id: None,
            locale: None,
            payment_channel: None,
            enable_partial_authorization: None,
            enable_overcapture: None,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn authorize_router_data(
        request: PaymentsAuthorizeData,
        auth_type: enums::AuthenticationType,
        access_token: Option<AccessToken>,
        payment_method_token: Option<String>,
        reference: &str,
    ) -> PaymentsAuthorizeRouterData {
        RouterData {
            flow: std::marker::PhantomData,
            merchant_id: common_utils::id_type::MerchantId::try_from(std::borrow::Cow::from(
                "wompi",
            ))
            .unwrap(),
            customer_id: None,
            connector_customer: None,
            connector: "wompi".to_string(),
            payment_id: reference.to_string(),
            attempt_id: reference.to_string(),
            tenant_id: common_utils::id_type::TenantId::try_from_string("public".to_string())
                .unwrap(),
            status: enums::AttemptStatus::default(),
            payment_method: enums::PaymentMethod::Card,
            connector_auth_type: test_auth(),
            description: None,
            address: hyperswitch_domain_models::payment_address::PaymentAddress::default(),
            auth_type,
            connector_meta_data: None,
            connector_wallets_details: None,
            amount_captured: None,
            access_token,
            session_token: None,
            reference_id: None,
            payment_method_token: payment_method_token.map(|token| {
                hyperswitch_domain_models::router_data::PaymentMethodToken::Token(Secret::new(
                    token,
                ))
            }),
            recurring_mandate_payment_data: None,
            preprocessing_id: None,
            payment_method_balance: None,
            connector_api_version: None,
            request,
            response: Err(ErrorResponse::default()),
            connector_request_reference_id: reference.to_string(),
            #[cfg(feature = "payouts")]
            payout_method_data: None,
            #[cfg(feature = "payouts")]
            quote_id: None,
            test_mode: Some(true),
            connector_http_status_code: None,
            external_latency: None,
            apple_pay_flow: None,
            frm_metadata: None,
            dispute_id: None,
            refund_id: None,
            connector_response: None,
            payment_method_status: None,
            minor_amount_captured: None,
            minor_amount_capturable: None,
            integrity_check: Ok(()),
            additional_merchant_data: None,
            header_payload: None,
            connector_mandate_request_reference_id: None,
            l2_l3_data: None,
            authentication_id: None,
            psd2_sca_exemption_type: None,
            raw_connector_response: None,
            is_payment_id_from_merchant: None,
        }
    }

    #[test]
    fn authorize_rejects_non_cop_currency() {
        let request = authorize_request_data(
            PaymentMethodData::Card(test_card()),
            enums::Currency::USD,
            100000,
            Some(common_utils::pii::Email::from_str("buyer@example.com").unwrap()),
            None,
        );
        let router_data = authorize_router_data(
            request,
            enums::AuthenticationType::NoThreeDs,
            Some(packed_access_token()),
            Some("tok_test_x".to_string()),
            "wompi-test-ref-1",
        );
        let amount = MinorUnit::new(100000);
        let wompi_router_data = WompiRouterData::from((amount, &router_data));
        let result = WompiTransactionsRequest::try_from(&wompi_router_data);
        assert!(matches!(
            result.unwrap_err().current_context(),
            errors::ConnectorError::CurrencyNotSupported { .. }
        ));
    }

    #[test]
    fn authorize_rejects_three_ds() {
        let request = authorize_request_data(
            PaymentMethodData::Card(test_card()),
            enums::Currency::COP,
            100000,
            Some(common_utils::pii::Email::from_str("buyer@example.com").unwrap()),
            None,
        );
        let router_data = authorize_router_data(
            request,
            enums::AuthenticationType::ThreeDs,
            Some(packed_access_token()),
            Some("tok_test_x".to_string()),
            "wompi-test-ref-2",
        );
        let amount = MinorUnit::new(100000);
        let wompi_router_data = WompiRouterData::from((amount, &router_data));
        let result = WompiTransactionsRequest::try_from(&wompi_router_data);
        assert!(matches!(
            result.unwrap_err().current_context(),
            errors::ConnectorError::NotSupported { .. }
        ));
    }

    #[test]
    fn authorize_requires_email() {
        let request = authorize_request_data(
            PaymentMethodData::Card(test_card()),
            enums::Currency::COP,
            100000,
            None,
            None,
        );
        let router_data = authorize_router_data(
            request,
            enums::AuthenticationType::NoThreeDs,
            Some(packed_access_token()),
            Some("tok_test_x".to_string()),
            "wompi-test-ref-3",
        );
        let amount = MinorUnit::new(100000);
        let wompi_router_data = WompiRouterData::from((amount, &router_data));
        let result = WompiTransactionsRequest::try_from(&wompi_router_data);
        assert!(matches!(
            result.unwrap_err().current_context(),
            errors::ConnectorError::MissingRequiredField {
                field_name: "email"
            }
        ));
    }

    #[test]
    fn authorize_requires_access_token() {
        let request = authorize_request_data(
            PaymentMethodData::Card(test_card()),
            enums::Currency::COP,
            100000,
            Some(common_utils::pii::Email::from_str("buyer@example.com").unwrap()),
            None,
        );
        let router_data = authorize_router_data(
            request,
            enums::AuthenticationType::NoThreeDs,
            None,
            Some("tok_test_x".to_string()),
            "wompi-test-ref-4",
        );
        let amount = MinorUnit::new(100000);
        let wompi_router_data = WompiRouterData::from((amount, &router_data));
        let result = WompiTransactionsRequest::try_from(&wompi_router_data);
        assert!(matches!(
            result.unwrap_err().current_context(),
            errors::ConnectorError::FailedToObtainAuthType
        ));
    }

    #[test]
    fn authorize_happy_path_serializes_expected_fields() {
        let mut request = authorize_request_data(
            PaymentMethodData::Card(test_card()),
            enums::Currency::COP,
            250000,
            Some(common_utils::pii::Email::from_str("buyer@example.com").unwrap()),
            None,
        );
        request.metadata = Some(serde_json::json!({"installments": 3}));
        let router_data = authorize_router_data(
            request,
            enums::AuthenticationType::NoThreeDs,
            Some(packed_access_token()),
            Some("tok_test_x".to_string()),
            "wompi-test-ref-5",
        );
        let amount = MinorUnit::new(250000);
        let wompi_router_data = WompiRouterData::from((amount, &router_data));
        let connector_request = WompiTransactionsRequest::try_from(&wompi_router_data)
            .expect("happy path must build a request");

        assert!(matches!(
            connector_request.payment_method.payment_method_type,
            WompiPaymentMethodType::Card
        ));
        assert_eq!(connector_request.payment_method.installments, 3);
        assert_eq!(connector_request.reference, "wompi-test-ref-5");

        let expected_signature = build_integrity_signature(
            "wompi-test-ref-5",
            amount,
            "COP",
            &Secret::new("test_integrity_x".to_string()),
        )
        .unwrap();
        assert_eq!(connector_request.signature, expected_signature);
    }

    #[test]
    fn declined_transaction_becomes_an_error_response() {
        let request = authorize_request_data(
            PaymentMethodData::Card(test_card()),
            enums::Currency::COP,
            100000,
            Some(common_utils::pii::Email::from_str("buyer@example.com").unwrap()),
            None,
        );
        let router_data = authorize_router_data(
            request,
            enums::AuthenticationType::NoThreeDs,
            Some(packed_access_token()),
            Some("tok_test_x".to_string()),
            "wompi-test-ref-6",
        );
        let transaction = WompiTransactionData {
            id: "txn_declined_1".to_string(),
            reference: "wompi-test-ref-6".to_string(),
            status: WompiTransactionStatus::Declined,
            status_message: Some("Fondos insuficientes".to_string()),
            created_at: None,
            finalized_at: None,
            payment_method_type: None,
        };
        let result = transaction_to_router_data(transaction, router_data, 200);
        assert_eq!(result.status, enums::AttemptStatus::Failure);
        let error = result
            .response
            .expect_err("a declined transaction must be an Err");
        assert_eq!(error.attempt_status, Some(enums::AttemptStatus::Failure));
        assert_eq!(error.code, "DECLINED");
        assert_eq!(error.message, "Fondos insuficientes");
    }

    #[test]
    fn hosted_checkout_merchant_response_builds_the_redirect_form() {
        let request = authorize_request_data(
            PaymentMethodData::Wallet(WalletData::WompiCheckout {}),
            enums::Currency::COP,
            150000,
            None,
            Some("https://example.com/return".to_string()),
        );
        let router_data = authorize_router_data(
            request,
            enums::AuthenticationType::NoThreeDs,
            None,
            None,
            "wompi-test-ref-7",
        );

        let merchant_response = WompiMerchantResponse {
            data: WompiMerchantData {
                active: true,
                presigned_acceptance: WompiPresignedToken {
                    acceptance_token: Secret::new("acc_x".to_string()),
                },
                presigned_personal_data_auth: WompiPresignedToken {
                    acceptance_token: Secret::new("pat_x".to_string()),
                },
            },
        };

        let response_router_data = ResponseRouterData {
            response: merchant_response,
            data: router_data,
            http_code: 200,
        };

        let result = PaymentsAuthorizeRouterData::try_from(response_router_data)
            .expect("hosted checkout conversion must succeed");

        assert_eq!(result.status, enums::AttemptStatus::AuthenticationPending);

        match result.response.expect("must be a TransactionResponse") {
            PaymentsResponseData::TransactionResponse {
                redirection_data, ..
            } => match *redirection_data {
                Some(RedirectForm::Form {
                    endpoint,
                    method,
                    form_fields,
                }) => {
                    assert_eq!(endpoint, WOMPI_CHECKOUT_ENDPOINT);
                    assert_eq!(method, Method::Get);
                    assert_eq!(
                        form_fields.get("public-key"),
                        Some(&"pub_test_x".to_string())
                    );
                    assert_eq!(
                        form_fields.get("amount-in-cents"),
                        Some(&"150000".to_string())
                    );
                    assert_eq!(
                        form_fields.get("reference"),
                        Some(&"wompi-test-ref-7".to_string())
                    );
                    let expected_signature = build_integrity_signature(
                        "wompi-test-ref-7",
                        MinorUnit::new(150000),
                        "COP",
                        &Secret::new("test_integrity_x".to_string()),
                    )
                    .unwrap();
                    assert_eq!(
                        form_fields.get("signature:integrity"),
                        Some(&expected_signature)
                    );
                    assert_eq!(
                        form_fields.get("redirect-url"),
                        Some(&"https://example.com/return".to_string())
                    );
                }
                other => panic!("expected a RedirectForm::Form, got {other:?}"),
            },
            other => panic!("expected a TransactionResponse, got {other:?}"),
        }
    }

    // ------------------------------------------------------------------
    // Refunds — test scaffolding
    // ------------------------------------------------------------------

    #[allow(clippy::too_many_arguments)]
    fn refund_request_data(
        connector_transaction_id: &str,
        currency: enums::Currency,
        refund_id: &str,
        minor_refund_amount: i64,
        reason: Option<String>,
    ) -> RefundsData {
        RefundsData {
            refund_id: refund_id.to_string(),
            connector_transaction_id: connector_transaction_id.to_string(),
            connector_refund_id: None,
            currency,
            payment_amount: minor_refund_amount,
            reason,
            webhook_url: None,
            refund_amount: minor_refund_amount,
            connector_metadata: None,
            refund_connector_metadata: None,
            browser_info: None,
            split_refunds: None,
            minor_payment_amount: MinorUnit::new(minor_refund_amount),
            minor_refund_amount: MinorUnit::new(minor_refund_amount),
            integrity_object: None,
            refund_status: enums::RefundStatus::Pending,
            merchant_account_id: None,
            merchant_config_currency: None,
            capture_method: None,
            additional_payment_method_data: None,
        }
    }

    fn refund_router_data<F>(request: RefundsData, reference: &str) -> RefundsRouterData<F> {
        RouterData {
            flow: std::marker::PhantomData,
            merchant_id: common_utils::id_type::MerchantId::try_from(std::borrow::Cow::from(
                "wompi",
            ))
            .unwrap(),
            customer_id: None,
            connector_customer: None,
            connector: "wompi".to_string(),
            payment_id: reference.to_string(),
            attempt_id: reference.to_string(),
            tenant_id: common_utils::id_type::TenantId::try_from_string("public".to_string())
                .unwrap(),
            status: enums::AttemptStatus::default(),
            payment_method: enums::PaymentMethod::Card,
            connector_auth_type: test_auth(),
            description: None,
            address: hyperswitch_domain_models::payment_address::PaymentAddress::default(),
            auth_type: enums::AuthenticationType::NoThreeDs,
            connector_meta_data: None,
            connector_wallets_details: None,
            amount_captured: None,
            access_token: None,
            session_token: None,
            reference_id: None,
            payment_method_token: None,
            recurring_mandate_payment_data: None,
            preprocessing_id: None,
            payment_method_balance: None,
            connector_api_version: None,
            request,
            response: Err(ErrorResponse::default()),
            connector_request_reference_id: reference.to_string(),
            #[cfg(feature = "payouts")]
            payout_method_data: None,
            #[cfg(feature = "payouts")]
            quote_id: None,
            test_mode: Some(true),
            connector_http_status_code: None,
            external_latency: None,
            apple_pay_flow: None,
            frm_metadata: None,
            dispute_id: None,
            refund_id: None,
            connector_response: None,
            payment_method_status: None,
            minor_amount_captured: None,
            minor_amount_capturable: None,
            integrity_check: Ok(()),
            additional_merchant_data: None,
            header_payload: None,
            connector_mandate_request_reference_id: None,
            l2_l3_data: None,
            authentication_id: None,
            psd2_sca_exemption_type: None,
            raw_connector_response: None,
            is_payment_id_from_merchant: None,
        }
    }

    // ------------------------------------------------------------------
    // Refund status mapping (shared vocabulary with the void response)
    // ------------------------------------------------------------------

    #[test]
    fn refund_status_mapping_never_maps_unknown_to_success() {
        assert_eq!(
            map_refund_status(WompiRefundStatus::Approved),
            enums::RefundStatus::Success
        );
        assert_eq!(
            map_refund_status(WompiRefundStatus::Declined),
            enums::RefundStatus::Failure
        );
        assert_eq!(
            map_refund_status(WompiRefundStatus::Error),
            enums::RefundStatus::Failure
        );
        assert_eq!(
            map_refund_status(WompiRefundStatus::Cancelled),
            enums::RefundStatus::Failure
        );
        assert_eq!(
            map_refund_status(WompiRefundStatus::Pending),
            enums::RefundStatus::Pending
        );
        assert_eq!(
            map_refund_status(WompiRefundStatus::Unknown),
            enums::RefundStatus::Pending
        );
    }

    #[test]
    fn refund_response_unknown_status_value_falls_back_via_serde_other() {
        let parsed: WompiRefundStatus = serde_json::from_str("\"SOME_NEW_STATUS\"").unwrap();
        assert_eq!(parsed, WompiRefundStatus::Unknown);
    }

    // ------------------------------------------------------------------
    // `payment_method_type` parsing and Charged connector_metadata
    // ------------------------------------------------------------------

    #[test]
    fn transaction_data_parses_payment_method_type_when_present() {
        let data: WompiTransactionData = serde_json::from_value(serde_json::json!({
            "id": "txn-1",
            "reference": "ref-1",
            "status": "APPROVED",
            "status_message": null,
            "payment_method_type": "CARD"
        }))
        .unwrap();
        assert_eq!(data.payment_method_type, Some("CARD".to_string()));
    }

    #[test]
    fn transaction_data_defaults_payment_method_type_when_absent() {
        let data: WompiTransactionData = serde_json::from_value(serde_json::json!({
            "id": "txn-1",
            "reference": "ref-1",
            "status": "APPROVED",
            "status_message": null
        }))
        .unwrap();
        assert_eq!(data.payment_method_type, None);
    }

    #[test]
    fn charged_card_transaction_carries_payment_metadata() {
        let request = authorize_request_data(
            PaymentMethodData::Card(test_card()),
            enums::Currency::COP,
            100000,
            Some(common_utils::pii::Email::from_str("buyer@example.com").unwrap()),
            None,
        );
        let router_data = authorize_router_data(
            request,
            enums::AuthenticationType::NoThreeDs,
            Some(packed_access_token()),
            Some("tok_test_x".to_string()),
            "wompi-test-ref-10",
        );
        let transaction = WompiTransactionData {
            id: "txn_charged_1".to_string(),
            reference: "wompi-test-ref-10".to_string(),
            status: WompiTransactionStatus::Approved,
            status_message: None,
            created_at: None,
            finalized_at: Some("2026-09-25T15:00:00Z".to_string()),
            payment_method_type: Some("CARD".to_string()),
        };
        let result = transaction_to_router_data(transaction, router_data, 200);
        assert_eq!(result.status, enums::AttemptStatus::Charged);
        match result.response.expect("charged must be Ok") {
            PaymentsResponseData::TransactionResponse {
                connector_metadata, ..
            } => {
                assert_eq!(
                    connector_metadata,
                    Some(serde_json::json!({
                        "payment_method_type": "CARD",
                        "finalized_at": "2026-09-25T15:00:00Z"
                    }))
                );
            }
            other => panic!("expected a TransactionResponse, got {other:?}"),
        }
    }

    #[test]
    fn non_charged_transaction_carries_no_connector_metadata() {
        let request = authorize_request_data(
            PaymentMethodData::Card(test_card()),
            enums::Currency::COP,
            100000,
            Some(common_utils::pii::Email::from_str("buyer@example.com").unwrap()),
            None,
        );
        let router_data = authorize_router_data(
            request,
            enums::AuthenticationType::NoThreeDs,
            Some(packed_access_token()),
            Some("tok_test_x".to_string()),
            "wompi-test-ref-11",
        );
        let transaction = WompiTransactionData {
            id: "txn_pending_1".to_string(),
            reference: "wompi-test-ref-11".to_string(),
            status: WompiTransactionStatus::Pending,
            status_message: None,
            created_at: None,
            finalized_at: None,
            payment_method_type: Some("CARD".to_string()),
        };
        let result = transaction_to_router_data(transaction, router_data, 200);
        match result.response.expect("pending must be Ok") {
            PaymentsResponseData::TransactionResponse {
                connector_metadata, ..
            } => assert_eq!(connector_metadata, None),
            other => panic!("expected a TransactionResponse, got {other:?}"),
        }
    }

    // ------------------------------------------------------------------
    // Refund void-eligibility validation (see `validate_void_refund`)
    // ------------------------------------------------------------------

    fn card_metadata(finalized_at: &str) -> serde_json::Value {
        serde_json::json!({ "payment_method_type": "CARD", "finalized_at": finalized_at })
    }

    #[test]
    fn validate_void_refund_ok_for_a_full_card_refund() {
        let metadata = card_metadata("2026-09-25T15:00:00Z");
        assert!(validate_void_refund(
            Some(&metadata),
            MinorUnit::new(100000),
            MinorUnit::new(100000),
            enums::Currency::COP,
        )
        .is_ok());
    }

    #[test]
    fn validate_void_refund_rejects_a_partial_amount() {
        let metadata = card_metadata("2026-09-25T15:00:00Z");
        let result = validate_void_refund(
            Some(&metadata),
            MinorUnit::new(50000),
            MinorUnit::new(100000),
            enums::Currency::COP,
        );
        assert!(matches!(
            result.unwrap_err().current_context(),
            errors::ConnectorError::NotSupported { .. }
        ));
    }

    #[test]
    fn validate_void_refund_rejects_a_non_card_payment() {
        let metadata = serde_json::json!({
            "payment_method_type": "NEQUI",
            "finalized_at": "2026-09-25T15:00:00Z"
        });
        let result = validate_void_refund(
            Some(&metadata),
            MinorUnit::new(100000),
            MinorUnit::new(100000),
            enums::Currency::COP,
        );
        assert!(matches!(
            result.unwrap_err().current_context(),
            errors::ConnectorError::NotSupported { .. }
        ));
    }

    #[test]
    fn validate_void_refund_ok_for_missing_metadata() {
        // Missing metadata means Wompi is the final authority: never guessed
        // "not void-eligible" on this connector's side alone.
        assert!(validate_void_refund(
            None,
            MinorUnit::new(100000),
            MinorUnit::new(100000),
            enums::Currency::COP,
        )
        .is_ok());
    }

    #[test]
    fn validate_void_refund_ok_for_unparsable_metadata() {
        let metadata = serde_json::json!("not an object");
        assert!(validate_void_refund(
            Some(&metadata),
            MinorUnit::new(100000),
            MinorUnit::new(100000),
            enums::Currency::COP,
        )
        .is_ok());
    }

    #[test]
    fn validate_void_refund_ok_for_a_payment_finalized_days_ago() {
        // There is no same-day rule anymore: a void of an old transaction is
        // let through here, and Wompi itself decides (via its own error) if
        // the transaction has since settled and can no longer be voided.
        let metadata = card_metadata("2026-09-01T15:00:00Z");
        assert!(validate_void_refund(
            Some(&metadata),
            MinorUnit::new(100000),
            MinorUnit::new(100000),
            enums::Currency::COP,
        )
        .is_ok());
    }

    #[test]
    fn validate_void_refund_rejects_non_cop_currency() {
        let metadata = card_metadata("2026-09-25T15:00:00Z");
        let result = validate_void_refund(
            Some(&metadata),
            MinorUnit::new(100000),
            MinorUnit::new(100000),
            enums::Currency::USD,
        );
        assert!(matches!(
            result.unwrap_err().current_context(),
            errors::ConnectorError::CurrencyNotSupported { .. }
        ));
    }

    // ------------------------------------------------------------------
    // Void response parsing (refund Execute's void-routed path)
    // ------------------------------------------------------------------

    #[test]
    fn void_response_parses_the_trimmed_production_shape() {
        // Trimmed 201 shape observed in production (2026-09-25): `data.status`
        // is the VOID's own status; the embedded transaction still reads
        // APPROVED at response time (see `WompiVoidResponse`'s doc comment).
        let body = serde_json::json!({
            "data": {
                "status": "APPROVED",
                "status_message": null,
                "transaction": {
                    "id": "144941-1790368341-22002"
                }
            },
            "meta": {}
        });
        let response: WompiVoidResponse = serde_json::from_value(body).unwrap();

        let request = refund_request_data(
            "144941-1790368341-22002",
            enums::Currency::COP,
            "refund-void-1",
            100000,
            None,
        );
        let router_data = refund_router_data(request, "wompi-refund-void-ref-1");
        let response_router_data = ResponseRouterData {
            response,
            data: router_data,
            http_code: 201,
        };
        let result = RefundsRouterData::<Execute>::try_from(response_router_data)
            .expect("a void response must convert");
        let refunds_response = result.response.expect("must be Ok");
        assert_eq!(refunds_response.refund_status, enums::RefundStatus::Success);
        assert_eq!(
            refunds_response.connector_refund_id,
            "void_144941-1790368341-22002"
        );
    }

    #[test]
    fn rejected_void_becomes_an_error_with_wompi_message() {
        // Production (2026-09-28): voiding a card charge three days later is
        // answered 201 with the void itself in ERROR.
        let body = serde_json::json!({
            "data": {
                "status": "ERROR",
                "status_message": "Original no Encontrado",
                "transaction": {
                    "id": "144941-1790379525-64907"
                }
            }
        });
        let response: WompiVoidResponse = serde_json::from_value(body).unwrap();

        let request = refund_request_data(
            "144941-1790379525-64907",
            enums::Currency::COP,
            "refund-void-late",
            150000,
            None,
        );
        let router_data = refund_router_data(request, "wompi-refund-void-late");
        let response_router_data = ResponseRouterData {
            response,
            data: router_data,
            http_code: 201,
        };
        let result = RefundsRouterData::<Execute>::try_from(response_router_data)
            .expect("a void response must convert");
        let error = result
            .response
            .expect_err("a rejected void must be an error");
        assert_eq!(error.code, "ERROR");
        assert_eq!(error.message, "Original no Encontrado");
        assert_eq!(error.reason.as_deref(), Some("Original no Encontrado"));
        assert_eq!(error.status_code, 201);
    }

    // ------------------------------------------------------------------
    // RSync void status mapping (see `map_void_status_to_refund_status`)
    // ------------------------------------------------------------------

    #[test]
    fn void_status_mapping_covers_every_transaction_status() {
        assert_eq!(
            map_void_status_to_refund_status(WompiTransactionStatus::Voided),
            enums::RefundStatus::Success
        );
        assert_eq!(
            map_void_status_to_refund_status(WompiTransactionStatus::Approved),
            enums::RefundStatus::Pending
        );
        assert_eq!(
            map_void_status_to_refund_status(WompiTransactionStatus::Pending),
            enums::RefundStatus::Pending
        );
        assert_eq!(
            map_void_status_to_refund_status(WompiTransactionStatus::Unknown),
            enums::RefundStatus::Pending
        );
        assert_eq!(
            map_void_status_to_refund_status(WompiTransactionStatus::Declined),
            enums::RefundStatus::Failure
        );
        assert_eq!(
            map_void_status_to_refund_status(WompiTransactionStatus::Error),
            enums::RefundStatus::Failure
        );
    }

    #[test]
    fn strip_void_refund_id_recognizes_only_the_void_prefix() {
        assert_eq!(strip_void_refund_id("void_abc-123"), Some("abc-123"));
        assert_eq!(strip_void_refund_id("plain-refund-id"), None);
    }
}
