use api_models::webhooks::IncomingWebhookEvent;
use base64::Engine;
use common_enums::enums;
use common_utils::{
    crypto::{HmacSha256, VerifySignature},
    errors::CustomResult,
    types::{MinorUnit, StringMajorUnit},
};
use error_stack::{report, ResultExt};
use hyperswitch_domain_models::{
    payment_method_data::{PaymentMethodData, WalletData},
    router_data::{AccessToken, ConnectorAuthType, ErrorResponse, RouterData},
    router_flow_types::{
        payments::PostCaptureVoid,
        refunds::{Execute, RSync},
    },
    router_request_types::{PaymentsCancelPostCaptureData, ResponseId},
    router_response_types::{PaymentsResponseData, RedirectForm, RefundsResponseData},
    types::{
        PaymentsAuthorizeRouterData, PaymentsCancelPostCaptureRouterData, PaymentsSyncRouterData,
        RefreshTokenRouterData, RefundsRouterData,
    },
};
use hyperswitch_interfaces::errors;
use hyperswitch_masking::{PeekInterface, Secret};
use serde::{Deserialize, Serialize};

use crate::{
    types::{PaymentsSyncResponseRouterData, RefundsResponseRouterData, ResponseRouterData},
    utils::{get_unimplemented_payment_method_error_message, RouterData as _},
};

/// Izipay Web SDK, sandbox. The environment is chosen per request from the MCA `test_mode`.
pub const SANDBOX_SDK_URL: &str = "https://sandbox-checkout.izipay.pe/payments/v1/js/index.js";
/// Izipay Web SDK, production.
pub const PRODUCTION_SDK_URL: &str = "https://checkout.izipay.pe/payments/v1/js/index.js";

/// Lifetime of an Izipay session token (15 minutes). The router never caches Izipay access
/// tokens (`Connector::issues_single_use_access_tokens`): they are generated per operation kind,
/// and a cached ECOMMERCE token handed to a refund of the same account (or the other way
/// around) would be rejected.
const ACCESS_TOKEN_EXPIRES_SECONDS: i64 = 900;

const IZIPAY_CONNECTOR_NAME: &str = "Izipay";
const ORDER_NUMBER_LENGTH: usize = 15;
/// Number of distinct order numbers: 36^15.
const ORDER_NUMBER_MODULUS: u128 = 36u128.pow(15);
const SUCCESS_CODE: &str = "00";
const ORDER_AUTHORIZED: &str = "Autorizado";
const ORDER_DENIED: &str = "Denegado";
const ORDER_VOIDED: &str = "Anulado";

pub struct IzipayRouterData<T> {
    pub amount: StringMajorUnit,
    pub router_data: T,
}

impl<T> From<(StringMajorUnit, T)> for IzipayRouterData<T> {
    fn from((amount, router_data): (StringMajorUnit, T)) -> Self {
        Self {
            amount,
            router_data,
        }
    }
}

// ============================================================================
// Auth and environment
// ============================================================================

pub struct IzipayAuthType {
    /// "Clave API nuevo botón": only used to generate session tokens.
    pub api_key: Secret<String>,
    pub merchant_code: String,
    /// "Clave Hash": signs the notifications and the signed payloads.
    pub hash_key: Secret<String>,
    /// "Clave pública Izipay" (RSA): `LoadForm.keyRSA` of the Web SDK.
    pub rsa_key: Secret<String>,
}

impl TryFrom<&ConnectorAuthType> for IzipayAuthType {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::MultiAuthKey {
                api_key,
                key1,
                api_secret,
                key2,
            } => Ok(Self {
                api_key: api_key.clone(),
                merchant_code: key1.peek().trim().to_string(),
                hash_key: api_secret.clone(),
                rsa_key: key2.clone(),
            }),
            _ => Err(errors::ConnectorError::FailedToObtainAuthType.into()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IzipayEnvironment {
    Sandbox,
    Production,
}

impl IzipayEnvironment {
    /// An unset `test_mode` means production: a production account that never set the flag
    /// must never be routed to the sandbox, where an approved payment never settles.
    pub fn from_test_mode(test_mode: Option<bool>) -> Self {
        if test_mode.unwrap_or(false) {
            Self::Sandbox
        } else {
            Self::Production
        }
    }

    pub fn sdk_url(self) -> &'static str {
        match self {
            Self::Sandbox => SANDBOX_SDK_URL,
            Self::Production => PRODUCTION_SDK_URL,
        }
    }
}

// ============================================================================
// Identifiers
// ============================================================================

/// Order number sent to Izipay (5-15 characters): 15 characters `[0-9A-Z]` that are the base36
/// form of a SHA-256 of the attempt id, so that it is deterministic (PSync and refunds can
/// recompute it) and unique per attempt without storing anything.
pub fn order_number_from_attempt_id(attempt_id: &str) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, attempt_id.as_bytes());
    let mut value = digest
        .as_ref()
        .iter()
        .take(16)
        .fold(0u128, |acc, byte| (acc << 8) | u128::from(*byte))
        % ORDER_NUMBER_MODULUS;

    let mut digits = Vec::with_capacity(ORDER_NUMBER_LENGTH);
    for _ in 0..ORDER_NUMBER_LENGTH {
        let digit = u32::try_from(value % 36)
            .ok()
            .and_then(|digit| char::from_digit(digit, 36))
            .unwrap_or('0');
        digits.push(digit.to_ascii_uppercase());
        value /= 36;
    }
    digits.iter().rev().collect()
}

/// Correlation id of one Token/Generate call: `{unix_ms}{4 random digits}`.
pub fn new_transaction_id() -> String {
    let unix_ms = common_utils::date_time::now_unix_timestamp_millis();
    let suffix = common_utils::generate_random_numeric_string(4);
    format!("{unix_ms}{suffix}")
}

/// `dateTimeTransaction` of the SDK order: 16 digits, unix milliseconds times 1000.
fn current_date_time_transaction() -> String {
    let unix_ms = common_utils::date_time::now_unix_timestamp_millis();
    format!("{}", unix_ms * 1000)
}

// ============================================================================
// Session tokens (Token/Generate) and the access token that packs them
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IzipayTokenKind {
    #[serde(rename = "ECOMMERCE")]
    Ecommerce,
    #[serde(rename = "REFUND")]
    Refund,
}

impl IzipayTokenKind {
    fn request_source(self) -> &'static str {
        match self {
            Self::Ecommerce => "ECOMMERCE",
            Self::Refund => "REFUND",
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IzipayTokenRequest {
    request_source: &'static str,
    merchant_code: String,
    order_number: String,
    public_key: Secret<String>,
    amount: String,
}

impl IzipayTokenRequest {
    /// Session token bound to one order and amount, used by the Web SDK (`LoadForm`).
    fn for_order(auth: &IzipayAuthType, order_number: String, amount: &StringMajorUnit) -> Self {
        Self {
            request_source: IzipayTokenKind::Ecommerce.request_source(),
            merchant_code: auth.merchant_code.clone(),
            order_number,
            public_key: auth.api_key.clone(),
            amount: amount.get_amount_as_string(),
        }
    }
}

/// Order and amount the session token of a post-capture void has to be bound to: Izipay's
/// Cancel API rejects a token that is not tied to the original order number and the amount
/// being voided (422 "the amount does not match the token's").
#[derive(Debug, PartialEq, Eq)]
struct VoidTokenBinding {
    order_number: String,
    amount: String,
}

/// Amount with two decimals, as Izipay expects it (PEN and USD, the only currencies the
/// connector supports, both have two).
fn two_decimal_amount(amount: MinorUnit) -> String {
    let minor = amount.get_amount_as_i64();
    format!("{}.{:02}", minor / 100, minor % 100)
}

/// Recognises the token request of a post-capture void. The router builds it from the flow's
/// router data, which keeps these fields, and no other Izipay flow produces this shape:
/// - refunds carry a `refund_id`
/// - authorize and payment sync pass the flow they run in (`current_flow`)
/// - capture, void and the rest are not supported by the connector
///
/// A post-capture void only exists for a charged attempt, and the amount to void is what was
/// captured. The order number is the attempt's connector reference, which is also the
/// connector transaction id the void is sent for.
fn post_capture_void_binding(req: &RefreshTokenRouterData) -> Option<VoidTokenBinding> {
    if req.refund_id.is_some()
        || req.request.current_flow.is_some()
        || req.status != enums::AttemptStatus::Charged
    {
        return None;
    }
    let captured = req.minor_amount_captured?;
    let order_number = req.connector_request_reference_id.trim();
    if order_number.is_empty() || captured.get_amount_as_i64() <= 0 {
        return None;
    }
    Some(VoidTokenBinding {
        order_number: order_number.to_string(),
        amount: two_decimal_amount(captured),
    })
}

/// Session token of one operation:
/// - post-capture void: bound to the original order number and the amount being voided
/// - everything else: generic, `orderNumber` is the merchant code and the amount is `0.00`,
///   which Izipay accepts for search and refund operations.
impl TryFrom<&RefreshTokenRouterData> for IzipayTokenRequest {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(req: &RefreshTokenRouterData) -> Result<Self, Self::Error> {
        let auth = IzipayAuthType::try_from(&req.connector_auth_type)?;
        if let Some(binding) = post_capture_void_binding(req) {
            return Ok(Self {
                request_source: IzipayTokenKind::Ecommerce.request_source(),
                merchant_code: auth.merchant_code,
                order_number: binding.order_number,
                public_key: auth.api_key,
                amount: binding.amount,
            });
        }
        let kind = if req.refund_id.is_some() {
            IzipayTokenKind::Refund
        } else {
            IzipayTokenKind::Ecommerce
        };
        Ok(Self {
            request_source: kind.request_source(),
            merchant_code: auth.merchant_code.clone(),
            order_number: auth.merchant_code,
            public_key: auth.api_key,
            amount: "0.00".to_string(),
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct IzipayTokenResponse {
    pub code: String,
    pub message: Option<String>,
    pub response: Option<IzipayTokenData>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct IzipayTokenData {
    pub token: Option<Secret<String>>,
}

impl IzipayTokenResponse {
    fn session_token(&self) -> Option<Secret<String>> {
        if self.code == SUCCESS_CODE {
            self.response.as_ref().and_then(|data| data.token.clone())
        } else {
            None
        }
    }
}

/// What the access token carries: the session token, the correlation id it is bound to and
/// the operation it was generated for.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IzipayPackedToken {
    pub kind: IzipayTokenKind,
    pub transaction_id: String,
    pub token: Secret<String>,
}

/// The correlation id a session token is bound to is only sent in the request header, so it is
/// read back from the token itself (claim `transactionId`), which is what Izipay checks the
/// header of the following calls against. The signature is not verified: the token is only
/// relayed back to the service that issued it.
fn transaction_id_from_session_token(token: &str) -> Option<String> {
    let payload_segment = token.split('.').nth(1)?;
    let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload_segment.trim_end_matches('='))
        .ok()?;
    let payload: serde_json::Value = serde_json::from_slice(&payload_bytes).ok()?;
    match payload.get("transactionId")? {
        serde_json::Value::String(id) if !id.is_empty() => Some(id.clone()),
        serde_json::Value::Number(id) => Some(id.to_string()),
        _ => None,
    }
}

fn error_response_from_code(
    code: &str,
    message: Option<&str>,
    http_code: u16,
    attempt_status: Option<enums::AttemptStatus>,
) -> ErrorResponse {
    ErrorResponse {
        status_code: http_code,
        code: code.to_string(),
        message: message.unwrap_or("Izipay rejected the request").to_string(),
        reason: message.map(str::to_string),
        attempt_status,
        connector_transaction_id: None,
        network_advice_code: None,
        network_decline_code: None,
        network_error_message: None,
        connector_metadata: None,
        connector_response_reference_id: None,
    }
}

impl<F, T> TryFrom<ResponseRouterData<F, IzipayTokenResponse, T, AccessToken>>
    for RouterData<F, T, AccessToken>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<F, IzipayTokenResponse, T, AccessToken>,
    ) -> Result<Self, Self::Error> {
        let Some(token) = item.response.session_token() else {
            return Ok(Self {
                response: Err(error_response_from_code(
                    &item.response.code,
                    item.response.message.as_deref(),
                    item.http_code,
                    None,
                )),
                ..item.data
            });
        };
        let transaction_id = transaction_id_from_session_token(token.peek())
            .ok_or(errors::ConnectorError::ResponseHandlingFailed)
            .attach_printable("Izipay session token carries no transactionId claim")?;
        let kind = if item.data.refund_id.is_some() {
            IzipayTokenKind::Refund
        } else {
            IzipayTokenKind::Ecommerce
        };
        let packed = IzipayPackedToken {
            kind,
            transaction_id,
            token,
        };
        let packed_json = serde_json::to_string(&packed)
            .change_context(errors::ConnectorError::ResponseHandlingFailed)?;
        Ok(Self {
            response: Ok(AccessToken {
                token: Secret::new(packed_json),
                expires: ACCESS_TOKEN_EXPIRES_SECONDS,
            }),
            ..item.data
        })
    }
}

/// Unpacks the access token fetched by the router and checks it was generated for the kind of
/// operation about to run. The router fetches a fresh token for every Izipay operation, so a
/// mismatch is a defect, not a race; nothing has been sent yet when it is detected.
pub fn unpack_access_token(
    access_token: Option<&AccessToken>,
    expected_kind: IzipayTokenKind,
) -> CustomResult<IzipayPackedToken, errors::ConnectorError> {
    let access_token = access_token.ok_or(errors::ConnectorError::MissingRequiredField {
        field_name: "access_token".into(),
    })?;
    let packed: IzipayPackedToken = serde_json::from_str(access_token.token.peek())
        .change_context(errors::ConnectorError::FailedToObtainAuthType)
        .attach_printable("Izipay access token is not a packed session token")?;
    if packed.kind != expected_kind {
        return Err(report!(errors::ConnectorError::FailedToObtainAuthType)).attach_printable(
            format!(
                "Izipay session token was generated for {:?} but this operation needs {:?}",
                packed.kind, expected_kind
            ),
        );
    }
    Ok(packed)
}

// ============================================================================
// Authorize: validated billing, Token/Generate request and the SDK redirect page
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IzipayBilling {
    pub first_name: String,
    pub last_name: String,
    pub email: String,
    pub phone_number: String,
    pub street: String,
    pub city: String,
    pub state: String,
    pub country: String,
    pub postal_code: String,
    pub document_type: String,
    pub document: String,
}

/// Everything of an Authorize request that has to be checked before anything is sent.
#[derive(Debug, Clone)]
pub struct IzipayCheckoutData {
    pub billing: IzipayBilling,
    pub merchant_buyer_id: String,
    pub return_url: String,
}

fn char_len(value: &str) -> usize {
    value.chars().count()
}

fn truncate_chars(value: &str, max_chars: usize) -> String {
    value.chars().take(max_chars).collect()
}

fn required_text(
    value: Option<&Secret<String>>,
    field_name: &'static str,
) -> CustomResult<String, errors::ConnectorError> {
    value
        .map(|value| value.peek().trim().to_string())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            report!(errors::ConnectorError::MissingRequiredField {
                field_name: field_name.into()
            })
        })
}

fn name_within_range(
    value: String,
    field_name: &'static str,
) -> CustomResult<String, errors::ConnectorError> {
    if (2..=50).contains(&char_len(&value)) {
        Ok(value)
    } else {
        Err(report!(errors::ConnectorError::InvalidDataFormat {
            field_name: field_name.into()
        }))
    }
}

/// Free text that Izipay limits to `min..=max` characters: longer values are cut (a street or a
/// city never has to be rejected for being too long), shorter ones cannot be repaired.
fn truncated_text(
    value: String,
    min_chars: usize,
    max_chars: usize,
    field_name: &'static str,
) -> CustomResult<String, errors::ConnectorError> {
    let value = if char_len(&value) > max_chars {
        truncate_chars(&value, max_chars).trim_end().to_string()
    } else {
        value
    };
    if char_len(&value) < min_chars {
        return Err(report!(errors::ConnectorError::InvalidDataFormat {
            field_name: field_name.into()
        }));
    }
    Ok(value)
}

/// Validates the billing data the Izipay SDK needs. Izipay's hosted page rejects a missing
/// field only after the buyer was redirected, and the SDK throws client-side on a length out of
/// range, so every rule is checked here, before the buyer is sent anywhere.
pub fn build_billing(
    router_data: &PaymentsAuthorizeRouterData,
) -> CustomResult<IzipayBilling, errors::ConnectorError> {
    let billing = router_data.get_optional_billing();
    let address = billing.and_then(|billing| billing.address.as_ref());

    let first_name = name_within_range(
        required_text(
            address.and_then(|address| address.first_name.as_ref()),
            "billing.address.first_name",
        )?,
        "billing.address.first_name",
    )?;
    let last_name = name_within_range(
        required_text(
            address.and_then(|address| address.last_name.as_ref()),
            "billing.address.last_name",
        )?,
        "billing.address.last_name",
    )?;

    let email = billing
        .and_then(|billing| billing.email.as_ref())
        .or(router_data.request.email.as_ref())
        .map(|email| email.peek().trim().to_string())
        .filter(|email| !email.is_empty())
        .ok_or(errors::ConnectorError::MissingRequiredField {
            field_name: "billing.email".into(),
        })?;

    let phone_number: String = billing
        .and_then(|billing| billing.phone.as_ref())
        .and_then(|phone| phone.number.as_ref())
        .map(|number| {
            number
                .peek()
                .chars()
                .filter(char::is_ascii_digit)
                .collect::<String>()
        })
        .filter(|number| !number.is_empty())
        .ok_or(errors::ConnectorError::MissingRequiredField {
            field_name: "billing.phone.number".into(),
        })?;
    if !(7..=15).contains(&phone_number.len()) {
        return Err(report!(errors::ConnectorError::InvalidDataFormat {
            field_name: "billing.phone.number".into()
        }));
    }

    let line1 = required_text(
        address.and_then(|address| address.line1.as_ref()),
        "billing.address.line1",
    )?;
    let street = match address
        .and_then(|address| address.line2.as_ref())
        .map(|line2| line2.peek().trim().to_string())
        .filter(|line2| !line2.is_empty())
    {
        Some(line2) => format!("{line1} {line2}"),
        None => line1,
    };
    let street = truncated_text(street, 5, 40, "billing.address.line1")?;

    let city = truncated_text(
        address
            .and_then(|address| address.city.as_ref())
            .map(|city| city.trim().to_string())
            .filter(|city| !city.is_empty())
            .ok_or(errors::ConnectorError::MissingRequiredField {
                field_name: "billing.address.city".into(),
            })?,
        3,
        25,
        "billing.address.city",
    )?;
    let state = truncated_text(
        required_text(
            address.and_then(|address| address.state.as_ref()),
            "billing.address.state",
        )?,
        3,
        25,
        "billing.address.state",
    )?;

    let country = address
        .and_then(|address| address.country)
        .ok_or(errors::ConnectorError::MissingRequiredField {
            field_name: "billing.address.country".into(),
        })?
        .to_string();

    let postal_code = required_text(
        address.and_then(|address| address.zip.as_ref()),
        "billing.address.zip",
    )?;
    if !(5..=10).contains(&char_len(&postal_code)) {
        return Err(report!(errors::ConnectorError::InvalidDataFormat {
            field_name: "billing.address.zip".into()
        }));
    }

    let (document_type, document) = build_document(router_data.request.metadata.as_ref())?;

    Ok(IzipayBilling {
        first_name,
        last_name,
        email,
        phone_number,
        street,
        city,
        state,
        country,
        postal_code,
        document_type,
        document,
    })
}

const DOCUMENT_TYPE_METADATA_KEY: &str = "buyer_document_type";
const DOCUMENT_NUMBER_METADATA_KEY: &str = "buyer_document_number";

/// Identity document of the buyer: Izipay's hosted page silently refuses to submit a payment
/// without one (verified in the sandbox), and the Hyperswitch billing address has no document
/// field, so it comes from the payment metadata: `buyer_document_type` (DNI, CE, PASAPORTE,
/// RUC or OTROS) and `buyer_document_number`, with the lengths Izipay documents per type.
fn build_document(
    metadata: Option<&serde_json::Value>,
) -> CustomResult<(String, String), errors::ConnectorError> {
    let metadata_text = |key: &str| {
        metadata
            .and_then(|metadata| metadata.get(key))
            .and_then(serde_json::Value::as_str)
            .map(|value| value.trim().to_ascii_uppercase())
            .filter(|value| !value.is_empty())
    };

    let document_type = metadata_text(DOCUMENT_TYPE_METADATA_KEY).ok_or(
        errors::ConnectorError::MissingRequiredField {
            field_name: "metadata.buyer_document_type".into(),
        },
    )?;
    let document = metadata_text(DOCUMENT_NUMBER_METADATA_KEY).ok_or(
        errors::ConnectorError::MissingRequiredField {
            field_name: "metadata.buyer_document_number".into(),
        },
    )?;

    let (allowed_lengths, digits_only) = match document_type.as_str() {
        "DNI" => (8..=8, true),
        "RUC" => (11..=11, true),
        "CE" => (9..=12, false),
        "PASAPORTE" | "OTROS" => (8..=12, false),
        _ => {
            return Err(report!(errors::ConnectorError::InvalidDataFormat {
                field_name: "metadata.buyer_document_type".into()
            }))
        }
    };
    let valid_characters = if digits_only {
        document.chars().all(|character| character.is_ascii_digit())
    } else {
        document
            .chars()
            .all(|character| character.is_ascii_alphanumeric())
    };
    if !valid_characters || !allowed_lengths.contains(&document.len()) {
        return Err(report!(errors::ConnectorError::InvalidDataFormat {
            field_name: "metadata.buyer_document_number".into()
        }));
    }

    Ok((document_type, document))
}

/// Checks shared by both modes: PEN or USD and automatic capture (Izipay has no authorize-only
/// flow in this connector).
fn validate_currency_and_capture_method(
    router_data: &PaymentsAuthorizeRouterData,
) -> CustomResult<(), errors::ConnectorError> {
    if !matches!(
        router_data.request.currency,
        enums::Currency::PEN | enums::Currency::USD
    ) {
        return Err(errors::ConnectorError::CurrencyNotSupported {
            message: router_data.request.currency.to_string(),
            connector: IZIPAY_CONNECTOR_NAME,
        }
        .into());
    }

    if !matches!(
        router_data.request.capture_method,
        None | Some(enums::CaptureMethod::Automatic | enums::CaptureMethod::SequentialAutomatic)
    ) {
        return Err(errors::ConnectorError::NotSupported {
            message: "manual capture".to_string(),
            connector: IZIPAY_CONNECTOR_NAME.into(),
        }
        .into());
    }
    Ok(())
}

fn validate_authorize_request(
    router_data: &PaymentsAuthorizeRouterData,
) -> CustomResult<IzipayCheckoutData, errors::ConnectorError> {
    match &router_data.request.payment_method_data {
        PaymentMethodData::Wallet(WalletData::IzipayCheckout {}) => {}
        _ => {
            return Err(errors::ConnectorError::NotImplemented(
                get_unimplemented_payment_method_error_message("izipay"),
            )
            .into())
        }
    }

    validate_currency_and_capture_method(router_data)?;

    let return_url = router_data.request.router_return_url.clone().ok_or(
        errors::ConnectorError::MissingRequiredField {
            field_name: "router_return_url".into(),
        },
    )?;
    // Fails early when the return url cannot carry the result marker.
    result_url(&return_url, "success")?;

    let billing = build_billing(router_data)?;

    let customer_id = router_data
        .request
        .customer_id
        .as_ref()
        .map(|customer_id| customer_id.get_string_repr().to_string())
        .filter(|customer_id| (6..=100).contains(&char_len(customer_id)));
    let merchant_buyer_id = customer_id.unwrap_or_else(|| router_data.payment_id.clone());

    Ok(IzipayCheckoutData {
        billing,
        merchant_buyer_id,
        return_url,
    })
}

impl TryFrom<&IzipayRouterData<&PaymentsAuthorizeRouterData>> for IzipayTokenRequest {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: &IzipayRouterData<&PaymentsAuthorizeRouterData>,
    ) -> Result<Self, Self::Error> {
        // Everything the redirect page needs is checked now, so that a bad request fails here
        // and not in the buyer's browser.
        validate_authorize_request(item.router_data)?;
        let auth = IzipayAuthType::try_from(&item.router_data.connector_auth_type)?;
        Ok(Self::for_order(
            &auth,
            item.router_data.connector_request_reference_id.clone(),
            &item.amount,
        ))
    }
}

/// Value of `izipay_result` the bridge page uses when the Izipay Web SDK could not be opened.
const SDK_ERROR_RESULT: &str = "sdk_error";
/// Stable internal error code of a payment whose bridge page gave up opening the SDK.
pub const SDK_ERROR_CODE: &str = "IZIPAY_SDK_ERROR";
const MAX_SDK_ERROR_DETAIL_CHARS: usize = 200;
const MAX_SDK_ERROR_REASON_CHARS: usize = 40;

/// Why the bridge page could not open Izipay's checkout, read back from the return url query
/// (`izipay_result=sdk_error&izipay_error=..&izipay_error_detail=..`). Both values come from
/// the buyer's browser, so they are untrusted: they are only logged and stored in internal
/// error fields, never used for decisions beyond "the page gave up".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IzipaySdkError {
    pub reason: String,
    pub detail: Option<String>,
}

impl IzipaySdkError {
    /// Reads the raw query string of the return url (what the router keeps as `encoded_data`).
    pub fn from_return_query(query: Option<&str>) -> Option<Self> {
        let query = query?.trim_start_matches('?');
        let mut is_sdk_error = false;
        let mut reason = None;
        let mut detail = None;
        for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
            match key.as_ref() {
                "izipay_result" if value == SDK_ERROR_RESULT => is_sdk_error = true,
                "izipay_error" => reason = Some(sanitize_sdk_error_reason(&value)),
                "izipay_error_detail" => detail = sanitize_sdk_error_detail(&value),
                _ => {}
            }
        }
        is_sdk_error.then(|| Self {
            reason: reason.unwrap_or_else(|| "unknown".to_string()),
            detail,
        })
    }
}

/// Machine code: lowercase letters, digits and underscores only.
fn sanitize_sdk_error_reason(value: &str) -> String {
    let reason: String = value.chars().take(MAX_SDK_ERROR_REASON_CHARS + 1).collect();
    let is_valid = !reason.is_empty()
        && char_len(&reason) <= MAX_SDK_ERROR_REASON_CHARS
        && reason
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_');
    if is_valid {
        reason
    } else {
        "unknown".to_string()
    }
}

/// Free text from the browser: control characters dropped, whitespace collapsed, truncated.
fn sanitize_sdk_error_detail(value: &str) -> Option<String> {
    let cleaned = value
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    let truncated: String = cleaned.chars().take(MAX_SDK_ERROR_DETAIL_CHARS).collect();
    (!truncated.is_empty()).then_some(truncated)
}

/// The attempt statuses in which Izipay has not reported any payment: a page that gave up is
/// only believed then; a payment Izipay reports as charged (or denied, or voided) wins.
fn is_unpaid_status(status: enums::AttemptStatus) -> bool {
    matches!(
        status,
        enums::AttemptStatus::Started
            | enums::AttemptStatus::AuthenticationPending
            | enums::AttemptStatus::Pending
            | enums::AttemptStatus::PaymentMethodAwaited
            | enums::AttemptStatus::ConfirmationAwaited
    )
}

/// Appends the `izipay_result` marker to the merchant return url (`?` or `&` as needed).
fn result_url(return_url: &str, result: &str) -> CustomResult<String, errors::ConnectorError> {
    let mut url =
        url::Url::parse(return_url).change_context(errors::ConnectorError::InvalidDataFormat {
            field_name: "router_return_url".into(),
        })?;
    url.query_pairs_mut().append_pair("izipay_result", result);
    Ok(url.to_string())
}

/// Serializes a value for embedding inside a `<script>` element: the characters that could
/// close the element, open a comment or end a JavaScript line are written as `\uXXXX`
/// escapes (valid both in JSON and in JavaScript string literals).
fn json_for_script(value: &serde_json::Value) -> CustomResult<String, errors::ConnectorError> {
    let json = serde_json::to_string(value)
        .change_context(errors::ConnectorError::RequestEncodingFailed)?;
    Ok(json
        .replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('&', "\\u0026")
        .replace('\u{2028}', "\\u2028")
        .replace('\u{2029}', "\\u2029"))
}

const CHECKOUT_PAGE_TEMPLATE: &str = r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Izipay</title>
<style>body{font-family:sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;color:#333}</style>
</head>
<body>
<p id="izipay-status">Taking you to the payment page&hellip;</p>
<script>
var izipayData = __PAGE_DATA__;
(function () {
  var isSpanish = (navigator.language || '').toLowerCase().indexOf('es') === 0;
  var texts = isSpanish
    ? {
        loading: 'Te estamos llevando a la página de pago…',
        failed: 'No pudimos abrir la página de pago. Te llevamos de vuelta para que puedas intentarlo de nuevo.'
      }
    : {
        loading: 'Taking you to the payment page…',
        failed: 'We couldn’t open the payment page. Taking you back so you can try again.'
      };
  var statusElement = document.getElementById('izipay-status');
  if (isSpanish) { document.documentElement.lang = 'es'; }
  statusElement.textContent = texts.loading;

  var retryDelaysMs = [1000, 2000, 4000];
  var loadTimeoutMs = 15000;
  var maxDetailLength = 200;
  var retries = 0;
  var opened = false;
  var givenUp = false;

  function describe(error) {
    var text = 'script load error';
    if (typeof error === 'string') {
      text = error;
    } else if (error && error.message) {
      text = (error.name || 'Error') + ': ' + error.message;
    }
    [izipayData.authorization, izipayData.keyRSA].forEach(function (secret) {
      if (secret && typeof secret === 'string') { text = text.split(secret).join('[removed]'); }
    });
    return text.replace(/[\u0000-\u001f\u007f]+/g, ' ').replace(/\s+/g, ' ').trim().slice(0, maxDetailLength);
  }

  function giveUp(code, error) {
    if (givenUp || opened) { return; }
    givenUp = true;
    statusElement.textContent = texts.failed;
    var url = izipayData.sdkErrorUrl;
    url += (url.indexOf('?') < 0 ? '?' : '&') + 'izipay_error=' + encodeURIComponent(code) +
      '&izipay_error_detail=' + encodeURIComponent(describe(error));
    setTimeout(function () { window.location.replace(url); }, 3000);
  }

  function retry(code, error) {
    if (opened || givenUp) { return; }
    if (retries >= retryDelaysMs.length) { giveUp(code, error); return; }
    var delay = retryDelaysMs[retries];
    retries += 1;
    setTimeout(attempt, delay);
  }

  function loadSdk(onReady, onFailed) {
    var settled = false;
    var script = document.createElement('script');
    var timer = null;
    function settle(error) {
      if (settled) { return; }
      settled = true;
      clearTimeout(timer);
      if (error === null) { onReady(); return; }
      if (script.parentNode) { script.parentNode.removeChild(script); }
      onFailed(error);
    }
    var url = izipayData.sdkUrl;
    if (retries > 0) { url += (url.indexOf('?') < 0 ? '?' : '&') + 'retry=' + retries; }
    script.async = true;
    script.onload = function () { settle(null); };
    script.onerror = function () { settle('script load error'); };
    timer = setTimeout(function () { settle('script load timeout'); }, loadTimeoutMs);
    script.src = url;
    document.head.appendChild(script);
  }

  function openForm() {
    if (opened) { return; }
    try {
      var checkout = new Izipay({ config: izipayData.config });
      checkout.LoadForm({ authorization: izipayData.authorization, keyRSA: izipayData.keyRSA });
      opened = true;
    } catch (error) {
      retry('sdk_init_failed', error);
    }
  }

  function attempt() {
    if (opened || givenUp) { return; }
    if (typeof Izipay === 'undefined') {
      loadSdk(openForm, function (error) { retry('sdk_load_failed', error); });
    } else {
      openForm();
    }
  }

  attempt();
})();
</script>
</body>
</html>
"#;

pub struct CheckoutPageParams<'a> {
    pub environment: IzipayEnvironment,
    pub transaction_id: &'a str,
    pub merchant_code: &'a str,
    pub order_number: &'a str,
    pub currency: &'a str,
    pub amount: &'a str,
    pub checkout: &'a IzipayCheckoutData,
    pub webhook_url: Option<&'a str>,
    pub session_token: &'a str,
    pub key_rsa: &'a str,
    pub date_time_transaction: &'a str,
}

/// The page that loads the Izipay Web SDK and opens the hosted checkout in redirect mode.
/// Every dynamic value (including buyer data) goes through JSON serialization and the script
/// escaping above; nothing is concatenated into the markup.
pub fn build_checkout_page(
    params: &CheckoutPageParams<'_>,
) -> CustomResult<String, errors::ConnectorError> {
    let billing = &params.checkout.billing;
    let return_url = &params.checkout.return_url;
    let mut config = serde_json::json!({
        "transactionId": params.transaction_id,
        "action": "pay",
        "merchantCode": params.merchant_code,
        "order": {
            "orderNumber": params.order_number,
            "currency": params.currency,
            "amount": params.amount,
            "processType": "AT",
            "merchantBuyerId": params.checkout.merchant_buyer_id,
            "dateTimeTransaction": params.date_time_transaction,
            "payMethod": "all",
        },
        "billing": {
            "firstName": billing.first_name,
            "lastName": billing.last_name,
            "email": billing.email,
            "phoneNumber": billing.phone_number,
            "street": billing.street,
            "city": billing.city,
            "state": billing.state,
            "country": billing.country,
            "postalCode": billing.postal_code,
            "documentType": billing.document_type,
            "document": billing.document,
        },
        "render": {
            "typeForm": "redirect",
            "redirectUrls": {
                "onSuccess": result_url(return_url, "success")?,
                "onError": result_url(return_url, "error")?,
                "onCancel": result_url(return_url, "cancel")?,
            },
        },
    });
    if let (Some(webhook_url), Some(config)) = (params.webhook_url, config.as_object_mut()) {
        config.insert("urlIPN".to_string(), serde_json::json!(webhook_url));
    }
    let page_data = serde_json::json!({
        "config": config,
        "authorization": params.session_token,
        "keyRSA": params.key_rsa,
        "sdkErrorUrl": result_url(return_url, SDK_ERROR_RESULT)?,
        "sdkUrl": params.environment.sdk_url(),
    });

    Ok(CHECKOUT_PAGE_TEMPLATE.replace("__PAGE_DATA__", &json_for_script(&page_data)?))
}

/// Token/Generate answered: builds the redirect to the hosted checkout. `amount` is the same
/// major-unit string the session token was bound to.
pub fn authorize_response(
    response: IzipayTokenResponse,
    data: PaymentsAuthorizeRouterData,
    http_code: u16,
    amount: &StringMajorUnit,
) -> CustomResult<PaymentsAuthorizeRouterData, errors::ConnectorError> {
    let Some(session_token) = response.session_token() else {
        return Ok(RouterData {
            status: enums::AttemptStatus::Failure,
            response: Err(error_response_from_code(
                &response.code,
                response.message.as_deref(),
                http_code,
                Some(enums::AttemptStatus::Failure),
            )),
            ..data
        });
    };
    let transaction_id = transaction_id_from_session_token(session_token.peek())
        .ok_or(errors::ConnectorError::ResponseHandlingFailed)
        .attach_printable("Izipay session token carries no transactionId claim")?;

    let auth = IzipayAuthType::try_from(&data.connector_auth_type)?;
    let checkout = validate_authorize_request(&data)?;
    let order_number = data.connector_request_reference_id.clone();
    let currency = data.request.currency.to_string();
    let amount = amount.get_amount_as_string();

    let page = build_checkout_page(&CheckoutPageParams {
        environment: IzipayEnvironment::from_test_mode(data.test_mode),
        transaction_id: &transaction_id,
        merchant_code: &auth.merchant_code,
        order_number: &order_number,
        currency: &currency,
        amount: &amount,
        checkout: &checkout,
        webhook_url: data.request.webhook_url.as_deref(),
        session_token: session_token.peek(),
        key_rsa: auth.rsa_key.peek(),
        date_time_transaction: &current_date_time_transaction(),
    })?;

    Ok(RouterData {
        status: enums::AttemptStatus::AuthenticationPending,
        response: Ok(PaymentsResponseData::TransactionResponse {
            resource_id: ResponseId::ConnectorTransactionId(order_number.clone()),
            redirection_data: Box::new(Some(RedirectForm::Html { html_data: page })),
            mandate_reference: Box::new(None),
            connector_metadata: Some(serde_json::json!({
                "transaction_id": transaction_id,
                "order_number": order_number,
            })),
            network_txn_id: None,
            connector_response_reference_id: Some(order_number),
            incremental_authorization_allowed: None,
            charges: None,
            network_txn_link_id: None,
            payment_account_reference: None,
            authentication_data: None,
        }),
        ..data
    })
}

// ============================================================================
// PSync: Transaction/Search (also the shape of the notification payload)
// ============================================================================

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IzipaySearchRequest {
    merchant_code: String,
    number_orden: String,
    language: &'static str,
}

impl TryFrom<&PaymentsSyncRouterData> for IzipaySearchRequest {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(req: &PaymentsSyncRouterData) -> Result<Self, Self::Error> {
        let auth = IzipayAuthType::try_from(&req.connector_auth_type)?;
        Ok(Self {
            merchant_code: auth.merchant_code,
            number_orden: req.connector_request_reference_id.clone(),
            language: "ESP",
        })
    }
}

/// Tolerant on purpose: Izipay sends `null` for many fields and the notification payload is a
/// superset of the Search response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IzipaySearchResponse {
    pub code: String,
    pub message: Option<String>,
    pub message_user: Option<String>,
    pub response: Option<IzipaySearchBody>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IzipaySearchBody {
    pub order: Option<Vec<IzipayOrder>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IzipayOrder {
    pub pay_method_authorization: Option<String>,
    pub code_auth: Option<String>,
    pub currency: Option<String>,
    pub amount: Option<String>,
    pub order_number: Option<String>,
    pub state_message: Option<String>,
    pub date_transaction: Option<String>,
    pub time_transaction: Option<String>,
    pub unique_id: Option<String>,
    pub reference_number: Option<String>,
}

impl IzipaySearchResponse {
    /// The order the outcome is read from: the authorized entry when there is one (a voided
    /// order is listed with a different entry), otherwise the first one.
    fn selected_order(&self) -> Option<&IzipayOrder> {
        let orders = self.response.as_ref()?.order.as_ref()?;
        orders
            .iter()
            .find(|order| state_is(order.state_message.as_deref(), ORDER_AUTHORIZED))
            .or_else(|| orders.first())
    }

    fn user_message(&self) -> Option<&str> {
        self.message_user
            .as_deref()
            .or(self.message.as_deref())
            .filter(|message| !message.is_empty())
    }
}

fn state_is(state_message: Option<&str>, expected: &str) -> bool {
    state_message.is_some_and(|state| state.trim().eq_ignore_ascii_case(expected))
}

/// Outcome of a Search (or notification payload):
/// - `00` and `Autorizado`: charged
/// - `00` and `Anulado`: voided
/// - `Denegado` or any code other than `00`: failed
/// - anything else: still pending
pub fn map_search_status(code: &str, order: Option<&IzipayOrder>) -> enums::AttemptStatus {
    let state_message = order.and_then(|order| order.state_message.as_deref());
    if code == SUCCESS_CODE && state_is(state_message, ORDER_AUTHORIZED) {
        enums::AttemptStatus::Charged
    } else if code == SUCCESS_CODE && state_is(state_message, ORDER_VOIDED) {
        enums::AttemptStatus::Voided
    } else if code != SUCCESS_CODE || state_is(state_message, ORDER_DENIED) {
        enums::AttemptStatus::Failure
    } else {
        enums::AttemptStatus::Pending
    }
}

/// `connector_metadata` of a charged payment: what Authorize stored plus the data a refund needs.
fn charged_connector_metadata(
    previous: Option<&serde_json::Value>,
    order: &IzipayOrder,
) -> serde_json::Value {
    let mut metadata = match previous {
        Some(serde_json::Value::Object(previous)) => previous.clone(),
        _ => serde_json::Map::new(),
    };
    let fields = [
        ("unique_id", &order.unique_id),
        ("authorization_code", &order.code_auth),
        ("reference_number", &order.reference_number),
        ("transaction_date", &order.date_transaction),
        ("transaction_time", &order.time_transaction),
        ("pay_method", &order.pay_method_authorization),
        ("currency", &order.currency),
        ("amount", &order.amount),
    ];
    for (key, value) in fields {
        if let Some(value) = value.as_ref().filter(|value| !value.is_empty()) {
            metadata.insert(key.to_string(), serde_json::json!(value));
        }
    }
    serde_json::Value::Object(metadata)
}

impl TryFrom<PaymentsSyncResponseRouterData<IzipaySearchResponse>> for PaymentsSyncRouterData {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: PaymentsSyncResponseRouterData<IzipaySearchResponse>,
    ) -> Result<Self, Self::Error> {
        let response = item.response;
        let order = response.selected_order();
        let order_number = order
            .and_then(|order| order.order_number.clone())
            .filter(|order_number| !order_number.is_empty())
            .unwrap_or_else(|| item.data.connector_request_reference_id.clone());
        let resource_id = order_number.clone();

        // "Transaction does not exist": the buyer has not paid (yet), so the attempt keeps the
        // status it has. Izipay answers it with HTTP 403, which is handled as an error (see
        // `get_error_response`); this covers a 2xx carrying the same code.
        let status = match map_search_status(&response.code, order) {
            _ if response.code == "MC" => item.data.status,
            // An order that was already charged and is now voided is a post-capture void
            // (the IPN of one we requested, or one done from Izipay's back office).
            enums::AttemptStatus::Voided
                if matches!(
                    item.data.status,
                    enums::AttemptStatus::Charged | enums::AttemptStatus::VoidedPostCharge
                ) =>
            {
                enums::AttemptStatus::VoidedPostCharge
            }
            status => status,
        };

        // The bridge page gave up opening the checkout and the buyer came back with
        // `izipay_result=sdk_error`. Izipay's own answer always wins: only when it reports
        // nothing paid is the attempt failed with a code we can find.
        let sdk_error =
            IzipaySdkError::from_return_query(item.data.request.encoded_data.as_deref())
                .filter(|_| is_unpaid_status(status));
        let status = if sdk_error.is_some() {
            enums::AttemptStatus::Failure
        } else {
            status
        };

        let payment_response = if status == enums::AttemptStatus::Failure {
            let (code, message, reason) = match &sdk_error {
                Some(sdk_error) => (
                    SDK_ERROR_CODE.to_string(),
                    format!(
                        "The Izipay checkout page could not be opened ({})",
                        sdk_error.reason
                    ),
                    sdk_error.detail.clone(),
                ),
                None => (
                    response.code.clone(),
                    response
                        .user_message()
                        .unwrap_or("Transaction declined")
                        .to_string(),
                    response.message.clone(),
                ),
            };
            Err(ErrorResponse {
                status_code: item.http_code,
                code,
                message,
                reason,
                attempt_status: Some(status),
                connector_transaction_id: Some(resource_id),
                network_advice_code: None,
                network_decline_code: None,
                network_error_message: None,
                connector_metadata: None,
                connector_response_reference_id: None,
            })
        } else {
            // A voided order is listed with a new unique id and authorization code: they must
            // never replace the ones a refund needs, so only a charged order refreshes them.
            let connector_metadata = match (status, order) {
                (enums::AttemptStatus::Charged, Some(order)) => Some(charged_connector_metadata(
                    item.data.request.connector_meta.as_ref(),
                    order,
                )),
                _ => None,
            };
            Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(resource_id),
                redirection_data: Box::new(None),
                mandate_reference: Box::new(None),
                connector_metadata,
                network_txn_id: None,
                connector_response_reference_id: Some(order_number),
                incremental_authorization_allowed: None,
                charges: None,
                network_txn_link_id: None,
                payment_account_reference: None,
                authentication_data: None,
            })
        };

        Ok(Self {
            status,
            response: payment_response,
            ..item.data
        })
    }
}

// ============================================================================
// Post-capture void: POST /cancel/api/Transaction/Cancel (ECOMMERCE session token bound to the
// original order number and amount, see `post_capture_void_binding`). Izipay voids the whole
// payment the day it was made (before 21:00 Lima time); after that a refund is needed.
// ============================================================================

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IzipayCancelRequest {
    merchant_code: String,
    order: IzipayCancelOrder,
    language: &'static str,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IzipayCancelOrder {
    order_number: String,
    currency: String,
    amount: String,
    pay_method: String,
    channel: &'static str,
    unique_id: String,
    authorization_code: String,
    transaction_datetime: String,
}

fn metadata_str<'a>(metadata: Option<&'a serde_json::Value>, key: &str) -> Option<&'a str> {
    metadata
        .and_then(|metadata| metadata.get(key))
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty())
}

/// `transactionDatetime` of the payment to void, from what the sync that charged it stored:
/// `transaction_date` (`YYYYMMDD`) and `transaction_time` (`HHMMSS`). Payments charged before
/// the time was stored fall back to `00:00:00`.
fn transaction_datetime(
    metadata: Option<&serde_json::Value>,
) -> CustomResult<String, errors::ConnectorError> {
    let date = metadata_text(
        metadata,
        "transaction_date",
        "connector_metadata.transaction_date",
    )?;
    let time = metadata_str(metadata, "transaction_time").unwrap_or("000000");
    let is_digits = |value: &str, len: usize| {
        value.len() == len && value.chars().all(|digit| digit.is_ascii_digit())
    };
    if !is_digits(&date, 8) {
        return Err(report!(errors::ConnectorError::InvalidDataFormat {
            field_name: "connector_metadata.transaction_date".into()
        }));
    }
    if !is_digits(time, 6) {
        return Err(report!(errors::ConnectorError::InvalidDataFormat {
            field_name: "connector_metadata.transaction_time".into()
        }));
    }
    Ok(format!(
        "{}-{}-{} {}:{}:{}.000",
        &date[0..4],
        &date[4..6],
        &date[6..8],
        &time[0..2],
        &time[2..4],
        &time[4..6]
    ))
}

impl TryFrom<&PaymentsCancelPostCaptureRouterData> for IzipayCancelRequest {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(req: &PaymentsCancelPostCaptureRouterData) -> Result<Self, Self::Error> {
        let auth = IzipayAuthType::try_from(&req.connector_auth_type)?;
        let currency =
            req.request
                .currency
                .ok_or(errors::ConnectorError::MissingRequiredField {
                    field_name: "currency".into(),
                })?;
        if !matches!(currency, enums::Currency::PEN | enums::Currency::USD) {
            return Err(errors::ConnectorError::CurrencyNotSupported {
                message: currency.to_string(),
                connector: IZIPAY_CONNECTOR_NAME,
            }
            .into());
        }
        let minor_amount =
            req.request
                .minor_amount
                .ok_or(errors::ConnectorError::MissingRequiredField {
                    field_name: "minor_amount".into(),
                })?;
        let amount = two_decimal_amount(minor_amount);
        let payment_metadata = req.request.connector_meta.as_ref();

        // Only the whole payment can be voided: the amount must be the one Izipay approved.
        if let Some(approved_amount) = metadata_str(payment_metadata, "amount") {
            if approved_amount != amount {
                return Err(errors::ConnectorError::NotSupported {
                    message: "Partial post-capture void".to_string(),
                    connector: IZIPAY_CONNECTOR_NAME.into(),
                }
                .into());
            }
        }

        Ok(Self {
            merchant_code: auth.merchant_code,
            order: IzipayCancelOrder {
                order_number: req.request.connector_transaction_id.clone(),
                currency: currency.to_string(),
                amount,
                pay_method: metadata_str(payment_metadata, "pay_method")
                    .unwrap_or("CARD")
                    .to_string(),
                channel: "ecommerce",
                unique_id: metadata_text(
                    payment_metadata,
                    "unique_id",
                    "connector_metadata.unique_id",
                )?,
                authorization_code: metadata_text(
                    payment_metadata,
                    "authorization_code",
                    "connector_metadata.authorization_code",
                )?,
                transaction_datetime: transaction_datetime(payment_metadata)?,
            },
            language: "ESP",
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IzipayCancelResponse {
    pub code: String,
    pub message: Option<String>,
    pub response: Option<IzipayCancelBody>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IzipayCancelBody {
    pub result: Option<IzipayCancelResult>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IzipayCancelResult {
    pub message_friendly: Option<String>,
    pub unique_id_cancel: Option<String>,
}

impl
    TryFrom<
        ResponseRouterData<
            PostCaptureVoid,
            IzipayCancelResponse,
            PaymentsCancelPostCaptureData,
            PaymentsResponseData,
        >,
    > for PaymentsCancelPostCaptureRouterData
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<
            PostCaptureVoid,
            IzipayCancelResponse,
            PaymentsCancelPostCaptureData,
            PaymentsResponseData,
        >,
    ) -> Result<Self, Self::Error> {
        if item.response.code != SUCCESS_CODE {
            let message = item
                .response
                .response
                .as_ref()
                .and_then(|body| body.result.as_ref())
                .and_then(|result| result.message_friendly.as_deref())
                .or(item.response.message.as_deref());
            // The attempt keeps the status it has: a failed void leaves it charged.
            return Ok(Self {
                response: Err(error_response_from_code(
                    &item.response.code,
                    message,
                    item.http_code,
                    None,
                )),
                ..item.data
            });
        }
        let order_number = item.data.request.connector_transaction_id.clone();
        let unique_id_cancel = item
            .response
            .response
            .as_ref()
            .and_then(|body| body.result.as_ref())
            .and_then(|result| result.unique_id_cancel.clone())
            .filter(|unique_id| !unique_id.is_empty());
        // What a refund or another void needs (`unique_id`, `authorization_code`) must stay as
        // it is: the cancellation id is stored beside it.
        let mut metadata = match item.data.request.connector_meta.as_ref() {
            Some(serde_json::Value::Object(previous)) => previous.clone(),
            _ => serde_json::Map::new(),
        };
        if let Some(unique_id_cancel) = unique_id_cancel {
            metadata.insert(
                "unique_id_cancel".to_string(),
                serde_json::json!(unique_id_cancel),
            );
        }
        Ok(Self {
            status: enums::AttemptStatus::VoidedPostCharge,
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(order_number.clone()),
                redirection_data: Box::new(None),
                mandate_reference: Box::new(None),
                connector_metadata: Some(serde_json::Value::Object(metadata)),
                network_txn_id: None,
                connector_response_reference_id: Some(order_number),
                incremental_authorization_allowed: None,
                charges: None,
                network_txn_link_id: None,
                payment_account_reference: None,
                authentication_data: None,
            }),
            ..item.data
        })
    }
}

// ============================================================================
// Refunds
// ============================================================================

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IzipayRefundRequest {
    merchant_code: String,
    ruc: String,
    id_unique: String,
    order: IzipayRefundOrder,
    card: IzipayRefundCard,
    language: &'static str,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IzipayRefundOrder {
    authorization_code: String,
    reference_number: String,
    currency: String,
    refund_amount: StringMajorUnit,
    /// Izipay documents these two as "must be empty".
    total_amount: &'static str,
    transaction_date: &'static str,
}

/// Izipay documents every card field as "must be empty".
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IzipayRefundCard {
    brand: &'static str,
    first_six_digits: &'static str,
    last_four_digits: &'static str,
}

fn metadata_text(
    metadata: Option<&serde_json::Value>,
    key: &str,
    field_name: &'static str,
) -> CustomResult<String, errors::ConnectorError> {
    metadata
        .and_then(|metadata| metadata.get(key))
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .ok_or_else(|| {
            report!(errors::ConnectorError::MissingRequiredField {
                field_name: field_name.into()
            })
        })
}

fn merchant_ruc(
    connector_meta_data: Option<&Secret<serde_json::Value>>,
) -> CustomResult<String, errors::ConnectorError> {
    let ruc = connector_meta_data
        .and_then(|metadata| metadata.peek().get("ruc"))
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|ruc| !ruc.is_empty())
        .ok_or(errors::ConnectorError::MissingRequiredField {
            field_name: "connector_metadata.ruc".into(),
        })?;
    if ruc.len() == 11 && ruc.chars().all(|digit| digit.is_ascii_digit()) {
        Ok(ruc.to_string())
    } else {
        Err(report!(errors::ConnectorError::InvalidDataFormat {
            field_name: "connector_metadata.ruc".into()
        }))
    }
}

impl TryFrom<&IzipayRouterData<&RefundsRouterData<Execute>>> for IzipayRefundRequest {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(item: &IzipayRouterData<&RefundsRouterData<Execute>>) -> Result<Self, Self::Error> {
        let req = item.router_data;
        let auth = IzipayAuthType::try_from(&req.connector_auth_type)?;
        let ruc = merchant_ruc(req.connector_meta_data.as_ref())?;
        if !matches!(
            req.request.currency,
            enums::Currency::PEN | enums::Currency::USD
        ) {
            return Err(errors::ConnectorError::CurrencyNotSupported {
                message: req.request.currency.to_string(),
                connector: IZIPAY_CONNECTOR_NAME,
            }
            .into());
        }
        // What Izipay needs to find the payment was stored by the payment sync that charged it.
        let payment_metadata = req.request.connector_metadata.as_ref();
        Ok(Self {
            merchant_code: auth.merchant_code,
            ruc,
            id_unique: metadata_text(
                payment_metadata,
                "unique_id",
                "connector_metadata.unique_id",
            )?,
            order: IzipayRefundOrder {
                authorization_code: metadata_text(
                    payment_metadata,
                    "authorization_code",
                    "connector_metadata.authorization_code",
                )?,
                reference_number: metadata_text(
                    payment_metadata,
                    "reference_number",
                    "connector_metadata.reference_number",
                )?,
                currency: req.request.currency.to_string(),
                refund_amount: item.amount.clone(),
                total_amount: "",
                transaction_date: "",
            },
            card: IzipayRefundCard {
                brand: "",
                first_six_digits: "",
                last_four_digits: "",
            },
            language: "ESP",
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IzipayRefundResponse {
    pub code: String,
    pub message: Option<String>,
    pub response: Option<IzipayRefundBody>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IzipayRefundBody {
    pub result: Option<IzipayRefundResult>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IzipayRefundResult {
    pub message_friendly: Option<String>,
    pub refund_transaction_id: Option<String>,
}

impl TryFrom<RefundsResponseRouterData<Execute, IzipayRefundResponse>>
    for RefundsRouterData<Execute>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: RefundsResponseRouterData<Execute, IzipayRefundResponse>,
    ) -> Result<Self, Self::Error> {
        let refund_id = item
            .response
            .response
            .as_ref()
            .and_then(|body| body.result.as_ref())
            .and_then(|result| result.refund_transaction_id.clone())
            .filter(|refund_id| !refund_id.is_empty());
        let response = match (item.response.code == SUCCESS_CODE, refund_id) {
            (true, Some(connector_refund_id)) => Ok(RefundsResponseData {
                connector_refund_id,
                // Izipay registers the refund; its final state comes from the status API.
                refund_status: enums::RefundStatus::Pending,
            }),
            (true, None) => return Err(errors::ConnectorError::ResponseHandlingFailed.into()),
            (false, _) => Err(error_response_from_code(
                &item.response.code,
                item.response.message.as_deref(),
                item.http_code,
                None,
            )),
        };
        Ok(Self {
            response,
            ..item.data
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IzipayRefundStatusResponse {
    pub code: String,
    pub message: Option<String>,
    pub response: Option<IzipayRefundStatusBody>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IzipayRefundStatusBody {
    pub status_code: Option<String>,
    pub status_name: Option<String>,
    pub response_code: Option<String>,
    pub rejection_reason: Option<String>,
}

/// Maps the refund status by its name. Izipay documents the status codes only by example
/// (`50`, `60`, `40`), not their meaning, so the codes are deliberately not used.
pub fn map_refund_status(status_name: Option<&str>) -> enums::RefundStatus {
    match status_name
        .map(|name| name.trim().to_uppercase())
        .as_deref()
    {
        Some("AUTORIZADO" | "PROCESADO" | "APROBADO" | "ABONADO" | "DEVUELTO") => {
            enums::RefundStatus::Success
        }
        Some("RECHAZADO" | "DENEGADO" | "ANULADO" | "ERROR") => enums::RefundStatus::Failure,
        _ => enums::RefundStatus::Pending,
    }
}

impl TryFrom<RefundsResponseRouterData<RSync, IzipayRefundStatusResponse>>
    for RefundsRouterData<RSync>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: RefundsResponseRouterData<RSync, IzipayRefundStatusResponse>,
    ) -> Result<Self, Self::Error> {
        let connector_refund_id = item.data.request.connector_refund_id.clone().ok_or(
            errors::ConnectorError::MissingRequiredField {
                field_name: "connector_refund_id".into(),
            },
        )?;
        let body = item.response.response.as_ref();
        let response = if item.response.code != SUCCESS_CODE {
            Err(error_response_from_code(
                &item.response.code,
                item.response.message.as_deref(),
                item.http_code,
                None,
            ))
        } else {
            let refund_status =
                map_refund_status(body.and_then(|body| body.status_name.as_deref()));
            if refund_status == enums::RefundStatus::Failure {
                Err(ErrorResponse {
                    status_code: item.http_code,
                    code: body
                        .and_then(|body| body.response_code.clone())
                        .unwrap_or_else(|| item.response.code.clone()),
                    message: body
                        .and_then(|body| body.rejection_reason.clone())
                        .filter(|reason| !reason.is_empty())
                        .or_else(|| body.and_then(|body| body.status_name.clone()))
                        .unwrap_or_else(|| "Refund rejected by Izipay".to_string()),
                    reason: item.response.message.clone(),
                    attempt_status: None,
                    connector_transaction_id: Some(connector_refund_id),
                    network_advice_code: None,
                    network_decline_code: None,
                    network_error_message: None,
                    connector_metadata: None,
                    connector_response_reference_id: None,
                })
            } else {
                Ok(RefundsResponseData {
                    connector_refund_id,
                    refund_status,
                })
            }
        };
        Ok(Self {
            response,
            ..item.data
        })
    }
}

// ============================================================================
// Errors
// ============================================================================

/// Izipay error bodies vary by service: `{code, message}`, `{code, message, messageUser, ..}`
/// and, for refunds, `{code, message, header, response: {messageFriendly, ..}}`.
#[derive(Debug, Serialize)]
pub struct IzipayErrorResponse {
    pub code: String,
    pub message: String,
    pub reason: Option<String>,
}

impl IzipayErrorResponse {
    /// `None` when the body is not a JSON object carrying a code or a message.
    pub fn parse(body: &[u8]) -> Option<Self> {
        let value: serde_json::Value = serde_json::from_slice(body).ok()?;
        let object = value.as_object()?;
        let text = |value: Option<&serde_json::Value>| -> Option<String> {
            match value? {
                serde_json::Value::String(text) if !text.trim().is_empty() => {
                    Some(text.trim().to_string())
                }
                serde_json::Value::Number(number) => Some(number.to_string()),
                _ => None,
            }
        };
        let code = text(object.get("code"));
        let message = text(object.get("message"));
        let friendly = text(
            object
                .get("response")
                .and_then(|response| response.get("messageFriendly")),
        );
        let message_user = text(object.get("messageUser"));
        if code.is_none() && message.is_none() && friendly.is_none() && message_user.is_none() {
            return None;
        }
        let best_message = friendly
            .or(message_user)
            .or_else(|| message.clone())
            .unwrap_or_else(|| "Izipay rejected the request".to_string());
        Some(Self {
            code: code.unwrap_or_else(|| "NO_ERROR_CODE".to_string()),
            reason: message.filter(|message| *message != best_message),
            message: best_message,
        })
    }
}

// ============================================================================
// Incoming notifications (IPN)
// ============================================================================

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IzipayWebhookBody {
    pub payload_http: Option<String>,
    pub signature: Option<String>,
}

/// Checks `base64(HMAC-SHA256(payloadHttp, hash key)) == signature`. The signature is read from
/// the body, falling back to the `Signature` header. The comparison is constant time.
pub fn verify_webhook_signature(
    body: &[u8],
    header_signature: Option<&str>,
    hash_key: &Secret<String>,
) -> CustomResult<bool, errors::ConnectorError> {
    let webhook_body: IzipayWebhookBody = serde_json::from_slice(body)
        .change_context(errors::ConnectorError::WebhookSignatureNotFound)?;
    let payload_http = webhook_body
        .payload_http
        .ok_or(errors::ConnectorError::WebhookSignatureNotFound)?;
    let signature = webhook_body
        .signature
        .filter(|signature| !signature.is_empty())
        .or_else(|| header_signature.map(str::to_string))
        .ok_or(errors::ConnectorError::WebhookSignatureNotFound)?;
    let signature = base64::engine::general_purpose::STANDARD
        .decode(signature.trim())
        .change_context(errors::ConnectorError::WebhookSignatureNotFound)?;
    HmacSha256
        .verify_signature(
            hash_key.peek().as_bytes(),
            &signature,
            payload_http.as_bytes(),
        )
        .change_context(errors::ConnectorError::WebhookSourceVerificationFailed)
}

/// The signed payload of a notification, parsed. Only this is ever read: the unsigned fields of
/// the notification body can be edited by anyone.
pub fn parse_signed_payload(
    body: &[u8],
) -> CustomResult<IzipaySearchResponse, errors::ConnectorError> {
    let webhook_body: IzipayWebhookBody = serde_json::from_slice(body)
        .change_context(errors::ConnectorError::WebhookBodyDecodingFailed)?;
    let payload_http = webhook_body
        .payload_http
        .ok_or(errors::ConnectorError::WebhookBodyDecodingFailed)?;
    serde_json::from_str(&payload_http)
        .change_context(errors::ConnectorError::WebhookBodyDecodingFailed)
}

/// The signed payload as a JSON value, handed to the PSync response handler.
pub fn signed_payload_value(
    body: &[u8],
) -> CustomResult<serde_json::Value, errors::ConnectorError> {
    let webhook_body: IzipayWebhookBody = serde_json::from_slice(body)
        .change_context(errors::ConnectorError::WebhookResourceObjectNotFound)?;
    let payload_http = webhook_body
        .payload_http
        .ok_or(errors::ConnectorError::WebhookResourceObjectNotFound)?;
    serde_json::from_str(&payload_http)
        .change_context(errors::ConnectorError::WebhookResourceObjectNotFound)
}

/// Reference of a notification: the order number of the first order of the signed payload.
pub fn webhook_reference(payload: &IzipaySearchResponse) -> Option<String> {
    payload
        .response
        .as_ref()?
        .order
        .as_ref()?
        .first()?
        .order_number
        .clone()
        .filter(|order_number| !order_number.is_empty())
}

pub fn map_webhook_event(payload: &IzipaySearchResponse) -> IncomingWebhookEvent {
    match map_search_status(&payload.code, payload.selected_order()) {
        enums::AttemptStatus::Charged => IncomingWebhookEvent::PaymentIntentSuccess,
        enums::AttemptStatus::Failure => IncomingWebhookEvent::PaymentIntentFailure,
        // A cancelled (voided) order is not turned into a failed payment: it may be the
        // reversal of a payment that was charged and refunded outside Hyperswitch.
        _ => IncomingWebhookEvent::EventNotSupported,
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use std::str::FromStr;

    use common_utils::{crypto::SignMessage, types::MinorUnit};
    use hyperswitch_domain_models::{
        address::{Address, AddressDetails, PhoneDetails},
        payment_address::PaymentAddress,
        router_flow_types::payments::{Authorize, PSync},
        router_request_types::{PaymentsAuthorizeData, PaymentsSyncData, RefundsData},
    };

    use super::*;

    const SEARCH_APPROVED: &str = r#"{"code":"00","message":"Operación exitosa","messageUser":"Operación exitosa","messageUserEng":"Successful","response":{"payMethod":"CARD","order":[{"payMethodAuthorization":"CARD","codeAuth":"S97758","currency":"PEN","amount":"1.99","installment":"00","deferred":"0","orderNumber":"PX1790971180429","stateMessage":"Autorizado","dateTransaction":"20261002","timeTransaction":"150001","uniqueId":"450249587","referenceNumber":"2000000"}],"card":{"brand":"VS","pan":"497010******0055","save":"false"},"billing":{"firstName":"Lucho","lastName":"Torres","email":"luchotorres@izipay.pe","phoneNumber":"989897960","street":"Av. Jorge Chavez 275","city":"Lima","state":"Lima","country":"PE","postalCode":"15000","documentType":"DNI","document":"12345678","companyName":""},"merchant":{"merchantCode":"4004353","facilitatorCode":""},"token":{"merchantBuyerId":"pxsol-test-buyer","cardToken":"","alias":""},"authentication":{"result":""},"customFields":[{"name":"field1","value":""}],"miles":{"netMiles":"","miles":""}},"payloadHttp":"{}","transactionId":"17909712094450964","signature":"CoFcYSUHzQJmJHuSwRY38K6TDyqmdDAmuxyRcEtHMsI="}"#;

    const SEARCH_DECLINED: &str = r#"{"code":"51","message":"Fondos Insuficientes","messageUser":"Fondos Insuficientes","messageUserEng":"Insufficient funds","response":{"payMethod":"CARD","order":[{"payMethodAuthorization":"CARD","codeAuth":"","currency":"PEN","amount":"1.99","installment":"00","deferred":"0","orderNumber":"PX1790971250459","stateMessage":"Denegado","dateTransaction":"20261002","timeTransaction":"150109","uniqueId":"450249588","referenceNumber":"2000000"}]}}"#;

    const SEARCH_VOIDED: &str = r#"{"code":"00","message":"Operación exitosa","messageUser":"Operación exitosa","messageUserEng":"Successful","response":{"payMethod":"CARD","order":[{"payMethodAuthorization":"CARD","codeAuth":"S80214","currency":"PEN","amount":"1.99","installment":"00","deferred":"0","orderNumber":"PX1790971180429","stateMessage":"Anulado","dateTransaction":"20261002","timeTransaction":"150627","uniqueId":"000000000000313455","referenceNumber":"2000000"}]}}"#;

    const SEARCH_NOT_FOUND: &str = r#"{"code":"MC","message":"Transacción Invalido","messageUser":"Transacción No Existe.","messageUserEng":"Transaction Does Not Exist.","response":{"order":[{"codeAuth":"","currency":"","amount":"0.00","installment":"","deferred":"","orderNumber":"PX1790971729304","stateMessage":"Denegado","dateTransaction":"00010101","timeTransaction":"000000","uniqueId":"","referenceNumber":""}],"card":{"brand":"","pan":"","save":"false"},"merchant":{"merchantCode":"4004353","facilitatorCode":""},"customFields":[],"miles":{"netMiles":"","miles":""}}}"#;

    const TOKEN_GENERATE_OK: &str = r#"{"code":"00","message":"OK","response":{"token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJtZXJjaGFudENvZGUiOiI0MDA0MzUzIiwiZmFjaWxpdGF0b3JDb2RlIjoiMCIsInRyYW5zYWN0aW9uSWQiOiIxNzkwOTcxMDU1NjgzMTY4OCIsIk9yZGVyTnVtYmVyIjoiUFgxNzkwOTcxMDU1NjgzIiwiQW1vdW50IjoiMS45OSIsIlRva2VuSWQiOiJmYzNhNWZjNy0wOGYyLTQwZGItYjI0YS1jNDE3ODhjY2Y5MmYiLCJuYmYiOjE3OTA5NzEwNTUsImV4cCI6MTc5MDk3MTk1NSwiaWF0IjoxNzkwOTcxMDU1fQ.qAedKjW_TGS6BpZ6ygOZQsiRnF_ZdzZRBmPDouZU49U","userOrg":"1snn5n9w","userScoring":"izipay_low"}}"#;

    const TOKEN_TRANSACTION_ID: &str = "17909710556831688";

    const RETURN_URL: &str = "https://hyperswitch.example/payments/pay_1/merchant_1/return";

    fn test_auth() -> ConnectorAuthType {
        ConnectorAuthType::MultiAuthKey {
            api_key: Secret::new("sample_api_key".to_string()),
            key1: Secret::new("4004353".to_string()),
            api_secret: Secret::new("sample_hash_key".to_string()),
            key2: Secret::new("sample_rsa_key".to_string()),
        }
    }

    fn billing_address(
        first_name: &str,
        zip: Option<&str>,
        line1: &str,
        city: &str,
    ) -> PaymentAddress {
        let address = Address {
            address: Some(AddressDetails {
                city: Some(city.to_string()),
                country: Some(common_enums::CountryAlpha2::PE),
                line1: Some(Secret::new(line1.to_string())),
                line2: None,
                line3: None,
                zip: zip.map(|zip| Secret::new(zip.to_string())),
                state: Some(Secret::new("Lima".to_string())),
                first_name: Some(Secret::new(first_name.to_string())),
                last_name: Some(Secret::new("Torres".to_string())),
                origin_zip: None,
            }),
            phone: Some(PhoneDetails {
                number: Some(Secret::new("+51 989-897-960".to_string())),
                country_code: Some("+51".to_string()),
            }),
            email: Some(common_utils::pii::Email::from_str("buyer@example.com").unwrap()),
        };
        PaymentAddress::new(None, Some(address), None, None)
    }

    fn authorize_request_data() -> PaymentsAuthorizeData {
        PaymentsAuthorizeData {
            payment_method_data: PaymentMethodData::Wallet(WalletData::IzipayCheckout {}),
            amount: 199,
            minor_amount: MinorUnit::new(199),
            order_tax_amount: None,
            email: None,
            customer_name: None,
            currency: enums::Currency::PEN,
            confirm: true,
            capture_method: Some(enums::CaptureMethod::Automatic),
            router_return_url: Some(RETURN_URL.to_string()),
            webhook_url: Some("https://hyperswitch.example/webhooks/merchant_1/mca_1".to_string()),
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
            metadata: Some(serde_json::json!({
                "buyer_document_type": "DNI",
                "buyer_document_number": "12345678",
            })),
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
            ucs_authentication_data: None,
            force_3ds_challenge: None,
            guest_customer: None,
            is_stored_credential: None,
            mit_category: None,
            billing_descriptor: None,
            tokenization: None,
            partner_merchant_identifier_details: None,
            feature_metadata: None,
            installment_details: None,
            connector_intent_metadata: None,
            is_account_funded_transaction: None,
            recipient_details: None,
            business_country: None,
        }
    }

    fn base_router_data<F, Req, Res>(
        request: Req,
        address: PaymentAddress,
        reference: &str,
    ) -> RouterData<F, Req, Res> {
        RouterData {
            flow: std::marker::PhantomData,
            merchant_id: common_utils::id_type::MerchantId::try_from(std::borrow::Cow::from(
                "izipay",
            ))
            .unwrap(),
            customer_id: None,
            connector_customer: None,
            connector: "izipay".to_string(),
            payment_id: "pay_test_izipay_1".to_string(),
            attempt_id: "pay_test_izipay_1_1".to_string(),
            tenant_id: common_utils::id_type::TenantId::try_from_string("public".to_string())
                .unwrap(),
            status: enums::AttemptStatus::AuthenticationPending,
            payment_method: enums::PaymentMethod::Wallet,
            connector_auth_type: test_auth(),
            description: None,
            address,
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
            payment_method_type: None,
            payout_id: None,
            authorized_amount: None,
            accept_amount_mismatch: None,
            customer_document_details: None,
            customer_date_of_birth: None,
            feature_data: None,
            sender_payment_instrument_id: None,
            connector_returned_payment_method_details: None,
        }
    }

    fn authorize_router_data() -> PaymentsAuthorizeRouterData {
        base_router_data::<Authorize, _, PaymentsResponseData>(
            authorize_request_data(),
            billing_address("Lucho", Some("15074"), "Av. Jorge Chavez 275", "Lima"),
            "PX1790971180429",
        )
    }

    fn sync_router_data(connector_meta: Option<serde_json::Value>) -> PaymentsSyncRouterData {
        base_router_data::<PSync, _, PaymentsResponseData>(
            PaymentsSyncData {
                connector_transaction_id: ResponseId::ConnectorTransactionId(
                    "PX1790971180429".to_string(),
                ),
                encoded_data: None,
                capture_method: None,
                connector_meta,
                sync_type: hyperswitch_domain_models::router_request_types::SyncRequestType::SinglePaymentSync,
                mandate_id: None,
                payment_method_type: None,
                currency: enums::Currency::PEN,
                payment_experience: None,
                split_payments: None,
                amount: MinorUnit::new(199),
                integrity_object: None,
                connector_reference_id: None,
                setup_future_usage: None,
                feature_metadata: None,
                connector_mandate_id: None,
                enable_partial_authorization: None,
                is_overcapture_enabled: None,
            },
            PaymentAddress::default(),
            "PX1790971180429",
        )
    }

    fn refund_request_data(connector_metadata: Option<serde_json::Value>) -> RefundsData {
        RefundsData {
            refund_id: "ref_1".to_string(),
            connector_transaction_id: "PX1790971180429".to_string(),
            connector_refund_id: None,
            currency: enums::Currency::PEN,
            payment_amount: 199,
            reason: None,
            webhook_url: None,
            refund_amount: 100,
            connector_metadata,
            refund_connector_metadata: None,
            browser_info: None,
            split_refunds: None,
            minor_payment_amount: MinorUnit::new(199),
            minor_refund_amount: MinorUnit::new(100),
            integrity_object: None,
            refund_status: enums::RefundStatus::Pending,
            merchant_account_id: None,
            merchant_config_currency: None,
            payment_connector_request_reference_id: None,
            capture_method: None,
            additional_payment_method_data: None,
        }
    }

    fn refund_router_data<F>(
        request: RefundsData,
        ruc: Option<&str>,
    ) -> RouterData<F, RefundsData, RefundsResponseData> {
        let mut router_data = base_router_data::<F, _, RefundsResponseData>(
            request,
            PaymentAddress::default(),
            "ref_1",
        );
        router_data.refund_id = Some("ref_1".to_string());
        router_data.connector_meta_data =
            ruc.map(|ruc| Secret::new(serde_json::json!({ "ruc": ruc })));
        router_data
    }

    fn amount(value: &str) -> StringMajorUnit {
        // Built through the same path as the connector: the converter output is only ever
        // serialized, so deserializing a string yields an identical value.
        serde_json::from_value(serde_json::json!(value)).unwrap()
    }

    // ------------------------------------------------------------------
    // Identifiers and environment
    // ------------------------------------------------------------------

    #[test]
    fn order_number_is_15_uppercase_alphanumerics_and_deterministic() {
        let first = order_number_from_attempt_id("pay_abc123_1");
        let second = order_number_from_attempt_id("pay_abc123_1");
        let other = order_number_from_attempt_id("pay_abc123_2");
        assert_eq!(first.len(), 15);
        assert!(first
            .chars()
            .all(|c| c.is_ascii_digit() || c.is_ascii_uppercase()));
        assert_eq!(first, second);
        assert_ne!(first, other);
    }

    #[test]
    fn transaction_id_is_the_unix_millis_plus_a_four_digit_random_suffix() {
        let before = common_utils::date_time::now_unix_timestamp_millis();
        let id = new_transaction_id();
        let after = common_utils::date_time::now_unix_timestamp_millis();
        assert!(id.chars().all(|c| c.is_ascii_digit()));
        // Izipay accepts 5 to 40 characters; the suffix keeps two ids of the same millisecond
        // apart with probability 9999/10000, which is not asserted (it would be flaky).
        assert!((5..=40).contains(&id.len()));
        let (millis, suffix) = id.split_at(id.len() - 4);
        let millis: i128 = millis.parse().unwrap();
        assert!((before..=after).contains(&millis));
        assert_eq!(suffix.len(), 4);
    }

    #[test]
    fn environment_follows_test_mode_and_defaults_to_production() {
        assert_eq!(
            IzipayEnvironment::from_test_mode(Some(true)),
            IzipayEnvironment::Sandbox
        );
        assert_eq!(
            IzipayEnvironment::from_test_mode(Some(false)),
            IzipayEnvironment::Production
        );
        assert_eq!(
            IzipayEnvironment::from_test_mode(None),
            IzipayEnvironment::Production
        );
        assert_eq!(
            IzipayEnvironment::Sandbox.sdk_url(),
            "https://sandbox-checkout.izipay.pe/payments/v1/js/index.js"
        );
        assert_eq!(
            IzipayEnvironment::Production.sdk_url(),
            "https://checkout.izipay.pe/payments/v1/js/index.js"
        );
    }

    #[test]
    fn auth_requires_multi_auth_key() {
        let auth = IzipayAuthType::try_from(&test_auth()).unwrap();
        assert_eq!(auth.merchant_code, "4004353");
        assert!(IzipayAuthType::try_from(&ConnectorAuthType::HeaderKey {
            api_key: Secret::new("x".to_string())
        })
        .is_err());
    }

    // ------------------------------------------------------------------
    // Billing validation
    // ------------------------------------------------------------------

    fn billing_error(
        router_data: &PaymentsAuthorizeRouterData,
    ) -> error_stack::Report<errors::ConnectorError> {
        build_billing(router_data).expect_err("billing must be rejected")
    }

    #[test]
    fn billing_is_normalized() {
        let billing = build_billing(&authorize_router_data()).unwrap();
        assert_eq!(billing.first_name, "Lucho");
        assert_eq!(billing.email, "buyer@example.com");
        assert_eq!(billing.phone_number, "51989897960");
        assert_eq!(billing.street, "Av. Jorge Chavez 275");
        assert_eq!(billing.country, "PE");
        assert_eq!(billing.postal_code, "15074");
    }

    #[test]
    fn billing_requires_each_field() {
        let mut router_data = authorize_router_data();
        router_data.address = PaymentAddress::default();
        assert!(matches!(
            billing_error(&router_data).current_context(),
            errors::ConnectorError::MissingRequiredField { field_name } if field_name == "billing.address.first_name"
        ));

        let mut router_data = authorize_router_data();
        router_data.address = billing_address("Lucho", None, "Av. Jorge Chavez 275", "Lima");
        assert!(matches!(
            billing_error(&router_data).current_context(),
            errors::ConnectorError::MissingRequiredField { field_name } if field_name == "billing.address.zip"
        ));

        // Neither a billing email nor a request email.
        let mut router_data = authorize_router_data();
        router_data.address = PaymentAddress::new(
            None,
            Some(Address {
                address: Some(AddressDetails {
                    city: None,
                    country: None,
                    line1: None,
                    line2: None,
                    line3: None,
                    zip: None,
                    state: None,
                    first_name: Some(Secret::new("Lucho".to_string())),
                    last_name: Some(Secret::new("Torres".to_string())),
                    origin_zip: None,
                }),
                phone: None,
                email: None,
            }),
            None,
            None,
        );
        assert!(matches!(
            billing_error(&router_data).current_context(),
            errors::ConnectorError::MissingRequiredField { field_name } if field_name == "billing.email"
        ));
    }

    #[test]
    fn billing_rejects_short_postal_code() {
        let mut router_data = authorize_router_data();
        router_data.address =
            billing_address("Lucho", Some("1425"), "Av. Jorge Chavez 275", "Lima");
        assert!(matches!(
            billing_error(&router_data).current_context(),
            errors::ConnectorError::InvalidDataFormat { field_name } if field_name == "billing.address.zip"
        ));
    }

    #[test]
    fn billing_truncates_street_and_city_on_char_boundaries() {
        let mut router_data = authorize_router_data();
        let long_street = "Ñandú ".repeat(10);
        let long_city = "Ñuñoa de la Santísima Trinidad del Norte";
        router_data.address = billing_address("Lucho", Some("15074"), &long_street, long_city);
        let billing = build_billing(&router_data).unwrap();
        assert!(billing.street.chars().count() <= 40);
        assert!(billing.street.starts_with("Ñandú Ñandú"));
        assert_eq!(billing.city.chars().count(), 25);
        assert!(billing.city.starts_with("Ñuñoa de la Santísima"));
    }

    #[test]
    fn billing_counts_characters_not_bytes() {
        // 5 characters but 10 bytes: valid. A byte count would also accept it, the opposite
        // case below (4 characters, 8 bytes) is what a byte count would wrongly accept.
        let mut router_data = authorize_router_data();
        router_data.address = billing_address("Lucho", Some("15074"), "ÑÑÑÑÑ", "Lima");
        assert_eq!(build_billing(&router_data).unwrap().street, "ÑÑÑÑÑ");

        router_data.address = billing_address("Lucho", Some("15074"), "ÑÑÑÑ", "Lima");
        assert!(matches!(
            billing_error(&router_data).current_context(),
            errors::ConnectorError::InvalidDataFormat { field_name } if field_name == "billing.address.line1"
        ));

        router_data.address = billing_address("Ñ", Some("15074"), "Av. Jorge Chavez 275", "Lima");
        assert!(matches!(
            billing_error(&router_data).current_context(),
            errors::ConnectorError::InvalidDataFormat { field_name } if field_name == "billing.address.first_name"
        ));

        router_data.address = billing_address("Ñé", Some("15074"), "Av. Jorge Chavez 275", "Lima");
        assert!(build_billing(&router_data).is_ok());
    }

    fn with_document(document_type: &str, document: &str) -> PaymentsAuthorizeRouterData {
        let mut router_data = authorize_router_data();
        router_data.request.metadata = Some(serde_json::json!({
            "buyer_document_type": document_type,
            "buyer_document_number": document,
        }));
        router_data
    }

    #[test]
    fn billing_requires_the_buyer_document_from_metadata() {
        let billing = build_billing(&authorize_router_data()).unwrap();
        assert_eq!(billing.document_type, "DNI");
        assert_eq!(billing.document, "12345678");

        let mut router_data = authorize_router_data();
        router_data.request.metadata = None;
        assert!(matches!(
            billing_error(&router_data).current_context(),
            errors::ConnectorError::MissingRequiredField { field_name } if field_name == "metadata.buyer_document_type"
        ));

        router_data.request.metadata = Some(serde_json::json!({ "buyer_document_type": "DNI" }));
        assert!(matches!(
            billing_error(&router_data).current_context(),
            errors::ConnectorError::MissingRequiredField { field_name } if field_name == "metadata.buyer_document_number"
        ));
    }

    #[test]
    fn billing_checks_the_document_length_per_type() {
        // Lowercase input is normalized.
        let billing = build_billing(&with_document("pasaporte", "ab1234567")).unwrap();
        assert_eq!(billing.document_type, "PASAPORTE");
        assert_eq!(billing.document, "AB1234567");
        assert!(build_billing(&with_document("RUC", "20123456789")).is_ok());
        assert!(build_billing(&with_document("CE", "001234567")).is_ok());
        assert!(build_billing(&with_document("OTROS", "X1234567")).is_ok());

        for (document_type, document) in [
            ("DNI", "1234567"),
            ("DNI", "1234567A"),
            ("RUC", "2012345678"),
            ("CE", "12345678"),
            ("PASAPORTE", "AB-123456"),
            ("OTROS", "1234567890123"),
        ] {
            assert!(
                matches!(
                    billing_error(&with_document(document_type, document)).current_context(),
                    errors::ConnectorError::InvalidDataFormat { field_name } if field_name == "metadata.buyer_document_number"
                ),
                "{document_type} {document} must be rejected"
            );
        }

        assert!(matches!(
            billing_error(&with_document("LIBRETA", "12345678")).current_context(),
            errors::ConnectorError::InvalidDataFormat { field_name } if field_name == "metadata.buyer_document_type"
        ));
    }

    // ------------------------------------------------------------------
    // Token/Generate and the redirect page
    // ------------------------------------------------------------------

    #[test]
    fn token_generate_request_matches_the_documented_shape() {
        let router_data = authorize_router_data();
        let item = IzipayRouterData::from((amount("1.99"), &router_data));
        let request = IzipayTokenRequest::try_from(&item).unwrap();
        assert_eq!(
            serde_json::to_value(&request).unwrap(),
            serde_json::json!({
                "requestSource": "ECOMMERCE",
                "merchantCode": "4004353",
                "orderNumber": "PX1790971180429",
                "publicKey": "sample_api_key",
                "amount": "1.99"
            })
        );
    }

    #[test]
    fn authorize_rejects_unsupported_requests() {
        let mut router_data = authorize_router_data();
        router_data.request.currency = enums::Currency::EUR;
        assert!(matches!(
            validate_authorize_request(&router_data)
                .unwrap_err()
                .current_context(),
            errors::ConnectorError::CurrencyNotSupported { .. }
        ));

        let mut router_data = authorize_router_data();
        router_data.request.capture_method = Some(enums::CaptureMethod::Manual);
        assert!(matches!(
            validate_authorize_request(&router_data)
                .unwrap_err()
                .current_context(),
            errors::ConnectorError::NotSupported { .. }
        ));

        let mut router_data = authorize_router_data();
        router_data.request.router_return_url = None;
        assert!(matches!(
            validate_authorize_request(&router_data)
                .unwrap_err()
                .current_context(),
            errors::ConnectorError::MissingRequiredField { field_name } if field_name == "router_return_url"
        ));

        let mut router_data = authorize_router_data();
        router_data.request.payment_method_data =
            PaymentMethodData::Wallet(WalletData::WompiCheckout {});
        assert!(matches!(
            validate_authorize_request(&router_data)
                .unwrap_err()
                .current_context(),
            errors::ConnectorError::NotImplemented(_)
        ));

        // three_ds is not rejected: Izipay's hosted page runs it.
        let mut router_data = authorize_router_data();
        router_data.auth_type = enums::AuthenticationType::ThreeDs;
        assert!(validate_authorize_request(&router_data).is_ok());
    }

    #[test]
    fn merchant_buyer_id_falls_back_to_the_payment_id() {
        let router_data = authorize_router_data();
        let checkout = validate_authorize_request(&router_data).unwrap();
        assert_eq!(checkout.merchant_buyer_id, "pay_test_izipay_1");

        let mut router_data = authorize_router_data();
        router_data.request.customer_id = Some(
            common_utils::id_type::CustomerId::try_from(std::borrow::Cow::from("cus_123456"))
                .unwrap(),
        );
        let checkout = validate_authorize_request(&router_data).unwrap();
        assert_eq!(checkout.merchant_buyer_id, "cus_123456");

        router_data.request.customer_id = Some(
            common_utils::id_type::CustomerId::try_from(std::borrow::Cow::from("c_1")).unwrap(),
        );
        let checkout = validate_authorize_request(&router_data).unwrap();
        assert_eq!(checkout.merchant_buyer_id, "pay_test_izipay_1");
    }

    fn token_response() -> IzipayTokenResponse {
        serde_json::from_str(TOKEN_GENERATE_OK).unwrap()
    }

    #[test]
    fn authorize_response_builds_the_redirect_page() {
        let response = token_response();
        let result = authorize_response(response, authorize_router_data(), 200, &amount("1.99"))
            .expect("authorize must succeed");
        assert_eq!(result.status, enums::AttemptStatus::AuthenticationPending);
        match result.response.expect("must be Ok") {
            PaymentsResponseData::TransactionResponse {
                resource_id,
                redirection_data,
                connector_metadata,
                connector_response_reference_id,
                ..
            } => {
                assert!(matches!(
                    resource_id,
                    ResponseId::ConnectorTransactionId(ref id) if id == "PX1790971180429"
                ));
                assert_eq!(
                    connector_response_reference_id.as_deref(),
                    Some("PX1790971180429")
                );
                assert_eq!(
                    connector_metadata,
                    Some(serde_json::json!({
                        "transaction_id": TOKEN_TRANSACTION_ID,
                        "order_number": "PX1790971180429",
                    }))
                );
                match *redirection_data {
                    Some(RedirectForm::Html { html_data }) => {
                        assert!(!html_data.contains("<script src="));
                        assert!(html_data.contains(
                            r#""sdkUrl":"https://sandbox-checkout.izipay.pe/payments/v1/js/index.js""#
                        ));
                        assert!(html_data.contains("document.createElement('script')"));
                        assert!(html_data.contains("var retryDelaysMs = [1000, 2000, 4000];"));
                        assert!(html_data.contains("sdk_load_failed"));
                        assert!(html_data.contains("sdk_init_failed"));
                        assert!(html_data.contains("izipay_error_detail="));
                        assert!(html_data.contains("Te estamos llevando a la página de pago"));
                        assert!(html_data.contains("Taking you to the payment page"));
                        assert!(html_data.contains("No pudimos abrir la página de pago"));
                        assert!(html_data.contains("We couldn’t open the payment page"));
                        assert!(html_data.contains("new Izipay({ config: izipayData.config })"));
                        assert!(html_data.contains("LoadForm"));
                        assert!(html_data.contains(r#""typeForm":"redirect""#));
                        assert!(html_data.contains(r#""processType":"AT""#));
                        assert!(html_data
                            .contains(&format!(r#""transactionId":"{TOKEN_TRANSACTION_ID}""#)));
                        assert!(html_data.contains(r#""amount":"1.99""#));
                        assert!(html_data.contains(r#""currency":"PEN""#));
                        assert!(html_data.contains(r#""documentType":"DNI""#));
                        assert!(html_data.contains(r#""document":"12345678""#));
                        assert!(html_data.contains(r#""keyRSA":"sample_rsa_key""#));
                        assert!(html_data.contains(
                            r#""urlIPN":"https://hyperswitch.example/webhooks/merchant_1/mca_1""#
                        ));
                        assert!(html_data.contains(&format!(
                            r#""onSuccess":"{RETURN_URL}?izipay_result=success""#
                        )));
                        assert!(html_data.contains("izipay_result=error"));
                        assert!(html_data.contains("izipay_result=cancel"));
                        assert!(html_data.contains("izipay_result=sdk_error"));
                    }
                    other => panic!("expected an html redirect form, got {other:?}"),
                }
            }
            other => panic!("expected a TransactionResponse, got {other:?}"),
        }
    }

    #[test]
    fn production_page_uses_the_production_sdk_and_omits_a_missing_ipn_url() {
        let mut router_data = authorize_router_data();
        router_data.test_mode = Some(false);
        router_data.request.webhook_url = None;
        router_data.request.router_return_url = Some(format!("{RETURN_URL}?a=b"));
        let result =
            authorize_response(token_response(), router_data, 200, &amount("1.99")).unwrap();
        match result.response.unwrap() {
            PaymentsResponseData::TransactionResponse {
                redirection_data, ..
            } => match *redirection_data {
                Some(RedirectForm::Html { html_data }) => {
                    assert!(html_data.contains(
                        r#""sdkUrl":"https://checkout.izipay.pe/payments/v1/js/index.js""#
                    ));
                    assert!(!html_data.contains("sandbox-checkout"));
                    assert!(!html_data.contains("urlIPN"));
                    assert!(html_data.contains(&format!(
                        r#""onCancel":"{RETURN_URL}?a=b\u0026izipay_result=cancel""#
                    )));
                }
                other => panic!("expected an html redirect form, got {other:?}"),
            },
            other => panic!("expected a TransactionResponse, got {other:?}"),
        }
    }

    #[test]
    fn guest_texts_have_no_technical_wording() {
        let page = authorize_page();
        let guest_texts: Vec<&str> = page
            .lines()
            .filter(|line| {
                let line = line.trim_start();
                line.starts_with("loading:") || line.starts_with("failed:")
            })
            .collect();
        assert_eq!(guest_texts.len(), 4, "two languages, two texts each");
        for text in guest_texts {
            let lowered = text.to_lowercase();
            for word in [
                "sdk",
                "izipay",
                "error",
                "script",
                "exception",
                "javascript",
            ] {
                assert!(!lowered.contains(word), "{word} in guest text: {text}");
            }
        }
    }

    fn authorize_page() -> String {
        let result = authorize_response(
            token_response(),
            authorize_router_data(),
            200,
            &amount("1.99"),
        )
        .unwrap();
        match result.response.unwrap() {
            PaymentsResponseData::TransactionResponse {
                redirection_data, ..
            } => match *redirection_data {
                Some(RedirectForm::Html { html_data }) => html_data,
                other => panic!("expected an html redirect form, got {other:?}"),
            },
            other => panic!("expected a TransactionResponse, got {other:?}"),
        }
    }

    #[test]
    fn page_data_never_leaks_into_the_error_url_logic() {
        // The error url only gets the machine code and the sanitized detail; the script strips
        // the session token and the RSA key from the detail before sending it.
        let page = authorize_page();
        assert!(page.contains("[izipayData.authorization, izipayData.keyRSA]"));
        assert!(page.contains(".slice(0, maxDetailLength)"));
        assert!(page.contains("encodeURIComponent(describe(error))"));
    }

    #[test]
    fn sdk_error_is_read_from_the_return_query() {
        let parsed = IzipaySdkError::from_return_query(Some(
            "izipay_result=sdk_error&izipay_error=sdk_load_failed&izipay_error_detail=script%20load%20timeout",
        ))
        .expect("sdk_error must be detected");
        assert_eq!(parsed.reason, "sdk_load_failed");
        assert_eq!(parsed.detail.as_deref(), Some("script load timeout"));

        // The merchant's own query parameters may come first.
        let with_prefix = IzipaySdkError::from_return_query(Some(
            "a=b&izipay_result=sdk_error&izipay_error=sdk_init_failed",
        ))
        .unwrap();
        assert_eq!(with_prefix.reason, "sdk_init_failed");
        assert_eq!(with_prefix.detail, None);

        let without_code =
            IzipaySdkError::from_return_query(Some("izipay_result=sdk_error")).unwrap();
        assert_eq!(without_code.reason, "unknown");

        for query in [
            None,
            Some(""),
            Some("izipay_result=success"),
            Some("izipay_result=cancel&izipay_error=sdk_load_failed"),
            Some("izipay_error=sdk_load_failed"),
        ] {
            assert_eq!(IzipaySdkError::from_return_query(query), None, "{query:?}");
        }
    }

    #[test]
    fn sdk_error_values_from_the_browser_are_sanitized() {
        let long_detail = "x".repeat(500);
        let query = format!(
            "izipay_result=sdk_error&izipay_error=Bad%20Code%3Cscript%3E&izipay_error_detail={long_detail}"
        );
        let parsed = IzipaySdkError::from_return_query(Some(&query)).unwrap();
        assert_eq!(parsed.reason, "unknown");
        assert_eq!(char_len(parsed.detail.as_deref().unwrap()), 200);

        let noisy = IzipaySdkError::from_return_query(Some(
            "izipay_result=sdk_error&izipay_error=sdk_load_failed&izipay_error_detail=%0A%0DTypeError%3A%09%20x%20%20is%20not%20defined%00",
        ))
        .unwrap();
        assert_eq!(noisy.detail.as_deref(), Some("TypeError: x is not defined"));

        let too_long_reason = format!("izipay_result=sdk_error&izipay_error={}", "a".repeat(41));
        assert_eq!(
            IzipaySdkError::from_return_query(Some(&too_long_reason))
                .unwrap()
                .reason,
            "unknown"
        );

        let blank = IzipaySdkError::from_return_query(Some(
            "izipay_result=sdk_error&izipay_error_detail=%20%0A",
        ))
        .unwrap();
        assert_eq!(blank.detail, None);
    }

    #[test]
    fn page_escapes_buyer_data_for_a_script_context() {
        let mut router_data = authorize_router_data();
        router_data.address = billing_address(
            "</script><script>alert(1)</script>",
            Some("15074"),
            "Av. Jorge Chavez 275 \u{2028}\u{2029} & co",
            "Lima",
        );
        let result =
            authorize_response(token_response(), router_data, 200, &amount("1.99")).unwrap();
        let PaymentsResponseData::TransactionResponse {
            redirection_data, ..
        } = result.response.unwrap()
        else {
            panic!("expected a TransactionResponse");
        };
        let Some(RedirectForm::Html { html_data }) = *redirection_data else {
            panic!("expected an html redirect form");
        };
        // The name is 34 characters long, so it is valid and has to appear escaped.
        assert!(!html_data.contains("alert(1)</script>"));
        assert!(
            html_data.contains(r"\u003c/script\u003e\u003cscript\u003ealert(1)\u003c/script\u003e")
        );
        assert!(!html_data.contains('\u{2028}'));
        assert!(!html_data.contains('\u{2029}'));
        assert!(html_data.contains(r"\u2028\u2029 \u0026 co"));
        // The only closing script tag is the one of the page itself.
        assert_eq!(html_data.matches("</script>").count(), 1);
    }

    #[test]
    fn authorize_error_responses_carry_the_izipay_code() {
        let response: IzipayTokenResponse =
            serde_json::from_str(r#"{"code":"500","message":"Error interno","response":{}}"#)
                .unwrap();
        let result =
            authorize_response(response, authorize_router_data(), 200, &amount("1.99")).unwrap();
        assert_eq!(result.status, enums::AttemptStatus::Failure);
        let error = result.response.unwrap_err();
        assert_eq!(error.code, "500");
        assert_eq!(error.message, "Error interno");
    }

    // ------------------------------------------------------------------
    // Session tokens
    // ------------------------------------------------------------------

    #[test]
    fn transaction_id_is_read_from_the_session_token() {
        let token = token_response().session_token().unwrap();
        assert_eq!(
            transaction_id_from_session_token(token.peek()).as_deref(),
            Some(TOKEN_TRANSACTION_ID)
        );
        assert_eq!(transaction_id_from_session_token("not-a-jwt"), None);
    }

    #[test]
    fn generic_token_request_depends_on_the_operation() {
        let router_data = base_router_data::<
            hyperswitch_domain_models::router_flow_types::access_token_auth::AccessTokenAuth,
            hyperswitch_domain_models::router_request_types::AccessTokenRequestData,
            AccessToken,
        >(
            hyperswitch_domain_models::router_request_types::AccessTokenRequestData {
                app_id: Secret::new("x".to_string()),
                id: None,
                authentication_token: None,
                current_flow: None,
            },
            PaymentAddress::default(),
            "PX1790971180429",
        );
        let request = IzipayTokenRequest::try_from(&router_data).unwrap();
        assert_eq!(
            serde_json::to_value(&request).unwrap(),
            serde_json::json!({
                "requestSource": "ECOMMERCE",
                "merchantCode": "4004353",
                "orderNumber": "4004353",
                "publicKey": "sample_api_key",
                "amount": "0.00"
            })
        );
        let mut refund_data = router_data;
        refund_data.refund_id = Some("ref_1".to_string());
        let request = IzipayTokenRequest::try_from(&refund_data).unwrap();
        assert_eq!(
            serde_json::to_value(&request).unwrap()["requestSource"],
            "REFUND"
        );
    }

    #[test]
    fn access_token_response_packs_and_unpacks() {
        let router_data = base_router_data::<
            hyperswitch_domain_models::router_flow_types::access_token_auth::AccessTokenAuth,
            hyperswitch_domain_models::router_request_types::AccessTokenRequestData,
            AccessToken,
        >(
            hyperswitch_domain_models::router_request_types::AccessTokenRequestData {
                app_id: Secret::new("x".to_string()),
                id: None,
                authentication_token: None,
                current_flow: None,
            },
            PaymentAddress::default(),
            "PX1790971180429",
        );
        let converted = RouterData::try_from(ResponseRouterData {
            response: token_response(),
            data: router_data,
            http_code: 200,
        })
        .unwrap();
        let access_token = converted.response.unwrap();
        assert_eq!(access_token.expires, 900);

        let packed = unpack_access_token(Some(&access_token), IzipayTokenKind::Ecommerce).unwrap();
        assert_eq!(packed.transaction_id, TOKEN_TRANSACTION_ID);
        assert!(packed.token.peek().starts_with("eyJ"));

        // The token was generated for an ecommerce operation: a refund must not use it.
        let mismatch = unpack_access_token(Some(&access_token), IzipayTokenKind::Refund)
            .expect_err("kind mismatch must fail");
        assert!(matches!(
            mismatch.current_context(),
            errors::ConnectorError::FailedToObtainAuthType
        ));
        assert!(matches!(
            unpack_access_token(None, IzipayTokenKind::Ecommerce)
                .unwrap_err()
                .current_context(),
            errors::ConnectorError::MissingRequiredField { .. }
        ));
    }

    // ------------------------------------------------------------------
    // PSync
    // ------------------------------------------------------------------

    fn sync(
        body: &str,
        connector_meta: Option<serde_json::Value>,
        http_code: u16,
    ) -> PaymentsSyncRouterData {
        let response: IzipaySearchResponse = serde_json::from_str(body).unwrap();
        PaymentsSyncRouterData::try_from(ResponseRouterData {
            response,
            data: sync_router_data(connector_meta),
            http_code,
        })
        .unwrap()
    }

    #[test]
    fn approved_search_is_charged_with_refund_metadata() {
        let authorize_metadata = serde_json::json!({
            "transaction_id": TOKEN_TRANSACTION_ID,
            "order_number": "PX1790971180429",
        });
        let result = sync(SEARCH_APPROVED, Some(authorize_metadata), 200);
        assert_eq!(result.status, enums::AttemptStatus::Charged);
        match result.response.unwrap() {
            PaymentsResponseData::TransactionResponse {
                resource_id,
                connector_metadata,
                ..
            } => {
                assert!(matches!(
                    resource_id,
                    ResponseId::ConnectorTransactionId(ref id) if id == "PX1790971180429"
                ));
                assert_eq!(
                    connector_metadata,
                    Some(serde_json::json!({
                        "transaction_id": TOKEN_TRANSACTION_ID,
                        "order_number": "PX1790971180429",
                        "unique_id": "450249587",
                        "authorization_code": "S97758",
                        "reference_number": "2000000",
                        "transaction_date": "20261002",
                        "transaction_time": "150001",
                        "pay_method": "CARD",
                        "currency": "PEN",
                        "amount": "1.99",
                    }))
                );
            }
            other => panic!("expected a TransactionResponse, got {other:?}"),
        }
    }

    #[test]
    fn declined_search_fails_with_the_izipay_code_and_message() {
        let result = sync(SEARCH_DECLINED, None, 200);
        assert_eq!(result.status, enums::AttemptStatus::Failure);
        let error = result.response.unwrap_err();
        assert_eq!(error.code, "51");
        assert_eq!(error.message, "Fondos Insuficientes");
        assert_eq!(error.attempt_status, Some(enums::AttemptStatus::Failure));
        assert_eq!(
            error.connector_transaction_id.as_deref(),
            Some("PX1790971250459")
        );
    }

    #[test]
    fn voided_search_is_voided_and_keeps_the_original_metadata() {
        let result = sync(SEARCH_VOIDED, None, 200);
        assert_eq!(result.status, enums::AttemptStatus::Voided);
        match result.response.unwrap() {
            PaymentsResponseData::TransactionResponse {
                connector_metadata, ..
            } => assert_eq!(connector_metadata, None),
            other => panic!("expected a TransactionResponse, got {other:?}"),
        }
    }

    #[test]
    fn authorized_entry_wins_over_a_voided_one() {
        let body = SEARCH_APPROVED.replace(
            r#""order":[{"#,
            r#""order":[{"orderNumber":"PX1790971180429","stateMessage":"Anulado","uniqueId":"313455"},{"#,
        );
        let result = sync(&body, None, 200);
        assert_eq!(result.status, enums::AttemptStatus::Charged);
    }

    #[test]
    fn not_found_keeps_the_attempt_status() {
        let result = sync(SEARCH_NOT_FOUND, None, 200);
        assert_eq!(result.status, enums::AttemptStatus::AuthenticationPending);
        assert!(result.response.is_ok());
    }

    #[test]
    fn search_status_mapping() {
        let order = |state: &str| IzipayOrder {
            pay_method_authorization: None,
            code_auth: None,
            currency: None,
            amount: None,
            order_number: None,
            state_message: Some(state.to_string()),
            date_transaction: None,
            time_transaction: None,
            unique_id: None,
            reference_number: None,
        };
        assert_eq!(
            map_search_status("00", Some(&order("autorizado"))),
            enums::AttemptStatus::Charged
        );
        assert_eq!(
            map_search_status("00", Some(&order("Denegado"))),
            enums::AttemptStatus::Failure
        );
        assert_eq!(
            map_search_status("05", Some(&order("Autorizado"))),
            enums::AttemptStatus::Failure
        );
        assert_eq!(
            map_search_status("00", Some(&order("Pendiente"))),
            enums::AttemptStatus::Pending
        );
        assert_eq!(map_search_status("00", None), enums::AttemptStatus::Pending);
    }

    #[test]
    fn search_request_uses_the_order_number() {
        let request = IzipaySearchRequest::try_from(&sync_router_data(None)).unwrap();
        assert_eq!(
            serde_json::to_value(&request).unwrap(),
            serde_json::json!({
                "merchantCode": "4004353",
                "numberOrden": "PX1790971180429",
                "language": "ESP"
            })
        );
    }

    #[test]
    fn error_bodies_are_parsed_tolerantly() {
        let not_found = IzipayErrorResponse::parse(SEARCH_NOT_FOUND.as_bytes()).unwrap();
        assert_eq!(not_found.code, "MC");
        assert_eq!(not_found.message, "Transacción No Existe.");

        let refund_error = IzipayErrorResponse::parse(
            r#"{"header":{},"code":"PI5","message":"El valor del tipo de proceso es inválido","response":{"messageFriendly":"Valor inválido"}}"#
                .as_bytes(),
        )
        .unwrap();
        assert_eq!(refund_error.code, "PI5");
        assert_eq!(refund_error.message, "Valor inválido");

        let numeric = IzipayErrorResponse::parse(br#"{"code":400,"message":"Bad"}"#).unwrap();
        assert_eq!(numeric.code, "400");

        assert!(IzipayErrorResponse::parse(b"<html>bad gateway</html>").is_none());
        assert!(IzipayErrorResponse::parse(b"{}").is_none());
    }

    // ------------------------------------------------------------------
    // Refunds
    // ------------------------------------------------------------------

    fn charged_metadata() -> serde_json::Value {
        serde_json::json!({
            "order_number": "PX1790971180429",
            "unique_id": "450249587",
            "authorization_code": "S97758",
            "reference_number": "2000000",
        })
    }

    #[test]
    fn refund_request_matches_the_documented_shape() {
        let router_data = refund_router_data::<Execute>(
            refund_request_data(Some(charged_metadata())),
            Some("20493020618"),
        );
        let item = IzipayRouterData::from((amount("1.00"), &router_data));
        let request = IzipayRefundRequest::try_from(&item).unwrap();
        assert_eq!(
            serde_json::to_value(&request).unwrap(),
            serde_json::json!({
                "merchantCode": "4004353",
                "ruc": "20493020618",
                "idUnique": "450249587",
                "order": {
                    "authorizationCode": "S97758",
                    "referenceNumber": "2000000",
                    "currency": "PEN",
                    "refundAmount": "1.00",
                    "totalAmount": "",
                    "transactionDate": ""
                },
                "card": {"brand": "", "firstSixDigits": "", "lastFourDigits": ""},
                "language": "ESP"
            })
        );
    }

    #[test]
    fn refund_request_requires_the_ruc_and_the_payment_metadata() {
        let router_data =
            refund_router_data::<Execute>(refund_request_data(Some(charged_metadata())), None);
        let item = IzipayRouterData::from((amount("1.00"), &router_data));
        assert!(matches!(
            IzipayRefundRequest::try_from(&item)
                .unwrap_err()
                .current_context(),
            errors::ConnectorError::MissingRequiredField { field_name } if field_name == "connector_metadata.ruc"
        ));

        let router_data = refund_router_data::<Execute>(
            refund_request_data(Some(charged_metadata())),
            Some("1234"),
        );
        let item = IzipayRouterData::from((amount("1.00"), &router_data));
        assert!(matches!(
            IzipayRefundRequest::try_from(&item)
                .unwrap_err()
                .current_context(),
            errors::ConnectorError::InvalidDataFormat { .. }
        ));

        let router_data =
            refund_router_data::<Execute>(refund_request_data(None), Some("20493020618"));
        let item = IzipayRouterData::from((amount("1.00"), &router_data));
        assert!(matches!(
            IzipayRefundRequest::try_from(&item)
                .unwrap_err()
                .current_context(),
            errors::ConnectorError::MissingRequiredField { field_name } if field_name == "connector_metadata.unique_id"
        ));
    }

    #[test]
    fn refund_response_is_pending_with_the_refund_transaction_id() {
        let response: IzipayRefundResponse = serde_json::from_str(
            r#"{"header":{"millis":1201},"code":"00","message":"La devolución fue registrada","response":{"merchantCode":"4007701","ruc":"20432405525","result":{"messageFriendly":"aprobado","refundTransactionId":"762954"}}}"#,
        )
        .unwrap();
        let router_data = refund_router_data::<Execute>(refund_request_data(None), None);
        let converted = RefundsRouterData::try_from(RefundsResponseRouterData {
            response,
            data: router_data,
            http_code: 200,
        })
        .unwrap();
        let refund = converted.response.unwrap();
        assert_eq!(refund.connector_refund_id, "762954");
        assert_eq!(refund.refund_status, enums::RefundStatus::Pending);
    }

    #[test]
    fn refund_rejection_carries_the_izipay_error() {
        let response: IzipayRefundResponse = serde_json::from_str(
            r#"{"code":"PI5","message":"El valor del tipo de proceso es inválido","response":null}"#,
        )
        .unwrap();
        let router_data = refund_router_data::<Execute>(refund_request_data(None), None);
        let converted = RefundsRouterData::try_from(RefundsResponseRouterData {
            response,
            data: router_data,
            http_code: 200,
        })
        .unwrap();
        let error = converted.response.unwrap_err();
        assert_eq!(error.code, "PI5");
    }

    #[test]
    fn refund_status_is_mapped_by_name() {
        for name in ["AUTORIZADO", "procesado", "Aprobado", "ABONADO", "DEVUELTO"] {
            assert_eq!(map_refund_status(Some(name)), enums::RefundStatus::Success);
        }
        for name in ["RECHAZADO", "DENEGADO", "ANULADO", "error"] {
            assert_eq!(map_refund_status(Some(name)), enums::RefundStatus::Failure);
        }
        for name in ["PENDIENTE", "EN PROCESO", ""] {
            assert_eq!(map_refund_status(Some(name)), enums::RefundStatus::Pending);
        }
        assert_eq!(map_refund_status(None), enums::RefundStatus::Pending);
    }

    #[test]
    fn refund_sync_response_uses_the_status_name() {
        let convert = |body: &str| {
            let response: IzipayRefundStatusResponse = serde_json::from_str(body).unwrap();
            let mut router_data = refund_router_data::<RSync>(refund_request_data(None), None);
            router_data.request.connector_refund_id = Some("762954".to_string());
            RefundsRouterData::<RSync>::try_from(RefundsResponseRouterData {
                response,
                data: router_data,
                http_code: 200,
            })
            .unwrap()
        };
        let approved = convert(
            r#"{"code":"00","message":"Operación exitosa","response":{"statusCode":"50","statusName":"AUTORIZADO","responseCode":"00","rejectionReason":""}}"#,
        );
        assert_eq!(
            approved.response.unwrap().refund_status,
            enums::RefundStatus::Success
        );
        let rejected = convert(
            r#"{"code":"00","message":"Operación exitosa","response":{"statusCode":"40","statusName":"RECHAZADO","responseCode":"D01","rejectionReason":"Monto excede"}}"#,
        );
        let error = rejected.response.unwrap_err();
        assert_eq!(error.code, "D01");
        assert_eq!(error.message, "Monto excede");
        let pending = convert(
            r#"{"code":"00","message":"Operación exitosa","response":{"statusCode":"10","statusName":"PENDIENTE"}}"#,
        );
        assert_eq!(
            pending.response.unwrap().refund_status,
            enums::RefundStatus::Pending
        );
    }

    // ------------------------------------------------------------------
    // Webhooks
    // ------------------------------------------------------------------

    const HASH_KEY: &str = "test-hash-key";

    fn signed_notification(payload: &str, hash_key: &str) -> Vec<u8> {
        let signature = HmacSha256
            .sign_message(hash_key.as_bytes(), payload.as_bytes())
            .unwrap();
        serde_json::to_vec(&serde_json::json!({
            "code": "00",
            "message": "OK",
            "messageUser": "Operación exitosa",
            "messageUserEng": "Successful",
            "response": {"order": [{"orderNumber": "UNSIGNED-ORDER"}]},
            "payloadHttp": payload,
            "signature": base64::engine::general_purpose::STANDARD.encode(signature),
            "transactionId": "17909712094450964"
        }))
        .unwrap()
    }

    #[test]
    fn webhook_signature_is_verified_against_the_payload() {
        let hash_key = Secret::new(HASH_KEY.to_string());
        let body = signed_notification(SEARCH_APPROVED, HASH_KEY);
        assert!(verify_webhook_signature(&body, None, &hash_key).unwrap());
        assert!(
            !verify_webhook_signature(&body, None, &Secret::new("other-key".to_string())).unwrap()
        );

        // Editing the signed payload invalidates it.
        let mut tampered: serde_json::Value = serde_json::from_slice(&body).unwrap();
        tampered["payloadHttp"] = serde_json::json!(SEARCH_APPROVED.replace("S97758", "S00000"));
        let tampered = serde_json::to_vec(&tampered).unwrap();
        assert!(!verify_webhook_signature(&tampered, None, &hash_key).unwrap());

        // A body without a signature falls back to the header.
        let mut unsigned: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let signature = unsigned["signature"].as_str().unwrap().to_string();
        unsigned.as_object_mut().unwrap().remove("signature");
        let unsigned = serde_json::to_vec(&unsigned).unwrap();
        assert!(verify_webhook_signature(&unsigned, Some(&signature), &hash_key).unwrap());
        assert!(verify_webhook_signature(&unsigned, None, &hash_key).is_err());
    }

    #[test]
    fn webhook_reference_comes_from_the_signed_payload() {
        let body = signed_notification(SEARCH_APPROVED, HASH_KEY);
        let payload = parse_signed_payload(&body).unwrap();
        // The unsigned outer `response` says UNSIGNED-ORDER and must be ignored.
        assert_eq!(
            webhook_reference(&payload).as_deref(),
            Some("PX1790971180429")
        );
    }

    #[test]
    fn webhook_event_types() {
        let event = |payload: &str| {
            map_webhook_event(
                &parse_signed_payload(&signed_notification(payload, HASH_KEY)).unwrap(),
            )
        };
        assert_eq!(
            event(SEARCH_APPROVED),
            IncomingWebhookEvent::PaymentIntentSuccess
        );
        assert_eq!(
            event(SEARCH_DECLINED),
            IncomingWebhookEvent::PaymentIntentFailure
        );
        assert_eq!(
            event(SEARCH_VOIDED),
            IncomingWebhookEvent::EventNotSupported
        );

        assert!(parse_signed_payload(b"{}").is_err());
        assert!(parse_signed_payload(br#"{"payloadHttp":"not json"}"#).is_err());
    }

    #[test]
    fn webhook_payload_is_parsed_by_the_sync_response_type() {
        let body = signed_notification(SEARCH_APPROVED, HASH_KEY);
        let resource = signed_payload_value(&body).unwrap();
        let response: IzipaySearchResponse = serde_json::from_value(resource).unwrap();
        assert_eq!(response.code, "00");
        let result = PaymentsSyncRouterData::try_from(ResponseRouterData {
            response,
            data: sync_router_data(None),
            http_code: 200,
        })
        .unwrap();
        assert_eq!(result.status, enums::AttemptStatus::Charged);
    }

    #[test]
    fn a_checkout_sync_body_without_orders_is_read_as_an_order_search() {
        // A non-00 code fails the attempt, MC keeps the status.
        let declined: IzipaySearchResponse =
            serde_json::from_str(r#"{"code":"05","message":"Operación Denegada"}"#).unwrap();
        let result = PaymentsSyncRouterData::try_from(ResponseRouterData {
            response: declined,
            data: sync_router_data(None),
            http_code: 200,
        })
        .unwrap();
        assert_eq!(result.status, enums::AttemptStatus::Failure);
        assert_eq!(result.response.unwrap_err().code, "05");

        let not_found: IzipaySearchResponse =
            serde_json::from_str(r#"{"code":"MC","message":"Transacción Invalido"}"#).unwrap();
        let data = sync_router_data(None);
        let status_before = data.status;
        let result = PaymentsSyncRouterData::try_from(ResponseRouterData {
            response: not_found,
            data,
            http_code: 200,
        })
        .unwrap();
        assert_eq!(result.status, status_before);
    }

    const SDK_ERROR_QUERY: &str =
        "izipay_result=sdk_error&izipay_error=sdk_load_failed&izipay_error_detail=script%20load%20timeout";

    fn sync_with_return_query(
        body: &str,
        query: &str,
        status_before: enums::AttemptStatus,
    ) -> PaymentsSyncRouterData {
        let mut data = sync_router_data(None);
        data.status = status_before;
        data.request.encoded_data = Some(query.to_string());
        let response: IzipaySearchResponse = serde_json::from_str(body).unwrap();
        PaymentsSyncRouterData::try_from(ResponseRouterData {
            response,
            data,
            http_code: 200,
        })
        .unwrap()
    }

    #[test]
    fn sdk_error_with_nothing_paid_fails_with_a_stable_code() {
        // Izipay answers "transaction does not exist" in a 2xx: the attempt would keep its
        // status, but the page already gave up, so it fails with the internal code.
        let result = sync_with_return_query(
            r#"{"code":"MC","message":"Transacción Invalido"}"#,
            SDK_ERROR_QUERY,
            enums::AttemptStatus::AuthenticationPending,
        );
        assert_eq!(result.status, enums::AttemptStatus::Failure);
        let error = result.response.unwrap_err();
        assert_eq!(error.code, SDK_ERROR_CODE);
        assert_eq!(
            error.message,
            "The Izipay checkout page could not be opened (sdk_load_failed)"
        );
        assert_eq!(error.reason.as_deref(), Some("script load timeout"));
        assert_eq!(error.attempt_status, Some(enums::AttemptStatus::Failure));

        // A pending order (the buyer never paid) is treated the same way.
        let pending = sync_with_return_query(
            r#"{"code":"00","response":{"order":[{"orderNumber":"PX1790971180429","stateMessage":"Pendiente"}]}}"#,
            SDK_ERROR_QUERY,
            enums::AttemptStatus::AuthenticationPending,
        );
        assert_eq!(pending.response.unwrap_err().code, SDK_ERROR_CODE);
    }

    #[test]
    fn a_paid_order_wins_over_the_sdk_error_marker() {
        let result = sync_with_return_query(
            SEARCH_APPROVED,
            SDK_ERROR_QUERY,
            enums::AttemptStatus::AuthenticationPending,
        );
        assert_eq!(result.status, enums::AttemptStatus::Charged);
        assert!(result.response.is_ok());

        // An attempt that already progressed (charged earlier) is never failed by a url param.
        let already_charged = sync_with_return_query(
            r#"{"code":"MC","message":"Transacción Invalido"}"#,
            SDK_ERROR_QUERY,
            enums::AttemptStatus::Charged,
        );
        assert_eq!(already_charged.status, enums::AttemptStatus::Charged);
    }

    #[test]
    fn izipays_own_decline_keeps_its_code_over_the_sdk_error_marker() {
        let result = sync_with_return_query(
            r#"{"code":"05","message":"Operación Denegada"}"#,
            SDK_ERROR_QUERY,
            enums::AttemptStatus::AuthenticationPending,
        );
        assert_eq!(result.status, enums::AttemptStatus::Failure);
        assert_eq!(result.response.unwrap_err().code, "05");
    }

    #[test]
    fn other_return_markers_do_not_change_the_sync_outcome() {
        let result = sync_with_return_query(
            r#"{"code":"MC","message":"Transacción Invalido"}"#,
            "izipay_result=cancel",
            enums::AttemptStatus::AuthenticationPending,
        );
        assert_eq!(result.status, enums::AttemptStatus::AuthenticationPending);
    }

    // ------------------------------------------------------------------
    // Post-capture void
    // ------------------------------------------------------------------

    const CANCEL_OK: &str = r#"{"code":"00","message":"Operación exitosa.","header":{"millis":"292"},"response":{"order":{"orderNumber":"PX1790971180429","currency":"PEN","amount":"1.99"},"result":{"messageFriendly":"Operación exitosa.","authorizationCode":"S97758","uniqueIdCancel":"S78185"}}}"#;

    const CANCEL_AMOUNT_MISMATCH: &str = r#"{"code":"422","message":"El monto no concinde con el del token.","response":{"result":{"messageFriendly":"El monto no concinde con el del token.","authorizationCode":"S97758","uniqueIdCancel":"450249587"}}}"#;

    fn void_charged_metadata() -> serde_json::Value {
        serde_json::json!({
            "transaction_id": TOKEN_TRANSACTION_ID,
            "order_number": "PX1790971180429",
            "unique_id": "450249587",
            "authorization_code": "S97758",
            "reference_number": "2000000",
            "transaction_date": "20261002",
            "transaction_time": "150001",
            "pay_method": "CARD",
            "currency": "PEN",
            "amount": "1.99",
        })
    }

    fn void_router_data(
        connector_meta: Option<serde_json::Value>,
        minor_amount: i64,
    ) -> PaymentsCancelPostCaptureRouterData {
        let mut router_data = base_router_data::<PostCaptureVoid, _, PaymentsResponseData>(
            PaymentsCancelPostCaptureData {
                currency: Some(enums::Currency::PEN),
                connector_transaction_id: "PX1790971180429".to_string(),
                cancellation_reason: None,
                connector_meta,
                minor_amount: Some(MinorUnit::new(minor_amount)),
            },
            PaymentAddress::default(),
            "PX1790971180429",
        );
        router_data.status = enums::AttemptStatus::Charged;
        router_data
    }

    fn void_body(router_data: &PaymentsCancelPostCaptureRouterData) -> serde_json::Value {
        serde_json::to_value(IzipayCancelRequest::try_from(router_data).unwrap()).unwrap()
    }

    fn cancel_response(body: &str, http_code: u16) -> PaymentsCancelPostCaptureRouterData {
        let response: IzipayCancelResponse = serde_json::from_str(body).unwrap();
        PaymentsCancelPostCaptureRouterData::try_from(ResponseRouterData {
            response,
            data: void_router_data(Some(void_charged_metadata()), 199),
            http_code,
        })
        .unwrap()
    }

    #[test]
    fn cancel_request_body_matches_the_verified_sandbox_call() {
        let body = void_body(&void_router_data(Some(void_charged_metadata()), 199));
        assert_eq!(
            body,
            serde_json::json!({
                "merchantCode": "4004353",
                "order": {
                    "orderNumber": "PX1790971180429",
                    "currency": "PEN",
                    "amount": "1.99",
                    "payMethod": "CARD",
                    "channel": "ecommerce",
                    "uniqueId": "450249587",
                    "authorizationCode": "S97758",
                    "transactionDatetime": "2026-10-02 15:00:01.000"
                },
                "language": "ESP"
            })
        );
    }

    #[test]
    fn cancel_request_uses_midnight_when_the_time_was_not_stored() {
        let mut metadata = void_charged_metadata();
        metadata.as_object_mut().unwrap().remove("transaction_time");
        metadata.as_object_mut().unwrap().remove("pay_method");
        let body = void_body(&void_router_data(Some(metadata), 199));
        assert_eq!(
            body["order"]["transactionDatetime"],
            "2026-10-02 00:00:00.000"
        );
        assert_eq!(body["order"]["payMethod"], "CARD");
    }

    #[test]
    fn cancel_request_needs_what_the_charging_sync_stored() {
        for missing in ["unique_id", "authorization_code", "transaction_date"] {
            let mut metadata = void_charged_metadata();
            metadata.as_object_mut().unwrap().remove(missing);
            let error = IzipayCancelRequest::try_from(&void_router_data(Some(metadata), 199))
                .expect_err("a missing field must fail before anything is sent");
            assert!(matches!(
                error.current_context(),
                errors::ConnectorError::MissingRequiredField { .. }
            ));
        }
        assert!(IzipayCancelRequest::try_from(&void_router_data(None, 199)).is_err());

        let mut metadata = void_charged_metadata();
        metadata["transaction_date"] = serde_json::json!("02/10/2026");
        assert!(matches!(
            IzipayCancelRequest::try_from(&void_router_data(Some(metadata), 199))
                .unwrap_err()
                .current_context(),
            errors::ConnectorError::InvalidDataFormat { .. }
        ));
    }

    #[test]
    fn cancel_request_rejects_a_partial_void() {
        let error =
            IzipayCancelRequest::try_from(&void_router_data(Some(void_charged_metadata()), 100))
                .expect_err("only the approved amount can be voided");
        assert!(matches!(
            error.current_context(),
            errors::ConnectorError::NotSupported { .. }
        ));
    }

    #[test]
    fn cancel_success_is_voided_post_charge_and_keeps_the_refund_metadata() {
        let result = cancel_response(CANCEL_OK, 200);
        assert_eq!(result.status, enums::AttemptStatus::VoidedPostCharge);
        match result.response.unwrap() {
            PaymentsResponseData::TransactionResponse {
                resource_id,
                connector_metadata,
                ..
            } => {
                assert!(matches!(
                    resource_id,
                    ResponseId::ConnectorTransactionId(ref id) if id == "PX1790971180429"
                ));
                let mut expected = void_charged_metadata();
                expected["unique_id_cancel"] = serde_json::json!("S78185");
                assert_eq!(connector_metadata, Some(expected));
            }
            other => panic!("expected a TransactionResponse, got {other:?}"),
        }
    }

    #[test]
    fn cancel_error_carries_the_izipay_code_and_keeps_the_status() {
        let result = cancel_response(CANCEL_AMOUNT_MISMATCH, 422);
        assert_eq!(result.status, enums::AttemptStatus::Charged);
        let error = result.response.unwrap_err();
        assert_eq!(error.code, "422");
        assert_eq!(error.message, "El monto no concinde con el del token.");
        assert_eq!(error.attempt_status, None);
    }

    fn token_router_data(
        status: enums::AttemptStatus,
        minor_amount_captured: Option<i64>,
        refund_id: Option<&str>,
        current_flow: Option<hyperswitch_domain_models::router_request_types::CurrentFlowInfo>,
    ) -> RefreshTokenRouterData {
        let mut router_data = base_router_data::<
            hyperswitch_domain_models::router_flow_types::access_token_auth::AccessTokenAuth,
            hyperswitch_domain_models::router_request_types::AccessTokenRequestData,
            AccessToken,
        >(
            hyperswitch_domain_models::router_request_types::AccessTokenRequestData {
                app_id: Secret::new("x".to_string()),
                id: None,
                authentication_token: None,
                current_flow,
            },
            PaymentAddress::default(),
            "PX1790971180429",
        );
        router_data.status = status;
        router_data.minor_amount_captured = minor_amount_captured.map(MinorUnit::new);
        router_data.refund_id = refund_id.map(str::to_string);
        router_data
    }

    fn token_body(router_data: &RefreshTokenRouterData) -> serde_json::Value {
        serde_json::to_value(IzipayTokenRequest::try_from(router_data).unwrap()).unwrap()
    }

    fn generic_token_body() -> serde_json::Value {
        serde_json::json!({
            "requestSource": "ECOMMERCE",
            "merchantCode": "4004353",
            "orderNumber": "4004353",
            "publicKey": "sample_api_key",
            "amount": "0.00"
        })
    }

    #[test]
    fn void_token_is_bound_to_the_original_order_and_amount() {
        let router_data = token_router_data(enums::AttemptStatus::Charged, Some(199), None, None);
        assert_eq!(
            token_body(&router_data),
            serde_json::json!({
                "requestSource": "ECOMMERCE",
                "merchantCode": "4004353",
                "orderNumber": "PX1790971180429",
                "publicKey": "sample_api_key",
                "amount": "1.99"
            })
        );
        // Amounts below one sol keep their leading zero and every amount two decimals.
        let router_data = token_router_data(enums::AttemptStatus::Charged, Some(5), None, None);
        assert_eq!(token_body(&router_data)["amount"], "0.05");
        let router_data = token_router_data(enums::AttemptStatus::Charged, Some(12000), None, None);
        assert_eq!(token_body(&router_data)["amount"], "120.00");
    }

    #[test]
    fn payment_sync_and_refund_tokens_are_not_bound_to_an_order() {
        let psync_flow = hyperswitch_domain_models::router_request_types::CurrentFlowInfo::Psync {
            request_data: Box::new(sync_router_data(None).request),
        };
        // Same charged attempt and captured amount as the void, but the flow tells them apart.
        let psync = token_router_data(
            enums::AttemptStatus::Charged,
            Some(199),
            None,
            Some(psync_flow),
        );
        assert_eq!(token_body(&psync), generic_token_body());

        let refund = token_router_data(
            enums::AttemptStatus::Charged,
            Some(199),
            Some("ref_1"),
            None,
        );
        let mut expected = generic_token_body();
        expected["requestSource"] = serde_json::json!("REFUND");
        assert_eq!(token_body(&refund), expected);

        // A payment that is not charged (or has no captured amount) is never a void.
        let pending = token_router_data(
            enums::AttemptStatus::AuthenticationPending,
            Some(199),
            None,
            None,
        );
        assert_eq!(token_body(&pending), generic_token_body());
        let no_amount = token_router_data(enums::AttemptStatus::Charged, None, None, None);
        assert_eq!(token_body(&no_amount), generic_token_body());
    }

    #[test]
    fn void_token_is_packed_as_an_ecommerce_token() {
        let router_data = token_router_data(enums::AttemptStatus::Charged, Some(199), None, None);
        let access_token = RouterData::try_from(ResponseRouterData {
            response: token_response(),
            data: router_data,
            http_code: 200,
        })
        .unwrap()
        .response
        .unwrap();
        // The cancel call reads it back as an ecommerce token, never as a refund one.
        assert!(unpack_access_token(Some(&access_token), IzipayTokenKind::Ecommerce).is_ok());
        assert!(unpack_access_token(Some(&access_token), IzipayTokenKind::Refund).is_err());
    }

    #[test]
    fn a_charged_order_that_izipay_reports_voided_is_a_post_capture_void() {
        let response: IzipaySearchResponse = serde_json::from_str(SEARCH_VOIDED).unwrap();
        for (before, expected) in [
            (
                enums::AttemptStatus::Charged,
                enums::AttemptStatus::VoidedPostCharge,
            ),
            (
                enums::AttemptStatus::VoidedPostCharge,
                enums::AttemptStatus::VoidedPostCharge,
            ),
            (
                enums::AttemptStatus::AuthenticationPending,
                enums::AttemptStatus::Voided,
            ),
        ] {
            let mut data = sync_router_data(Some(void_charged_metadata()));
            data.status = before;
            let result = PaymentsSyncRouterData::try_from(ResponseRouterData {
                response: response.clone(),
                data,
                http_code: 200,
            })
            .unwrap();
            assert_eq!(result.status, expected);
        }
    }
}
