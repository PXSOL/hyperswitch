use common_enums::enums;
use common_utils::types::FloatMajorUnit;
use hyperswitch_domain_models::{
    payment_method_data::{PaymentMethodData, WalletData},
    router_data::{ConnectorAuthType, ErrorResponse, RouterData},
    router_flow_types::refunds::{Execute, RSync},
    router_request_types::ResponseId,
    router_response_types::{PaymentsResponseData, RefundsResponseData},
    types::{PaymentsAuthorizeRouterData, PaymentsCaptureRouterData, RefundsRouterData},
};
use hyperswitch_interfaces::errors;
use masking::{PeekInterface, Secret};
use serde::{de::Deserialize as DeDeserialize, Deserialize, Serialize};

use crate::{
    types::{RefundsResponseRouterData, ResponseRouterData},
    utils::RouterData as _,
};

pub struct MercadopagoRouterData<T> {
    pub amount: FloatMajorUnit,
    pub router_data: T,
}

impl<T> From<(FloatMajorUnit, T)> for MercadopagoRouterData<T> {
    fn from((amount, item): (FloatMajorUnit, T)) -> Self {
        Self {
            amount,
            router_data: item,
        }
    }
}

pub struct MercadopagoAuthType {
    /// Access token for API calls (Bearer token)
    pub(super) api_key: Secret<String>,
}

impl TryFrom<&ConnectorAuthType> for MercadopagoAuthType {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::HeaderKey { api_key } => Ok(Self {
                api_key: api_key.to_owned(),
            }),
            _ => Err(errors::ConnectorError::FailedToObtainAuthType.into()),
        }
    }
}


#[derive(Debug, Serialize)]
pub struct MercadopagoPayer {
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identification: Option<MercadopagoIdentification>,
}

#[derive(Debug, Serialize)]
pub struct MercadopagoIdentification {
    #[serde(rename = "type")]
    pub id_type: Option<String>,
    pub number: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct MercadopagoPaymentsRequest {
    pub transaction_amount: FloatMajorUnit,
    pub token: Secret<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub installments: i32,
    pub payment_method_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer_id: Option<i64>,
    pub payer: MercadopagoPayer,
    pub capture: bool,
    pub external_reference: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub binary_mode: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notification_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub statement_descriptor: Option<String>,
}

impl TryFrom<&MercadopagoRouterData<&PaymentsAuthorizeRouterData>> for MercadopagoPaymentsRequest {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: &MercadopagoRouterData<&PaymentsAuthorizeRouterData>,
    ) -> Result<Self, Self::Error> {
        let router_data = item.router_data;

        let (token, payment_method_id, issuer_id, installments, identification_type, identification_number) =
            match &router_data.request.payment_method_data {
                PaymentMethodData::Wallet(WalletData::MercadoPagoSdk(mp_data)) => {
                    let issuer_id_parsed = mp_data
                        .issuer_id
                        .as_ref()
                        .and_then(|id| id.parse::<i64>().ok());
                    (
                        Secret::new(mp_data.token.clone()),
                        mp_data.payment_method_id.clone(),
                        issuer_id_parsed,
                        mp_data.installments.unwrap_or(1),
                        mp_data.identification_type.clone(),
                        mp_data.identification_number.clone(),
                    )
                }
                _ => {
                    return Err(errors::ConnectorError::NotImplemented(
                        "Payment method not supported for MercadoPago".to_string(),
                    )
                    .into())
                }
            };

        let transaction_amount = item.amount;

        let capture = matches!(
            router_data.request.capture_method,
            Some(enums::CaptureMethod::Automatic) | None
        );

        // Try to get email from request first, then fallback to billing
        let payer_email = router_data
            .request
            .email
            .as_ref()
            .map(|e| e.peek().to_string())
            .or_else(|| {
                router_data
                    .get_optional_billing_email()
                    .map(|e| e.peek().to_string())
            });

        let payer_first_name = router_data
            .get_optional_billing_first_name()
            .map(|n| n.peek().to_string());

        let payer_last_name = router_data
            .get_optional_billing_last_name()
            .map(|n| n.peek().to_string());

        // Filter out localhost URLs for notification_url (Mercado Pago requires public URLs)
        let notification_url = router_data
            .request
            .webhook_url
            .as_ref()
            .filter(|url| !url.contains("localhost") && !url.contains("127.0.0.1"))
            .cloned();

        // Build payer identification if provided
        let payer_identification = if identification_type.is_some() || identification_number.is_some() {
            Some(MercadopagoIdentification {
                id_type: identification_type,
                number: identification_number,
            })
        } else {
            None
        };

        Ok(Self {
            transaction_amount,
            token,
            description: None,
            installments,
            payment_method_id,
            issuer_id,
            payer: MercadopagoPayer {
                email: payer_email,
                first_name: payer_first_name,
                last_name: payer_last_name,
                identification: payer_identification,
            },
            capture,
            external_reference: router_data.connector_request_reference_id.clone(),
            binary_mode: Some(true),
            notification_url,
            statement_descriptor: router_data.request.statement_descriptor.clone(),
        })
    }
}

#[derive(Debug, Serialize)]
pub struct MercadopagoCaptureRequest {
    pub capture: bool,
}

impl TryFrom<&PaymentsCaptureRouterData> for MercadopagoCaptureRequest {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(_item: &PaymentsCaptureRouterData) -> Result<Self, Self::Error> {
        Ok(Self { capture: true })
    }
}

#[derive(Debug, Serialize)]
pub struct MercadopagoCancelRequest {
    pub status: &'static str,
}

impl Default for MercadopagoCancelRequest {
    fn default() -> Self {
        Self {
            status: "cancelled",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum MercadopagoPaymentStatus {
    Approved,
    Pending,
    Authorized,
    InProcess,
    InMediation,
    Rejected,
    Cancelled,
    Refunded,
    ChargedBack,
}

impl From<MercadopagoPaymentStatus> for enums::AttemptStatus {
    fn from(status: MercadopagoPaymentStatus) -> Self {
        match status {
            MercadopagoPaymentStatus::Approved => Self::Charged,
            MercadopagoPaymentStatus::Authorized => Self::Authorized,
            MercadopagoPaymentStatus::Pending | MercadopagoPaymentStatus::InProcess => {
                Self::Pending
            }
            MercadopagoPaymentStatus::InMediation => Self::Pending,
            MercadopagoPaymentStatus::Rejected => Self::Failure,
            MercadopagoPaymentStatus::Cancelled => Self::Voided,
            MercadopagoPaymentStatus::Refunded => Self::AutoRefunded,
            MercadopagoPaymentStatus::ChargedBack => Self::AutoRefunded,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MercadopagoPaymentsResponse {
    pub id: i64,
    pub status: MercadopagoPaymentStatus,
    #[serde(default)]
    pub status_detail: Option<String>,
    #[serde(default)]
    pub external_reference: Option<String>,
    #[serde(default)]
    pub date_created: Option<String>,
    #[serde(default)]
    pub date_approved: Option<String>,
    #[serde(default)]
    pub transaction_amount: Option<f64>,
    #[serde(default)]
    pub currency_id: Option<String>,
    #[serde(default)]
    pub payment_method_id: Option<String>,
    #[serde(default)]
    pub payment_type_id: Option<String>,
}

impl<F, T> TryFrom<ResponseRouterData<F, MercadopagoPaymentsResponse, T, PaymentsResponseData>>
    for RouterData<F, T, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<F, MercadopagoPaymentsResponse, T, PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        let connector_transaction_id = item.response.id.to_string();
        let status = enums::AttemptStatus::from(item.response.status.clone());

        let response = if status == enums::AttemptStatus::Failure {
            let error_code = item
                .response
                .status_detail
                .clone()
                .unwrap_or_else(|| "rejected".to_string());
            let error_message = get_mercadopago_error_message(&error_code);

            Err(ErrorResponse {
                code: error_code.clone(),
                message: error_message.clone(),
                reason: Some(error_message.clone()),
                status_code: item.http_code,
                attempt_status: Some(status),
                connector_transaction_id: Some(connector_transaction_id.clone()),
                connector_metadata: None,
                network_advice_code: None,
                network_decline_code: Some(error_code),
                network_error_message: Some(error_message),
            })
        } else {
            Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(connector_transaction_id.clone()),
                redirection_data: Box::new(None),
                mandate_reference: Box::new(None),
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: item
                    .response
                    .external_reference
                    .or(Some(connector_transaction_id)),
                incremental_authorization_allowed: None,
                charges: None,
            })
        };

        Ok(Self {
            status,
            response,
            ..item.data
        })
    }
}

fn get_mercadopago_error_message(status_detail: &str) -> String {
    match status_detail {
        // Card rejections - bad filled data
        "cc_rejected_bad_filled_card_number" => "The card number is incorrect".to_string(),
        "cc_rejected_bad_filled_date" => "The expiration date is incorrect".to_string(),
        "cc_rejected_bad_filled_other" => "Some card detail is incorrect".to_string(),
        "cc_rejected_bad_filled_security_code" => "The security code (CVV) is incorrect".to_string(),

        // Card rejections - card issues
        "cc_rejected_blacklist" => "The card is blocked".to_string(),
        "cc_rejected_call_for_authorize" => "The payment requires authorization - call your bank".to_string(),
        "cc_rejected_card_disabled" => "The card is disabled - contact your bank".to_string(),
        "cc_rejected_card_error" => "The card could not be processed".to_string(),
        "cc_rejected_card_type_not_allowed" => "This card type is not allowed for this payment".to_string(),

        // Card rejections - transaction issues
        "cc_rejected_duplicated_payment" => "This payment has already been processed".to_string(),
        "cc_rejected_high_risk" => "The payment was rejected due to high risk".to_string(),
        "cc_rejected_insufficient_amount" => "Insufficient funds".to_string(),
        "cc_rejected_invalid_installments" => "Invalid number of installments for this card".to_string(),
        "cc_rejected_max_attempts" => "Maximum retry attempts reached - try with another card".to_string(),
        "cc_rejected_other_reason" => "The payment was rejected by the card issuer".to_string(),

        // 3DS rejections
        "cc_rejected_3ds_challenge" => "Payment rejected for not passing 3DS challenge".to_string(),
        "cc_rejected_3ds_mandatory" => "3DS authentication is mandatory for this payment".to_string(),

        // Amount/limit rejections
        "cc_amount_rate_limit_exceeded" => "Amount exceeds the allowed rate limit".to_string(),
        "rejected_by_regulations" => "Payment rejected due to regulatory restrictions".to_string(),

        // Bank/debit card rejections
        "bank_error" => "Bank processing error - try again later".to_string(),
        "insufficient_amount" => "Insufficient funds in the account".to_string(),
        "rejected_by_bank" => "The payment was rejected by the bank".to_string(),

        // Pending states
        "pending_contingency" => "Payment is pending due to a processing contingency".to_string(),
        "pending_review_manual" => "Payment is under manual review".to_string(),
        "pending_waiting_payment" => "Waiting for payment confirmation".to_string(),
        "pending_waiting_transfer" => "Waiting for bank transfer".to_string(),
        "pending_challenge" => "Payment requires additional authentication".to_string(),
        "pending_provider_response" => "Waiting for payment provider response".to_string(),

        // Approved states
        "accredited" => "Payment approved and credited".to_string(),
        "partially_refunded" => "Payment partially refunded".to_string(),

        // Refund/chargeback states
        "refunded" => "Payment has been refunded".to_string(),
        "charged_back" => "Payment has been charged back".to_string(),
        "in_mediation" => "Payment is in dispute mediation".to_string(),
        "bpp_refunded" => "Payment refunded by buyer protection".to_string(),
        "reimbursed" => "Payment has been reimbursed".to_string(),

        // Cancellation states
        "by_admin" => "Payment cancelled by administrator".to_string(),
        "by_collector" => "Payment cancelled by merchant".to_string(),
        "by_payer" => "Payment cancelled by payer".to_string(),
        "expired" => "Payment expired".to_string(),

        // Default
        _ => format!("Payment rejected: {}", status_detail),
    }
}

/// Get a descriptive error message for API validation errors (HTTP 400)
fn get_api_validation_error_message(error_code: &str, cause_code: Option<&str>) -> String {
    match error_code {
        "bad_request" => {
            match cause_code {
                Some("1") | Some("3") => "Invalid or missing parameters in the request".to_string(),
                Some("2") => "Invalid token - the card token may have expired or is invalid".to_string(),
                Some("4") => "Invalid customer data".to_string(),
                Some("5") => "Invalid card data".to_string(),
                Some("6") => "Invalid security code".to_string(),
                Some("7") => "Invalid expiration date".to_string(),
                Some("8") => "Invalid card number".to_string(),
                Some("105") => "User not found or invalid user".to_string(),
                Some("106") => "Card token not found or expired".to_string(),
                Some("107") => "Card not found".to_string(),
                Some("109") => "Invalid card expiration date".to_string(),
                Some("145") => "User ID is required".to_string(),
                Some("150") => "Payer email must be different from collector email".to_string(),
                Some("151") => "Payer ID must be different from collector ID".to_string(),
                Some("160") => "Card issuer not found".to_string(),
                Some("200") => "Invalid amount".to_string(),
                Some("205") | Some("E205") => "Card number is required".to_string(),
                Some("208") | Some("E208") => "Card expiration month is required".to_string(),
                Some("209") | Some("E209") => "Card expiration year is required".to_string(),
                Some("212") | Some("E212") => "Card type is required".to_string(),
                Some("213") | Some("E213") => "Document type is required".to_string(),
                Some("214") | Some("E214") => "Document number is required".to_string(),
                Some("220") | Some("E220") => "Card issuer is required".to_string(),
                Some("221") | Some("E221") => "Invalid card number".to_string(),
                Some("224") | Some("E224") => "Security code is required".to_string(),
                Some("E301") => "Invalid card number".to_string(),
                Some("E302") => "Invalid security code".to_string(),
                Some("316") => "Cardholder name is required".to_string(),
                Some("322") => "Invalid document type".to_string(),
                Some("323") => "Invalid document number".to_string(),
                Some("324") => "Invalid document subtype".to_string(),
                Some("325") => "Invalid document number for the document type".to_string(),
                Some("326") => "Invalid document type for the country".to_string(),
                _ => "Invalid request parameters".to_string(),
            }
        }
        "invalid_token" => "The card token is invalid or has expired".to_string(),
        "invalid_card_expiration_month" => "Invalid card expiration month".to_string(),
        "invalid_card_expiration_year" => "Invalid card expiration year".to_string(),
        "invalid_security_code" => "Invalid card security code".to_string(),
        "invalid_card_number" => "Invalid card number".to_string(),
        "invalid_payer_email" => "Invalid payer email".to_string(),
        "invalid_installments" => "Invalid number of installments".to_string(),
        "invalid_issuer_id" => "Invalid card issuer".to_string(),
        "invalid_payment_method_id" => "Invalid payment method".to_string(),
        "invalid_transaction_amount" => "Invalid transaction amount".to_string(),
        "json_syntax_error" => "Invalid JSON format in the request".to_string(),
        "required_properties" => "Required fields are missing in the request".to_string(),
        "unsupported_properties" => "Unsupported fields in the request".to_string(),
        "property_type" => "Invalid field type in the request".to_string(),
        "property_value" => "Invalid field value in the request".to_string(),
        "internal_error" => "Internal server error - please try again".to_string(),
        _ => format!("API error: {}", error_code),
    }
}

#[derive(Debug, Serialize)]
pub struct MercadopagoRefundRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amount: Option<FloatMajorUnit>,
}

impl<F> TryFrom<&MercadopagoRouterData<&RefundsRouterData<F>>> for MercadopagoRefundRequest {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(item: &MercadopagoRouterData<&RefundsRouterData<F>>) -> Result<Self, Self::Error> {
        Ok(Self {
            amount: Some(item.amount),
        })
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum MercadopagoRefundStatus {
    Approved,
    #[default]
    Pending,
    Rejected,
    Cancelled,
}

impl From<MercadopagoRefundStatus> for enums::RefundStatus {
    fn from(status: MercadopagoRefundStatus) -> Self {
        match status {
            MercadopagoRefundStatus::Approved => Self::Success,
            MercadopagoRefundStatus::Pending => Self::Pending,
            MercadopagoRefundStatus::Rejected | MercadopagoRefundStatus::Cancelled => Self::Failure,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefundResponse {
    pub id: i64,
    #[serde(default)]
    pub status: MercadopagoRefundStatus,
    #[serde(default)]
    pub amount: Option<f64>,
    #[serde(default)]
    pub date_created: Option<String>,
}

impl TryFrom<RefundsResponseRouterData<Execute, RefundResponse>> for RefundsRouterData<Execute> {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: RefundsResponseRouterData<Execute, RefundResponse>,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            response: Ok(RefundsResponseData {
                connector_refund_id: item.response.id.to_string(),
                refund_status: enums::RefundStatus::from(item.response.status),
            }),
            ..item.data
        })
    }
}

impl TryFrom<RefundsResponseRouterData<RSync, RefundResponse>> for RefundsRouterData<RSync> {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: RefundsResponseRouterData<RSync, RefundResponse>,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            response: Ok(RefundsResponseData {
                connector_refund_id: item.response.id.to_string(),
                refund_status: enums::RefundStatus::from(item.response.status),
            }),
            ..item.data
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MercadopagoErrorResponse {
    #[serde(default)]
    pub message: String,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub status: Option<i32>,
    #[serde(default)]
    pub cause: Option<Vec<MercadopagoErrorCause>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MercadopagoErrorCause {
    #[serde(default, deserialize_with = "deserialize_code")]
    pub code: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
}

fn deserialize_code<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Error;
    let value: Option<serde_json::Value> = DeDeserialize::deserialize(deserializer)?;
    match value {
        Some(serde_json::Value::String(s)) => Ok(Some(s)),
        Some(serde_json::Value::Number(n)) => Ok(Some(n.to_string())),
        Some(_) => Err(D::Error::custom("expected string or number")),
        None => Ok(None),
    }
}

impl MercadopagoErrorResponse {
    pub fn get_error_code(&self) -> String {
        self.error
            .clone()
            .or_else(|| {
                self.cause
                    .as_ref()
                    .and_then(|c| c.first())
                    .and_then(|c| c.code.clone())
            })
            .unwrap_or_else(|| "UNKNOWN_ERROR".to_string())
    }

    pub fn get_error_message(&self) -> String {
        let error_code = self.error.as_deref().unwrap_or("");
        let cause_code = self
            .cause
            .as_ref()
            .and_then(|c| c.first())
            .and_then(|c| c.code.as_deref());

        // Use descriptive message based on error code and cause
        let descriptive_message = get_api_validation_error_message(error_code, cause_code);

        // If we have a specific message from the API and it's not just "Params Error",
        // append it for context
        if !self.message.is_empty() && self.message != "Params Error" {
            format!("{} - {}", descriptive_message, self.message)
        } else {
            descriptive_message
        }
    }

    pub fn get_detailed_reason(&self) -> Option<String> {
        self.cause.as_ref().map(|causes| {
            causes
                .iter()
                .filter_map(|c| {
                    match (&c.code, &c.description) {
                        (Some(code), Some(desc)) => Some(format!("Code {}: {}", code, desc)),
                        (Some(code), None) => Some(format!("Code {}", code)),
                        (None, Some(desc)) => Some(desc.clone()),
                        (None, None) => None,
                    }
                })
                .collect::<Vec<_>>()
                .join("; ")
        }).filter(|s| !s.is_empty())
    }
}

// ============================================================================
// Webhook Types
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MercadopagoWebhookBody {
    pub id: Option<i64>,
    pub live_mode: Option<bool>,
    #[serde(rename = "type")]
    pub webhook_type: Option<String>,
    pub date_created: Option<String>,
    pub application_id: Option<i64>,
    pub user_id: Option<i64>,
    pub api_version: Option<String>,
    pub action: String,
    pub data: MercadopagoWebhookData,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MercadopagoWebhookData {
    pub id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum MercadopagoWebhookAction {
    #[serde(rename = "payment.created")]
    PaymentCreated,
    #[serde(rename = "payment.updated")]
    PaymentUpdated,
    #[serde(rename = "refund.created")]
    RefundCreated,
    #[serde(rename = "refund.updated")]
    RefundUpdated,
    #[serde(rename = "chargeback.created")]
    ChargebackCreated,
    #[serde(rename = "chargeback.updated")]
    ChargebackUpdated,
    #[serde(other)]
    Unknown,
}

impl From<&str> for MercadopagoWebhookAction {
    fn from(action: &str) -> Self {
        match action {
            "payment.created" => Self::PaymentCreated,
            "payment.updated" => Self::PaymentUpdated,
            "refund.created" => Self::RefundCreated,
            "refund.updated" => Self::RefundUpdated,
            "chargeback.created" => Self::ChargebackCreated,
            "chargeback.updated" => Self::ChargebackUpdated,
            _ => Self::Unknown,
        }
    }
}

impl From<MercadopagoWebhookAction> for api_models::webhooks::IncomingWebhookEvent {
    fn from(action: MercadopagoWebhookAction) -> Self {
        match action {
            MercadopagoWebhookAction::PaymentCreated => Self::PaymentIntentProcessing,
            MercadopagoWebhookAction::PaymentUpdated => Self::PaymentIntentSuccess,
            MercadopagoWebhookAction::RefundCreated | MercadopagoWebhookAction::RefundUpdated => {
                Self::RefundSuccess
            }
            MercadopagoWebhookAction::ChargebackCreated
            | MercadopagoWebhookAction::ChargebackUpdated => Self::DisputeOpened,
            MercadopagoWebhookAction::Unknown => Self::EventNotSupported,
        }
    }
}
