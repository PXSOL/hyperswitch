use common_enums::enums;
use common_utils::{pii::SecretSerdeValue, types::FloatMajorUnit};
use hyperswitch_domain_models::{
    payment_method_data::PaymentMethodData,
    router_data::{ConnectorAuthType, ErrorResponse, RouterData},
    router_flow_types::{
        payments::PaymentMethodToken,
        refunds::{Execute, RSync},
    },
    router_request_types::ResponseId,
    router_response_types::{PaymentsResponseData, RefundsResponseData},
    types::{PaymentsAuthorizeRouterData, PaymentsCaptureRouterData, RefundsRouterData, TokenizationRouterData},
};
use hyperswitch_interfaces::errors;
use masking::{PeekInterface, Secret};
use serde::{de::Deserialize as DeDeserialize, Deserialize, Serialize};

use crate::{
    types::{RefundsResponseRouterData, ResponseRouterData},
    utils::{self, RouterData as _},
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

// ============================================================================
// Metadata Structure - Custom fields for MercadoPago payments
// ============================================================================

#[derive(Debug, Default, Serialize, Deserialize, Clone)]
pub struct MercadopagoPayerInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_name: Option<Secret<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_name: Option<Secret<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone: Option<Secret<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<Secret<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub zip_code: Option<Secret<String>>,
}

#[derive(Debug, Default, Serialize, Deserialize, Clone)]
pub struct MercadopagoItemInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub category_id: Option<String>,
}

#[derive(Debug, Default, Serialize, Deserialize, Clone)]
pub struct MercadopagoMetadata {
    /// Payment method ID from Mercado Pago (visa, master, amex, naranja, cabal, etc.)
    pub payment_method_id: Option<String>,
    /// Issuer ID from Mercado Pago (bank that issued the card)
    pub issuer_id: Option<String>,
    /// Number of installments (1 = single payment, 3, 6, 12, etc.)
    pub installments: Option<i32>,
    /// Payer identification type (DNI, CPF, CUIT, CUIL, RUT, CC, CE, etc.)
    pub identification_type: Option<String>,
    /// Payer identification number
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identification_number: Option<Secret<String>>,
    /// Additional payer information for anti-fraud
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payer: Option<MercadopagoPayerInfo>,
    /// Item information for anti-fraud
    #[serde(skip_serializing_if = "Option::is_none")]
    pub item: Option<MercadopagoItemInfo>,
    /// Device ID from Mercado Pago SDK for anti-fraud (X-meli-session-id header)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_id: Option<Secret<String>>,
}

impl TryFrom<&Option<SecretSerdeValue>> for MercadopagoMetadata {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(meta_data: &Option<SecretSerdeValue>) -> Result<Self, Self::Error> {
        match meta_data {
            Some(metadata) => {
                let json_value = metadata.peek().clone();
                serde_json::from_value::<Self>(json_value)
                    .map_err(|_| errors::ConnectorError::InvalidConnectorConfig { config: "frm_metadata" }.into())
            }
            None => Ok(Self::default()),
        }
    }
}

impl TryFrom<&Option<serde_json::Value>> for MercadopagoMetadata {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(meta_data: &Option<serde_json::Value>) -> Result<Self, Self::Error> {
        match meta_data {
            Some(metadata) => serde_json::from_value::<Self>(metadata.clone())
                .map_err(|_e| errors::ConnectorError::InvalidConnectorConfig { config: "metadata" }.into()),
            None => Ok(Self::default()),
        }
    }
}

// ============================================================================
// Tokenization Types - POST /v1/card_tokens
// ============================================================================

#[derive(Debug, Serialize)]
pub struct MercadopagoCardholderIdentification {
    #[serde(rename = "type")]
    pub id_type: String,
    pub number: Secret<String>,
}

#[derive(Debug, Serialize)]
pub struct MercadopagoCardholder {
    pub name: Secret<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identification: Option<MercadopagoCardholderIdentification>,
}

#[derive(Debug, Serialize)]
pub struct MercadopagoTokenRequest {
    pub card_number: cards::CardNumber,
    pub expiration_month: Secret<String>,
    pub expiration_year: Secret<String>,
    pub security_code: Secret<String>,
    pub cardholder: MercadopagoCardholder,
}

impl TryFrom<&TokenizationRouterData> for MercadopagoTokenRequest {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(item: &TokenizationRouterData) -> Result<Self, Self::Error> {
        match &item.request.payment_method_data {
            PaymentMethodData::Card(card) => {
                // Get metadata from frm_metadata field in RouterData
                // This is a workaround since PaymentMethodTokenizationData doesn't have metadata field
                // User should pass MercadoPago metadata in frm_metadata of the payment request
                let metadata = MercadopagoMetadata::try_from(&item.frm_metadata)?;
                
                let cardholder_name = card
                    .card_holder_name
                    .clone()
                    .unwrap_or_else(|| Secret::new("APRO".to_string()));

                // Build identification for cardholder if provided in metadata
                let identification = match (metadata.identification_type, metadata.identification_number) {
                    (Some(id_type), Some(id_number)) => Some(MercadopagoCardholderIdentification {
                        id_type,
                        number: id_number,
                    }),
                    _ => None,
                };

                Ok(Self {
                    card_number: card.card_number.clone(),
                    expiration_month: card.card_exp_month.clone(),
                    expiration_year: card.card_exp_year.clone(),
                    security_code: card.card_cvc.clone(),
                    cardholder: MercadopagoCardholder {
                        name: cardholder_name,
                        identification,
                    },
                })
            }
            _ => Err(errors::ConnectorError::NotImplemented(
                "Payment method not supported for MercadoPago tokenization".to_string(),
            )
            .into()),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MercadopagoTokenResponse {
    pub id: String,
    pub status: Option<String>,
    pub first_six_digits: Option<String>,
    pub last_four_digits: Option<String>,
    pub expiration_month: Option<i32>,
    pub expiration_year: Option<i32>,
}

impl<T>
    TryFrom<
        ResponseRouterData<PaymentMethodToken, MercadopagoTokenResponse, T, PaymentsResponseData>,
    > for RouterData<PaymentMethodToken, T, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: ResponseRouterData<
            PaymentMethodToken,
            MercadopagoTokenResponse,
            T,
            PaymentsResponseData,
        >,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            response: Ok(PaymentsResponseData::TokenizationResponse {
                token: item.response.id,
            }),
            ..item.data
        })
    }
}

// ============================================================================
// Payment Request Types
// ============================================================================

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
    pub number: Option<Secret<String>>,
}

#[derive(Debug, Serialize)]
pub struct MercadopagoAdditionalInfoPayerPhone {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub number: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct MercadopagoAdditionalInfoPayerAddress {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub street_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub zip_code: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct MercadopagoAdditionalInfoPayer {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone: Option<MercadopagoAdditionalInfoPayerPhone>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<MercadopagoAdditionalInfoPayerAddress>,
}

#[derive(Debug, Serialize)]
pub struct MercadopagoAdditionalInfoItem {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub category_id: Option<String>,
    pub quantity: i32,
    pub unit_price: FloatMajorUnit,
}

#[derive(Debug, Serialize)]
pub struct MercadopagoAdditionalInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payer: Option<MercadopagoAdditionalInfoPayer>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub items: Option<Vec<MercadopagoAdditionalInfoItem>>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub additional_info: Option<MercadopagoAdditionalInfo>,
}

impl TryFrom<&MercadopagoRouterData<&PaymentsAuthorizeRouterData>> for MercadopagoPaymentsRequest {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: &MercadopagoRouterData<&PaymentsAuthorizeRouterData>,
    ) -> Result<Self, Self::Error> {
        let router_data = item.router_data;

        // Get token from payment_method_token (generated in tokenization step)
        let token = match router_data.get_payment_method_token()? {
            hyperswitch_domain_models::router_data::PaymentMethodToken::Token(t) => {
                Secret::new(t.peek().to_string())
            }
            _ => {
                return Err(errors::ConnectorError::MissingRequiredField {
                    field_name: "payment_method_token",
                }
                .into())
            }
        };

        // Get metadata with MercadoPago-specific fields
        // Try request.metadata first, then fall back to frm_metadata (for consistency with tokenization)
        let metadata_from_request = MercadopagoMetadata::try_from(&router_data.request.metadata)?;
        let metadata = if metadata_from_request.payment_method_id.is_some() {
            metadata_from_request
        } else {
            // Fallback to frm_metadata if request.metadata doesn't have payment_method_id
            MercadopagoMetadata::try_from(&router_data.frm_metadata)?
        };

        // payment_method_id is required
        let payment_method_id = metadata
            .payment_method_id
            .ok_or(errors::ConnectorError::MissingRequiredField {
                field_name: "metadata.payment_method_id",
            })?;

        let issuer_id = metadata
            .issuer_id
            .as_ref()
            .and_then(|id| id.parse::<i64>().ok());

        let installments = metadata.installments.unwrap_or(1);

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

        // Build payer identification from metadata
        let payer_identification = match (&metadata.identification_type, &metadata.identification_number) {
            (Some(id_type), Some(id_number)) => Some(MercadopagoIdentification {
                id_type: Some(id_type.clone()),
                number: Some(id_number.clone()),
            }),
            _ => None,
        };

        // Build additional_info for anti-fraud from metadata
        let additional_info = {
            let has_payer_info = metadata.payer.is_some();
            let has_item_info = metadata.item.is_some();

            if has_payer_info || has_item_info {
                let additional_payer = metadata.payer.as_ref().map(|p| {
                    MercadopagoAdditionalInfoPayer {
                        first_name: p.first_name.as_ref().map(|s| s.peek().to_string()),
                        last_name: p.last_name.as_ref().map(|s| s.peek().to_string()),
                        phone: p.phone.as_ref().map(|ph| MercadopagoAdditionalInfoPayerPhone {
                            number: Some(ph.peek().to_string()),
                        }),
                        address: if p.address.is_some() || p.zip_code.is_some() {
                            Some(MercadopagoAdditionalInfoPayerAddress {
                                street_name: p.address.as_ref().map(|s| s.peek().to_string()),
                                zip_code: p.zip_code.as_ref().map(|s| s.peek().to_string()),
                            })
                        } else {
                            None
                        },
                    }
                });

                let additional_items = metadata.item.as_ref().map(|i| {
                    vec![MercadopagoAdditionalInfoItem {
                        id: "1".to_string(),
                        title: i.title.clone(),
                        description: i.description.clone(),
                        category_id: i.category_id.clone(),
                        quantity: 1,
                        unit_price: transaction_amount,
                    }]
                });

                Some(MercadopagoAdditionalInfo {
                    payer: additional_payer,
                    items: additional_items,
                })
            } else {
                None
            }
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
            additional_info,
        })
    }
}

#[derive(Debug, Serialize)]
pub struct MercadopagoCaptureRequest {
    pub capture: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction_amount: Option<FloatMajorUnit>,
}

impl TryFrom<&MercadopagoRouterData<&PaymentsCaptureRouterData>> for MercadopagoCaptureRequest {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(item: &MercadopagoRouterData<&PaymentsCaptureRouterData>) -> Result<Self, Self::Error> {
        let router_data = item.router_data;
        
        let transaction_amount = if router_data.request.amount_to_capture != router_data.request.payment_amount {
            Some(item.amount)
        } else {
            None
        };

        Ok(Self {
            capture: true,
            transaction_amount,
        })
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

/// Webhooks v1 format: full JSON with action and data.id
/// Example: {"action":"payment.created","data":{"id":"150211668619"},...}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MercadopagoWebhookBody {
    #[serde(default)]
    pub id: Option<serde_json::Value>,
    pub live_mode: Option<bool>,
    #[serde(rename = "type")]
    pub webhook_type: Option<String>,
    pub date_created: Option<String>,
    #[serde(default)]
    pub application_id: Option<serde_json::Value>,
    #[serde(default)]
    pub user_id: Option<serde_json::Value>,
    pub api_version: Option<String>,
    pub action: String,
    pub data: MercadopagoWebhookData,
}

/// Feed v2 format: minimal JSON with resource and topic
/// Example: {"resource":"150211668619","topic":"payment"}
/// Used by "MercadoPago Feed v2.0 payment" user-agent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MercadopagoWebhookFeedBody {
    pub resource: String,
    pub topic: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum MercadopagoWebhookBodyEnum {
    Full(MercadopagoWebhookBody),
    Feed(MercadopagoWebhookFeedBody),
}

impl MercadopagoWebhookBodyEnum {
    /// Get the connector transaction ID (payment/refund/chargeback ID) from either format
    pub fn get_resource_id(&self) -> String {
        match self {
            Self::Full(body) => body.data.id.clone(),
            Self::Feed(body) => body.resource.clone(),
        }
    }

    /// Get the webhook action/event type
    pub fn get_action(&self) -> MercadopagoWebhookAction {
        match self {
            Self::Full(body) => MercadopagoWebhookAction::from(body.action.as_str()),
            Self::Feed(body) => topic_to_action(&body.topic),
        }
    }

    /// Convert to a unified struct for get_webhook_resource_object (implements ErasedMaskSerialize)
    pub fn to_resource_object(&self) -> MercadopagoWebhookResourceObject {
        match self {
            Self::Full(body) => MercadopagoWebhookResourceObject {
                resource_id: body.data.id.clone(),
                topic: body.webhook_type.clone().unwrap_or_else(|| "payment".to_string()),
                action: Some(body.action.clone()),
            },
            Self::Feed(body) => MercadopagoWebhookResourceObject {
                resource_id: body.resource.clone(),
                topic: body.topic.clone(),
                action: None,
            },
        }
    }
}

/// Unified resource object for logging (implements ErasedMaskSerialize)
#[derive(Debug, Clone, Serialize)]
pub struct MercadopagoWebhookResourceObject {
    #[serde(rename = "resource_id")]
    pub resource_id: String,
    pub topic: String,
    pub action: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MercadopagoWebhookData {
    pub id: String,
}

fn topic_to_action(topic: &str) -> MercadopagoWebhookAction {
    match topic {
        "payment" => MercadopagoWebhookAction::PaymentUpdated,
        "chargebacks" => MercadopagoWebhookAction::ChargebackUpdated,
        _ => MercadopagoWebhookAction::Unknown,
    }
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
        // NOTE: MercadoPago webhooks only contain the resource ID, not the actual status.
        // The action (e.g., "payment.updated") doesn't indicate whether the payment succeeded,
        // failed, or was cancelled. Therefore, we map to processing/pending states and rely
        // on the sync mechanism to fetch the actual status from MercadoPago's API.
        //
        // For refunds, since IncomingWebhookEvent doesn't have a RefundProcessing variant,
        // we map to EventNotSupported. Refund status is updated via periodic sync (RSync) calls.
        match action {
            MercadopagoWebhookAction::PaymentCreated
            | MercadopagoWebhookAction::PaymentUpdated => Self::PaymentIntentProcessing,
            MercadopagoWebhookAction::RefundCreated
            | MercadopagoWebhookAction::RefundUpdated => {
                // MercadoPago webhook payloads only contain the resource ID (no status).
                // Since there is no RefundProcessing event variant, refund status changes
                // are NOT tracked via webhooks. Refund state is updated exclusively through
                // periodic sync (RSync) calls. EventNotSupported causes this webhook to be
                // acknowledged and discarded without modifying refund state.
                Self::EventNotSupported
            }
            MercadopagoWebhookAction::ChargebackCreated
            | MercadopagoWebhookAction::ChargebackUpdated => Self::DisputeOpened,
            MercadopagoWebhookAction::Unknown => Self::EventNotSupported,
        }
    }
}
