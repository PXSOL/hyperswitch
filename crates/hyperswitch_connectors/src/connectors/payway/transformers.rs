use common_enums::enums;
use hyperswitch_domain_models::types;
use common_utils::pii::SecretSerdeValue;
use common_utils::types::{
    StringMinorUnit,
};
use hyperswitch_domain_models::{
    payment_method_data::PaymentMethodData,
    router_data::{ConnectorAuthType, RouterData},
    router_flow_types::{
        payments,
        refunds::{Execute, RSync},
    },
    router_request_types::ResponseId,
    router_response_types::{PaymentsResponseData, RefundsResponseData},
    types::{PaymentsAuthorizeRouterData, RefundsRouterData},
};
use hyperswitch_interfaces::errors;
use masking::{PeekInterface, Secret};
use serde::{Deserialize, Serialize};

use crate::{
    types::{RefundsResponseRouterData, ResponseRouterData},
    utils,
};
use crate::utils::RouterData as _;

//TODO: Fill the struct with respective fields
pub struct PaywayRouterData<T> {
    pub amount: StringMinorUnit, // The type of amount that a connector accepts, for example, String, i64, f64, etc.
    pub router_data: T,
}

impl<T> From<(StringMinorUnit, T)> for PaywayRouterData<T> {
    fn from((amount, item): (StringMinorUnit, T)) -> Self {
        //Todo :  use utils to convert the amount to the type of amount that a connector accepts
        Self {
            amount,
            router_data: item,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct PaywayPurchaseTotals {
    pub currency: String,
    pub amount: i64,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
pub struct PaywayBillTo {
    pub country: String,
    pub city: Option<String>,
    pub customer_id: Option<String>,
    pub email: Option<String>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub phone_number: Option<String>,
    pub postal_code: Option<String>,
    pub state: Option<String>,
    pub street1: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct PaywayServicesItem {
    pub code: String,
    pub description: String,
    pub name: String,
    pub sku: String,
    pub total_amount: i64,
    pub quantity: i32,
    pub unit_price: i64,
}

#[derive(Debug, Serialize)]
pub struct PaywayServicesTransactionData {
    pub service_type: String,
    pub items: Vec<PaywayServicesItem>,
}

#[derive(Debug, Serialize)]
pub struct PaywayCustomerInSite {
    pub days_in_site: i32,
    pub is_guest: bool,
    pub num_of_transactions: i32,
}

#[derive(Debug, Serialize)]
pub struct PaywayFraudDetectionAuth {
    pub channel: String,
    pub device_unique_identifier: String,
    pub purchase_totals: PaywayPurchaseTotals,
    pub bill_to: PaywayBillTo,
    pub customer_in_site: PaywayCustomerInSite,
    pub services_transaction_data: PaywayServicesTransactionData,
}

#[derive(Debug, Serialize)]
pub struct PaywayPaymentsRequest {
    pub site_transaction_id: String,
    pub token: String,
    pub payment_method_id: i32,
    pub bin: String,
    pub amount: i64,
    pub currency: String,
    pub description: Option<String>,
    pub payment_type: String,
    pub installments: i32,
    pub sub_payments: Vec<serde_json::Value>,
    pub fraud_detection: PaywayFraudDetectionAuth,
}

impl TryFrom<&PaywayRouterData<&PaymentsAuthorizeRouterData>> for PaywayPaymentsRequest {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(item: &PaywayRouterData<&PaymentsAuthorizeRouterData>) -> Result<Self, Self::Error> {
        let capture_method = item.router_data.request.capture_method.unwrap_or_default();
            match capture_method {
            enums::CaptureMethod::Automatic => {}
            enums::CaptureMethod::Manual => {}
            enums::CaptureMethod::Scheduled | enums::CaptureMethod::ManualMultiple | enums::CaptureMethod::SequentialAutomatic => {
                return Err(errors::ConnectorError::NotImplemented("Capture Method".to_string()).into());
            }
        }

        let meta = PaywayMetadataObject::try_from(&item.router_data.request.metadata)?;

        let bill_to_meta = meta
            .bill_to
            .as_ref()
            .ok_or(errors::ConnectorError::MissingRequiredField { field_name: "metadata.bill_to" })?;

        let bill_to = PaywayBillTo {
            country: "AR".to_string(),
            city: bill_to_meta.city.clone(),
            customer_id: bill_to_meta.customer_id.clone(),
            email: bill_to_meta.email.clone(),
            first_name: bill_to_meta.first_name.clone(),
            last_name: bill_to_meta.last_name.clone(),
            phone_number: bill_to_meta.phone_number.clone(),
            postal_code: bill_to_meta.postal_code.clone(),
            state: bill_to_meta.state.clone(),
            street1: bill_to_meta.street1.clone(),
        };

        let token = match item.router_data.get_payment_method_token()? {
            hyperswitch_domain_models::router_data::PaymentMethodToken::Token(t) => t.peek().to_string(),
            _ => return Err(errors::ConnectorError::MissingRequiredField { field_name: "payment_method_token" }.into()),
        };

        let amount = item.router_data.request.minor_amount.get_amount_as_i64();

        let installments = meta.installments.unwrap_or(1);

        let currency = item.router_data.request.currency.to_string();

        let bin = match &item.router_data.request.payment_method_data {
            PaymentMethodData::Card(card) => card.card_number.get_card_isin(),
            _ => {
                return Err(
                    errors::ConnectorError::MissingRequiredField {
                        field_name: "payment_method_data.card",
                    }
                    .into(),
                )
            }
        };

        let device_id = item.router_data.connector_request_reference_id.clone();

        let fraud_detection = PaywayFraudDetectionAuth {
            channel: "Web".to_string(),
            device_unique_identifier: device_id,
            purchase_totals: PaywayPurchaseTotals { currency: currency.clone(), amount: amount },
            bill_to,
            customer_in_site: PaywayCustomerInSite { days_in_site: 1, is_guest: true, num_of_transactions: 0 },
            services_transaction_data: PaywayServicesTransactionData {
                service_type: "payment".to_string(),
                items: vec![PaywayServicesItem {
                    code: "SERVICE".to_string(),
                    description: item.router_data.description.clone().unwrap_or_else(|| "Payment".to_string()),
                    name: "Payment service".to_string(),
                    sku: "SERVICE".to_string(),
                    total_amount: amount,
                    quantity: 1,
                    unit_price: amount,
                }],
            },
        };

        let transaction_id = item.router_data.connector_request_reference_id.clone();

        Ok(Self {
            site_transaction_id: transaction_id,
            token,
            payment_method_id: map_network_to_payway_id(&bin),
            bin,
            amount,
            currency,
            description: item.router_data.description.clone(),
            payment_type: "single".to_string(),
            installments,
            sub_payments: vec![],
            fraud_detection,
        })
    }
}

fn map_network_to_payway_id(bin: &str) -> i32 {
    if is_tarjeta_naranja(bin) {
        24
    } else if is_tarjeta_cencosud(bin) {
        43
    } else if is_tuya(bin) {
        59
    } else if is_amex(bin) {
        65
    } else if is_cabal(bin) {
        63
    } else if is_mastercard(bin) {
        104
    } else if is_discover(bin) {
        139
    } else if is_diners_club(bin) {
        8
    } else if is_maestro(bin) {
        105
    } else if is_visa(bin) {
        1
    } else {
        1
    }
}

fn is_discover(bin: &str) -> bool {
    if bin.len() >= 6 {
        let p6 = &bin[0..6];
        let p6_int: u32 = p6.parse().unwrap_or(0);

        let p4 = &bin[0..4];
        let _p4_int: u32 = p4.parse().unwrap_or(0);

        let p3 = &bin[0..3];
        let p3_int: u32 = p3.parse().unwrap_or(0);

        let p2 = &bin[0..2];
        let p2_int: u32 = p2.parse().unwrap_or(0);

        return p4 == "6011"
            || (622126..=622925).contains(&p6_int)
            || (644..=649).contains(&p3_int)
            || p2_int == 65;
    }
    false
}

fn is_diners_club(bin: &str) -> bool {
    if bin.len() < 3 {
        return false;
    }
    let p3: u32 = bin[0..3].parse().unwrap_or(0);
    let p2: u32 = bin[0..2].parse().unwrap_or(0);
    p3 >= 300 && p3 <= 305 || p2 == 36 || p2 == 38 || p2 == 39
}

fn is_visa(bin: &str) -> bool {
    bin.starts_with('4')
}

fn is_mastercard(bin: &str) -> bool {
    if bin.len() < 2 { return false; }
    let prefix2: u32 = bin[0..2].parse().unwrap_or(0);
    if (51..=55).contains(&prefix2) { return true; }
    if bin.len() >= 6 {
        let prefix6: u32 = bin[0..6].parse().unwrap_or(0);
        return (222100..=272099).contains(&prefix6);
    }
    false
}

fn is_amex(bin: &str) -> bool {
    bin.starts_with("34") || bin.starts_with("37")
}

fn is_maestro(bin: &str) -> bool {
    if bin.len() < 2 { return false; }
    let prefix2: u32 = bin[0..2].parse().unwrap_or(0);
    if prefix2 == 50 || (56..=58).contains(&prefix2) || (60..=69).contains(&prefix2) {
        // Avoid collision with Mastercard and Amex already filtered above
        return !is_mastercard(bin) && !is_amex(bin) && !is_visa(bin);
    }
    false
}

fn is_cabal(bin: &str) -> bool {
    // TODO: add more BINs of Cabal AR when available
    const KNOWN_CABAL_P6: &[&str] = &["589657", "604201"];
    const KNOWN_CABAL_P5: &[&str] = &["60420"]; // prefix
    if bin.len() >= 6 {
        let p6 = &bin[0..6];
        if KNOWN_CABAL_P6.contains(&p6) { return true; }
    }
    if bin.len() >= 5 {
        let p5 = &bin[0..5];
        if KNOWN_CABAL_P5.contains(&p5) { return true; }
    }
    false
}

fn is_tarjeta_naranja(bin: &str) -> bool {
    const KNOWN: &[&str] = &[
        "589562", "589244", "589262", "565333", "569562", // Naranja propios
        "402917", "402918", "404471", "414427"           // Visa Naranja
    ];
    if bin.len() >= 6 {
        let p6 = &bin[0..6];
        return KNOWN.contains(&p6);
    }
    false
}

fn is_tarjeta_cencosud(bin: &str) -> bool {
    const KNOWN: &[&str] = &[
        "905050", "905051", // private-label
        "510541", "559198", "559137", "557935", "523793" // MasterCard Cencosud
    ];
    if bin.len() >= 6 {
        let p6 = &bin[0..6];
        return KNOWN.contains(&p6);
    }
    false
}

fn is_tuya(bin: &str) -> bool {
    const KNOWN: &[&str] = &[
        "589657", // Tuya Argentina
        "603522", // also seen in BIN DB
        "555845"  // MasterCard Tuya
    ];
    if bin.len() >= 6 {
        let p6 = &bin[0..6];
        return KNOWN.contains(&p6);
    }
    false
}

// Auth Struct
pub struct PaywayAuthType {
    pub(super) public_key: Secret<String>,
    pub(super) secret_key: Secret<String>,
}

impl TryFrom<&ConnectorAuthType> for PaywayAuthType {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::BodyKey { api_key, key1 } => Ok(Self {
                public_key: api_key.to_owned(),
                secret_key: key1.to_owned(),
            }),
            _ => Err(errors::ConnectorError::FailedToObtainAuthType.into()),
        }
    }
}
// PaymentsResponse
//TODO: Append the remaining status flags
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum PaywayPaymentStatus {
    Succeeded,
    Failed,
    #[default]
    Processing,
}

impl From<PaywayPaymentStatus> for common_enums::AttemptStatus {
    fn from(item: PaywayPaymentStatus) -> Self {
        match item {
            PaywayPaymentStatus::Succeeded => Self::Charged,
            PaywayPaymentStatus::Failed => Self::Failure,
            PaywayPaymentStatus::Processing => Self::Authorizing,
        }
    }
}

//TODO: Fill the struct with respective fields
#[derive(Default, Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PaywayPaymentsResponse {
    status: PaywayPaymentStatus,
    id: String,
}

impl<F, T> TryFrom<ResponseRouterData<F, PaywayPaymentsResponse, T, PaymentsResponseData>>
    for RouterData<F, T, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: ResponseRouterData<F, PaywayPaymentsResponse, T, PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            status: common_enums::AttemptStatus::from(item.response.status),
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(item.response.id),
                redirection_data: Box::new(None),
                mandate_reference: Box::new(None),
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: None,
                incremental_authorization_allowed: None,
                charges: None,
            }),
            ..item.data
        })
    }
}

#[derive(Default, Debug, Serialize)]
pub struct PaywayRefundRequest {
    pub amount: i64,
}

impl<F> TryFrom<&PaywayRouterData<&RefundsRouterData<F>>> for PaywayRefundRequest {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(item: &PaywayRouterData<&RefundsRouterData<F>>) -> Result<Self, Self::Error> {
        let amount = item.router_data.request.minor_refund_amount.get_amount_as_i64();
        Ok(Self {
            amount,
        })
    }
}

// Type definition for Refund Response
#[allow(dead_code)]
#[derive(Debug, Copy, Serialize, Default, Deserialize, Clone)]
#[serde(rename_all = "lowercase")]
pub enum RefundStatus {
    #[serde(rename = "approved")]
    Succeeded,
    #[serde(rename = "rejected")]
    Failed,
    #[default]
    Processing,
}

impl From<RefundStatus> for enums::RefundStatus {
    fn from(item: RefundStatus) -> Self {
        match item {
            RefundStatus::Succeeded => Self::Success,
            RefundStatus::Failed => Self::Failure,
            RefundStatus::Processing => Self::Pending,
        }
    }
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct RefundResponse {
    id: i32,
    amount: i64,
    sub_payments: Option<Vec<serde_json::Value>>,
    error: Option<serde_json::Value>,
    status_details: Option<serde_json::Value>,
    status: RefundStatus,
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

//TODO: Fill the struct with respective fields
#[derive(Default, Debug, Serialize, Deserialize, PartialEq)]
pub struct PaywayErrorResponse {
    pub status_code: u16,
    pub code: String,
    pub message: String,
    pub reason: Option<String>,
    pub network_advice_code: Option<String>,
    pub network_decline_code: Option<String>,
    pub network_error_message: Option<String>,
}

// Tokenization request
#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct PaywayTokenRequest {
    card_number: cards::CardNumber,
    card_expiration_month: Secret<String>,
    card_expiration_year: Secret<String>,
    card_holder_name: Secret<String>,
    security_code: Secret<String>,
    #[serde(default)]
    card_holder_identification: Vec<serde_json::Value>,
    fraud_detection: FraudDetection,
}

#[derive(Debug, Serialize)]
pub struct FraudDetection {
    device_unique_identifier: String,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct PaywayMetadataObject {
    pub token: Option<String>,
    pub installments: Option<i32>,
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    pub bill_to: Option<PaywayBillTo>,
}

impl TryFrom<&Option<SecretSerdeValue>> for PaywayMetadataObject {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        meta_data: &Option<SecretSerdeValue>,
    ) -> Result<Self, Self::Error> {
        match meta_data {
            Some(metadata) => Ok(utils::to_connector_meta_from_secret::<Self>(Some(metadata.clone()))
                .map_err(|_e| errors::ConnectorError::InvalidConnectorConfig { config: "metadata" })?),
            None => Ok(Self::default()),
        }
    }
}

impl TryFrom<&Option<serde_json::Value>> for PaywayMetadataObject {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(meta_data: &Option<serde_json::Value>) -> Result<Self, Self::Error> {
        let secret_meta: Option<SecretSerdeValue> = meta_data.as_ref().map(|v| Secret::new(v.clone()));
        let metadata = utils::to_connector_meta_from_secret::<Self>(secret_meta)
            .map_err(|_e| errors::ConnectorError::InvalidConnectorConfig { config: "metadata" })?;
        Ok(metadata)
    }
}

impl TryFrom<&types::TokenizationRouterData> for PaywayTokenRequest {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(item: &types::TokenizationRouterData) -> Result<Self, Self::Error> {
        let device_id = item.connector_request_reference_id.clone();

        match item.request.payment_method_data.clone() {
            PaymentMethodData::Card(card) => Ok(Self {
                card_number: card.card_number.clone(),
                card_expiration_month: card.card_exp_month.clone(),
                card_expiration_year: card.card_exp_year.clone(),
                card_holder_name: card.card_holder_name.clone().unwrap_or_else(|| Secret::new("".to_string())),
                security_code: card.card_cvc,
                card_holder_identification: vec![],
                fraud_detection: FraudDetection {
                    device_unique_identifier: device_id,
                },
            }),
            _ => Err(errors::ConnectorError::NotImplemented("Payment method".to_string()).into()),
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PaywayTokenResponse {
    pub id: Secret<String>,
    status: String,
}

impl<T> TryFrom<ResponseRouterData<payments::PaymentMethodToken, PaywayTokenResponse, T, PaymentsResponseData>> for RouterData<payments::PaymentMethodToken, T, PaymentsResponseData> {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(item: ResponseRouterData<payments::PaymentMethodToken, PaywayTokenResponse, T, PaymentsResponseData>) -> Result<Self, Self::Error> {
        Ok(Self {
            response: Ok(PaymentsResponseData::TokenizationResponse { token: item.response.id.peek().to_string() }),
            ..item.data
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PaywayAuthorizeResponse {
    pub id: serde_json::Value,
    pub site_transaction_id: Option<String>,
    pub payment_method_id: Option<i32>,
    pub amount: Option<i64>,
    pub currency: Option<String>,
    pub status: Option<String>,
}

impl<F, T> TryFrom<ResponseRouterData<F, PaywayAuthorizeResponse, T, PaymentsResponseData>>
    for RouterData<F, T, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(item: ResponseRouterData<F, PaywayAuthorizeResponse, T, PaymentsResponseData>) -> Result<Self, Self::Error> {
        let status = match item.response.status.as_deref() {
            Some("approved") => common_enums::AttemptStatus::Charged,
            Some(_) => common_enums::AttemptStatus::Failure,
            None => common_enums::AttemptStatus::Failure,
        };
        Ok(Self {
            status,
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(item.response.id.to_string()),
                redirection_data: Box::new(None),
                mandate_reference: Box::new(None),
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: item.response.site_transaction_id.clone(),
                incremental_authorization_allowed: None,
                charges: None,
            }),
            ..item.data
        })
    }
}
