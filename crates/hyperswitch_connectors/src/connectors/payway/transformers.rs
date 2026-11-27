use common_enums::enums;
use common_utils::{
    pii::SecretSerdeValue,
    types::{MinorUnit, StringMinorUnit},
};
use hyperswitch_domain_models::{
    payment_method_data::PaymentMethodData,
    router_data::{
        AdditionalPaymentMethodConnectorResponse, ConnectorAuthType, ConnectorReportedActivity,
        ConnectorReportedRefund, ConnectorResponseData, ErrorResponse, RouterData,
    },
    router_flow_types::{
        payments,
        refunds::{Execute, RSync},
    },
    router_request_types::ResponseId,
    router_response_types::{PaymentsResponseData, RefundsResponseData},
    types,
    types::{PaymentsAuthorizeRouterData, RefundsRouterData},
};
use hyperswitch_interfaces::{consts, errors};
use hyperswitch_masking::{PeekInterface, Secret};
use serde::{Deserialize, Serialize};

use crate::{
    types::{RefundsResponseRouterData, ResponseRouterData},
    utils,
    utils::{CardData as _, RouterData as _},
};

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
pub struct PaywayShipTo {
    pub country: String,
    pub city: Option<String>,
    pub email: Option<String>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub phone_number: Option<String>,
    pub postal_code: Option<String>,
    pub state: Option<String>,
    pub street1: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct PaywayRetailTransactionData {
    pub ship_to: PaywayShipTo,
    pub items: Vec<PaywayServicesItem>,
}

#[derive(Debug, Serialize)]
pub struct PaywayCustomerInSite {
    pub days_in_site: i32,
    pub is_guest: bool,
    pub num_of_transactions: i32,
}

impl PaywayCustomerInSite {
    /// The guest history from `metadata.customer_in_site`; each value missing or unusable
    /// keeps the constant every charge sent before (1 day, guest, no transactions).
    fn from_metadata(metadata: Option<&PaywayCustomerInSiteMetadata>) -> Self {
        let count = |value: Option<i64>| {
            value
                .filter(|value| *value >= 0)
                .and_then(|value| i32::try_from(value).ok())
        };
        Self {
            days_in_site: count(metadata.and_then(|metadata| metadata.days_in_site)).unwrap_or(1),
            is_guest: metadata
                .and_then(|metadata| metadata.is_guest)
                .unwrap_or(true),
            num_of_transactions: count(metadata.and_then(|metadata| metadata.num_of_transactions))
                .unwrap_or(0),
        }
    }
}

/// Top-level `customer` of `POST /payments`. Sent only with CyberSource (`send_to_cs`).
#[derive(Debug, Serialize)]
pub struct PaywayCustomer {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<Secret<String>>,
    /// The guest's IP, from the authorize request's `browser_info`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip_address: Option<Secret<String>>,
}

#[derive(Debug, Serialize)]
pub struct PaywayFraudDetectionAuth {
    pub channel: String,
    pub send_to_cs: bool,
    pub device_unique_identifier: String,
    pub purchase_totals: PaywayPurchaseTotals,
    pub bill_to: PaywayBillTo,
    pub customer_in_site: PaywayCustomerInSite,
    pub services_transaction_data: PaywayServicesTransactionData,
    pub retail_transaction_data: PaywayRetailTransactionData,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub customer: Option<PaywayCustomer>,
    pub fraud_detection: PaywayFraudDetectionAuth,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub establishment_name: Option<String>,
}

/// Maximum length of Payway's `establishment_name` (SDK guide: alphanumeric, 25 chars).
const PAYWAY_ESTABLISHMENT_NAME_MAX_LEN: usize = 25;

/// Returns the name only if Payway accepts it as is (trimmed, non-empty, at most 25
/// characters, ASCII letters, digits and spaces). It omits instead of altering the value,
/// so a rejected name can never block a charge.
fn valid_establishment_name(statement_descriptor: Option<&str>) -> Option<String> {
    let name = statement_descriptor?.trim();
    let is_valid = !name.is_empty()
        && name.chars().count() <= PAYWAY_ESTABLISHMENT_NAME_MAX_LEN
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == ' ');
    is_valid.then(|| name.to_string())
}

/// `service_type` and item `name` of a charge sent through CyberSource (`send_to_cs`): the
/// values of the charge CyberSource approved in production (2026-11-27). Without CyberSource
/// the charge keeps "payment" and "Payment service".
const CYBERSOURCE_SERVICE: &str = "Alojamiento";

/// Country sent in `bill_to` and `ship_to` when the payer's is not usable (and for every
/// charge before the payer's country was read).
const PAYWAY_DEFAULT_COUNTRY: &str = "AR";

/// The payer's country (`metadata.country`) as Payway takes it: an ISO 3166-1 alpha-2 code,
/// uppercased. A name, a numeric or three-letter code, a blank or an unknown code keeps
/// `PAYWAY_DEFAULT_COUNTRY`, so a bad value can never block a charge.
fn payway_country(country: &str) -> String {
    Some(country.trim())
        .filter(|code| code.len() == 2 && code.chars().all(|c| c.is_ascii_alphabetic()))
        .and_then(|code| {
            code.to_ascii_uppercase()
                .parse::<enums::CountryAlpha2>()
                .ok()
        })
        .map(|country| country.to_string())
        .unwrap_or_else(|| PAYWAY_DEFAULT_COUNTRY.to_string())
}

impl TryFrom<&PaywayRouterData<&PaymentsAuthorizeRouterData>> for PaywayPaymentsRequest {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: &PaywayRouterData<&PaymentsAuthorizeRouterData>,
    ) -> Result<Self, Self::Error> {
        let capture_method = item.router_data.request.capture_method.unwrap_or_default();
        match capture_method {
            enums::CaptureMethod::Automatic => {}
            enums::CaptureMethod::Manual => {}
            enums::CaptureMethod::Scheduled
            | enums::CaptureMethod::ManualMultiple
            | enums::CaptureMethod::SequentialAutomatic => {
                return Err(
                    errors::ConnectorError::NotImplemented("Capture Method".to_string()).into(),
                );
            }
        }

        let meta = PaywayMetadataObject::resolve(item.router_data.request.metadata.as_ref())?;

        let bill_to_meta =
            meta.bill_to
                .as_ref()
                .ok_or(errors::ConnectorError::MissingRequiredField {
                    field_name: "metadata.bill_to".into(),
                })?;

        let reference_id = item.router_data.connector_request_reference_id.clone();

        let reference_customer_id = if let Some(stripped) = reference_id.strip_prefix("pay_") {
            format!("customer_{}", stripped)
        } else {
            reference_id.clone()
        };

        // CyberSource only with `send_to_cs`. Without it every value below is the one each
        // charge sent before, so the request is unchanged; with it, a missing value keeps it.
        let send_to_cs = meta.send_to_cs.unwrap_or(false);
        let (customer_id, device_id, customer_in_site) = if send_to_cs {
            (
                bill_to_meta
                    .customer_id
                    .as_deref()
                    .map(str::trim)
                    .filter(|customer_id| !customer_id.is_empty())
                    .map(str::to_string)
                    .unwrap_or(reference_customer_id),
                meta.device_id.clone().unwrap_or(reference_id),
                PaywayCustomerInSite::from_metadata(meta.customer_in_site.as_ref()),
            )
        } else {
            (
                reference_customer_id,
                reference_id,
                PaywayCustomerInSite::from_metadata(None),
            )
        };
        let customer = send_to_cs.then(|| PaywayCustomer {
            id: customer_id.clone(),
            email: bill_to_meta.email.clone().map(Secret::new),
            ip_address: item
                .router_data
                .request
                .browser_info
                .as_ref()
                .and_then(|browser_info| browser_info.ip_address)
                .map(|ip_address| Secret::new(ip_address.to_string())),
        });

        let country = payway_country(&bill_to_meta.country);

        let bill_to = PaywayBillTo {
            country: country.clone(),
            city: bill_to_meta.city.clone(),
            customer_id: Some(customer_id),
            email: bill_to_meta.email.clone(),
            first_name: bill_to_meta.first_name.clone(),
            last_name: bill_to_meta.last_name.clone(),
            phone_number: bill_to_meta.phone_number.clone(),
            postal_code: bill_to_meta.postal_code.clone(),
            state: bill_to_meta.state.clone(),
            street1: bill_to_meta.street1.clone(),
        };

        let token = match item.router_data.get_payment_method_token()? {
            hyperswitch_domain_models::router_data::PaymentMethodToken::Token(t) => {
                t.peek().to_string()
            }
            _ => {
                return Err(errors::ConnectorError::MissingRequiredField {
                    field_name: "payment_method_token".into(),
                }
                .into())
            }
        };

        let amount = item.router_data.request.minor_amount.get_amount_as_i64();

        let installments = meta.installments.unwrap_or(1);

        let currency = item.router_data.request.currency.to_string();

        let bin = match &item.router_data.request.payment_method_data {
            PaymentMethodData::Card(card) => card.card_number.get_card_isin(),
            _ => {
                return Err(errors::ConnectorError::MissingRequiredField {
                    field_name: "payment_method_data.card".into(),
                }
                .into())
            }
        };

        let ship_to = PaywayShipTo {
            country,
            city: bill_to_meta.city.clone(),
            email: bill_to_meta.email.clone(),
            first_name: bill_to_meta.first_name.clone(),
            last_name: bill_to_meta.last_name.clone(),
            phone_number: bill_to_meta.phone_number.clone(),
            postal_code: bill_to_meta.postal_code.clone(),
            state: bill_to_meta.state.clone(),
            street1: bill_to_meta.street1.clone(),
        };

        let (service_type, service_name) = if send_to_cs {
            (CYBERSOURCE_SERVICE, CYBERSOURCE_SERVICE)
        } else {
            ("payment", "Payment service")
        };

        let fraud_detection = PaywayFraudDetectionAuth {
            channel: "Web".to_string(),
            send_to_cs,
            device_unique_identifier: device_id,
            purchase_totals: PaywayPurchaseTotals {
                currency: currency.clone(),
                amount,
            },
            bill_to,
            customer_in_site,
            services_transaction_data: PaywayServicesTransactionData {
                service_type: service_type.to_string(),
                items: vec![PaywayServicesItem {
                    code: "SERVICE".to_string(),
                    description: item
                        .router_data
                        .description
                        .clone()
                        .unwrap_or_else(|| "Payment".to_string()),
                    name: service_name.to_string(),
                    sku: "SERVICE".to_string(),
                    total_amount: amount,
                    quantity: 1,
                    unit_price: amount,
                }],
            },
            retail_transaction_data: PaywayRetailTransactionData {
                ship_to,
                items: vec![PaywayServicesItem {
                    code: "SERVICE".to_string(),
                    description: item
                        .router_data
                        .description
                        .clone()
                        .unwrap_or_else(|| "Payment".to_string()),
                    name: service_name.to_string(),
                    sku: "SERVICE".to_string(),
                    total_amount: amount,
                    quantity: 1,
                    unit_price: amount,
                }],
            },
        };

        let transaction_id = item.router_data.connector_request_reference_id.clone();

        let payment_method_id =
            meta.payment_method_id
                .ok_or(errors::ConnectorError::MissingRequiredField {
                    field_name: "metadata.payment_method_id".into(),
                })?;

        Ok(Self {
            site_transaction_id: transaction_id,
            token,
            payment_method_id,
            bin,
            amount,
            currency,
            description: item.router_data.description.clone(),
            payment_type: "single".to_string(),
            installments,
            sub_payments: vec![],
            customer,
            fraud_detection,
            establishment_name: valid_establishment_name(
                item.router_data
                    .request
                    .billing_descriptor
                    .as_ref()
                    .and_then(|descriptor| descriptor.statement_descriptor.as_deref()),
            ),
        })
    }
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
// Payment status, as reported by `GET /payments/{id}` (and the authorize response).
//
// The OpenAPI document lists lowercase statuses (approved, rejected, pre_approved, pending,
// cancelled, refunded) while the functional documentation names the states in upper case
// (PROCESS, PREAPPROVED, APPROVED, ACCREDITED, ANNULLED, ANNULMENT_APPROVED, REFUNDED,
// REFUNDED_APPROVED, APPROVED_WITH_REFUND, REJECTED, REVIEW). The real casing has not been
// verified live, so both vocabularies are accepted, case-insensitively.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaywayStatus {
    Approved,
    PreApproved,
    Pending,
    Rejected,
    /// Voided before settlement (annulment) or cancelled.
    Annulled,
    /// Fully refunded after settlement.
    Refunded,
    /// Partially refunded; the API does not say how much.
    PartiallyRefunded,
    Unknown,
}

impl PaywayStatus {
    pub fn parse(status: Option<&str>) -> Self {
        let normalized = status
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase()
            .replace(['-', ' '], "_");
        match normalized.as_str() {
            "approved" | "accredited" => Self::Approved,
            "pre_approved" | "preapproved" => Self::PreApproved,
            "pending" | "process" | "processing" | "review" => Self::Pending,
            "rejected" => Self::Rejected,
            "annulled" | "annulment_approved" | "cancelled" | "canceled" => Self::Annulled,
            "refunded" | "refunded_approved" => Self::Refunded,
            "approved_with_refund" => Self::PartiallyRefunded,
            _ => Self::Unknown,
        }
    }

    /// Attempt status of an attempt that is NOT settled yet.
    ///
    /// Consistent with the authorize mapping (approved is Charged, a rejection is a
    /// failure). A refunded payment, total or partial, maps to `Charged`: the money was
    /// taken and the refund is reported separately. An unknown status keeps the current one.
    fn attempt_status(self, current: enums::AttemptStatus) -> enums::AttemptStatus {
        match self {
            Self::Approved | Self::Refunded | Self::PartiallyRefunded => {
                enums::AttemptStatus::Charged
            }
            Self::PreApproved => enums::AttemptStatus::Authorized,
            Self::Pending => enums::AttemptStatus::Pending,
            Self::Rejected => enums::AttemptStatus::Failure,
            Self::Annulled => enums::AttemptStatus::Voided,
            Self::Unknown => current,
        }
    }
}

/// `GET /payments/{payment_id}`. Everything is optional and unknown fields and statuses are
/// tolerated: a payment sync must never fail to parse because of a field it does not use.
///
/// Only what the sync uses is typed. `status_details` also carries issuer data (authorization
/// code, ticket, address validation) that must not reach the logs or the connector events.
/// The authorization code and the ticket are kept because they are stored as receipt data; they
/// are typed as `Secret` for that reason, so `Debug` prints them masked and the connector event
/// (`set_response_body`, which serializes through `masked_serialize`) masks them. The address
/// validation code is not kept.
#[derive(Default, Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct PaywayPaymentsResponse {
    /// Integer in the API, which is what the authorize response stored as the
    /// `connector_transaction_id`.
    id: serde_json::Value,
    site_transaction_id: Option<String>,
    status: Option<String>,
    #[serde(deserialize_with = "lenient")]
    status_details: Option<PaywayStatusDetails>,
    #[serde(deserialize_with = "lenient_amount")]
    amount: Option<i64>,
    currency: Option<String>,
    #[serde(deserialize_with = "lenient")]
    fraud_detection: Option<PaywayFraudDetectionResult>,
}

/// `fraud_detection` of a payment response: the CyberSource result of a charge sent with
/// `send_to_cs`.
#[derive(Default, Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct PaywayFraudDetectionResult {
    #[serde(deserialize_with = "lenient")]
    status: Option<PaywayCyberSourceStatus>,
}

/// `fraud_detection.status`. Payway's CyberSource reason codes: 100 accept (green), 480 review
/// (yellow), 481, 101, 102, 202 and 231 reject (red), 150 to 153 CyberSource unavailable
/// (blue), 10XXX data missing or invalid (black).
#[derive(Default, Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct PaywayCyberSourceStatus {
    #[serde(deserialize_with = "lenient_text")]
    decision: Option<String>,
    #[serde(deserialize_with = "lenient_text")]
    request_id: Option<String>,
    #[serde(deserialize_with = "lenient_amount")]
    reason_code: Option<i64>,
    #[serde(deserialize_with = "lenient_text")]
    description: Option<String>,
    #[serde(deserialize_with = "lenient")]
    details: Option<PaywayCyberSourceDetails>,
}

#[derive(Default, Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct PaywayCyberSourceDetails {
    #[serde(deserialize_with = "lenient")]
    validation_errors: Option<Vec<serde_json::Value>>,
}

/// `status_details.error.type` of a charge CyberSource rejected.
const CYBERSOURCE_ERROR_TYPE: &str = "cybersource_error";
/// Prefix of the error code of a charge CyberSource rejected (`CS_<reason code>`).
pub const CYBERSOURCE_CODE_PREFIX: &str = "CS_";
/// CyberSource's review reason code (decision yellow).
const CYBERSOURCE_REVIEW_REASON_CODE: i64 = 480;

impl PaywayFraudDetectionResult {
    /// The CyberSource result, when Payway reported a decision or a reason code.
    fn cybersource(&self) -> Option<&PaywayCyberSourceStatus> {
        self.status
            .as_ref()
            .filter(|status| status.decision.is_some() || status.reason_code.is_some())
    }
}

impl PaywayCyberSourceStatus {
    fn decision(&self) -> Option<String> {
        self.decision.as_deref().map(str::to_ascii_lowercase)
    }

    /// Decision Manager sent the charge to manual review.
    fn is_review(&self) -> bool {
        self.decision().as_deref() == Some("yellow")
            || self.reason_code == Some(CYBERSOURCE_REVIEW_REASON_CODE)
    }

    /// What the caller stores: `{"cybersource": {decision, reason_code, request_id}}`.
    fn result(&self) -> serde_json::Value {
        serde_json::json!({
            "cybersource": {
                "decision": self.decision(),
                "reason_code": self.reason_code,
                "request_id": self.request_id,
            }
        })
    }

    /// `CyberSource <decision>: <description>: <validation params>`, leaving out what Payway
    /// did not send.
    fn message(&self) -> String {
        let params: Vec<&str> = self
            .details
            .as_ref()
            .and_then(|details| details.validation_errors.as_ref())
            .into_iter()
            .flatten()
            .filter_map(|error| error.get("param").and_then(serde_json::Value::as_str))
            .map(str::trim)
            .filter(|param| !param.is_empty())
            .collect();
        let mut parts = vec![match self.decision() {
            Some(decision) => format!("CyberSource {decision}"),
            None => "CyberSource".to_string(),
        }];
        parts.extend(self.description.clone());
        if !params.is_empty() {
            parts.push(params.join("; "));
        }
        parts.join(": ")
    }
}

/// The CyberSource result in `payment_checks`, where the payment response shows it as
/// `payment_method_data.card.payment_checks`.
fn cybersource_payment_checks(
    result: serde_json::Value,
) -> AdditionalPaymentMethodConnectorResponse {
    AdditionalPaymentMethodConnectorResponse::Card {
        authentication_data: None,
        payment_checks: Some(result),
        card_network: None,
        domestic_network: None,
        auth_code: None,
        processor_card_network: None,
        card_subtype: None,
        card_segment_type: None,
        funding_source: None,
        card_type: None,
        issuer_name: None,
        issuer_country: None,
    }
}

/// Attaches the CyberSource result of a response, if any, to the router data.
fn attach_cybersource_result<F, T>(
    router_data: &mut RouterData<F, T, PaymentsResponseData>,
    cybersource: Option<&PaywayCyberSourceStatus>,
) {
    let Some(checks) =
        cybersource.map(|cybersource| cybersource_payment_checks(cybersource.result()))
    else {
        return;
    };
    match router_data.connector_response.as_mut() {
        Some(connector_response) => {
            connector_response.additional_payment_method_data = Some(checks);
        }
        None => {
            router_data.connector_response = Some(
                ConnectorResponseData::with_additional_payment_method_data(checks),
            );
        }
    }
}

#[derive(Default, Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct PaywayStatusDetails {
    #[serde(deserialize_with = "lenient")]
    error: Option<PaywayStatusError>,
    /// Authorization code returned by the card issuer.
    #[serde(deserialize_with = "lenient_secret_text")]
    card_authorization_code: Option<Secret<String>>,
    /// Ticket of the payment at the acquirer.
    #[serde(deserialize_with = "lenient_secret_text")]
    ticket: Option<Secret<String>>,
}

impl PaywayStatusDetails {
    /// Receipt data as connector metadata, `None` when Payway returned neither value.
    fn receipt_metadata(&self) -> Option<serde_json::Value> {
        utils::merge_receipt_into_metadata(
            None,
            Some(utils::ReceiptMetadata {
                authorization_code: self
                    .card_authorization_code
                    .as_ref()
                    .map(|code| code.peek().clone()),
                ticket_number: self.ticket.as_ref().map(|ticket| ticket.peek().clone()),
                reference_number: None,
            }),
        )
    }
}

#[derive(Default, Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct PaywayStatusError {
    #[serde(rename = "type")]
    error_type: Option<String>,
    #[serde(deserialize_with = "lenient")]
    reason: Option<PaywayErrorReason>,
}

#[derive(Default, Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct PaywayErrorReason {
    #[serde(deserialize_with = "lenient_amount")]
    id: Option<i64>,
    description: Option<String>,
}

/// Deserializes `T`, or `None` when the value is null or has a shape `T` does not accept, so a
/// field the sync only reads for a message can never fail the whole response.
fn lenient<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::de::DeserializeOwned,
{
    let value = Option::<serde_json::Value>::deserialize(deserializer)?;
    Ok(value.and_then(|value| serde_json::from_value(value).ok()))
}

/// Text, or a number rendered as text, kept as a `Secret`; anything else (including blank text)
/// is `None`, so a bad type never fails the whole response.
fn lenient_secret_text<'de, D>(deserializer: D) -> Result<Option<Secret<String>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = Option::<serde_json::Value>::deserialize(deserializer)?;
    Ok(match value {
        Some(serde_json::Value::String(text)) => Some(text.trim().to_owned()),
        Some(serde_json::Value::Number(number)) => Some(number.to_string()),
        _ => None,
    }
    .filter(|text| !text.is_empty())
    .map(Secret::new))
}

/// Trimmed non-blank text, or a number rendered as text; anything else is `None`.
fn lenient_text<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(lenient_secret_text(deserializer)?.map(|text| text.peek().clone()))
}

/// Trimmed non-blank text; anything else (a number included) is `None`.
fn lenient_string<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = Option::<serde_json::Value>::deserialize(deserializer)?;
    Ok(match value {
        Some(serde_json::Value::String(text)) => Some(text.trim().to_owned()),
        _ => None,
    }
    .filter(|text| !text.is_empty()))
}

/// A boolean, or the text `true` / `false` (any case, trimmed); anything else is `None`.
fn lenient_flag<'de, D>(deserializer: D) -> Result<Option<bool>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = Option::<serde_json::Value>::deserialize(deserializer)?;
    Ok(match value {
        Some(serde_json::Value::Bool(flag)) => Some(flag),
        Some(serde_json::Value::String(text)) => match text.trim().to_ascii_lowercase().as_str() {
            "true" => Some(true),
            "false" => Some(false),
            _ => None,
        },
        _ => None,
    })
}

/// Integer, float (rounded to the nearest unit) or numeric string; anything else is `None`.
// The only `as` casts are on a float that was checked to be finite and inside the `i64` range.
#[allow(clippy::as_conversions)]
fn lenient_amount<'de, D>(deserializer: D) -> Result<Option<i64>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = Option::<serde_json::Value>::deserialize(deserializer)?;
    let float_to_integer = |float: f64| {
        (float.is_finite() && float.abs() < i64::MAX as f64).then(|| float.round() as i64)
    };
    Ok(match value {
        Some(serde_json::Value::Number(number)) => number
            .as_i64()
            .or_else(|| number.as_f64().and_then(float_to_integer)),
        Some(serde_json::Value::String(text)) => {
            let text = text.trim();
            text.parse::<i64>()
                .ok()
                .or_else(|| text.parse::<f64>().ok().and_then(float_to_integer))
        }
        _ => None,
    })
}

/// Prefix of the error code of a declined payment (`PD_<reason id>`), shared by the declined
/// authorize (402) and the rejected payment sync.
pub const DECLINED_CODE_PREFIX: &str = "PD_";
/// `reason` of the error of a declined payment.
pub const DECLINED_REASON: &str = "payment_declined";

/// Error code of a declined payment: `PD_<reason id>`, or the standard "no error code" when
/// Payway gave no reason id.
pub fn declined_error_code(reason_id: Option<&str>) -> String {
    match reason_id.filter(|id| !id.is_empty()) {
        Some(id) => format!("{DECLINED_CODE_PREFIX}{id}"),
        None => consts::NO_ERROR_CODE.to_string(),
    }
}

/// Prefix of the id of the refund that stands for an annulled payment.
const ANNULMENT_REFUND_ID_PREFIX: &str = "annulment_";
/// Prefix of the id of the refund that stands for a fully refunded payment.
const REFUND_REFUND_ID_PREFIX: &str = "refund_";
/// Prefix of the id of the refund that stands for a cumulative partial refund; the cumulative
/// refunded amount (minor units) is appended, so every new total gets its own id.
const PARTIAL_REFUND_ID_PREFIX: &str = "partial_";

pub fn is_settled_attempt(status: enums::AttemptStatus) -> bool {
    matches!(
        status,
        enums::AttemptStatus::Charged | enums::AttemptStatus::PartialCharged
    )
}

impl PaywayPaymentsResponse {
    fn payment_id(&self) -> Option<String> {
        match &self.id {
            serde_json::Value::Number(number) => Some(number.to_string()),
            serde_json::Value::String(id) if !id.trim().is_empty() => Some(id.trim().to_string()),
            _ => None,
        }
    }

    /// Receipt data (authorization code and ticket) as connector metadata.
    pub(super) fn receipt_metadata(&self) -> Option<serde_json::Value> {
        self.status_details
            .as_ref()
            .and_then(PaywayStatusDetails::receipt_metadata)
    }

    pub fn payway_status(&self) -> PaywayStatus {
        PaywayStatus::parse(self.status.as_deref())
    }

    /// The CyberSource result of the payment, if it went through CyberSource.
    fn cybersource(&self) -> Option<&PaywayCyberSourceStatus> {
        self.fraud_detection
            .as_ref()
            .and_then(PaywayFraudDetectionResult::cybersource)
    }

    /// Error of a payment CyberSource rejected (`status_details.error.type` is
    /// `cybersource_error`): code `CS_<reason code>`, the decision, description and validation
    /// params as the message, and the CyberSource result as the issuer message (there is no
    /// issuer, so no network decline code). `None` for any other error, or when Payway gave
    /// no reason code, which keeps the error of a declined payment.
    pub fn cybersource_error(&self, http_code: u16) -> Option<ErrorResponse> {
        let error_type = self
            .status_details
            .as_ref()?
            .error
            .as_ref()?
            .error_type
            .as_deref()?;
        if !error_type
            .trim()
            .eq_ignore_ascii_case(CYBERSOURCE_ERROR_TYPE)
        {
            return None;
        }
        let cybersource = self.cybersource()?;
        let reason_code = cybersource.reason_code?;
        Some(ErrorResponse {
            status_code: http_code,
            code: format!("{CYBERSOURCE_CODE_PREFIX}{reason_code}"),
            message: cybersource.message(),
            reason: Some(DECLINED_REASON.to_string()),
            attempt_status: Some(enums::AttemptStatus::Failure),
            connector_transaction_id: self.payment_id(),
            network_advice_code: None,
            network_decline_code: None,
            network_error_message: Some(cybersource.result().to_string()),
            connector_metadata: None,
            connector_response_reference_id: None,
        })
    }

    /// Error of a rejected payment, built like the one of a declined authorize (402).
    pub(super) fn rejection(&self, http_code: u16) -> ErrorResponse {
        if let Some(error) = self.cybersource_error(http_code) {
            return error;
        }
        let error = self
            .status_details
            .as_ref()
            .and_then(|details| details.error.as_ref());
        let error_type = error
            .and_then(|error| error.error_type.as_deref())
            .unwrap_or("payment_error");
        let reason = error.and_then(|error| error.reason.as_ref());
        let reason_id = reason.and_then(|reason| reason.id).map(|id| id.to_string());
        let reason_description = reason
            .and_then(|reason| reason.description.clone())
            .unwrap_or_default();
        let message = if reason_description.is_empty() {
            error_type.to_string()
        } else {
            format!("{error_type}: {reason_description}")
        };
        ErrorResponse {
            status_code: http_code,
            code: declined_error_code(reason_id.as_deref()),
            message: message.clone(),
            reason: Some(DECLINED_REASON.to_string()),
            attempt_status: Some(enums::AttemptStatus::Failure),
            connector_transaction_id: self.payment_id(),
            network_advice_code: None,
            network_decline_code: reason_id,
            network_error_message: Some(if reason_description.is_empty() {
                message
            } else {
                reason_description
            }),
            connector_metadata: None,
            connector_response_reference_id: None,
        }
    }

    /// Refund the sync reports when the payment was annulled or refunded outside Hyperswitch
    /// (Payway panel).
    ///
    /// It depends on the status the sync RESULTS in (`resulting_status`), not on the one the
    /// attempt had before: an attempt that was not settled yet but this sync moves to `Charged`
    /// (a refunded payment maps to `Charged`) reports its refund right away, while an annulled
    /// payment of a non-settled attempt becomes `Voided` and reports nothing.
    ///
    /// - Annulled or refunded in full: Payway exposes neither a refund id nor an amount, so the
    ///   refund is a "balance" one: its amount is computed by the reconciliation (the refundable
    ///   total minus the refunds Hyperswitch already has) and `amount` here is only the payment
    ///   amount for reference, ignored because of `amount_is_remaining_balance`. The id is
    ///   deterministic per payment and kind, which makes repeated syncs idempotent.
    /// - Partially refunded: before the batch close Payway keeps the status `approved` and only
    ///   lowers `amount` (it never returns `approved_with_refund` then). When the reported
    ///   `amount` is lower than `original_amount` (the amount of the attempt, minor units, same
    ///   unit as Payway's), the difference is the TOTAL refunded so far and is reported as one
    ///   cumulative refund (`amount_is_cumulative_total`) whose id carries that total, so the
    ///   reconciliation records only what Hyperswitch does not hold yet. Without a usable lower
    ///   amount a `approved_with_refund` is logged and not reported.
    pub fn reported_activity(
        &self,
        resulting_status: enums::AttemptStatus,
        original_amount: Option<MinorUnit>,
    ) -> Option<ConnectorReportedActivity> {
        if !is_settled_attempt(resulting_status) {
            return None;
        }
        let payment_id = self.payment_id();
        let status = self.payway_status();
        let prefix = match status {
            PaywayStatus::Annulled => ANNULMENT_REFUND_ID_PREFIX,
            PaywayStatus::Refunded => REFUND_REFUND_ID_PREFIX,
            PaywayStatus::Approved | PaywayStatus::PartiallyRefunded => {
                let refunded_total = original_amount
                    .map(MinorUnit::get_amount_as_i64)
                    .zip(self.amount)
                    .filter(|(original, current)| *current >= 0 && current < original)
                    .map(|(original, current)| original - current);
                return match (refunded_total, payment_id) {
                    (Some(refunded_total), Some(payment_id)) => Some(ConnectorReportedActivity {
                        refunds: vec![ConnectorReportedRefund {
                            connector_refund_id: format!(
                                "{PARTIAL_REFUND_ID_PREFIX}{payment_id}_{refunded_total}"
                            ),
                            amount: MinorUnit::new(refunded_total),
                            status: enums::RefundStatus::Success,
                            amount_is_remaining_balance: false,
                            amount_is_cumulative_total: true,
                        }],
                        dispute: None,
                    }),
                    _ => {
                        if status == PaywayStatus::PartiallyRefunded {
                            router_env::logger::warn!(
                                payment_id = ?self.payment_id(),
                                "payway: payment partially refunded outside Hyperswitch without a \
                                 lower amount; the refunded amount is unknown, so it is not reported"
                            );
                        }
                        None
                    }
                };
            }
            _ => return None,
        };
        let payment_id = payment_id?;
        Some(ConnectorReportedActivity {
            refunds: vec![ConnectorReportedRefund {
                connector_refund_id: format!("{prefix}{payment_id}"),
                amount: MinorUnit::new(self.amount.unwrap_or_default()),
                status: enums::RefundStatus::Success,
                amount_is_remaining_balance: true,
                amount_is_cumulative_total: false,
            }],
            dispute: None,
        })
    }
}

impl<F, T> TryFrom<ResponseRouterData<F, PaywayPaymentsResponse, T, PaymentsResponseData>>
    for RouterData<F, T, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: ResponseRouterData<F, PaywayPaymentsResponse, T, PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        let payway_status = item.response.payway_status();
        let cybersource = item.response.cybersource().cloned();
        // A CyberSource review (yellow, 480) under a status Payway does not document is
        // still undecided: pending. Assumed, no production sample of a review yet.
        let status = if payway_status == PaywayStatus::Unknown
            && cybersource
                .as_ref()
                .is_some_and(PaywayCyberSourceStatus::is_review)
        {
            enums::AttemptStatus::Pending
        } else {
            payway_status.attempt_status(item.data.status)
        };
        let response = if payway_status == PaywayStatus::Rejected {
            Err(item.response.rejection(item.http_code))
        } else {
            Ok(PaymentsResponseData::TransactionResponse {
                resource_id: item
                    .response
                    .payment_id()
                    .map(ResponseId::ConnectorTransactionId)
                    .unwrap_or(ResponseId::NoResponseId),
                redirection_data: Box::new(None),
                mandate_reference: Box::new(None),
                connector_metadata: item.response.receipt_metadata(),
                network_txn_id: None,
                connector_response_reference_id: item.response.site_transaction_id.clone(),
                incremental_authorization_allowed: None,
                charges: None,
                network_txn_link_id: None,
                payment_account_reference: None,
                authentication_data: None,
            })
        };
        let mut router_data = Self {
            status,
            response,
            ..item.data
        };
        attach_cybersource_result(&mut router_data, cybersource.as_ref());
        Ok(router_data)
    }
}

/// Closes the payment sync of an attempt: keeps a settled attempt from moving to a weaker
/// status and attaches the refund the sync reports.
///
/// A `Charged` or `PartialCharged` attempt is never downgraded by a sync (annulled, rejected,
/// pending, unknown...): the current status is kept, and a failure response of such a sync is
/// replaced by a successful one with the same id so the router does not mark a real charge as
/// failed. The annulment or refund still reaches the reconciliation as a reported refund,
/// decided on the status the sync ends up with.
pub fn finish_payment_sync<F, T>(
    mut router_data: RouterData<F, T, PaymentsResponseData>,
    attempt_status: enums::AttemptStatus,
    attempt_connector_transaction_id: &ResponseId,
    original_amount: MinorUnit,
    response: &PaywayPaymentsResponse,
) -> RouterData<F, T, PaymentsResponseData> {
    if is_settled_attempt(attempt_status) && !is_settled_attempt(router_data.status) {
        router_env::logger::warn!(
            payment_id = ?response
                .payment_id()
                .or_else(|| attempt_connector_transaction_id.get_connector_transaction_id().ok()),
            payway_status = ?response.status,
            reported_status = ?router_data.status,
            "payway: weaker status reported for a charged attempt; keeping the current one"
        );
        router_data.status = attempt_status;
    }
    if is_settled_attempt(attempt_status) && router_data.response.is_err() {
        router_data.response = Ok(PaymentsResponseData::TransactionResponse {
            resource_id: attempt_connector_transaction_id.clone(),
            redirection_data: Box::new(None),
            mandate_reference: Box::new(None),
            connector_metadata: None,
            network_txn_id: None,
            connector_response_reference_id: None,
            incremental_authorization_allowed: None,
            charges: None,
            network_txn_link_id: None,
            payment_account_reference: None,
            authentication_data: None,
        });
    }
    if let Some(activity) = response.reported_activity(router_data.status, Some(original_amount)) {
        match router_data.connector_response.as_mut() {
            Some(connector_response) => connector_response.set_reported_activity(activity),
            None => {
                router_data.connector_response =
                    Some(ConnectorResponseData::with_reported_activity(activity));
            }
        }
    }
    router_data
}

#[derive(Default, Debug, Serialize)]
pub struct PaywayRefundRequest {
    pub amount: i64,
}

impl<F> TryFrom<&PaywayRouterData<&RefundsRouterData<F>>> for PaywayRefundRequest {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(item: &PaywayRouterData<&RefundsRouterData<F>>) -> Result<Self, Self::Error> {
        let amount = item
            .router_data
            .request
            .minor_refund_amount
            .get_amount_as_i64();
        Ok(Self { amount })
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

/// Payway's generic error body, e.g. a 404 on `GET /payments/{id}`:
/// `{"error_type": "not_found_error", "entity_name": "payments", "id": "749607027"}`.
/// Every field is optional (`id` comes as a number or a string), so an error is
/// reported even when Payway sends another shape.
#[derive(Default, Debug, Serialize, Deserialize, PartialEq)]
pub struct PaywayErrorResponse {
    pub error_type: Option<String>,
    pub entity_name: Option<String>,
    pub id: Option<serde_json::Value>,
    pub message: Option<String>,
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
    /// The cardholder's document, or the empty list every token request sent before one was
    /// read (see `card_holder_identification`).
    #[serde(serialize_with = "serialize_card_holder_identification")]
    card_holder_identification: Option<PaywayCardHolderIdentification>,
    fraud_detection: FraudDetection,
}

/// `card_holder_identification` of `POST /tokens`. Optional for Payway; Visa uses it for its
/// additional data validation (VTE), whose result is only advisory.
#[derive(Debug, Serialize)]
pub struct PaywayCardHolderIdentification {
    #[serde(rename = "type")]
    identification_type: &'static str,
    number: Secret<String>,
}

fn serialize_card_holder_identification<S>(
    identification: &Option<PaywayCardHolderIdentification>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    match identification {
        Some(identification) => identification.serialize(serializer),
        None => serializer.collect_seq(std::iter::empty::<()>()),
    }
}

/// Payway's identification type for a document type as the caller names it, compared without
/// case, accents or punctuation (`"D.N.I."` is `dni`). Only the values Payway's SDKs send are
/// mapped: `dni` (every SDK) and `cuil` (the JavaScript SDK token table, "dni/DNI, cuil/CUIL").
fn payway_identification_type(doc_type: &str) -> Option<&'static str> {
    let key: String = doc_type
        .chars()
        .flat_map(char::to_lowercase)
        .map(|c| match c {
            'á' | 'à' | 'â' | 'ä' => 'a',
            'é' | 'è' | 'ê' | 'ë' => 'e',
            'í' | 'ì' | 'î' | 'ï' => 'i',
            'ó' | 'ò' | 'ô' | 'ö' => 'o',
            'ú' | 'ù' | 'û' | 'ü' => 'u',
            other => other,
        })
        .filter(char::is_ascii_alphanumeric)
        .collect();
    match key.as_str() {
        "dni" => Some("dni"),
        "cuil" => Some("cuil"),
        _ => None,
    }
}

/// A trimmed, non-blank text value of `metadata[key]`.
fn metadata_text<'a>(metadata: &'a serde_json::Value, key: &str) -> Option<&'a str> {
    metadata
        .get(key)
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

/// The cardholder's document from `frm_metadata` `doc_type` and `doc_number` (`payway.*`
/// first, then flat keys). The token request sees no payment metadata, so the document comes
/// from `frm_metadata`. `None` when either key is missing, not text or blank, or the type is
/// not one Payway takes.
fn card_holder_identification(
    frm_metadata: Option<&serde_json::Value>,
) -> Option<PaywayCardHolderIdentification> {
    let metadata = utils::merge_connector_scoped_metadata(PAYWAY_METADATA_SCOPE, &[frm_metadata])?;
    let identification_type = payway_identification_type(metadata_text(&metadata, "doc_type")?)?;
    let number = metadata_text(&metadata, "doc_number")?;
    Some(PaywayCardHolderIdentification {
        identification_type,
        number: Secret::new(number.to_string()),
    })
}

/// Key of the device fingerprint session id in `frm_metadata`, for `POST /tokens`.
const TOKEN_DEVICE_ID_KEY: &str = "device_unique_identifier";

/// The device fingerprint session id for `POST /tokens`: `frm_metadata`
/// `payway.device_unique_identifier`, then the flat key. The token request sees no payment
/// metadata, so it comes from `frm_metadata`. CyberSource rejects the charge (reason 10150,
/// "DeviceFingerprintID is required") unless the token carries the same id as the payment.
/// `None` when neither is non-blank text.
fn token_device_unique_identifier(frm_metadata: Option<&serde_json::Value>) -> Option<String> {
    let metadata = frm_metadata?;
    metadata
        .get(PAYWAY_METADATA_SCOPE)
        .and_then(|scoped| metadata_text(scoped, TOKEN_DEVICE_ID_KEY))
        .or_else(|| metadata_text(metadata, TOKEN_DEVICE_ID_KEY))
        .map(str::to_string)
}

#[derive(Debug, Serialize)]
pub struct FraudDetection {
    device_unique_identifier: String,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct PaywayMetadataObject {
    pub token: Option<String>,
    pub installments: Option<i32>,
    pub payment_method_id: Option<i32>,
    /// `true` sends the charge through CyberSource (and the anti-fraud values below). Also
    /// the text "true" / "false"; anything else is off. The flat `customer_id` key is read
    /// through `bill_to`.
    #[serde(default, deserialize_with = "lenient_flag")]
    pub send_to_cs: Option<bool>,
    /// The device fingerprint session id, for the payment's
    /// `fraud_detection.device_unique_identifier`.
    #[serde(default, deserialize_with = "lenient_string")]
    pub device_id: Option<String>,
    /// The guest history for `fraud_detection.customer_in_site`.
    #[serde(default, deserialize_with = "lenient")]
    pub customer_in_site: Option<PaywayCustomerInSiteMetadata>,
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    pub bill_to: Option<PaywayBillTo>,
}

/// `metadata.customer_in_site`. Every value is optional and read leniently (numbers also as
/// numeric text, `is_guest` also as "true" / "false").
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct PaywayCustomerInSiteMetadata {
    #[serde(deserialize_with = "lenient_amount")]
    pub days_in_site: Option<i64>,
    #[serde(deserialize_with = "lenient_flag")]
    pub is_guest: Option<bool>,
    #[serde(deserialize_with = "lenient_amount")]
    pub num_of_transactions: Option<i64>,
}

/// Key of the connector-scoped object inside the payment metadata.
const PAYWAY_METADATA_SCOPE: &str = "payway";

impl PaywayMetadataObject {
    /// Resolves each key as `metadata.payway.*` first, then flat `metadata.*`.
    fn resolve(
        request_metadata: Option<&serde_json::Value>,
    ) -> Result<Self, error_stack::Report<errors::ConnectorError>> {
        let Some(mut value) =
            utils::merge_connector_scoped_metadata(PAYWAY_METADATA_SCOPE, &[request_metadata])
        else {
            return Ok(Self::default());
        };
        // The billing fields are flat in the stored shape; also accept them grouped
        // under a `bill_to` object, which wins over flat keys.
        if let Some(object) = value.as_object_mut() {
            if let Some(serde_json::Value::Object(bill_to)) = object.remove("bill_to") {
                object.extend(bill_to);
            }
        }
        serde_json::from_value::<Self>(value).map_err(|_e| {
            errors::ConnectorError::InvalidConnectorConfig { config: "metadata" }.into()
        })
    }
}

impl TryFrom<&Option<SecretSerdeValue>> for PaywayMetadataObject {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(meta_data: &Option<SecretSerdeValue>) -> Result<Self, Self::Error> {
        match meta_data {
            Some(metadata) => Ok(utils::to_connector_meta_from_secret::<Self>(Some(
                metadata.clone(),
            ))
            .map_err(|_e| errors::ConnectorError::InvalidConnectorConfig { config: "metadata" })?),
            None => Ok(Self::default()),
        }
    }
}

impl TryFrom<&Option<serde_json::Value>> for PaywayMetadataObject {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(meta_data: &Option<serde_json::Value>) -> Result<Self, Self::Error> {
        let secret_meta: Option<SecretSerdeValue> =
            meta_data.as_ref().map(|v| Secret::new(v.clone()));
        let metadata = utils::to_connector_meta_from_secret::<Self>(secret_meta)
            .map_err(|_e| errors::ConnectorError::InvalidConnectorConfig { config: "metadata" })?;
        Ok(metadata)
    }
}

impl TryFrom<&types::TokenizationRouterData> for PaywayTokenRequest {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(item: &types::TokenizationRouterData) -> Result<Self, Self::Error> {
        let frm_metadata = item.frm_metadata.as_ref().map(|metadata| metadata.peek());
        let device_id = token_device_unique_identifier(frm_metadata)
            .unwrap_or_else(|| item.connector_request_reference_id.clone());

        match item.request.payment_method_data.clone() {
            PaymentMethodData::Card(card) => Ok(Self {
                card_number: card.card_number.clone(),
                card_expiration_month: card.card_exp_month.clone(),
                // Payway takes a 2-digit year; a 4-digit one (e.g. from a shared card form) is rejected.
                card_expiration_year: card.get_card_expiry_year_2_digit()?,
                card_holder_name: card
                    .card_holder_name
                    .clone()
                    .unwrap_or_else(|| Secret::new("".to_string())),
                security_code: card.card_cvc,
                card_holder_identification: card_holder_identification(frm_metadata),
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

impl<T>
    TryFrom<
        ResponseRouterData<
            payments::PaymentMethodToken,
            PaywayTokenResponse,
            T,
            PaymentsResponseData,
        >,
    > for RouterData<payments::PaymentMethodToken, T, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: ResponseRouterData<
            payments::PaymentMethodToken,
            PaywayTokenResponse,
            T,
            PaymentsResponseData,
        >,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            response: Ok(PaymentsResponseData::TokenizationResponse {
                token: item.response.id.peek().to_string(),
            }),
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
    #[serde(default, deserialize_with = "lenient")]
    pub status_details: Option<PaywayStatusDetails>,
    #[serde(default, deserialize_with = "lenient")]
    pub fraud_detection: Option<PaywayFraudDetectionResult>,
}

impl<F, T> TryFrom<ResponseRouterData<F, PaywayAuthorizeResponse, T, PaymentsResponseData>>
    for RouterData<F, T, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: ResponseRouterData<F, PaywayAuthorizeResponse, T, PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        let cybersource = item
            .response
            .fraud_detection
            .as_ref()
            .and_then(PaywayFraudDetectionResult::cybersource)
            .cloned();
        let status = match item.response.status.as_deref() {
            Some("approved") => common_enums::AttemptStatus::Charged,
            // A CyberSource review (yellow, 480) under a pending or undocumented status is
            // still undecided: pending, to be settled by the payment sync. Assumed, no
            // production sample of a review yet.
            Some(status)
                if cybersource
                    .as_ref()
                    .is_some_and(PaywayCyberSourceStatus::is_review)
                    && matches!(
                        PaywayStatus::parse(Some(status)),
                        PaywayStatus::Pending | PaywayStatus::Unknown
                    ) =>
            {
                common_enums::AttemptStatus::Pending
            }
            Some(_) => common_enums::AttemptStatus::Failure,
            None => common_enums::AttemptStatus::Failure,
        };
        let mut router_data = Self {
            status,
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(item.response.id.to_string()),
                redirection_data: Box::new(None),
                mandate_reference: Box::new(None),
                connector_metadata: item
                    .response
                    .status_details
                    .as_ref()
                    .and_then(PaywayStatusDetails::receipt_metadata),
                network_txn_id: None,
                connector_response_reference_id: item.response.site_transaction_id.clone(),
                incremental_authorization_allowed: None,
                charges: None,
                network_txn_link_id: None,
                payment_account_reference: None,
                authentication_data: None,
            }),
            ..item.data
        };
        attach_cybersource_result(&mut router_data, cybersource.as_ref());
        Ok(router_data)
    }
}

#[cfg(test)]
mod tests {
    // The tests read the serialized requests by key, as `payment_sync_tests` reads responses.
    #![allow(clippy::indexing_slicing)]

    use common_utils::types::{AmountConvertor, StringMinorUnitForConnector};

    use super::*;
    use crate::connectors::mercadopago::transformers::test_support;

    #[test]
    fn metadata_scoped_value_wins_over_flat() {
        let request = serde_json::json!({
            "payment_method_id": 1,
            "installments": 3,
            "country": "AR",
            "city": "Flat City",
            "payway": { "payment_method_id": 15, "city": "Scoped City" }
        });
        let meta = PaywayMetadataObject::resolve(Some(&request)).unwrap();
        assert_eq!(meta.payment_method_id, Some(15));
        assert_eq!(meta.installments, Some(3));
        assert_eq!(
            meta.bill_to.and_then(|b| b.city).as_deref(),
            Some("Scoped City")
        );
    }

    #[test]
    fn metadata_nested_bill_to_is_accepted() {
        let request = serde_json::json!({
            "payway": {
                "payment_method_id": 1,
                "bill_to": { "country": "AR", "email": "a@b.com", "street1": "Calle 1" }
            }
        });
        let meta = PaywayMetadataObject::resolve(Some(&request)).unwrap();
        let bill_to = meta.bill_to.unwrap();
        assert_eq!(bill_to.email.as_deref(), Some("a@b.com"));
        assert_eq!(bill_to.street1.as_deref(), Some("Calle 1"));
    }

    #[test]
    fn metadata_flat_keys_still_work() {
        let request = serde_json::json!({
            "payment_method_id": 1,
            "installments": 6,
            "country": "AR",
            "email": "a@b.com"
        });
        let meta = PaywayMetadataObject::resolve(Some(&request)).unwrap();
        assert_eq!(meta.payment_method_id, Some(1));
        assert_eq!(meta.installments, Some(6));
        assert_eq!(
            meta.bill_to.and_then(|b| b.email).as_deref(),
            Some("a@b.com")
        );
    }

    #[test]
    fn metadata_missing_values_stay_none() {
        let request = serde_json::json!({ "mercadopago": { "payment_method_id": "visa" } });
        let meta = PaywayMetadataObject::resolve(Some(&request)).unwrap();
        assert!(meta.payment_method_id.is_none());
        assert!(meta.bill_to.is_none());
        let meta = PaywayMetadataObject::resolve(None).unwrap();
        assert!(meta.payment_method_id.is_none());
        assert!(meta.bill_to.is_none());
    }

    #[test]
    fn establishment_name_valid_is_kept() {
        assert_eq!(
            valid_establishment_name(Some("San Nicolas Plaza Hotel")).as_deref(),
            Some("San Nicolas Plaza Hotel")
        );
    }

    #[test]
    fn establishment_name_is_trimmed() {
        assert_eq!(
            valid_establishment_name(Some("  Hotel Sol  ")).as_deref(),
            Some("Hotel Sol")
        );
    }

    #[test]
    fn establishment_name_of_25_characters_is_kept() {
        let name = "A".repeat(25);
        assert_eq!(valid_establishment_name(Some(&name)), Some(name));
    }

    #[test]
    fn establishment_name_of_26_characters_is_omitted() {
        assert_eq!(valid_establishment_name(Some(&"A".repeat(26))), None);
    }

    #[test]
    fn establishment_name_with_accent_is_omitted() {
        assert_eq!(valid_establishment_name(Some("Hotel Nicol\u{e1}s")), None);
    }

    #[test]
    fn establishment_name_with_symbol_is_omitted() {
        assert_eq!(valid_establishment_name(Some("Hotel & Spa")), None);
        assert_eq!(valid_establishment_name(Some("O'Hara")), None);
    }

    #[test]
    fn establishment_name_empty_is_omitted() {
        assert_eq!(valid_establishment_name(Some("")), None);
        assert_eq!(valid_establishment_name(Some("   ")), None);
    }

    #[test]
    fn establishment_name_without_descriptor_is_omitted() {
        assert_eq!(valid_establishment_name(None), None);
    }

    fn payment_request(establishment_name: Option<String>) -> PaywayPaymentsRequest {
        let item = || PaywayServicesItem {
            code: "SERVICE".to_string(),
            description: "Payment".to_string(),
            name: "Payment service".to_string(),
            sku: "SERVICE".to_string(),
            total_amount: 10000,
            quantity: 1,
            unit_price: 10000,
        };
        PaywayPaymentsRequest {
            site_transaction_id: "pay_1".to_string(),
            token: "token".to_string(),
            payment_method_id: 1,
            bin: "450799".to_string(),
            amount: 10000,
            currency: "ARS".to_string(),
            description: None,
            payment_type: "single".to_string(),
            installments: 1,
            sub_payments: vec![],
            customer: None,
            fraud_detection: PaywayFraudDetectionAuth {
                channel: "Web".to_string(),
                send_to_cs: false,
                device_unique_identifier: "pay_1".to_string(),
                purchase_totals: PaywayPurchaseTotals {
                    currency: "ARS".to_string(),
                    amount: 10000,
                },
                bill_to: PaywayBillTo::default(),
                customer_in_site: PaywayCustomerInSite {
                    days_in_site: 1,
                    is_guest: true,
                    num_of_transactions: 0,
                },
                services_transaction_data: PaywayServicesTransactionData {
                    service_type: "payment".to_string(),
                    items: vec![item()],
                },
                retail_transaction_data: PaywayRetailTransactionData {
                    ship_to: PaywayShipTo {
                        country: "AR".to_string(),
                        city: None,
                        email: None,
                        first_name: None,
                        last_name: None,
                        phone_number: None,
                        postal_code: None,
                        state: None,
                        street1: None,
                    },
                    items: vec![item()],
                },
            },
            establishment_name,
        }
    }

    #[test]
    fn payment_request_sends_establishment_name_only_when_present() {
        let without = serde_json::to_value(payment_request(None)).unwrap();
        assert!(without.get("establishment_name").is_none());

        let with =
            serde_json::to_value(payment_request(Some("San Nicolas Plaza Hotel".to_string())))
                .unwrap();
        assert_eq!(with["establishment_name"], "San Nicolas Plaza Hotel");
    }

    /// The amount of a card charge, as the connector receives it.
    fn charge_amount(router_data: &PaymentsAuthorizeRouterData) -> StringMinorUnit {
        StringMinorUnitForConnector
            .convert(
                router_data.request.minor_amount,
                router_data.request.currency,
            )
            .unwrap()
    }

    /// What a card charge builds from the given payment metadata.
    fn charge_request(
        metadata: serde_json::Value,
    ) -> Result<PaywayPaymentsRequest, error_stack::Report<errors::ConnectorError>> {
        let router_data = test_support::authorize_router_data(Some(metadata), None);
        let amount = charge_amount(&router_data);
        PaywayPaymentsRequest::try_from(&PaywayRouterData::from((amount, &router_data)))
    }

    /// The text at `pointer` in a serialized charge.
    fn text_at(request: &serde_json::Value, pointer: &str) -> String {
        request
            .pointer(pointer)
            .and_then(serde_json::Value::as_str)
            .unwrap()
            .to_string()
    }

    /// The `(bill_to, ship_to)` countries a card charge sends for the given payer country.
    fn countries_sent_for(country: &str) -> (String, String) {
        let request = serde_json::to_value(
            charge_request(billing_metadata(serde_json::json!(country)))
                .expect("the charge must build"),
        )
        .unwrap();
        (
            text_at(&request, "/fraud_detection/bill_to/country"),
            text_at(
                &request,
                "/fraud_detection/retail_transaction_data/ship_to/country",
            ),
        )
    }

    /// The flat billing metadata api2 sends, with the given `country`.
    fn billing_metadata(country: serde_json::Value) -> serde_json::Value {
        serde_json::json!({
            "payment_method_id": 1,
            "installments": 1,
            "country": country,
            "city": "Mendoza",
            "email": "guest@example.com",
            "first_name": "Ana",
            "last_name": "Gomez",
            "phone_number": "5492610000000",
            "postal_code": "5500",
            "state": "M",
            "street1": "Calle 1"
        })
    }

    #[test]
    fn charge_sends_the_payer_country_uppercased() {
        for (given, sent) in [("uy", "UY"), ("Br", "BR"), (" cl ", "CL"), ("US", "US")] {
            assert_eq!(
                countries_sent_for(given),
                (sent.to_string(), sent.to_string()),
                "{given:?}"
            );
        }
    }

    #[test]
    fn charge_keeps_ar_for_an_unusable_payer_country() {
        for given in ["", "  ", "Uruguay", "URY", "858", "U1", "XX", "\u{d1}U"] {
            assert_eq!(
                countries_sent_for(given),
                ("AR".to_string(), "AR".to_string()),
                "{given:?}"
            );
        }
    }

    #[test]
    fn charge_for_an_argentine_payer_sends_the_same_billing_as_before() {
        let request = serde_json::to_value(
            charge_request(billing_metadata(serde_json::json!("AR"))).unwrap(),
        )
        .unwrap();
        assert_eq!(
            request.pointer("/fraud_detection/bill_to"),
            Some(&serde_json::json!({
                "country": "AR",
                "city": "Mendoza",
                "customer_id": "pxs_mp_1",
                "email": "guest@example.com",
                "first_name": "Ana",
                "last_name": "Gomez",
                "phone_number": "5492610000000",
                "postal_code": "5500",
                "state": "M",
                "street1": "Calle 1"
            }))
        );
        assert_eq!(
            request.pointer("/fraud_detection/retail_transaction_data/ship_to"),
            Some(&serde_json::json!({
                "country": "AR",
                "city": "Mendoza",
                "email": "guest@example.com",
                "first_name": "Ana",
                "last_name": "Gomez",
                "phone_number": "5492610000000",
                "postal_code": "5500",
                "state": "M",
                "street1": "Calle 1"
            }))
        );
    }

    #[test]
    fn charge_without_a_payer_country_still_reports_missing_billing() {
        // The country is what makes the flat billing keys a `bill_to`; without it the charge
        // fails as before instead of going out with the default country.
        let mut without_country = billing_metadata(serde_json::Value::Null);
        without_country.as_object_mut().unwrap().remove("country");
        for metadata in [without_country, billing_metadata(serde_json::Value::Null)] {
            let error = charge_request(metadata).expect_err("billing is required");
            assert!(
                matches!(
                    error.current_context(),
                    errors::ConnectorError::MissingRequiredField { field_name }
                        if field_name == "metadata.bill_to"
                ),
                "{error:?}"
            );
        }
    }

    /// The token request (`POST /tokens`) built with the given `frm_metadata`.
    fn token_request_sent_for(frm_metadata: Option<serde_json::Value>) -> serde_json::Value {
        let router_data = test_support::tokenization_router_data(
            Some("ANA GOMEZ"),
            hyperswitch_domain_models::payment_address::PaymentAddress::default(),
            frm_metadata,
        );
        serde_json::to_value(PaywayTokenRequest::try_from(&router_data).unwrap()).unwrap()
    }

    fn identification_sent_for(frm_metadata: Option<serde_json::Value>) -> serde_json::Value {
        token_request_sent_for(frm_metadata)
            .get("card_holder_identification")
            .cloned()
            .unwrap()
    }

    #[test]
    fn token_request_sends_the_cardholder_document() {
        for (doc_type, sent_type) in [
            ("DNI", "dni"),
            ("dni", "dni"),
            (" D.N.I. ", "dni"),
            ("CUIL", "cuil"),
            ("Cu\u{ed}l", "cuil"),
        ] {
            assert_eq!(
                identification_sent_for(Some(serde_json::json!({
                    "doc_type": doc_type,
                    "doc_number": " 30111222 "
                }))),
                serde_json::json!({ "type": sent_type, "number": "30111222" }),
                "{doc_type:?}"
            );
        }
        // Keys under `payway` win over flat ones, as in the payment metadata.
        assert_eq!(
            identification_sent_for(Some(serde_json::json!({
                "doc_type": "CUIL",
                "doc_number": "20301112223",
                "payway": { "doc_type": "DNI", "doc_number": "30111222" }
            }))),
            serde_json::json!({ "type": "dni", "number": "30111222" })
        );
    }

    #[test]
    fn token_request_without_a_usable_document_sends_the_empty_list() {
        for frm_metadata in [
            serde_json::json!({}),
            serde_json::json!({ "device_id": "device-1" }),
            serde_json::json!({ "doc_type": "Pasaporte", "doc_number": "AA123456" }),
            serde_json::json!({ "doc_type": "CUIT", "doc_number": "20301112223" }),
            serde_json::json!({ "doc_type": "", "doc_number": "30111222" }),
            serde_json::json!({ "doc_type": "DNI", "doc_number": "  " }),
            serde_json::json!({ "doc_type": "DNI" }),
            serde_json::json!({ "doc_type": "DNI", "doc_number": 30111222 }),
        ] {
            assert_eq!(
                identification_sent_for(Some(frm_metadata.clone())),
                serde_json::json!([]),
                "{frm_metadata}"
            );
        }
    }

    #[test]
    fn token_request_without_frm_metadata_is_the_same_as_before() {
        assert_eq!(
            token_request_sent_for(None),
            serde_json::json!({
                "card_number": "4509953566233704",
                "card_expiration_month": "11",
                "card_expiration_year": "30",
                "card_holder_name": "ANA GOMEZ",
                "security_code": "123",
                "card_holder_identification": [],
                "fraud_detection": { "device_unique_identifier": "pxs_mp_1" }
            })
        );
    }

    /// The charge built from `metadata`, serialized as it goes on the wire, with the guest IP
    /// the router reads from `browser_info` (if any).
    fn charge_sent(metadata: serde_json::Value, ip_address: Option<&str>) -> String {
        let mut router_data = test_support::authorize_router_data(Some(metadata), None);
        router_data.request.browser_info = ip_address.map(|ip| {
            hyperswitch_domain_models::router_request_types::BrowserInformation {
                ip_address: Some(ip.parse().unwrap()),
                ..Default::default()
            }
        });
        let amount = charge_amount(&router_data);
        serde_json::to_string(
            &PaywayPaymentsRequest::try_from(&PaywayRouterData::from((amount, &router_data)))
                .unwrap(),
        )
        .unwrap()
    }

    fn charge_sent_json(
        metadata: serde_json::Value,
        ip_address: Option<&str>,
    ) -> serde_json::Value {
        serde_json::from_str(&charge_sent(metadata, ip_address)).unwrap()
    }

    /// `billing_metadata("AR")` plus the given extra keys.
    fn billing_metadata_with(extra: serde_json::Value) -> serde_json::Value {
        let mut metadata = billing_metadata(serde_json::json!("AR"));
        let object = metadata.as_object_mut().unwrap();
        for (key, value) in extra.as_object().unwrap() {
            object.insert(key.clone(), value.clone());
        }
        metadata
    }

    /// The anti-fraud keys api2 sends for a motor charge, without `send_to_cs`.
    fn antifraud_keys() -> serde_json::Value {
        serde_json::json!({
            "customer_id": "g_0123456789abcdef0123456789abcdef",
            "device_id": "tmx-session-1",
            "customer_in_site": { "days_in_site": 0, "is_guest": true, "num_of_transactions": 0 }
        })
    }

    fn with_send_to_cs(send_to_cs: serde_json::Value) -> serde_json::Value {
        let mut keys = antifraud_keys();
        keys.as_object_mut()
            .unwrap()
            .insert("send_to_cs".to_string(), send_to_cs);
        billing_metadata_with(keys)
    }

    /// `POST /payments` byte for byte as origin/main (273229ddf0) serializes the charge of
    /// `billing_metadata("AR")`. Captured by running this test on that commit.
    const ORIGIN_MAIN_CHARGE: &str = concat!(
        r#"{"site_transaction_id":"pxs_mp_1","token":"card-token-1","payment_method_id":1,"#,
        r#""bin":"450995","amount":15000,"currency":"ARS","description":null,"#,
        r#""payment_type":"single","installments":1,"sub_payments":[],"fraud_detection":{"channel":"Web","#,
        r#""send_to_cs":false,"device_unique_identifier":"pxs_mp_1","purchase_totals":{"currency":"ARS","#,
        r#""amount":15000},"bill_to":{"country":"AR","city":"Mendoza","customer_id":"pxs_mp_1","#,
        r#""email":"guest@example.com","first_name":"Ana","last_name":"Gomez","#,
        r#""phone_number":"5492610000000","postal_code":"5500","state":"M","#,
        r#""street1":"Calle 1"},"customer_in_site":{"days_in_site":1,"is_guest":true,"#,
        r#""num_of_transactions":0},"services_transaction_data":{"service_type":"payment","#,
        r#""items":[{"code":"SERVICE","description":"Payment","name":"Payment service","#,
        r#""sku":"SERVICE","total_amount":15000,"quantity":1,"unit_price":15000}]},"#,
        r#""retail_transaction_data":{"ship_to":{"country":"AR","city":"Mendoza","#,
        r#""email":"guest@example.com","first_name":"Ana","last_name":"Gomez","#,
        r#""phone_number":"5492610000000","postal_code":"5500","state":"M","#,
        r#""street1":"Calle 1"},"items":[{"code":"SERVICE","description":"Payment","#,
        r#""name":"Payment service","sku":"SERVICE","total_amount":15000,"#,
        r#""quantity":1,"unit_price":15000}]}}}"#,
    );

    /// `POST /tokens` byte for byte as origin/main (273229ddf0) serializes it without a
    /// cardholder document. Captured by running this test on that commit.
    const ORIGIN_MAIN_TOKEN: &str = concat!(
        r#"{"card_number":"4509953566233704","card_expiration_month":"11","#,
        r#""card_expiration_year":"30","card_holder_name":"ANA GOMEZ","security_code":"123","#,
        r#""card_holder_identification":[],"fraud_detection":{"device_unique_identifier":"pxs_mp_1"}}"#,
    );

    #[test]
    fn charge_without_send_to_cs_is_byte_identical_to_origin_main() {
        let variants = vec![
            (billing_metadata(serde_json::json!("AR")), None),
            (billing_metadata(serde_json::json!("AR")), Some("190.2.3.4")),
            (billing_metadata_with(antifraud_keys()), Some("190.2.3.4")),
            (with_send_to_cs(serde_json::json!(false)), Some("190.2.3.4")),
            (with_send_to_cs(serde_json::json!("false")), None),
            (with_send_to_cs(serde_json::json!(null)), None),
            (with_send_to_cs(serde_json::json!("yes")), None),
            (with_send_to_cs(serde_json::json!(1)), None),
            (
                billing_metadata_with(serde_json::json!({ "payway": { "send_to_cs": false } })),
                None,
            ),
            // The scoped key wins over the flat one, as for every other key.
            (
                billing_metadata_with(serde_json::json!({
                    "send_to_cs": true,
                    "payway": { "send_to_cs": false }
                })),
                Some("190.2.3.4"),
            ),
        ];
        let sent: Vec<String> = variants
            .into_iter()
            .map(|(metadata, ip)| charge_sent(metadata, ip))
            .collect();
        for charge in &sent {
            assert_eq!(charge, ORIGIN_MAIN_CHARGE, "every variant: {sent:#?}");
        }
    }

    #[test]
    fn token_request_without_a_device_id_is_byte_identical_to_origin_main() {
        let sent: Vec<String> = [
            None,
            Some(serde_json::json!({})),
            Some(serde_json::json!({ "device_id": "tmx-session-1" })),
            Some(serde_json::json!({ "device_unique_identifier": "  " })),
            Some(serde_json::json!({ "device_unique_identifier": 12345 })),
            Some(serde_json::json!({ "payway": { "device_unique_identifier": null } })),
        ]
        .into_iter()
        .map(|frm_metadata| {
            let router_data = test_support::tokenization_router_data(
                Some("ANA GOMEZ"),
                hyperswitch_domain_models::payment_address::PaymentAddress::default(),
                frm_metadata,
            );
            serde_json::to_string(&PaywayTokenRequest::try_from(&router_data).unwrap()).unwrap()
        })
        .collect();
        for token in &sent {
            assert_eq!(token, ORIGIN_MAIN_TOKEN, "every variant: {sent:#?}");
        }
    }

    #[test]
    fn charge_with_send_to_cs_sends_the_customer_the_device_and_the_guest_history() {
        for metadata in [
            with_send_to_cs(serde_json::json!(true)),
            with_send_to_cs(serde_json::json!("true")),
            with_send_to_cs(serde_json::json!(" TRUE ")),
            billing_metadata_with({
                let mut keys = antifraud_keys();
                keys.as_object_mut().unwrap().insert(
                    "payway".to_string(),
                    serde_json::json!({ "send_to_cs": true }),
                );
                keys
            }),
        ] {
            let request = charge_sent_json(metadata.clone(), Some("190.2.3.4"));
            assert_eq!(
                request.get("customer"),
                Some(&serde_json::json!({
                    "id": "g_0123456789abcdef0123456789abcdef",
                    "email": "guest@example.com",
                    "ip_address": "190.2.3.4"
                })),
                "{metadata}"
            );
            let fraud_detection = &request["fraud_detection"];
            assert_eq!(fraud_detection["send_to_cs"], true, "{metadata}");
            assert_eq!(
                fraud_detection["device_unique_identifier"], "tmx-session-1",
                "{metadata}"
            );
            assert_eq!(
                fraud_detection["bill_to"]["customer_id"], "g_0123456789abcdef0123456789abcdef",
                "{metadata}"
            );
            assert_eq!(
                fraud_detection["customer_in_site"],
                serde_json::json!({ "days_in_site": 0, "is_guest": true, "num_of_transactions": 0 }),
                "{metadata}"
            );

            // Nothing else changes: the rest is the charge origin/main sends.
            let mut expected: serde_json::Value = serde_json::from_str(ORIGIN_MAIN_CHARGE).unwrap();
            let object = expected.as_object_mut().unwrap();
            object.insert("customer".to_string(), request["customer"].clone());
            let expected_fraud_detection = &mut expected["fraud_detection"];
            expected_fraud_detection["send_to_cs"] = serde_json::json!(true);
            expected_fraud_detection["device_unique_identifier"] =
                serde_json::json!("tmx-session-1");
            expected_fraud_detection["bill_to"]["customer_id"] =
                serde_json::json!("g_0123456789abcdef0123456789abcdef");
            expected_fraud_detection["customer_in_site"] = serde_json::json!({ "days_in_site": 0, "is_guest": true, "num_of_transactions": 0 });
            expected_fraud_detection["services_transaction_data"]["service_type"] =
                serde_json::json!("Alojamiento");
            expected_fraud_detection["services_transaction_data"]["items"][0]["name"] =
                serde_json::json!("Alojamiento");
            expected_fraud_detection["retail_transaction_data"]["items"][0]["name"] =
                serde_json::json!("Alojamiento");
            assert_eq!(request, expected, "{metadata}");
        }
    }

    #[test]
    fn charge_with_send_to_cs_sends_the_lodging_service_that_passed_cybersource() {
        // L20: the charge CyberSource approved in production sent "Alojamiento".
        let request = charge_sent_json(with_send_to_cs(serde_json::json!(true)), None);
        let fraud_detection = &request["fraud_detection"];
        assert_eq!(
            fraud_detection["services_transaction_data"]["service_type"],
            "Alojamiento"
        );
        for items in ["services_transaction_data", "retail_transaction_data"] {
            assert_eq!(
                fraud_detection[items]["items"],
                serde_json::json!([{
                    "code": "SERVICE",
                    "description": "Payment",
                    "name": "Alojamiento",
                    "sku": "SERVICE",
                    "total_amount": 15000,
                    "quantity": 1,
                    "unit_price": 15000
                }]),
                "{items}"
            );
        }
    }

    #[test]
    fn charge_with_send_to_cs_and_missing_values_keeps_todays_values() {
        let request = charge_sent_json(
            billing_metadata_with(serde_json::json!({
                "send_to_cs": true,
                "customer_id": "  ",
                "device_id": null,
                "customer_in_site": "not an object"
            })),
            None,
        );
        // Without an IP the key is omitted rather than sent empty.
        assert_eq!(
            request.get("customer"),
            Some(&serde_json::json!({ "id": "pxs_mp_1", "email": "guest@example.com" }))
        );
        let fraud_detection = &request["fraud_detection"];
        assert_eq!(fraud_detection["send_to_cs"], true);
        assert_eq!(fraud_detection["device_unique_identifier"], "pxs_mp_1");
        assert_eq!(fraud_detection["bill_to"]["customer_id"], "pxs_mp_1");
        assert_eq!(
            fraud_detection["customer_in_site"],
            serde_json::json!({ "days_in_site": 1, "is_guest": true, "num_of_transactions": 0 })
        );

        // A partial guest history keeps today's constant for each missing or unusable value.
        let request = charge_sent_json(
            billing_metadata_with(serde_json::json!({
                "send_to_cs": true,
                "customer_in_site": { "days_in_site": 0, "num_of_transactions": "3" }
            })),
            None,
        );
        assert_eq!(
            request["fraud_detection"]["customer_in_site"],
            serde_json::json!({ "days_in_site": 0, "is_guest": true, "num_of_transactions": 3 })
        );
        let request = charge_sent_json(
            billing_metadata_with(serde_json::json!({
                "send_to_cs": true,
                "customer_in_site": { "days_in_site": -2, "is_guest": "false", "num_of_transactions": "many" }
            })),
            None,
        );
        assert_eq!(
            request["fraud_detection"]["customer_in_site"],
            serde_json::json!({ "days_in_site": 1, "is_guest": false, "num_of_transactions": 0 })
        );
    }

    #[test]
    fn token_request_sends_the_device_id_from_frm_metadata() {
        let device_sent = |frm_metadata: serde_json::Value| {
            token_request_sent_for(Some(frm_metadata))["fraud_detection"]
                ["device_unique_identifier"]
                .clone()
        };
        assert_eq!(
            device_sent(serde_json::json!({ "device_unique_identifier": " tmx-session-1 " })),
            "tmx-session-1"
        );
        assert_eq!(
            device_sent(serde_json::json!({
                "device_unique_identifier": "flat",
                "payway": { "device_unique_identifier": "tmx-session-2" }
            })),
            "tmx-session-2"
        );
        // The cardholder document still goes out next to it.
        let request = token_request_sent_for(Some(serde_json::json!({
            "doc_type": "DNI",
            "doc_number": "30111222",
            "device_unique_identifier": "tmx-session-1"
        })));
        assert_eq!(
            request["card_holder_identification"],
            serde_json::json!({ "type": "dni", "number": "30111222" })
        );
        assert_eq!(
            request["fraud_detection"]["device_unique_identifier"],
            "tmx-session-1"
        );
    }
}
