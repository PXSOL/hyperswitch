use common_enums::enums;
use common_utils::{
    pii::SecretSerdeValue,
    types::{MinorUnit, StringMinorUnit},
};
use hyperswitch_domain_models::{
    payment_method_data::PaymentMethodData,
    router_data::{
        ConnectorAuthType, ConnectorReportedActivity, ConnectorReportedRefund,
        ConnectorResponseData, ErrorResponse, RouterData,
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
    utils::RouterData as _,
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
    pub fraud_detection: PaywayFraudDetectionAuth,
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

        let meta = PaywayMetadataObject::try_from(&item.router_data.request.metadata)?;

        let bill_to_meta =
            meta.bill_to
                .as_ref()
                .ok_or(errors::ConnectorError::MissingRequiredField {
                    field_name: "metadata.bill_to".into(),
                })?;

        let device_id = item.router_data.connector_request_reference_id.clone();

        let customer_id = if let Some(stripped) = device_id.strip_prefix("pay_") {
            format!("customer_{}", stripped)
        } else {
            device_id.clone()
        };

        let bill_to = PaywayBillTo {
            country: "AR".to_string(),
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
            country: "AR".to_string(),
            city: bill_to_meta.city.clone(),
            email: bill_to_meta.email.clone(),
            first_name: bill_to_meta.first_name.clone(),
            last_name: bill_to_meta.last_name.clone(),
            phone_number: bill_to_meta.phone_number.clone(),
            postal_code: bill_to_meta.postal_code.clone(),
            state: bill_to_meta.state.clone(),
            street1: bill_to_meta.street1.clone(),
        };

        let fraud_detection = PaywayFraudDetectionAuth {
            channel: "Web".to_string(),
            send_to_cs: false,
            device_unique_identifier: device_id,
            purchase_totals: PaywayPurchaseTotals {
                currency: currency.clone(),
                amount,
            },
            bill_to,
            customer_in_site: PaywayCustomerInSite {
                days_in_site: 1,
                is_guest: true,
                num_of_transactions: 0,
            },
            services_transaction_data: PaywayServicesTransactionData {
                service_type: "payment".to_string(),
                items: vec![PaywayServicesItem {
                    code: "SERVICE".to_string(),
                    description: item
                        .router_data
                        .description
                        .clone()
                        .unwrap_or_else(|| "Payment".to_string()),
                    name: "Payment service".to_string(),
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
                    name: "Payment service".to_string(),
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
            fraud_detection,
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
/// code, ticket, address validation) that must not reach the logs or the connector events, so
/// only its `error` sub-object is kept.
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
}

#[derive(Default, Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct PaywayStatusDetails {
    #[serde(deserialize_with = "lenient")]
    error: Option<PaywayStatusError>,
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

    pub fn payway_status(&self) -> PaywayStatus {
        PaywayStatus::parse(self.status.as_deref())
    }

    /// Error of a rejected payment, built like the one of a declined authorize (402).
    pub(super) fn rejection(&self, http_code: u16) -> ErrorResponse {
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
        let status = payway_status.attempt_status(item.data.status);
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
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: item.response.site_transaction_id.clone(),
                incremental_authorization_allowed: None,
                charges: None,
                network_txn_link_id: None,
                payment_account_reference: None,
                authentication_data: None,
            })
        };
        Ok(Self {
            status,
            response,
            ..item.data
        })
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
    pub payment_method_id: Option<i32>,
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    pub bill_to: Option<PaywayBillTo>,
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
        let device_id = item.connector_request_reference_id.clone();

        match item.request.payment_method_data.clone() {
            PaymentMethodData::Card(card) => Ok(Self {
                card_number: card.card_number.clone(),
                card_expiration_month: card.card_exp_month.clone(),
                card_expiration_year: card.card_exp_year.clone(),
                card_holder_name: card
                    .card_holder_name
                    .clone()
                    .unwrap_or_else(|| Secret::new("".to_string())),
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
}

impl<F, T> TryFrom<ResponseRouterData<F, PaywayAuthorizeResponse, T, PaymentsResponseData>>
    for RouterData<F, T, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: ResponseRouterData<F, PaywayAuthorizeResponse, T, PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
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
                network_txn_link_id: None,
                payment_account_reference: None,
                authentication_data: None,
            }),
            ..item.data
        })
    }
}
