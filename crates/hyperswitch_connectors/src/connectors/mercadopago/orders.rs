//! Mercado Pago Orders API (in-person dynamic QR).
//!
//! An order id (`ORD...`) is a string, unlike the numeric ids of `/v1/payments`, so
//! the Orders flows have their own request and response types. The `ORD` prefix of the
//! connector transaction id is what routes psync, void, refund and refund sync to
//! `/v1/orders`; numeric ids keep taking the `/v1/payments` paths.

use common_enums::enums;
use common_utils::types::{FloatMajorUnit, FloatMajorUnitForConnector};
use error_stack::ResultExt;
use hyperswitch_domain_models::{
    payment_method_data::{PaymentMethodData, WalletData},
    router_data::{ConnectorReportedActivity, ConnectorReportedRefund, ErrorResponse, RouterData},
    router_request_types::ResponseId,
    router_response_types::{PaymentsResponseData, RefundsResponseData},
    types::{PaymentsAuthorizeRouterData, RefundsRouterData},
};
use hyperswitch_interfaces::errors;
use serde::{Deserialize, Serialize};

use super::transformers::{
    get_mercadopago_error_message, MercadopagoMetadata, MercadopagoRouterData,
    MAX_APPLICATION_FEE_RATIO,
};
use crate::{
    types::{RefundsResponseRouterData, ResponseRouterData},
    utils::{self, QrImage},
};

/// Prefix of every Orders API order id (sandbox ids are `ORDTST...`).
const ORDER_ID_PREFIX: &str = "ORD";
/// How long a dynamic QR can be paid, as sent to Mercado Pago (ISO 8601 duration).
const QR_ORDER_EXPIRATION_TIME: &str = "PT30M";
const QR_ORDER_EXPIRATION_MINUTES: i64 = 30;

/// Key under which the POS created by the store setup endpoint lives in the connector
/// account metadata (`connector_meta_data`).
pub const QR_POS_METADATA_KEY: &str = "qr_pos";
/// Key of the Mercado Pago payment id (`PAY...`) next to the QR fields of the attempt's
/// `connector_metadata`. Refunds need it, and `QrCodeInformation` ignores unknown keys.
pub const MP_PAYMENT_ID_KEY: &str = "mp_payment_id";

/// Whether a connector transaction id belongs to the Orders API.
pub fn is_order_id(connector_transaction_id: &str) -> bool {
    connector_transaction_id.starts_with(ORDER_ID_PREFIX)
}

/// `GET` path to sync a payment: an order for an `ORD` id, a payment otherwise.
pub fn psync_path(connector_transaction_id: &str) -> String {
    if is_order_id(connector_transaction_id) {
        format!("/v1/orders/{connector_transaction_id}")
    } else {
        format!("/v1/payments/{connector_transaction_id}")
    }
}

/// Path to void: `POST .../cancel` for an order, `PUT` of the payment otherwise.
pub fn void_path(connector_transaction_id: &str) -> String {
    if is_order_id(connector_transaction_id) {
        format!("/v1/orders/{connector_transaction_id}/cancel")
    } else {
        format!("/v1/payments/{connector_transaction_id}")
    }
}

pub fn refund_path(connector_transaction_id: &str) -> String {
    if is_order_id(connector_transaction_id) {
        format!("/v1/orders/{connector_transaction_id}/refund")
    } else {
        format!("/v1/payments/{connector_transaction_id}/refunds")
    }
}

/// An order lists its refunds, so syncing one reads the order.
pub fn refund_sync_path(connector_transaction_id: &str, connector_refund_id: &str) -> String {
    if is_order_id(connector_transaction_id) {
        format!("/v1/orders/{connector_transaction_id}")
    } else {
        format!("/v1/payments/{connector_transaction_id}/refunds/{connector_refund_id}")
    }
}

pub fn is_qr_wallet(payment_method_data: &PaymentMethodData) -> bool {
    matches!(
        payment_method_data,
        PaymentMethodData::Wallet(WalletData::MercadoPagoQr {})
    )
}

/// The store and POS of a seller, as saved in the connector account metadata by the
/// store setup endpoint. Mercado Pago ids are numbers on the wire; they are kept as text.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MercadopagoQrPos {
    /// The Mercado Pago user that owns the store: its POS only works with that user's token.
    pub seller_id: String,
    pub store_id: String,
    pub external_store_id: String,
    pub pos_id: String,
    pub external_pos_id: String,
    /// Plain URLs Mercado Pago serves for the POS's fixed QR. Absent in metadata saved
    /// before they were stored.
    #[serde(default)]
    pub qr_image: Option<String>,
    #[serde(default)]
    pub qr_template_document: Option<String>,
    #[serde(default)]
    pub qr_template_image: Option<String>,
}

/// The `external_pos_id` of the seller's POS, from the connector account metadata.
fn qr_external_pos_id(
    connector_meta_data: Option<&serde_json::Value>,
) -> Result<String, error_stack::Report<errors::ConnectorError>> {
    connector_meta_data
        .and_then(|metadata| metadata.get(QR_POS_METADATA_KEY))
        .and_then(|pos| pos.get("external_pos_id"))
        .and_then(|id| id.as_str())
        .filter(|id| !id.is_empty())
        .map(str::to_string)
        .ok_or_else(|| {
            errors::ConnectorError::MissingRequiredField {
                field_name: "connector_meta_data.qr_pos.external_pos_id".into(),
            }
            .into()
        })
}

/// Mercado Pago Orders takes amounts as decimal strings.
fn format_amount(amount: FloatMajorUnit) -> String {
    format!("{:.2}", amount.get_amount_as_f64())
}

/// Longest `description` and item `title` Mercado Pago accepts.
const MAX_DESCRIPTION_CHARS: usize = 150;

fn truncate_chars(text: &str) -> String {
    text.chars().take(MAX_DESCRIPTION_CHARS).collect()
}

/// QR modes this connector can create. `static` is left out: the connector needs the
/// `qr_data` that only `dynamic` and `hybrid` return.
const QR_MODE_DYNAMIC: &str = "dynamic";
const QR_MODE_HYBRID: &str = "hybrid";

/// The order `config.qr.mode` for the `qr_mode` metadata value: `dynamic` by default,
/// `hybrid` on request, an error for anything else (before any call to Mercado Pago).
fn resolve_qr_mode(
    qr_mode: Option<&str>,
) -> Result<&'static str, error_stack::Report<errors::ConnectorError>> {
    match qr_mode {
        None | Some(QR_MODE_DYNAMIC) => Ok(QR_MODE_DYNAMIC),
        Some(QR_MODE_HYBRID) => Ok(QR_MODE_HYBRID),
        Some(_) => Err(errors::ConnectorError::InvalidDataFormat {
            field_name: "qr_mode (only dynamic and hybrid are supported)".into(),
        }
        .into()),
    }
}

/// Applies the 0.7% marketplace fee cap shared with the other flows. `None` when there is
/// no fee to send.
fn resolve_marketplace_fee(
    application_fee: Option<f64>,
    amount: FloatMajorUnit,
) -> Result<Option<String>, error_stack::Report<errors::ConnectorError>> {
    match application_fee {
        Some(fee) if fee > 0.0 => {
            let max_fee = amount.get_amount_as_f64() * MAX_APPLICATION_FEE_RATIO;
            if fee > max_fee {
                return Err(errors::ConnectorError::InvalidDataFormat {
                    field_name:
                        "application_fee exceeds maximum allowed (0.7% of transaction_amount)"
                            .into(),
                }
                .into());
            }
            Ok(Some(format!("{fee:.2}")))
        }
        _ => Ok(None),
    }
}

// ============================================================================
// Create order - POST /v1/orders
// ============================================================================

#[derive(Debug, Serialize)]
pub struct MercadopagoQrOrderRequest {
    #[serde(rename = "type")]
    pub order_type: &'static str,
    pub total_amount: String,
    /// Mercado Pago rejects a currency the seller cannot use, instead of charging the same
    /// figure in the seller's own currency.
    pub currency: enums::Currency,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// One entry carrying the description, so the loaded order does not show "default item".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub items: Option<Vec<MercadopagoOrderItem>>,
    pub external_reference: String,
    pub expiration_time: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub marketplace_fee: Option<String>,
    pub integration_data: MercadopagoIntegrationData,
    pub config: MercadopagoOrderConfig,
    pub transactions: MercadopagoOrderPaymentsRequest,
}

#[derive(Debug, Serialize)]
pub struct MercadopagoOrderItem {
    pub title: String,
    pub unit_price: String,
    pub quantity: u32,
    pub unit_measure: &'static str,
}

#[derive(Debug, Serialize)]
pub struct MercadopagoIntegrationData {
    pub platform_id: &'static str,
}

#[derive(Debug, Serialize)]
pub struct MercadopagoOrderConfig {
    pub qr: MercadopagoQrConfig,
}

#[derive(Debug, Serialize)]
pub struct MercadopagoQrConfig {
    pub external_pos_id: String,
    pub mode: &'static str,
}

#[derive(Debug, Serialize)]
pub struct MercadopagoOrderPaymentsRequest {
    pub payments: Vec<MercadopagoOrderPaymentRequest>,
}

#[derive(Debug, Serialize)]
pub struct MercadopagoOrderPaymentRequest {
    pub amount: String,
}

impl MercadopagoQrOrderRequest {
    fn build(
        amount: FloatMajorUnit,
        currency: enums::Currency,
        description: Option<String>,
        external_reference: String,
        application_fee: Option<f64>,
        external_pos_id: String,
        qr_mode: Option<&str>,
    ) -> Result<Self, error_stack::Report<errors::ConnectorError>> {
        let mode = resolve_qr_mode(qr_mode)?;
        let total_amount = format_amount(amount);
        let description = description
            .filter(|text| !text.is_empty())
            .map(|text| truncate_chars(&text));
        let items = description.as_ref().map(|title| {
            vec![MercadopagoOrderItem {
                title: title.clone(),
                unit_price: total_amount.clone(),
                quantity: 1,
                unit_measure: "unit",
            }]
        });
        Ok(Self {
            order_type: "qr",
            total_amount: total_amount.clone(),
            currency,
            description,
            items,
            external_reference,
            expiration_time: QR_ORDER_EXPIRATION_TIME,
            marketplace_fee: resolve_marketplace_fee(application_fee, amount)?,
            integration_data: MercadopagoIntegrationData {
                platform_id: super::PXSOL_PLATFORM_ID,
            },
            config: MercadopagoOrderConfig {
                qr: MercadopagoQrConfig {
                    external_pos_id,
                    mode,
                },
            },
            transactions: MercadopagoOrderPaymentsRequest {
                payments: vec![MercadopagoOrderPaymentRequest {
                    amount: total_amount,
                }],
            },
        })
    }
}

impl TryFrom<&MercadopagoRouterData<&PaymentsAuthorizeRouterData>> for MercadopagoQrOrderRequest {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: &MercadopagoRouterData<&PaymentsAuthorizeRouterData>,
    ) -> Result<Self, Self::Error> {
        let router_data = item.router_data;

        // The order is paid by the guest scanning the QR: there is no authorization to capture.
        if matches!(
            router_data.request.capture_method,
            Some(enums::CaptureMethod::Manual) | Some(enums::CaptureMethod::ManualMultiple)
        ) {
            return Err(errors::ConnectorError::NotImplemented(
                "manual capture for Mercado Pago QR".to_string(),
            )
            .into());
        }

        // Same resolution as Checkout Pro: request metadata first, frm_metadata as fallback.
        let meta_request =
            MercadopagoMetadata::resolve(router_data.request.metadata.as_ref(), &None, "metadata")?;
        let meta_frm =
            MercadopagoMetadata::resolve(None, &router_data.frm_metadata, "frm_metadata")?;
        let application_fee = meta_request.application_fee.or(meta_frm.application_fee);
        let qr_mode = meta_request.qr_mode.or(meta_frm.qr_mode);

        let external_pos_id = qr_external_pos_id(
            router_data
                .connector_meta_data
                .as_ref()
                .map(hyperswitch_masking::PeekInterface::peek),
        )?;

        Self::build(
            item.amount,
            router_data.request.currency,
            router_data.description.clone(),
            router_data.connector_request_reference_id.clone(),
            application_fee,
            external_pos_id,
            qr_mode.as_deref(),
        )
    }
}

// ============================================================================
// Order response (create, get, cancel and refund all return the order)
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MercadopagoOrderResponse {
    pub id: String,
    /// Kept as text: a status this connector does not know must map to Pending, not fail
    /// the parse.
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub status_detail: Option<String>,
    #[serde(default)]
    pub external_reference: Option<String>,
    #[serde(default)]
    pub currency: Option<String>,
    #[serde(default)]
    pub total_amount: Option<String>,
    #[serde(default)]
    pub transactions: Option<MercadopagoOrderTransactions>,
    #[serde(default)]
    pub type_response: Option<MercadopagoOrderTypeResponse>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MercadopagoOrderTransactions {
    #[serde(default)]
    pub payments: Vec<MercadopagoOrderPayment>,
    #[serde(default)]
    pub refunds: Vec<MercadopagoOrderRefund>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MercadopagoOrderPayment {
    pub id: String,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub status_detail: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MercadopagoOrderRefund {
    pub id: String,
    #[serde(default)]
    pub transaction_id: Option<String>,
    #[serde(default)]
    pub amount: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MercadopagoOrderTypeResponse {
    #[serde(default)]
    pub qr_data: Option<String>,
}

/// Maps an order status. `refunded` stays Charged, as the connector treats refunded
/// payments; `expired` is terminal and retryable like a rejected payment. `at_terminal`,
/// `action_required` (both Point) and any status not listed are Pending, never an error.
pub fn order_status_to_attempt_status(status: Option<&str>) -> enums::AttemptStatus {
    match status {
        Some("created") => enums::AttemptStatus::AuthenticationPending,
        Some("processed") | Some("refunded") => enums::AttemptStatus::Charged,
        Some("failed") | Some("expired") => enums::AttemptStatus::Failure,
        Some("canceled") => enums::AttemptStatus::Voided,
        _ => enums::AttemptStatus::Pending,
    }
}

/// `processed` is the only success; `failed` and `rejected` are final; anything else is
/// still in flight.
pub fn order_refund_status(status: Option<&str>) -> enums::RefundStatus {
    match status {
        Some("processed") => enums::RefundStatus::Success,
        Some("failed") | Some("rejected") => enums::RefundStatus::Failure,
        _ => enums::RefundStatus::Pending,
    }
}

fn normalize_amount(amount: &str) -> String {
    amount
        .trim()
        .parse::<f64>()
        .map(|value| format!("{value:.2}"))
        .unwrap_or_else(|_| amount.trim().to_string())
}

/// Minor units of a decimal string amount, `None` when it does not parse.
fn amount_to_minor_units(
    amount: &str,
    currency: enums::Currency,
) -> Option<common_utils::types::MinorUnit> {
    let value = amount.trim().parse::<f64>().ok()?;
    let factor = 10f64.powi(i32::from(currency.number_of_digits_after_decimal_point()));
    Some(common_utils::types::MinorUnit::new(
        (value * factor).round() as i64,
    ))
}

impl MercadopagoOrderResponse {
    pub fn attempt_status(&self) -> enums::AttemptStatus {
        order_status_to_attempt_status(self.status.as_deref())
    }

    fn refunds(&self) -> &[MercadopagoOrderRefund] {
        self.transactions
            .as_ref()
            .map(|transactions| transactions.refunds.as_slice())
            .unwrap_or_default()
    }

    /// The refund created by a refund request: the last entry whose amount matches it
    /// (a second refund of the same amount appends after the first one).
    pub fn refund_for_amount(&self, amount: &str) -> Option<&MercadopagoOrderRefund> {
        let wanted = normalize_amount(amount);
        self.refunds().iter().rev().find(|refund| {
            refund
                .amount
                .as_deref()
                .is_some_and(|candidate| normalize_amount(candidate) == wanted)
        })
    }

    /// What differs between this order and what the request asked to charge. A field Mercado
    /// Pago did not send is not a difference: the request already told it what to charge.
    pub(crate) fn charge_mismatch(
        &self,
        currency: enums::Currency,
        amount: &str,
    ) -> Option<String> {
        let wanted_currency = currency.to_string();
        if let Some(order_currency) = self
            .currency
            .as_deref()
            .filter(|order_currency| !order_currency.eq_ignore_ascii_case(&wanted_currency))
        {
            return Some(format!(
                "The order was created in {order_currency}, not {wanted_currency}"
            ));
        }
        self.total_amount
            .as_deref()
            .filter(|total| normalize_amount(total) != normalize_amount(amount))
            .map(|total| format!("The order was created for {total}, not {amount}"))
    }

    pub fn refund_by_id(&self, refund_id: &str) -> Option<&MercadopagoOrderRefund> {
        self.refunds().iter().find(|refund| refund.id == refund_id)
    }

    /// Error info for a failed order: the payment's own detail (e.g. `high_risk`) is more
    /// useful than the order's generic `failed`.
    fn failure_detail(&self) -> String {
        self.transactions
            .as_ref()
            .and_then(|transactions| transactions.payments.first())
            .and_then(|payment| payment.status_detail.clone())
            .filter(|detail| !detail.is_empty())
            .or_else(|| {
                self.status_detail
                    .clone()
                    .filter(|detail| !detail.is_empty())
            })
            .or_else(|| self.status.clone())
            .unwrap_or_else(|| "failed".to_string())
    }

    /// Refunds seen on the order, reported so the ones made outside Hyperswitch are recorded.
    /// Our own refunds carry the same `REF...` id as their `connector_refund_id`.
    pub(crate) fn reported_activity(
        &self,
        currency: enums::Currency,
    ) -> Option<ConnectorReportedActivity> {
        let refunds: Vec<ConnectorReportedRefund> = self
            .refunds()
            .iter()
            .filter_map(|refund| {
                Some(ConnectorReportedRefund {
                    amount_is_remaining_balance: false,
                    amount_is_cumulative_total: false,
                    connector_refund_id: refund.id.clone(),
                    amount: amount_to_minor_units(refund.amount.as_deref()?, currency)?,
                    status: order_refund_status(refund.status.as_deref()),
                })
            })
            .collect();
        (!refunds.is_empty()).then_some(ConnectorReportedActivity {
            refunds,
            dispute: None,
        })
    }
}

/// The attempt's `connector_metadata` for a new QR: a serialized `QrCodeInformation` (what
/// core turns into the `qr_code` next action) plus the Mercado Pago payment id.
fn build_qr_connector_metadata(
    qr_data: &str,
    mp_payment_id: Option<&str>,
    display_to_timestamp_ms: i64,
) -> Result<serde_json::Value, error_stack::Report<errors::ConnectorError>> {
    let image = QrImage::new_from_data(qr_data.to_string())
        .change_context(errors::ConnectorError::ResponseHandlingFailed)?;
    let image_data_url = url::Url::parse(&image.data)
        .change_context(errors::ConnectorError::ResponseHandlingFailed)?;

    let qr_info = api_models::payments::QrCodeInformation::QrCodeUrl {
        image_data_url,
        qr_code_url: None,
        display_to_timestamp: Some(display_to_timestamp_ms),
        expiry_type: None,
        raw_qr_data: Some(qr_data.to_string()),
    };
    let mut metadata = serde_json::to_value(qr_info)
        .change_context(errors::ConnectorError::ResponseHandlingFailed)?;
    if let (Some(object), Some(payment_id)) = (metadata.as_object_mut(), mp_payment_id) {
        object.insert(
            MP_PAYMENT_ID_KEY.to_string(),
            serde_json::Value::String(payment_id.to_string()),
        );
    }
    Ok(metadata)
}

/// The Mercado Pago payment id stored on the attempt by [`build_qr_connector_metadata`].
fn stored_mp_payment_id(
    connector_metadata: Option<&serde_json::Value>,
) -> Result<String, error_stack::Report<errors::ConnectorError>> {
    connector_metadata
        .and_then(|metadata| metadata.get(MP_PAYMENT_ID_KEY))
        .and_then(|id| id.as_str())
        .filter(|id| !id.is_empty())
        .map(str::to_string)
        .ok_or_else(|| {
            errors::ConnectorError::MissingRequiredField {
                field_name: "connector_metadata.mp_payment_id".into(),
            }
            .into()
        })
}

fn order_failure(
    order: &MercadopagoOrderResponse,
    http_code: u16,
    code: String,
    message: String,
) -> ErrorResponse {
    ErrorResponse {
        code: code.clone(),
        message: message.clone(),
        reason: Some(message.clone()),
        status_code: http_code,
        attempt_status: Some(enums::AttemptStatus::Failure),
        connector_transaction_id: Some(order.id.clone()),
        connector_metadata: None,
        network_advice_code: None,
        network_decline_code: Some(code),
        network_error_message: Some(message),
        connector_response_reference_id: None,
    }
}

fn order_payments_response<F, T>(
    order: &MercadopagoOrderResponse,
    data: RouterData<F, T, PaymentsResponseData>,
    http_code: u16,
    connector_metadata: Option<serde_json::Value>,
) -> RouterData<F, T, PaymentsResponseData> {
    let status = order.attempt_status();
    let response = if status == enums::AttemptStatus::Failure {
        let code = order.failure_detail();
        let message = get_mercadopago_error_message(&code);
        Err(order_failure(order, http_code, code, message))
    } else {
        Ok(PaymentsResponseData::TransactionResponse {
            resource_id: ResponseId::ConnectorTransactionId(order.id.clone()),
            redirection_data: Box::new(None),
            mandate_reference: Box::new(None),
            connector_metadata,
            network_txn_id: None,
            connector_response_reference_id: order
                .external_reference
                .clone()
                .or_else(|| Some(order.id.clone())),
            incremental_authorization_allowed: None,
            charges: None,
            network_txn_link_id: None,
            payment_account_reference: None,
            authentication_data: None,
        })
    };
    RouterData {
        status,
        response,
        ..data
    }
}

/// Authorize: the order was just created, so its QR is stored as the attempt's next action.
/// An order that does not match the request fails without storing the QR: nobody can scan it,
/// and it expires on its own at Mercado Pago.
pub(crate) fn authorize_order_response<F, T>(
    item: ResponseRouterData<F, MercadopagoOrderResponse, T, PaymentsResponseData>,
    requested_currency: enums::Currency,
    requested_amount: FloatMajorUnit,
) -> Result<RouterData<F, T, PaymentsResponseData>, error_stack::Report<errors::ConnectorError>> {
    let order = &item.response;
    if let Some(mismatch) =
        order.charge_mismatch(requested_currency, &format_amount(requested_amount))
    {
        let response = Err(order_failure(
            order,
            item.http_code,
            "order_mismatch".to_string(),
            mismatch,
        ));
        return Ok(RouterData {
            status: enums::AttemptStatus::Failure,
            response,
            ..item.data
        });
    }
    let connector_metadata = if order.attempt_status() == enums::AttemptStatus::Failure {
        None
    } else {
        let qr_data = order
            .type_response
            .as_ref()
            .and_then(|type_response| type_response.qr_data.as_deref())
            .ok_or(errors::ConnectorError::MissingRequiredField {
                field_name: "type_response.qr_data".into(),
            })?;
        let mp_payment_id = order
            .transactions
            .as_ref()
            .and_then(|transactions| transactions.payments.first())
            .map(|payment| payment.id.as_str());
        let expires_at = common_utils::date_time::now().assume_utc()
            + time::Duration::minutes(QR_ORDER_EXPIRATION_MINUTES);
        Some(build_qr_connector_metadata(
            qr_data,
            mp_payment_id,
            expires_at.unix_timestamp() * 1000,
        )?)
    };
    Ok(order_payments_response(
        order,
        item.data,
        item.http_code,
        connector_metadata,
    ))
}

/// Psync and void: the stored metadata (QR, payment id) is left untouched by returning none.
pub(crate) fn sync_order_response<F, T>(
    item: ResponseRouterData<F, MercadopagoOrderResponse, T, PaymentsResponseData>,
) -> RouterData<F, T, PaymentsResponseData> {
    order_payments_response(&item.response, item.data, item.http_code, None)
}

// ============================================================================
// Refund - POST /v1/orders/{id}/refund
// ============================================================================

#[derive(Debug, Serialize)]
pub struct MercadopagoOrderRefundRequest {
    pub transactions: Vec<MercadopagoOrderRefundTransaction>,
}

#[derive(Debug, Serialize)]
pub struct MercadopagoOrderRefundTransaction {
    pub id: String,
    pub amount: String,
}

impl<F> TryFrom<&MercadopagoRouterData<&RefundsRouterData<F>>> for MercadopagoOrderRefundRequest {
    type Error = error_stack::Report<errors::ConnectorError>;

    /// The amount is always explicit, including for a full refund.
    fn try_from(item: &MercadopagoRouterData<&RefundsRouterData<F>>) -> Result<Self, Self::Error> {
        Ok(Self {
            transactions: vec![MercadopagoOrderRefundTransaction {
                id: stored_mp_payment_id(item.router_data.request.connector_metadata.as_ref())?,
                amount: format_amount(item.amount),
            }],
        })
    }
}

impl
    TryFrom<
        RefundsResponseRouterData<
            hyperswitch_domain_models::router_flow_types::refunds::Execute,
            MercadopagoOrderResponse,
        >,
    > for RefundsRouterData<hyperswitch_domain_models::router_flow_types::refunds::Execute>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: RefundsResponseRouterData<
            hyperswitch_domain_models::router_flow_types::refunds::Execute,
            MercadopagoOrderResponse,
        >,
    ) -> Result<Self, Self::Error> {
        let requested = utils::convert_amount(
            &FloatMajorUnitForConnector,
            item.data.request.minor_refund_amount,
            item.data.request.currency,
        )?;
        let refund = item
            .response
            .refund_for_amount(&format_amount(requested))
            .ok_or(errors::ConnectorError::ResponseHandlingFailed)?;
        Ok(Self {
            response: Ok(RefundsResponseData {
                connector_refund_id: refund.id.clone(),
                refund_status: order_refund_status(refund.status.as_deref()),
            }),
            ..item.data
        })
    }
}

impl
    TryFrom<
        RefundsResponseRouterData<
            hyperswitch_domain_models::router_flow_types::refunds::RSync,
            MercadopagoOrderResponse,
        >,
    > for RefundsRouterData<hyperswitch_domain_models::router_flow_types::refunds::RSync>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: RefundsResponseRouterData<
            hyperswitch_domain_models::router_flow_types::refunds::RSync,
            MercadopagoOrderResponse,
        >,
    ) -> Result<Self, Self::Error> {
        let refund_id = utils::RefundsRequestData::get_connector_refund_id(&item.data.request)?;
        // A refund the order does not list (yet) stays pending instead of failing.
        let refund_status = item
            .response
            .refund_by_id(&refund_id)
            .map(|refund| order_refund_status(refund.status.as_deref()))
            .unwrap_or(enums::RefundStatus::Pending);
        Ok(Self {
            response: Ok(RefundsResponseData {
                connector_refund_id: refund_id,
                refund_status,
            }),
            ..item.data
        })
    }
}

#[cfg(test)]
mod tests {
    use common_utils::types::{AmountConvertor, MinorUnit};

    use super::*;
    use crate::connectors::mercadopago::transformers::MercadopagoMetadata;

    fn amount(minor: i64) -> FloatMajorUnit {
        FloatMajorUnitForConnector
            .convert(MinorUnit::new(minor), enums::Currency::ARS)
            .expect("amount converts")
    }

    fn pos_metadata() -> serde_json::Value {
        serde_json::json!({
            "other_key": 1,
            "qr_pos": {
                "store_id": "1001",
                "external_store_id": "PXSOLSTORE",
                "pos_id": "2002",
                "external_pos_id": "PXSOLPOS1"
            }
        })
    }

    fn build_request(
        fee: Option<f64>,
        total_minor: i64,
    ) -> Result<MercadopagoQrOrderRequest, error_stack::Report<errors::ConnectorError>> {
        MercadopagoQrOrderRequest::build(
            amount(total_minor),
            enums::Currency::ARS,
            Some("Reservation 42".to_string()),
            "pay_ref_1".to_string(),
            fee,
            qr_external_pos_id(Some(&pos_metadata()))?,
            None,
        )
    }

    fn build_with(
        description: Option<&str>,
        qr_mode: Option<&str>,
    ) -> Result<serde_json::Value, error_stack::Report<errors::ConnectorError>> {
        MercadopagoQrOrderRequest::build(
            amount(10_000),
            enums::Currency::ARS,
            description.map(str::to_string),
            "pay_ref_1".to_string(),
            None,
            "PXSOLPOS1".to_string(),
            qr_mode,
        )
        .map(|request| serde_json::to_value(request).expect("serializes"))
    }

    const QR_RESPONSE: &str = r#"{
        "id": "ORDTST00000000000000000000000AAA",
        "type": "qr",
        "external_reference": "pay_ref_1",
        "total_amount": "100.00",
        "status": "created",
        "status_detail": "created",
        "currency": "ARS",
        "transactions": {"payments": [
            {"id": "PAY00000000000000000000000001", "amount": "100.00",
             "status": "created", "status_detail": "ready_to_process"}
        ]},
        "type_response": {"qr_data": "00020101021243650016com.mercadolibre0201306363044D91"}
    }"#;

    const REFUNDED_RESPONSE: &str = r#"{
        "id": "ORDTST00000000000000000000000AAA",
        "status": "processed",
        "status_detail": "partially_refunded",
        "transactions": {
            "payments": [{"id": "PAY00000000000000000000000001", "status": "processed"}],
            "refunds": [
                {"id": "REF00000000000000000000000001", "transaction_id": "PAY00000000000000000000000001",
                 "reference_id": "3463380491", "amount": "30.00", "status": "processed"},
                {"id": "REF00000000000000000000000002", "transaction_id": "PAY00000000000000000000000001",
                 "reference_id": "3463380492", "amount": "30.00", "status": "processed"},
                {"id": "REF00000000000000000000000003", "transaction_id": "PAY00000000000000000000000001",
                 "amount": "10.00", "status": "failed"}
            ]
        }
    }"#;

    fn order(json: &str) -> MercadopagoOrderResponse {
        serde_json::from_str(json).expect("order parses")
    }

    #[test]
    fn order_id_helper_only_matches_orders() {
        assert!(is_order_id("ORDTST01M6KM7DZ95HJT4M08GSGQEK2Y"));
        assert!(is_order_id("ORD01M6KM7DZ95HJT4M08GSGQEK2Y"));
        assert!(!is_order_id("150211668619"));
        assert!(!is_order_id(""));
        assert!(!is_order_id("PAY01M6KM7DZ95HJT4M08GSGQEK2Y"));
    }

    #[test]
    fn numeric_ids_keep_the_payments_paths_and_order_ids_take_orders() {
        assert_eq!(psync_path("150211668619"), "/v1/payments/150211668619");
        assert_eq!(void_path("150211668619"), "/v1/payments/150211668619");
        assert_eq!(
            refund_path("150211668619"),
            "/v1/payments/150211668619/refunds"
        );
        assert_eq!(
            refund_sync_path("150211668619", "99"),
            "/v1/payments/150211668619/refunds/99"
        );

        assert_eq!(psync_path("ORDTST1"), "/v1/orders/ORDTST1");
        assert_eq!(void_path("ORDTST1"), "/v1/orders/ORDTST1/cancel");
        assert_eq!(refund_path("ORDTST1"), "/v1/orders/ORDTST1/refund");
        assert_eq!(refund_sync_path("ORDTST1", "REF1"), "/v1/orders/ORDTST1");
    }

    #[test]
    fn authorize_body_with_fee() {
        let body = serde_json::to_value(build_request(Some(0.7), 10_000).unwrap()).unwrap();
        assert_eq!(
            body,
            serde_json::json!({
                "type": "qr",
                "total_amount": "100.00",
                "currency": "ARS",
                "description": "Reservation 42",
                "items": [{
                    "title": "Reservation 42",
                    "unit_price": "100.00",
                    "quantity": 1,
                    "unit_measure": "unit"
                }],
                "external_reference": "pay_ref_1",
                "expiration_time": "PT30M",
                "marketplace_fee": "0.70",
                "integration_data": {"platform_id": super::super::PXSOL_PLATFORM_ID},
                "config": {"qr": {"external_pos_id": "PXSOLPOS1", "mode": "dynamic"}},
                "transactions": {"payments": [{"amount": "100.00"}]}
            })
        );
    }

    #[test]
    fn items_follow_the_description_and_are_truncated_with_it() {
        let body = build_with(Some("Reserva #48213 - Hotel"), None).unwrap();
        assert_eq!(body["items"][0]["title"], "Reserva #48213 - Hotel");
        assert_eq!(body["items"][0]["unit_price"], "100.00");
        assert_eq!(body["items"][0]["quantity"], 1);
        assert_eq!(body["items"][0]["unit_measure"], "unit");

        let long = "ñ".repeat(200);
        let body = build_with(Some(&long), None).unwrap();
        assert_eq!(body["description"].as_str().unwrap().chars().count(), 150);
        assert_eq!(body["items"][0]["title"], body["description"]);

        for none in [None, Some("")] {
            let body = build_with(none, None).unwrap();
            assert!(body.get("items").is_none());
            assert!(body.get("description").is_none());
        }
    }

    #[test]
    fn qr_mode_defaults_to_dynamic_accepts_hybrid_and_rejects_the_rest() {
        let mode = |value| build_with(None, value).map(|body| body["config"]["qr"]["mode"].clone());
        assert_eq!(mode(None).unwrap(), "dynamic");
        assert_eq!(mode(Some("dynamic")).unwrap(), "dynamic");
        assert_eq!(mode(Some("hybrid")).unwrap(), "hybrid");
        for other in ["static", "Hybrid", ""] {
            assert!(matches!(
                mode(Some(other)).unwrap_err().current_context(),
                errors::ConnectorError::InvalidDataFormat { .. }
            ));
        }
    }

    #[test]
    fn qr_mode_is_resolved_like_the_fee() {
        let request = serde_json::json!({"mercadopago": {"qr_mode": "hybrid"}});
        let frm = Some(hyperswitch_masking::Secret::new(
            serde_json::json!({"qr_mode": "dynamic"}),
        ));
        let from_request = MercadopagoMetadata::resolve(Some(&request), &None, "metadata").unwrap();
        let from_frm = MercadopagoMetadata::resolve(None, &frm, "frm_metadata").unwrap();
        assert_eq!(
            from_request.qr_mode.or(from_frm.qr_mode.clone()).as_deref(),
            Some("hybrid")
        );
        assert_eq!(from_frm.qr_mode.as_deref(), Some("dynamic"));
    }

    #[test]
    fn an_order_that_differs_from_the_request_is_a_mismatch() {
        let order: MercadopagoOrderResponse =
            serde_json::from_str(QR_RESPONSE).expect("the sample parses");
        assert_eq!(order.charge_mismatch(enums::Currency::ARS, "100.00"), None);
        assert_eq!(order.charge_mismatch(enums::Currency::ARS, "100"), None);
        let wrong_currency = order
            .charge_mismatch(enums::Currency::USD, "100.00")
            .expect("USD differs from the order's ARS");
        assert!(wrong_currency.contains("ARS") && wrong_currency.contains("USD"));
        assert!(order
            .charge_mismatch(enums::Currency::ARS, "150.00")
            .is_some());

        // Without those fields the request is what Mercado Pago validated.
        let bare: MercadopagoOrderResponse =
            serde_json::from_str(r#"{"id":"ORD1","status":"created"}"#).expect("a bare order");
        assert_eq!(bare.charge_mismatch(enums::Currency::USD, "150.00"), None);
    }

    #[test]
    fn mercado_pago_refusing_the_currency_keeps_its_code_and_detail() {
        // Real answer of POST /v1/orders with USD for an ARS seller.
        let error: crate::connectors::mercadopago::transformers::MercadopagoErrorResponse =
            serde_json::from_str(
                r#"{"errors":[{"code":"property_value","message":"Invalid value for property",
                    "details":["The seller is not authorized to use this currency"]}]}"#,
            )
            .expect("the Orders error shape parses");
        assert_eq!(error.get_error_code(), "property_value");
        assert_eq!(
            error.get_detailed_reason().as_deref(),
            Some("The seller is not authorized to use this currency")
        );
    }

    #[test]
    fn authorize_body_sends_the_currency_and_omits_a_missing_fee() {
        for fee in [None, Some(0.0)] {
            let body = serde_json::to_value(build_request(fee, 10_050).unwrap()).unwrap();
            assert!(body.get("marketplace_fee").is_none());
            assert_eq!(body["currency"], "ARS");
            assert_eq!(body["total_amount"], "100.50");
            assert_eq!(body["transactions"]["payments"][0]["amount"], "100.50");
        }
    }

    #[test]
    fn fee_above_the_cap_is_rejected_and_the_cap_itself_passes() {
        // 0.7% of 100.00 is 0.70.
        assert!(build_request(Some(0.71), 10_000).is_err());
        assert!(build_request(Some(1.0), 10_000).is_err());
        assert!(build_request(Some(0.7), 10_000).is_ok());
    }

    #[test]
    fn fee_is_resolved_from_metadata_with_frm_fallback() {
        let request = serde_json::json!({"application_fee": 0.5});
        let frm = Some(hyperswitch_masking::Secret::new(
            serde_json::json!({"mercadopago": {"application_fee": 0.6}}),
        ));
        let from_request = MercadopagoMetadata::resolve(Some(&request), &None, "metadata").unwrap();
        let from_frm = MercadopagoMetadata::resolve(None, &frm, "frm_metadata").unwrap();
        assert_eq!(
            from_request.application_fee.or(from_frm.application_fee),
            Some(0.5)
        );
        assert_eq!(from_frm.application_fee, Some(0.6));
    }

    #[test]
    fn missing_pos_is_a_clear_error() {
        for metadata in [
            None,
            Some(serde_json::json!({})),
            Some(serde_json::json!({"qr_pos": {}})),
            Some(serde_json::json!({"qr_pos": {"external_pos_id": ""}})),
            Some(serde_json::json!({"qr_pos": {"external_pos_id": 7}})),
        ] {
            let err = qr_external_pos_id(metadata.as_ref()).unwrap_err();
            assert!(matches!(
                err.current_context(),
                errors::ConnectorError::MissingRequiredField { field_name }
                    if field_name.contains("external_pos_id")
            ));
        }
    }

    #[test]
    fn pos_metadata_round_trips() {
        let pos = MercadopagoQrPos {
            seller_id: "777".into(),
            store_id: "1001".into(),
            external_store_id: "PXSOLSTORE".into(),
            pos_id: "2002".into(),
            external_pos_id: "PXSOLPOS1".into(),
            qr_image: Some("https://mp.test/qr.png".into()),
            qr_template_document: None,
            qr_template_image: None,
        };
        let metadata = serde_json::json!({ QR_POS_METADATA_KEY: pos });
        assert_eq!(qr_external_pos_id(Some(&metadata)).unwrap(), "PXSOLPOS1");
        assert_eq!(
            serde_json::from_value::<MercadopagoQrPos>(metadata[QR_POS_METADATA_KEY].clone())
                .unwrap(),
            pos
        );
    }

    #[test]
    fn status_mapping_table() {
        use enums::AttemptStatus as A;
        for (status, expected) in [
            (Some("created"), A::AuthenticationPending),
            (Some("processed"), A::Charged),
            (Some("refunded"), A::Charged),
            (Some("failed"), A::Failure),
            (Some("expired"), A::Failure),
            (Some("canceled"), A::Voided),
            (Some("at_terminal"), A::Pending),
            (Some("action_required"), A::Pending),
            (Some("something_new"), A::Pending),
            (None, A::Pending),
        ] {
            assert_eq!(
                order_status_to_attempt_status(status),
                expected,
                "{status:?}"
            );
        }
    }

    #[test]
    fn refund_status_mapping() {
        use enums::RefundStatus as R;
        assert_eq!(order_refund_status(Some("processed")), R::Success);
        assert_eq!(order_refund_status(Some("failed")), R::Failure);
        assert_eq!(order_refund_status(Some("rejected")), R::Failure);
        assert_eq!(order_refund_status(Some("in_process")), R::Pending);
        assert_eq!(order_refund_status(None), R::Pending);
    }

    #[test]
    fn qr_metadata_round_trips_through_qr_code_information() {
        let created = order(QR_RESPONSE);
        let qr_data = created
            .type_response
            .as_ref()
            .and_then(|t| t.qr_data.as_deref())
            .unwrap();
        let stored = build_qr_connector_metadata(
            qr_data,
            Some("PAY00000000000000000000000001"),
            1_700_000_000_000,
        )
        .unwrap();

        // Core parses the stored value as `QrCodeInformation`; the extra key must not break it.
        let parsed: api_models::payments::QrCodeInformation =
            serde_json::from_value(stored.clone()).unwrap();
        match parsed {
            api_models::payments::QrCodeInformation::QrCodeUrl {
                image_data_url,
                display_to_timestamp,
                raw_qr_data,
                ..
            } => {
                assert_eq!(image_data_url.scheme(), "data");
                assert_eq!(display_to_timestamp, Some(1_700_000_000_000));
                assert_eq!(raw_qr_data.as_deref(), Some(qr_data));
            }
            other => panic!("unexpected QrCodeInformation variant: {other:?}"),
        }
        assert_eq!(
            stored_mp_payment_id(Some(&stored)).unwrap(),
            "PAY00000000000000000000000001"
        );
        assert!(stored_mp_payment_id(None).is_err());
        assert!(stored_mp_payment_id(Some(&serde_json::json!({"image_data_url": "x"}))).is_err());
    }

    #[test]
    fn refund_body_is_explicit_with_the_stored_payment_id() {
        let stored = serde_json::json!({ MP_PAYMENT_ID_KEY: "PAY00000000000000000000000001" });
        let body = serde_json::to_value(MercadopagoOrderRefundRequest {
            transactions: vec![MercadopagoOrderRefundTransaction {
                id: stored_mp_payment_id(Some(&stored)).unwrap(),
                amount: format_amount(amount(3_000)),
            }],
        })
        .unwrap();
        assert_eq!(
            body,
            serde_json::json!({"transactions": [
                {"id": "PAY00000000000000000000000001", "amount": "30.00"}
            ]})
        );
    }

    #[test]
    fn refund_id_is_the_last_matching_amount() {
        let refunded = order(REFUNDED_RESPONSE);
        assert_eq!(
            refunded.refund_for_amount("30.00").unwrap().id,
            "REF00000000000000000000000002"
        );
        assert_eq!(
            refunded.refund_for_amount("30").unwrap().id,
            "REF00000000000000000000000002"
        );
        assert_eq!(
            refunded.refund_for_amount("10.00").unwrap().id,
            "REF00000000000000000000000003"
        );
        assert!(refunded.refund_for_amount("99.00").is_none());
    }

    #[test]
    fn refund_sync_finds_the_refund_by_id() {
        let refunded = order(REFUNDED_RESPONSE);
        let status = |id: &str| {
            refunded
                .refund_by_id(id)
                .map(|refund| order_refund_status(refund.status.as_deref()))
        };
        assert_eq!(
            status("REF00000000000000000000000001"),
            Some(enums::RefundStatus::Success)
        );
        assert_eq!(
            status("REF00000000000000000000000003"),
            Some(enums::RefundStatus::Failure)
        );
        assert_eq!(status("REF_unknown"), None);
    }

    #[test]
    fn fully_refunded_order_stays_charged_and_parses_without_optional_fields() {
        let refunded = order(
            r#"{"id":"ORD1","status":"refunded","status_detail":"refunded",
                "transactions":{"refunds":[{"id":"REF1","amount":"60.00","status":"processed"}]}}"#,
        );
        assert_eq!(refunded.attempt_status(), enums::AttemptStatus::Charged);
        assert!(order(r#"{"id":"ORD2"}"#).refund_by_id("REF1").is_none());
        assert_eq!(
            order(r#"{"id":"ORD2"}"#).attempt_status(),
            enums::AttemptStatus::Pending
        );
    }

    #[test]
    fn failure_detail_prefers_the_payment_detail() {
        let failed = order(
            r#"{"id":"ORD3","status":"failed","status_detail":"failed",
                "transactions":{"payments":[{"id":"PAY3","status":"failed","status_detail":"high_risk"}]}}"#,
        );
        assert_eq!(failed.failure_detail(), "high_risk");
        let expired = order(r#"{"id":"ORD4","status":"expired","status_detail":"expired"}"#);
        assert_eq!(expired.failure_detail(), "expired");
    }

    #[test]
    fn reported_activity_lists_order_refunds_in_minor_units() {
        let activity = order(REFUNDED_RESPONSE)
            .reported_activity(enums::Currency::ARS)
            .expect("refunds are reported");
        assert_eq!(activity.refunds.len(), 3);
        assert_eq!(
            activity.refunds[0].connector_refund_id,
            "REF00000000000000000000000001"
        );
        assert_eq!(activity.refunds[0].amount, MinorUnit::new(3_000));
        assert_eq!(activity.refunds[2].status, enums::RefundStatus::Failure);
        assert!(order(QR_RESPONSE)
            .reported_activity(enums::Currency::ARS)
            .is_none());
    }
}
