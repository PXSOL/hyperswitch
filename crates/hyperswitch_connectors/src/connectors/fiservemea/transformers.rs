use std::collections::HashMap;

use common_enums::enums;
use common_utils::{
    request::Method,
    types::{FloatMajorUnit, StringMajorUnit},
};
use hyperswitch_domain_models::{
    payment_method_data::PaymentMethodData,
    router_data::{ConnectorAuthType, RouterData},
    router_flow_types::refunds::{Execute, RSync},
    router_request_types::{CompleteAuthorizeRedirectResponse, ResponseId},
    router_response_types::{PaymentsResponseData, RedirectForm, RefundsResponseData},
    types::{
        PaymentsAuthorizeRouterData, PaymentsCancelRouterData, PaymentsCaptureRouterData,
        PaymentsCompleteAuthorizeRouterData, RefundsRouterData,
    },
};
use hyperswitch_interfaces::errors;
use masking::{PeekInterface, Secret};
use serde::{Deserialize, Serialize};

use crate::{
    types::{RefundsResponseRouterData, ResponseRouterData},
    utils::{CardData as _, RouterData as _},
};

//TODO: Fill the struct with respective fields
pub struct FiservemeaRouterData<T> {
    pub amount: StringMajorUnit, // The type of amount that a connector accepts, for example, String, i64, f64, etc.
    pub router_data: T,
}

impl<T> From<(StringMajorUnit, T)> for FiservemeaRouterData<T> {
    fn from((amount, item): (StringMajorUnit, T)) -> Self {
        //Todo :  use utils to convert the amount to the type of amount that a connector accepts
        Self {
            amount,
            router_data: item,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct FiservemeaTransactionAmount {
    total: StringMajorUnit,
    currency: common_enums::Currency,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaOrder {
    order_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    installment_options: Option<FiservemeaInstallmentOptions>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    additional_details: Option<FiservemeaAdditionalDetails>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum FiservemeaLegalFramework {
    #[serde(rename = "NO_TAX_REFUND")]
    NoTaxRefund,
    #[serde(rename = "URY_RETURNS_IVA_LAW_17934")]
    UryReturnsIvaLaw17934,
    #[serde(rename = "URY_RETURNS_IMESI_LAW_18083")]
    UryReturnsImesiLaw18083,
    #[serde(rename = "URY_RETURNS_AFAM_LAW_18910")]
    UryReturnsAfamLaw18910,
    #[serde(rename = "URY_TAX_REFUND_LAW_18999")]
    UryTaxRefundLaw18999,
    #[serde(rename = "URY_RETURNS_IVA_LAW_19210")]
    UryReturnsIvaLaw19210,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct FiservemeaMetadataObject {
    #[serde(alias = "number_of_installments")]
    pub installments: Option<i32>,
    pub installment_interest: Option<bool>,
    #[serde(alias = "legal_framework")]
    pub tax_refund_legal_framework: Option<FiservemeaLegalFramework>,
}

impl FiservemeaMetadataObject {
    /// Reads from `request.metadata` and, for each missing field, falls back to
    /// `request.frm_metadata`. Both sources are intentionally supported (see spec §3.1).
    /// Tolerant of invalid/absent JSON.
    fn from_sources(
        metadata: Option<&serde_json::Value>,
        frm_metadata: Option<&serde_json::Value>,
    ) -> Self {
        let primary = metadata
            .and_then(|v| serde_json::from_value::<Self>(v.clone()).ok())
            .unwrap_or_default();
        let fallback = frm_metadata
            .and_then(|v| serde_json::from_value::<Self>(v.clone()).ok())
            .unwrap_or_default();
        Self {
            installments: primary.installments.or(fallback.installments),
            installment_interest: primary
                .installment_interest
                .or(fallback.installment_interest),
            tax_refund_legal_framework: primary
                .tax_refund_legal_framework
                .or(fallback.tax_refund_legal_framework),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaInstallmentOptions {
    number_of_installments: i32,
    #[serde(rename = "Interest", skip_serializing_if = "Option::is_none", default)]
    interest: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaTaxRefundRequestData {
    legal_framework: FiservemeaLegalFramework,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaAdditionalDetails {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    tax_refund_request_data: Option<FiservemeaTaxRefundRequestData>,
}

#[derive(Debug, Serialize)]
pub enum FiservemeaRequestType {
    PaymentCardSaleTransaction,
    PaymentCardPreAuthTransaction,
    PostAuthTransaction,
    VoidTransaction,
    VoidPreAuthTransactions,
    ReturnTransaction,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaExpiryDate {
    month: Secret<String>,
    year: Secret<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaPaymentCard {
    number: cards::CardNumber,
    expiry_date: FiservemeaExpiryDate,
    security_code: Secret<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum FiservemeaPaymentMethods {
    PaymentCard(FiservemeaPaymentCard),
}

/// 3DS native (Fiserv IPG "provider-owned" flow) authentication request object.
/// Only emitted when the payment is `is_three_ds()`; absent otherwise so the
/// NoThreeDs request stays byte-identical to the pre-3DS behavior. See vendor doc
/// §10.1.1 (lines 526-578) and design spec §3.4.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaAuthenticationRequest {
    authentication_type: String,
    #[serde(rename = "termURL")]
    term_url: String,
    #[serde(rename = "methodNotificationURL")]
    method_notification_url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    challenge_indicator: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    challenge_window_size: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaPaymentsRequest {
    request_type: FiservemeaRequestType,
    merchant_transaction_id: String,
    transaction_amount: FiservemeaTransactionAmount,
    order: FiservemeaOrder,
    payment_method: FiservemeaPaymentMethods,
    #[serde(skip_serializing_if = "Option::is_none")]
    authentication_request: Option<FiservemeaAuthenticationRequest>,
}

/// Whether `capture_method` signals auto-capture (`Automatic`/`SequentialAutomatic`), i.e. the
/// transaction should be treated as a sale/postauth rather than a pre-auth. Shared by the
/// Authorize request-type selection and `select_void_request_type` below, which both need the
/// same auto-capture-vs-manual distinction.
fn is_auto_capture(capture_method: Option<enums::CaptureMethod>) -> bool {
    matches!(
        capture_method,
        Some(enums::CaptureMethod::Automatic) | Some(enums::CaptureMethod::SequentialAutomatic)
    )
}

impl TryFrom<&FiservemeaRouterData<&PaymentsAuthorizeRouterData>> for FiservemeaPaymentsRequest {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: &FiservemeaRouterData<&PaymentsAuthorizeRouterData>,
    ) -> Result<Self, Self::Error> {
        match item.router_data.request.payment_method_data.clone() {
            PaymentMethodData::Card(req_card) => {
                let card = FiservemeaPaymentCard {
                    number: req_card.card_number.clone(),
                    expiry_date: FiservemeaExpiryDate {
                        month: req_card.card_exp_month.clone(),
                        year: req_card.get_card_expiry_year_2_digit()?,
                    },
                    security_code: req_card.card_cvc,
                };
                let request_type = if is_auto_capture(item.router_data.request.capture_method) {
                    FiservemeaRequestType::PaymentCardSaleTransaction
                } else {
                    FiservemeaRequestType::PaymentCardPreAuthTransaction
                };

                let fiservemea_meta = FiservemeaMetadataObject::from_sources(
                    item.router_data.request.metadata.as_ref(),
                    item.router_data
                        .frm_metadata
                        .as_ref()
                        .map(|secret| secret.peek()),
                );
                let installment_options = fiservemea_meta.installments.and_then(|n| {
                    (n > 1).then_some(FiservemeaInstallmentOptions {
                        number_of_installments: n,
                        interest: fiservemea_meta.installment_interest,
                    })
                });
                let additional_details =
                    fiservemea_meta
                        .tax_refund_legal_framework
                        .map(|legal_framework| FiservemeaAdditionalDetails {
                            tax_refund_request_data: Some(FiservemeaTaxRefundRequestData {
                                legal_framework,
                            }),
                        });

                // 3DS is optional: only attach `authenticationRequest` when the payment
                // requests ThreeDs. The NoThreeDs branch leaves this `None`, keeping the
                // serialized request byte-identical to the pre-3DS behavior (spec §3.4).
                let authentication_request = if item.router_data.is_three_ds() {
                    let return_url = item
                        .router_data
                        .request
                        .complete_authorize_url
                        .clone()
                        .ok_or(errors::ConnectorError::MissingRequiredField {
                            field_name: "complete_authorize_url",
                        })?;
                    Some(FiservemeaAuthenticationRequest {
                        authentication_type: "Secure3D21AuthenticationRequest".to_string(),
                        term_url: return_url.clone(),
                        method_notification_url: return_url,
                        challenge_indicator: Some("01".to_string()),
                        challenge_window_size: Some("01".to_string()),
                    })
                } else {
                    None
                };

                Ok(Self {
                    request_type,
                    merchant_transaction_id: item
                        .router_data
                        .request
                        .merchant_order_reference_id
                        .clone()
                        .unwrap_or(item.router_data.connector_request_reference_id.clone()),
                    transaction_amount: FiservemeaTransactionAmount {
                        total: item.amount.clone(),
                        currency: item.router_data.request.currency,
                    },
                    order: FiservemeaOrder {
                        order_id: item.router_data.connector_request_reference_id.clone(),
                        installment_options,
                        additional_details,
                    },
                    payment_method: FiservemeaPaymentMethods::PaymentCard(card),
                    authentication_request,
                })
            }
            _ => Err(errors::ConnectorError::NotImplemented(
                "Selected payment method through fiservemea".to_string(),
            )
            .into()),
        }
    }
}

/// ACS challenge result wrapper for the final 3DS continuation PATCH (vendor doc §10.1.5.d,
/// lines 758-783). `cRes` is the Base64 challenge-result message the issuer ACS posts back to
/// the `termURL` when the cardholder completes the challenge.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaAcsResponse {
    #[serde(rename = "cRes")]
    c_res: String,
}

/// 3DS native continuation request, sent as a PATCH on the original transaction. Two shapes
/// share this payload (vendor doc §10.1.4/§10.1.5):
/// - after the device-fingerprint (methodForm) step: `methodNotificationStatus` only.
/// - after the cardholder challenge: `acsResponse.cRes` only.
/// Both carry `authenticationType: "Secure3D21AuthenticationUpdateRequest"`.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaCompleteAuthorizeRequest {
    authentication_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    method_notification_status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    acs_response: Option<FiservemeaAcsResponse>,
}

/// Extracts the ACS challenge result (`cRes`) that the issuer ACS posts back to the `termURL`
/// when the challenge completes (vendor doc lines 758-783). Hyperswitch forwards the browser's
/// return data in `redirect_response`, which may be a JSON body (`payload`) or a query string
/// (`params`). The vendor labels the field `cRes`; browsers/intermediaries may lower-case it,
/// so both `cRes` and `cres` are accepted. Returns `None` after the device-fingerprint
/// (methodForm) step, which carries no challenge result.
fn extract_acs_cres(redirect_response: &CompleteAuthorizeRedirectResponse) -> Option<String> {
    // Prefer the JSON payload (the shape most ACS `termURL` posts use).
    if let Some(payload) = redirect_response.payload.as_ref() {
        let value = payload.peek();
        if let Some(c_res) = value
            .get("cRes")
            .or_else(|| value.get("cres"))
            .and_then(|v| v.as_str())
        {
            return Some(c_res.to_string());
        }
    }
    // Fall back to the query-string form (`cRes=...&...`).
    if let Some(params) = redirect_response.params.as_ref() {
        for pair in params.peek().split('&') {
            let mut kv = pair.splitn(2, '=');
            if let (Some(key), Some(val)) = (kv.next(), kv.next()) {
                if key.eq_ignore_ascii_case("cres") {
                    return Some(val.to_string());
                }
            }
        }
    }
    None
}

impl TryFrom<&PaymentsCompleteAuthorizeRouterData> for FiservemeaCompleteAuthorizeRequest {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(item: &PaymentsCompleteAuthorizeRouterData) -> Result<Self, Self::Error> {
        let redirect_response = item.request.redirect_response.as_ref().ok_or(
            errors::ConnectorError::MissingRequiredField {
                field_name: "redirect_response",
            },
        )?;

        // If the browser returned a challenge result (`cRes`), this is the final continuation
        // (§10.1.5.d). Otherwise the browser returned from the methodForm/device-fingerprint
        // step (§10.1.4.a); report `RECEIVED` since Hyperswitch only re-invokes
        // CompleteAuthorize after the browser has come back from `methodNotificationURL`.
        match extract_acs_cres(redirect_response) {
            Some(c_res) => Ok(Self {
                authentication_type: "Secure3D21AuthenticationUpdateRequest".to_string(),
                method_notification_status: None,
                acs_response: Some(FiservemeaAcsResponse { c_res }),
            }),
            None => Ok(Self {
                authentication_type: "Secure3D21AuthenticationUpdateRequest".to_string(),
                method_notification_status: Some("RECEIVED".to_string()),
                acs_response: None,
            }),
        }
    }
}

// Auth Struct
#[derive(Clone)]
pub struct FiservemeaAuthType {
    pub(super) api_key: Secret<String>,
    pub(super) secret_key: Secret<String>,
}

impl TryFrom<&ConnectorAuthType> for FiservemeaAuthType {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::BodyKey { api_key, key1 } => Ok(Self {
                api_key: api_key.to_owned(),
                secret_key: key1.to_owned(),
            }),
            _ => Err(errors::ConnectorError::FailedToObtainAuthType.into()),
        }
    }
}

// PaymentsResponse
#[derive(Debug, Serialize, Deserialize)]
pub enum ResponseType {
    BadRequest,
    Unauthenticated,
    Unauthorized,
    NotFound,
    GatewayDeclined,
    EndpointDeclined,
    ServerError,
    EndpointCommunicationError,
    UnsupportedMediaType,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FiservemeaTransactionType {
    Sale,
    Preauth,
    Credit,
    ForcedTicket,
    Void,
    Return,
    Postauth,
    PayerAuth,
    Disbursement,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum FiservemeaTransactionOrigin {
    Ecom,
    Moto,
    Mail,
    Phone,
    Retail,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FiservemeaPaymentStatus {
    Approved,
    Waiting,
    Partial,
    ValidationFailed,
    ProcessingFailed,
    Declined,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FiservemeaPaymentResult {
    Approved,
    Declined,
    Failed,
    Waiting,
    Partial,
    Fraud,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaPaymentCardResponse {
    expiry_date: Option<FiservemeaExpiryDate>,
    bin: Option<String>,
    last4: Option<String>,
    brand: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaPaymentMethodDetails {
    payment_card: Option<FiservemeaPaymentCardResponse>,
    payment_method_type: Option<String>,
    payment_method_brand: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Components {
    subtotal: Option<f64>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AmountDetails {
    // Typed as `FloatMajorUnit` (rather than a bare `f64`) so it can be fed directly into
    // `get_*_integrity_object` via a `FloatMajorUnitForConnector` amount converter without any
    // lossy/hacky string round-tripping (see `FiservemeaPaymentsResponse::settlement_amount`).
    total: Option<FloatMajorUnit>,
    currency: Option<common_enums::Currency>,
    components: Option<Components>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AvsResponse {
    street_match: Option<String>,
    postal_code_match: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Processor {
    reference_number: Option<String>,
    authorization_code: Option<String>,
    response_code: Option<String>,
    response_message: Option<String>,
    avs_response: Option<AvsResponse>,
    security_code_response: Option<String>,
}

fn map_status(
    fiservemea_status: Option<FiservemeaPaymentStatus>,
    fiservemea_result: Option<FiservemeaPaymentResult>,
    transaction_type: FiservemeaTransactionType,
) -> common_enums::AttemptStatus {
    match fiservemea_status {
        Some(status) => match status {
            FiservemeaPaymentStatus::Approved => match transaction_type {
                FiservemeaTransactionType::Preauth => common_enums::AttemptStatus::Authorized,
                FiservemeaTransactionType::Void => common_enums::AttemptStatus::Voided,
                FiservemeaTransactionType::Sale | FiservemeaTransactionType::Postauth => {
                    common_enums::AttemptStatus::Charged
                }
                FiservemeaTransactionType::Credit
                | FiservemeaTransactionType::ForcedTicket
                | FiservemeaTransactionType::Return
                | FiservemeaTransactionType::PayerAuth
                | FiservemeaTransactionType::Disbursement => common_enums::AttemptStatus::Failure,
            },
            FiservemeaPaymentStatus::Waiting => common_enums::AttemptStatus::Pending,
            FiservemeaPaymentStatus::Partial => common_enums::AttemptStatus::PartialCharged,
            FiservemeaPaymentStatus::ValidationFailed
            | FiservemeaPaymentStatus::ProcessingFailed
            | FiservemeaPaymentStatus::Declined => common_enums::AttemptStatus::Failure,
        },
        None => match fiservemea_result {
            Some(result) => match result {
                FiservemeaPaymentResult::Approved => match transaction_type {
                    FiservemeaTransactionType::Preauth => common_enums::AttemptStatus::Authorized,
                    FiservemeaTransactionType::Void => common_enums::AttemptStatus::Voided,
                    FiservemeaTransactionType::Sale | FiservemeaTransactionType::Postauth => {
                        common_enums::AttemptStatus::Charged
                    }
                    FiservemeaTransactionType::Credit
                    | FiservemeaTransactionType::ForcedTicket
                    | FiservemeaTransactionType::Return
                    | FiservemeaTransactionType::PayerAuth
                    | FiservemeaTransactionType::Disbursement => {
                        common_enums::AttemptStatus::Failure
                    }
                },
                FiservemeaPaymentResult::Waiting => common_enums::AttemptStatus::Pending,
                FiservemeaPaymentResult::Partial => common_enums::AttemptStatus::PartialCharged,
                FiservemeaPaymentResult::Declined
                | FiservemeaPaymentResult::Failed
                | FiservemeaPaymentResult::Fraud => common_enums::AttemptStatus::Failure,
            },
            None => common_enums::AttemptStatus::Pending,
        },
    }
}

/// 3DSMethod block returned on the initial Authorize response (vendor doc §10.1.2,
/// lines 599-617). `method_form` is a self-contained HTML snippet with a hidden
/// iframe that auto-submits browser data to the issuer ACS.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaSecure3dMethod {
    method_form: Option<String>,
    secure3d_trans_id: Option<String>,
}

/// ACS challenge params returned on the challenge continuation (vendor doc §10.1.5,
/// lines 709-740). `cReq`/`sessiondata` are posted to `acsURL`.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaAcsParams {
    #[serde(rename = "acsURL")]
    acs_url: Option<String>,
    #[serde(rename = "cReq")]
    c_req: Option<String>,
    #[serde(rename = "termURL")]
    term_url: Option<String>,
    sessiondata: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaAuthenticationResponse {
    #[serde(rename = "type")]
    auth_type: Option<String>,
    version: Option<String>,
    secure3d_method: Option<FiservemeaSecure3dMethod>,
    params: Option<FiservemeaAcsParams>,
}

impl FiservemeaAuthenticationResponse {
    /// Builds the redirect the browser must follow to progress 3DS, or `None` when the
    /// response carries no actionable 3DS data (e.g. an unenrolled cardholder that got an
    /// immediate APPROVED/DECLINED). Two shapes per the vendor doc:
    /// - `secure3dMethod.methodForm` (§10.1.2) => hidden-iframe HTML for device fingerprinting.
    /// - `params.acsURL` (§10.1.5) => self-posting form to the ACS challenge page. Field names
    ///   `creq`/`threeDSSessionData` are exactly what the ACS expects (vendor doc lines 742-753).
    fn to_redirection(&self) -> Option<RedirectForm> {
        if let Some(method_form) = self
            .secure3d_method
            .as_ref()
            .and_then(|method| method.method_form.clone())
        {
            return Some(RedirectForm::Html {
                html_data: method_form,
            });
        }

        let params = self.params.as_ref()?;
        let acs_url = params.acs_url.clone()?;
        let mut form_fields = HashMap::new();
        if let Some(c_req) = params.c_req.clone() {
            form_fields.insert("creq".to_string(), c_req);
        }
        if let Some(sessiondata) = params.sessiondata.clone() {
            form_fields.insert("threeDSSessionData".to_string(), sessiondata);
        }
        Some(RedirectForm::Form {
            endpoint: acs_url,
            method: Method::Post,
            form_fields,
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaPaymentsResponse {
    response_type: Option<ResponseType>,
    #[serde(rename = "type")]
    fiservemea_type: Option<String>,
    client_request_id: Option<String>,
    api_trace_id: Option<String>,
    ipg_transaction_id: String,
    order_id: Option<String>,
    transaction_type: FiservemeaTransactionType,
    transaction_origin: Option<FiservemeaTransactionOrigin>,
    payment_method_details: Option<FiservemeaPaymentMethodDetails>,
    country: Option<Secret<String>>,
    terminal_id: Option<String>,
    merchant_id: Option<String>,
    merchant_transaction_id: Option<String>,
    transaction_time: Option<i64>,
    approved_amount: Option<AmountDetails>,
    transaction_amount: Option<AmountDetails>,
    transaction_status: Option<FiservemeaPaymentStatus>, // FiservEMEA Docs mention that this field is deprecated. We are using it for now because transaction_result is not present in the response.
    transaction_result: Option<FiservemeaPaymentResult>,
    approval_code: Option<String>,
    error_message: Option<String>,
    transaction_state: Option<String>,
    scheme_transaction_id: Option<String>,
    processor: Option<Processor>,
    // Present only on 3DS Authorize/CompleteAuthorize responses; `None` for
    // capture/void/refund responses, which is what keeps those flows unaffected.
    authentication_response: Option<FiservemeaAuthenticationResponse>,
}

impl FiservemeaPaymentsResponse {
    /// Picks the settlement amount/currency used to build the amount integrity object for
    /// Authorize/Capture/PSync/Refund/RSync responses (see `fiservemea.rs::handle_response`).
    /// Prefers `approvedAmount` (the amount actually settled) and falls back to
    /// `transactionAmount` (the requested amount) when the former is absent, e.g. on
    /// non-approved outcomes. Returns `None` when neither amount block carries both a total and
    /// a currency, since a partial value can't be safely compared against the request amount;
    /// callers then skip setting `integrity_object` entirely rather than guessing a default.
    pub fn settlement_amount(&self) -> Option<(FloatMajorUnit, common_enums::Currency)> {
        let amount_details = self
            .approved_amount
            .as_ref()
            .or(self.transaction_amount.as_ref())?;
        Some((amount_details.total?, amount_details.currency?))
    }
}

impl<F, T> TryFrom<ResponseRouterData<F, FiservemeaPaymentsResponse, T, PaymentsResponseData>>
    for RouterData<F, T, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: ResponseRouterData<F, FiservemeaPaymentsResponse, T, PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        // 3DS handling is inert for non-3DS flows: capture/void/refund responses never
        // carry `authenticationResponse`, so `redirection_data` stays `None` and the status
        // is derived by `map_status` exactly as before. Only when actionable 3DS data is
        // present do we emit a redirect and flip the status to `AuthenticationPending`.
        let redirection_data = item
            .response
            .authentication_response
            .as_ref()
            .and_then(|auth| auth.to_redirection());
        let status = if redirection_data.is_some() {
            common_enums::AttemptStatus::AuthenticationPending
        } else {
            map_status(
                item.response.transaction_status,
                item.response.transaction_result,
                item.response.transaction_type,
            )
        };
        Ok(Self {
            status,
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(item.response.ipg_transaction_id),
                redirection_data: Box::new(redirection_data),
                mandate_reference: Box::new(None),
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: item.response.order_id,
                incremental_authorization_allowed: None,
                charges: None,
            }),
            ..item.data
        })
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaCaptureRequest {
    request_type: FiservemeaRequestType,
    transaction_amount: FiservemeaTransactionAmount,
}

impl TryFrom<&FiservemeaRouterData<&PaymentsCaptureRouterData>> for FiservemeaCaptureRequest {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: &FiservemeaRouterData<&PaymentsCaptureRouterData>,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            request_type: FiservemeaRequestType::PostAuthTransaction,
            transaction_amount: FiservemeaTransactionAmount {
                total: item.amount.clone(),
                currency: item.router_data.request.currency,
            },
        })
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaVoidRequest {
    request_type: FiservemeaRequestType,
}

// `PaymentsCancelData` exposes `capture_method: Option<storage_enums::CaptureMethod>`
// (see hyperswitch_domain_models::router_request_types::PaymentsCancelData), populated from the
// original payment attempt's capture method
// (crates/router/src/core/payments/transformers.rs, `PaymentsCancelData::try_from`).
// Per the Fiserv EMEA API docs, `VoidTransaction` must be used to void a sale/postauth (i.e. a
// transaction that was, or would be, auto-captured), while `VoidPreAuthTransactions` is reserved
// for voiding an un-captured pre-auth. We reuse the same automatic-capture signal already used
// in `FiservemeaPaymentsRequest` to pick between `PaymentCardSaleTransaction` and
// `PaymentCardPreAuthTransaction`. Extracted as a standalone function so the selection logic can
// be unit-tested without constructing a full `PaymentsCancelRouterData`.
fn select_void_request_type(capture_method: Option<enums::CaptureMethod>) -> FiservemeaRequestType {
    if is_auto_capture(capture_method) {
        FiservemeaRequestType::VoidTransaction
    } else {
        // Manual capture (or no capture-method signal at all) is treated as a pre-auth void,
        // preserving the connector's previous default behavior.
        FiservemeaRequestType::VoidPreAuthTransactions
    }
}

impl TryFrom<&PaymentsCancelRouterData> for FiservemeaVoidRequest {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(item: &PaymentsCancelRouterData) -> Result<Self, Self::Error> {
        Ok(Self {
            request_type: select_void_request_type(item.request.capture_method),
        })
    }
}

// REFUND :
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaRefundRequest {
    request_type: FiservemeaRequestType,
    transaction_amount: FiservemeaTransactionAmount,
}

impl<F> TryFrom<&FiservemeaRouterData<&RefundsRouterData<F>>> for FiservemeaRefundRequest {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(item: &FiservemeaRouterData<&RefundsRouterData<F>>) -> Result<Self, Self::Error> {
        Ok(Self {
            request_type: FiservemeaRequestType::ReturnTransaction,
            transaction_amount: FiservemeaTransactionAmount {
                total: item.amount.clone(),
                currency: item.router_data.request.currency,
            },
        })
    }
}

fn map_refund_status(
    fiservemea_status: Option<FiservemeaPaymentStatus>,
    fiservemea_result: Option<FiservemeaPaymentResult>,
) -> Result<enums::RefundStatus, errors::ConnectorError> {
    match fiservemea_status {
        Some(status) => match status {
            FiservemeaPaymentStatus::Approved => Ok(enums::RefundStatus::Success),
            FiservemeaPaymentStatus::Partial | FiservemeaPaymentStatus::Waiting => {
                Ok(enums::RefundStatus::Pending)
            }
            FiservemeaPaymentStatus::ValidationFailed
            | FiservemeaPaymentStatus::ProcessingFailed
            | FiservemeaPaymentStatus::Declined => Ok(enums::RefundStatus::Failure),
        },
        None => match fiservemea_result {
            Some(result) => match result {
                FiservemeaPaymentResult::Approved => Ok(enums::RefundStatus::Success),
                FiservemeaPaymentResult::Partial | FiservemeaPaymentResult::Waiting => {
                    Ok(enums::RefundStatus::Pending)
                }
                FiservemeaPaymentResult::Declined
                | FiservemeaPaymentResult::Failed
                | FiservemeaPaymentResult::Fraud => Ok(enums::RefundStatus::Failure),
            },
            None => Err(errors::ConnectorError::MissingRequiredField {
                field_name: "transactionResult",
            }),
        },
    }
}

impl TryFrom<RefundsResponseRouterData<Execute, FiservemeaPaymentsResponse>>
    for RefundsRouterData<Execute>
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: RefundsResponseRouterData<Execute, FiservemeaPaymentsResponse>,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            response: Ok(RefundsResponseData {
                connector_refund_id: item.response.ipg_transaction_id,
                refund_status: map_refund_status(
                    item.response.transaction_status,
                    item.response.transaction_result,
                )?,
            }),
            ..item.data
        })
    }
}

impl TryFrom<RefundsResponseRouterData<RSync, FiservemeaPaymentsResponse>>
    for RefundsRouterData<RSync>
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: RefundsResponseRouterData<RSync, FiservemeaPaymentsResponse>,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            response: Ok(RefundsResponseData {
                connector_refund_id: item.response.ipg_transaction_id,
                refund_status: map_refund_status(
                    item.response.transaction_status,
                    item.response.transaction_result,
                )?,
            }),
            ..item.data
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ErrorDetails {
    pub field: Option<String>,
    pub message: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FiservemeaError {
    pub code: Option<String>,
    pub message: Option<String>,
    pub details: Option<Vec<ErrorDetails>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FiservemeaErrorResponse {
    #[serde(rename = "type")]
    fiservemea_type: Option<String>,
    client_request_id: Option<String>,
    api_trace_id: Option<String>,
    pub response_type: Option<String>,
    pub error: Option<FiservemeaError>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a minimal `FiservemeaPaymentsResponse` (only the required fields plus whichever
    /// amount blocks the caller supplies as raw JSON) for `settlement_amount` tests, without
    /// needing every private field to be individually settable from this module.
    fn response_with_amounts(amounts: serde_json::Value) -> FiservemeaPaymentsResponse {
        let mut json = serde_json::json!({
            "ipgTransactionId": "ipg_1",
            "transactionType": "SALE",
        });
        json.as_object_mut()
            .unwrap()
            .extend(amounts.as_object().unwrap().clone());
        serde_json::from_value(json).unwrap()
    }

    #[test]
    fn settlement_amount_prefers_approved_amount_when_present() {
        let response = response_with_amounts(serde_json::json!({
            "approvedAmount": { "total": 12.5, "currency": "USD" },
            "transactionAmount": { "total": 99.0, "currency": "EUR" },
        }));
        let (amount, currency) = response.settlement_amount().unwrap();
        assert_eq!(amount.get_amount_as_f64(), 12.5);
        assert_eq!(currency, common_enums::Currency::USD);
    }

    #[test]
    fn settlement_amount_falls_back_to_transaction_amount_when_approved_amount_missing() {
        let response = response_with_amounts(serde_json::json!({
            "transactionAmount": { "total": 42.0, "currency": "ARS" },
        }));
        let (amount, currency) = response.settlement_amount().unwrap();
        assert_eq!(amount.get_amount_as_f64(), 42.0);
        assert_eq!(currency, common_enums::Currency::ARS);
    }

    #[test]
    fn settlement_amount_is_none_when_approved_amount_total_missing() {
        // `approvedAmount` is present but incomplete (no `total`): we do not fall back to
        // `transactionAmount` in this case (see `settlement_amount` doc comment) since the two
        // blocks aren't guaranteed to agree, so the caller skips setting `integrity_object`.
        let response = response_with_amounts(serde_json::json!({
            "approvedAmount": { "currency": "USD" },
            "transactionAmount": { "total": 42.0, "currency": "ARS" },
        }));
        assert!(response.settlement_amount().is_none());
    }

    #[test]
    fn settlement_amount_is_none_when_no_amount_block_present() {
        let response = response_with_amounts(serde_json::json!({}));
        assert!(response.settlement_amount().is_none());
    }

    #[test]
    fn installments_serialize_into_order() {
        let order = FiservemeaOrder {
            order_id: "ord_1".to_string(),
            installment_options: Some(FiservemeaInstallmentOptions {
                number_of_installments: 6,
                interest: Some(true),
            }),
            additional_details: None,
        };
        let json = serde_json::to_value(&order).unwrap();
        assert_eq!(json["installmentOptions"]["numberOfInstallments"], 6);
        assert_eq!(json["installmentOptions"]["Interest"], true);
    }

    #[test]
    fn metadata_reads_from_frm_fallback() {
        let frm = serde_json::json!({ "installments": 3 });
        let meta = FiservemeaMetadataObject::from_sources(None, Some(&frm));
        assert_eq!(meta.installments, Some(3));
    }

    #[test]
    fn tax_refund_legal_framework_serializes() {
        let details = FiservemeaAdditionalDetails {
            tax_refund_request_data: Some(FiservemeaTaxRefundRequestData {
                legal_framework: FiservemeaLegalFramework::UryReturnsIvaLaw19210,
            }),
        };
        let json = serde_json::to_value(&details).unwrap();
        assert_eq!(
            json["taxRefundRequestData"]["legalFramework"],
            "URY_RETURNS_IVA_LAW_19210"
        );
    }

    #[test]
    fn void_request_type_auto_capture_selects_void_transaction() {
        assert!(matches!(
            select_void_request_type(Some(enums::CaptureMethod::Automatic)),
            FiservemeaRequestType::VoidTransaction
        ));
        assert!(matches!(
            select_void_request_type(Some(enums::CaptureMethod::SequentialAutomatic)),
            FiservemeaRequestType::VoidTransaction
        ));
    }

    #[test]
    fn void_request_type_manual_or_missing_capture_selects_preauth_void() {
        assert!(matches!(
            select_void_request_type(Some(enums::CaptureMethod::Manual)),
            FiservemeaRequestType::VoidPreAuthTransactions
        ));
        assert!(matches!(
            select_void_request_type(None),
            FiservemeaRequestType::VoidPreAuthTransactions
        ));
    }

    fn sample_request(
        authentication_request: Option<FiservemeaAuthenticationRequest>,
    ) -> FiservemeaPaymentsRequest {
        FiservemeaPaymentsRequest {
            request_type: FiservemeaRequestType::PaymentCardSaleTransaction,
            merchant_transaction_id: "mtx_1".to_string(),
            transaction_amount: FiservemeaTransactionAmount {
                total: StringMajorUnit::zero(),
                currency: common_enums::Currency::USD,
            },
            order: FiservemeaOrder {
                order_id: "ord_1".to_string(),
                installment_options: None,
                additional_details: None,
            },
            payment_method: FiservemeaPaymentMethods::PaymentCard(FiservemeaPaymentCard {
                number: "4111111111111111".parse().unwrap(),
                expiry_date: FiservemeaExpiryDate {
                    month: Secret::new("12".to_string()),
                    year: Secret::new("30".to_string()),
                },
                security_code: Secret::new("123".to_string()),
            }),
            authentication_request,
        }
    }

    #[test]
    fn three_ds_authentication_request_serializes() {
        let url = "https://hyperswitch.io/complete/abc".to_string();
        let request = sample_request(Some(FiservemeaAuthenticationRequest {
            authentication_type: "Secure3D21AuthenticationRequest".to_string(),
            term_url: url.clone(),
            method_notification_url: url.clone(),
            challenge_indicator: Some("01".to_string()),
            challenge_window_size: Some("01".to_string()),
        }));
        let json = serde_json::to_value(&request).unwrap();
        assert_eq!(
            json["authenticationRequest"]["authenticationType"],
            "Secure3D21AuthenticationRequest"
        );
        assert_eq!(json["authenticationRequest"]["termURL"], url);
        assert_eq!(json["authenticationRequest"]["methodNotificationURL"], url);
        assert_eq!(json["authenticationRequest"]["challengeIndicator"], "01");
        assert_eq!(json["authenticationRequest"]["challengeWindowSize"], "01");
    }

    #[test]
    fn no_three_ds_request_omits_authentication_request() {
        let request = sample_request(None);
        let json = serde_json::to_value(&request).unwrap();
        assert!(
            json.get("authenticationRequest").is_none(),
            "NoThreeDs request must not serialize an authenticationRequest field"
        );
    }

    #[test]
    fn method_form_maps_to_html_redirect() {
        let auth = FiservemeaAuthenticationResponse {
            auth_type: Some("3D_SECURE".to_string()),
            version: Some("2.1".to_string()),
            secure3d_method: Some(FiservemeaSecure3dMethod {
                method_form: Some("<form id=\"tds\"></form>".to_string()),
                secure3d_trans_id: Some("trans_1".to_string()),
            }),
            params: None,
        };
        match auth.to_redirection() {
            Some(RedirectForm::Html { html_data }) => {
                assert_eq!(html_data, "<form id=\"tds\"></form>");
            }
            other => panic!("expected Html redirect, got {other:?}"),
        }
    }

    #[test]
    fn challenge_params_map_to_acs_form() {
        let auth = FiservemeaAuthenticationResponse {
            auth_type: Some("3D_SECURE".to_string()),
            version: Some("2.1".to_string()),
            secure3d_method: None,
            params: Some(FiservemeaAcsParams {
                acs_url: Some("https://acs.example.com/challenge".to_string()),
                c_req: Some("creq_value".to_string()),
                term_url: Some("https://hyperswitch.io/complete/abc".to_string()),
                sessiondata: Some("session_value".to_string()),
            }),
        };
        match auth.to_redirection() {
            Some(RedirectForm::Form {
                endpoint,
                method,
                form_fields,
            }) => {
                assert_eq!(endpoint, "https://acs.example.com/challenge");
                assert_eq!(method, Method::Post);
                assert_eq!(form_fields.get("creq"), Some(&"creq_value".to_string()));
                assert_eq!(
                    form_fields.get("threeDSSessionData"),
                    Some(&"session_value".to_string())
                );
            }
            other => panic!("expected Form redirect, got {other:?}"),
        }
    }

    #[test]
    fn no_authentication_response_yields_no_redirect() {
        // A response without ACS data (e.g. unenrolled cardholder or a capture/void
        // response) must not produce a redirect.
        let auth = FiservemeaAuthenticationResponse {
            auth_type: Some("3D_SECURE".to_string()),
            version: Some("2.1".to_string()),
            secure3d_method: None,
            params: None,
        };
        assert!(auth.to_redirection().is_none());
    }

    #[test]
    fn complete_authorize_method_status_serializes() {
        // Continuation after the device-fingerprint step: only `methodNotificationStatus`.
        let request = FiservemeaCompleteAuthorizeRequest {
            authentication_type: "Secure3D21AuthenticationUpdateRequest".to_string(),
            method_notification_status: Some("RECEIVED".to_string()),
            acs_response: None,
        };
        let json = serde_json::to_value(&request).unwrap();
        assert_eq!(
            json["authenticationType"],
            "Secure3D21AuthenticationUpdateRequest"
        );
        assert_eq!(json["methodNotificationStatus"], "RECEIVED");
        assert!(
            json.get("acsResponse").is_none(),
            "method-status continuation must not serialize acsResponse"
        );
    }

    #[test]
    fn complete_authorize_cres_serializes() {
        // Continuation after the challenge: only `acsResponse.cRes`.
        let request = FiservemeaCompleteAuthorizeRequest {
            authentication_type: "Secure3D21AuthenticationUpdateRequest".to_string(),
            method_notification_status: None,
            acs_response: Some(FiservemeaAcsResponse {
                c_res: "cRes_value".to_string(),
            }),
        };
        let json = serde_json::to_value(&request).unwrap();
        assert_eq!(
            json["authenticationType"],
            "Secure3D21AuthenticationUpdateRequest"
        );
        assert_eq!(json["acsResponse"]["cRes"], "cRes_value");
        assert!(
            json.get("methodNotificationStatus").is_none(),
            "cRes continuation must not serialize methodNotificationStatus"
        );
    }

    #[test]
    fn extract_acs_cres_reads_json_payload() {
        // ACS posts the challenge result as a JSON body -> forwarded in `payload`.
        let redirect = CompleteAuthorizeRedirectResponse {
            params: None,
            payload: Some(Secret::new(serde_json::json!({ "cRes": "abc123" }))),
        };
        assert_eq!(extract_acs_cres(&redirect), Some("abc123".to_string()));
    }

    #[test]
    fn extract_acs_cres_reads_query_params() {
        // ACS result forwarded as a query string -> case-insensitive key match.
        let redirect = CompleteAuthorizeRedirectResponse {
            params: Some(Secret::new("foo=bar&cres=xyz789".to_string())),
            payload: None,
        };
        assert_eq!(extract_acs_cres(&redirect), Some("xyz789".to_string()));
    }

    #[test]
    fn extract_acs_cres_none_after_method_step() {
        // Return from the methodForm step carries no challenge result.
        let redirect = CompleteAuthorizeRedirectResponse {
            params: Some(Secret::new("threeDSMethodData=xyz".to_string())),
            payload: None,
        };
        assert!(extract_acs_cres(&redirect).is_none());
    }
}
