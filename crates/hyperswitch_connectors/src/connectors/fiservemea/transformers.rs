use std::collections::HashMap;

use common_enums::enums;
use common_utils::{
    request::Method,
    types::{FloatMajorUnit, StringMajorUnit},
};
use hyperswitch_domain_models::{
    payment_method_data::PaymentMethodData,
    router_data::{ConnectorAuthType, PaymentMethodToken, RouterData},
    router_flow_types::{
        payments::{self, SetupMandate},
        refunds::{Execute, RSync},
    },
    router_request_types::{
        CompleteAuthorizeRedirectResponse, ResponseId, SetupMandateRequestData,
    },
    router_response_types::{PaymentsResponseData, RedirectForm, RefundsResponseData},
    types::{
        PaymentsAuthorizeRouterData, PaymentsCancelRouterData, PaymentsCaptureRouterData,
        PaymentsCompleteAuthorizeRouterData, RefundsRouterData, TokenizationRouterData,
    },
};
use hyperswitch_interfaces::errors;
use masking::{ExposeInterface, PeekInterface, Secret};
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

/// Soft descriptor — the merchant name shown on the cardholder's statement. Nested under
/// `order` (`order.softDescriptor.dynamicMerchantName`); the IPG API rejects it at the top
/// level of the transaction (verified against the cert gateway: a top-level `softDescriptor`
/// returns `INVALID_INPUT "No field named 'softDescriptor'"`).
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaSoftDescriptor {
    dynamic_merchant_name: Secret<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaOrder {
    order_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    installment_options: Option<FiservemeaInstallmentOptions>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    additional_details: Option<FiservemeaAdditionalDetails>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    soft_descriptor: Option<FiservemeaSoftDescriptor>,
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

// NOTE: This struct is never deserialized directly — it is built field-by-field in
// `from_sources` via the `extract_*` helpers, each of which reads raw `serde_json::Value` and
// carries its own alias key list in its `lookup_field(&[...])` call. The previous
// `#[derive(Deserialize)]` + `#[serde(default)]` + `#[serde(alias = ...)]` attributes were
// therefore dead (duplicating those alias lists) and have been removed.
#[derive(Debug, Clone, Default)]
pub struct FiservemeaMetadataObject {
    pub installments: Option<i32>,
    pub installment_interest: Option<bool>,
    pub tax_refund_legal_framework: Option<FiservemeaLegalFramework>,
    /// Soft descriptor / dynamic merchant name shown on the cardholder statement
    /// (`softDescriptor.dynamicMerchantName`, vendor doc §7.2 / Apéndice III).
    pub dynamic_merchant_name: Option<String>,
    /// Opt-in to Mastercard 3DS Data-Only (`messageCategory: "80"`, vendor doc §10.1.6).
    pub three_ds_data_only: Option<bool>,
}

/// Looks up `keys` (in order) inside `source` (a JSON object) and returns the first present
/// value, regardless of whether it later parses cleanly. Used so that a single malformed
/// sibling key can't hide a field that *is* present under one of its aliases.
fn lookup_field<'a>(
    source: Option<&'a serde_json::Value>,
    keys: &[&str],
) -> Option<&'a serde_json::Value> {
    let object = source?.as_object()?;
    keys.iter().find_map(|key| object.get(*key))
}

/// Extracts `installments` from a single JSON source, tolerant of the value being a JSON
/// number (`6`) or a numeric string (`"6"`), and of the alias key `number_of_installments`.
/// Returns `None` (rather than failing) when the field is absent or not parseable as an
/// integer, so one malformed field never takes down the others.
fn extract_installments(source: Option<&serde_json::Value>) -> Option<i32> {
    let value = lookup_field(source, &["installments", "number_of_installments"])?;
    value
        .as_i64()
        .or_else(|| value.as_str().and_then(|s| s.trim().parse::<i64>().ok()))
        .and_then(|n| i32::try_from(n).ok())
}

/// Extracts `installment_interest` from a single JSON source, tolerant of a JSON bool or a
/// bool-ish string (`"true"`/`"false"`, case-insensitive). `None` when absent/unparseable.
fn extract_installment_interest(source: Option<&serde_json::Value>) -> Option<bool> {
    let value = lookup_field(source, &["installment_interest"])?;
    value.as_bool().or_else(|| match value.as_str() {
        Some(s) if s.eq_ignore_ascii_case("true") => Some(true),
        Some(s) if s.eq_ignore_ascii_case("false") => Some(false),
        _ => None,
    })
}

/// Extracts `tax_refund_legal_framework` from a single JSON source, accepting the alias key
/// `legal_framework`. The enum is parsed from its serialized string representation so an
/// unknown/typo'd value yields `None` instead of failing the whole metadata object.
fn extract_legal_framework(source: Option<&serde_json::Value>) -> Option<FiservemeaLegalFramework> {
    let value = lookup_field(source, &["tax_refund_legal_framework", "legal_framework"])?;
    serde_json::from_value(value.clone()).ok()
}

/// Extracts the dynamic merchant name (soft descriptor) from a single JSON source, accepting the
/// alias keys `dynamic_merchant_name` / `dynamicMerchantName` / `soft_descriptor`. A blank value
/// is treated as absent so we never serialize an empty `dynamicMerchantName`.
fn extract_dynamic_merchant_name(source: Option<&serde_json::Value>) -> Option<String> {
    lookup_field(
        source,
        &[
            "dynamic_merchant_name",
            "dynamicMerchantName",
            "soft_descriptor",
        ],
    )?
    .as_str()
    .map(str::trim)
    .filter(|s| !s.is_empty())
    .map(str::to_string)
}

/// Extracts the `three_ds_data_only` opt-in flag (JSON bool or bool-ish string), mirroring
/// `extract_installment_interest`. `None` when absent/unparseable.
fn extract_three_ds_data_only(source: Option<&serde_json::Value>) -> Option<bool> {
    let value = lookup_field(source, &["three_ds_data_only", "threeDsDataOnly"])?;
    value.as_bool().or_else(|| match value.as_str() {
        Some(s) if s.eq_ignore_ascii_case("true") => Some(true),
        Some(s) if s.eq_ignore_ascii_case("false") => Some(false),
        _ => None,
    })
}

impl FiservemeaMetadataObject {
    /// Reads from `request.metadata` and, for each missing field, falls back to
    /// `request.frm_metadata`. Both sources are intentionally supported (see spec §3.1).
    ///
    /// Each field is parsed independently, per source, so that a malformed/typo'd sibling key
    /// (e.g. `installments` sent as a non-numeric string, or an unknown `legal_framework`)
    /// cannot cause the *whole* object to fail to parse and silently drop otherwise-valid
    /// fields (see fix for the "customer charged in 1 installment instead of N" issue).
    fn from_sources(
        metadata: Option<&serde_json::Value>,
        frm_metadata: Option<&serde_json::Value>,
    ) -> Self {
        Self {
            installments: extract_installments(metadata)
                .or_else(|| extract_installments(frm_metadata)),
            installment_interest: extract_installment_interest(metadata)
                .or_else(|| extract_installment_interest(frm_metadata)),
            tax_refund_legal_framework: extract_legal_framework(metadata)
                .or_else(|| extract_legal_framework(frm_metadata)),
            dynamic_merchant_name: extract_dynamic_merchant_name(metadata)
                .or_else(|| extract_dynamic_merchant_name(frm_metadata)),
            three_ds_data_only: extract_three_ds_data_only(metadata)
                .or_else(|| extract_three_ds_data_only(frm_metadata)),
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
    // IPG gateway tokenization (Card-on-File): create a token, then pay with it (vendor doc §9.1).
    PaymentCardPaymentTokenizationRequest,
    PaymentTokenSaleTransaction,
    PaymentTokenPreAuthTransaction,
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
    // Documented `paymentCard` field (Appendix III / §7.2). Sending the cardholder name aids
    // 3DS success and AVS. Serialized as `cardholderName`; omitted entirely when absent so a
    // request without a holder name stays byte-identical to the previous behavior.
    #[serde(skip_serializing_if = "Option::is_none")]
    cardholder_name: Option<Secret<String>>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum FiservemeaPaymentMethods {
    PaymentCard(FiservemeaPaymentCard),
    /// Pay with a previously created IPG gateway token (Card-on-File, vendor doc §9.1.4.2).
    /// Serialized as `paymentToken`.
    PaymentToken(FiservemeaPaymentTokenRef),
}

/// Reference to an IPG gateway token used to pay (`paymentMethod.paymentToken`, vendor doc §9.1.4.2).
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaPaymentTokenRef {
    value: Secret<String>,
    token_origin_store_id: Secret<String>,
}

/// 3DS native (Fiserv IPG "provider-owned" flow) authentication request object.
/// Only emitted when the payment is `is_three_ds()`; absent otherwise so the
/// NoThreeDs request stays byte-identical to the pre-3DS behavior. See vendor doc
/// §10.1.1 (lines 526-578) and design spec §3.4.
///
/// Mastercard Data-Only (`messageCategory: "80"`, vendor doc §10.1.6) is opt-in via
/// `metadata.three_ds_data_only`; see `message_category` below.
///
/// NOTE: 3DS v1 (`Secure3D10AuthenticationRequest`/`payerAuthenticationResponse`, vendor doc
/// §10.1.5 v1 variant) is intentionally not implemented — the card schemes have sunset 3DS v1,
/// so only the 3DS v2.1/v2.2 (`Secure3D21...`) flow is supported.
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
    // Mastercard 3DS Data-Only: `"80"` requests authentication data without a challenge
    // (vendor doc §10.1.6). Set from `metadata.three_ds_data_only`; omitted otherwise so the
    // normal 3DS request stays byte-identical.
    #[serde(skip_serializing_if = "Option::is_none")]
    message_category: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaPaymentsRequest {
    request_type: FiservemeaRequestType,
    store_id: Secret<String>,
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
        let auth = FiservemeaAuthType::try_from(&item.router_data.connector_auth_type)?;

        // Order-level fields derived from metadata are shared by the card and token flows.
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
                    tax_refund_request_data: Some(FiservemeaTaxRefundRequestData { legal_framework }),
                });
        let soft_descriptor = fiservemea_meta.dynamic_merchant_name.clone().map(|name| {
            FiservemeaSoftDescriptor {
                dynamic_merchant_name: Secret::new(name),
            }
        });
        let order = FiservemeaOrder {
            order_id: item.router_data.connector_request_reference_id.clone(),
            installment_options,
            additional_details,
            soft_descriptor,
        };
        let merchant_transaction_id = item
            .router_data
            .request
            .merchant_order_reference_id
            .clone()
            .unwrap_or(item.router_data.connector_request_reference_id.clone());
        let transaction_amount = FiservemeaTransactionAmount {
            total: item.amount.clone(),
            currency: item.router_data.request.currency,
        };
        let auto_capture = is_auto_capture(item.router_data.request.capture_method);

        // Card-on-File: pay with a previously created IPG gateway token (vendor doc §9.1.4.2).
        // Hyperswitch runs the PaymentMethodToken flow first and hands the token back here.
        if let Ok(PaymentMethodToken::Token(pm_token)) = item.router_data.get_payment_method_token()
        {
            // Fail closed: never authorize a token (Card-on-File) payment without authentication
            // when the merchant requested 3DS. IPG token + native 3DS is not implemented, so
            // silently dropping `authenticationRequest` here would skip Strong Customer
            // Authentication and authorize anyway. Error out instead (mirrors the card branch,
            // which fails closed when `complete_authorize_url` is missing).
            if item.router_data.is_three_ds() {
                return Err(errors::ConnectorError::NotImplemented(
                    "3DS with a stored IPG token (Card-on-File) for fiservemea".to_string(),
                )
                .into());
            }
            return Ok(Self {
                request_type: if auto_capture {
                    FiservemeaRequestType::PaymentTokenSaleTransaction
                } else {
                    FiservemeaRequestType::PaymentTokenPreAuthTransaction
                },
                store_id: auth.store_id.clone(),
                merchant_transaction_id,
                transaction_amount,
                order,
                payment_method: FiservemeaPaymentMethods::PaymentToken(FiservemeaPaymentTokenRef {
                    value: pm_token,
                    token_origin_store_id: auth.store_id,
                }),
                authentication_request: None,
            });
        }

        match item.router_data.request.payment_method_data.clone() {
            PaymentMethodData::Card(req_card) => {
                let card = FiservemeaPaymentCard {
                    number: req_card.card_number.clone(),
                    expiry_date: FiservemeaExpiryDate {
                        month: req_card.card_exp_month.clone(),
                        year: req_card.get_card_expiry_year_2_digit()?,
                    },
                    security_code: req_card.card_cvc,
                    cardholder_name: req_card.card_holder_name.clone(),
                };
                let request_type = if auto_capture {
                    FiservemeaRequestType::PaymentCardSaleTransaction
                } else {
                    FiservemeaRequestType::PaymentCardPreAuthTransaction
                };

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
                        // `01` = no preference (vendor doc §10.1.1, line ~536).
                        challenge_indicator: Some("01".to_string()),
                        // `05` = full screen (vendor doc §10.1.1, line ~552). The narrowest
                        // option `01` (250x400) is a poor default on modern/mobile viewports, so
                        // request full screen for a better challenge UX.
                        challenge_window_size: Some("05".to_string()),
                        // Mastercard Data-Only (`"80"`) when opted-in via metadata; else omitted.
                        message_category: fiservemea_meta
                            .three_ds_data_only
                            .unwrap_or(false)
                            .then(|| "80".to_string()),
                    })
                } else {
                    None
                };

                Ok(Self {
                    request_type,
                    store_id: auth.store_id,
                    merchant_transaction_id,
                    transaction_amount,
                    order,
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

/// Zero Auth (account verification) — a zero-amount `PaymentCardSaleTransaction` that validates
/// the card without a real charge (vendor doc Parte 3 §Zero Auth). Wired to Hyperswitch's
/// `SetupMandate` flow. Verified against the cert gateway: `total: 0` → APPROVED.
impl TryFrom<&RouterData<SetupMandate, SetupMandateRequestData, PaymentsResponseData>>
    for FiservemeaPaymentsRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: &RouterData<SetupMandate, SetupMandateRequestData, PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        let auth = FiservemeaAuthType::try_from(&item.connector_auth_type)?;
        match item.request.payment_method_data.clone() {
            PaymentMethodData::Card(req_card) => {
                let card = FiservemeaPaymentCard {
                    number: req_card.card_number.clone(),
                    expiry_date: FiservemeaExpiryDate {
                        month: req_card.card_exp_month.clone(),
                        year: req_card.get_card_expiry_year_2_digit()?,
                    },
                    security_code: req_card.card_cvc,
                    cardholder_name: req_card.card_holder_name.clone(),
                };
                Ok(Self {
                    request_type: FiservemeaRequestType::PaymentCardSaleTransaction,
                    store_id: auth.store_id,
                    merchant_transaction_id: item.connector_request_reference_id.clone(),
                    // Zero amount: the issuer validates the card without a real charge.
                    transaction_amount: FiservemeaTransactionAmount {
                        total: StringMajorUnit::zero(),
                        currency: item.request.currency,
                    },
                    order: FiservemeaOrder {
                        order_id: item.connector_request_reference_id.clone(),
                        installment_options: None,
                        additional_details: None,
                        soft_descriptor: None,
                    },
                    payment_method: FiservemeaPaymentMethods::PaymentCard(card),
                    authentication_request: None,
                })
            }
            _ => Err(errors::ConnectorError::NotImplemented(
                "Selected payment method through fiservemea zero auth".to_string(),
            )
            .into()),
        }
    }
}

// ---- IPG gateway tokenization (Card-on-File, vendor doc §9.1) ----

/// `createToken` block of a `PaymentCardPaymentTokenizationRequest`.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaCreateToken {
    reusable: bool,
    decline_duplicates: bool,
}

/// Create-token request — sent to `POST /payment-tokens`. Note `paymentCard` is a top-level field
/// here (not under `paymentMethod`), verified against the cert gateway.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaCreateTokenRequest {
    request_type: FiservemeaRequestType,
    store_id: Secret<String>,
    payment_card: FiservemeaPaymentCard,
    create_token: FiservemeaCreateToken,
}

impl TryFrom<&TokenizationRouterData> for FiservemeaCreateTokenRequest {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(item: &TokenizationRouterData) -> Result<Self, Self::Error> {
        let auth = FiservemeaAuthType::try_from(&item.connector_auth_type)?;
        match item.request.payment_method_data.clone() {
            PaymentMethodData::Card(req_card) => Ok(Self {
                request_type: FiservemeaRequestType::PaymentCardPaymentTokenizationRequest,
                store_id: auth.store_id,
                payment_card: FiservemeaPaymentCard {
                    number: req_card.card_number.clone(),
                    expiry_date: FiservemeaExpiryDate {
                        month: req_card.card_exp_month.clone(),
                        year: req_card.get_card_expiry_year_2_digit()?,
                    },
                    security_code: req_card.card_cvc,
                    cardholder_name: req_card.card_holder_name.clone(),
                },
                create_token: FiservemeaCreateToken {
                    reusable: true,
                    decline_duplicates: false,
                },
            }),
            _ => Err(errors::ConnectorError::NotImplemented(
                "Selected payment method through fiservemea tokenization".to_string(),
            )
            .into()),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaTokenValue {
    value: Secret<String>,
}

/// Create-token response (`paymentToken.value` = the IPG token / Hosted Data ID, vendor doc §9.1).
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaTokenResponse {
    payment_token: FiservemeaTokenValue,
}

impl<T>
    TryFrom<
        ResponseRouterData<
            payments::PaymentMethodToken,
            FiservemeaTokenResponse,
            T,
            PaymentsResponseData,
        >,
    > for RouterData<payments::PaymentMethodToken, T, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: ResponseRouterData<
            payments::PaymentMethodToken,
            FiservemeaTokenResponse,
            T,
            PaymentsResponseData,
        >,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            response: Ok(PaymentsResponseData::TokenizationResponse {
                token: item.response.payment_token.value.expose(),
            }),
            ..item.data
        })
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
///
/// Both carry `authenticationType: "Secure3D21AuthenticationUpdateRequest"`.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaCompleteAuthorizeRequest {
    authentication_type: String,
    store_id: Secret<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    method_notification_status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    acs_response: Option<FiservemeaAcsResponse>,
}

/// Extracts the ACS challenge result (`cRes`) that the issuer ACS posts back to the `termURL`
/// when the challenge completes (vendor doc lines 758-783). Hyperswitch forwards the browser's
/// return data in `redirect_response`, which may be a JSON body (`payload`) or a query string
/// (`params`). The vendor labels the field `cRes`; browsers/intermediaries may alter its casing,
/// so the key is matched case-insensitively (mirroring the query-string branch and
/// `has_three_ds_method_data`). Returns `None` after the device-fingerprint (methodForm) step,
/// which carries no challenge result.
fn extract_acs_cres(redirect_response: &CompleteAuthorizeRedirectResponse) -> Option<String> {
    // Prefer the JSON payload (the shape most ACS `termURL` posts use).
    if let Some(payload) = redirect_response.payload.as_ref() {
        if let Some(object) = payload.peek().as_object() {
            if let Some(c_res) = object
                .iter()
                .find(|(key, _)| key.eq_ignore_ascii_case("cres"))
                .and_then(|(_, value)| value.as_str())
            {
                return Some(c_res.to_string());
            }
        }
    }
    // Fall back to the query-string form (`cRes=...&...`). Query-string values are
    // `application/x-www-form-urlencoded`, so a Base64 `cRes` blob may contain `+` (space) or
    // `%xx` percent-escapes; decode via `url::form_urlencoded::parse` rather than taking the
    // raw substring, which would otherwise pass through a still-encoded (corrupted) value.
    if let Some(params) = redirect_response.params.as_ref() {
        for (key, val) in url::form_urlencoded::parse(params.peek().as_bytes()) {
            if key.eq_ignore_ascii_case("cres") {
                return Some(val.into_owned());
            }
        }
    }
    None
}

/// Reports whether the browser's return data carries a `threeDSMethodData` field, i.e. the
/// issuer ACS actually POSTed the 3DSMethod device-fingerprint notification to the
/// `methodNotificationURL` (vendor doc §10.1.3, lines 619-651). Mirrors `extract_acs_cres`:
/// checks the JSON `payload` first, then the `params` query string. The field name is matched
/// case-insensitively since browsers/intermediaries may alter its casing. Used to distinguish
/// `RECEIVED` (notification arrived) from `EXPECTED_BUT_NOT_RECEIVED` (issuer didn't POST it)
/// on the methodForm continuation. `NOT_EXPECTED` is never emitted because
/// `methodNotificationURL` is always sent on the initial Authorize request.
fn has_three_ds_method_data(redirect_response: &CompleteAuthorizeRedirectResponse) -> bool {
    if let Some(payload) = redirect_response.payload.as_ref() {
        if let Some(object) = payload.peek().as_object() {
            if object
                .keys()
                .any(|key| key.eq_ignore_ascii_case("threeDSMethodData"))
            {
                return true;
            }
        }
    }
    if let Some(params) = redirect_response.params.as_ref() {
        if url::form_urlencoded::parse(params.peek().as_bytes())
            .any(|(key, _)| key.eq_ignore_ascii_case("threeDSMethodData"))
        {
            return true;
        }
    }
    false
}

/// Builds the 3DS continuation PATCH body from the browser's `redirect_response`. Extracted as a
/// standalone function (like `select_void_request_type`) so the branch selection can be
/// unit-tested without constructing a full `PaymentsCompleteAuthorizeRouterData`.
///
/// - If the browser returned a challenge result (`cRes`), this is the final continuation after
///   the cardholder challenge (§10.1.5.d): send `acsResponse.cRes`.
/// - Otherwise the browser returned from the methodForm/device-fingerprint step (§10.1.4.a):
///   send `methodNotificationStatus`. It is `RECEIVED` when the ACS POSTed `threeDSMethodData`
///   to the `methodNotificationURL`, and `EXPECTED_BUT_NOT_RECEIVED` when it did not (some
///   issuers don't support browser data collection — vendor doc §10.1.1 line ~580 / §10.1.3).
fn build_continuation_request(
    redirect_response: &CompleteAuthorizeRedirectResponse,
    store_id: Secret<String>,
) -> FiservemeaCompleteAuthorizeRequest {
    match extract_acs_cres(redirect_response) {
        Some(c_res) => FiservemeaCompleteAuthorizeRequest {
            authentication_type: "Secure3D21AuthenticationUpdateRequest".to_string(),
            store_id,
            method_notification_status: None,
            acs_response: Some(FiservemeaAcsResponse { c_res }),
        },
        None => {
            let method_notification_status = if has_three_ds_method_data(redirect_response) {
                "RECEIVED"
            } else {
                "EXPECTED_BUT_NOT_RECEIVED"
            };
            FiservemeaCompleteAuthorizeRequest {
                authentication_type: "Secure3D21AuthenticationUpdateRequest".to_string(),
                store_id,
                method_notification_status: Some(method_notification_status.to_string()),
                acs_response: None,
            }
        }
    }
}

impl TryFrom<&PaymentsCompleteAuthorizeRouterData> for FiservemeaCompleteAuthorizeRequest {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(item: &PaymentsCompleteAuthorizeRouterData) -> Result<Self, Self::Error> {
        let auth = FiservemeaAuthType::try_from(&item.connector_auth_type)?;
        let redirect_response = item.request.redirect_response.as_ref().ok_or(
            errors::ConnectorError::MissingRequiredField {
                field_name: "redirect_response",
            },
        )?;

        Ok(build_continuation_request(redirect_response, auth.store_id))
    }
}

// Auth Struct
//
// Field mapping (`ConnectorAuthType::SignatureKey`):
//   api_key    -> Fiserv API Key    (public key, sent in the `API-KEY` header)
//   api_secret -> Fiserv API Secret (HMAC key used to sign every request)
//   key1       -> Fiserv Store Id   (required by the IPG API in the request body / sync query)
#[derive(Clone)]
pub struct FiservemeaAuthType {
    pub(super) api_key: Secret<String>,
    pub(super) secret_key: Secret<String>,
    pub(super) store_id: Secret<String>,
}

impl TryFrom<&ConnectorAuthType> for FiservemeaAuthType {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::SignatureKey {
                api_key,
                key1,
                api_secret,
            } => Ok(Self {
                api_key: api_key.to_owned(),
                secret_key: api_secret.to_owned(),
                store_id: key1.to_owned(),
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
///
/// `methodForm`/`secure3dTransId` are spelled consistently between the doc's field table
/// (line ~594) and its JSON example (lines 611-613), so no `#[serde(alias = ...)]` is needed
/// for either field here — see `FiservemeaAuthenticationResponse` for the field that *is*
/// inconsistent in this section of the doc.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaSecure3dMethod {
    method_form: Option<String>,
    secure3d_trans_id: Option<String>,
}

/// ACS challenge params returned on the challenge continuation (vendor doc §10.1.5,
/// lines 709-740). `cReq`/`sessionData` are posted to `acsURL`.
///
/// `acsURL`/`cReq`/`termURL` are spelled consistently between the field table (line ~715) and
/// the JSON example (lines 732-737), so no alias is needed for those three. `sessionData` is
/// the exception: the field table spells it `sessionData` while the JSON example spells it
/// `sessiondata` — accept both so a real gateway response using either casing still parses
/// instead of silently dropping session data needed for the ACS challenge POST.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaAcsParams {
    #[serde(rename = "acsURL")]
    acs_url: Option<String>,
    #[serde(rename = "cReq")]
    c_req: Option<String>,
    #[serde(rename = "termURL")]
    term_url: Option<String>,
    #[serde(alias = "sessionData")]
    sessiondata: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaAuthenticationResponse {
    #[serde(rename = "type")]
    auth_type: Option<String>,
    version: Option<String>,
    // The doc's field table for this section (line ~594) spells this `secure3DMethod`
    // (capital D), while its JSON example (line ~611) spells it `secure3dMethod` (lowercase
    // d, which is also what `rename_all = "camelCase"` derives from `secure3d_method` below).
    // Accept both spellings so a gateway response using either casing still parses — the
    // alternative is a silent "no redirect / payment stuck in Pending" for 3DS payments.
    #[serde(alias = "secure3DMethod")]
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

/// 3DS authentication outcome echoed on the frictionless/challenge terminal responses (vendor
/// doc §10.1.4.b line ~691 and §10.1.5.e line ~802). Parsed for observability only: the
/// accept/decline decision stays driven by `transactionStatus`/`transactionResult` via
/// `map_status`, never by this field. Its `responseCode3dSecure` is surfaced on the response
/// `connector_metadata` so it is available in logs/analytics rather than being silently dropped.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaSecure3dResponse {
    response_code3d_secure: Option<String>,
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
    // Present only on the frictionless/challenge terminal 3DS responses (§10.1.4.b/§10.1.5.e).
    // Parsed purely for observability (see `FiservemeaSecure3dResponse`); does not drive status.
    secure3d_response: Option<FiservemeaSecure3dResponse>,
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
        let mapped_status = map_status(
            item.response.transaction_status,
            item.response.transaction_result,
            item.response.transaction_type,
        );
        // Only treat the payment as awaiting authentication when it carries actionable 3DS
        // redirect data AND has not already reached a terminal outcome. A terminal response
        // (e.g. Charged/Failure/Voided) that still echoes `authenticationResponse` must map to
        // its real status instead of stalling in `AuthenticationPending`.
        let status = if redirection_data.is_some() && !mapped_status.is_terminal_status() {
            common_enums::AttemptStatus::AuthenticationPending
        } else {
            mapped_status
        };
        // Surface the 3DS authentication outcome (`responseCode3dSecure`) for observability when
        // present. It never influences status (that's `map_status`'s job); it's only attached so
        // it shows up in logs/analytics instead of being silently dropped. Absent on non-3DS and
        // intermediate 3DS responses, so `connector_metadata` stays `None` there as before.
        let connector_metadata = item
            .response
            .secure3d_response
            .as_ref()
            .and_then(|secure3d| secure3d.response_code3d_secure.as_ref())
            .map(|code| serde_json::json!({ "responseCode3dSecure": code }));
        Ok(Self {
            status,
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(item.response.ipg_transaction_id),
                redirection_data: Box::new(redirection_data),
                mandate_reference: Box::new(None),
                connector_metadata,
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
    store_id: Secret<String>,
    transaction_amount: FiservemeaTransactionAmount,
}

impl TryFrom<&FiservemeaRouterData<&PaymentsCaptureRouterData>> for FiservemeaCaptureRequest {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: &FiservemeaRouterData<&PaymentsCaptureRouterData>,
    ) -> Result<Self, Self::Error> {
        let auth = FiservemeaAuthType::try_from(&item.router_data.connector_auth_type)?;
        Ok(Self {
            request_type: FiservemeaRequestType::PostAuthTransaction,
            store_id: auth.store_id,
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
    store_id: Secret<String>,
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
        let auth = FiservemeaAuthType::try_from(&item.connector_auth_type)?;
        Ok(Self {
            request_type: select_void_request_type(item.request.capture_method),
            store_id: auth.store_id,
        })
    }
}

// REFUND :
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaRefundRequest {
    request_type: FiservemeaRequestType,
    store_id: Secret<String>,
    transaction_amount: FiservemeaTransactionAmount,
}

impl<F> TryFrom<&FiservemeaRouterData<&RefundsRouterData<F>>> for FiservemeaRefundRequest {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(item: &FiservemeaRouterData<&RefundsRouterData<F>>) -> Result<Self, Self::Error> {
        let auth = FiservemeaAuthType::try_from(&item.router_data.connector_auth_type)?;
        Ok(Self {
            request_type: FiservemeaRequestType::ReturnTransaction,
            store_id: auth.store_id,
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
    #![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

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
            soft_descriptor: None,
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
    fn metadata_malformed_sibling_key_does_not_lose_installments() {
        // A malformed/unknown `tax_refund_legal_framework` value must not cause the whole
        // metadata object to fail to parse and take a perfectly valid `installments` down
        // with it (previously: `serde_json::from_value::<Self>` on the whole object, so one
        // bad field silently dropped every field -- including installments, which could
        // silently charge the customer in 1 installment instead of N).
        let metadata = serde_json::json!({
            "installments": 6,
            "tax_refund_legal_framework": "NOT_A_REAL_LEGAL_FRAMEWORK",
        });
        let meta = FiservemeaMetadataObject::from_sources(Some(&metadata), None);
        assert_eq!(meta.installments, Some(6));
        assert_eq!(meta.tax_refund_legal_framework, None);
    }

    #[test]
    fn installments_as_numeric_string_parses() {
        // Some senders may serialize `installments` as a JSON string instead of a number;
        // tolerate that rather than failing to parse.
        let metadata = serde_json::json!({ "installments": "6" });
        let meta = FiservemeaMetadataObject::from_sources(Some(&metadata), None);
        assert_eq!(meta.installments, Some(6));
    }

    #[test]
    fn metadata_missing_field_falls_back_to_frm_metadata_per_field() {
        // `metadata` supplies `installment_interest` but not `installments`; the latter must
        // be filled in independently from `frm_metadata` without the presence of one field in
        // `metadata` blocking the fallback for a different, absent field.
        let metadata = serde_json::json!({ "installment_interest": true });
        let frm_metadata = serde_json::json!({ "installments": 12 });
        let meta = FiservemeaMetadataObject::from_sources(Some(&metadata), Some(&frm_metadata));
        assert_eq!(meta.installments, Some(12));
        assert_eq!(meta.installment_interest, Some(true));
    }

    #[test]
    fn metadata_supports_alias_keys() {
        let metadata = serde_json::json!({
            "number_of_installments": 4,
            "legal_framework": "URY_TAX_REFUND_LAW_18999",
        });
        let meta = FiservemeaMetadataObject::from_sources(Some(&metadata), None);
        assert_eq!(meta.installments, Some(4));
        assert_eq!(
            meta.tax_refund_legal_framework,
            Some(FiservemeaLegalFramework::UryTaxRefundLaw18999)
        );
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
            store_id: Secret::new("teststore".to_string()),
            merchant_transaction_id: "mtx_1".to_string(),
            transaction_amount: FiservemeaTransactionAmount {
                total: StringMajorUnit::zero(),
                currency: common_enums::Currency::USD,
            },
            order: FiservemeaOrder {
                order_id: "ord_1".to_string(),
                installment_options: None,
                additional_details: None,
                soft_descriptor: None,
            },
            payment_method: FiservemeaPaymentMethods::PaymentCard(FiservemeaPaymentCard {
                number: "4111111111111111".parse().unwrap(),
                expiry_date: FiservemeaExpiryDate {
                    month: Secret::new("12".to_string()),
                    year: Secret::new("30".to_string()),
                },
                security_code: Secret::new("123".to_string()),
                cardholder_name: None,
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
            message_category: None,
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
    fn alternate_secure3d_method_casing_still_redirects() {
        // The vendor doc's field table (line ~594) spells this `secure3DMethod` (capital D)
        // while its JSON example (line ~611) spells it `secure3dMethod`. A gateway that
        // follows the field table must still deserialize and produce a redirect, instead of
        // silently leaving the payment stuck in `Pending`.
        let json = serde_json::json!({
            "type": "3D_SECURE",
            "version": "2.1",
            "secure3DMethod": {
                "methodForm": "<form id=\"tds-alt\"></form>",
                "secure3dTransId": "trans_alt",
            },
        });
        let auth: FiservemeaAuthenticationResponse = serde_json::from_value(json).unwrap();
        match auth.to_redirection() {
            Some(RedirectForm::Html { html_data }) => {
                assert_eq!(html_data, "<form id=\"tds-alt\"></form>");
            }
            other => panic!("expected Html redirect, got {other:?}"),
        }
    }

    #[test]
    fn alternate_session_data_casing_still_redirects() {
        // The vendor doc's field table (line ~718) spells this `sessionData` while its JSON
        // example (line ~736) spells it `sessiondata`. Either casing must still parse and
        // reach the ACS challenge form.
        let json = serde_json::json!({
            "type": "3D_SECURE",
            "version": "2.1",
            "params": {
                "acsURL": "https://acs.example.com/challenge",
                "cReq": "creq_value",
                "termURL": "https://hyperswitch.io/complete/abc",
                "sessionData": "session_value",
            },
        });
        let auth: FiservemeaAuthenticationResponse = serde_json::from_value(json).unwrap();
        match auth.to_redirection() {
            Some(RedirectForm::Form { form_fields, .. }) => {
                assert_eq!(
                    form_fields.get("threeDSSessionData"),
                    Some(&"session_value".to_string())
                );
            }
            other => panic!("expected Form redirect, got {other:?}"),
        }
    }

    #[test]
    fn complete_authorize_method_status_serializes() {
        // Continuation after the device-fingerprint step: only `methodNotificationStatus`.
        let request = FiservemeaCompleteAuthorizeRequest {
            authentication_type: "Secure3D21AuthenticationUpdateRequest".to_string(),
            store_id: Secret::new("teststore".to_string()),
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
            store_id: Secret::new("teststore".to_string()),
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
    fn extract_acs_cres_json_payload_case_insensitive() {
        // Browsers/intermediaries may alter the key casing; the JSON branch must match
        // case-insensitively, like the query-string branch. Regression test for a payload
        // keyed `CRES` (would be missed by an exact `cRes`/`cres` lookup).
        let redirect = CompleteAuthorizeRedirectResponse {
            params: None,
            payload: Some(Secret::new(serde_json::json!({ "CRES": "xyz789" }))),
        };
        assert_eq!(extract_acs_cres(&redirect), Some("xyz789".to_string()));
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

    #[test]
    fn extract_acs_cres_url_decodes_query_param() {
        // A Base64 `cRes` blob may contain `+`/`=` that gets percent-encoded on the wire
        // (e.g. `+` -> `%2B`, `=` -> `%3D`). The query-param fallback must decode it back to
        // the original bytes rather than passing through the still-encoded string.
        let redirect = CompleteAuthorizeRedirectResponse {
            params: Some(Secret::new("cres=abc%2Bdef%3D%3D".to_string())),
            payload: None,
        };
        assert_eq!(extract_acs_cres(&redirect), Some("abc+def==".to_string()));
    }

    #[test]
    fn extract_acs_cres_decodes_literal_plus_as_space() {
        // `application/x-www-form-urlencoded` semantics: a literal `+` in the query string
        // means an (unencoded) space, not a literal plus sign.
        let redirect = CompleteAuthorizeRedirectResponse {
            params: Some(Secret::new("cres=abc+def".to_string())),
            payload: None,
        };
        assert_eq!(extract_acs_cres(&redirect), Some("abc def".to_string()));
    }

    // ---- Item 1: methodNotificationStatus RECEIVED vs EXPECTED_BUT_NOT_RECEIVED ----

    #[test]
    fn continuation_reports_received_when_method_data_present() {
        // The ACS POSTed `threeDSMethodData` to the methodNotificationURL (§10.1.3) -> RECEIVED.
        let redirect = CompleteAuthorizeRedirectResponse {
            params: None,
            payload: Some(Secret::new(serde_json::json!({
                "threeDSMethodData": "eyJ0aHJlZURTU2VydmVyVHJhbnNJRCI6IjNhYzcifQ==",
            }))),
        };
        let request = build_continuation_request(&redirect, Secret::new("teststore".to_string()));
        assert_eq!(
            request.method_notification_status.as_deref(),
            Some("RECEIVED")
        );
        assert!(request.acs_response.is_none());
    }

    #[test]
    fn continuation_reports_expected_but_not_received_when_method_data_absent() {
        // The browser came back from the methodForm step but the ACS never POSTed
        // `threeDSMethodData` (issuer doesn't support browser data collection, §10.1.1 line
        // ~580) -> EXPECTED_BUT_NOT_RECEIVED (never `RECEIVED`, never `NOT_EXPECTED`).
        let redirect = CompleteAuthorizeRedirectResponse {
            params: Some(Secret::new("foo=bar".to_string())),
            payload: None,
        };
        let request = build_continuation_request(&redirect, Secret::new("teststore".to_string()));
        assert_eq!(
            request.method_notification_status.as_deref(),
            Some("EXPECTED_BUT_NOT_RECEIVED")
        );
        assert!(request.acs_response.is_none());
    }

    #[test]
    fn continuation_reports_received_from_query_string_method_data() {
        // `threeDSMethodData` may arrive as a query-string param rather than a JSON payload.
        let redirect = CompleteAuthorizeRedirectResponse {
            params: Some(Secret::new("threeDSMethodData=eyJ0aHJlZSJ9".to_string())),
            payload: None,
        };
        let request = build_continuation_request(&redirect, Secret::new("teststore".to_string()));
        assert_eq!(
            request.method_notification_status.as_deref(),
            Some("RECEIVED")
        );
    }

    #[test]
    fn continuation_sends_cres_when_challenge_result_present() {
        // A challenge result (`cRes`) means the final continuation (§10.1.5.d): send
        // `acsResponse.cRes` and no `methodNotificationStatus`, regardless of methodData.
        let redirect = CompleteAuthorizeRedirectResponse {
            params: None,
            payload: Some(Secret::new(serde_json::json!({ "cRes": "cres_blob" }))),
        };
        let request = build_continuation_request(&redirect, Secret::new("teststore".to_string()));
        assert_eq!(
            request.acs_response.as_ref().map(|acs| acs.c_res.clone()),
            Some("cres_blob".to_string())
        );
        assert!(request.method_notification_status.is_none());
    }

    // ---- Item 3: secure3dResponse.responseCode3dSecure is parsed, not dropped ----

    #[test]
    fn secure3d_response_code_is_captured() {
        // §10.1.4.b / §10.1.5.e terminal response: `secure3dResponse.responseCode3dSecure` must
        // deserialize into the response so it is available for observability.
        let json = serde_json::json!({
            "ipgTransactionId": "838916029301",
            "transactionType": "SALE",
            "transactionStatus": "APPROVED",
            "secure3dResponse": { "responseCode3dSecure": "1" },
        });
        let response: FiservemeaPaymentsResponse = serde_json::from_value(json).unwrap();
        assert_eq!(
            response
                .secure3d_response
                .and_then(|secure3d| secure3d.response_code3d_secure),
            Some("1".to_string())
        );
    }

    // ---- Item 4: paymentCard.cardholderName ----

    fn sample_card(cardholder_name: Option<Secret<String>>) -> FiservemeaPaymentCard {
        FiservemeaPaymentCard {
            number: "4111111111111111".parse().unwrap(),
            expiry_date: FiservemeaExpiryDate {
                month: Secret::new("12".to_string()),
                year: Secret::new("30".to_string()),
            },
            security_code: Secret::new("123".to_string()),
            cardholder_name,
        }
    }

    #[test]
    fn payment_card_serializes_cardholder_name_when_present() {
        let card = sample_card(Some(Secret::new("Jane Doe".to_string())));
        let json = serde_json::to_value(&card).unwrap();
        assert_eq!(json["cardholderName"], "Jane Doe");
    }

    #[test]
    fn payment_card_omits_cardholder_name_when_absent() {
        let card = sample_card(None);
        let json = serde_json::to_value(&card).unwrap();
        assert!(
            json.get("cardholderName").is_none(),
            "cardholderName must be omitted when no holder name is present"
        );
    }

    // ---- Doc-fixture tests: lock the wire format to the vendor doc (§10) ----

    #[test]
    fn doc_method_form_response_produces_html_redirect() {
        // EXACT shape from vendor doc §10.1.2 (lines 599-616): the methodForm auth response must
        // deserialize and produce an `Html` RedirectForm carrying the methodForm HTML verbatim.
        let json = serde_json::json!({
            "clientRequestId": "30dd879c-ee2f-11db-8314-0800200c9a66",
            "apiTraceId": "rrt-0c80a3403e2c2def0-d-ea-28805-6810951-2",
            "ipgTransactionId": "838916029301",
            "transactionType": "SALE",
            "transactionTime": 1518811817_i64,
            "approvedAmount": { "total": 122.04, "currency": "USD" },
            "transactionStatus": "WAITING",
            "authenticationResponse": {
                "type": "3D_SECURE",
                "version": "2.1",
                "secure3dMethod": {
                    "methodForm": "<form name=\"frm\" method=\"POST\"><iframe hidden></iframe></form>",
                    "secure3dTransId": "3ac7caa7-aa42-2663-791b-2ac05a542c4a"
                }
            }
        });
        let response: FiservemeaPaymentsResponse = serde_json::from_value(json).unwrap();
        let auth = response
            .authentication_response
            .expect("doc response carries an authenticationResponse");
        match auth.to_redirection() {
            Some(RedirectForm::Html { html_data }) => {
                assert_eq!(
                    html_data,
                    "<form name=\"frm\" method=\"POST\"><iframe hidden></iframe></form>"
                );
            }
            other => panic!("expected Html redirect, got {other:?}"),
        }
    }

    #[test]
    fn doc_challenge_params_response_produces_acs_form() {
        // EXACT shape from vendor doc §10.1.5.b (lines 720-739): the challenge params response
        // must deserialize (note the doc's lowercase `sessiondata`) and produce a `Form`
        // POST to `acsURL` carrying `creq`/`threeDSSessionData` (the field names the ACS
        // expects, doc lines 749-753).
        let json = serde_json::json!({
            "clientRequestId": "30dd879c-ee2f-11db-8314-0800200c9a66",
            "apiTraceId": "rrt-0c80a3403e2c2def0-d-ea-28805-6810951-2",
            "ipgTransactionId": "838916029301",
            "transactionType": "SALE",
            "transactionTime": 1518811817_i64,
            "approvedAmount": { "total": 122.04, "currency": "USD" },
            "transactionStatus": "WAITING",
            "authenticationResponse": {
                "type": "3D_SECURE",
                "version": "2.1",
                "params": {
                    "acsURL": "https://3ds-acs.test.modirum.com/mdpayacs/pareq",
                    "termURL": "https://www.mywebshop.com/process3dSecure/",
                    "cReq": "ewogICAiYWNzVHJhbCIgOiA...wMDAtMDAwMDAwMDA0MWE5Igp9",
                    "sessiondata": "50F2156E03083CA665BCB4.."
                }
            }
        });
        let response: FiservemeaPaymentsResponse = serde_json::from_value(json).unwrap();
        let auth = response
            .authentication_response
            .expect("doc response carries an authenticationResponse");
        match auth.to_redirection() {
            Some(RedirectForm::Form {
                endpoint,
                method,
                form_fields,
            }) => {
                assert_eq!(endpoint, "https://3ds-acs.test.modirum.com/mdpayacs/pareq");
                assert_eq!(method, Method::Post);
                assert_eq!(
                    form_fields.get("creq"),
                    Some(&"ewogICAiYWNzVHJhbCIgOiA...wMDAtMDAwMDAwMDA0MWE5Igp9".to_string())
                );
                assert_eq!(
                    form_fields.get("threeDSSessionData"),
                    Some(&"50F2156E03083CA665BCB4..".to_string())
                );
            }
            other => panic!("expected Form redirect, got {other:?}"),
        }
    }
}
