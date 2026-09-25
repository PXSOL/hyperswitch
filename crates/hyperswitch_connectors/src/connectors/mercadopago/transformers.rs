use std::collections::HashMap;

use common_enums::enums;
use common_utils::{
    pii::SecretSerdeValue,
    request::Method,
    types::{FloatMajorUnit, FloatMajorUnitForConnector},
};
use hyperswitch_domain_models::{
    payment_method_data::{PaymentMethodData, WalletData},
    router_data::{
        ConnectorAuthType, ConnectorReportedActivity, ConnectorReportedDispute,
        ConnectorReportedRefund, ErrorResponse, RouterData,
    },
    router_flow_types::{
        payments::PaymentMethodToken,
        refunds::{Execute, RSync},
    },
    router_request_types::ResponseId,
    router_response_types::{PaymentsResponseData, RedirectForm, RefundsResponseData},
    types::{
        PaymentsAuthorizeRouterData, PaymentsCaptureRouterData, RefundsRouterData,
        TokenizationRouterData,
    },
};
use hyperswitch_interfaces::errors;
use masking::{PeekInterface, Secret};
use serde::{de::Deserialize as DeDeserialize, Deserialize, Serialize};

use crate::{
    types::{RefundsResponseRouterData, ResponseRouterData},
    utils::{self, RouterData as _},
};

const MAX_APPLICATION_FEE_RATIO: f64 = 0.007;

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
    /// Marketplace commission — absolute amount in the transaction currency
    #[serde(skip_serializing_if = "Option::is_none")]
    pub application_fee: Option<f64>,
    /// Checkout Pro (hosted checkout) options
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checkout_pro: Option<MercadopagoCheckoutProOptions>,
}

#[derive(Debug, Default, Serialize, Deserialize, Clone)]
pub struct MercadopagoCheckoutProOptions {
    /// true = approve/reject only, no intermediate states (disables offline methods)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub binary_mode: Option<bool>,
    /// Maximum installments offered in the hosted checkout
    #[serde(skip_serializing_if = "Option::is_none")]
    pub installments: Option<i32>,
    /// Payment types to exclude in the hosted checkout (e.g. "ticket" for cash)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub excluded_payment_types: Option<Vec<String>>,
}

impl TryFrom<&Option<SecretSerdeValue>> for MercadopagoMetadata {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(meta_data: &Option<SecretSerdeValue>) -> Result<Self, Self::Error> {
        match meta_data {
            Some(metadata) => {
                let json_value = metadata.peek().clone();
                serde_json::from_value::<Self>(json_value).map_err(|_| {
                    errors::ConnectorError::InvalidConnectorConfig {
                        config: "frm_metadata",
                    }
                    .into()
                })
            }
            None => Ok(Self::default()),
        }
    }
}

impl TryFrom<&Option<serde_json::Value>> for MercadopagoMetadata {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(meta_data: &Option<serde_json::Value>) -> Result<Self, Self::Error> {
        match meta_data {
            Some(metadata) => serde_json::from_value::<Self>(metadata.clone()).map_err(|_e| {
                errors::ConnectorError::InvalidConnectorConfig { config: "metadata" }.into()
            }),
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
                let identification =
                    match (metadata.identification_type, metadata.identification_number) {
                        (Some(id_type), Some(id_number)) => {
                            Some(MercadopagoCardholderIdentification {
                                id_type,
                                number: id_number,
                            })
                        }
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

#[derive(Debug, Clone, Serialize)]
pub struct MercadopagoPassenger {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_name: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct MercadopagoCategoryDescriptor {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub passenger: Option<MercadopagoPassenger>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_date: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub category_descriptor: Option<MercadopagoCategoryDescriptor>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub application_fee: Option<f64>,
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
        let payment_method_id =
            metadata
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
        let payer_identification = match (
            &metadata.identification_type,
            &metadata.identification_number,
        ) {
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
                let additional_payer =
                    metadata
                        .payer
                        .as_ref()
                        .map(|p| MercadopagoAdditionalInfoPayer {
                            first_name: p.first_name.as_ref().map(|s| s.peek().to_string()),
                            last_name: p.last_name.as_ref().map(|s| s.peek().to_string()),
                            phone: p
                                .phone
                                .as_ref()
                                .map(|ph| MercadopagoAdditionalInfoPayerPhone {
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
                        });

                let category_descriptor = metadata.payer.as_ref().and_then(|p| {
                    if p.first_name.is_some() || p.last_name.is_some() {
                        Some(MercadopagoCategoryDescriptor {
                            passenger: Some(MercadopagoPassenger {
                                first_name: p.first_name.as_ref().map(|s| s.peek().to_string()),
                                last_name: p.last_name.as_ref().map(|s| s.peek().to_string()),
                            }),
                        })
                    } else {
                        None
                    }
                });

                let event_date = common_utils::date_time::date_as_yyyymmddthhmmssmmmz().ok();

                let additional_items = metadata.item.as_ref().map(|i| {
                    vec![MercadopagoAdditionalInfoItem {
                        id: "1".to_string(),
                        title: i.title.clone(),
                        description: i.description.clone(),
                        category_id: i.category_id.clone(),
                        quantity: 1,
                        unit_price: transaction_amount,
                        event_date: event_date.clone(),
                        category_descriptor: category_descriptor.clone(),
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

        let application_fee = match metadata.application_fee {
            Some(fee) if fee > 0.0 => {
                let amount_f64 = transaction_amount.get_amount_as_f64();
                let max_fee = amount_f64 * MAX_APPLICATION_FEE_RATIO;
                if fee > max_fee {
                    return Err(errors::ConnectorError::InvalidDataFormat {
                        field_name:
                            "application_fee exceeds maximum allowed (0.7% of transaction_amount)",
                    }
                    .into());
                }
                Some(fee)
            }
            _ => None,
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
            application_fee,
        })
    }
}

// ============================================================================
// Checkout Pro - POST /checkout/preferences (hosted checkout redirect)
// ============================================================================

/// Mercado Pago rejects non-public hosts in `back_urls` and `notification_url`.
/// Parses the host (instead of substring-matching the whole URL) so legitimate
/// URLs like `https://shop.com/return?next=localhost` are not dropped.
pub(crate) fn filter_public_url(url: Option<&String>) -> Option<String> {
    let candidate = url?;
    let parsed = url::Url::parse(candidate).ok()?;
    let is_local = match parsed.host()? {
        url::Host::Domain(domain) => {
            let domain = domain.to_ascii_lowercase();
            domain == "localhost"
                || domain.ends_with(".localhost")
                || domain == "host.docker.internal"
        }
        url::Host::Ipv4(ip) => ip.is_loopback() || ip.is_unspecified() || ip.is_private(),
        url::Host::Ipv6(ip) => ip.is_loopback() || ip.is_unspecified(),
    };

    if is_local {
        router_env::logger::warn!(
            "mercadopago: dropping non-public URL from the preference payload"
        );
        None
    } else {
        Some(candidate.clone())
    }
}

#[derive(Debug, Serialize)]
pub struct MercadopagoPreferenceItem {
    pub id: String,
    pub title: String,
    pub quantity: i32,
    pub unit_price: FloatMajorUnit,
    pub currency_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub category_id: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct MercadopagoBackUrls {
    pub success: String,
    pub pending: String,
    pub failure: String,
}

#[derive(Debug, Serialize)]
pub struct MercadopagoExcludedPaymentType {
    pub id: String,
}

#[derive(Debug, Serialize)]
pub struct MercadopagoPreferencePaymentMethods {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub installments: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub excluded_payment_types: Option<Vec<MercadopagoExcludedPaymentType>>,
}

#[derive(Debug, Serialize)]
pub struct MercadopagoPreferencePayer {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<Secret<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<Secret<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub surname: Option<Secret<String>>,
}

#[derive(Debug, Serialize)]
pub struct MercadopagoPreferenceRequest {
    pub items: Vec<MercadopagoPreferenceItem>,
    pub external_reference: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payer: Option<MercadopagoPreferencePayer>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub back_urls: Option<MercadopagoBackUrls>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auto_return: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notification_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub statement_descriptor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub binary_mode: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payment_methods: Option<MercadopagoPreferencePaymentMethods>,
    /// Marketplace commission for OAuth-connected sellers (preferences use
    /// `marketplace_fee`, unlike direct payments which use `application_fee`)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub marketplace_fee: Option<f64>,
}

impl TryFrom<&MercadopagoRouterData<&PaymentsAuthorizeRouterData>>
    for MercadopagoPreferenceRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: &MercadopagoRouterData<&PaymentsAuthorizeRouterData>,
    ) -> Result<Self, Self::Error> {
        let router_data = item.router_data;

        // Checkout Pro auto-captures inside Mercado Pago: manual capture cannot work.
        if matches!(
            router_data.request.capture_method,
            Some(enums::CaptureMethod::Manual) | Some(enums::CaptureMethod::ManualMultiple)
        ) {
            return Err(errors::ConnectorError::NotImplemented(
                "manual capture for Mercado Pago Checkout Pro".to_string(),
            )
            .into());
        }

        // Merge metadata: request.metadata first, frm_metadata as per-field fallback
        // (api2 sends the marketplace fee through frm_metadata, like the card flow).
        let meta_request = MercadopagoMetadata::try_from(&router_data.request.metadata)?;
        let meta_frm = MercadopagoMetadata::try_from(&router_data.frm_metadata)?;
        let checkout_pro = meta_request
            .checkout_pro
            .or(meta_frm.checkout_pro)
            .unwrap_or_default();
        let application_fee = meta_request.application_fee.or(meta_frm.application_fee);
        let item_info = meta_request.item.or(meta_frm.item);

        let unit_price = item.amount;

        let marketplace_fee = match application_fee {
            Some(fee) if fee > 0.0 => {
                let amount_f64 = unit_price.get_amount_as_f64();
                let max_fee = amount_f64 * MAX_APPLICATION_FEE_RATIO;
                if fee > max_fee {
                    return Err(errors::ConnectorError::InvalidDataFormat {
                        field_name:
                            "application_fee exceeds maximum allowed (0.7% of transaction_amount)",
                    }
                    .into());
                }
                Some(fee)
            }
            _ => None,
        };

        let title = item_info
            .as_ref()
            .and_then(|i| i.title.clone())
            .or_else(|| router_data.description.clone())
            .unwrap_or_else(|| "Pago".to_string());

        // The buyer returns to Hyperswitch's own redirect-response endpoint
        // (router_return_url), which triggers PSync and only then forwards to the
        // merchant's return_url. Mercado Pago rejects localhost back_urls, so in
        // that case the preference is created without them (webhook/PSync only).
        let back_urls =
            filter_public_url(router_data.request.router_return_url.as_ref()).map(|return_url| {
                MercadopagoBackUrls {
                    success: return_url.clone(),
                    pending: return_url.clone(),
                    failure: return_url,
                }
            });
        let auto_return = back_urls.as_ref().map(|_| "approved".to_string());

        let notification_url = filter_public_url(router_data.request.webhook_url.as_ref());

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
        let payer_name = router_data
            .get_optional_billing_first_name()
            .map(|n| n.peek().to_string());
        let payer_surname = router_data
            .get_optional_billing_last_name()
            .map(|n| n.peek().to_string());
        let payer = if payer_email.is_some() || payer_name.is_some() || payer_surname.is_some() {
            Some(MercadopagoPreferencePayer {
                email: payer_email.map(Secret::new),
                name: payer_name.map(Secret::new),
                surname: payer_surname.map(Secret::new),
            })
        } else {
            None
        };

        let excluded_payment_types = checkout_pro.excluded_payment_types.as_ref().map(|types| {
            types
                .iter()
                .map(|id| MercadopagoExcludedPaymentType { id: id.clone() })
                .collect::<Vec<_>>()
        });
        let payment_methods =
            if checkout_pro.installments.is_some() || excluded_payment_types.is_some() {
                Some(MercadopagoPreferencePaymentMethods {
                    installments: checkout_pro.installments,
                    excluded_payment_types,
                })
            } else {
                None
            };

        Ok(Self {
            items: vec![MercadopagoPreferenceItem {
                id: router_data.connector_request_reference_id.clone(),
                title,
                quantity: 1,
                unit_price,
                currency_id: router_data.request.currency.to_string(),
                category_id: item_info.and_then(|i| i.category_id),
            }],
            external_reference: router_data.connector_request_reference_id.clone(),
            payer,
            back_urls,
            auto_return,
            notification_url,
            statement_descriptor: router_data.request.statement_descriptor.clone(),
            binary_mode: checkout_pro.binary_mode,
            payment_methods,
            marketplace_fee,
        })
    }
}

/// Authorize dispatch: Checkout Pro wallet goes to POST /checkout/preferences,
/// everything else keeps the existing card-token POST /v1/payments path.
#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum MercadopagoAuthorizeRequest {
    Preference(Box<MercadopagoPreferenceRequest>),
    Payment(Box<MercadopagoPaymentsRequest>),
}

impl MercadopagoAuthorizeRequest {
    pub fn is_checkout_pro(payment_method_data: &PaymentMethodData) -> bool {
        matches!(
            payment_method_data,
            PaymentMethodData::Wallet(WalletData::MercadoPagoCheckoutPro {})
        )
    }
}

impl TryFrom<&MercadopagoRouterData<&PaymentsAuthorizeRouterData>> for MercadopagoAuthorizeRequest {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: &MercadopagoRouterData<&PaymentsAuthorizeRouterData>,
    ) -> Result<Self, Self::Error> {
        if Self::is_checkout_pro(&item.router_data.request.payment_method_data) {
            Ok(Self::Preference(Box::new(
                MercadopagoPreferenceRequest::try_from(item)?,
            )))
        } else {
            Ok(Self::Payment(Box::new(
                MercadopagoPaymentsRequest::try_from(item)?,
            )))
        }
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

    fn try_from(
        item: &MercadopagoRouterData<&PaymentsCaptureRouterData>,
    ) -> Result<Self, Self::Error> {
        let router_data = item.router_data;

        let transaction_amount =
            if router_data.request.amount_to_capture != router_data.request.payment_amount {
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
            MercadopagoPaymentStatus::Rejected => Self::Failure,
            MercadopagoPaymentStatus::Cancelled => Self::Voided,
            // The money was already captured: a refund, chargeback or mediation
            // is its own Hyperswitch record (see the payment-sync reconciliation
            // this payment status drives), and must never regress a settled
            // attempt back to processing/failed.
            MercadopagoPaymentStatus::Refunded
            | MercadopagoPaymentStatus::ChargedBack
            | MercadopagoPaymentStatus::InMediation => Self::Charged,
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
    // A newtype over f64 (deserializes transparently from the same JSON number
    // MP sends): needed, rather than a plain f64, so `reported_dispute` below
    // can call `FloatMajorUnitForConnector::convert_back` on it directly —
    // `FloatMajorUnit::new` is private outside `common_utils`.
    #[serde(default)]
    pub transaction_amount: Option<FloatMajorUnit>,
    #[serde(default)]
    pub currency_id: Option<String>,
    #[serde(default)]
    pub payment_method_id: Option<String>,
    #[serde(default)]
    pub payment_type_id: Option<String>,
    /// Refunds Mercado Pago reports directly on the payment object. Kept as
    /// raw JSON: a malformed array (or a malformed entry in it) must never
    /// fail parsing the payment sync response — see `reported_refunds`, which
    /// parses each entry leniently and skips ones it cannot read.
    #[serde(default)]
    pub refunds: Option<Vec<serde_json::Value>>,
}

/// One entry of `MercadopagoPaymentsResponse::refunds`. Deliberately tolerant:
/// every field is optional (except via `id`, which is required for the entry
/// to be usable) so a single unexpected shape does not fail the whole array.
#[derive(Debug, Clone, Deserialize)]
struct MercadopagoPaymentRefundEntry {
    #[serde(default, deserialize_with = "deserialize_code")]
    id: Option<String>,
    #[serde(default)]
    amount: Option<FloatMajorUnit>,
    #[serde(default)]
    status: Option<String>,
}

impl MercadopagoPaymentRefundEntry {
    fn into_reported_refund(self, currency: enums::Currency) -> Option<ConnectorReportedRefund> {
        let connector_refund_id = self.id?;
        // A missing amount must never silently become a 0-amount refund:
        // skip the entry instead (it will simply be retried on the next
        // sync once Mercado Pago's response is well-formed).
        let amount = match self.amount {
            Some(amount) => amount,
            None => {
                router_env::logger::warn!(
                    connector_refund_id = %connector_refund_id,
                    "mercadopago: skipping a reported refund with no amount"
                );
                return None;
            }
        };
        let amount = match utils::convert_back_amount_to_minor_units(
            &FloatMajorUnitForConnector,
            amount,
            currency,
        ) {
            Ok(amount) => amount,
            Err(error) => {
                router_env::logger::warn!(
                    ?error,
                    connector_refund_id = %connector_refund_id,
                    "mercadopago: could not convert a reported refund's amount, skipping it"
                );
                return None;
            }
        };
        Some(ConnectorReportedRefund {
            connector_refund_id,
            amount,
            status: mercadopago_reported_refund_status(self.status.as_deref()),
        })
    }
}

/// Mercado Pago's own refund status vocabulary, mapped tolerantly: any status
/// this doesn't recognize (or that is missing) is treated as still pending
/// rather than failing the sync.
fn mercadopago_reported_refund_status(status: Option<&str>) -> enums::RefundStatus {
    match status {
        Some("approved") => enums::RefundStatus::Success,
        Some("rejected" | "cancelled") => enums::RefundStatus::Failure,
        // "pending", "in_process", anything unrecognized, or missing.
        _ => enums::RefundStatus::Pending,
    }
}

/// Maps a `charged_back` payment's `status_detail` to a dispute status, per
/// the Mercado Pago contract: `in_process` is still open, `settled` means the
/// chargeback stuck (Hyperswitch lost the dispute), `reimbursed` means the
/// chargeback was reverted back to the merchant (Hyperswitch won it). Any
/// other value (or a missing one) is conservatively left open.
fn mercadopago_reported_dispute_status(status_detail: Option<&str>) -> enums::DisputeStatus {
    match status_detail {
        Some("settled") => enums::DisputeStatus::DisputeLost,
        Some("reimbursed") => enums::DisputeStatus::DisputeWon,
        _ => enums::DisputeStatus::DisputeOpened,
    }
}

impl MercadopagoPaymentsResponse {
    /// Parses `refunds[]` leniently: an entry that fails to parse, or that
    /// has no usable id, is skipped and logged rather than failing the sync.
    fn reported_refunds(&self) -> Vec<MercadopagoPaymentRefundEntry> {
        let mut parsed = Vec::new();
        for raw_entry in self.refunds.iter().flatten() {
            match serde_json::from_value::<MercadopagoPaymentRefundEntry>(raw_entry.clone()) {
                Ok(entry) if entry.id.is_some() => parsed.push(entry),
                Ok(_) => router_env::logger::warn!(
                    "mercadopago: skipping a reported refund with no usable id"
                ),
                Err(error) => router_env::logger::warn!(
                    ?error,
                    "mercadopago: skipping a malformed reported refund entry"
                ),
            }
        }
        parsed
    }

    /// A `charged_back` payment has no disputed-amount field of its own: the
    /// whole payment's `transaction_amount` is used, per the Mercado Pago
    /// contract (a full chargeback is the only kind MP's payment object
    /// reports).
    fn reported_dispute(&self, currency: enums::Currency) -> Option<ConnectorReportedDispute> {
        if self.status != MercadopagoPaymentStatus::ChargedBack {
            return None;
        }
        let transaction_amount = self.transaction_amount?;
        let amount = utils::convert_back_amount_to_minor_units(
            &FloatMajorUnitForConnector,
            transaction_amount,
            currency,
        )
        .map_err(|error| {
            router_env::logger::warn!(
                ?error,
                "mercadopago: could not convert the charged-back amount, skipping the dispute"
            );
        })
        .ok()?;

        Some(ConnectorReportedDispute {
            connector_dispute_id: self.id.to_string(),
            stage: enums::DisputeStage::Dispute,
            status: mercadopago_reported_dispute_status(self.status_detail.as_deref()),
            connector_status: "charged_back".to_string(),
            amount,
            currency,
            reason: self.status_detail.clone(),
        })
    }

    /// Builds the D5 carrier from this payment's `refunds[]` and (when
    /// `charged_back`) its own chargeback status. `None` when there is
    /// nothing to report, so the caller never attaches an empty carrier.
    pub(crate) fn reported_activity(
        &self,
        currency: enums::Currency,
    ) -> Option<ConnectorReportedActivity> {
        let refunds: Vec<ConnectorReportedRefund> = self
            .reported_refunds()
            .into_iter()
            .filter_map(|entry| entry.into_reported_refund(currency))
            .collect();
        let dispute = self.reported_dispute(currency);

        if refunds.is_empty() && dispute.is_none() {
            None
        } else {
            Some(ConnectorReportedActivity { refunds, dispute })
        }
    }
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

// ============================================================================
// Checkout Pro - Responses (preference on Authorize, search on PSync)
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MercadopagoPreferenceResponse {
    /// Preference id, format "{collector_id}-{uuid}" — a String, which is what
    /// disambiguates the untagged enum against payments (id: i64).
    pub id: String,
    /// Hosted checkout URL. Required on purpose: a payment response never has it,
    /// so an untagged match can't confuse the two variants.
    pub init_point: String,
    #[serde(default)]
    pub sandbox_init_point: Option<String>,
    #[serde(default)]
    pub external_reference: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum MercadopagoAuthorizeResponse {
    /// `id: i64` + `status` — fails to parse a preference (id is a String there).
    /// Boxed: `MercadopagoPaymentsResponse` is large enough to trip
    /// clippy::large_enum_variant against the much smaller `Preference` variant.
    Payment(Box<MercadopagoPaymentsResponse>),
    /// `id: String` + `init_point` — fails to parse a payment (no init_point)
    Preference(Box<MercadopagoPreferenceResponse>),
}

impl<F, T> TryFrom<ResponseRouterData<F, MercadopagoAuthorizeResponse, T, PaymentsResponseData>>
    for RouterData<F, T, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<F, MercadopagoAuthorizeResponse, T, PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        match item.response {
            MercadopagoAuthorizeResponse::Payment(payment) => Self::try_from(ResponseRouterData {
                response: *payment,
                data: item.data,
                http_code: item.http_code,
            }),
            MercadopagoAuthorizeResponse::Preference(preference) => {
                // The MP payment does not exist until the buyer pays on the hosted
                // page: no transaction id yet. PSync finds it by external_reference
                // and its resource_id promotion persists the real id on the attempt.
                let redirection_data = RedirectForm::Form {
                    endpoint: preference.init_point.clone(),
                    method: Method::Get,
                    form_fields: HashMap::new(),
                };

                Ok(Self {
                    status: enums::AttemptStatus::AuthenticationPending,
                    response: Ok(PaymentsResponseData::TransactionResponse {
                        resource_id: ResponseId::NoResponseId,
                        redirection_data: Box::new(Some(redirection_data)),
                        mandate_reference: Box::new(None),
                        connector_metadata: Some(
                            serde_json::json!({ "preference_id": preference.id }),
                        ),
                        network_txn_id: None,
                        connector_response_reference_id: preference
                            .external_reference
                            .clone()
                            .or(Some(preference.id.clone())),
                        incremental_authorization_allowed: None,
                        charges: None,
                    }),
                    ..item.data
                })
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MercadopagoSearchResponse {
    /// DELIBERATELY required (no serde default): with a default, a single-payment
    /// response would deserialize as `Search { results: [] }` and every PSync
    /// would silently report "buyer hasn't paid yet".
    pub results: Vec<MercadopagoPaymentsResponse>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum MercadopagoPSyncResponse {
    /// Must stay FIRST: `results` is required, so a payment body falls through,
    /// while `{"results": [], ...}` (buyer hasn't paid) matches here.
    Search(MercadopagoSearchResponse),
    Payment(MercadopagoPaymentsResponse),
}

impl MercadopagoPSyncResponse {
    /// The payment object this sync resolved to, if any — the most recent
    /// search result for a Checkout Pro promotion, or the payment body
    /// itself. Used to build the D5 reported-activity carrier; a rejected or
    /// cancelled search result naturally reports nothing (a payment that was
    /// never captured has no refunds or chargeback), so no special-casing is
    /// needed to match `keep_waiting_for_buyer` below.
    pub(crate) fn resolved_payment(&self) -> Option<&MercadopagoPaymentsResponse> {
        match self {
            Self::Payment(payment) => Some(payment),
            Self::Search(search) => search.results.first(),
        }
    }
}

impl<F, T> TryFrom<ResponseRouterData<F, MercadopagoPSyncResponse, T, PaymentsResponseData>>
    for RouterData<F, T, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<F, MercadopagoPSyncResponse, T, PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        match item.response {
            MercadopagoPSyncResponse::Payment(payment) => Self::try_from(ResponseRouterData {
                response: payment,
                data: item.data,
                http_code: item.http_code,
            }),
            MercadopagoPSyncResponse::Search(search) => {
                // Promotion path (Checkout Pro attempt without a transaction id):
                // the search runs over OUR external_reference — never over ids taken
                // from the redirect query string, which the buyer controls. Results
                // come sorted by date_created desc, so first = most recent.
                match search.results.into_iter().next() {
                    // Never promote (nor hard-fail on) a rejected/cancelled payment
                    // while the hosted session can still be retried: the buyer may
                    // pay again on the same preference, and a terminal Failure here
                    // would lose that second payment and block future syncs
                    // (check_force_psync_precondition excludes Failure).
                    Some(payment)
                        if matches!(
                            payment.status,
                            MercadopagoPaymentStatus::Rejected
                                | MercadopagoPaymentStatus::Cancelled
                        ) =>
                    {
                        Ok(keep_waiting_for_buyer(item.data))
                    }
                    Some(payment) => Self::try_from(ResponseRouterData {
                        response: payment,
                        data: item.data,
                        http_code: item.http_code,
                    }),
                    // Empty search = the buyer hasn't paid yet.
                    None => Ok(keep_waiting_for_buyer(item.data)),
                }
            }
        }
    }
}

/// Sync outcome for a Checkout Pro attempt whose payment is not (yet) usable:
/// preserves the current attempt status — asserting a fixed status here could
/// resurrect an attempt that already failed for other reasons.
fn keep_waiting_for_buyer<F, T>(
    data: RouterData<F, T, PaymentsResponseData>,
) -> RouterData<F, T, PaymentsResponseData> {
    RouterData {
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
    }
}

fn get_mercadopago_error_message(status_detail: &str) -> String {
    match status_detail {
        // Card rejections - bad filled data
        "cc_rejected_bad_filled_card_number" => "The card number is incorrect".to_string(),
        "cc_rejected_bad_filled_date" => "The expiration date is incorrect".to_string(),
        "cc_rejected_bad_filled_other" => "Some card detail is incorrect".to_string(),
        "cc_rejected_bad_filled_security_code" => {
            "The security code (CVV) is incorrect".to_string()
        }

        // Card rejections - card issues
        "cc_rejected_blacklist" => "The card is blocked".to_string(),
        "cc_rejected_call_for_authorize" => {
            "The payment requires authorization - call your bank".to_string()
        }
        "cc_rejected_card_disabled" => "The card is disabled - contact your bank".to_string(),
        "cc_rejected_card_error" => "The card could not be processed".to_string(),
        "cc_rejected_card_type_not_allowed" => {
            "This card type is not allowed for this payment".to_string()
        }

        // Card rejections - transaction issues
        "cc_rejected_duplicated_payment" => "This payment has already been processed".to_string(),
        "cc_rejected_high_risk" => "The payment was rejected due to high risk".to_string(),
        "cc_rejected_insufficient_amount" => "Insufficient funds".to_string(),
        "cc_rejected_invalid_installments" => {
            "Invalid number of installments for this card".to_string()
        }
        "cc_rejected_max_attempts" => {
            "Maximum retry attempts reached - try with another card".to_string()
        }
        "cc_rejected_other_reason" => "The payment was rejected by the card issuer".to_string(),

        // 3DS rejections
        "cc_rejected_3ds_challenge" => "Payment rejected for not passing 3DS challenge".to_string(),
        "cc_rejected_3ds_mandatory" => {
            "3DS authentication is mandatory for this payment".to_string()
        }

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
        "bad_request" => match cause_code {
            Some("1") | Some("3") => "Invalid or missing parameters in the request".to_string(),
            Some("2") => {
                "Invalid token - the card token may have expired or is invalid".to_string()
            }
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
        },
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
        self.cause
            .as_ref()
            .map(|causes| {
                causes
                    .iter()
                    .filter_map(|c| match (&c.code, &c.description) {
                        (Some(code), Some(desc)) => Some(format!("Code {}: {}", code, desc)),
                        (Some(code), None) => Some(format!("Code {}", code)),
                        (None, Some(desc)) => Some(desc.clone()),
                        (None, None) => None,
                    })
                    .collect::<Vec<_>>()
                    .join("; ")
            })
            .filter(|s| !s.is_empty())
    }
}

// ============================================================================
// Webhook Types
// ============================================================================

/// Webhooks v1 / app-level push format: full JSON body.
/// Payment example: {"action":"payment.created","data":{"id":"150211668619"},...}
/// Chargeback example (app-level push only, never via `notification_url`):
/// {"type":"topic_chargebacks_wh","actions":["created"],
///  "data":{"id":"<chargeback id>","payment_id":168355689156},...}
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
    /// Present on payment/refund notifications ("payment.updated", ...).
    /// Absent on the dedicated chargeback push format, which uses `actions`
    /// (plural, below) and `type` instead.
    #[serde(default)]
    pub action: Option<String>,
    /// Only present on the chargeback push format. Not otherwise consumed;
    /// kept for observability (visible via `get_webhook_resource_object`'s
    /// masked_serialize logging is action-based, not actions-based, so this
    /// mainly documents the wire format for future readers).
    #[serde(default)]
    pub actions: Option<Vec<String>>,
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
    // Boxed: `MercadopagoWebhookBody` is large enough to trip
    // clippy::large_enum_variant against the much smaller `Feed` variant.
    Full(Box<MercadopagoWebhookBody>),
    Feed(MercadopagoWebhookFeedBody),
}

impl MercadopagoWebhookBodyEnum {
    /// Classifies the notification into what Hyperswitch can act on: which
    /// payment (if any) needs a re-sync, or that there is nothing to do.
    /// Both `get_webhook_event_type` and `get_webhook_object_reference_id`
    /// (in `mercadopago.rs`) go through this single place so the two stay
    /// consistent with each other.
    pub fn classify(&self) -> MercadopagoWebhookNotification {
        match self {
            Self::Full(body) => body.classify(),
            Self::Feed(body) => match body.topic.as_str() {
                "payment" => MercadopagoWebhookNotification::Payment {
                    payment_id: body.resource.clone(),
                },
                // Feed v2 never carries the payment a chargeback applies to.
                "chargebacks" => MercadopagoWebhookNotification::ChargebackWithoutPayment,
                _ => MercadopagoWebhookNotification::Unknown,
            },
        }
    }

    /// Convert to a unified struct for get_webhook_resource_object (implements ErasedMaskSerialize)
    pub fn to_resource_object(&self) -> MercadopagoWebhookResourceObject {
        match self {
            Self::Full(body) => MercadopagoWebhookResourceObject {
                resource_id: body.data.id.clone(),
                topic: body
                    .webhook_type
                    .clone()
                    .unwrap_or_else(|| "payment".to_string()),
                action: body.action.clone(),
            },
            Self::Feed(body) => MercadopagoWebhookResourceObject {
                resource_id: body.resource.clone(),
                topic: body.topic.clone(),
                action: None,
            },
        }
    }
}

impl MercadopagoWebhookBody {
    fn classify(&self) -> MercadopagoWebhookNotification {
        // The dedicated chargeback push: no singular `action`, `type` names
        // the topic. The chargeback id (`data.id`) is never usable as a
        // payment id — only `data.payment_id`, when present, is.
        if self.webhook_type.as_deref() == Some("topic_chargebacks_wh") {
            return chargeback_notification(self.data.payment_id.as_deref());
        }

        match self.action.as_deref() {
            Some("payment.created") | Some("payment.updated") => {
                MercadopagoWebhookNotification::Payment {
                    payment_id: self.data.id.clone(),
                }
            }
            // Refund state is read from the payment's own PSync response
            // (`refunds[]`, see D5/D6), never from the webhook body itself:
            // Mercado Pago's webhook payloads carry no refund status or
            // amount, only a resource id.
            Some("refund.created") | Some("refund.updated") => {
                MercadopagoWebhookNotification::Refund
            }
            // Not observed from Mercado Pago via `notification_url` in
            // practice (chargebacks arrive through the `topic_chargebacks_wh`
            // push above, or the IPN `chargebacks` topic/query below), kept
            // for forward compatibility with the documented action names.
            Some("chargeback.created") | Some("chargeback.updated") => {
                chargeback_notification(self.data.payment_id.as_deref())
            }
            _ => MercadopagoWebhookNotification::Unknown,
        }
    }
}

fn chargeback_notification(payment_id: Option<&str>) -> MercadopagoWebhookNotification {
    match payment_id {
        Some(payment_id) => MercadopagoWebhookNotification::ChargebackWithPayment {
            payment_id: payment_id.to_string(),
        },
        None => MercadopagoWebhookNotification::ChargebackWithoutPayment,
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
    /// The payment a chargeback applies to. Mercado Pago sends this as either
    /// a JSON number or a string depending on the push format, hence the
    /// tolerant deserializer (shared with `MercadopagoErrorCause::code`).
    #[serde(default, deserialize_with = "deserialize_code")]
    pub payment_id: Option<String>,
}

/// A Mercado Pago webhook notification, normalized across all wire formats
/// (Webhooks v1 / app-level push, Feed v2, IPN legacy) into what Hyperswitch
/// can act on. Never carries a status: Mercado Pago webhooks only ever
/// signal "something changed on this id", so every supported variant here
/// just triggers a live PSync (D1) — MP's own API, called with the
/// merchant's credentials, is the only source of truth for the actual state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MercadopagoWebhookNotification {
    /// A payment notification: PSync `payment_id`.
    Payment {
        payment_id: String,
    },
    /// A chargeback notification that names the payment it applies to: PSync
    /// that payment id (the sync itself reconciles the dispute record — D6).
    ChargebackWithPayment {
        payment_id: String,
    },
    /// A chargeback notification without a payment id (e.g. the IPN
    /// `topic=chargebacks` fallback, which carries only the chargeback id):
    /// nothing safe to sync against a chargeback id alone — never treat a
    /// chargeback id as a payment id.
    ChargebackWithoutPayment,
    /// A refund notification: refund state is read from the payment's own
    /// PSync response, never from here.
    Refund,
    Unknown,
}

impl MercadopagoWebhookNotification {
    /// The payment id to PSync, if this notification calls for one.
    pub fn payment_id_to_sync(&self) -> Option<&str> {
        match self {
            Self::Payment { payment_id } | Self::ChargebackWithPayment { payment_id } => {
                Some(payment_id.as_str())
            }
            Self::ChargebackWithoutPayment | Self::Refund | Self::Unknown => None,
        }
    }
}

impl From<&MercadopagoWebhookNotification> for api_models::webhooks::IncomingWebhookEvent {
    fn from(notification: &MercadopagoWebhookNotification) -> Self {
        match notification {
            MercadopagoWebhookNotification::Payment { .. }
            | MercadopagoWebhookNotification::ChargebackWithPayment { .. } => {
                Self::PaymentIntentProcessing
            }
            MercadopagoWebhookNotification::ChargebackWithoutPayment
            | MercadopagoWebhookNotification::Refund
            | MercadopagoWebhookNotification::Unknown => Self::EventNotSupported,
        }
    }
}

#[cfg(test)]
mod tests {
    use common_utils::types::MinorUnit;

    use super::*;

    const PAYMENT_JSON: &str = r#"{
        "id": 123456789,
        "status": "approved",
        "status_detail": "accredited",
        "external_reference": "pay_abc_1",
        "transaction_amount": 100.5
    }"#;

    const PREFERENCE_JSON: &str = r#"{
        "id": "1963547549-6b18effb-eeba-4daa-9c57-6c916c8f1775",
        "init_point": "https://www.mercadopago.com.ar/checkout/v1/redirect?pref_id=x",
        "sandbox_init_point": "https://sandbox.mercadopago.com.ar/checkout/v1/redirect?pref_id=x",
        "external_reference": "pay_abc_1"
    }"#;

    #[test]
    fn authorize_response_discriminates_payment_from_preference() {
        let payment: MercadopagoAuthorizeResponse = serde_json::from_str(PAYMENT_JSON).unwrap();
        assert!(matches!(payment, MercadopagoAuthorizeResponse::Payment(p) if p.id == 123456789));

        let preference: MercadopagoAuthorizeResponse =
            serde_json::from_str(PREFERENCE_JSON).unwrap();
        match preference {
            MercadopagoAuthorizeResponse::Preference(p) => {
                assert!(p.init_point.contains("checkout/v1/redirect"));
                assert_eq!(p.external_reference.as_deref(), Some("pay_abc_1"));
            }
            MercadopagoAuthorizeResponse::Payment(_) => {
                panic!("preference response must not parse as payment")
            }
        }
    }

    #[test]
    fn psync_response_single_payment_is_not_swallowed_by_search_variant() {
        // Guard for the serde trap: `results` must stay required, otherwise this
        // payment body would deserialize as Search { results: [] }.
        let parsed: MercadopagoPSyncResponse = serde_json::from_str(PAYMENT_JSON).unwrap();
        assert!(matches!(parsed, MercadopagoPSyncResponse::Payment(p) if p.id == 123456789));
    }

    #[test]
    fn psync_response_search_variants() {
        let empty: MercadopagoPSyncResponse =
            serde_json::from_str(r#"{"results": [], "paging": {"total": 0}}"#).unwrap();
        assert!(matches!(empty, MercadopagoPSyncResponse::Search(s) if s.results.is_empty()));

        let with_result: MercadopagoPSyncResponse = serde_json::from_str(&format!(
            r#"{{"results": [{PAYMENT_JSON}], "paging": {{"total": 1}}}}"#
        ))
        .unwrap();
        assert!(matches!(with_result, MercadopagoPSyncResponse::Search(s) if s.results.len() == 1));
    }

    #[test]
    fn filter_public_url_drops_local_hosts() {
        for local in [
            "http://localhost:8080/return",
            "http://sub.localhost/return",
            "http://127.0.0.1/return",
            "http://127.5.5.5/return",
            "http://[::1]/return",
            "http://0.0.0.0/return",
            "http://10.0.0.5/return",
            "http://192.168.1.10/return",
            "http://host.docker.internal:8080/return",
            "not a url",
        ] {
            assert_eq!(filter_public_url(Some(&local.to_string())), None, "{local}");
        }

        // Host parsing, not substring matching: these are legitimate public URLs.
        for public in [
            "https://pxsol.com/return",
            "https://shop.com/return?next=localhost",
            "https://mylocalhost.shop/return",
            "https://declensional-moira-bruno.ngrok-free.dev/payments/x/y/redirect/response/mercadopago",
        ] {
            assert_eq!(
                filter_public_url(Some(&public.to_string())),
                Some(public.to_string()),
                "{public}"
            );
        }

        assert_eq!(filter_public_url(None), None);
    }

    // ------------------------------------------------------------------
    // T1: webhook body parsing / classification
    // ------------------------------------------------------------------

    #[test]
    fn classifies_webhooks_v1_payment_notification() {
        let body: MercadopagoWebhookBodyEnum = serde_json::from_str(
            r#"{"action":"payment.updated","data":{"id":"150211668619"},"type":"payment"}"#,
        )
        .unwrap();
        assert_eq!(
            body.classify(),
            MercadopagoWebhookNotification::Payment {
                payment_id: "150211668619".to_string()
            }
        );
    }

    #[test]
    fn classifies_chargeback_push_with_payment_id_as_numeric_json() {
        let body: MercadopagoWebhookBodyEnum = serde_json::from_str(
            r#"{"type":"topic_chargebacks_wh","actions":["created"],
                "data":{"id":"cb_1","payment_id":168355689156}}"#,
        )
        .unwrap();
        assert_eq!(
            body.classify(),
            MercadopagoWebhookNotification::ChargebackWithPayment {
                payment_id: "168355689156".to_string()
            }
        );
    }

    #[test]
    fn classifies_chargeback_push_with_payment_id_as_string() {
        let body: MercadopagoWebhookBodyEnum = serde_json::from_str(
            r#"{"type":"topic_chargebacks_wh","actions":["created"],
                "data":{"id":"cb_1","payment_id":"168355689156"}}"#,
        )
        .unwrap();
        assert_eq!(
            body.classify(),
            MercadopagoWebhookNotification::ChargebackWithPayment {
                payment_id: "168355689156".to_string()
            }
        );
    }

    #[test]
    fn classifies_chargeback_push_without_payment_id_as_unsupported() {
        let body: MercadopagoWebhookBodyEnum = serde_json::from_str(
            r#"{"type":"topic_chargebacks_wh","actions":["created"],"data":{"id":"cb_1"}}"#,
        )
        .unwrap();
        assert_eq!(
            body.classify(),
            MercadopagoWebhookNotification::ChargebackWithoutPayment
        );
        assert_eq!(
            api_models::webhooks::IncomingWebhookEvent::from(&body.classify()),
            api_models::webhooks::IncomingWebhookEvent::EventNotSupported
        );
        // Never a payment id to sync against.
        assert_eq!(body.classify().payment_id_to_sync(), None);
    }

    #[test]
    fn classifies_refund_action_as_not_supported() {
        let body: MercadopagoWebhookBodyEnum = serde_json::from_str(
            r#"{"action":"refund.created","data":{"id":"r_1"},"type":"payment"}"#,
        )
        .unwrap();
        assert_eq!(body.classify(), MercadopagoWebhookNotification::Refund);
        assert_eq!(
            api_models::webhooks::IncomingWebhookEvent::from(&body.classify()),
            api_models::webhooks::IncomingWebhookEvent::EventNotSupported
        );
    }

    #[test]
    fn classifies_unknown_action_as_not_supported() {
        let body: MercadopagoWebhookBodyEnum = serde_json::from_str(
            r#"{"action":"something.else","data":{"id":"x"},"type":"payment"}"#,
        )
        .unwrap();
        assert_eq!(body.classify(), MercadopagoWebhookNotification::Unknown);
    }

    #[test]
    fn classifies_feed_v2_payment_topic() {
        let body: MercadopagoWebhookBodyEnum =
            serde_json::from_str(r#"{"resource":"150211668619","topic":"payment"}"#).unwrap();
        assert_eq!(
            body.classify(),
            MercadopagoWebhookNotification::Payment {
                payment_id: "150211668619".to_string()
            }
        );
    }

    #[test]
    fn classifies_feed_v2_chargebacks_topic_as_unsupported() {
        let body: MercadopagoWebhookBodyEnum =
            serde_json::from_str(r#"{"resource":"cb_1","topic":"chargebacks"}"#).unwrap();
        assert_eq!(
            body.classify(),
            MercadopagoWebhookNotification::ChargebackWithoutPayment
        );
    }

    #[test]
    fn payment_notification_never_carries_a_chargeback_id_as_payment_id() {
        // Regression guard for the original bug: a chargeback notification's
        // own id must never surface as the payment id to sync.
        let chargeback = MercadopagoWebhookNotification::ChargebackWithoutPayment;
        assert_eq!(chargeback.payment_id_to_sync(), None);
    }

    // ------------------------------------------------------------------
    // T2: PSync status mapping + refunds[] / dispute carrier
    // ------------------------------------------------------------------

    #[test]
    fn refunded_charged_back_and_in_mediation_map_to_charged() {
        for status in [
            MercadopagoPaymentStatus::Refunded,
            MercadopagoPaymentStatus::ChargedBack,
            MercadopagoPaymentStatus::InMediation,
        ] {
            assert_eq!(
                enums::AttemptStatus::from(status),
                enums::AttemptStatus::Charged
            );
        }
    }

    fn payment_response_with_refunds(
        refunds_json: &str,
        status: &str,
    ) -> MercadopagoPaymentsResponse {
        serde_json::from_str(&format!(
            r#"{{"id":168355689156,"status":"{status}","transaction_amount":1000.0,
                "currency_id":"ARS","refunds":{refunds_json}}}"#
        ))
        .unwrap()
    }

    #[test]
    fn parses_refunds_and_converts_float_to_minor_units() {
        let payment = payment_response_with_refunds(
            r#"[{"id":1,"amount":10.5,"status":"approved"}]"#,
            "approved",
        );
        let activity = payment.reported_activity(enums::Currency::ARS).unwrap();
        assert_eq!(activity.refunds.len(), 1);
        assert_eq!(activity.refunds[0].connector_refund_id, "1");
        assert_eq!(activity.refunds[0].amount, MinorUnit::new(1050));
        assert_eq!(activity.refunds[0].status, enums::RefundStatus::Success);
    }

    #[test]
    fn parses_refund_id_as_numeric_or_string() {
        let payment = payment_response_with_refunds(
            r#"[{"id":1,"amount":10.0,"status":"pending"},
                {"id":"2","amount":5.0,"status":"pending"}]"#,
            "approved",
        );
        let activity = payment.reported_activity(enums::Currency::ARS).unwrap();
        let ids: Vec<_> = activity
            .refunds
            .iter()
            .map(|r| r.connector_refund_id.as_str())
            .collect();
        assert_eq!(ids, vec!["1", "2"]);
    }

    #[test]
    fn unknown_refund_status_is_tolerantly_mapped_to_pending() {
        let payment = payment_response_with_refunds(
            r#"[{"id":1,"amount":10.0,"status":"some_new_status_mp_might_add"}]"#,
            "approved",
        );
        let activity = payment.reported_activity(enums::Currency::ARS).unwrap();
        assert_eq!(activity.refunds[0].status, enums::RefundStatus::Pending);
    }

    #[test]
    fn in_process_and_rejected_and_cancelled_refund_statuses_map_correctly() {
        let payment = payment_response_with_refunds(
            r#"[{"id":1,"amount":1.0,"status":"in_process"},
                {"id":2,"amount":1.0,"status":"rejected"},
                {"id":3,"amount":1.0,"status":"cancelled"}]"#,
            "approved",
        );
        let activity = payment.reported_activity(enums::Currency::ARS).unwrap();
        assert_eq!(activity.refunds[0].status, enums::RefundStatus::Pending);
        assert_eq!(activity.refunds[1].status, enums::RefundStatus::Failure);
        assert_eq!(activity.refunds[2].status, enums::RefundStatus::Failure);
    }

    #[test]
    fn payment_without_a_refunds_field_parses_fine() {
        // The common case: most payments carry no `refunds` at all.
        let payment: MercadopagoPaymentsResponse =
            serde_json::from_str(r#"{"id":1,"status":"approved","transaction_amount":100.0}"#)
                .unwrap();
        assert!(payment.refunds.is_none());
        assert!(payment.reported_activity(enums::Currency::ARS).is_none());
    }

    #[test]
    fn a_malformed_individual_refund_entry_is_skipped_not_fatal() {
        let payment = payment_response_with_refunds(
            r#"[{"id":1,"amount":10.0,"status":"approved"},
                {"amount":5.0,"status":"approved"},
                "not-an-object"]"#,
            "approved",
        );
        let activity = payment.reported_activity(enums::Currency::ARS).unwrap();
        // Only the first, well-formed entry survives.
        assert_eq!(activity.refunds.len(), 1);
        assert_eq!(activity.refunds[0].connector_refund_id, "1");
    }

    #[test]
    fn a_refund_entry_without_an_amount_is_skipped_not_defaulted_to_zero() {
        let payment =
            payment_response_with_refunds(r#"[{"id":1,"status":"approved"}]"#, "approved");
        assert!(payment.reported_activity(enums::Currency::ARS).is_none());
    }

    #[test]
    fn no_reported_activity_when_nothing_to_report() {
        let payment: MercadopagoPaymentsResponse =
            serde_json::from_str(r#"{"id":1,"status":"approved","transaction_amount":100.0}"#)
                .unwrap();
        assert!(payment.reported_activity(enums::Currency::ARS).is_none());
    }

    #[test]
    fn charged_back_status_detail_maps_to_dispute_snapshot() {
        for (status_detail, expected) in [
            ("in_process", enums::DisputeStatus::DisputeOpened),
            ("settled", enums::DisputeStatus::DisputeLost),
            ("reimbursed", enums::DisputeStatus::DisputeWon),
            ("something_else", enums::DisputeStatus::DisputeOpened),
        ] {
            let payment: MercadopagoPaymentsResponse = serde_json::from_str(&format!(
                r#"{{"id":168355689156,"status":"charged_back","status_detail":"{status_detail}",
                    "transaction_amount":250.0}}"#
            ))
            .unwrap();
            let activity = payment.reported_activity(enums::Currency::ARS).unwrap();
            let dispute = activity
                .dispute
                .expect("charged_back must report a dispute");
            assert_eq!(dispute.status, expected, "status_detail={status_detail}");
            assert_eq!(dispute.connector_dispute_id, "168355689156");
            assert_eq!(dispute.stage, enums::DisputeStage::Dispute);
            assert_eq!(dispute.amount, MinorUnit::new(25000));
        }
    }

    #[test]
    fn in_mediation_never_creates_a_dispute() {
        let payment: MercadopagoPaymentsResponse =
            serde_json::from_str(r#"{"id":1,"status":"in_mediation","transaction_amount":100.0}"#)
                .unwrap();
        assert!(payment.reported_activity(enums::Currency::ARS).is_none());
    }
}
