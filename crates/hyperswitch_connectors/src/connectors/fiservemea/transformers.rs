use std::collections::HashMap;

use common_enums::enums;
use common_utils::{
    request::Method,
    types::{FloatMajorUnit, StringMajorUnit},
};
use hyperswitch_domain_models::{
    payment_method_data::PaymentMethodData,
    router_data::{ConnectorAuthType, ErrorResponse, PaymentMethodToken, RouterData},
    router_flow_types::{
        payments::{self, SetupMandate},
        refunds::{Execute, RSync},
    },
    router_request_types::{
        CompleteAuthorizeRedirectResponse, ResponseId, SetupMandateRequestData,
    },
    router_response_types::{
        MandateReference, PaymentsResponseData, RedirectForm, RefundsResponseData,
    },
    types::{
        PaymentsAuthorizeRouterData, PaymentsCancelRouterData, PaymentsCaptureRouterData,
        PaymentsCompleteAuthorizeRouterData, RefundsRouterData, TokenizationRouterData,
    },
};
use error_stack::ResultExt;
use hyperswitch_interfaces::{consts, errors};
use masking::{ExposeInterface, PeekInterface, Secret};
use serde::{Deserialize, Serialize};

use crate::{
    types::{RefundsResponseRouterData, ResponseRouterData},
    utils::{
        CardData as _, CardIssuer, NetworkTokenData as _,
        PaymentsAuthorizeRequestData as _, RouterData as _,
    },
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
    /// Criptograma del Network Token, en base64. Sólo aplica al flujo passthrough (§9.2), donde
    /// el comercio ya tiene su propio token de red: en el flujo integrado el gateway resuelve el
    /// token por su cuenta y este campo no va. El gateway valida el largo entre 20 y 256
    /// caracteres (verificado contra cert: `"ZZZZ"` devuelve
    /// `order.tokenCryptogram: size must be between 20 and 256`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    token_cryptogram: Option<Secret<String>>,
}

/// Largos que el gateway acepta para `order.tokenCryptogram`.
const FISERVEMEA_TOKEN_CRYPTOGRAM_LEN: std::ops::RangeInclusive<usize> = 20..=256;

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
    /// Declara que la tarjeta detrás de un token guardado es Mastercard, para poder emitir el
    /// bloque de Card on File que la guía pide para esa marca. Sólo hace falta cuando se cobra
    /// con un token de IPG, donde el request no trae la marca.
    pub card_network_is_mastercard: Option<bool>,
    /// `authenticationRequest.challengeIndicator` crudo, tal como lo mandó el comercio; se
    /// valida en `FiservemeaAuthenticationRequest::new` contra `FISERVEMEA_CHALLENGE_INDICATORS`.
    pub challenge_indicator: Option<String>,
    /// `authenticationRequest.challengeWindowSize` crudo; se valida contra
    /// `FISERVEMEA_CHALLENGE_WINDOW_SIZES`.
    pub challenge_window_size: Option<String>,
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
    // Fiserv caps `dynamicMerchantName` around 25 characters (the exact limit varies by
    // acquirer/brand and is truncated downstream); truncate defensively so an over-long value
    // isn't rejected. `chars()` keeps the truncation on a UTF-8 boundary.
    .map(|s| s.chars().take(25).collect::<String>())
}

/// Extracts the `three_ds_data_only` opt-in flag (JSON bool or bool-ish string), mirroring
/// `extract_installment_interest`. `None` when absent/unparseable.
fn extract_three_ds_data_only(source: Option<&serde_json::Value>) -> Option<bool> {
    extract_bool_field(source, &["three_ds_data_only", "threeDsDataOnly"])
}

/// Lee un bool que puede venir como bool JSON o como string bool-ish, igual que el resto de los
/// extractores de metadata de este archivo.
fn extract_bool_field(source: Option<&serde_json::Value>, keys: &[&str]) -> Option<bool> {
    let value = lookup_field(source, keys)?;
    value.as_bool().or_else(|| match value.as_str() {
        Some(s) if s.eq_ignore_ascii_case("true") => Some(true),
        Some(s) if s.eq_ignore_ascii_case("false") => Some(false),
        _ => None,
    })
}

/// Extrae el valor crudo de `challengeIndicator`/`challengeWindowSize` de una fuente JSON.
///
/// A diferencia del resto de los `extract_*`, acá un valor mal formado NO se descarta: se
/// devuelve tal cual para que la validación posterior lo rechace. Descartarlo caería al default
/// `01`/`05`, y en el caso del indicador eso puede ser una autenticación más débil que la que el
/// comercio pidió (p. ej. un `04` con typo terminaría como "sin preferencia").
/// Todo lo que sea un entero —el número JSON `3` o el string `"3"`— se normaliza a dos dígitos
/// (`"03"`), porque la guía escribe los valores con cero a la izquierda y es fácil que un cliente
/// mande el número pelado.
/// Un `null` o un string vacío se toman como "no configurado" (y por lo tanto caen al default),
/// no como valor inválido: es la forma habitual en que un cliente serializa un campo opcional
/// que no completó.
fn extract_challenge_field(source: Option<&serde_json::Value>, keys: &[&str]) -> Option<String> {
    let raw = match lookup_field(source, keys)? {
        serde_json::Value::Null => return None,
        serde_json::Value::String(s) => s.trim().to_string(),
        other => other.to_string(),
    };
    if raw.is_empty() {
        return None;
    }
    Some(match raw.parse::<u8>() {
        Ok(number) => format!("{number:02}"),
        Err(_) => raw,
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
            challenge_indicator: extract_challenge_field(metadata, CHALLENGE_INDICATOR_KEYS)
                .or_else(|| extract_challenge_field(frm_metadata, CHALLENGE_INDICATOR_KEYS)),
            challenge_window_size: extract_challenge_field(metadata, CHALLENGE_WINDOW_SIZE_KEYS)
                .or_else(|| extract_challenge_field(frm_metadata, CHALLENGE_WINDOW_SIZE_KEYS)),
            card_network_is_mastercard: extract_bool_field(metadata, CARD_NETWORK_MASTERCARD_KEYS)
                .or_else(|| extract_bool_field(frm_metadata, CARD_NETWORK_MASTERCARD_KEYS)),
        }
    }
}

const CARD_NETWORK_MASTERCARD_KEYS: &[&str] =
    &["card_network_is_mastercard", "cardNetworkIsMastercard"];
const CHALLENGE_INDICATOR_KEYS: &[&str] = &["challenge_indicator", "challengeIndicator"];
const CHALLENGE_WINDOW_SIZE_KEYS: &[&str] = &["challenge_window_size", "challengeWindowSize"];

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaInstallmentOptions {
    /// Opcional porque los ejemplos de recurrencia de la guía mandan `installmentOptions` con
    /// sólo `recurringType`, sin cuotas. Cuando hay cuotas se serializa igual que antes.
    #[serde(skip_serializing_if = "Option::is_none")]
    number_of_installments: Option<i32>,
    #[serde(rename = "Interest", skip_serializing_if = "Option::is_none", default)]
    interest: Option<bool>,
    /// `FIRST` en la primera transacción del ciclo recurrente y `REPEAT` en las siguientes
    /// (guía §11.3.1). Va acá dentro y no a nivel de `order`.
    #[serde(skip_serializing_if = "Option::is_none")]
    recurring_type: Option<FiservemeaRecurringType>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "UPPERCASE")]
pub enum FiservemeaRecurringType {
    First,
    Repeat,
}

/// Mensajería de credencial almacenada (Card on File), a nivel raíz del request.
///
/// Los valores salen de los ejemplos de la guía §11.3.1, y NO son simétricos entre marcas:
///
/// - **Visa FIRST**: no lleva `storedCredentials`; alcanza `recurringType: FIRST`.
/// - **Visa REPEAT**: `sequence: SUBSEQUENT` + `referencedSchemeTransactionId` con el
///   `schemeTransactionId` que devolvió la transacción original.
/// - **Mastercard FIRST y REPEAT**: `initiator: MERCHANT` +
///   `indicatorSubcategory: CREDENTIAL_ON_FILE_FIRST` en los dos casos (el ejemplo de la guía
///   repite `CREDENTIAL_ON_FILE_FIRST` también en la SUBSEQUENT), y el FIRST agrega además el
///   bloque de 3DS Data Only.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaStoredCredentials {
    sequence: FiservemeaStoredCredentialSequence,
    scheduled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    initiator: Option<FiservemeaStoredCredentialInitiator>,
    #[serde(skip_serializing_if = "Option::is_none")]
    indicator_subcategory: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    referenced_scheme_transaction_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "UPPERCASE")]
pub enum FiservemeaStoredCredentialSequence {
    First,
    Subsequent,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "UPPERCASE")]
pub enum FiservemeaStoredCredentialInitiator {
    Cardholder,
    Merchant,
}

/// Único valor de `indicatorSubcategory` que usan los ejemplos de la guía.
const FISERVEMEA_INDICATOR_CREDENTIAL_ON_FILE_FIRST: &str = "CREDENTIAL_ON_FILE_FIRST";

impl FiservemeaStoredCredentials {
    /// Arma el bloque según marca y posición en el ciclo, siguiendo los ejemplos de la guía.
    /// Devuelve `None` cuando la guía no manda el bloque (el FIRST de Visa).
    fn new(
        is_mastercard: bool,
        is_first: bool,
        referenced_scheme_transaction_id: Option<String>,
    ) -> Option<Self> {
        let sequence = if is_first {
            FiservemeaStoredCredentialSequence::First
        } else {
            FiservemeaStoredCredentialSequence::Subsequent
        };
        if is_mastercard {
            return Some(Self {
                sequence,
                scheduled: false,
                initiator: Some(FiservemeaStoredCredentialInitiator::Merchant),
                indicator_subcategory: Some(FISERVEMEA_INDICATOR_CREDENTIAL_ON_FILE_FIRST),
                referenced_scheme_transaction_id,
            });
        }
        // Visa: el FIRST no lleva el bloque, y el REPEAT lo lleva sólo para transportar el
        // `referencedSchemeTransactionId`. Sin ese id no hay nada que informar.
        let referenced = referenced_scheme_transaction_id?;
        Some(Self {
            sequence,
            scheduled: false,
            initiator: None,
            indicator_subcategory: None,
            referenced_scheme_transaction_id: Some(referenced),
        })
    }
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
    /// Opcional porque el network token passthrough no lo lleva: la guía dice que ahí "el
    /// parámetro CardCodeValue no será requerido". En los pagos con tarjeta va siempre, así que
    /// el request serializado queda igual que antes.
    #[serde(skip_serializing_if = "Option::is_none")]
    security_code: Option<Secret<String>>,
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

/// Subclase 3DS 2.1/2.2 del `authenticationRequest`. Acepta `challengeIndicator` y
/// `challengeWindowSize`, pero NO `messageCategory`.
const FISERVEMEA_AUTH_TYPE_SECURE3D21: &str = "Secure3D21AuthenticationRequest";

/// Clase base del `authenticationRequest`, la única que declara `messageCategory`
/// (guía §10.1.6). Es la que exige la modalidad Data Only.
const FISERVEMEA_AUTH_TYPE_SECURE3D_BASE: &str = "Secure3DAuthenticationRequest";

/// `messageCategory` de la modalidad Mastercard Data Only (guía §10.1.6 y §10.4).
const FISERVEMEA_MESSAGE_CATEGORY_DATA_ONLY: &str = "80";

/// Valores válidos de `challengeIndicator` (guía §10.1.1, pág. 31). El gateway los valida
/// contra esta misma lista cerrada.
const FISERVEMEA_CHALLENGE_INDICATORS: [&str; 9] =
    ["01", "02", "03", "04", "05", "06", "07", "08", "09"];

/// Marcador con el que el conector distingue, en el retorno del 3DS, cuál de las dos URLs se
/// golpeó. NO es una atestación de autenticación: es un hecho del servidor sobre qué endpoint
/// recibió la llamada, y por eso se puede confiar en él para decidir el flujo.
const THREE_DS_CALLBACK_PARAM: &str = "fiservemea3ds";
/// La URL que se le da al ACS para que publique la notificación del 3DSMethod. Esa llamada
/// ocurre DENTRO del iframe oculto, así que su respuesta es invisible y no puede ser la que
/// continúe la autenticación.
const THREE_DS_CALLBACK_METHOD: &str = "method";
/// La URL a la que el wrapper navega la ventana principal cumplida la espera. Es la única visible
/// para el tarjetahabiente, así que es la que tiene que llevar el PATCH de continuación: su
/// respuesta es la que trae el desafío.
const THREE_DS_CALLBACK_TERM: &str = "term";

/// Cuelga el marcador del `complete_authorize_url` sin romper un query string existente.
fn build_three_ds_callback_url(
    complete_authorize_url: &str,
    callback: &str,
) -> Result<String, error_stack::Report<errors::ConnectorError>> {
    let mut url = url::Url::parse(complete_authorize_url).change_context(
        errors::ConnectorError::InvalidDataFormat {
            field_name: "complete_authorize_url",
        },
    )?;
    url.query_pairs_mut()
        .append_pair(THREE_DS_CALLBACK_PARAM, callback);
    Ok(url.into())
}

/// `true` cuando este CompleteAuthorize es la notificación que el ACS publicó en la
/// `methodNotificationURL`, o sea la que llega dentro del iframe oculto.
///
/// Es la llamada que NO debe continuar la autenticación: si lo hiciera, la respuesta —el form del
/// desafío, o el resultado final— se renderizaría invisible y el tarjetahabiente nunca volvería al
/// comercio. La continuación la manda el retorno por la `termURL`, que sí ocurre en la ventana
/// principal.
///
/// Se acepta el marcador tanto en el query string como en el payload JSON, porque el ACS publica
/// de las dos formas. Sin marcador se responde `false`, que es el comportamiento de antes: sirve
/// para las transacciones iniciadas antes de este cambio.
pub(super) fn is_acs_method_notification(
    redirect_response: &CompleteAuthorizeRedirectResponse,
) -> bool {
    if let Some(params) = redirect_response.params.as_ref() {
        for (key, val) in url::form_urlencoded::parse(params.peek().as_bytes()) {
            if key.eq_ignore_ascii_case(THREE_DS_CALLBACK_PARAM) {
                return val.eq_ignore_ascii_case(THREE_DS_CALLBACK_METHOD);
            }
        }
    }
    if let Some(payload) = redirect_response.payload.as_ref() {
        if let Some(object) = payload.peek().as_object() {
            if let Some(value) = object
                .iter()
                .find(|(key, _)| key.eq_ignore_ascii_case(THREE_DS_CALLBACK_PARAM))
                .and_then(|(_, value)| value.as_str())
            {
                return value.eq_ignore_ascii_case(THREE_DS_CALLBACK_METHOD);
            }
        }
    }
    false
}

/// Espera mínima antes de continuar la autenticación tras mostrar el `methodForm`. La guía es
/// explícita: hay que esperar un mínimo de 10 segundos a que el ACS complete su POST y recién
/// entonces determinar el estado de notificación del método.
const THREE_DS_METHOD_MIN_WAIT_MS: u32 = 10_000;

/// Escapa un valor para meterlo en un atributo HTML entre comillas dobles (`srcdoc`).
fn escape_html_attribute(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#39;"),
            other => escaped.push(other),
        }
    }
    escaped
}

/// Escapa un valor para usarlo como literal de string JavaScript entre comillas dobles.
/// `<` va en su forma unicode para que nada dentro del valor pueda cerrar el `<script>`.
fn escape_js_string(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            '<' => escaped.push_str("\\u003c"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            other => escaped.push(other),
        }
    }
    escaped
}

/// Envuelve el `methodForm` del gateway en una página que sí puede continuar el flujo.
///
/// El `methodForm` que manda Fiserv es un iframe **oculto** más un form cuyo `target` apunta a
/// ese mismo iframe. Entregado tal cual, todo el 3DS queda encerrado ahí: el desafío se
/// renderiza invisible y el tarjetahabiente nunca vuelve al comercio. El wrapper lo aloja en un
/// iframe propio (para que el fingerprint del emisor igual se ejecute) y, cumplida la espera
/// mínima de la guía, navega la **ventana principal** a la URL de retorno, que es la única
/// forma de que la respuesta siguiente sea visible.
///
/// La guarda `window.self === window.top` es necesaria porque esta misma página puede terminar
/// cargada dentro de un iframe si el ACS reenvía la notificación: en ese caso no debe navegar
/// nada, o dispararía un retorno duplicado.
pub(super) fn build_three_ds_method_wrapper(method_form: &str, return_url: &str) -> String {
    let srcdoc = escape_html_attribute(method_form);
    let return_url_js = escape_js_string(return_url);
    format!(
        r#"<div style="text-align:center;font-family:Arial,Helvetica,sans-serif;padding:24px;">Verificando su tarjeta, aguarde unos segundos…</div>
<iframe id="fiservemeaThreeDsMethodFrame" style="visibility:hidden;width:1px;height:1px;border:0;position:absolute;" srcdoc="{srcdoc}"></iframe>
<script type="text/javascript">
(function () {{
  if (window.self !== window.top) {{ return; }}
  var target = "{return_url_js}";
  var navigated = false;
  function continueAuthentication() {{
    if (navigated) {{ return; }}
    navigated = true;
    window.location.replace(target);
  }}
  window.setTimeout(continueAuthentication, {THREE_DS_METHOD_MIN_WAIT_MS});
}})();
</script>"#
    )
}

/// Reemplaza el `methodForm` crudo de la respuesta por la página wrapper.
///
/// Se hace acá y no en `to_redirection` porque la URL de retorno sale del
/// `complete_authorize_url` del request, que la conversión genérica de respuestas no ve.
pub(super) fn wrap_three_ds_method_redirection(router_data: &mut PaymentsAuthorizeRouterData) {
    // `Html` sólo lo produce la rama del `methodForm`; el desafío sale como `Form` al ACS y no
    // necesita wrapper. Sin `complete_authorize_url` se deja la respuesta como está.
    let Some(url) = router_data.request.complete_authorize_url.clone() else {
        return;
    };
    // La ventana principal vuelve por la termURL, que es la que lleva el PATCH de continuación.
    let Ok(return_url) = build_three_ds_callback_url(&url, THREE_DS_CALLBACK_TERM) else {
        return;
    };
    if let Ok(PaymentsResponseData::TransactionResponse {
        ref mut redirection_data,
        ..
    }) = router_data.response
    {
        if let Some(RedirectForm::Html { html_data }) = redirection_data.as_ref() {
            **redirection_data = Some(RedirectForm::Html {
                html_data: build_three_ds_method_wrapper(html_data, &return_url),
            });
        }
    }
}

/// Valores válidos de `challengeWindowSize` (guía §10.1.1, pág. 31):
/// 01 = 250x400, 02 = 390x400, 03 = 500x600, 04 = 600x400, 05 = pantalla completa.
const FISERVEMEA_CHALLENGE_WINDOW_SIZES: [&str; 5] = ["01", "02", "03", "04", "05"];

/// `01` = sin preferencia; es además el valor que el gateway completa por defecto si el campo
/// no viaja, así que mandarlo explícito no cambia el comportamiento.
const FISERVEMEA_DEFAULT_CHALLENGE_INDICATOR: &str = "01";

/// `05` = pantalla completa. La opción más angosta (`01`, 250x400) rinde mal en viewports
/// modernos/móviles, así que el default propio es pantalla completa.
const FISERVEMEA_DEFAULT_CHALLENGE_WINDOW_SIZE: &str = "05";

/// 3DS native (Fiserv IPG "provider-owned" flow) authentication request object.
/// Only emitted when the payment is `is_three_ds()`; absent otherwise so the
/// NoThreeDs request stays byte-identical to the pre-3DS behavior. See vendor doc
/// §10.1.1 (lines 526-578) and design spec §3.4.
///
/// El `authenticationType` no es decorativo: selecciona la clase Java que IPG usa para
/// deserializar el objeto, y cada clase acepta un conjunto distinto de campos. Ver
/// `FiservemeaAuthenticationRequest::new` para la bifurcación 3DS normal / Data Only.
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
    // Mastercard 3DS Data-Only: `"80"` pide los datos de autenticación sin desafío
    // (guía §10.1.6). Sólo existe en la clase base, nunca en `Secure3D21AuthenticationRequest`.
    #[serde(skip_serializing_if = "Option::is_none")]
    message_category: Option<String>,
}

/// Valida un valor de `challengeIndicator`/`challengeWindowSize` contra la lista cerrada de la
/// guía. Delegar la validación al gateway no sirve: ante un valor fuera de rango contesta un 400
/// con un `error` pelado, sin `code` ni `details`
/// (`"Error parsing json. Erroneous Field: authenticationRequest.challengeIndicator.
/// Cause: Unexpected value '99'"`), que el comercio no puede correlacionar con su metadata.
fn validate_challenge_field(
    value: &str,
    allowed: &[&str],
    field_name: &'static str,
) -> Result<String, error_stack::Report<errors::ConnectorError>> {
    if allowed.contains(&value) {
        Ok(value.to_string())
    } else {
        Err(errors::ConnectorError::InvalidDataFormat { field_name }.into())
    }
}

impl FiservemeaAuthenticationRequest {
    /// Arma el `authenticationRequest` según la modalidad pedida por el comercio.
    ///
    /// Data Only y 3DS normal no comparten la misma clase de request. `messageCategory` sólo
    /// existe en la clase base `Secure3DAuthenticationRequest`: emitirlo junto a la subclase
    /// `Secure3D21AuthenticationRequest` hace que el gateway rechace la transacción entera con
    /// 400 `INVALID_INPUT` / `"No field named 'messageCategory' exists for class
    /// Secure3D21AuthenticationRequest"` (verificado contra cert), así que el pago ni siquiera
    /// llega a autorizarse. Por simetría con el ejemplo de la guía §10.1.6, la rama Data Only
    /// tampoco manda `challengeIndicator`/`challengeWindowSize`: en Data Only no hay desafío
    /// que configurar.
    fn new(
        term_url: String,
        method_notification_url: String,
        meta: &FiservemeaMetadataObject,
        is_mastercard: bool,
    ) -> Result<Self, error_stack::Report<errors::ConnectorError>> {
        let challenge_indicator = meta
            .challenge_indicator
            .as_deref()
            .map(|value| {
                validate_challenge_field(
                    value,
                    &FISERVEMEA_CHALLENGE_INDICATORS,
                    "metadata.challenge_indicator",
                )
            })
            .transpose()?;
        // El tamaño de la ventana del desafío no es un parámetro de autenticación: es el
        // tamaño del iframe. Un valor fuera de rango no degrada nada, así que se cae al default
        // en vez de tirar el pago abajo — a diferencia del indicador, donde sí importa.
        let challenge_window_size = meta.challenge_window_size.as_deref().filter(|value| {
            let valido = FISERVEMEA_CHALLENGE_WINDOW_SIZES.contains(value);
            if !valido {
                router_env::logger::warn!(
                    challenge_window_size = %value,
                    "fiservemea: challengeWindowSize fuera de rango; se usa el default"
                );
            }
            valido
        });

        // Data Only existe sólo para Mastercard. Con cualquier otra marca el gateway responde
        // `50738 "Invalid Message Category"` (verificado contra cert con una Visa), así que si
        // el comercio deja la bandera puesta como default global, todas sus ventas Visa
        // fallarían. Se ignora la bandera en vez de fallar: la alternativa correcta para esa
        // tarjeta es el 3DS normal, que es exactamente lo que hace la rama de abajo.
        let data_only = meta.three_ds_data_only.unwrap_or(false) && is_mastercard;
        if meta.three_ds_data_only.unwrap_or(false) && !is_mastercard {
            router_env::logger::warn!(
                "fiservemea: three_ds_data_only pedido en una tarjeta que no es Mastercard; \
                 se ignora y se usa 3DS normal (Data Only es exclusivo de Mastercard)"
            );
        }

        if data_only {
            return Ok(Self {
                authentication_type: FISERVEMEA_AUTH_TYPE_SECURE3D_BASE.to_string(),
                term_url,
                method_notification_url,
                challenge_indicator: None,
                challenge_window_size: None,
                message_category: Some(FISERVEMEA_MESSAGE_CATEGORY_DATA_ONLY.to_string()),
            });
        }

        Ok(Self {
            authentication_type: FISERVEMEA_AUTH_TYPE_SECURE3D21.to_string(),
            term_url,
            method_notification_url,
            challenge_indicator: Some(
                challenge_indicator
                    .unwrap_or_else(|| FISERVEMEA_DEFAULT_CHALLENGE_INDICATOR.to_string()),
            ),
            challenge_window_size: Some(
                challenge_window_size
                    .unwrap_or(FISERVEMEA_DEFAULT_CHALLENGE_WINDOW_SIZE)
                    .to_string(),
            ),
            message_category: None,
        })
    }
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
    /// Mensajería de Card on File. Va a nivel raíz del request, no dentro de `order`
    /// (guía §11.3.1). `None` en los pagos sueltos, que es el caso por defecto y deja el
    /// request serializado byte a byte igual que antes.
    #[serde(skip_serializing_if = "Option::is_none")]
    stored_credentials: Option<FiservemeaStoredCredentials>,
}

/// Whether `capture_method` signals auto-capture (`Automatic`/`SequentialAutomatic`), i.e. the
/// transaction should be treated as a sale/postauth rather than a pre-auth. Shared by the
/// Authorize request-type selection and `select_void_request_type` below, which both need the
/// same auto-capture-vs-manual distinction.
/// Largo máximo de `merchantTransactionId` en IPG (verificado contra el gateway cert).
const FISERVEMEA_MERCHANT_TRANSACTION_ID_MAX_LEN: usize = 40;

/// Parte el `approvalCode` de IPG, que llega como `<Y|N>:<código>:<texto>`
/// (por ejemplo `N:-11101:installment not supported` o `N:05:Do not honour`),
/// en (código, texto). Devuelve `(None, None)` si no tiene esa forma, para no
/// inventar un código cuando el gateway manda algo distinto.
fn split_approval_code(approval_code: Option<&str>) -> (Option<String>, Option<String>) {
    let mut parts = match approval_code {
        Some(code) => code.splitn(3, ':'),
        None => return (None, None),
    };
    let (_prefix, code, message) = (parts.next(), parts.next(), parts.next());
    let non_empty = |s: Option<&str>| {
        s.map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
    };
    (non_empty(code), non_empty(message))
}

fn is_auto_capture(capture_method: Option<enums::CaptureMethod>) -> bool {
    // `None` significa captura automática en la API de Hyperswitch, igual que en
    // PaymentsAuthorizeRequestData::is_auto_capture (crates/hyperswitch_connectors/src/utils.rs).
    // Tratarlo como manual mandaba PaymentCardPreAuthTransaction en pagos que el
    // comercio pidió automáticos: quedaba la retención sin capturar.
    !matches!(capture_method, Some(enums::CaptureMethod::Manual))
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
        // `installmentOptions` puede existir por cuotas, por recurrencia (`recurringType`), o
        // por las dos: la guía manda el mismo bloque para ambas cosas.
        let installments = fiservemea_meta.installments.filter(|n| *n > 1);
        let recurring_type = if item.router_data.request.is_cit_mandate_payment() {
            Some(FiservemeaRecurringType::First)
        } else if item.router_data.request.is_mandate_payment() {
            Some(FiservemeaRecurringType::Repeat)
        } else {
            None
        };
        let installment_options = (installments.is_some() || recurring_type.is_some()).then(|| {
            FiservemeaInstallmentOptions {
                number_of_installments: installments,
                // `Interest` sólo tiene sentido con un plan de cuotas: mandarlo suelto en un
                // recurrente sin cuotas sería un campo sin referente.
                interest: installments.and(fiservemea_meta.installment_interest),
                recurring_type,
            }
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
        let mut order = FiservemeaOrder {
            order_id: item.router_data.connector_request_reference_id.clone(),
            installment_options,
            additional_details,
            soft_descriptor,
            // Se completa más abajo, sólo en la rama de network token passthrough.
            token_cryptogram: None,
        };
        // IPG limita `merchantTransactionId` a 40 caracteres, mientras que
        // `merchant_order_reference_id` acepta hasta 255 en la API de Hyperswitch:
        // sin truncar, una referencia larga del comercio hace que el gateway
        // rechace la transacción entera. `chars()` corta en borde UTF-8.
        let merchant_transaction_id = item
            .router_data
            .request
            .merchant_order_reference_id
            .clone()
            .unwrap_or(item.router_data.connector_request_reference_id.clone())
            .chars()
            .take(FISERVEMEA_MERCHANT_TRANSACTION_ID_MAX_LEN)
            .collect::<String>();
        let transaction_amount = FiservemeaTransactionAmount {
            total: item.amount.clone(),
            currency: item.router_data.request.currency,
        };
        let auto_capture = is_auto_capture(item.router_data.request.capture_method);

        // Señales de Card on File, compartidas por la rama del token y la de tarjeta. La primera
        // del ciclo es la que trae la aceptación del titular y pide guardar la credencial; las
        // siguientes llegan con el `schemeTransactionId` de la original, que Hyperswitch persiste
        // como network transaction id y que Visa exige devolver en
        // `referencedSchemeTransactionId` (guía §11.3.1.1.b).
        let is_first_cof = item.router_data.request.is_cit_mandate_payment();
        let referenced_scheme_transaction_id = item
            .router_data
            .request
            .get_optional_network_transaction_id();
        // La marca decide la forma del bloque de Card on File, y no es simétrica entre marcas
        // (ver `FiservemeaStoredCredentials`).
        //
        // LÍMITE CONOCIDO: cuando se cobra con un token de IPG ya guardado, el request no trae
        // ni el PAN ni la marca — `payment_method_data` no es `Card` —, así que no se puede
        // resolver desde acá. En ese caso se cae a la forma de Visa, que es la mínima que la
        // guía documenta, y se avisa por log. Para el REPEAT de Mastercard la guía pide además
        // `initiator: MERCHANT` e `indicatorSubcategory`, que en ese camino no se pueden emitir:
        // el comercio lo puede forzar declarando la marca en la metadata.
        let brand_is_mastercard = match &item.router_data.request.payment_method_data {
            PaymentMethodData::Card(card) => {
                matches!(card.get_card_issuer(), Ok(CardIssuer::Master))
            }
            // El network token sí declara la marca.
            PaymentMethodData::NetworkToken(token) => {
                matches!(token.card_network, Some(common_enums::CardNetwork::Mastercard))
                    || matches!(token.get_card_issuer(), Ok(CardIssuer::Master))
            }
            _ => fiservemea_meta.card_network_is_mastercard.unwrap_or(false),
        };
        if (is_first_cof || referenced_scheme_transaction_id.is_some())
            && !brand_is_mastercard
            && !matches!(
                item.router_data.request.payment_method_data,
                PaymentMethodData::Card(_) | PaymentMethodData::NetworkToken(_)
            )
        {
            router_env::logger::warn!(
                "fiservemea: Card on File sin marca resoluble (se cobra con un token guardado); \
                 se usa la forma de storedCredentials de Visa. Si la tarjeta es Mastercard, \
                 declararlo en metadata.card_network_is_mastercard"
            );
        }
        let stored_credentials = if is_first_cof || referenced_scheme_transaction_id.is_some() {
            FiservemeaStoredCredentials::new(
                brand_is_mastercard,
                is_first_cof,
                referenced_scheme_transaction_id.clone(),
            )
        } else {
            None
        };

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
                // Es el caso central de Card on File: los ejemplos de recurrencia de la guía
                // usan justamente `PaymentTokenSaleTransaction` con un `paymentToken`.
                stored_credentials,
            });
        }

        match item.router_data.request.payment_method_data.clone() {
            PaymentMethodData::Card(req_card) => {
                // Se resuelve la marca ANTES de construir `card`, porque ahí `req_card` queda
                // parcialmente movido. Data Only es exclusivo de Mastercard; un BIN que no se
                // reconoce se trata como "no Mastercard", que es el lado seguro: se usa 3DS
                // normal en vez de pedir una modalidad que el gateway rechazaría con 50738.
                let is_mastercard = matches!(req_card.get_card_issuer(), Ok(CardIssuer::Master));
                let card = FiservemeaPaymentCard {
                    number: req_card.card_number.clone(),
                    expiry_date: FiservemeaExpiryDate {
                        month: req_card.card_exp_month.clone(),
                        year: req_card.get_card_expiry_year_2_digit()?,
                    },
                    security_code: Some(req_card.card_cvc),
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
                    // Las dos URLs tienen que ser distinguibles: la notificación del ACS llega
                    // dentro del iframe oculto y no puede continuar la autenticación; el retorno
                    // del navegador por la termURL sí.
                    Some(FiservemeaAuthenticationRequest::new(
                        build_three_ds_callback_url(&return_url, THREE_DS_CALLBACK_TERM)?,
                        build_three_ds_callback_url(&return_url, THREE_DS_CALLBACK_METHOD)?,
                        &fiservemea_meta,
                        is_mastercard,
                    )?)
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
                    stored_credentials,
                })
            }
            // Network Token passthrough (§9.2): el comercio ya tiene su token de red (propio o de
            // un TSP) y Hyperswitch lo entrega acá. El token viaja como `paymentCard.number`,
            // con su propio vencimiento y SIN CVV — la guía dice textual que "el parámetro
            // CardCodeValue no será requerido" —, y el criptograma va en `order.tokenCryptogram`.
            //
            // No confundir con el flujo MTRG integrado (OnTheGo/Asíncrono), donde se manda el PAN
            // real con CVV y es Fiserv quien le pide el token a la marca: ése entra por la rama
            // `PaymentMethodData::Card` de arriba y no lleva criptograma.
            PaymentMethodData::NetworkToken(token_data) => {
                // El 3DS sobre un network token se resuelve fuera del conector. Si el comercio
                // pidió 3DS y acá lo ignoráramos, la venta saldría sin autenticar sin que nadie
                // se enterase: es una degradación silenciosa de SCA, así que falla cerrado.
                if item.router_data.is_three_ds() {
                    return Err(errors::ConnectorError::NotImplemented(
                        "3DS with a network token for fiservemea".to_string(),
                    )
                    .into());
                }

                // El criptograma es obligatorio en la primera del ciclo, pero la guía dice
                // textual que "no hará falta enviar el criptograma en las transacciones de tipo
                // REPEAT" (§11.2). Exigirlo siempre rompería justamente el REPEAT documentado.
                let cryptogram = token_data.get_cryptogram();
                let es_repeat = referenced_scheme_transaction_id.is_some() || !is_first_cof;
                match cryptogram {
                    Some(cryptogram) => {
                        // Falla cerrado antes de pegarle al gateway: un criptograma fuera de
                        // rango devuelve un 400 opaco que no se puede atribuir al campo. El
                        // largo se mide en caracteres, que es la unidad del mensaje del gateway.
                        if !FISERVEMEA_TOKEN_CRYPTOGRAM_LEN
                            .contains(&cryptogram.peek().chars().count())
                        {
                            return Err(errors::ConnectorError::InvalidDataFormat {
                                field_name: "payment_method_data.network_token.token_cryptogram",
                            }
                            .into());
                        }
                        order.token_cryptogram = Some(cryptogram);
                    }
                    None if es_repeat => {}
                    None => {
                        return Err(errors::ConnectorError::MissingRequiredField {
                            field_name: "payment_method_data.network_token.token_cryptogram",
                        }
                        .into())
                    }
                }

                let card = FiservemeaPaymentCard {
                    number: token_data.get_network_token(),
                    expiry_date: FiservemeaExpiryDate {
                        month: token_data.get_network_token_expiry_month(),
                        year: token_data.get_token_expiry_year_2_digit()?,
                    },
                    // Sin CVV: el token de red no lo lleva.
                    security_code: None,
                    cardholder_name: None,
                };
                let request_type = if auto_capture {
                    FiservemeaRequestType::PaymentCardSaleTransaction
                } else {
                    FiservemeaRequestType::PaymentCardPreAuthTransaction
                };
                Ok(Self {
                    request_type,
                    store_id: auth.store_id,
                    merchant_transaction_id,
                    transaction_amount,
                    order,
                    payment_method: FiservemeaPaymentMethods::PaymentCard(card),
                    // Ya se verificó arriba que no se pidió 3DS.
                    authentication_request: None,
                    stored_credentials,
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
                    security_code: Some(req_card.card_cvc),
                    cardholder_name: req_card.card_holder_name.clone(),
                };
                Ok(Self {
                    request_type: FiservemeaRequestType::PaymentCardSaleTransaction,
                    store_id: auth.store_id,
                    // Mismo recorte que en Authorize: IPG rechaza con 400 INVALID_INPUT un
                    // `merchantTransactionId` de más de 40 caracteres (verificado contra el
                    // gateway cert: 40 pasa, 41 falla). El `connector_request_reference_id` es
                    // el `attempt_id`, o sea `{payment_id}_{n}`, y el `payment_id` que manda el
                    // comercio admite hasta 64 caracteres: sin recortar, un Zero Auth con una
                    // referencia larga se caía entero.
                    merchant_transaction_id: item
                        .connector_request_reference_id
                        .chars()
                        .take(FISERVEMEA_MERCHANT_TRANSACTION_ID_MAX_LEN)
                        .collect(),
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
                        token_cryptogram: None,
                    },
                    payment_method: FiservemeaPaymentMethods::PaymentCard(card),
                    authentication_request: None,
                    // El Zero Auth valida la tarjeta, no abre un ciclo recurrente.
                    stored_credentials: None,
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
                    security_code: Some(req_card.card_cvc),
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
// Todos los enums de respuesta llevan una variante `Unknown` con `#[serde(other)]`.
// Sin ella, la deserialización es todo-o-nada: un valor nuevo en CUALQUIERA de estos
// campos rompe el parseo de la respuesta entera, y como el gateway aprueba con HTTP 2xx,
// una venta cobrada termina reportada como error de conector (plata cobrada que
// Hyperswitch no registra). El descarte convierte "no conozco este valor" en un dato
// más, que después `map_status`/`map_refund_status` resuelven de forma conservadora.
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
    #[serde(other)]
    Unknown,
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
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum FiservemeaTransactionOrigin {
    Ecom,
    Moto,
    Mail,
    Phone,
    Retail,
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FiservemeaPaymentStatus {
    Approved,
    Waiting,
    Partial,
    ValidationFailed,
    ProcessingFailed,
    Declined,
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FiservemeaPaymentResult {
    Approved,
    Declined,
    Failed,
    Waiting,
    Partial,
    Fraud,
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaPaymentCardResponse {
    expiry_date: Option<FiservemeaExpiryDate>,
    bin: Option<String>,
    last4: Option<String>,
    brand: Option<String>,
    /// BIN y últimos 4 de la tarjeta que FONDEA la transacción, o sea el PAN real. Cuando el
    /// gateway procesa con Network Token, `bin`/`last4` de arriba son los del TOKEN y estos los
    /// del PAN. El manual de Network Token lo pide explícitamente: "es necesario que en cada
    /// transacción aprobada se realice un emparejamiento entre el Network Token y BIN + últimos
    /// 4 dígitos de la tarjeta original, para poder identificar qué transacción se realizó con
    /// cada tarjeta", porque en un desconocimiento o una conciliación lo que vuelve es el token.
    funding_card_number: Option<FiservemeaFundingCardNumber>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaFundingCardNumber {
    bin: Option<String>,
    last4: Option<String>,
}

/// Emparejamiento Network Token ↔ PAN de una transacción aprobada, tal como lo exige el manual
/// de Network Token para poder conciliar y atender desconocimientos.
#[derive(Debug, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaNetworkTokenPairing {
    /// BIN y últimos 4 del Network Token con el que se procesó.
    network_token_bin: String,
    network_token_last4: String,
    /// BIN y últimos 4 del PAN real que fondea.
    funding_card_bin: String,
    funding_card_last4: String,
}

impl FiservemeaPaymentMethodDetails {
    /// Devuelve el emparejamiento **sólo** cuando el gateway efectivamente sustituyó por un
    /// Network Token, o sea cuando el BIN procesado difiere del BIN que fondea.
    ///
    /// La comparación es necesaria: IPG manda `fundingCardNumber` también en ventas sin token
    /// (verificado contra cert), y ahí los dos BIN son el mismo. Emitir el emparejamiento en ese
    /// caso escribiría un dato afirmativo y falso — diría que hubo tokenización de marca donde
    /// no hubo — en un campo que después se usa para conciliar.
    pub(crate) fn network_token_pairing(&self) -> Option<FiservemeaNetworkTokenPairing> {
        let card = self.payment_card.as_ref()?;
        let funding = card.funding_card_number.as_ref()?;
        let (token_bin, funding_bin) = (card.bin.as_ref()?, funding.bin.as_ref()?);
        if token_bin == funding_bin {
            return None;
        }
        Some(FiservemeaNetworkTokenPairing {
            network_token_bin: token_bin.clone(),
            network_token_last4: card.last4.clone()?,
            funding_card_bin: funding_bin.clone(),
            funding_card_last4: funding.last4.clone()?,
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaResponsePaymentToken {
    value: Option<Secret<String>>,
    reusable: Option<bool>,
    network_token_provision_status: Option<String>,
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
    /// Código que devuelve la marca (Visa/Mastercard), distinto del `responseCode` ISO del
    /// emisor. Fiserv lo publica en REST como `processor.associationResponseCode`
    /// (`ipgapi:ProcessorAssociationResponseCode` en la API SOAP); es el campo con el que las
    /// marcas categorizan los rechazos para su política de reintentos.
    association_response_code: Option<String>,
    /// Merchant Advice Code de Mastercard (tabla 55). Fiserv sólo lo manda si el comercio pidió
    /// `order.installmentOptions.merchantAdviceCodeSupported = TRUE` en un pago recurrente
    /// rechazado (guía, pág. 79). Reintentar contra un MAC que dice "no reintentes" es lo que
    /// dispara la penalidad de USD 0,50 por transacción del mandato de Mastercard.
    merchant_advice_code_indicator: Option<String>,
}

/// Los tres códigos de red que `ErrorResponse` expone para que el motor de reintentos
/// (revenue recovery) decida si vale la pena reintentar y con qué espera.
#[derive(Debug, Default, PartialEq)]
pub(crate) struct FiservemeaNetworkCodes {
    pub decline_code: Option<String>,
    pub advice_code: Option<String>,
    pub error_message: Option<String>,
}

impl FiservemeaNetworkCodes {
    /// Traduce el bloque `processor` de IPG a la convención que ya usan otros conectores del
    /// repo: el MAC va en `network_advice_code` (igual que `merchantAdvice.codeRaw` en
    /// cybersource o `merchantAdviceCode` en adyen) y el código de red en
    /// `network_decline_code`.
    ///
    /// Para el código de rechazo se prefiere `associationResponseCode` porque es el que emite la
    /// marca, y se cae a `responseCode` cuando IPG no lo manda —hoy el gateway de certificación
    /// nunca lo manda, y sin el fallback el motor de reintentos se quedaría sin ningún código,
    /// que es exactamente lo que hacen cybersource/bankofamerica/barclaycard mapeando
    /// `processorInformation.responseCode`. No se cae al `approvalCode`: ese código
    /// (`N:-11101:...`) es del gateway, no de la red, y mezclarlos haría que el motor de
    /// reintentos clasifique un error de configuración como si fuera un rechazo del emisor.
    ///
    /// `network_error_message` lleva el texto crudo del procesador (`responseMessage`) sin
    /// fallbacks: si el texto que se muestra vino de `errorMessage` o del `approvalCode`, no es
    /// de la red y no corresponde publicarlo como tal.
    pub(crate) fn from_processor(processor: Option<&Processor>) -> Self {
        Self {
            // Se usa `responseCode`, que es el único que vimos llevando códigos ISO reales
            // (01, 05, 51…). NO se prefiere `associationResponseCode`: no aparece ni una vez
            // en las respuestas del gateway de certificación, y el único ejemplo publicado que
            // lo trae lo muestra como `"XX"` en una transacción aprobada. Preferirlo sobre un
            // valor verificado publicaría eso como código de rechazo de red y degradaría la
            // clasificación de reintentos por debajo de lo que hace hoy.
            decline_code: processor.and_then(|p| p.response_code.clone()),
            advice_code: processor.and_then(|p| p.merchant_advice_code_indicator.clone()),
            error_message: processor.and_then(|p| p.response_message.clone()),
        }
    }
}

/// Estado con el que se resuelve todo dato que el gateway mandó pero el conector no sabe
/// interpretar (valor nuevo en un enum, o campo ausente).
///
/// `Pending` es el único que no miente en ninguna de las dos direcciones peligrosas: no da la
/// plata por cobrada (nadie despacha mercadería contra un valor que no entendemos) ni la da por
/// perdida marcando `Failure` sobre una transacción que el gateway pudo haber aprobado y
/// cobrado. Además deja el intento vivo para que el PSync lo resuelva, mientras que un
/// `Failure` es terminal y dejaría el cobro huérfano.
const UNKNOWN_ATTEMPT_STATUS: common_enums::AttemptStatus = common_enums::AttemptStatus::Pending;

/// Estados terminales de `transactionState` que contradicen al `transactionType`, y con qué
/// hay que quedarse.
///
/// Es imprescindible mirar este campo en el PSync: al consultar una venta que después se anuló, el
/// gateway responde `transactionType: SALE` + `transactionStatus: APPROVED` + `transactionState:
/// VOIDED` (verificado en vivo contra certificación: venta 1000.00 ARS aprobada con state CAPTURED,
/// anulada, y la consulta posterior de ESA venta devuelve state VOIDED). Mirando sólo el tipo, un
/// pago anulado se reporta como cobrado — plata que el comercio cree haber cobrado y no cobró.
fn map_transaction_state(state: Option<&str>) -> Option<common_enums::AttemptStatus> {
    match state?.to_ascii_uppercase().as_str() {
        "VOIDED" => Some(common_enums::AttemptStatus::Voided),
        "DECLINED" => Some(common_enums::AttemptStatus::Failure),
        // CAPTURED y WAITING no agregan nada sobre el tipo, y un valor desconocido no debe
        // pisar la clasificación que sí se conoce.
        _ => None,
    }
}

/// Traduce un resultado aprobado según el tipo de transacción que lo produjo.
///
/// `transaction_state` manda cuando es terminal y contradice al tipo (ver `map_transaction_state`).
fn map_approved_status(
    transaction_type: Option<&FiservemeaTransactionType>,
    transaction_state: Option<&str>,
) -> common_enums::AttemptStatus {
    if let Some(status) = map_transaction_state(transaction_state) {
        return status;
    }
    match transaction_type {
        Some(FiservemeaTransactionType::Preauth) => common_enums::AttemptStatus::Authorized,
        Some(FiservemeaTransactionType::Void) => common_enums::AttemptStatus::Voided,
        Some(FiservemeaTransactionType::Sale | FiservemeaTransactionType::Postauth) => {
            common_enums::AttemptStatus::Charged
        }
        Some(
            FiservemeaTransactionType::Credit
            | FiservemeaTransactionType::ForcedTicket
            | FiservemeaTransactionType::Return
            | FiservemeaTransactionType::PayerAuth
            | FiservemeaTransactionType::Disbursement,
        ) => common_enums::AttemptStatus::Failure,
        // Sin un `transactionType` conocido no se puede distinguir entre autorizado,
        // capturado y anulado: los tres son "aprobado" y significan cosas distintas para el
        // dinero. Se difiere al PSync en vez de elegir uno al azar.
        Some(FiservemeaTransactionType::Unknown) | None => UNKNOWN_ATTEMPT_STATUS,
    }
}

fn map_status(
    fiservemea_status: Option<FiservemeaPaymentStatus>,
    fiservemea_result: Option<FiservemeaPaymentResult>,
    transaction_type: Option<FiservemeaTransactionType>,
    transaction_state: Option<&str>,
) -> common_enums::AttemptStatus {
    // `transactionStatus` está deprecado pero sigue llegando; se lo consulta primero sólo
    // cuando trae un valor que conocemos. Un valor no contemplado ahí no debe tapar al
    // `transactionResult`, que es el campo vigente y suele venir en la misma respuesta.
    let from_status = match fiservemea_status {
        Some(FiservemeaPaymentStatus::Approved) => {
            Some(map_approved_status(transaction_type.as_ref(), transaction_state))
        }
        Some(FiservemeaPaymentStatus::Waiting) => Some(common_enums::AttemptStatus::Pending),
        Some(FiservemeaPaymentStatus::Partial) => Some(common_enums::AttemptStatus::PartialCharged),
        Some(
            FiservemeaPaymentStatus::ValidationFailed
            | FiservemeaPaymentStatus::ProcessingFailed
            | FiservemeaPaymentStatus::Declined,
        ) => Some(common_enums::AttemptStatus::Failure),
        Some(FiservemeaPaymentStatus::Unknown) | None => None,
    };
    if let Some(status) = from_status {
        return status;
    }

    match fiservemea_result {
        Some(FiservemeaPaymentResult::Approved) => {
            map_approved_status(transaction_type.as_ref(), transaction_state)
        }
        Some(FiservemeaPaymentResult::Waiting) => common_enums::AttemptStatus::Pending,
        Some(FiservemeaPaymentResult::Partial) => common_enums::AttemptStatus::PartialCharged,
        Some(
            FiservemeaPaymentResult::Declined
            | FiservemeaPaymentResult::Failed
            | FiservemeaPaymentResult::Fraud,
        ) => common_enums::AttemptStatus::Failure,
        Some(FiservemeaPaymentResult::Unknown) | None => {
            // Sin este aviso el descarte es mudo: el intento queda en Pending para siempre y
            // no queda rastro de que el gateway mandó algo que no conocemos. `#[serde(other)]`
            // ya perdió el string original, así que se registra al menos qué combinación llegó.
            router_env::logger::warn!(
                transaction_status = ?fiservemea_status,
                transaction_result = ?fiservemea_result,
                transaction_type = ?transaction_type,
                "fiservemea: estado de transacción no contemplado; se difiere al PSync"
            );
            UNKNOWN_ATTEMPT_STATUS
        }
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
    ///
    /// El `methodForm` no se entrega crudo: va dentro de la página de
    /// `build_three_ds_method_wrapper`, que es la que puede navegar la ventana principal para
    /// que el paso siguiente sea visible. `return_url` es el `complete_authorize_url`; sin él
    /// no se puede armar el wrapper y se devuelve el form crudo, que es el comportamiento
    /// anterior (peor, pero no una regresión).
    fn to_redirection(&self, return_url: Option<&str>) -> Option<RedirectForm> {
        if let Some(method_form) = self
            .secure3d_method
            .as_ref()
            .and_then(|method| method.method_form.clone())
        {
            return Some(RedirectForm::Html {
                html_data: match return_url {
                    Some(url) => build_three_ds_method_wrapper(&method_form, url),
                    None => method_form,
                },
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
    /// Mensaje que el emisor manda para mostrarle al comprador cuando rechaza la autenticación
    /// (por ejemplo "Your card has not been configured to support EMV 3-D Secure").
    cardholder_info: Option<String>,
    /// Motivo numérico del `transStatus`. No está documentado en el material de Fiserv, así que
    /// se publica tal cual, sin interpretarlo.
    transaction_status_reason: Option<String>,
}

impl FiservemeaSecure3dResponse {
    /// Empaqueta el resultado de la autenticación para publicarlo. Es lo que el checklist de
    /// homologación pide informar por caso.
    pub(crate) fn to_metadata(&self) -> Option<serde_json::Value> {
        let mut map = serde_json::Map::new();
        if let Some(code) = self.response_code3d_secure.as_ref() {
            map.insert("responseCode3dSecure".to_string(), serde_json::json!(code));
        }
        if let Some(info) = self.cardholder_info.as_ref() {
            map.insert("cardholderInfo".to_string(), serde_json::json!(info));
        }
        if let Some(reason) = self.transaction_status_reason.as_ref() {
            map.insert(
                "transactionStatusReason".to_string(),
                serde_json::json!(reason),
            );
        }
        (!map.is_empty()).then(|| serde_json::Value::Object(map))
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
    // Opcionales a propósito: el gateway devuelve respuestas reales sin estos dos campos
    // (p. ej. el rechazo de "Unable to verify card enrollment" llega sin `ipgTransactionId`
    // ni `transactionType`, sólo con `transactionStatus`/`error`). Exigirlos hacía que la
    // respuesta entera no parseara y se perdiera incluso el motivo del rechazo; peor aún,
    // bastaría una respuesta aprobada sin uno de los dos para transformar un cobro real en
    // un error de deserialización.
    ipg_transaction_id: Option<String>,
    order_id: Option<String>,
    transaction_type: Option<FiservemeaTransactionType>,
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
    /// El gateway devuelve `paymentToken` en casi toda respuesta de pago, pero con `value`
    /// **sólo** cuando efectivamente hay un token reusable (verificado sobre las respuestas
    /// capturadas: 518 lo traen sin `value` y 19 con él). Es el `hosted-data-id` que se reusa
    /// para cobrar Card on File, así que cuando viene se publica como referencia de mandato.
    payment_token: Option<FiservemeaResponsePaymentToken>,
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

/// Cuerpo que devuelve la consulta por orden (`GET /orders/{orderId}?storeId=...`).
///
/// La guía (§7.3) dice que al endpoint de consulta se le manda "el identificador de la
/// transacción u orden" y que se recibe "un Payload de tipo TransactionResponse u
/// OrderResponse respectivamente": consultando por orden los datos de la transacción no
/// vienen arriba sino dentro del array `transactions`, así que hace falta un struct propio.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaOrderResponse {
    #[serde(rename = "type")]
    fiservemea_type: Option<String>,
    client_request_id: Option<String>,
    api_trace_id: Option<String>,
    order_id: Option<String>,
    transactions: Vec<FiservemeaPaymentsResponse>,
}

/// Respuesta del PSync, que según por dónde se haya consultado llega con una forma u otra.
///
/// Se discrimina por el campo `type`, que el gateway manda siempre (verificado sobre las
/// respuestas capturadas: 450 `transactionResponse` y 12 `orderResponse`, ninguna sin él).
///
/// No va `untagged` por dos motivos. El primero es de corrección: las dos formas dejaron de
/// ser disjuntas por estructura cuando `ipgTransactionId` y `transactionType` pasaron a ser
/// opcionales, así que un `orderResponse` puede satisfacer la forma de transacción y
/// deserializarse como tal, perdiendo el array `transactions`. Con `untagged` eso dependía
/// del orden de declaración de las variantes, que es una garantía demasiado frágil. El
/// segundo es de diagnóstico: `untagged` colapsa cualquier error de parseo en
/// "data did not match any variant", que no dice qué campo falló.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum FiservemeaSyncResponse {
    #[serde(rename = "orderResponse")]
    Order(FiservemeaOrderResponse),
    #[serde(rename = "transactionResponse")]
    Transaction(Box<FiservemeaPaymentsResponse>),
}

impl FiservemeaSyncResponse {
    /// Deja una única transacción para que el resto del PSync siga siendo el de siempre.
    ///
    /// De una orden con varias transacciones se toma la **primera**. Verificado en vivo
    /// contra cert: IPG las devuelve en orden cronológico y la primaria va al frente
    /// (`PX-1786053427-07-void` → `[SALE 84667286296, VOID 84667286297]`,
    /// `PX-1786053434-09-retpar` → `[SALE 84667286310, RETURN 84667286311]`). La primaria
    /// es la que le corresponde al intento de pago que el PSync está consultando; las
    /// secundarias (VOID/RETURN/POSTAUTH) son otros flujos de Hyperswitch, que sincronizan
    /// con su propio id (RSync para los refunds). Quedarse con la última sería activamente
    /// peor: en una orden con devolución parcial la última es el RETURN y `map_status` lo
    /// mapea a `Failure`, o sea que un pago cobrado se reportaría como fallido.
    pub fn into_transaction(
        self,
    ) -> Result<FiservemeaPaymentsResponse, error_stack::Report<errors::ConnectorError>> {
        match self {
            Self::Transaction(transaction) => Ok(*transaction),
            Self::Order(order) => {
                let total = order.transactions.len();
                if total > 1 {
                    // Se avisa en vez de callar: si alguna vez el orden dejara de ser
                    // cronológico, el log es la única pista de que se eligió mal.
                    router_env::logger::warn!(
                        transactions_in_order = total,
                        order_id = ?order.order_id,
                        "fiservemea orderResponse carries multiple transactions; syncing with the first (primary) one"
                    );
                }
                order.transactions.into_iter().next().ok_or_else(|| {
                    // Una orden sin transacciones no permite decidir ningún estado: es
                    // preferible que el PSync falle a inventar un `Pending` o un `Failure`.
                    error_stack::Report::new(errors::ConnectorError::MissingRequiredField {
                        field_name: "transactions",
                    })
                })
            }
        }
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
            // La conversión genérica no ve el request, así que acá no hay `complete_authorize_url`.
            // El wrapper del methodForm se aplica después, en el `handle_response` de Authorize,
            // que es el único lugar con acceso a esa URL.
            .and_then(|auth| auth.to_redirection(None));
        let mapped_status = map_status(
            item.response.transaction_status,
            item.response.transaction_result,
            item.response.transaction_type,
            item.response.transaction_state.as_deref(),
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
        // Al `responseCode3dSecure` se le suma el emparejamiento Network Token ↔ PAN cuando la
        // transacción se procesó con tokenización de marca. Es el dato que el manual de Network
        // Token exige guardar en cada transacción aprobada para poder conciliar y atender
        // desconocimientos, porque lo que vuelve del procesador es el token y no el PAN.
        let three_ds_code = item
            .response
            .secure3d_response
            .as_ref()
            .and_then(|secure3d| secure3d.to_metadata());
        let token_pairing = item
            .response
            .payment_method_details
            .as_ref()
            .and_then(|details| details.network_token_pairing());
        let connector_metadata = match (three_ds_code, token_pairing) {
            (None, None) => None,
            (code, pairing) => {
                let mut map = serde_json::Map::new();
                if let Some(serde_json::Value::Object(three_ds)) = code {
                    map.extend(three_ds);
                }
                // `to_value` sobre este struct no puede fallar (sólo strings), pero si alguna vez
                // fallara, perder el emparejamiento no justifica tirar abajo un cobro aprobado.
                if let Some(value) = pairing.and_then(|p| serde_json::to_value(p).ok()) {
                    map.insert("networkTokenPairing".to_string(), value);
                }
                Some(serde_json::Value::Object(map))
            }
        };

        // Un rechazo de IPG llega con HTTP 2xx y sólo se distingue por el estado, así
        // que sin esto el pago quedaba en Failure sin código ni motivo. El código real
        // viene en `processor.responseCode` y el texto en `processor.responseMessage`;
        // `approvalCode` los trae juntos con el formato `N:<código>:<texto>`.
        if status == common_enums::AttemptStatus::Failure {
            let (approval_code, approval_message) =
                split_approval_code(item.response.approval_code.as_deref());
            let processor = item.response.processor.as_ref();
            let code = processor
                .and_then(|p| p.response_code.clone())
                .or(approval_code)
                .unwrap_or_else(|| consts::NO_ERROR_CODE.to_string());
            let message = processor
                .and_then(|p| p.response_message.clone())
                .or_else(|| item.response.error_message.clone())
                .or(approval_message)
                .unwrap_or_else(|| consts::NO_ERROR_MESSAGE.to_string());
            let network = FiservemeaNetworkCodes::from_processor(processor);
            return Ok(Self {
                status,
                response: Err(ErrorResponse {
                    code,
                    message: message.clone(),
                    reason: Some(message),
                    status_code: item.http_code,
                    attempt_status: Some(status),
                    // `ipgTransactionId` es opcional: el gateway lo omite en los rechazos que
                    // fallan antes de crear la transacción (por ejemplo el 409 de Data Only).
                    connector_transaction_id: item.response.ipg_transaction_id,
                    network_decline_code: network.decline_code,
                    network_advice_code: network.advice_code,
                    network_error_message: network.error_message,
                    connector_metadata: connector_metadata.map(Secret::new),
                }),
                ..item.data
            });
        }

        Ok(Self {
            status,
            response: Ok(PaymentsResponseData::TransactionResponse {
                // Si el gateway omitió el id, se prefiere registrar el intento con el estado
                // real (y sin id para sincronizar) antes que descartar la respuesta entera:
                // un cobro sin id sigue siendo un cobro que el comercio tiene que ver.
                resource_id: item
                    .response
                    .ipg_transaction_id
                    .map_or(ResponseId::NoResponseId, ResponseId::ConnectorTransactionId),
                redirection_data: Box::new(redirection_data),
                // El token del gateway es lo que permite volver a cobrar la tarjeta guardada:
                // sin publicarlo como referencia de mandato, el token vive sólo dentro de la
                // ejecución que lo creó y Card on File no se puede encadenar.
                mandate_reference: Box::new(
                    item.response
                        .payment_token
                        .as_ref()
                        .and_then(|token| token.value.clone())
                        .map(|value| MandateReference {
                            connector_mandate_id: Some(value.expose()),
                            payment_method_id: None,
                            mandate_metadata: None,
                            connector_mandate_request_reference_id: None,
                        }),
                ),
                connector_metadata,
                // Visa exige guardar el `schemeTransactionId` de la transacción original y
                // devolverlo en `referencedSchemeTransactionId` en los REPEAT del ciclo
                // recurrente. Hyperswitch lo persiste como `network_txn_id`; antes se parseaba
                // de la respuesta y se descartaba, así que la recurrencia Visa no se podía armar.
                network_txn_id: item.response.scheme_transaction_id.clone(),
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
        // Incluye `None`: en la API de Hyperswitch significa captura automática, o sea
        // que el pago se envió como `PaymentCardSaleTransaction` y se anula con
        // `VoidTransaction`. Mantiene la selección alineada con la de Authorize.
        FiservemeaRequestType::VoidTransaction
    } else {
        // Sólo la captura manual explícita corresponde a un pre-auth sin capturar.
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

/// Estado con el que se resuelve un reembolso que el gateway ya ejecutó pero cuyo desenlace no
/// se puede clasificar. `Pending` en vez de un error: el `RETURN` viajó al gateway, y devolver
/// `Failure`/error deja el reembolso como reintentable, o sea habilita un segundo pago al
/// tarjetahabiente. `Pending` no confirma nada y deja que el RSync resuelva.
const UNKNOWN_REFUND_STATUS: enums::RefundStatus = enums::RefundStatus::Pending;

fn map_refund_status(
    fiservemea_status: Option<FiservemeaPaymentStatus>,
    fiservemea_result: Option<FiservemeaPaymentResult>,
) -> enums::RefundStatus {
    // Mismo criterio que en `map_status`: el campo deprecado sólo decide cuando trae un valor
    // conocido, si no manda el `transactionResult` vigente.
    let from_status = match fiservemea_status {
        Some(FiservemeaPaymentStatus::Approved) => Some(enums::RefundStatus::Success),
        Some(FiservemeaPaymentStatus::Partial | FiservemeaPaymentStatus::Waiting) => {
            Some(enums::RefundStatus::Pending)
        }
        Some(
            FiservemeaPaymentStatus::ValidationFailed
            | FiservemeaPaymentStatus::ProcessingFailed
            | FiservemeaPaymentStatus::Declined,
        ) => Some(enums::RefundStatus::Failure),
        Some(FiservemeaPaymentStatus::Unknown) | None => None,
    };
    if let Some(status) = from_status {
        return status;
    }

    match fiservemea_result {
        Some(FiservemeaPaymentResult::Approved) => enums::RefundStatus::Success,
        Some(FiservemeaPaymentResult::Partial | FiservemeaPaymentResult::Waiting) => {
            enums::RefundStatus::Pending
        }
        Some(
            FiservemeaPaymentResult::Declined
            | FiservemeaPaymentResult::Failed
            | FiservemeaPaymentResult::Fraud,
        ) => enums::RefundStatus::Failure,
        Some(FiservemeaPaymentResult::Unknown) | None => {
            // Igual que en `map_status`: el descarte no puede ser mudo. Un reembolso que queda
            // en Pending sin rastro de por qué es indiagnosticable después.
            router_env::logger::warn!(
                transaction_status = ?fiservemea_status,
                transaction_result = ?fiservemea_result,
                "fiservemea: estado de reembolso no contemplado; se difiere al RSync"
            );
            UNKNOWN_REFUND_STATUS
        }
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
                // A diferencia del pago, acá no hay equivalente a `NoResponseId`: sin el id del
                // `RETURN` el RSync apuntaría al id del pago original y leería el estado del
                // cobro como si fuera el del reembolso. Se falla con el campo concreto que
                // faltó, que es accionable, en vez de con un error de deserialización opaco.
                connector_refund_id: item.response.ipg_transaction_id.ok_or(
                    errors::ConnectorError::MissingRequiredField {
                        field_name: "ipgTransactionId",
                    },
                )?,
                refund_status: map_refund_status(
                    item.response.transaction_status,
                    item.response.transaction_result,
                ),
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
                // Ver la nota del flujo Execute: el id del reembolso no admite fallback.
                connector_refund_id: item.response.ipg_transaction_id.ok_or(
                    errors::ConnectorError::MissingRequiredField {
                        field_name: "ipgTransactionId",
                    },
                )?,
                refund_status: map_refund_status(
                    item.response.transaction_status,
                    item.response.transaction_result,
                ),
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

// El gateway serializa en camelCase (clientRequestId, apiTraceId, responseType).
// Sin este rename_all los tres campos quedaban siempre en None, y el apiTraceId
// es justamente el identificador con el que Fiserv busca la transacción en sus logs.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaErrorResponse {
    #[serde(rename = "type")]
    fiservemea_type: Option<String>,
    pub client_request_id: Option<String>,
    pub api_trace_id: Option<String>,
    pub response_type: Option<String>,
    pub error: Option<FiservemeaError>,
    /// Un rechazo del emisor llega con HTTP 422 y `responseType: EndpointDeclined` (verificado
    /// contra cert: monto 1005 → `responseCode: "05"`, `responseMessage: "Do not honour"`), o
    /// sea que cae en `build_error_response` y no en el `TryFrom` de la respuesta. Sin parsear
    /// acá el bloque `processor`, los códigos de red del único camino por el que pasan los
    /// rechazos reales se perdían.
    pub processor: Option<Processor>,
    /// El gateway sí devuelve el id de transacción en la mayoría de los rechazos (90 de 107
    /// respuestas de error capturadas contra cert lo traen; los 17 que no son los que fallan
    /// antes de crear la transacción, como el `INVALID_INPUT` por payload inválido). Sin
    /// declararlo acá se descartaba justo en el camino de los rechazos del emisor, y sin id no
    /// se puede consultar ni conciliar la transacción después.
    pub ipg_transaction_id: Option<String>,
    /// El resultado de la autenticación 3DS también llega en el camino de error, y es el dato que
    /// el checklist de homologación pide reportar por caso: 11 de las 22 filas 3DS terminan en un
    /// HTTP 409 con `secure3dResponse.responseCode3dSecure` (los "Not Authenticated" y
    /// "Rejected", que cierran por diseño en `N:-50716`). Sin declararlo acá se descartaba
    /// justamente en las filas donde hace falta.
    pub secure3d_response: Option<FiservemeaSecure3dResponse>,
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::panic
    )]

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
                number_of_installments: Some(6),
                recurring_type: None,
                interest: Some(true),
            }),
            additional_details: None,
            soft_descriptor: None,
            token_cryptogram: None,
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
    fn dynamic_merchant_name_truncated_to_25_chars() {
        let metadata =
            serde_json::json!({ "dynamic_merchant_name": "PXSOL_SUPER_LONG_STORE_NAME_1234567890" });
        let meta = FiservemeaMetadataObject::from_sources(Some(&metadata), None);
        let name = meta.dynamic_merchant_name.expect("should extract");
        assert_eq!(name.chars().count(), 25);
        assert!(name.starts_with("PXSOL_SUPER_LONG_STORE_NA"));
    }

    #[test]
    fn order_serializes_soft_descriptor_dynamic_merchant_name() {
        let order = FiservemeaOrder {
            order_id: "ord_1".to_string(),
            installment_options: None,
            additional_details: None,
            soft_descriptor: Some(FiservemeaSoftDescriptor {
                dynamic_merchant_name: Secret::new("PXSOL*Reservas".to_string()),
            }),
            token_cryptogram: None,
        };
        let json = serde_json::to_value(&order).unwrap();
        assert_eq!(json["softDescriptor"]["dynamicMerchantName"], "PXSOL*Reservas");
    }

    /// Metadata del comercio a partir de un objeto JSON, sin `frm_metadata`.
    fn meta_from_json(value: serde_json::Value) -> FiservemeaMetadataObject {
        FiservemeaMetadataObject::from_sources(Some(&value), None)
    }

    /// URL de retorno usada en los tests de `authenticationRequest`; el conector manda la misma
    /// en `termURL` y en `methodNotificationURL`.
    const TEST_RETURN_URL: &str = "https://www.pxsol.com/3ds/return";

    fn auth_request_json(metadata: serde_json::Value) -> serde_json::Value {
        auth_request_json_for_brand(metadata, true)
    }

    /// `is_mastercard` decide si Data Only aplica: la modalidad es exclusiva de Mastercard.
    fn auth_request_json_for_brand(
        metadata: serde_json::Value,
        is_mastercard: bool,
    ) -> serde_json::Value {
        let meta = meta_from_json(metadata);
        let request = FiservemeaAuthenticationRequest::new(
            TEST_RETURN_URL.to_string(),
            TEST_RETURN_URL.to_string(),
            &meta,
            is_mastercard,
        )
        .unwrap();
        serde_json::to_value(&request).unwrap()
    }

    #[test]
    fn authentication_request_locks_wire_values() {
        // El 3DS normal usa la subclase 2.1/2.2 con los defaults del conector y NUNCA
        // `messageCategory`. Igualdad del objeto completo para que un campo nuevo no se cuele
        // sin que nadie lo mire.
        assert_eq!(
            auth_request_json(serde_json::json!({})),
            serde_json::json!({
                "authenticationType": "Secure3D21AuthenticationRequest",
                "termURL": TEST_RETURN_URL,
                "methodNotificationURL": TEST_RETURN_URL,
                "challengeIndicator": "01",
                "challengeWindowSize": "05",
            })
        );
    }

    #[test]
    fn data_only_uses_base_class_and_omits_challenge_fields() {
        // Payload calcado del ejemplo de la guía §10.1.6 y de la request que el gateway cert
        // aceptó (apiTraceId anX08HbyIFesn-w_H26JWQAAA88: la clase base con messageCategory 80
        // pasa la validación de forma y llega a decidirse por negocio).
        assert_eq!(
            auth_request_json(serde_json::json!({ "three_ds_data_only": true })),
            serde_json::json!({
                "authenticationType": "Secure3DAuthenticationRequest",
                "termURL": TEST_RETURN_URL,
                "methodNotificationURL": TEST_RETURN_URL,
                "messageCategory": "80",
            })
        );
    }

    #[test]
    fn secure3d21_never_carries_message_category() {
        // La subclase no declara `messageCategory`: mandárselo tira toda la transacción abajo
        // con 400 INVALID_INPUT (ver `real_cert_error_for_message_category_on_secure3d21`).
        // Ninguna combinación de metadata que no sea Data Only puede emitirlo.
        for metadata in [
            serde_json::json!({}),
            serde_json::json!({ "three_ds_data_only": false }),
            serde_json::json!({ "three_ds_data_only": "false", "challenge_indicator": "05" }),
            // Un valor no booleano no es un opt-in: cae al 3DS normal, no a Data Only.
            serde_json::json!({ "three_ds_data_only": "quizas" }),
        ] {
            let json = auth_request_json(metadata.clone());
            assert_eq!(
                json["authenticationType"], "Secure3D21AuthenticationRequest",
                "metadata {metadata} debería quedarse en 3DS normal"
            );
            assert!(
                json.get("messageCategory").is_none(),
                "metadata {metadata} emitió messageCategory sobre la subclase 2.1"
            );
        }
    }

    #[test]
    fn real_cert_error_for_message_category_on_secure3d21() {
        // Respuesta literal del gateway cert (HTTP 400) al mandar la subclase 2.1 con
        // `messageCategory`, que es lo que hacía el conector cuando three_ds_data_only estaba
        // activo. El `details[]` es la única parte que dice qué campo molestó.
        let raw = serde_json::json!({
            "type": "errorResponse",
            "clientRequestId": "0da890f7-c3a4-40bb-88e2-6083cb9e23b8",
            "apiTraceId": "anX07XbyIFesn-w_H26JQwAAA-U",
            "error": {
                "code": "INVALID_INPUT",
                "message": "Invalid request input. Please see details below.",
                "details": [{
                    "field": "messageCategory",
                    "message": "No field named 'messageCategory' exists for class Secure3D21AuthenticationRequest"
                }]
            }
        });
        let parsed: FiservemeaErrorResponse = serde_json::from_value(raw).unwrap();
        let error = parsed.error.expect("el gateway manda el objeto error");
        assert_eq!(error.code.as_deref(), Some("INVALID_INPUT"));
        let details = error.details.expect("INVALID_INPUT trae details");
        assert_eq!(details[0].field.as_deref(), Some("messageCategory"));
        assert_eq!(
            details[0].message.as_deref(),
            Some(
                "No field named 'messageCategory' exists for class Secure3D21AuthenticationRequest"
            )
        );
    }

    #[test]
    fn challenge_fields_come_from_metadata() {
        // `challengeIndicator: "03"` (desafío pedido) + `challengeWindowSize: "03"` (500x600):
        // combinación aceptada en vivo por cert, apiTraceId anX08yKQSojaSWQEaFLrlwAAA9o.
        assert_eq!(
            auth_request_json(serde_json::json!({
                "challenge_indicator": "03",
                "challenge_window_size": "03",
            })),
            serde_json::json!({
                "authenticationType": "Secure3D21AuthenticationRequest",
                "termURL": TEST_RETURN_URL,
                "methodNotificationURL": TEST_RETURN_URL,
                "challengeIndicator": "03",
                "challengeWindowSize": "03",
            })
        );
    }

    #[test]
    fn challenge_fields_accept_camel_case_aliases_and_integers() {
        let meta = meta_from_json(serde_json::json!({
            "challengeIndicator": 4,
            "challengeWindowSize": " 2 ",
        }));
        assert_eq!(meta.challenge_indicator.as_deref(), Some("04"));
        assert_eq!(meta.challenge_window_size.as_deref(), Some("02"));
    }

    #[test]
    fn null_or_blank_challenge_fields_fall_back_to_the_defaults() {
        // Un opcional que el cliente serializó como `null`/`""` no es una configuración
        // inválida: si lo tratáramos como tal, romperíamos pagos que hoy funcionan.
        assert_eq!(
            auth_request_json(serde_json::json!({
                "challenge_indicator": null,
                "challenge_window_size": "  ",
            })),
            serde_json::json!({
                "authenticationType": "Secure3D21AuthenticationRequest",
                "termURL": TEST_RETURN_URL,
                "methodNotificationURL": TEST_RETURN_URL,
                "challengeIndicator": "01",
                "challengeWindowSize": "05",
            })
        );
    }

    #[test]
    fn challenge_fields_fall_back_to_frm_metadata() {
        let frm = serde_json::json!({ "challenge_window_size": "04" });
        let meta = FiservemeaMetadataObject::from_sources(
            Some(&serde_json::json!({ "challenge_indicator": "02" })),
            Some(&frm),
        );
        assert_eq!(meta.challenge_indicator.as_deref(), Some("02"));
        assert_eq!(meta.challenge_window_size.as_deref(), Some("04"));
    }

    #[test]
    fn out_of_range_challenge_values_are_rejected() {
        // El gateway también los rechaza, pero con un 400 sin `code` ni `details`
        // ("Error parsing json. Erroneous Field: authenticationRequest.challengeIndicator.
        // Cause: Unexpected value '99'"), imposible de atribuir a la metadata del comercio.
        // Y descartarlos en silencio caería al default, que puede autenticar más flojo.
        for bad in ["99", "10", "00", "0", "abc", "true"] {
            let meta = meta_from_json(serde_json::json!({ "challenge_indicator": bad }));
            assert!(
                FiservemeaAuthenticationRequest::new(
                    TEST_RETURN_URL.to_string(),
                    TEST_RETURN_URL.to_string(),
                    &meta,
                    true
                )
                .is_err(),
                "challenge_indicator {bad:?} debería rechazarse"
            );
        }
        // El tamaño de ventana NO hace fallar el pago: no es un parámetro de autenticación,
        // así que un valor fuera de rango cae al default. `06` es un indicador válido pero no
        // un tamaño válido, y sirve para comprobar que no se confunden las dos listas.
        for bad in ["06", "09", "0", "grande"] {
            let json = auth_request_json(serde_json::json!({ "challenge_window_size": bad }));
            assert_eq!(
                json["challengeWindowSize"], FISERVEMEA_DEFAULT_CHALLENGE_WINDOW_SIZE,
                "challenge_window_size {bad:?} debería caer al default"
            );
        }
    }

    #[test]
    fn data_only_is_ignored_on_a_card_that_is_not_mastercard() {
        // Data Only es exclusivo de Mastercard: con una Visa el gateway responde
        // `50738 "Invalid Message Category"` (verificado contra cert). Si el comercio deja la
        // bandera como default global, sus ventas Visa tienen que seguir andando por 3DS
        // normal en vez de fallar todas.
        let json = auth_request_json_for_brand(
            serde_json::json!({ "three_ds_data_only": true }),
            false,
        );
        assert_eq!(json["authenticationType"], FISERVEMEA_AUTH_TYPE_SECURE3D21);
        assert!(json.get("messageCategory").is_none());
        assert_eq!(json["challengeIndicator"], FISERVEMEA_DEFAULT_CHALLENGE_INDICATOR);

        // Y con Mastercard sí sale Data Only, con la clase base y sin campos de desafío.
        let json =
            auth_request_json_for_brand(serde_json::json!({ "three_ds_data_only": true }), true);
        assert_eq!(json["authenticationType"], FISERVEMEA_AUTH_TYPE_SECURE3D_BASE);
        assert_eq!(json["messageCategory"], FISERVEMEA_MESSAGE_CATEGORY_DATA_ONLY);
        assert!(json.get("challengeIndicator").is_none());
        assert!(json.get("challengeWindowSize").is_none());
    }

    #[test]
    fn every_documented_challenge_value_is_accepted() {
        // Lista completa de la guía §10.1.1 (pág. 31): indicador 01..09, ventana 01..05.
        for indicator in FISERVEMEA_CHALLENGE_INDICATORS {
            let json = auth_request_json(serde_json::json!({ "challenge_indicator": indicator }));
            assert_eq!(json["challengeIndicator"], indicator);
        }
        for size in FISERVEMEA_CHALLENGE_WINDOW_SIZES {
            let json = auth_request_json(serde_json::json!({ "challenge_window_size": size }));
            assert_eq!(json["challengeWindowSize"], size);
        }
    }

    #[test]
    fn payment_method_payment_token_serializes() {
        let pm = FiservemeaPaymentMethods::PaymentToken(FiservemeaPaymentTokenRef {
            value: Secret::new("TOKEN-123".to_string()),
            token_origin_store_id: Secret::new("5926072901".to_string()),
        });
        let json = serde_json::to_value(&pm).unwrap();
        assert_eq!(json["paymentToken"]["value"], "TOKEN-123");
        assert_eq!(json["paymentToken"]["tokenOriginStoreId"], "5926072901");
    }

    #[test]
    fn real_cert_sale_response_deserializes_and_maps_to_charged() {
        // Full APPROVED sale response captured live from the Fiserv cert gateway. It carries
        // `transactionResult` (not the deprecated `transactionStatus`), so it exercises the
        // result-based status path against a complete, real payload (all fields must parse).
        let raw = serde_json::json!({
            "type": "transactionResponse",
            "clientRequestId": "c4abc979-df0d-4626-aa08-97d6dae93b3f",
            "apiTraceId": "amvFrHVLgzSvT6IP5kfSbQAAAq4",
            "ipgTransactionId": "84666242633",
            "orderId": "1c2e11bb-3075-4195-bc95-591789e2b995",
            "transactionType": "SALE",
            "paymentToken": { "last4": "0019", "brand": "VISA" },
            "transactionOrigin": "ECOM",
            "paymentMethodDetails": {
                "paymentCard": {
                    "expiryDate": { "month": "12", "year": "2026" },
                    "bin": "400555", "last4": "0019", "brand": "VISA"
                },
                "paymentMethodType": "PAYMENT_CARD",
                "paymentMethodBrand": "VISA"
            },
            "terminalId": "98000003",
            "merchantId": "00000014",
            "merchantTransactionId": "1c2e11bb-3075-4195-bc95-591789e2b995",
            "transactionTime": 1_785_447_849_i64,
            "approvedAmount": { "total": 10.00, "currency": "UYU", "components": { "subtotal": 10.00 } },
            "transactionAmount": { "total": 10.00, "currency": "UYU", "components": { "subtotal": 10.00 } },
            "transactionResult": "APPROVED",
            "approvalCode": "Y:375878:4666242633:PPXX:1107096288",
            "transactionState": "CAPTURED",
            "processor": { "referenceNumber": "000000018547", "responseCode": "00" }
        });
        let response: FiservemeaPaymentsResponse =
            serde_json::from_value(raw).expect("real cert sale response must deserialize");
        // Borrow first (settlement_amount takes &self), then move the status fields into map_status.
        assert!(response.settlement_amount().is_some());
        let status = map_status(
            response.transaction_status,
            response.transaction_result,
            response.transaction_type,
            response.transaction_state.as_deref(),
        );
        assert_eq!(status, common_enums::AttemptStatus::Charged);
    }

    #[test]
    fn real_cert_network_token_response_extracts_value() {
        // Real NETWORK_TOKEN tokenization response (POST /payment-tokens). Verifies the
        // create-token response struct extracts `paymentToken.value` (the IPG token).
        let raw = serde_json::json!({
            "type": "paymentTokenizationResponse",
            "clientRequestId": "c39278c0-826c-4d59-b450-1285f81b3148",
            "requestStatus": "SUCCESS",
            "paymentToken": {
                "value": "96DCAB40-0110-4821-9230-F852720DCC98",
                "reusable": true,
                "declineDuplicates": false,
                "last4": "3013",
                "brand": "MASTERCARD",
                "type": "NETWORK_TOKEN",
                "networkTokenProvisionStatus": "PROVISIONED"
            },
            "orderId": "R-9d34b7b8-09c1-49d4-8009-240ae08a3cf9",
            "ipgTransactionId": "84681094144"
        });
        let response: FiservemeaTokenResponse =
            serde_json::from_value(raw).expect("real cert token response must deserialize");
        assert_eq!(
            response.payment_token.value.peek(),
            "96DCAB40-0110-4821-9230-F852720DCC98"
        );
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
    fn void_request_type_only_manual_capture_selects_preauth_void() {
        assert!(matches!(
            select_void_request_type(Some(enums::CaptureMethod::Manual)),
            FiservemeaRequestType::VoidPreAuthTransactions
        ));
        // `None` es captura automática: el pago se envió como sale, así que se anula
        // con VoidTransaction. Antes esto elegía VoidPreAuthTransactions y fallaba
        // al anular una venta creada sin capture_method explícito.
        assert!(matches!(
            select_void_request_type(None),
            FiservemeaRequestType::VoidTransaction
        ));
    }

    fn sample_request(
        authentication_request: Option<FiservemeaAuthenticationRequest>,
    ) -> FiservemeaPaymentsRequest {
        FiservemeaPaymentsRequest {
            stored_credentials: None,
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
                token_cryptogram: None,
            },
            payment_method: FiservemeaPaymentMethods::PaymentCard(FiservemeaPaymentCard {
                number: "4111111111111111".parse().unwrap(),
                expiry_date: FiservemeaExpiryDate {
                    month: Secret::new("12".to_string()),
                    year: Secret::new("30".to_string()),
                },
                security_code: Some(Secret::new("123".to_string())),
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
        match auth.to_redirection(None) {
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
        match auth.to_redirection(None) {
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
        assert!(auth.to_redirection(None).is_none());
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
        match auth.to_redirection(None) {
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
        match auth.to_redirection(None) {
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

    // =====================================================================================
    // Los 21 casos 3DS del checklist y los pasos de continuación, contra los requests
    // REALES que el gateway de certificación aceptó
    // (fiserv_homologacion_logs/20260806-215656/evidencia.jsonl).
    //
    // La única diferencia legítima con la evidencia son las dos URLs de callback: el harness
    // usó dos paths distintos (`/3ds/return` y `/3ds/method`) y el conector, que sólo tiene el
    // `complete_authorize_url` de Hyperswitch, distingue con el marcador `fiservemea3ds`. Que
    // esa forma también sirve está verificado en vivo: la misma venta frictionless con estas
    // URLs salió APPROVED con `responseCode3dSecure: 1`
    // (ipgTransactionId 84668171318, apiTraceId an0HWCR5qsxv6kPs1WrZ4wAAAc0).
    // =====================================================================================

    /// `complete_authorize_url` de Hyperswitch: una sola URL para los dos callbacks.
    const THREE_DS_COMPLETE_AUTHORIZE_URL: &str =
        "https://sandbox.hyperswitch.io/payments/redirect/pay_abc/merch_1/pm_1";
    /// Retorno del navegador (ventana principal): es el que lleva el PATCH de continuación.
    const THREE_DS_TERM_URL: &str =
        "https://sandbox.hyperswitch.io/payments/redirect/pay_abc/merch_1/pm_1?fiservemea3ds=term";
    /// Notificación que el ACS publica dentro del iframe oculto: no continúa nada.
    const THREE_DS_METHOD_URL: &str =
        "https://sandbox.hyperswitch.io/payments/redirect/pay_abc/merch_1/pm_1?fiservemea3ds=method";

    /// `authenticationRequest` que el gateway aceptó en los 20 casos 3DS que no son Data Only
    /// (evidencia.jsonl líneas 18-56), con las URLs del conector en lugar de las del harness.
    fn expected_secure3d21_auth_request(
        challenge_indicator: &str,
        challenge_window_size: &str,
    ) -> serde_json::Value {
        serde_json::json!({
            "authenticationType": "Secure3D21AuthenticationRequest",
            "termURL": THREE_DS_TERM_URL,
            "methodNotificationURL": THREE_DS_METHOD_URL,
            "challengeIndicator": challenge_indicator,
            "challengeWindowSize": challenge_window_size,
        })
    }

    /// Venta 3DS completa tal como la arma el conector: `auth_type = ThreeDs` +
    /// `complete_authorize_url`, que es lo único que hace aparecer el `authenticationRequest`.
    fn three_ds_sale_payload(
        card_number: &str,
        metadata: Option<serde_json::Value>,
    ) -> serde_json::Value {
        let mut request = cert_authorize_data(
            cert_card_data(card_number),
            100_000,
            common_enums::Currency::ARS,
            metadata,
        );
        request.complete_authorize_url = Some(THREE_DS_COMPLETE_AUTHORIZE_URL.to_string());
        let mut router_data: PaymentsAuthorizeRouterData =
            cert_router_data(CERT_STORE_AR, "PX-3ds-checklist", request);
        router_data.auth_type = common_enums::AuthenticationType::ThreeDs;
        authorize_payload(&router_data)
    }

    /// Las 21 tarjetas 3DS del checklist de homologación: `(id del caso, tarjeta, flujo)`. Los ids
    /// son los que usa el harness y aparecen en los `case` de evidencia.jsonl; las tarjetas son
    /// exactamente las que viajaron en esos `POST /payments`. Los 21 casos son:
    ///   fric-y/n/a/r/u → Frictionless: Authenticated · Not Authenticated · Attempted · Rejected
    ///                    · Unable to Authenticate
    ///   mth-y/n/a/r/u  → 3DSMethod, los mismos cinco resultados
    ///   cha-r, cha-1/4/3/6 → Challenge: "R" y configurable con responseCode3dSecure 1/4/3/6
    ///   chm-r, chm-1/4/3/6 → Challenge + 3DSMethod, ídem
    ///   dataonly       → Data Only de Mastercard (`messageCategory: "80"`)
    const THREE_DS_CHECKLIST: [(&str, &str, &str); 21] = [
        ("fric-y", "4147463011110083", "fric"),
        ("fric-n", "4147463011110091", "fric"),
        ("fric-a", "4147463011110117", "fric"),
        ("fric-r", "4147463011110042", "fric"),
        ("fric-u", "4147463011110067", "fric"),
        ("mth-y", "4099000000001978", "method"),
        ("mth-n", "4265880000000015", "method"),
        ("mth-a", "4149011500000519", "method"),
        ("mth-r", "4016360000000085", "method"),
        ("mth-u", "4265880000000080", "method"),
        ("cha-r", "4147463011110034", "challenge"),
        ("cha-1", "4147463011110059", "challenge"),
        ("cha-4", "4147463011110059", "challenge"),
        ("cha-3", "4147463011110059", "challenge"),
        ("cha-6", "4147463011110059", "challenge"),
        ("chm-r", "4149011500000535", "challenge_method"),
        ("chm-1", "4265880000000064", "challenge_method"),
        ("chm-4", "4265880000000064", "challenge_method"),
        ("chm-3", "4265880000000064", "challenge_method"),
        ("chm-6", "4265880000000064", "challenge_method"),
        ("dataonly", "5239290700000028", "dataonly"),
    ];

    /// Los 20 casos que no son Data Only mandan EXACTAMENTE el mismo `authenticationRequest`:
    /// el flujo (frictionless / 3DSMethod / challenge / challenge+method) lo decide el emisor a
    /// partir del BIN, no el request. Eso es lo que este test fija: que ninguna de las 20
    /// tarjetas del checklist se desvíe de la forma que el gateway aceptó.
    #[test]
    fn the_20_non_data_only_checklist_cases_send_the_cert_accepted_authentication_request() {
        let expected = expected_secure3d21_auth_request("01", "05");
        for (label, card, flow) in THREE_DS_CHECKLIST {
            if flow == "dataonly" {
                continue;
            }
            let payload = three_ds_sale_payload(card, None);
            assert_eq!(
                payload["authenticationRequest"], expected,
                "caso 3DS `{label}` ({card}, flujo {flow}) no manda el authenticationRequest que \
                 aceptó cert"
            );
            // La venta sigue siendo la misma que en los casos sin 3DS: el 3DS agrega el objeto,
            // no cambia el tipo de transacción ni el medio de pago.
            assert_eq!(payload["requestType"], "PaymentCardSaleTransaction");
            assert_eq!(payload["paymentMethod"]["paymentCard"]["number"], card);
            assert_eq!(payload["transactionAmount"]["total"], "1000.00");
        }
    }

    /// Caso 21: Data Only. La clase es la BASE (`Secure3DAuthenticationRequest`), con
    /// `messageCategory: "80"` y sin `challengeIndicator` ni `challengeWindowSize` — igualito al
    /// request de evidencia.jsonl línea 57. Verificado en vivo con las URLs del conector: el
    /// gateway lo procesa (no es un rechazo de forma) y contesta el 50655 de negocio
    /// `Unable to verify card enrollment` / `responseCode3dSecure: 8`, que es la tienda sin
    /// Mastercard Insights habilitado (apiTraceId an0HZZ2Cn6oVn4oVRUS3VAAAAxs).
    #[test]
    fn the_data_only_checklist_case_uses_the_base_class_with_message_category_80() {
        let payload = three_ds_sale_payload(
            "5239290700000028",
            Some(serde_json::json!({ "three_ds_data_only": true })),
        );
        assert_eq!(
            payload["authenticationRequest"],
            serde_json::json!({
                "authenticationType": "Secure3DAuthenticationRequest",
                "termURL": THREE_DS_TERM_URL,
                "methodNotificationURL": THREE_DS_METHOD_URL,
                "messageCategory": "80",
            })
        );
        // Explícito además de la igualdad de arriba: en Data Only no hay desafío que configurar,
        // y la clase base tampoco declara esos dos campos.
        let auth_request = &payload["authenticationRequest"];
        assert!(auth_request.get("challengeIndicator").is_none());
        assert!(auth_request.get("challengeWindowSize").is_none());
    }

    /// La misma tarjeta Mastercard del caso Data Only, pero sin el opt-in, tiene que salir por el
    /// 3DS normal: `three_ds_data_only` es una bandera del comercio, no algo que se deduzca del
    /// BIN. Si se filtrara sola, toda venta Mastercard con 3DS iría a Data Only.
    #[test]
    fn the_data_only_card_without_the_opt_in_stays_on_normal_three_ds() {
        let payload = three_ds_sale_payload("5239290700000028", None);
        assert_eq!(
            payload["authenticationRequest"],
            expected_secure3d21_auth_request("01", "05")
        );
    }

    /// `challengeIndicator`/`challengeWindowSize` de la metadata llegan al request completo, no
    /// sólo al constructor. `04`/`03` verificado en vivo (apiTraceId an0HYuOTJZTvEmGNMGldfgAAAvE,
    /// HTTP 200 WAITING, y el `cReq` del ACS vuelve con `challengeWindowSize: "03"`).
    #[test]
    fn checklist_challenge_configurable_takes_the_values_from_metadata() {
        let payload = three_ds_sale_payload(
            "4147463011110059",
            Some(serde_json::json!({
                "challenge_indicator": "04",
                "challenge_window_size": "03",
            })),
        );
        assert_eq!(
            payload["authenticationRequest"],
            expected_secure3d21_auth_request("04", "03")
        );
    }

    /// Sin 3DS no hay `authenticationRequest`: es lo que mantiene los 10 casos básicos del
    /// checklist byte a byte como los aprobó cert.
    #[test]
    fn no_three_ds_sale_carries_no_authentication_request() {
        let payload = cert_card_sale_payload(
            CERT_STORE_AR,
            "PX-sin-3ds",
            "4147463011110083",
            100_000,
            common_enums::Currency::ARS,
            None,
        );
        assert!(payload.get("authenticationRequest").is_none());
    }

    // ---- Punto 3: las dos URLs de callback tienen que salir distinguibles ----

    /// `build_three_ds_callback_url` ya está cubierto por
    /// `the_two_three_ds_callbacks_are_distinguishable`; lo que falta cubrir es que las dos URLs
    /// lleguen distintas AL PAYLOAD que sale a la red, que es lo único que el gateway ve. Si
    /// salieran iguales, la notificación del ACS (que ocurre en el iframe oculto) y el retorno del
    /// navegador serían indistinguibles y el PATCH de continuación se mandaría dentro del iframe,
    /// donde el desafío queda invisible.
    #[test]
    fn the_authorize_payload_carries_the_two_callback_urls_apart() {
        let auth_request =
            three_ds_sale_payload("4099000000001978", None)["authenticationRequest"].clone();
        let term = auth_request["termURL"].as_str().unwrap();
        let method = auth_request["methodNotificationURL"].as_str().unwrap();
        assert_ne!(term, method, "las dos URLs de callback salieron iguales");
        assert_eq!(term, THREE_DS_TERM_URL);
        assert_eq!(method, THREE_DS_METHOD_URL);
        // El `complete_authorize_url` del comercio se conserva entero: el marcador va como query.
        for url in [term, method] {
            assert!(url.starts_with(THREE_DS_COMPLETE_AUTHORIZE_URL));
        }
    }

    /// La URL del payload y la que usa el wrapper del `methodForm` para navegar la ventana
    /// principal tienen que ser LA MISMA: si no, el navegador volvería a un callback que el
    /// conector no clasifica como retorno y la continuación no saldría nunca.
    #[test]
    fn the_method_wrapper_navigates_to_the_same_term_url_that_went_in_the_payload() {
        let payload = three_ds_sale_payload("4099000000001978", None);
        let term_url_del_payload = payload["authenticationRequest"]["termURL"]
            .as_str()
            .unwrap()
            .to_string();
        let wrapper = build_three_ds_method_wrapper("<form/>", &term_url_del_payload);
        assert!(
            wrapper.contains(&format!("var target = \"{term_url_del_payload}\"")),
            "el wrapper no navega a la termURL del payload: {wrapper}"
        );
    }

    // ---- Punto 3: clasificación de los dos callbacks, con las formas reales ----

    /// `threeDSMethodData` real que el ACS de test publicó en la `methodNotificationURL`
    /// (evidencia.jsonl línea 23, campo del `methodForm`). Decodificado dice
    /// `{"threeDSServerTransID": "...", "threeDSMethodNotificationURL": ".../3ds/method?ref=..."}`:
    /// o sea que el destino de la notificación es la URL del METHOD, nunca la `termURL`.
    const CERT_THREE_DS_METHOD_DATA: &str = "eyAidGhyZWVEU1NlcnZlclRyYW5zSUQiIDogImVkMjNkYzI4LTRkYmMtNTBlMC04MDAwLTAwMDAwNDRmNzhmMyIsICJ0aHJlZURTTWV0aG9kTm90aWZpY2F0aW9uVVJMIiA6ICJodHRwczovL3d3dy5weHNvbC5jb20vM2RzL21ldGhvZD9yZWY9UFgtMTc4NjA1MzQ2My0xOC0zZHMtbXRoLXkiIH0";

    /// La notificación del ACS: entra por la URL del marcador `method` y trae el
    /// `threeDSMethodData` en el cuerpo. El conector la tiene que reconocer como notificación
    /// —no como retorno del navegador— porque ocurre dentro del iframe oculto.
    #[test]
    fn the_acs_notification_callback_is_classified_as_the_method_notification() {
        let acs_notification = CompleteAuthorizeRedirectResponse {
            params: Some(Secret::new("fiservemea3ds=method".to_string())),
            payload: Some(Secret::new(serde_json::json!({
                "threeDSMethodData": CERT_THREE_DS_METHOD_DATA,
            }))),
        };
        assert!(
            is_acs_method_notification(&acs_notification),
            "la notificación del ACS se confundió con el retorno del navegador: el PATCH saldría \
             dentro del iframe oculto"
        );
    }

    /// El retorno del navegador después del `methodForm`: entra por la URL del marcador `term`,
    /// sin cRes y sin `threeDSMethodData` (el wrapper sólo hace `window.location.replace`). Es la
    /// llamada que SÍ tiene que llevar la continuación.
    #[test]
    fn the_browser_return_after_the_method_step_is_the_continuation() {
        let browser_return = CompleteAuthorizeRedirectResponse {
            params: Some(Secret::new("fiservemea3ds=term".to_string())),
            payload: None,
        };
        assert!(!is_acs_method_notification(&browser_return));
        let request =
            build_continuation_request(&browser_return, Secret::new(CERT_STORE_AR.to_string()));
        assert!(request.method_notification_status.is_some());
        assert!(request.acs_response.is_none());
    }

    /// El retorno del navegador después del desafío: el ACS postea el `cRes` a la `termURL`, así
    /// que llega el marcador `term` y el `cRes` juntos. Tiene que clasificar como retorno y la
    /// continuación tiene que ser la del `cRes`, no la del método.
    #[test]
    fn the_browser_return_after_the_challenge_sends_the_cres() {
        let browser_return = CompleteAuthorizeRedirectResponse {
            params: Some(Secret::new("fiservemea3ds=term".to_string())),
            payload: Some(Secret::new(
                serde_json::json!({ "cRes": CERT_CRES_RESPONSE_1 }),
            )),
        };
        assert!(!is_acs_method_notification(&browser_return));
        let request =
            build_continuation_request(&browser_return, Secret::new(CERT_STORE_AR.to_string()));
        assert_eq!(
            request.acs_response.as_ref().map(|acs| acs.c_res.as_str()),
            Some(CERT_CRES_RESPONSE_1)
        );
        assert!(request.method_notification_status.is_none());
    }

    /// El marcador manda por sobre el contenido: si el ACS reenvía su notificación con el
    /// `threeDSMethodData` a la URL del método, sigue siendo notificación aunque el cuerpo se
    /// parezca al de un retorno. Al revés también: `term` es retorno aunque venga con
    /// `threeDSMethodData`.
    #[test]
    fn the_callback_marker_decides_the_classification_not_the_body() {
        let method_con_cres = CompleteAuthorizeRedirectResponse {
            params: Some(Secret::new("fiservemea3ds=method".to_string())),
            payload: Some(Secret::new(
                serde_json::json!({ "cRes": "no-deberia-continuar" }),
            )),
        };
        assert!(is_acs_method_notification(&method_con_cres));

        let term_con_method_data = CompleteAuthorizeRedirectResponse {
            params: Some(Secret::new(format!(
                "fiservemea3ds=term&threeDSMethodData={CERT_THREE_DS_METHOD_DATA}"
            ))),
            payload: None,
        };
        assert!(!is_acs_method_notification(&term_con_method_data));
    }

    // ---- Punto 2: los bodies de continuación, iguales a los PATCH que cert aceptó ----

    /// `cRes` real que el ACS de test devolvió en "Challenge - configurable / response 1"
    /// (evidencia.jsonl línea 35), el que el gateway aceptó con HTTP 200.
    const CERT_CRES_RESPONSE_1: &str = "ewogICJhY3NUcmFuc0lEIiA6ICJlZmYzYmFhNi0zYzU4LTQzOTEtODY0Ni1mZGMwMDc4M2Q5YmMiLAogICJtZXNzYWdlVHlwZSIgOiAiQ1JlcyIsCiAgIm1lc3NhZ2VWZXJzaW9uIiA6ICIyLjIuMCIsCiAgInRocmVlRFNTZXJ2ZXJUcmFuc0lEIiA6ICI1MmEzNGMwOC1mZjAxLTU1ZTItODAwMC0wMDAwMDQ0Zjc5NTciLAogICJ0cmFuc1N0YXR1cyIgOiAiWSIKfQ";

    /// Serializa el body de continuación por el mismo camino que `get_request_body`.
    fn continuation_body(redirect: &CompleteAuthorizeRedirectResponse) -> serde_json::Value {
        serde_json::to_value(build_continuation_request(
            redirect,
            Secret::new(CERT_STORE_AR.to_string()),
        ))
        .unwrap()
    }

    /// Igualdad EXACTA con el PATCH que cert aceptó en el paso del método
    /// (evidencia.jsonl línea 24 — `3DS 3DSMethod Authenticated [methodNotificationStatus]`,
    /// HTTP 200, apiTraceId anUDYSKQSojaSWQEaFJUFwAAA-E). Tres campos, ni uno más: `acsResponse`
    /// no puede colarse en este paso.
    #[test]
    fn the_method_notification_patch_body_matches_the_one_cert_accepted() {
        let con_notificacion = CompleteAuthorizeRedirectResponse {
            params: Some(Secret::new("fiservemea3ds=term".to_string())),
            payload: Some(Secret::new(serde_json::json!({
                "threeDSMethodData": CERT_THREE_DS_METHOD_DATA,
            }))),
        };
        assert_eq!(
            continuation_body(&con_notificacion),
            serde_json::json!({
                "authenticationType": "Secure3D21AuthenticationUpdateRequest",
                "storeId": CERT_STORE_AR,
                "methodNotificationStatus": "RECEIVED",
            })
        );
    }

    /// El mismo paso cuando la notificación no llegó. Es el body que el conector manda SIEMPRE en
    /// el flujo real (ver `the_received_status_is_unreachable_in_the_real_flow`), así que hace
    /// falta saber que el gateway lo acepta: verificado en vivo sobre la tarjeta 3DSMethod del
    /// checklist (4099000000001978) — HTTP 200, APPROVED, `responseCode3dSecure: 1`,
    /// ipgTransactionId 84668171370, apiTraceId an0HXCR5qsxv6kPs1WraCAAAAcU. Y en
    /// Challenge+Method (4265880000000064) el desafío igual llega después de este PATCH y el
    /// `cRes` cierra en APPROVED (ipgTransactionId 84668171452, apiTraceId
    /// an0Hq52Cn6oVn4oVRUS4qwAAAx8).
    #[test]
    fn the_expected_but_not_received_patch_body_is_accepted_by_cert() {
        let sin_notificacion = CompleteAuthorizeRedirectResponse {
            params: Some(Secret::new("fiservemea3ds=term".to_string())),
            payload: None,
        };
        assert_eq!(
            continuation_body(&sin_notificacion),
            serde_json::json!({
                "authenticationType": "Secure3D21AuthenticationUpdateRequest",
                "storeId": CERT_STORE_AR,
                "methodNotificationStatus": "EXPECTED_BUT_NOT_RECEIVED",
            })
        );
    }

    /// Igualdad EXACTA con el PATCH del `cRes` que cert aceptó (evidencia.jsonl línea 35, HTTP
    /// 200, apiTraceId anUDkZEFKuhRjoXAr1V6TQAAANs). El mismo body, con un `cRes` obtenido en una
    /// corrida propia, se aceptó de nuevo en vivo: ipgTransactionId 84668171391, apiTraceId
    /// an0HbGYBclzAjybWpPC7TAAAA5w, APPROVED con `responseCode3dSecure: 1`.
    #[test]
    fn the_cres_patch_body_matches_the_one_cert_accepted() {
        let con_cres = CompleteAuthorizeRedirectResponse {
            params: Some(Secret::new("fiservemea3ds=term".to_string())),
            payload: Some(Secret::new(
                serde_json::json!({ "cRes": CERT_CRES_RESPONSE_1 }),
            )),
        };
        assert_eq!(
            continuation_body(&con_cres),
            serde_json::json!({
                "authenticationType": "Secure3D21AuthenticationUpdateRequest",
                "storeId": CERT_STORE_AR,
                "acsResponse": { "cRes": CERT_CRES_RESPONSE_1 },
            })
        );
    }

    /// GAP CONOCIDO, no un comportamiento deseado.
    ///
    /// `RECEIVED` es inalcanzable en el flujo real. `has_three_ds_method_data` mira el retorno
    /// del navegador por la `termURL`, pero el `threeDSMethodData` nunca llega ahí: el ACS lo
    /// publica en la `methodNotificationURL` —está escrito dentro del propio blob, campo
    /// `threeDSMethodNotificationURL` (ver `CERT_THREE_DS_METHOD_DATA`)— y esa llamada el
    /// conector la degrada a un PSync y la descarta. El retorno que sí manda el PATCH lo produce
    /// `build_three_ds_method_wrapper` con un `window.location.replace(termURL)` pelado, sin
    /// reenviar nada.
    ///
    /// Consecuencia: el conector le declara al emisor que el fingerprint del dispositivo falló
    /// incluso cuando salió bien. En cert no cambia el resultado (los dos valores cierran en
    /// APPROVED con `responseCode3dSecure: 1`), pero es un dato falso que en producción empuja al
    /// emisor a pedir desafío donde correspondía frictionless.
    #[test]
    fn the_received_status_is_unreachable_in_the_real_flow() {
        // 1. El wrapper navega a la termURL pelada: el destino no lleva ningún dato del método.
        //    (El `threeDSMethodData` sí aparece dentro del `srcdoc`, que es el methodForm del
        //    gateway hospedado en el iframe; lo que importa es que NO viaja en la navegación.)
        let term_url =
            build_three_ds_callback_url(THREE_DS_COMPLETE_AUTHORIZE_URL, "term").unwrap();
        let wrapper = build_three_ds_method_wrapper(
            "<form id=\"tdsMmethodForm\"><input name=\"threeDSMethodData\" value=\"x\"/></form>",
            &term_url,
        );
        assert!(
            wrapper.contains(&format!("var target = \"{term_url}\"")),
            "el wrapper no navega a la termURL pelada: {wrapper}"
        );
        assert!(
            !term_url.contains("threeDSMethodData"),
            "el destino de la navegación lleva threeDSMethodData; el gap ya no existiría"
        );

        // 2. El retorno que llega, entonces, es sólo el marcador `term`.
        let retorno_real = CompleteAuthorizeRedirectResponse {
            params: Some(Secret::new("fiservemea3ds=term".to_string())),
            payload: None,
        };
        assert!(!has_three_ds_method_data(&retorno_real));
        assert_eq!(
            build_continuation_request(&retorno_real, Secret::new(CERT_STORE_AR.to_string()))
                .method_notification_status
                .as_deref(),
            Some("EXPECTED_BUT_NOT_RECEIVED"),
            "si esto pasa a RECEIVED, el gap se cerró y hay que actualizar este test"
        );

        // 3. Y el callback que sí trae el dato es el del método, que no continúa nada.
        let notificacion = CompleteAuthorizeRedirectResponse {
            params: Some(Secret::new("fiservemea3ds=method".to_string())),
            payload: Some(Secret::new(serde_json::json!({
                "threeDSMethodData": CERT_THREE_DS_METHOD_DATA,
            }))),
        };
        assert!(has_three_ds_method_data(&notificacion));
        assert!(is_acs_method_notification(&notificacion));
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
            security_code: Some(Secret::new("123".to_string())),
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
        match auth.to_redirection(None) {
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
        match auth.to_redirection(None) {
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

    #[test]
    fn error_response_deserializes_camel_case_fields() {
        // Respuesta real del gateway cert ante un authenticationType inválido.
        let raw = serde_json::json!({
            "type": "errorResponse",
            "clientRequestId": "a81ea7ae-078d-456f-a106-e8aa5a13ade2",
            "apiTraceId": "anTLkyKQSojaSWQEaFJ6awAAA-M",
            "responseType": "BadRequest",
            "error": {
                "code": "INVALID_INPUT",
                "message": "Invalid request input. Please see details below."
            }
        });
        let parsed: FiservemeaErrorResponse = serde_json::from_value(raw).unwrap();
        assert_eq!(
            parsed.client_request_id.as_deref(),
            Some("a81ea7ae-078d-456f-a106-e8aa5a13ade2")
        );
        // El apiTraceId es el identificador con el que Fiserv busca en sus logs:
        // antes se perdía porque el struct no declaraba camelCase.
        assert_eq!(
            parsed.api_trace_id.as_deref(),
            Some("anTLkyKQSojaSWQEaFJ6awAAA-M")
        );
        assert_eq!(parsed.response_type.as_deref(), Some("BadRequest"));
    }

    #[test]
    fn capture_method_none_is_auto_capture() {
        // `None` significa automático en la API de Hyperswitch: tratarlo como manual
        // mandaba un PreAuth y dejaba la retención sin capturar.
        assert!(is_auto_capture(None));
        assert!(is_auto_capture(Some(enums::CaptureMethod::Automatic)));
        assert!(is_auto_capture(Some(enums::CaptureMethod::SequentialAutomatic)));
        assert!(!is_auto_capture(Some(enums::CaptureMethod::Manual)));
    }

    #[test]
    fn split_approval_code_parses_real_gateway_values() {
        // Valores reales capturados contra cert.
        assert_eq!(
            split_approval_code(Some("N:-11101:installment not supported")),
            (
                Some("-11101".to_string()),
                Some("installment not supported".to_string())
            )
        );
        assert_eq!(
            split_approval_code(Some("N:05:Do not honour")),
            (Some("05".to_string()), Some("Do not honour".to_string()))
        );
        // El texto puede llevar ':' adentro y no debe partirse.
        assert_eq!(
            split_approval_code(Some("N:-50716:Transaction declined: 3D Secure")),
            (
                Some("-50716".to_string()),
                Some("Transaction declined: 3D Secure".to_string())
            )
        );
        // Formatos que no son `X:código:texto` no deben inventar un código.
        assert_eq!(split_approval_code(Some("Y:683316")), (Some("683316".to_string()), None));
        assert_eq!(split_approval_code(Some("")), (None, None));
        assert_eq!(split_approval_code(None), (None, None));
    }

    /// Rechazo real del emisor traído del gateway de certificación (tienda AR, Mastercard
    /// 5165850000000008, monto 1005 = "Do not honour" según la tabla de códigos DECLINED).
    /// Llega con HTTP 422 y `responseType: EndpointDeclined`, o sea que lo procesa
    /// `build_error_response`, no el `TryFrom` de `FiservemeaPaymentsResponse`.
    fn real_cert_issuer_decline_422() -> serde_json::Value {
        serde_json::json!({
            "type": "TransactionErrorResponse",
            "clientRequestId": "04e9f8af-56a6-4486-8292-6c3ad92f7742",
            "apiTraceId": "anX00xdinKHsuo_YUYCS7QAAA40",
            "responseType": "EndpointDeclined",
            "ipgTransactionId": "84667456653",
            "orderId": "PX-1786115282-01-gap5",
            "transactionType": "SALE",
            "transactionStatus": "DECLINED",
            "transactionResult": "DECLINED",
            "approvalCode": "N:05:Do not honour",
            "errorMessage": "50005: Do not honour",
            "transactionState": "DECLINED",
            "processor": {
                "referenceNumber": "000000024168",
                "authorizationCode": "82333",
                "responseCode": "05",
                "responseMessage": "Do not honour",
                "avsResponse": {
                    "streetMatch": "NO_INPUT_DATA",
                    "postalCodeMatch": "NO_INPUT_DATA"
                },
                "securityCodeResponse": "NOT_CHECKED",
                "taxRefundData": {}
            },
            "error": { "code": "50005", "message": "Do not honour" }
        })
    }

    #[test]
    fn issuer_decline_error_response_parses_processor_block() {
        // El camino real de un rechazo del emisor es el HTTP 422, así que
        // `FiservemeaErrorResponse` tiene que quedarse con el `processor`: sin eso los códigos
        // de red se perdían en el único flujo donde efectivamente llegan.
        let parsed: FiservemeaErrorResponse =
            serde_json::from_value(real_cert_issuer_decline_422()).unwrap();
        assert_eq!(parsed.response_type.as_deref(), Some("EndpointDeclined"));

        let network = FiservemeaNetworkCodes::from_processor(parsed.processor.as_ref());
        assert_eq!(
            network,
            FiservemeaNetworkCodes {
                // Cert no manda `associationResponseCode`; el fallback al `responseCode` ISO
                // evita que el motor de reintentos se quede sin ningún código.
                decline_code: Some("05".to_string()),
                advice_code: None,
                error_message: Some("Do not honour".to_string()),
            }
        );
    }

    #[test]
    fn network_codes_use_the_iso_response_code_and_expose_merchant_advice_code() {
        // Bloque `processor` tal cual lo publica el Manual NetworkToken MTRG en su forma REST:
        // es el único documento de Fiserv que muestra `associationResponseCode`, y lo muestra
        // con el valor `"XX"` en una transacción APROBADA. Ese fixture es justamente el motivo
        // para no preferirlo: publicar `"XX"` como código de rechazo de red le daría al motor
        // de reintentos un valor que no es un código ISO.
        let processor: Processor = serde_json::from_value(serde_json::json!({
            "referenceNumber": "908651908651",
            "authorizationCode": "908651",
            "responseCode": "00",
            "associationResponseCode": "XX",
            "responseMessage": "Function performed error-free",
            "avsResponse": {
                "streetMatch": "NO_INPUT_DATA",
                "postalCodeMatch": "NO_INPUT_DATA"
            },
            "securityCodeResponse": "NOT_CHECKED",
            "merchantAdviceCodeIndicator": "01",
            "taxRefundData": {}
        }))
        .unwrap();

        let network = FiservemeaNetworkCodes::from_processor(Some(&processor));
        assert_eq!(
            network,
            FiservemeaNetworkCodes {
                // El ISO del procesador, que es el único campo que vimos llevando códigos
                // reales (01, 05, 51…) en las respuestas del gateway de certificación.
                decline_code: Some("00".to_string()),
                // El MAC de Mastercard es lo que decide si reintentar tiene penalidad.
                advice_code: Some("01".to_string()),
                error_message: Some("Function performed error-free".to_string()),
            }
        );
        // `associationResponseCode` se sigue parseando: si más adelante se confirma qué publica
        // en un rechazo real, el campo ya está disponible sin volver a tocar el struct.
        assert_eq!(processor.association_response_code.as_deref(), Some("XX"));
    }

    #[test]
    fn network_codes_are_empty_without_processor_block() {
        // Los rechazos de validación del gateway (HTTP 409 `GatewayDeclined`, p. ej.
        // `N:-11101:installment not supported`) no traen `processor`: no hay código de red que
        // publicar y no hay que fabricarlo con el del gateway.
        assert_eq!(
            FiservemeaNetworkCodes::from_processor(None),
            FiservemeaNetworkCodes::default()
        );
    }

    #[test]
    fn merchant_transaction_id_is_truncated_to_gateway_limit() {
        // IPG corta en 40; merchant_order_reference_id acepta hasta 255.
        let largo = "PXSOL-RESERVA-2026-08-06-HOTEL-1234-HABITACION-501-CONFIRMADA";
        let truncado: String = largo
            .chars()
            .take(FISERVEMEA_MERCHANT_TRANSACTION_ID_MAX_LEN)
            .collect();
        assert_eq!(truncado.chars().count(), 40);
        assert!(largo.starts_with(&truncado));
    }

    /// Venta APROBADA real del gateway de cert (POST /payments, HTTP 200). Se usa como base
    /// de los casos de valor desconocido: lo importante es que ninguna mutación puntual de un
    /// enum convierta este cobro en un error de deserialización.
    fn real_cert_approved_sale() -> serde_json::Value {
        serde_json::json!({
            "type": "transactionResponse",
            "clientRequestId": "d0479c7c-ed0b-4628-86f4-5d9cdee57a30",
            "apiTraceId": "anUDKXbyIFesn-w_H27JzQAAA9E",
            "ipgTransactionId": "84667286258",
            "orderId": "PX-1786053416-01-sale",
            "transactionType": "SALE",
            "transactionOrigin": "ECOM",
            "paymentMethodDetails": {
                "paymentCard": {
                    "expiryDate": { "month": "12", "year": "2029" },
                    "bin": "516585", "last4": "0008", "brand": "MASTERCARD"
                },
                "paymentMethodType": "PAYMENT_CARD",
                "paymentMethodBrand": "MASTERCARD"
            },
            "country": "Argentina",
            "terminalId": "98000002",
            "merchantId": "00000014",
            "merchantTransactionId": "PX-1786053416-01-sale",
            "transactionTime": 1_786_053_417_i64,
            "approvedAmount": { "total": 1000.0, "currency": "ARS", "components": { "subtotal": 1000.0 } },
            "transactionAmount": { "total": 1000.0, "currency": "ARS", "components": { "subtotal": 1000.0 } },
            "transactionStatus": "APPROVED",
            "transactionResult": "APPROVED",
            "approvalCode": "Y:943616:4667286258:PPXX:9476656675",
            "transactionState": "CAPTURED",
            "processor": {
                "referenceNumber": "000000019357",
                "authorizationCode": "943616",
                "responseCode": "00",
                "responseMessage": "Function performed error-free"
            }
        })
    }

    fn parse_response(raw: serde_json::Value) -> FiservemeaPaymentsResponse {
        serde_json::from_value(raw).expect("la respuesta del gateway debe deserializar")
    }

    fn status_of(response: FiservemeaPaymentsResponse) -> common_enums::AttemptStatus {
        map_status(
            response.transaction_status,
            response.transaction_result,
            response.transaction_type,
            response.transaction_state.as_deref(),
        )
    }

    #[test]
    fn real_cert_approved_sale_still_maps_to_charged() {
        // Línea de base: el caso feliz no cambia de significado por el fallback.
        assert_eq!(
            status_of(parse_response(real_cert_approved_sale())),
            common_enums::AttemptStatus::Charged
        );
    }

    #[test]
    fn unknown_transaction_type_parses_and_does_not_claim_charged() {
        // Mismo cobro real, con un `transactionType` que el conector no contempla. Antes esto
        // no deserializaba y el cobro se reportaba como error de conector.
        let mut raw = real_cert_approved_sale();
        raw["transactionType"] = serde_json::json!("SPLIT_SHIPMENT");
        let response = parse_response(raw);
        assert_eq!(
            response.transaction_type,
            Some(FiservemeaTransactionType::Unknown)
        );
        // Aprobado pero sin saber si autorizó, capturó o anuló: ni Charged ni Failure.
        assert_eq!(
            status_of(response),
            common_enums::AttemptStatus::Pending,
            "un tipo desconocido no puede dar el cobro por bueno ni por perdido"
        );
    }

    #[test]
    fn missing_transaction_type_parses_and_stays_pending() {
        // El gateway devuelve respuestas sin `transactionType` (ver el rechazo real
        // "Unable to verify card enrollment"), así que el campo no puede ser obligatorio.
        let mut raw = real_cert_approved_sale();
        raw.as_object_mut().unwrap().remove("transactionType");
        let response = parse_response(raw);
        assert!(response.transaction_type.is_none());
        assert_eq!(status_of(response), common_enums::AttemptStatus::Pending);
    }

    #[test]
    fn unknown_transaction_status_falls_back_to_transaction_result() {
        // `transactionStatus` está deprecado: si trae un valor nuevo no debe tapar al
        // `transactionResult` vigente, que en esta misma respuesta real dice APPROVED.
        let mut raw = real_cert_approved_sale();
        raw["transactionStatus"] = serde_json::json!("SETTLED");
        let response = parse_response(raw);
        assert_eq!(
            response.transaction_status,
            Some(FiservemeaPaymentStatus::Unknown)
        );
        assert_eq!(status_of(response), common_enums::AttemptStatus::Charged);
    }

    #[test]
    fn unknown_transaction_result_keeps_attempt_pending() {
        // Sin ningún campo interpretable no se puede decidir: queda para el PSync.
        let mut raw = real_cert_approved_sale();
        raw.as_object_mut().unwrap().remove("transactionStatus");
        raw["transactionResult"] = serde_json::json!("REVIEW");
        let response = parse_response(raw);
        assert_eq!(
            response.transaction_result,
            Some(FiservemeaPaymentResult::Unknown)
        );
        assert_eq!(status_of(response), common_enums::AttemptStatus::Pending);
    }

    #[test]
    fn unknown_transaction_origin_and_response_type_do_not_break_parsing() {
        // Estos dos enums no deciden el estado, pero al ser campos de la misma struct un
        // valor nuevo en cualquiera de ellos hacía fallar el parseo de todo el cobro.
        let mut raw = real_cert_approved_sale();
        raw["transactionOrigin"] = serde_json::json!("IN_APP");
        raw["responseType"] = serde_json::json!("SomethingNew");
        assert_eq!(
            status_of(parse_response(raw)),
            common_enums::AttemptStatus::Charged
        );
    }

    #[test]
    fn real_cert_decline_without_ids_deserializes() {
        // Rechazo real (HTTP 409) del caso 3DS Data Only: llega sin `ipgTransactionId` y sin
        // `transactionType`. Con esos campos obligatorios la respuesta no parseaba y se perdía
        // hasta el motivo del rechazo.
        let raw = serde_json::json!({
            "type": "TransactionErrorResponse",
            "clientRequestId": "496db1e7-352f-46ea-9946-3b1c8c57d2ea",
            "apiTraceId": "anUD4RdinKHsuo_YUYCCjQAAA5M",
            "responseType": "GatewayDeclined",
            "orderId": "PX-1786053599-33-3ds-dataonly",
            "transactionTime": 1_786_053_601_i64,
            "transactionStatus": "VALIDATION_FAILED",
            "transactionResult": "FAILED",
            "approvalCode": "N:-50655:Unable to verify card enrollment",
            "errorMessage": "50655: Unable to verify card enrollment",
            "secure3dResponse": { "responseCode3dSecure": "8" }
        });
        let response = parse_response(raw);
        assert!(response.ipg_transaction_id.is_none());
        assert!(response.transaction_type.is_none());
        assert_eq!(status_of(response), common_enums::AttemptStatus::Failure);
    }

    #[test]
    fn real_cert_declined_sale_maps_to_failure() {
        // Rechazo real de cuotas con tarjeta no local (HTTP 409): VALIDATION_FAILED/FAILED
        // debe seguir siendo Failure después de reordenar `map_status`.
        let raw = serde_json::json!({
            "type": "TransactionErrorResponse",
            "responseType": "GatewayDeclined",
            "ipgTransactionId": "84667286314",
            "orderId": "PX-1786053442-11-mtrg",
            "transactionType": "SALE",
            "transactionStatus": "VALIDATION_FAILED",
            "transactionResult": "FAILED",
            "approvalCode": "N:-11101:installment not supported",
            "errorMessage": "11101: installment only supported for local cards",
            "transactionState": "DECLINED"
        });
        assert_eq!(
            status_of(parse_response(raw)),
            common_enums::AttemptStatus::Failure
        );
    }

    #[test]
    fn real_cert_void_maps_to_voided() {
        // Anulación real: APPROVED + transactionType VOID.
        let raw = serde_json::json!({
            "type": "transactionResponse",
            "ipgTransactionId": "84667286297",
            "orderId": "PX-1786053427-07-void",
            "transactionType": "VOID",
            "transactionStatus": "APPROVED",
            "transactionResult": "APPROVED",
            "approvalCode": "Y:470405:4667286297:PPXX:9476816680",
            "transactionState": "VOIDED"
        });
        assert_eq!(
            status_of(parse_response(raw)),
            common_enums::AttemptStatus::Voided
        );
    }

    #[test]
    fn real_cert_waiting_3ds_maps_to_pending() {
        // Primer paso 3DS real: WAITING en los dos campos mientras corre el 3DSMethod.
        let raw = serde_json::json!({
            "type": "transactionResponse",
            "ipgTransactionId": "84667286332",
            "orderId": "PX-1786053463-18-3ds-mth-y",
            "transactionType": "SALE",
            "transactionStatus": "WAITING",
            "transactionResult": "WAITING",
            "approvalCode": "?:waiting 3dsecureMethod",
            "transactionState": "WAITING"
        });
        assert_eq!(
            status_of(parse_response(raw)),
            common_enums::AttemptStatus::Pending
        );
    }

    /// Devolución total real del gateway de cert (POST /payments/{id}).
    fn real_cert_return() -> serde_json::Value {
        serde_json::json!({
            "type": "transactionResponse",
            "ipgTransactionId": "84667286299",
            "orderId": "PX-1786053430-08-rettot",
            "transactionType": "RETURN",
            "transactionOrigin": "ECOM",
            "transactionTime": 1_786_053_434_i64,
            "approvedAmount": { "total": 1000.0, "currency": "ARS", "components": { "subtotal": 1000.0 } },
            "transactionAmount": { "total": 1000.0, "currency": "ARS", "components": { "subtotal": 1000.0 } },
            "transactionStatus": "APPROVED",
            "transactionResult": "APPROVED",
            "approvalCode": "Y:954253:4667286299:PPXX:9476858437",
            "transactionState": "CAPTURED"
        })
    }

    #[test]
    fn real_cert_return_maps_refund_to_success() {
        let response = parse_response(real_cert_return());
        assert_eq!(
            map_refund_status(response.transaction_status, response.transaction_result),
            enums::RefundStatus::Success
        );
    }

    #[test]
    fn unknown_refund_result_stays_pending_instead_of_failing() {
        // El `RETURN` ya viajó al gateway. Un desenlace que no sabemos leer no puede quedar
        // como Failure/error, porque eso habilita reintentar y pagarle dos veces al cliente.
        let mut raw = real_cert_return();
        raw["transactionStatus"] = serde_json::json!("SETTLED");
        raw["transactionResult"] = serde_json::json!("REVIEW");
        let response = parse_response(raw);
        assert_eq!(
            map_refund_status(response.transaction_status, response.transaction_result),
            enums::RefundStatus::Pending
        );
    }

    #[test]
    fn unknown_refund_status_falls_back_to_refund_result() {
        let mut raw = real_cert_return();
        raw["transactionStatus"] = serde_json::json!("SETTLED");
        let response = parse_response(raw);
        assert_eq!(
            map_refund_status(response.transaction_status, response.transaction_result),
            enums::RefundStatus::Success
        );
    }

    #[test]
    fn refund_without_any_outcome_field_stays_pending() {
        // Antes esto era `Err(MissingRequiredField)`: mismo riesgo de doble devolución.
        let mut raw = real_cert_return();
        let object = raw.as_object_mut().unwrap();
        object.remove("transactionStatus");
        object.remove("transactionResult");
        let response = parse_response(raw);
        assert_eq!(
            map_refund_status(response.transaction_status, response.transaction_result),
            enums::RefundStatus::Pending
        );
    }
    /// `methodForm` real del gateway de certificación (respuesta del POST /payments del caso
    /// "3DSMethod Authenticated"), recortado a lo estructural: el iframe oculto y el form que
    /// apunta a ese mismo iframe.
    const CERT_METHOD_FORM: &str = r#"<iframe id="tdsMmethodTgtFrame" name="tdsMmethodTgtFrame" style="visibility: hidden; width: 1px; height: 1px;"></iframe><form id="tdsMmethodForm" name="tdsMmethodForm" action="https://3ds-acs.test.modirum.com/mdpayacs/3ds-method" method="post" target="tdsMmethodTgtFrame"><input type="hidden" name="threeDSMethodData" value="eyAidGhyZWVEU1Nl"/></form>"#;

    #[test]
    fn cert_method_form_cannot_continue_the_flow_on_its_own() {
        // Es el diagnóstico que justifica el wrapper: el form del gateway apunta su `target` al
        // iframe oculto y no toca la ventana principal, así que lo que venga después del
        // fingerprint se renderiza invisible.
        assert!(CERT_METHOD_FORM.contains("visibility: hidden"));
        assert!(CERT_METHOD_FORM.contains(r#"target="tdsMmethodTgtFrame""#));
        assert!(!CERT_METHOD_FORM.contains("window.top"));
        assert!(!CERT_METHOD_FORM.contains("location"));
    }

    #[test]
    fn method_form_wrapper_hosts_the_form_and_navigates_the_main_window() {
        let wrapper = build_three_ds_method_wrapper(CERT_METHOD_FORM, TEST_RETURN_URL);

        // El form viaja escapado dentro del `srcdoc`, no suelto en la página: si se inyectara
        // crudo, su `</form>` cerraría el marcado del wrapper.
        assert!(wrapper.contains("srcdoc=\""));
        assert!(!wrapper.contains(r#"<form id="tdsMmethodForm""#));
        assert!(wrapper.contains("&lt;form id=&quot;tdsMmethodForm&quot;"));
        // Pero el fingerprint del emisor tiene que seguir ejecutándose.
        assert!(wrapper.contains("https://3ds-acs.test.modirum.com/mdpayacs/3ds-method"));

        // La espera mínima que exige la guía, y la navegación de la ventana principal.
        assert!(wrapper.contains("window.setTimeout(continueAuthentication, 10000)"));
        assert!(wrapper.contains(TEST_RETURN_URL));
        // Y la guarda que evita un retorno duplicado si esta misma página quedara anidada.
        assert!(wrapper.contains("window.self !== window.top"));
    }

    #[test]
    fn method_form_wrapper_escapes_a_hostile_return_url() {
        // La URL de retorno es configuración del comercio: no puede cerrar el `<script>`.
        let wrapper = build_three_ds_method_wrapper(
            CERT_METHOD_FORM,
            r#"https://x.test/r?a="</script><script>alert(1)</script>"#,
        );
        assert!(!wrapper.contains("</script><script>alert(1)"));
        assert!(wrapper.contains("\\u003c/script"));
    }

    #[test]
    fn method_form_redirection_is_wrapped_only_when_the_return_url_is_known() {
        let auth: FiservemeaAuthenticationResponse = serde_json::from_value(serde_json::json!({
            "type": "3D_SECURE",
            "version": "2.2",
            "secure3dMethod": { "methodForm": CERT_METHOD_FORM }
        }))
        .unwrap();

        match auth.to_redirection(Some(TEST_RETURN_URL)) {
            Some(RedirectForm::Html { html_data }) => {
                assert!(html_data.contains("window.setTimeout(continueAuthentication"))
            }
            other => panic!("se esperaba el wrapper, salió {other:?}"),
        }
        // Sin URL de retorno se devuelve el form crudo: es el comportamiento anterior, peor pero
        // no una regresión respecto de no responder nada.
        match auth.to_redirection(None) {
            Some(RedirectForm::Html { html_data }) => assert_eq!(html_data, CERT_METHOD_FORM),
            other => panic!("se esperaba el form crudo, salió {other:?}"),
        }
    }

    #[test]
    fn network_token_pairing_only_when_the_gateway_substituted() {
        // Venta MTRG real por el flujo OnTheGo: el gateway procesó con Network Token, así que el
        // BIN procesado (432312) difiere del que fondea (462294). Es el emparejamiento que el
        // manual de Network Token exige guardar en cada transacción aprobada.
        let details: FiservemeaPaymentMethodDetails = serde_json::from_value(serde_json::json!({
            "paymentCard": {
                "expiryDate": { "month": "12", "year": "2029" },
                "fundingCardNumber": { "bin": "462294", "last4": "2366" },
                "bin": "432312",
                "last4": "7867",
                "brand": "VISA"
            },
            "paymentMethodType": "PAYMENT_CARD",
            "paymentMethodBrand": "VISA"
        }))
        .unwrap();
        assert_eq!(
            details.network_token_pairing(),
            Some(FiservemeaNetworkTokenPairing {
                network_token_bin: "432312".to_string(),
                network_token_last4: "7867".to_string(),
                funding_card_bin: "462294".to_string(),
                funding_card_last4: "2366".to_string(),
            })
        );

        // Venta común sin tokenización de marca: IPG manda `fundingCardNumber` igual, con el
        // MISMO bin. Emitir el emparejamiento acá afirmaría una tokenización que no ocurrió.
        let details: FiservemeaPaymentMethodDetails = serde_json::from_value(serde_json::json!({
            "paymentCard": {
                "fundingCardNumber": { "bin": "516585", "last4": "0008" },
                "bin": "516585",
                "last4": "0008",
                "brand": "MASTERCARD"
            }
        }))
        .unwrap();
        assert_eq!(details.network_token_pairing(), None);
    }

    #[test]
    fn stored_credentials_follow_the_vendor_examples_per_brand() {
        // Visa FIRST: la guía NO manda el bloque; alcanza `recurringType: FIRST`.
        assert_eq!(FiservemeaStoredCredentials::new(false, true, None), None);

        // Visa REPEAT: sólo transporta el `referencedSchemeTransactionId`, sin initiator ni
        // indicatorSubcategory (guía §11.3.1.1.b).
        assert_eq!(
            FiservemeaStoredCredentials::new(false, false, Some("098765432112345".to_string())),
            Some(FiservemeaStoredCredentials {
                sequence: FiservemeaStoredCredentialSequence::Subsequent,
                scheduled: false,
                initiator: None,
                indicator_subcategory: None,
                referenced_scheme_transaction_id: Some("098765432112345".to_string()),
            })
        );
        // Y sin ese id no hay nada que informar.
        assert_eq!(FiservemeaStoredCredentials::new(false, false, None), None);

        // Mastercard FIRST y SUBSEQUENT: los dos con MERCHANT + CREDENTIAL_ON_FILE_FIRST. El
        // ejemplo de la guía repite esa subcategoría también en la SUBSEQUENT (§11.3.1.2.b).
        for (is_first, esperado) in [
            (true, FiservemeaStoredCredentialSequence::First),
            (false, FiservemeaStoredCredentialSequence::Subsequent),
        ] {
            let sc = FiservemeaStoredCredentials::new(true, is_first, None).unwrap();
            assert_eq!(sc.sequence, esperado);
            assert_eq!(
                sc.initiator,
                Some(FiservemeaStoredCredentialInitiator::Merchant)
            );
            assert_eq!(
                sc.indicator_subcategory,
                Some(FISERVEMEA_INDICATOR_CREDENTIAL_ON_FILE_FIRST)
            );
        }
    }

    #[test]
    fn stored_credentials_serialize_like_the_vendor_example() {
        // Comparación del objeto completo contra el ejemplo Mastercard FIRST de la guía, para
        // que un campo nuevo no se cuele sin que un test lo note.
        let sc = FiservemeaStoredCredentials::new(true, true, None).unwrap();
        assert_eq!(
            serde_json::to_value(&sc).unwrap(),
            serde_json::json!({
                "sequence": "FIRST",
                "scheduled": false,
                "initiator": "MERCHANT",
                "indicatorSubcategory": "CREDENTIAL_ON_FILE_FIRST"
            })
        );
    }

    #[test]
    fn installment_options_carry_recurring_type_without_inventing_installments() {
        // Los ejemplos de recurrencia mandan `installmentOptions` con SÓLO `recurringType`:
        // serializar un `numberOfInstallments: 0` ahí sería inventar un plan de cuotas.
        let options = FiservemeaInstallmentOptions {
            number_of_installments: None,
            interest: None,
            recurring_type: Some(FiservemeaRecurringType::First),
        };
        assert_eq!(
            serde_json::to_value(&options).unwrap(),
            serde_json::json!({ "recurringType": "FIRST" })
        );
    }

    #[test]
    fn interest_is_not_emitted_without_an_installment_plan() {
        // `Interest` sin `numberOfInstallments` sería un campo sin referente: la guía sólo lo
        // documenta acompañando un plan de cuotas.
        let options = FiservemeaInstallmentOptions {
            number_of_installments: None,
            interest: None,
            recurring_type: Some(FiservemeaRecurringType::Repeat),
        };
        let json = serde_json::to_value(&options).unwrap();
        assert!(json.get("Interest").is_none());
        assert!(json.get("numberOfInstallments").is_none());
        assert_eq!(json["recurringType"], "REPEAT");
    }

    #[test]
    fn token_cryptogram_length_is_measured_in_characters() {
        // El gateway valida el largo entre 20 y 256 (verificado contra cert: "ZZZZ" devuelve
        // `order.tokenCryptogram: size must be between 20 and 256`). El criptograma real es
        // base64, o sea ASCII, pero medir en caracteres y no en bytes evita que un valor con
        // multibyte pase o falle por el motivo equivocado.
        let ejemplo = "AgAAAAoAPlUosiUEDQNSgElQEAA=";
        assert_eq!(ejemplo.chars().count(), 28);
        assert!(FISERVEMEA_TOKEN_CRYPTOGRAM_LEN.contains(&ejemplo.chars().count()));
        assert!(!FISERVEMEA_TOKEN_CRYPTOGRAM_LEN.contains(&"ZZZZ".chars().count()));
        // 20 caracteres multibyte son 40+ bytes: medido en bytes esto pasaría el mínimo por el
        // motivo equivocado.
        let multibyte: String = "ñ".repeat(20);
        assert_eq!(multibyte.chars().count(), 20);
        assert!(multibyte.len() > 20);
        assert!(FISERVEMEA_TOKEN_CRYPTOGRAM_LEN.contains(&multibyte.chars().count()));
    }

    #[test]
    fn the_two_three_ds_callbacks_are_distinguishable() {
        let term = build_three_ds_callback_url(TEST_RETURN_URL, THREE_DS_CALLBACK_TERM).unwrap();
        let method =
            build_three_ds_callback_url(TEST_RETURN_URL, THREE_DS_CALLBACK_METHOD).unwrap();
        assert_ne!(term, method);
        assert!(term.contains("fiservemea3ds=term"));
        assert!(method.contains("fiservemea3ds=method"));

        // Un complete_authorize_url que ya trae query string no se rompe.
        let con_query =
            build_three_ds_callback_url("https://x.test/r?pago=abc", THREE_DS_CALLBACK_METHOD)
                .unwrap();
        assert!(con_query.contains("pago=abc"));
        assert!(con_query.contains("fiservemea3ds=method"));

        // Y una URL inválida falla cerrado en vez de mandarle basura al ACS.
        assert!(build_three_ds_callback_url("no-es-una-url", THREE_DS_CALLBACK_TERM).is_err());
    }

    #[test]
    fn authentication_request_sends_the_two_urls_apart() {
        // Es la corrección de fondo del 3DS: si las dos URLs son la misma, la notificación que el
        // ACS publica dentro del iframe oculto dispara la continuación y el desafío se renderiza
        // invisible. Separándolas, la continuación la manda el retorno por la termURL, que ocurre
        // en la ventana principal.
        let meta = meta_from_json(serde_json::json!({}));
        let request = FiservemeaAuthenticationRequest::new(
            build_three_ds_callback_url(TEST_RETURN_URL, THREE_DS_CALLBACK_TERM).unwrap(),
            build_three_ds_callback_url(TEST_RETURN_URL, THREE_DS_CALLBACK_METHOD).unwrap(),
            &meta,
            false,
        )
        .unwrap();
        let json = serde_json::to_value(&request).unwrap();
        assert_ne!(json["termURL"], json["methodNotificationURL"]);
        assert!(json["termURL"].as_str().unwrap().contains("=term"));
        assert!(json["methodNotificationURL"]
            .as_str()
            .unwrap()
            .contains("=method"));
    }

    #[test]
    fn acs_method_notification_is_told_apart_from_the_browser_return() {
        // El POST del ACS a la methodNotificationURL: NO debe continuar la autenticación.
        let acs = CompleteAuthorizeRedirectResponse {
            params: Some(Secret::new(
                "fiservemea3ds=method&threeDSMethodData=eyJ0aHJlZURTU2Vy".to_string(),
            )),
            payload: None,
        };
        assert!(is_acs_method_notification(&acs));

        // El retorno del navegador por la termURL: es el que lleva el PATCH.
        let browser = CompleteAuthorizeRedirectResponse {
            params: Some(Secret::new("fiservemea3ds=term".to_string())),
            payload: None,
        };
        assert!(!is_acs_method_notification(&browser));

        // También se acepta el marcador en el payload JSON, porque el ACS publica de las dos
        // formas.
        let acs_json = CompleteAuthorizeRedirectResponse {
            params: None,
            payload: Some(Secret::new(
                serde_json::json!({ "fiservemea3ds": "method" }),
            )),
        };
        assert!(is_acs_method_notification(&acs_json));

        // Sin marcador se trata como retorno del navegador: es el comportamiento anterior, para
        // las transacciones iniciadas antes de este cambio.
        let sin_marcador = CompleteAuthorizeRedirectResponse {
            params: Some(Secret::new("cres=abc".to_string())),
            payload: None,
        };
        assert!(!is_acs_method_notification(&sin_marcador));
    }

    #[test]
    fn wrapper_navigates_to_the_term_callback_not_the_method_one() {
        // Si el wrapper navegara a la methodNotificationURL, el retorno visible se degradaría a
        // una consulta y el desafío no se mostraría nunca.
        let term = build_three_ds_callback_url(TEST_RETURN_URL, THREE_DS_CALLBACK_TERM).unwrap();
        let wrapper = build_three_ds_method_wrapper(CERT_METHOD_FORM, &term);
        assert!(wrapper.contains("fiservemea3ds=term"));
        assert!(!wrapper.contains("fiservemea3ds=method"));
    }

    // =================================================================================
    // CONTRASTE CONTRA LOS PAYLOADS REALES DEL GATEWAY DE CERTIFICACIÓN
    //
    // Cada `expected` de acá abajo es, copiado tal cual, el `request` que el harness de
    // homologación mandó y que el gateway respondió con HTTP 200. Fuente:
    //   fiserv_homologacion_logs/20260806-215656/evidencia.jsonl
    // (una línea por caso; el índice de la línea va citado en cada test).
    //
    // Los tests construyen el request POR EL CAMINO REAL del conector — el mismo `TryFrom`
    // que usa `get_request_body`, con la misma conversión de importe
    // (`StringMajorUnitForConnector`) — y comparan el JSON completo contra el que el gateway
    // ya aceptó. Cualquier diferencia de nombre de campo, de tipo (string vs número) o de
    // anidamiento hace fallar el test.
    // =================================================================================

    use std::marker::PhantomData;

    use common_utils::types::{AmountConvertor, MinorUnit, StringMajorUnitForConnector};
    use hyperswitch_domain_models::{
        payment_address::PaymentAddress,
        payment_method_data::Card,
        router_request_types::{
            PaymentMethodTokenizationData, PaymentsAuthorizeData, PaymentsCancelData,
            PaymentsCaptureData, RefundsData,
        },
    };

    /// Tienda AR del checklist.
    const CERT_STORE_AR: &str = "5926072901";
    /// Tienda con TOKEN GW habilitado.
    const CERT_STORE_TOKEN_GW: &str = "5926072902";
    /// Mastercard de pruebas de la homologación.
    const CERT_CARD: &str = "5165850000000008";
    /// Visa que el gateway sustituye por Network Token (flujo MTRG OnTheGo).
    const CERT_CARD_MTRG: &str = "4622943127032366";

    fn cert_auth(store_id: &str) -> ConnectorAuthType {
        ConnectorAuthType::SignatureKey {
            api_key: Secret::new("apikey".to_string()),
            key1: Secret::new(store_id.to_string()),
            api_secret: Secret::new("apisecret".to_string()),
        }
    }

    /// Tarjeta con el vencimiento 12/2029 que usó la homologación (el conector lo recorta a
    /// dos dígitos, igual que el harness).
    fn cert_card_data(number: &str) -> PaymentMethodData {
        PaymentMethodData::Card(Card {
            card_number: number.parse().unwrap(),
            card_exp_month: Secret::new("12".to_string()),
            card_exp_year: Secret::new("2029".to_string()),
            card_cvc: Secret::new("123".to_string()),
            ..Default::default()
        })
    }

    /// `RouterData` mínimo pero completo: sólo se llenan los campos que el conector lee.
    fn cert_router_data<Flow, Req, Res>(
        store_id: &str,
        reference_id: &str,
        request: Req,
    ) -> RouterData<Flow, Req, Res> {
        RouterData {
            flow: PhantomData,
            merchant_id: common_utils::id_type::MerchantId::default(),
            customer_id: None,
            connector_customer: None,
            connector: "fiservemea".to_string(),
            payment_id: reference_id.to_string(),
            attempt_id: reference_id.to_string(),
            tenant_id: common_utils::id_type::TenantId::try_from_string("public".to_string())
                .unwrap(),
            status: common_enums::AttemptStatus::Pending,
            payment_method: common_enums::PaymentMethod::Card,
            connector_auth_type: cert_auth(store_id),
            description: None,
            address: PaymentAddress::default(),
            auth_type: common_enums::AuthenticationType::NoThreeDs,
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
            connector_request_reference_id: reference_id.to_string(),
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
        }
    }

    fn cert_authorize_data(
        payment_method_data: PaymentMethodData,
        minor_amount: i64,
        currency: common_enums::Currency,
        metadata: Option<serde_json::Value>,
    ) -> PaymentsAuthorizeData {
        PaymentsAuthorizeData {
            payment_method_data,
            amount: minor_amount,
            order_tax_amount: None,
            email: None,
            customer_name: None,
            currency,
            confirm: true,
            statement_descriptor_suffix: None,
            statement_descriptor: None,
            // La homologación mandó ventas (`PaymentCardSaleTransaction`), o sea captura
            // automática.
            capture_method: Some(common_enums::CaptureMethod::Automatic),
            router_return_url: None,
            webhook_url: None,
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
            metadata,
            authentication_data: None,
            request_extended_authorization: None,
            split_payments: None,
            minor_amount: MinorUnit::new(minor_amount),
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
        }
    }

    /// Serializa el request de Authorize por el mismo camino que `get_request_body`.
    fn authorize_payload(router_data: &PaymentsAuthorizeRouterData) -> serde_json::Value {
        let amount = StringMajorUnitForConnector
            .convert(router_data.request.minor_amount, router_data.request.currency)
            .unwrap();
        let wrapped = FiservemeaRouterData::from((amount, router_data));
        let request = FiservemeaPaymentsRequest::try_from(&wrapped).unwrap();
        serde_json::to_value(&request).unwrap()
    }

    /// Venta con tarjeta tal como la armaría el conector, con los datos del checklist.
    fn cert_card_sale_payload(
        store_id: &str,
        reference_id: &str,
        card_number: &str,
        minor_amount: i64,
        currency: common_enums::Currency,
        metadata: Option<serde_json::Value>,
    ) -> serde_json::Value {
        let router_data: PaymentsAuthorizeRouterData = cert_router_data(
            store_id,
            reference_id,
            cert_authorize_data(
                cert_card_data(card_number),
                minor_amount,
                currency,
                metadata,
            ),
        );
        authorize_payload(&router_data)
    }

    /// evidencia.jsonl línea 0 — "AR SALE 1 pago", HTTP 200 APPROVED.
    #[test]
    fn cert_case_sale_one_payment_matches_the_accepted_payload() {
        let expected = serde_json::json!({
            "requestType": "PaymentCardSaleTransaction",
            "merchantTransactionId": "PX-1786053416-01-sale",
            "storeId": "5926072901",
            "transactionAmount": { "total": "1000.00", "currency": "ARS" },
            "order": { "orderId": "PX-1786053416-01-sale" },
            "paymentMethod": {
                "paymentCard": {
                    "number": "5165850000000008",
                    "expiryDate": { "month": "12", "year": "29" },
                    "securityCode": "123"
                }
            }
        });
        let got = cert_card_sale_payload(
            CERT_STORE_AR,
            "PX-1786053416-01-sale",
            CERT_CARD,
            100_000,
            common_enums::Currency::ARS,
            None,
        );
        assert_eq!(got, expected);
    }

    /// evidencia.jsonl línea 1 — "AR SALE 1 pago USD", HTTP 200 APPROVED.
    #[test]
    fn cert_case_sale_usd_matches_the_accepted_payload() {
        let expected = serde_json::json!({
            "requestType": "PaymentCardSaleTransaction",
            "merchantTransactionId": "PX-1786053417-02-saleusd",
            "storeId": "5926072901",
            "transactionAmount": { "total": "1000.00", "currency": "USD" },
            "order": { "orderId": "PX-1786053417-02-saleusd" },
            "paymentMethod": {
                "paymentCard": {
                    "number": "5165850000000008",
                    "expiryDate": { "month": "12", "year": "29" },
                    "securityCode": "123"
                }
            }
        });
        let got = cert_card_sale_payload(
            CERT_STORE_AR,
            "PX-1786053417-02-saleusd",
            CERT_CARD,
            100_000,
            common_enums::Currency::USD,
            None,
        );
        assert_eq!(got, expected);
    }

    /// evidencia.jsonl línea 3 — "AR SALE cuotas (6)", HTTP 200 APPROVED.
    /// `numberOfInstallments` viaja como NÚMERO, no como string.
    #[test]
    fn cert_case_sale_installments_matches_the_accepted_payload() {
        let expected = serde_json::json!({
            "requestType": "PaymentCardSaleTransaction",
            "merchantTransactionId": "PX-1786053420-04-cuotas",
            "storeId": "5926072901",
            "transactionAmount": { "total": "1000.00", "currency": "ARS" },
            "order": {
                "orderId": "PX-1786053420-04-cuotas",
                "installmentOptions": { "numberOfInstallments": 6 }
            },
            "paymentMethod": {
                "paymentCard": {
                    "number": "5165850000000008",
                    "expiryDate": { "month": "12", "year": "29" },
                    "securityCode": "123"
                }
            }
        });
        let got = cert_card_sale_payload(
            CERT_STORE_AR,
            "PX-1786053420-04-cuotas",
            CERT_CARD,
            100_000,
            common_enums::Currency::ARS,
            Some(serde_json::json!({ "installments": 6 })),
        );
        assert_eq!(got, expected);
        assert!(got["order"]["installmentOptions"]["numberOfInstallments"].is_number());
    }

    /// evidencia.jsonl línea 4 — "AR DYNAMIC MERCHANT NAME", HTTP 200 APPROVED.
    /// `softDescriptor` va DENTRO de `order`, y el campo es `dynamicMerchantName`.
    #[test]
    fn cert_case_dynamic_merchant_name_matches_the_accepted_payload() {
        let expected = serde_json::json!({
            "requestType": "PaymentCardSaleTransaction",
            "merchantTransactionId": "PX-1786053422-05-dmn",
            "storeId": "5926072901",
            "transactionAmount": { "total": "1000.00", "currency": "ARS" },
            "order": {
                "orderId": "PX-1786053422-05-dmn",
                "softDescriptor": { "dynamicMerchantName": "PXSOL*Reservas" }
            },
            "paymentMethod": {
                "paymentCard": {
                    "number": "5165850000000008",
                    "expiryDate": { "month": "12", "year": "29" },
                    "securityCode": "123"
                }
            }
        });
        let got = cert_card_sale_payload(
            CERT_STORE_AR,
            "PX-1786053422-05-dmn",
            CERT_CARD,
            100_000,
            common_enums::Currency::ARS,
            Some(serde_json::json!({ "dynamic_merchant_name": "PXSOL*Reservas" })),
        );
        assert_eq!(got, expected);
        // El gateway rechaza un `softDescriptor` a nivel raíz con INVALID_INPUT.
        assert!(got.get("softDescriptor").is_none());
    }

    /// evidencia.jsonl línea 17 — "AR SALE TOKEN MTRG 1 pago", HTTP 200 APPROVED.
    /// El flujo MTRG integrado (OnTheGo) manda el PAN real con CVV: es Fiserv quien resuelve
    /// el Network Token. No lleva criptograma ni nada distinto de una venta normal.
    #[test]
    fn cert_case_token_mtrg_one_payment_matches_the_accepted_payload() {
        let expected = serde_json::json!({
            "requestType": "PaymentCardSaleTransaction",
            "merchantTransactionId": "PX-1786053444-12-mtrg",
            "storeId": "5926072901",
            "transactionAmount": { "total": "1000.00", "currency": "ARS" },
            "order": { "orderId": "PX-1786053444-12-mtrg" },
            "paymentMethod": {
                "paymentCard": {
                    "number": "4622943127032366",
                    "expiryDate": { "month": "12", "year": "29" },
                    "securityCode": "123"
                }
            }
        });
        let got = cert_card_sale_payload(
            CERT_STORE_AR,
            "PX-1786053444-12-mtrg",
            CERT_CARD_MTRG,
            100_000,
            common_enums::Currency::ARS,
            None,
        );
        assert_eq!(got, expected);
    }

    /// evidencia.jsonl línea 15 — "AR SALE cuotas TOKEN GW", HTTP 200 APPROVED.
    #[test]
    fn cert_case_token_gw_installments_matches_the_accepted_payload() {
        let expected = serde_json::json!({
            "requestType": "PaymentTokenSaleTransaction",
            "merchantTransactionId": "PX-1786053439-10-tokgw",
            "storeId": "5926072902",
            "transactionAmount": { "total": "1000.00", "currency": "ARS" },
            "order": {
                "orderId": "PX-1786053439-10-tokgw",
                "installmentOptions": { "numberOfInstallments": 6 }
            },
            "paymentMethod": {
                "paymentToken": {
                    "value": "CF49734F-986F-4FD1-8040-9A16657E9B3E",
                    "tokenOriginStoreId": "5926072902"
                }
            }
        });
        let mut router_data: PaymentsAuthorizeRouterData = cert_router_data(
            CERT_STORE_TOKEN_GW,
            "PX-1786053439-10-tokgw",
            cert_authorize_data(
                cert_card_data(CERT_CARD),
                100_000,
                common_enums::Currency::ARS,
                Some(serde_json::json!({ "installments": 6 })),
            ),
        );
        // Hyperswitch corre primero el flujo PaymentMethodToken y devuelve el token acá.
        router_data.payment_method_token = Some(PaymentMethodToken::Token(Secret::new(
            "CF49734F-986F-4FD1-8040-9A16657E9B3E".to_string(),
        )));
        assert_eq!(authorize_payload(&router_data), expected);
    }

    /// evidencia.jsonl línea 14 — "AR CREATE TOKEN GW" (`POST /payment-tokens`), HTTP 200.
    /// `paymentCard` va a nivel raíz, NO bajo `paymentMethod`.
    #[test]
    fn cert_case_create_token_gw_matches_the_accepted_payload() {
        let expected = serde_json::json!({
            "requestType": "PaymentCardPaymentTokenizationRequest",
            "storeId": "5926072902",
            "paymentCard": {
                "number": "5165850000000008",
                "expiryDate": { "month": "12", "year": "29" },
                "securityCode": "123"
            },
            "createToken": { "reusable": true, "declineDuplicates": false }
        });
        let router_data: TokenizationRouterData = cert_router_data(
            CERT_STORE_TOKEN_GW,
            "PX-1786053439-10-tokgw",
            PaymentMethodTokenizationData {
                payment_method_data: cert_card_data(CERT_CARD),
                browser_info: None,
                currency: common_enums::Currency::ARS,
                amount: Some(100_000),
                split_payments: None,
                customer_acceptance: None,
                setup_future_usage: None,
                setup_mandate_details: None,
                mandate_id: None,
            },
        );
        let request = FiservemeaCreateTokenRequest::try_from(&router_data).unwrap();
        assert_eq!(serde_json::to_value(&request).unwrap(), expected);
    }

    /// evidencia.jsonl línea 2 — "AR SALE ZEROAUTH", HTTP 200 APPROVED.
    /// El importe viaja como `"0"` (string, sin decimales), tal cual lo aceptó el gateway.
    #[test]
    fn cert_case_zeroauth_matches_the_accepted_payload() {
        let expected = serde_json::json!({
            "requestType": "PaymentCardSaleTransaction",
            "merchantTransactionId": "PX-1786053418-03-zeroauth",
            "storeId": "5926072901",
            "transactionAmount": { "total": "0", "currency": "ARS" },
            "order": { "orderId": "PX-1786053418-03-zeroauth" },
            "paymentMethod": {
                "paymentCard": {
                    "number": "5165850000000008",
                    "expiryDate": { "month": "12", "year": "29" },
                    "securityCode": "123"
                }
            }
        });
        let router_data: RouterData<SetupMandate, SetupMandateRequestData, PaymentsResponseData> =
            cert_router_data(
                CERT_STORE_AR,
                "PX-1786053418-03-zeroauth",
                SetupMandateRequestData {
                    currency: common_enums::Currency::ARS,
                    payment_method_data: cert_card_data(CERT_CARD),
                    amount: Some(0),
                    confirm: true,
                    statement_descriptor_suffix: None,
                    customer_acceptance: None,
                    mandate_id: None,
                    setup_future_usage: None,
                    off_session: None,
                    setup_mandate_details: None,
                    router_return_url: None,
                    webhook_url: None,
                    browser_info: None,
                    email: None,
                    customer_name: None,
                    return_url: None,
                    payment_method_type: None,
                    request_incremental_authorization: false,
                    metadata: None,
                    complete_authorize_url: None,
                    capture_method: None,
                    enrolled_for_3ds: false,
                    related_transaction_id: None,
                    minor_amount: Some(MinorUnit::new(0)),
                    shipping_cost: None,
                    connector_testing_data: None,
                    customer_id: None,
                    enable_partial_authorization: None,
                    payment_channel: None,
                },
            );
        let request = FiservemeaPaymentsRequest::try_from(&router_data).unwrap();
        assert_eq!(serde_json::to_value(&request).unwrap(), expected);
    }

    /// evidencia.jsonl línea 9 — "AR VOID (anulación)", HTTP 200 APPROVED.
    /// El cuerpo lleva SÓLO `requestType` y `storeId`: ni importe ni orden.
    #[test]
    fn cert_case_void_matches_the_accepted_payload() {
        let expected = serde_json::json!({
            "requestType": "VoidTransaction",
            "storeId": "5926072901"
        });
        let router_data: PaymentsCancelRouterData = cert_router_data(
            CERT_STORE_AR,
            "PX-1786053424-07-void",
            PaymentsCancelData {
                connector_transaction_id: "84667286296".to_string(),
                currency: Some(common_enums::Currency::ARS),
                amount: Some(100_000),
                minor_amount: Some(MinorUnit::new(100_000)),
                // La venta original salió como `PaymentCardSaleTransaction`.
                capture_method: Some(common_enums::CaptureMethod::Automatic),
                ..Default::default()
            },
        );
        let request = FiservemeaVoidRequest::try_from(&router_data).unwrap();
        assert_eq!(serde_json::to_value(&request).unwrap(), expected);
    }

    fn cert_refund_payload(reference_id: &str, minor_refund_amount: i64) -> serde_json::Value {
        let router_data: RefundsRouterData<Execute> = cert_router_data(
            CERT_STORE_AR,
            reference_id,
            RefundsData {
                refund_id: "ref_1".to_string(),
                connector_transaction_id: "84667286298".to_string(),
                connector_refund_id: None,
                currency: common_enums::Currency::ARS,
                payment_amount: 100_000,
                reason: None,
                webhook_url: None,
                refund_amount: minor_refund_amount,
                connector_metadata: None,
                refund_connector_metadata: None,
                browser_info: None,
                split_refunds: None,
                minor_payment_amount: MinorUnit::new(100_000),
                minor_refund_amount: MinorUnit::new(minor_refund_amount),
                integrity_object: None,
                refund_status: common_enums::RefundStatus::Pending,
                merchant_account_id: None,
                merchant_config_currency: None,
                capture_method: Some(common_enums::CaptureMethod::Automatic),
                additional_payment_method_data: None,
            },
        );
        let amount = StringMajorUnitForConnector
            .convert(
                router_data.request.minor_refund_amount,
                router_data.request.currency,
            )
            .unwrap();
        let wrapped = FiservemeaRouterData::from((amount, &router_data));
        let request = FiservemeaRefundRequest::try_from(&wrapped).unwrap();
        serde_json::to_value(&request).unwrap()
    }

    /// evidencia.jsonl línea 11 — "AR RETURN total", HTTP 200 APPROVED.
    #[test]
    fn cert_case_return_total_matches_the_accepted_payload() {
        let expected = serde_json::json!({
            "requestType": "ReturnTransaction",
            "storeId": "5926072901",
            "transactionAmount": { "total": "1000.00", "currency": "ARS" }
        });
        assert_eq!(
            cert_refund_payload("PX-1786053425-08-rettot", 100_000),
            expected
        );
    }

    /// evidencia.jsonl línea 13 — "AR RETURN parcial", HTTP 200 APPROVED.
    #[test]
    fn cert_case_return_partial_matches_the_accepted_payload() {
        let expected = serde_json::json!({
            "requestType": "ReturnTransaction",
            "storeId": "5926072901",
            "transactionAmount": { "total": "500.00", "currency": "ARS" }
        });
        assert_eq!(
            cert_refund_payload("PX-1786053426-09-retpar", 50_000),
            expected
        );
    }

    /// La captura NO está entre los 31 casos de la homologación: el checklist es todo ventas.
    /// Este test sólo fija la forma del cuerpo que el conector emite (`PostAuthTransaction` +
    /// `storeId` + `transactionAmount`), que es la que documenta la guía. NO está verificada
    /// contra el gateway.
    #[test]
    fn capture_payload_shape_is_post_auth_with_amount_not_verified_against_cert() {
        let router_data: PaymentsCaptureRouterData = cert_router_data(
            CERT_STORE_AR,
            "PX-capture",
            PaymentsCaptureData {
                amount_to_capture: 100_000,
                currency: common_enums::Currency::ARS,
                connector_transaction_id: "84667286296".to_string(),
                payment_amount: 100_000,
                minor_payment_amount: MinorUnit::new(100_000),
                minor_amount_to_capture: MinorUnit::new(100_000),
                capture_method: Some(common_enums::CaptureMethod::Manual),
                ..Default::default()
            },
        );
        let amount = StringMajorUnitForConnector
            .convert(
                router_data.request.minor_amount_to_capture,
                router_data.request.currency,
            )
            .unwrap();
        let wrapped = FiservemeaRouterData::from((amount, &router_data));
        let request = FiservemeaCaptureRequest::try_from(&wrapped).unwrap();
        assert_eq!(
            serde_json::to_value(&request).unwrap(),
            serde_json::json!({
                "requestType": "PostAuthTransaction",
                "storeId": "5926072901",
                "transactionAmount": { "total": "1000.00", "currency": "ARS" }
            })
        );
    }

    /// `merchantTransactionId` sale de `merchant_order_reference_id` cuando el comercio lo
    /// manda, y de la referencia del conector cuando no. `order.orderId` es SIEMPRE la
    /// referencia del conector: es con la que después se consulta `GET /orders/{orderId}`.
    /// En la homologación los dos coincidían, así que este test es el que separa los caminos.
    #[test]
    fn merchant_transaction_id_and_order_id_come_from_different_sources() {
        let mut request_data = cert_authorize_data(
            cert_card_data(CERT_CARD),
            100_000,
            common_enums::Currency::ARS,
            None,
        );
        request_data.merchant_order_reference_id = Some("factura-del-comercio-123".to_string());
        let router_data: PaymentsAuthorizeRouterData =
            cert_router_data(CERT_STORE_AR, "PX-ref-del-conector", request_data);
        let got = authorize_payload(&router_data);
        assert_eq!(got["merchantTransactionId"], "factura-del-comercio-123");
        assert_eq!(got["order"]["orderId"], "PX-ref-del-conector");
    }

    /// Referencia de 66 caracteres: es lo que produce un `payment_id` del comercio del largo
    /// máximo (64) más el sufijo `_1` del intento.
    const REFERENCIA_LARGA: &str =
        "PXSOL-RESERVA-2026-08-12-HOTEL-1234-HABITACION-501-CONFIRMADA-XY_1";

    /// El gateway rechaza con 400 INVALID_INPUT un `merchantTransactionId` de 41 caracteres
    /// (verificado en cert: 40 pasa, 41 falla). Los dos caminos que emiten el campo tienen que
    /// recortarlo, incluido el Zero Auth — que antes lo mandaba entero y tiraba abajo la
    /// verificación de tarjeta de cualquier comercio con un `payment_id` largo.
    #[test]
    fn merchant_transaction_id_is_capped_at_40_in_both_flows() {
        assert_eq!(REFERENCIA_LARGA.chars().count(), 66);

        let authorize: PaymentsAuthorizeRouterData = cert_router_data(
            CERT_STORE_AR,
            REFERENCIA_LARGA,
            cert_authorize_data(
                cert_card_data(CERT_CARD),
                100_000,
                common_enums::Currency::ARS,
                None,
            ),
        );
        let got = authorize_payload(&authorize);
        assert_eq!(
            got["merchantTransactionId"]
                .as_str()
                .unwrap()
                .chars()
                .count(),
            FISERVEMEA_MERCHANT_TRANSACTION_ID_MAX_LEN
        );

        let zero_auth: RouterData<SetupMandate, SetupMandateRequestData, PaymentsResponseData> =
            cert_router_data(
                CERT_STORE_AR,
                REFERENCIA_LARGA,
                SetupMandateRequestData {
                    currency: common_enums::Currency::ARS,
                    payment_method_data: cert_card_data(CERT_CARD),
                    amount: Some(0),
                    confirm: true,
                    statement_descriptor_suffix: None,
                    customer_acceptance: None,
                    mandate_id: None,
                    setup_future_usage: None,
                    off_session: None,
                    setup_mandate_details: None,
                    router_return_url: None,
                    webhook_url: None,
                    browser_info: None,
                    email: None,
                    customer_name: None,
                    return_url: None,
                    payment_method_type: None,
                    request_incremental_authorization: false,
                    metadata: None,
                    complete_authorize_url: None,
                    capture_method: None,
                    enrolled_for_3ds: false,
                    related_transaction_id: None,
                    minor_amount: Some(MinorUnit::new(0)),
                    shipping_cost: None,
                    connector_testing_data: None,
                    customer_id: None,
                    enable_partial_authorization: None,
                    payment_channel: None,
                },
            );
        let request = FiservemeaPaymentsRequest::try_from(&zero_auth).unwrap();
        let got = serde_json::to_value(&request).unwrap();
        assert_eq!(
            got["merchantTransactionId"]
                .as_str()
                .unwrap()
                .chars()
                .count(),
            FISERVEMEA_MERCHANT_TRANSACTION_ID_MAX_LEN
        );
        // El `orderId` NO se recorta: es la clave con la que después se consulta
        // `GET /orders/{orderId}`, así que tiene que quedar igual a la referencia.
        assert_eq!(got["order"]["orderId"], REFERENCIA_LARGA);
    }

    /// 1 cuota no emite `installmentOptions`: el harness tampoco lo mandó en los casos de
    /// 1 pago que el gateway aprobó (evidencia.jsonl líneas 0, 82, 91).
    #[test]
    fn a_single_installment_does_not_emit_installment_options() {
        let got = cert_card_sale_payload(
            CERT_STORE_AR,
            "PX-1-cuota",
            CERT_CARD,
            100_000,
            common_enums::Currency::ARS,
            Some(serde_json::json!({ "installments": 1 })),
        );
        assert!(got["order"].get("installmentOptions").is_none());
    }
    #[test]
    fn psync_of_a_voided_sale_is_not_reported_as_charged() {
        // Respuesta REAL de certificación: se consultó una venta que había sido anulada. El
        // gateway devuelve el tipo y el estado de la VENTA (SALE / APPROVED) pero con
        // `transactionState: VOIDED`. Mirando sólo el tipo, el pago se reportaba como cobrado:
        // plata que el comercio cree haber cobrado y no cobró.
        let raw = serde_json::json!({
            "type": "transactionResponse",
            "ipgTransactionId": "84668213533",
            "transactionType": "SALE",
            "transactionStatus": "APPROVED",
            "transactionResult": "APPROVED",
            "transactionState": "VOIDED"
        });
        let response: FiservemeaPaymentsResponse = serde_json::from_value(raw).unwrap();
        assert_eq!(
            map_status(
                response.transaction_status,
                response.transaction_result,
                response.transaction_type,
                response.transaction_state.as_deref(),
            ),
            common_enums::AttemptStatus::Voided
        );
    }

    #[test]
    fn transaction_state_only_overrides_when_it_is_terminal_and_known() {
        // CAPTURED y WAITING no agregan nada sobre el tipo, y un valor que no conocemos no debe
        // pisar la clasificación que sí conocemos.
        assert_eq!(
            map_transaction_state(Some("VOIDED")),
            Some(common_enums::AttemptStatus::Voided)
        );
        assert_eq!(
            map_transaction_state(Some("DECLINED")),
            Some(common_enums::AttemptStatus::Failure)
        );
        assert_eq!(map_transaction_state(Some("CAPTURED")), None);
        assert_eq!(map_transaction_state(Some("WAITING")), None);
        assert_eq!(map_transaction_state(Some("ESTADO_NUEVO")), None);
        assert_eq!(map_transaction_state(None), None);
        // Y una venta capturada sigue siendo un cobro.
        assert_eq!(
            map_approved_status(Some(&FiservemeaTransactionType::Sale), Some("CAPTURED")),
            common_enums::AttemptStatus::Charged
        );
    }

}
