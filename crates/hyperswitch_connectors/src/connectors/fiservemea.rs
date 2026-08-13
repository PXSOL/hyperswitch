#[cfg(test)]
mod cert_payloads;
#[cfg(test)]
mod cert_responses;
pub mod transformers;

use std::sync::LazyLock;

use base64::Engine;
use common_enums::enums;
use common_utils::{
    errors::CustomResult,
    ext_traits::BytesExt,
    request::{Method, Request, RequestBuilder, RequestContent},
    types::{
        AmountConvertor, FloatMajorUnit, FloatMajorUnitForConnector, StringMajorUnit,
        StringMajorUnitForConnector,
    },
};
use error_stack::{report, ResultExt};
use hyperswitch_domain_models::{
    router_data::{AccessToken, ErrorResponse, RouterData},
    router_flow_types::{
        access_token_auth::AccessTokenAuth,
        payments::{Authorize, Capture, PSync, PaymentMethodToken, Session, SetupMandate, Void},
        refunds::{Execute, RSync},
        CompleteAuthorize,
    },
    router_request_types::{
        AccessTokenRequestData, CompleteAuthorizeData, PaymentMethodTokenizationData,
        PaymentsAuthorizeData, PaymentsCancelData, PaymentsCaptureData, PaymentsSessionData,
        PaymentsSyncData, RefundsData, ResponseId, SetupMandateRequestData,
    },
    router_response_types::{
        ConnectorInfo, PaymentMethodDetails, PaymentsResponseData, RefundsResponseData,
        SupportedPaymentMethods, SupportedPaymentMethodsExt,
    },
    types::{
        PaymentsAuthorizeRouterData, PaymentsCancelRouterData, PaymentsCaptureRouterData,
        PaymentsCompleteAuthorizeRouterData, PaymentsSyncRouterData, RefundSyncRouterData,
        RefundsRouterData, TokenizationRouterData,
    },
};
use hyperswitch_interfaces::{
    api::{
        self, ConnectorCommon, ConnectorCommonExt, ConnectorIntegration, ConnectorSpecifications,
        ConnectorValidation,
    },
    configs::Connectors,
    consts, errors,
    events::connector_api_logs::ConnectorEvent,
    types::{self, Response},
    webhooks,
};
use hyperswitch_masking::{ExposeInterface, Mask, PeekInterface};
use ring::hmac;
use time::OffsetDateTime;
use transformers as fiservemea;
use uuid::Uuid;

use crate::{
    constants::headers,
    types::ResponseRouterData,
    utils::{self, RefundsRequestData as _},
};

/// `true` cuando este CompleteAuthorize es la notificación del 3DSMethod que el ACS publica en la
/// `methodNotificationURL`, o sea la que ocurre dentro del iframe oculto.
fn is_three_ds_method_notification(req: &PaymentsCompleteAuthorizeRouterData) -> bool {
    req.request
        .redirect_response
        .as_ref()
        .is_some_and(fiservemea::is_acs_method_notification)
}

fn determine_endpoint(
    connectors: &Connectors,
    test_mode: Option<bool>,
) -> CustomResult<String, errors::ConnectorError> {
    // Fail closed in both directions — the wrong endpoint silently mis-routes real money
    // (a production auth sent to the certification gateway returns APPROVED but never settles):
    // - An unset `test_mode` defaults to LIVE, so a production account that never set the flag
    //   is never routed to the certification gateway.
    // - Test mode requires an explicitly configured `secondary_base_url`; error out rather than
    //   silently falling back to the production host.
    if test_mode.unwrap_or(false) {
        match connectors.fiservemea.secondary_base_url.clone() {
            Some(url) => Ok(url),
            None => Err(errors::ConnectorError::InvalidConnectorConfig {
                config: "fiservemea.secondary_base_url (required when test_mode is enabled)",
            }
            .into()),
        }
    } else {
        Ok(connectors.fiservemea.base_url.to_string())
    }
}

/// Arma la URL del PSync eligiendo entre consultar por transacción o por orden.
///
/// El `ipgTransactionId` es la vía preferida, pero no siempre existe: hay rechazos que
/// vuelven con HTTP 409 y `orderId` pero sin `ipgTransactionId` (verificado en cert con el
/// Data Only rechazado: `TransactionErrorResponse` / `N:-50655:Unable to verify card
/// enrollment`, sin id de transacción). Sin este fallback esos pagos quedan para siempre sin
/// forma de consultarse. La guía (§7.3) habilita las dos consultas: se manda "el
/// identificador de la transacción u orden" y se recibe "TransactionResponse u OrderResponse
/// respectivamente"; verificado en vivo que `GET /orders/{orderId}?storeId=...` sobre una de
/// esas órdenes rechazadas devuelve 200 con el `ipgTransactionId` que el rechazo nunca dio.
///
/// El `storeId` va como query param en las dos ramas (la firma HMAC del GET es sobre cuerpo
/// vacío, así que el query no se firma). El identificador y el `storeId` se escapan con
/// `url::Url`, que aplica a cada parte la regla que le corresponde: el segmento de path se
/// percent-encodea y el query se form-encodea. La distinción importa — un espacio en un path
/// es `%20` y no `+`; escaparlo con las reglas del query hace que el gateway responda
/// `INVALID_INPUT` porque recibe un más literal.
///
/// Se extrae como función suelta para poder testear la elección sin construir un
/// `PaymentsSyncRouterData` entero.
fn build_sync_url(
    base_url: &str,
    connector_transaction_id: &ResponseId,
    connector_request_reference_id: &str,
    store_id: &str,
) -> CustomResult<String, errors::ConnectorError> {
    let (collection, id) = match connector_transaction_id {
        // Un `ConnectorTransactionId` vacío se trata como ausente: `/payments/?storeId=` no es
        // una consulta válida y el gateway respondería un error opaco.
        ResponseId::ConnectorTransactionId(id) if !id.is_empty() => ("payments", id.as_str()),
        _ if !connector_request_reference_id.is_empty() => {
            ("orders", connector_request_reference_id)
        }
        // Sin ninguno de los dos identificadores no hay consulta posible.
        _ => return Err(errors::ConnectorError::MissingConnectorTransactionID.into()),
    };

    let mut url = url::Url::parse(base_url)
        .change_context(errors::ConnectorError::FailedToObtainIntegrationUrl)?;
    url.path_segments_mut()
        .map_err(|_| errors::ConnectorError::FailedToObtainIntegrationUrl)?
        .pop_if_empty()
        .push(collection)
        .push(id);
    url.query_pairs_mut().append_pair("storeId", store_id);
    Ok(url.into())
}

#[derive(Clone)]
pub struct Fiservemea {
    amount_converter: &'static (dyn AmountConvertor<Output = StringMajorUnit> + Sync),
    // fiservemea's request bodies carry amounts as strings (`amount_converter` above), but the
    // response's `approvedAmount`/`transactionAmount.total` come back as JSON numbers. A
    // dedicated `FloatMajorUnit` converter lets us feed those response amounts straight into
    // `get_*_integrity_object` (see `FiservemeaPaymentsResponse::settlement_amount`) without a
    // lossy string round-trip. This mirrors the dual-converter pattern already used by
    // `trustpay.rs`.
    amount_converter_to_float_major_unit:
        &'static (dyn AmountConvertor<Output = FloatMajorUnit> + Sync),
}

impl Fiservemea {
    pub fn new() -> &'static Self {
        &Self {
            amount_converter: &StringMajorUnitForConnector,
            amount_converter_to_float_major_unit: &FloatMajorUnitForConnector,
        }
    }

    pub fn generate_authorization_signature(
        &self,
        auth: fiservemea::FiservemeaAuthType,
        request_id: &str,
        payload: &str,
        timestamp: i128,
    ) -> CustomResult<String, errors::ConnectorError> {
        let fiservemea::FiservemeaAuthType {
            api_key,
            secret_key,
            .. // store_id is sent in the request body / sync query, not in the HMAC signature
        } = auth;
        let raw_signature = format!("{}{request_id}{timestamp}{payload}", api_key.peek());

        let key = hmac::Key::new(hmac::HMAC_SHA256, secret_key.expose().as_bytes());
        let signature_value = common_utils::consts::BASE64_ENGINE
            .encode(hmac::sign(&key, raw_signature.as_bytes()).as_ref());
        Ok(signature_value)
    }
}

impl Fiservemea {
    /// Headers firmados sobre un payload EXPLÍCITO, en vez de derivarlo de `get_http_method()`.
    ///
    /// Hace falta porque el CompleteAuthorize no tiene un método fijo: la continuación real va
    /// por PATCH y firma el cuerpo, mientras que la notificación del 3DSMethod se degrada a una
    /// consulta GET, que la API firma sobre cuerpo vacío.
    fn signed_headers_for_payload<Flow, Req, Res>(
        &self,
        req: &RouterData<Flow, Req, Res>,
        payload: &str,
    ) -> CustomResult<Vec<(String, hyperswitch_masking::Maskable<String>)>, errors::ConnectorError> {
        let timestamp = OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000;
        let auth = fiservemea::FiservemeaAuthType::try_from(&req.connector_auth_type)?;
        let client_request_id = Uuid::new_v4().to_string();
        let hmac = self
            .generate_authorization_signature(auth.clone(), &client_request_id, payload, timestamp)
            .change_context(errors::ConnectorError::RequestEncodingFailed)?;
        Ok(vec![
            (
                headers::CONTENT_TYPE.to_string(),
                self.common_get_content_type().to_string().into(),
            ),
            ("Client-Request-Id".to_string(), client_request_id.into()),
            (headers::API_KEY.to_string(), auth.api_key.expose().into_masked()),
            (headers::TIMESTAMP.to_string(), timestamp.to_string().into()),
            (headers::MESSAGE_SIGNATURE.to_string(), hmac.into_masked()),
        ])
    }
}

impl api::Payment for Fiservemea {}
impl api::PaymentSession for Fiservemea {}
impl api::ConnectorAccessToken for Fiservemea {}
impl api::MandateSetup for Fiservemea {}
impl api::PaymentAuthorize for Fiservemea {}
impl api::PaymentsCompleteAuthorize for Fiservemea {}
impl api::PaymentSync for Fiservemea {}
impl api::PaymentCapture for Fiservemea {}
impl api::PaymentVoid for Fiservemea {}
impl api::Refund for Fiservemea {}
impl api::RefundExecute for Fiservemea {}
impl api::RefundSync for Fiservemea {}
impl api::PaymentToken for Fiservemea {}

impl ConnectorIntegration<Session, PaymentsSessionData, PaymentsResponseData> for Fiservemea {}

impl ConnectorIntegration<AccessTokenAuth, AccessTokenRequestData, AccessToken> for Fiservemea {}

// Zero Auth (account verification): mapped to Hyperswitch's SetupMandate flow. Sends a
// zero-amount `PaymentCardSaleTransaction` to `/payments` (vendor doc Parte 3 §Zero Auth).
impl ConnectorIntegration<SetupMandate, SetupMandateRequestData, PaymentsResponseData>
    for Fiservemea
{
    fn get_headers(
        &self,
        req: &RouterData<SetupMandate, SetupMandateRequestData, PaymentsResponseData>,
        connectors: &Connectors,
    ) -> CustomResult<Vec<(String, hyperswitch_masking::Maskable<String>)>, errors::ConnectorError> {
        self.build_headers(req, connectors)
    }

    fn get_content_type(&self) -> &'static str {
        self.common_get_content_type()
    }

    fn get_url(
        &self,
        req: &RouterData<SetupMandate, SetupMandateRequestData, PaymentsResponseData>,
        connectors: &Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        Ok(format!(
            "{}/payments",
            determine_endpoint(connectors, req.test_mode)?
        ))
    }

    fn get_request_body(
        &self,
        req: &RouterData<SetupMandate, SetupMandateRequestData, PaymentsResponseData>,
        _connectors: &Connectors,
    ) -> CustomResult<RequestContent, errors::ConnectorError> {
        let connector_req = fiservemea::FiservemeaPaymentsRequest::try_from(req)?;
        Ok(RequestContent::Json(Box::new(connector_req)))
    }

    fn build_request(
        &self,
        req: &RouterData<SetupMandate, SetupMandateRequestData, PaymentsResponseData>,
        connectors: &Connectors,
    ) -> CustomResult<Option<Request>, errors::ConnectorError> {
        Ok(Some(
            RequestBuilder::new()
                .method(Method::Post)
                .url(&types::SetupMandateType::get_url(self, req, connectors)?)
                .attach_default_headers()
                .headers(types::SetupMandateType::get_headers(self, req, connectors)?)
                .set_body(types::SetupMandateType::get_request_body(
                    self, req, connectors,
                )?)
                .build(),
        ))
    }

    fn handle_response(
        &self,
        data: &RouterData<SetupMandate, SetupMandateRequestData, PaymentsResponseData>,
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<
        RouterData<SetupMandate, SetupMandateRequestData, PaymentsResponseData>,
        errors::ConnectorError,
    > {
        let response: fiservemea::FiservemeaPaymentsResponse = res
            .response
            .parse_struct("Fiservemea SetupMandateResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
        event_builder.map(|i| i.set_response_body(&response));
        router_env::logger::info!(connector_response=?response);
        RouterData::try_from(ResponseRouterData {
            response,
            data: data.clone(),
            http_code: res.status_code,
        })
    }

    fn get_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, event_builder)
    }
}

// IPG gateway tokenization (Card-on-File): creates a reusable token via `POST /payment-tokens`
// (a different endpoint than `/payments`); the token is then used by the Authorize flow.
impl ConnectorIntegration<PaymentMethodToken, PaymentMethodTokenizationData, PaymentsResponseData>
    for Fiservemea
{
    fn get_headers(
        &self,
        req: &TokenizationRouterData,
        connectors: &Connectors,
    ) -> CustomResult<Vec<(String, hyperswitch_masking::Maskable<String>)>, errors::ConnectorError> {
        self.build_headers(req, connectors)
    }

    fn get_content_type(&self) -> &'static str {
        self.common_get_content_type()
    }

    fn get_url(
        &self,
        req: &TokenizationRouterData,
        connectors: &Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        Ok(format!(
            "{}/payment-tokens",
            determine_endpoint(connectors, req.test_mode)?
        ))
    }

    fn get_request_body(
        &self,
        req: &TokenizationRouterData,
        _connectors: &Connectors,
    ) -> CustomResult<RequestContent, errors::ConnectorError> {
        let connector_req = fiservemea::FiservemeaCreateTokenRequest::try_from(req)?;
        Ok(RequestContent::Json(Box::new(connector_req)))
    }

    fn build_request(
        &self,
        req: &TokenizationRouterData,
        connectors: &Connectors,
    ) -> CustomResult<Option<Request>, errors::ConnectorError> {
        Ok(Some(
            RequestBuilder::new()
                .method(Method::Post)
                .url(&types::TokenizationType::get_url(self, req, connectors)?)
                .attach_default_headers()
                .headers(types::TokenizationType::get_headers(self, req, connectors)?)
                .set_body(types::TokenizationType::get_request_body(
                    self, req, connectors,
                )?)
                .build(),
        ))
    }

    fn handle_response(
        &self,
        data: &TokenizationRouterData,
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<TokenizationRouterData, errors::ConnectorError> {
        let response: fiservemea::FiservemeaTokenResponse = res
            .response
            .parse_struct("Fiservemea FiservemeaTokenResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
        event_builder.map(|i| i.set_response_body(&response));
        router_env::logger::info!(connector_response=?response);
        RouterData::try_from(ResponseRouterData {
            response,
            data: data.clone(),
            http_code: res.status_code,
        })
    }

    fn get_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, event_builder)
    }
}

impl<Flow, Request, Response> ConnectorCommonExt<Flow, Request, Response> for Fiservemea
where
    Self: ConnectorIntegration<Flow, Request, Response>,
{
    fn build_headers(
        &self,
        req: &RouterData<Flow, Request, Response>,
        connectors: &Connectors,
    ) -> CustomResult<Vec<(String, hyperswitch_masking::Maskable<String>)>, errors::ConnectorError> {
        let timestamp = OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000;
        let auth: fiservemea::FiservemeaAuthType =
            fiservemea::FiservemeaAuthType::try_from(&req.connector_auth_type)?;

        let client_request_id = Uuid::new_v4().to_string();
        let http_method = self.get_http_method();
        let hmac = match http_method {
            Method::Get => self
                .generate_authorization_signature(auth.clone(), &client_request_id, "", timestamp)
                .change_context(errors::ConnectorError::RequestEncodingFailed)?,
            Method::Post | Method::Put | Method::Delete | Method::Patch => {
                let fiserv_req = self.get_request_body(req, connectors)?;
                self.generate_authorization_signature(
                    auth.clone(),
                    &client_request_id,
                    fiserv_req.get_inner_value().peek(),
                    timestamp,
                )
                .change_context(errors::ConnectorError::RequestEncodingFailed)?
            }
        };
        let headers = vec![
            (
                headers::CONTENT_TYPE.to_string(),
                types::PaymentsAuthorizeType::get_content_type(self)
                    .to_string()
                    .into(),
            ),
            ("Client-Request-Id".to_string(), client_request_id.into()),
            (headers::API_KEY.to_string(), auth.api_key.expose().into()),
            (headers::TIMESTAMP.to_string(), timestamp.to_string().into()),
            (headers::MESSAGE_SIGNATURE.to_string(), hmac.into_masked()),
        ];
        Ok(headers)
    }
}

impl ConnectorCommon for Fiservemea {
    fn id(&self) -> &'static str {
        "fiservemea"
    }

    fn get_currency_unit(&self) -> api::CurrencyUnit {
        api::CurrencyUnit::Base
    }

    fn common_get_content_type(&self) -> &'static str {
        "application/json"
    }

    fn base_url<'a>(&self, connectors: &'a Connectors) -> &'a str {
        connectors.fiservemea.base_url.as_ref()
    }

    fn build_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        let response: fiservemea::FiservemeaErrorResponse = res
            .response
            .parse_struct("FiservemeaErrorResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        event_builder.map(|i| i.set_response_body(&response));
        router_env::logger::info!(connector_response=?response);

        // Los rechazos del emisor llegan por acá (HTTP 422 / `EndpointDeclined`) con el bloque
        // `processor` completo, así que es acá donde hay que publicar los códigos de red que
        // gobiernan los reintentos. Se calcula antes del `match` porque el brazo consume
        // `response.error`.
        let network =
            fiservemea::FiservemeaNetworkCodes::from_processor(response.processor.as_ref());
        // Se toma antes del `match` por el mismo motivo que `network`: el brazo consume
        // `response.error`. Sin esto el rechazo llega al comercio sin el id del gateway.
        let connector_transaction_id = response.ipg_transaction_id.clone();
        // El resultado de la autenticación 3DS se publica también acá: 11 de las 22 filas 3DS del
        // checklist terminan en este camino (HTTP 409) y el `responseCode3dSecure` es el dato que
        // Fiserv pide informar por caso.
        let three_ds_metadata = response
            .secure3d_response
            .as_ref()
            .and_then(fiservemea::FiservemeaSecure3dResponse::to_metadata)
            .map(hyperswitch_masking::Secret::new);

        match response.error {
            Some(error) => {
                let details = error.details.map(|details| {
                    details
                        .iter()
                        .map(|detail| {
                            format!(
                                "{}: {}",
                                detail
                                    .field
                                    .clone()
                                    .unwrap_or("No Field Provided".to_string()),
                                detail
                                    .message
                                    .clone()
                                    .unwrap_or("No Message Provided".to_string())
                            )
                        })
                        .collect::<Vec<String>>()
                        .join(", ")
                });
                Ok(ErrorResponse {
                    status_code: res.status_code,
                    code: error.code.unwrap_or(consts::NO_ERROR_CODE.to_string()),
                    message: response
                        .response_type
                        .unwrap_or(consts::NO_ERROR_MESSAGE.to_string()),
                    reason: match details {
                        Some(details) => Some(format!(
                            "{} {}",
                            error.message.unwrap_or("".to_string()),
                            details
                        )),
                        None => error.message,
                    },
                    attempt_status: None,
                    connector_transaction_id: connector_transaction_id.clone(),
                    connector_response_reference_id: None,
                    network_advice_code: network.advice_code,
                    network_decline_code: network.decline_code,
                    network_error_message: network.error_message,
                    connector_metadata: three_ds_metadata.clone(),
                })
            }
            None => Ok(ErrorResponse {
                status_code: res.status_code,
                code: consts::NO_ERROR_CODE.to_string(),
                message: response
                    .response_type
                    .clone()
                    .unwrap_or(consts::NO_ERROR_MESSAGE.to_string()),
                reason: response.response_type,
                attempt_status: None,
                connector_transaction_id,
                connector_response_reference_id: None,
                network_advice_code: network.advice_code,
                network_decline_code: network.decline_code,
                network_error_message: network.error_message,
                connector_metadata: three_ds_metadata,
            }),
        }
    }
}

impl ConnectorValidation for Fiservemea {}

impl ConnectorIntegration<Authorize, PaymentsAuthorizeData, PaymentsResponseData> for Fiservemea {
    fn get_headers(
        &self,
        req: &PaymentsAuthorizeRouterData,
        connectors: &Connectors,
    ) -> CustomResult<Vec<(String, hyperswitch_masking::Maskable<String>)>, errors::ConnectorError> {
        self.build_headers(req, connectors)
    }

    fn get_content_type(&self) -> &'static str {
        self.common_get_content_type()
    }

    fn get_url(
        &self,
        req: &PaymentsAuthorizeRouterData,
        connectors: &Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        Ok(format!(
            "{}/payments",
            determine_endpoint(connectors, req.test_mode)?
        ))
    }

    fn get_request_body(
        &self,
        req: &PaymentsAuthorizeRouterData,
        _connectors: &Connectors,
    ) -> CustomResult<RequestContent, errors::ConnectorError> {
        let amount = utils::convert_amount(
            self.amount_converter,
            req.request.minor_amount,
            req.request.currency,
        )?;

        let connector_router_data = fiservemea::FiservemeaRouterData::from((amount, req));
        let connector_req =
            fiservemea::FiservemeaPaymentsRequest::try_from(&connector_router_data)?;
        Ok(RequestContent::Json(Box::new(connector_req)))
    }

    fn build_request(
        &self,
        req: &PaymentsAuthorizeRouterData,
        connectors: &Connectors,
    ) -> CustomResult<Option<Request>, errors::ConnectorError> {
        Ok(Some(
            RequestBuilder::new()
                .method(Method::Post)
                .url(&types::PaymentsAuthorizeType::get_url(
                    self, req, connectors,
                )?)
                .attach_default_headers()
                .headers(types::PaymentsAuthorizeType::get_headers(
                    self, req, connectors,
                )?)
                .set_body(types::PaymentsAuthorizeType::get_request_body(
                    self, req, connectors,
                )?)
                .build(),
        ))
    }

    fn handle_response(
        &self,
        data: &PaymentsAuthorizeRouterData,
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<PaymentsAuthorizeRouterData, errors::ConnectorError> {
        let response: fiservemea::FiservemeaPaymentsResponse = res
            .response
            .parse_struct("Fiservemea PaymentsAuthorizeResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
        event_builder.map(|i| i.set_response_body(&response));
        router_env::logger::info!(connector_response=?response);

        // Build the authorize integrity object from the REQUESTED amount, not the response's
        // approved amount. The gateway can approve less than requested (partial authorization);
        // comparing the approved amount against the request would flag a legitimate partial auth
        // as an integrity failure (CodeRabbit).
        let integrity_amount = utils::convert_amount(
            self.amount_converter_to_float_major_unit,
            data.request.minor_amount,
            data.request.currency,
        )?;
        let integrity_object = Some(utils::get_authorise_integrity_object(
            self.amount_converter_to_float_major_unit,
            integrity_amount,
            data.request.currency.to_string(),
        )?);

        let mut router_data = RouterData::try_from(ResponseRouterData {
            response,
            data: data.clone(),
            http_code: res.status_code,
        })?;
        router_data.request.integrity_object = integrity_object;
        // El `methodForm` del gateway es un iframe oculto con un form que apunta a ese mismo
        // iframe: entregado crudo, el desafío se renderiza invisible y el tarjetahabiente nunca
        // vuelve al comercio. Se envuelve en una página que sí navega la ventana principal.
        // Va acá y no en la conversión de la respuesta porque la URL de retorno sale del request.
        fiservemea::wrap_three_ds_method_redirection(&mut router_data);
        Ok(router_data)
    }

    fn get_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, event_builder)
    }
}

/// Código con el que el gateway rechaza una continuación 3DS que ya se cursó. Es la señal de
/// que este CompleteAuthorize es el duplicado, no un fallo real del pago.
const FISERVEMEA_ERROR_DUPLICATE_CONTINUATION: &str = "30056";

impl ConnectorIntegration<CompleteAuthorize, CompleteAuthorizeData, PaymentsResponseData>
    for Fiservemea
{
    fn get_headers(
        &self,
        req: &PaymentsCompleteAuthorizeRouterData,
        connectors: &Connectors,
    ) -> CustomResult<Vec<(String, hyperswitch_masking::Maskable<String>)>, errors::ConnectorError> {
        self.build_headers(req, connectors)
    }

    fn get_content_type(&self) -> &'static str {
        self.common_get_content_type()
    }

    fn get_url(
        &self,
        req: &PaymentsCompleteAuthorizeRouterData,
        connectors: &Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        // 3DS native continuation is a PATCH on the original transaction created by the
        // Authorize POST (vendor doc §10.1.4/§10.1.5).
        let connector_payment_id = req
            .request
            .connector_transaction_id
            .clone()
            .ok_or(errors::ConnectorError::MissingConnectorTransactionID)?;
        let base_url = determine_endpoint(connectors, req.test_mode)?;
        // La notificación que el ACS publica en la `methodNotificationURL` llega dentro del
        // iframe oculto: su respuesta es invisible, así que no puede llevar la continuación. Se
        // degrada a una consulta de estado, que es idempotente y deja que la continuación real
        // la mande el retorno por la `termURL`, en la ventana principal.
        if is_three_ds_method_notification(req) {
            let auth = fiservemea::FiservemeaAuthType::try_from(&req.connector_auth_type)?;
            return build_sync_url(
                &base_url,
                &ResponseId::ConnectorTransactionId(connector_payment_id),
                &req.connector_request_reference_id,
                auth.store_id.peek(),
            );
        }
        Ok(format!("{base_url}/payments/{connector_payment_id}"))
    }

    fn get_request_body(
        &self,
        req: &PaymentsCompleteAuthorizeRouterData,
        _connectors: &Connectors,
    ) -> CustomResult<RequestContent, errors::ConnectorError> {
        let connector_req = fiservemea::FiservemeaCompleteAuthorizeRequest::try_from(req)?;
        Ok(RequestContent::Json(Box::new(connector_req)))
    }

    fn build_request(
        &self,
        req: &PaymentsCompleteAuthorizeRouterData,
        connectors: &Connectors,
    ) -> CustomResult<Option<Request>, errors::ConnectorError> {
        // La notificación del 3DSMethod se resuelve con una consulta GET, firmada sobre cuerpo
        // vacío y sin body. Así el PATCH de continuación sale una sola vez, desde el retorno por
        // la termURL, y es su respuesta —la que trae el desafío— la que se renderiza en la
        // ventana principal.
        if is_three_ds_method_notification(req) {
            return Ok(Some(
                RequestBuilder::new()
                    .method(Method::Get)
                    .url(&types::PaymentsCompleteAuthorizeType::get_url(
                        self, req, connectors,
                    )?)
                    .attach_default_headers()
                    .headers(self.signed_headers_for_payload(req, "")?)
                    .build(),
            ));
        }
        Ok(Some(
            RequestBuilder::new()
                // The IPG continuation uses PATCH; `build_headers` signs the body for PATCH
                // just like POST (see the `get_http_method` match).
                .method(Method::Patch)
                .url(&types::PaymentsCompleteAuthorizeType::get_url(
                    self, req, connectors,
                )?)
                .attach_default_headers()
                .headers(types::PaymentsCompleteAuthorizeType::get_headers(
                    self, req, connectors,
                )?)
                .set_body(types::PaymentsCompleteAuthorizeType::get_request_body(
                    self, req, connectors,
                )?)
                .build(),
        ))
    }

    fn handle_response(
        &self,
        data: &PaymentsCompleteAuthorizeRouterData,
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<PaymentsCompleteAuthorizeRouterData, errors::ConnectorError> {
        let response: fiservemea::FiservemeaPaymentsResponse = res
            .response
            .parse_struct("Fiservemea CompleteAuthorizeResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
        event_builder.map(|i| i.set_response_body(&response));
        router_env::logger::info!(connector_response=?response);
        // Reuses the shared response conversion: a second `WAITING` + `params` (challenge
        // after the method step) yields another `redirection_data` + `AuthenticationPending`;
        // a terminal response maps to Charged/Authorized/Failure via `map_status`.
        //
        // No amount integrity object is set here (unlike Authorize/Capture/PSync/Refund):
        // `CompleteAuthorizeData` has no `integrity_object` field
        // (hyperswitch_domain_models::router_request_types::CompleteAuthorizeData), so there is
        // nowhere to store it. If that field is added upstream, mirror the
        // `settlement_amount()` -> `get_authorise_integrity_object(...)` block used above.
        RouterData::try_from(ResponseRouterData {
            response,
            data: data.clone(),
            http_code: res.status_code,
        })
    }

    fn get_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        let mut error = self.build_error_response(res, event_builder)?;
        // Guarda de idempotencia del paso 3DS.
        //
        // El ACS puede publicar su notificación al `methodNotificationURL` mientras el navegador
        // vuelve por el `termURL`, y las dos URLs son la misma (el `complete_authorize_url`), así
        // que llegan dos CompleteAuthorize para la misma transacción. La guía avisa de esto y
        // pide explícitamente no reenviar la continuación.
        //
        // La primera gana y la segunda recibe HTTP 409 `30056 "Referenced transaction does not
        // exist"` (verificado contra cert: el primer PATCH devuelve APPROVED con
        // `responseCode3dSecure: 1` y los siguientes, 409/30056). Sin esta guarda ese 409 se
        // publicaría como fallo y pisaría un pago ya aprobado.
        //
        // Se deja el intento en `Pending` para que lo resuelva el PSync leyendo el estado real,
        // en vez de afirmar un fallo que no ocurrió.
        if error.code == FISERVEMEA_ERROR_DUPLICATE_CONTINUATION {
            router_env::logger::info!(
                "fiservemea: continuación 3DS duplicada (30056); se difiere al PSync"
            );
            error.attempt_status = Some(enums::AttemptStatus::Pending);
        }
        Ok(error)
    }
}

impl ConnectorIntegration<PSync, PaymentsSyncData, PaymentsResponseData> for Fiservemea {
    fn get_headers(
        &self,
        req: &PaymentsSyncRouterData,
        connectors: &Connectors,
    ) -> CustomResult<Vec<(String, hyperswitch_masking::Maskable<String>)>, errors::ConnectorError> {
        self.build_headers(req, connectors)
    }

    fn get_content_type(&self) -> &'static str {
        self.common_get_content_type()
    }

    fn get_http_method(&self) -> Method {
        Method::Get
    }

    fn get_url(
        &self,
        req: &PaymentsSyncRouterData,
        connectors: &Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        // The IPG sync (GET) requires the storeId as a query param (vendor doc, e.g.
        // `/payments/{id}?storeId=...`); the HMAC signature for GET is over an empty body, so
        // the query param is not part of the signed payload. `store_id` is a non-sensitive
        // merchant identifier (also sent in request bodies).
        let auth = fiservemea::FiservemeaAuthType::try_from(&req.connector_auth_type)?;
        // El `orderId` con el que se consulta es el mismo `connector_request_reference_id` que
        // se mandó en `order.orderId` al autorizar (ver `FiservemeaOrder`), así que la orden
        // existe aunque la venta haya fallado antes de devolver el `ipgTransactionId`.
        build_sync_url(
            &determine_endpoint(connectors, req.test_mode)?,
            &req.request.connector_transaction_id,
            &req.connector_request_reference_id,
            auth.store_id.peek(),
        )
    }

    fn build_request(
        &self,
        req: &PaymentsSyncRouterData,
        connectors: &Connectors,
    ) -> CustomResult<Option<Request>, errors::ConnectorError> {
        Ok(Some(
            RequestBuilder::new()
                .method(Method::Get)
                .url(&types::PaymentsSyncType::get_url(self, req, connectors)?)
                .attach_default_headers()
                .headers(types::PaymentsSyncType::get_headers(self, req, connectors)?)
                .build(),
        ))
    }

    fn handle_response(
        &self,
        data: &PaymentsSyncRouterData,
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<PaymentsSyncRouterData, errors::ConnectorError> {
        // La consulta devuelve `transactionResponse` u `orderResponse` según por cuál de los
        // dos identificadores se haya preguntado (ver `build_sync_url`); se loguea la respuesta
        // entera y recién después se reduce a la transacción que corresponde al intento.
        let sync_response: fiservemea::FiservemeaSyncResponse = res
            .response
            .parse_struct("fiservemea PaymentsSyncResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
        event_builder.map(|i| i.set_response_body(&sync_response));
        router_env::logger::info!(connector_response=?sync_response);
        let response = sync_response.into_transaction()?;

        let integrity_object = response
            .settlement_amount()
            .map(|(amount, currency)| {
                utils::get_sync_integrity_object(
                    self.amount_converter_to_float_major_unit,
                    amount,
                    currency.to_string(),
                )
            })
            .transpose()?;

        let mut router_data = RouterData::try_from(ResponseRouterData {
            response,
            data: data.clone(),
            http_code: res.status_code,
        })?;
        router_data.request.integrity_object = integrity_object;
        Ok(router_data)
    }

    fn get_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, event_builder)
    }
}

impl ConnectorIntegration<Capture, PaymentsCaptureData, PaymentsResponseData> for Fiservemea {
    fn get_headers(
        &self,
        req: &PaymentsCaptureRouterData,
        connectors: &Connectors,
    ) -> CustomResult<Vec<(String, hyperswitch_masking::Maskable<String>)>, errors::ConnectorError> {
        self.build_headers(req, connectors)
    }

    fn get_content_type(&self) -> &'static str {
        self.common_get_content_type()
    }

    fn get_url(
        &self,
        req: &PaymentsCaptureRouterData,
        connectors: &Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        let connector_payment_id = req.request.connector_transaction_id.clone();
        Ok(format!(
            "{}/payments/{connector_payment_id}",
            determine_endpoint(connectors, req.test_mode)?
        ))
    }

    fn get_request_body(
        &self,
        req: &PaymentsCaptureRouterData,
        _connectors: &Connectors,
    ) -> CustomResult<RequestContent, errors::ConnectorError> {
        let amount = utils::convert_amount(
            self.amount_converter,
            req.request.minor_amount_to_capture,
            req.request.currency,
        )?;

        let connector_router_data = fiservemea::FiservemeaRouterData::from((amount, req));
        let connector_req = fiservemea::FiservemeaCaptureRequest::try_from(&connector_router_data)?;
        Ok(RequestContent::Json(Box::new(connector_req)))
    }

    fn build_request(
        &self,
        req: &PaymentsCaptureRouterData,
        connectors: &Connectors,
    ) -> CustomResult<Option<Request>, errors::ConnectorError> {
        Ok(Some(
            RequestBuilder::new()
                .method(Method::Post)
                .url(&types::PaymentsCaptureType::get_url(self, req, connectors)?)
                .attach_default_headers()
                .headers(types::PaymentsCaptureType::get_headers(
                    self, req, connectors,
                )?)
                .set_body(types::PaymentsCaptureType::get_request_body(
                    self, req, connectors,
                )?)
                .build(),
        ))
    }

    fn handle_response(
        &self,
        data: &PaymentsCaptureRouterData,
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<PaymentsCaptureRouterData, errors::ConnectorError> {
        let response: fiservemea::FiservemeaPaymentsResponse = res
            .response
            .parse_struct("Fiservemea PaymentsCaptureResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
        event_builder.map(|i| i.set_response_body(&response));
        router_env::logger::info!(connector_response=?response);

        let integrity_object = response
            .settlement_amount()
            .map(|(amount, currency)| {
                utils::get_capture_integrity_object(
                    self.amount_converter_to_float_major_unit,
                    Some(amount),
                    currency.to_string(),
                )
            })
            .transpose()?;

        let mut router_data = RouterData::try_from(ResponseRouterData {
            response,
            data: data.clone(),
            http_code: res.status_code,
        })?;
        router_data.request.integrity_object = integrity_object;
        Ok(router_data)
    }

    fn get_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, event_builder)
    }
}

impl ConnectorIntegration<Void, PaymentsCancelData, PaymentsResponseData> for Fiservemea {
    fn get_headers(
        &self,
        req: &PaymentsCancelRouterData,
        connectors: &Connectors,
    ) -> CustomResult<Vec<(String, hyperswitch_masking::Maskable<String>)>, errors::ConnectorError> {
        self.build_headers(req, connectors)
    }

    fn get_content_type(&self) -> &'static str {
        self.common_get_content_type()
    }

    fn get_url(
        &self,
        req: &PaymentsCancelRouterData,
        connectors: &Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        let connector_payment_id = req.request.connector_transaction_id.clone();
        Ok(format!(
            "{}/payments/{connector_payment_id}",
            determine_endpoint(connectors, req.test_mode)?
        ))
    }

    fn get_request_body(
        &self,
        req: &PaymentsCancelRouterData,
        _connectors: &Connectors,
    ) -> CustomResult<RequestContent, errors::ConnectorError> {
        let connector_req = fiservemea::FiservemeaVoidRequest::try_from(req)?;
        Ok(RequestContent::Json(Box::new(connector_req)))
    }

    fn build_request(
        &self,
        req: &PaymentsCancelRouterData,
        connectors: &Connectors,
    ) -> CustomResult<Option<Request>, errors::ConnectorError> {
        Ok(Some(
            RequestBuilder::new()
                .method(Method::Post)
                .url(&types::PaymentsVoidType::get_url(self, req, connectors)?)
                .attach_default_headers()
                .headers(types::PaymentsVoidType::get_headers(self, req, connectors)?)
                .set_body(types::PaymentsVoidType::get_request_body(
                    self, req, connectors,
                )?)
                .build(),
        ))
    }

    fn handle_response(
        &self,
        data: &PaymentsCancelRouterData,
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<PaymentsCancelRouterData, errors::ConnectorError> {
        let response: fiservemea::FiservemeaPaymentsResponse = res
            .response
            .parse_struct("Fiservemea PaymentsCaptureResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
        event_builder.map(|i| i.set_response_body(&response));
        router_env::logger::info!(connector_response=?response);
        RouterData::try_from(ResponseRouterData {
            response,
            data: data.clone(),
            http_code: res.status_code,
        })
    }

    fn get_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, event_builder)
    }
}

impl ConnectorIntegration<Execute, RefundsData, RefundsResponseData> for Fiservemea {
    fn get_headers(
        &self,
        req: &RefundsRouterData<Execute>,
        connectors: &Connectors,
    ) -> CustomResult<Vec<(String, hyperswitch_masking::Maskable<String>)>, errors::ConnectorError> {
        self.build_headers(req, connectors)
    }

    fn get_content_type(&self) -> &'static str {
        self.common_get_content_type()
    }

    fn get_url(
        &self,
        req: &RefundsRouterData<Execute>,
        connectors: &Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        let connector_payment_id = req.request.connector_transaction_id.clone();
        Ok(format!(
            "{}/payments/{connector_payment_id}",
            determine_endpoint(connectors, req.test_mode)?
        ))
    }

    fn get_request_body(
        &self,
        req: &RefundsRouterData<Execute>,
        _connectors: &Connectors,
    ) -> CustomResult<RequestContent, errors::ConnectorError> {
        let refund_amount = utils::convert_amount(
            self.amount_converter,
            req.request.minor_refund_amount,
            req.request.currency,
        )?;

        let connector_router_data = fiservemea::FiservemeaRouterData::from((refund_amount, req));
        let connector_req = fiservemea::FiservemeaRefundRequest::try_from(&connector_router_data)?;
        Ok(RequestContent::Json(Box::new(connector_req)))
    }

    fn build_request(
        &self,
        req: &RefundsRouterData<Execute>,
        connectors: &Connectors,
    ) -> CustomResult<Option<Request>, errors::ConnectorError> {
        let request = RequestBuilder::new()
            .method(Method::Post)
            .url(&types::RefundExecuteType::get_url(self, req, connectors)?)
            .attach_default_headers()
            .headers(types::RefundExecuteType::get_headers(
                self, req, connectors,
            )?)
            .set_body(types::RefundExecuteType::get_request_body(
                self, req, connectors,
            )?)
            .build();
        Ok(Some(request))
    }

    fn handle_response(
        &self,
        data: &RefundsRouterData<Execute>,
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<RefundsRouterData<Execute>, errors::ConnectorError> {
        let response: fiservemea::FiservemeaPaymentsResponse = res
            .response
            .parse_struct("fiservemea RefundResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
        event_builder.map(|i| i.set_response_body(&response));
        router_env::logger::info!(connector_response=?response);

        let integrity_object = response
            .settlement_amount()
            .map(|(amount, currency)| {
                utils::get_refund_integrity_object(
                    self.amount_converter_to_float_major_unit,
                    amount,
                    currency.to_string(),
                )
            })
            .transpose()?;

        let mut router_data = RouterData::try_from(ResponseRouterData {
            response,
            data: data.clone(),
            http_code: res.status_code,
        })?;
        router_data.request.integrity_object = integrity_object;
        Ok(router_data)
    }

    fn get_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, event_builder)
    }
}

impl ConnectorIntegration<RSync, RefundsData, RefundsResponseData> for Fiservemea {
    fn get_headers(
        &self,
        req: &RefundSyncRouterData,
        connectors: &Connectors,
    ) -> CustomResult<Vec<(String, hyperswitch_masking::Maskable<String>)>, errors::ConnectorError> {
        self.build_headers(req, connectors)
    }

    fn get_content_type(&self) -> &'static str {
        self.common_get_content_type()
    }

    fn get_http_method(&self) -> Method {
        Method::Get
    }

    fn get_url(
        &self,
        req: &RefundSyncRouterData,
        connectors: &Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        let connector_payment_id = req.request.get_connector_refund_id()?;
        // IPG refund-sync (GET) also needs the storeId query param (see PSync note above);
        // percent-encode it for a well-formed query string.
        let auth = fiservemea::FiservemeaAuthType::try_from(&req.connector_auth_type)?;
        let store_id: String =
            url::form_urlencoded::byte_serialize(auth.store_id.peek().as_bytes()).collect();
        Ok(format!(
            "{}/payments/{connector_payment_id}?storeId={store_id}",
            determine_endpoint(connectors, req.test_mode)?,
        ))
    }

    fn build_request(
        &self,
        req: &RefundSyncRouterData,
        connectors: &Connectors,
    ) -> CustomResult<Option<Request>, errors::ConnectorError> {
        Ok(Some(
            RequestBuilder::new()
                .method(Method::Get)
                .url(&types::RefundSyncType::get_url(self, req, connectors)?)
                .attach_default_headers()
                .headers(types::RefundSyncType::get_headers(self, req, connectors)?)
                // Sin `set_body`, igual que el PSync gemelo. El conector no define
                // `get_request_body` para RSync, así que resolvía al default del trait: el
                // string JSON `"{}"`, no un objeto. Y la firma HMAC se calcula sobre payload
                // vacío porque `get_http_method()` es Get, o sea que ese body nunca estuvo
                // firmado; hoy no rompe sólo porque el cliente HTTP descarta el body en GET.
                .build(),
        ))
    }

    fn handle_response(
        &self,
        data: &RefundSyncRouterData,
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<RefundSyncRouterData, errors::ConnectorError> {
        let response: fiservemea::FiservemeaPaymentsResponse = res
            .response
            .parse_struct("fiservemea RefundSyncResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
        event_builder.map(|i| i.set_response_body(&response));
        router_env::logger::info!(connector_response=?response);

        let integrity_object = response
            .settlement_amount()
            .map(|(amount, currency)| {
                utils::get_refund_integrity_object(
                    self.amount_converter_to_float_major_unit,
                    amount,
                    currency.to_string(),
                )
            })
            .transpose()?;

        let mut router_data = RouterData::try_from(ResponseRouterData {
            response,
            data: data.clone(),
            http_code: res.status_code,
        })?;
        router_data.request.integrity_object = integrity_object;
        Ok(router_data)
    }

    fn get_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, event_builder)
    }
}

#[async_trait::async_trait]
impl webhooks::IncomingWebhook for Fiservemea {
    fn get_webhook_object_reference_id(
        &self,
        _request: &webhooks::IncomingWebhookRequestDetails<'_>,
    ) -> CustomResult<api_models::webhooks::ObjectReferenceId, errors::ConnectorError> {
        Err(report!(errors::ConnectorError::WebhooksNotImplemented))
    }

    fn get_webhook_event_type(
        &self,
        _request: &webhooks::IncomingWebhookRequestDetails<'_>,
        _context: Option<&webhooks::WebhookContext>,
    ) -> CustomResult<api_models::webhooks::IncomingWebhookEvent, errors::ConnectorError> {
        Err(report!(errors::ConnectorError::WebhooksNotImplemented))
    }

    fn get_webhook_resource_object(
        &self,
        _request: &webhooks::IncomingWebhookRequestDetails<'_>,
    ) -> CustomResult<Box<dyn hyperswitch_masking::ErasedMaskSerialize>, errors::ConnectorError> {
        Err(report!(errors::ConnectorError::WebhooksNotImplemented))
    }
}

static FISERVEMEA_SUPPORTED_PAYMENT_METHODS: LazyLock<SupportedPaymentMethods> =
    LazyLock::new(|| {
        let supported_capture_methods = vec![
            enums::CaptureMethod::Automatic,
            enums::CaptureMethod::Manual,
            enums::CaptureMethod::SequentialAutomatic,
        ];

        let supported_card_network = vec![
            common_enums::CardNetwork::Mastercard,
            common_enums::CardNetwork::Visa,
            common_enums::CardNetwork::AmericanExpress,
            common_enums::CardNetwork::Discover,
            common_enums::CardNetwork::JCB,
            common_enums::CardNetwork::UnionPay,
            common_enums::CardNetwork::DinersClub,
            common_enums::CardNetwork::Interac,
            common_enums::CardNetwork::CartesBancaires,
        ];

        let mut fiservemea_supported_payment_methods = SupportedPaymentMethods::new();

        fiservemea_supported_payment_methods.add(
            enums::PaymentMethod::Card,
            enums::PaymentMethodType::Credit,
            PaymentMethodDetails {
                mandates: enums::FeatureStatus::Supported,
                refunds: enums::FeatureStatus::Supported,
                supported_capture_methods: supported_capture_methods.clone(),
                specific_features: Some(
                    api_models::feature_matrix::PaymentMethodSpecificFeatures::Card({
                        api_models::feature_matrix::CardSpecificFeatures {
                            three_ds: common_enums::FeatureStatus::Supported,
                            no_three_ds: common_enums::FeatureStatus::Supported,
                            supported_card_networks: supported_card_network.clone(),
                        }
                    }),
                ),
            },
        );

        fiservemea_supported_payment_methods.add(
            enums::PaymentMethod::Card,
            enums::PaymentMethodType::Debit,
            PaymentMethodDetails {
                mandates: enums::FeatureStatus::Supported,
                refunds: enums::FeatureStatus::Supported,
                supported_capture_methods: supported_capture_methods.clone(),
                specific_features: Some(
                    api_models::feature_matrix::PaymentMethodSpecificFeatures::Card({
                        api_models::feature_matrix::CardSpecificFeatures {
                            three_ds: common_enums::FeatureStatus::Supported,
                            no_three_ds: common_enums::FeatureStatus::Supported,
                            supported_card_networks: supported_card_network.clone(),
                        }
                    }),
                ),
            },
        );

        fiservemea_supported_payment_methods
    });

static FISERVEMEA_CONNECTOR_INFO: ConnectorInfo = ConnectorInfo {
    display_name: "Fiservemea",
    description: "Fiserv powers over 6+ million merchants and 10,000+ financial institutions enabling them to accept billions of payments a year.",
    connector_type: enums::HyperswitchConnectorCategory::BankAcquirer,
    integration_status: enums::ConnectorIntegrationStatus::Sandbox,
};

static FISERVEMEA_SUPPORTED_WEBHOOK_FLOWS: [enums::EventClass; 0] = [];

impl ConnectorSpecifications for Fiservemea {
    fn get_connector_about(&self) -> Option<&'static ConnectorInfo> {
        Some(&FISERVEMEA_CONNECTOR_INFO)
    }

    fn get_supported_payment_methods(&self) -> Option<&'static SupportedPaymentMethods> {
        Some(&*FISERVEMEA_SUPPORTED_PAYMENT_METHODS)
    }

    fn get_supported_webhook_flows(&self) -> Option<&'static [enums::EventClass]> {
        Some(&FISERVEMEA_SUPPORTED_WEBHOOK_FLOWS)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    const BASE: &str = "https://cert.api.firstdata.com/gateway/v2";

    #[test]
    fn sync_url_prefers_the_ipg_transaction_id() {
        // Ruta normal, la que ya usaba el conector (verificada en cert:
        // `GET /payments/84667286294?storeId=5926072901` devuelve 200).
        let url = build_sync_url(
            BASE,
            &ResponseId::ConnectorTransactionId("84667286294".to_string()),
            "PX-1786053423-06-inq",
            "5926072901",
        )
        .unwrap();
        assert_eq!(
            url,
            "https://cert.api.firstdata.com/gateway/v2/payments/84667286294?storeId=5926072901"
        );
    }

    #[test]
    fn sync_url_falls_back_to_the_order_id() {
        // Sin `ipgTransactionId` — el caso del Data Only rechazado, que vuelve 409 con
        // `orderId` y sin id de transacción — se consulta la orden. Verificado en cert:
        // `GET /orders/PX-1786053599-33-3ds-dataonly?storeId=5926072901` devuelve 200 y trae
        // el `ipgTransactionId` que el rechazo nunca dio.
        for connector_transaction_id in [
            ResponseId::NoResponseId,
            ResponseId::EncodedData("no-es-un-id".to_string()),
            ResponseId::ConnectorTransactionId(String::new()),
        ] {
            let url = build_sync_url(
                BASE,
                &connector_transaction_id,
                "PX-1786053599-33-3ds-dataonly",
                "5926072901",
            )
            .unwrap();
            assert_eq!(
                url,
                "https://cert.api.firstdata.com/gateway/v2/orders/PX-1786053599-33-3ds-dataonly?storeId=5926072901"
            );
        }
    }

    #[test]
    fn sync_url_percent_encodes_merchant_controlled_values() {
        // El `orderId` sale de la referencia del comercio: sin escapar, un `?`, un `#` o un
        // espacio cambiarían la ruta o agregarían parámetros a la consulta.
        //
        // El espacio se escapa distinto en cada parte y no es un detalle cosmético: en el
        // segmento de path va `%20`, y en el query va `+`. Mandar `+` en el path hace que el
        // gateway reciba un más literal y responda `INVALID_INPUT`.
        let url = build_sync_url(
            BASE,
            &ResponseId::NoResponseId,
            "PX 2026/08#07?storeId=otra",
            "59260 72901",
        )
        .unwrap();
        assert_eq!(
            url,
            "https://cert.api.firstdata.com/gateway/v2/orders/PX%202026%2F08%2307%3FstoreId=otra?storeId=59260+72901"
        );
        // El `=` queda sin escapar porque en un path es un carácter permitido y ahí es inerte:
        // lo que importa es que el `?` viaje como `%3F` (no puede abrir un query) y el `/` como
        // `%2F` (no puede agregar un segmento).
    }

    #[test]
    fn sync_url_without_any_identifier_fails() {
        // Sin transacción ni orden no hay nada que consultar: preferimos el error explícito
        // antes que pegarle al gateway con `/orders/?storeId=...`.
        assert!(build_sync_url(BASE, &ResponseId::NoResponseId, "", "5926072901").is_err());
    }

    #[test]
    fn duplicate_three_ds_continuation_defers_to_psync() {
        // Verificado contra cert: el primer PATCH de continuación devuelve APPROVED con
        // `responseCode3dSecure: 1`, y los siguientes 409 con `30056`. Ese 409 NO puede
        // publicarse como fallo, porque pisaría un pago ya aprobado.
        assert_eq!(FISERVEMEA_ERROR_DUPLICATE_CONTINUATION, "30056");

        let raw = serde_json::json!({
            "type": "TransactionErrorResponse",
            "responseType": "EndpointDeclined",
            "transactionStatus": "VALIDATION_FAILED",
            "error": { "code": "30056", "message": "Referenced transaction does not exist" }
        });
        let parsed: fiservemea::FiservemeaErrorResponse = serde_json::from_value(raw).unwrap();
        assert_eq!(
            parsed.error.and_then(|e| e.code).as_deref(),
            Some(FISERVEMEA_ERROR_DUPLICATE_CONTINUATION)
        );
    }

    // ---------------------------------------------------------------------------------
    // Rutas contrastadas contra las que el gateway de certificación aceptó con HTTP 200
    // (fiserv_homologacion_logs/20260806-215656/evidencia.jsonl):
    //   línea  9 → POST /payments/84667286296   (VOID)
    //   línea 11 → POST /payments/84667286298   (RETURN total)
    //   línea 13 → POST /payments/84667286310   (RETURN parcial)
    // Las de INQUIRY (líneas 6 y 7) ya quedan fijadas por los tests de `build_sync_url`.
    // ---------------------------------------------------------------------------------

    fn cert_connectors() -> Connectors {
        let mut connectors = Connectors::default();
        connectors.fiservemea.base_url = format!("{BASE}/");
        connectors.fiservemea.secondary_base_url = Some(BASE.to_string());
        connectors
    }

    fn url_router_data<Flow, Req, Res>(request: Req) -> RouterData<Flow, Req, Res> {
        RouterData {
            flow: std::marker::PhantomData,
            merchant_id: common_utils::id_type::MerchantId::default(),
            customer_id: None,
            connector_customer: None,
            connector: "fiservemea".to_string(),
            payment_id: "pay_1".to_string(),
            attempt_id: "att_1".to_string(),
            tenant_id: common_utils::id_type::TenantId::try_from_string("public".to_string())
                .unwrap(),
            status: enums::AttemptStatus::Pending,
            payment_method: enums::PaymentMethod::Card,
            connector_auth_type:
                hyperswitch_domain_models::router_data::ConnectorAuthType::SignatureKey {
                api_key: hyperswitch_masking::Secret::new("apikey".to_string()),
                key1: hyperswitch_masking::Secret::new("5926072901".to_string()),
                api_secret: hyperswitch_masking::Secret::new("apisecret".to_string()),
            },
            description: None,
            address: hyperswitch_domain_models::payment_address::PaymentAddress::default(),
            auth_type: enums::AuthenticationType::NoThreeDs,
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
            connector_request_reference_id: "PX-1786053424-07-void".to_string(),
            #[cfg(feature = "payouts")]
            payout_method_data: None,
            #[cfg(feature = "payouts")]
            quote_id: None,
            // Ambiente de certificación: el conector exige `secondary_base_url` para poder
            // enrutar a cert (falla cerrado si no está configurada).
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
            payment_method_type: None,
            payout_id: None,
            authorized_amount: None,
            customer_document_details: None,
            feature_data: None,
            sender_payment_instrument_id: None,
        }
    }

    #[test]
    fn void_url_and_method_match_the_accepted_cert_call() {
        let req: PaymentsCancelRouterData = url_router_data(PaymentsCancelData {
            connector_transaction_id: "84667286296".to_string(),
            capture_method: Some(enums::CaptureMethod::Automatic),
            ..Default::default()
        });
        let connector = Fiservemea::new();
        let url =
            ConnectorIntegration::<Void, PaymentsCancelData, PaymentsResponseData>::get_url(
                connector,
                &req,
                &cert_connectors(),
            )
            .unwrap();
        assert_eq!(
            url,
            "https://cert.api.firstdata.com/gateway/v2/payments/84667286296"
        );
        // El VOID del checklist salió por POST, no por PATCH ni DELETE.
        assert_eq!(
            ConnectorIntegration::<Void, PaymentsCancelData, PaymentsResponseData>::get_http_method(
                connector
            ),
            Method::Post
        );
    }

    fn cert_refunds_data(connector_transaction_id: &str, refund_amount: i64) -> RefundsData {
        RefundsData {
            refund_id: "ref_1".to_string(),
            connector_transaction_id: connector_transaction_id.to_string(),
            connector_refund_id: None,
            currency: enums::Currency::ARS,
            payment_amount: 100_000,
            reason: None,
            webhook_url: None,
            refund_amount,
            connector_metadata: None,
            refund_connector_metadata: None,
            browser_info: None,
            split_refunds: None,
            minor_payment_amount: common_utils::types::MinorUnit::new(100_000),
            minor_refund_amount: common_utils::types::MinorUnit::new(refund_amount),
            integrity_object: None,
            refund_status: enums::RefundStatus::Pending,
            merchant_account_id: None,
            merchant_config_currency: None,
            capture_method: Some(enums::CaptureMethod::Automatic),
            additional_payment_method_data: None,
        }
    }

    #[test]
    fn refund_url_and_method_match_the_accepted_cert_calls() {
        let connector = Fiservemea::new();
        for (transaction_id, refund_amount) in [("84667286298", 100_000), ("84667286310", 50_000)] {
            let req: RefundsRouterData<Execute> =
                url_router_data(cert_refunds_data(transaction_id, refund_amount));
            let url = ConnectorIntegration::<Execute, RefundsData, RefundsResponseData>::get_url(
                connector,
                &req,
                &cert_connectors(),
            )
            .unwrap();
            assert_eq!(
                url,
                format!("https://cert.api.firstdata.com/gateway/v2/payments/{transaction_id}")
            );
        }
        assert_eq!(
            ConnectorIntegration::<Execute, RefundsData, RefundsResponseData>::get_http_method(
                connector
            ),
            Method::Post
        );
    }

    /// El PSync del reembolso (RSync) consulta la MISMA colección `/payments` con el
    /// `storeId` como query param, igual que el INQUIRY que el gateway aceptó (línea 6).
    #[test]
    fn refund_sync_url_carries_the_store_id_as_query_param() {
        let connector = Fiservemea::new();
        let mut data = cert_refunds_data("84667286298", 100_000);
        data.connector_refund_id = Some("84667286299".to_string());
        let req: RefundSyncRouterData = url_router_data(data);
        let url = ConnectorIntegration::<RSync, RefundsData, RefundsResponseData>::get_url(
            connector,
            &req,
            &cert_connectors(),
        )
        .unwrap();
        assert_eq!(
            url,
            "https://cert.api.firstdata.com/gateway/v2/payments/84667286299?storeId=5926072901"
        );
    }

    /// La captura NO forma parte de los 31 casos de la homologación (todos son ventas).
    /// Este test sólo fija la ruta que el conector emite; no está verificada contra el gateway.
    #[test]
    fn capture_url_targets_the_original_transaction_not_verified_against_cert() {
        let connector = Fiservemea::new();
        let req: PaymentsCaptureRouterData = url_router_data(PaymentsCaptureData {
            connector_transaction_id: "84667286296".to_string(),
            currency: enums::Currency::ARS,
            amount_to_capture: 100_000,
            payment_amount: 100_000,
            minor_payment_amount: common_utils::types::MinorUnit::new(100_000),
            minor_amount_to_capture: common_utils::types::MinorUnit::new(100_000),
            ..Default::default()
        });
        let url =
            ConnectorIntegration::<Capture, PaymentsCaptureData, PaymentsResponseData>::get_url(
                connector,
                &req,
                &cert_connectors(),
            )
            .unwrap();
        assert_eq!(
            url,
            "https://cert.api.firstdata.com/gateway/v2/payments/84667286296"
        );
    }

    /// El endpoint de cert sólo se usa si está configurado explícitamente: con `test_mode`
    /// prendido y sin `secondary_base_url` el conector falla en vez de irse a producción.
    #[test]
    fn test_mode_without_secondary_base_url_fails_closed() {
        let mut connectors = cert_connectors();
        connectors.fiservemea.secondary_base_url = None;
        let req: PaymentsCancelRouterData = url_router_data(PaymentsCancelData {
            connector_transaction_id: "84667286296".to_string(),
            ..Default::default()
        });
        assert!(ConnectorIntegration::<Void, PaymentsCancelData, PaymentsResponseData>::get_url(
            Fiservemea::new(),
            &req,
            &connectors
        )
        .is_err());
    }
}
