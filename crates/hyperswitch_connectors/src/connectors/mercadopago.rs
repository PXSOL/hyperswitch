pub mod orders;
pub mod transformers;

use common_enums::enums;
use common_utils::{
    errors::CustomResult,
    ext_traits::{ByteSliceExt, BytesExt},
    request::{Method, Request, RequestBuilder, RequestContent},
    types::{AmountConvertor, FloatMajorUnit, FloatMajorUnitForConnector},
};
use error_stack::ResultExt;
use hyperswitch_domain_models::{
    router_data::{AccessToken, ConnectorAuthType, ErrorResponse, RouterData},
    router_flow_types::{
        access_token_auth::AccessTokenAuth,
        payments::{Authorize, Capture, PSync, PaymentMethodToken, Session, SetupMandate, Void},
        refunds::{Execute, RSync},
    },
    router_request_types::{
        AccessTokenRequestData, PaymentMethodTokenizationData, PaymentsAuthorizeData,
        PaymentsCancelData, PaymentsCaptureData, PaymentsSessionData, PaymentsSyncData,
        RefundsData, SetupMandateRequestData,
    },
    router_response_types::{PaymentsResponseData, RefundsResponseData},
    types::{
        PaymentsAuthorizeRouterData, PaymentsCancelRouterData, PaymentsCaptureRouterData,
        PaymentsSyncRouterData, RefundSyncRouterData, RefundsRouterData,
    },
};
use hyperswitch_interfaces::{
    api::{
        self, ConnectorCommon, ConnectorCommonExt, ConnectorIntegration, ConnectorSpecifications,
        ConnectorValidation,
    },
    configs::Connectors,
    errors,
    events::connector_api_logs::ConnectorEvent,
    types::{self, Response},
    webhooks,
};
use hyperswitch_masking::{Mask, PeekInterface};
use transformers as mercadopago;

use crate::{constants::headers, types::ResponseRouterData, utils, utils::RefundsRequestData};

const PXSOL_PLATFORM_ID: &str = "dev_ab8e21775bb211ed88d80242ac130004";

#[derive(Clone)]
pub struct Mercadopago {
    amount_converter: &'static (dyn AmountConvertor<Output = FloatMajorUnit> + Sync),
}

impl Mercadopago {
    pub fn new() -> &'static Self {
        static INSTANCE: Mercadopago = Mercadopago {
            amount_converter: &FloatMajorUnitForConnector,
        };
        &INSTANCE
    }
}

impl api::Payment for Mercadopago {}
impl api::PaymentSession for Mercadopago {}
impl api::ConnectorAccessToken for Mercadopago {}
impl api::MandateSetup for Mercadopago {}
impl api::PaymentAuthorize for Mercadopago {}
impl api::PaymentSync for Mercadopago {}
impl api::PaymentCapture for Mercadopago {}
impl api::PaymentVoid for Mercadopago {}
impl api::Refund for Mercadopago {}
impl api::RefundExecute for Mercadopago {}
impl api::RefundSync for Mercadopago {}
impl api::PaymentToken for Mercadopago {}

impl ConnectorIntegration<PaymentMethodToken, PaymentMethodTokenizationData, PaymentsResponseData>
    for Mercadopago
{
    fn get_headers(
        &self,
        req: &hyperswitch_domain_models::types::TokenizationRouterData,
        connectors: &Connectors,
    ) -> CustomResult<Vec<(String, hyperswitch_masking::Maskable<String>)>, errors::ConnectorError>
    {
        let mut headers = self.build_headers(req, connectors)?;
        headers.push((
            "x-platform-id".to_string(),
            hyperswitch_masking::Secret::new(PXSOL_PLATFORM_ID.to_string()).into_masked(),
        ));
        Ok(headers)
    }

    fn get_content_type(&self) -> &'static str {
        self.common_get_content_type()
    }

    fn get_url(
        &self,
        _req: &hyperswitch_domain_models::types::TokenizationRouterData,
        connectors: &Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        Ok(format!("{}/v1/card_tokens", self.base_url(connectors)))
    }

    fn get_request_body(
        &self,
        req: &hyperswitch_domain_models::types::TokenizationRouterData,
        _connectors: &Connectors,
    ) -> CustomResult<RequestContent, errors::ConnectorError> {
        let connector_req = mercadopago::MercadopagoTokenRequest::try_from(req)?;
        Ok(RequestContent::Json(Box::new(connector_req)))
    }

    fn build_request(
        &self,
        req: &hyperswitch_domain_models::types::TokenizationRouterData,
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
        data: &hyperswitch_domain_models::types::TokenizationRouterData,
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<
        hyperswitch_domain_models::types::TokenizationRouterData,
        errors::ConnectorError,
    >
    where
        PaymentsResponseData: Clone,
    {
        let response: mercadopago::MercadopagoTokenResponse = res
            .response
            .parse_struct("MercadopagoTokenResponse")
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

impl<Flow, Request, Response> ConnectorCommonExt<Flow, Request, Response> for Mercadopago
where
    Self: ConnectorIntegration<Flow, Request, Response>,
{
    fn build_headers(
        &self,
        req: &RouterData<Flow, Request, Response>,
        _connectors: &Connectors,
    ) -> CustomResult<Vec<(String, hyperswitch_masking::Maskable<String>)>, errors::ConnectorError>
    {
        let mut header = vec![(
            headers::CONTENT_TYPE.to_string(),
            self.get_content_type().to_string().into(),
        )];
        let mut api_key = self.get_auth_header(&req.connector_auth_type)?;
        header.append(&mut api_key);
        Ok(header)
    }
}

impl ConnectorCommon for Mercadopago {
    fn id(&self) -> &'static str {
        "mercadopago"
    }

    fn get_currency_unit(&self) -> api::CurrencyUnit {
        // Mercado Pago expects amounts in the smallest currency unit (cents)
        // but we convert to decimal in the transformers
        api::CurrencyUnit::Minor
    }

    fn common_get_content_type(&self) -> &'static str {
        "application/json"
    }

    fn base_url<'a>(&self, connectors: &'a Connectors) -> &'a str {
        connectors.mercadopago.base_url.as_ref()
    }

    fn get_auth_header(
        &self,
        auth_type: &ConnectorAuthType,
    ) -> CustomResult<Vec<(String, hyperswitch_masking::Maskable<String>)>, errors::ConnectorError>
    {
        let auth = mercadopago::MercadopagoAuthType::try_from(auth_type)
            .change_context(errors::ConnectorError::FailedToObtainAuthType)?;

        // Mercado Pago uses Bearer token authentication
        let auth_header = format!("Bearer {}", auth.api_key.peek());
        Ok(vec![(
            headers::AUTHORIZATION.to_string(),
            auth_header.into_masked(),
        )])
    }

    fn build_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        let response: mercadopago::MercadopagoErrorResponse = res
            .response
            .parse_struct("MercadopagoErrorResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        event_builder.map(|i| i.set_response_body(&response));
        router_env::logger::info!(connector_response=?response);

        Ok(ErrorResponse {
            status_code: res.status_code,
            code: response.get_error_code(),
            message: response.get_error_message(),
            reason: response.get_detailed_reason(),
            attempt_status: None,
            connector_transaction_id: None,
            network_advice_code: None,
            network_decline_code: Some(response.get_error_code()),
            network_error_message: Some(response.get_error_message()),
            connector_metadata: None,
            connector_response_reference_id: None,
        })
    }
}

impl ConnectorValidation for Mercadopago {
    fn validate_psync_reference_id(
        &self,
        _data: &PaymentsSyncData,
        _is_three_ds: bool,
        _status: enums::AttemptStatus,
        _connector_meta_data: Option<common_utils::pii::SecretSerdeValue>,
    ) -> CustomResult<(), errors::ConnectorError> {
        Ok(())
    }
}

impl ConnectorIntegration<Session, PaymentsSessionData, PaymentsResponseData> for Mercadopago {}

impl ConnectorIntegration<AccessTokenAuth, AccessTokenRequestData, AccessToken> for Mercadopago {}

impl ConnectorIntegration<SetupMandate, SetupMandateRequestData, PaymentsResponseData>
    for Mercadopago
{
}

// ============================================================================
// Authorize Flow - POST /v1/payments
// ============================================================================

impl ConnectorIntegration<Authorize, PaymentsAuthorizeData, PaymentsResponseData> for Mercadopago {
    fn get_headers(
        &self,
        req: &PaymentsAuthorizeRouterData,
        connectors: &Connectors,
    ) -> CustomResult<Vec<(String, hyperswitch_masking::Maskable<String>)>, errors::ConnectorError>
    {
        let mut headers = self.build_headers(req, connectors)?;
        // Mercado Pago requires X-Idempotency-Key header
        headers.push((
            "X-Idempotency-Key".to_string(),
            req.connector_request_reference_id.clone().into(),
        ));
        headers.push((
            "x-platform-id".to_string(),
            hyperswitch_masking::Secret::new(PXSOL_PLATFORM_ID.to_string()).into_masked(),
        ));
        // Device fingerprint from Mercado Pago's SDK, for anti-fraud. Resolved like every other
        // Mercado Pago key (scoped `metadata.mercadopago.device_id` first, then flat, then
        // frm_metadata), but on its own: the header is absent only when there is no device id.
        let device_id = mercadopago::MercadopagoMetadata::resolve_device_id(
            req.request.metadata.as_ref(),
            &req.frm_metadata,
        );

        if let Some(device_id) = device_id {
            headers.push((
                "X-meli-session-id".to_string(),
                device_id.peek().to_string().into_masked(),
            ));
        }
        Ok(headers)
    }

    fn get_content_type(&self) -> &'static str {
        self.common_get_content_type()
    }

    fn get_url(
        &self,
        req: &PaymentsAuthorizeRouterData,
        connectors: &Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        // Checkout Pro (hosted checkout) creates a preference; the card-token flow
        // posts a payment directly.
        if mercadopago::MercadopagoAuthorizeRequest::is_checkout_pro(
            &req.request.payment_method_data,
        ) {
            Ok(format!(
                "{}/checkout/preferences",
                self.base_url(connectors)
            ))
        } else if mercadopago::MercadopagoAuthorizeRequest::is_qr(&req.request.payment_method_data)
        {
            Ok(format!("{}/v1/orders", self.base_url(connectors)))
        } else {
            Ok(format!("{}/v1/payments", self.base_url(connectors)))
        }
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

        let connector_router_data = mercadopago::MercadopagoRouterData::from((amount, req));
        let connector_req =
            mercadopago::MercadopagoAuthorizeRequest::try_from(&connector_router_data)?;
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
        if mercadopago::MercadopagoAuthorizeRequest::is_qr(&data.request.payment_method_data) {
            let response: orders::MercadopagoOrderResponse = res
                .response
                .parse_struct("MercadopagoOrderResponse")
                .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
            event_builder.map(|i| i.set_response_body(&response));
            router_env::logger::info!(order_id=%response.id, order_status=?response.status);
            let requested_amount = utils::convert_amount(
                self.amount_converter,
                data.request.minor_amount,
                data.request.currency,
            )?;
            return orders::authorize_order_response(
                ResponseRouterData {
                    response,
                    data: data.clone(),
                    http_code: res.status_code,
                },
                data.request.currency,
                requested_amount,
            );
        }
        let response: mercadopago::MercadopagoAuthorizeResponse = res
            .response
            .parse_struct("MercadopagoAuthorizeResponse")
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

// ============================================================================
// Payment Sync Flow - GET /v1/payments/{id}
// ============================================================================

impl ConnectorIntegration<PSync, PaymentsSyncData, PaymentsResponseData> for Mercadopago {
    fn get_headers(
        &self,
        req: &PaymentsSyncRouterData,
        connectors: &Connectors,
    ) -> CustomResult<Vec<(String, hyperswitch_masking::Maskable<String>)>, errors::ConnectorError>
    {
        self.build_headers(req, connectors)
    }

    fn get_content_type(&self) -> &'static str {
        self.common_get_content_type()
    }

    fn get_url(
        &self,
        req: &PaymentsSyncRouterData,
        connectors: &Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        let base_url = self.base_url(connectors);

        // Checkout Pro: the MP payment id does not exist until the buyer pays, so a
        // wallet attempt without a transaction id syncs by searching OUR
        // external_reference. The payment_id from the redirect query string is
        // deliberately NOT used: it is buyer-controllable input (cross-payment
        // substitution / bogus-id kills). The resource_id the sync returns is
        // persisted on the attempt, promoting the real id.
        match req
            .request
            .connector_transaction_id
            .get_connector_transaction_id()
        {
            // An `ORD` id (QR) syncs the order, a numeric id the payment.
            Ok(connector_payment_id) => Ok(format!(
                "{base_url}{}",
                orders::psync_path(&connector_payment_id)
            )),
            Err(_) if req.payment_method == enums::PaymentMethod::Wallet => Ok(format!(
                "{}/v1/payments/search?external_reference={}&sort=date_created&criteria=desc",
                base_url, req.connector_request_reference_id
            )),
            // Card-flow attempts always have the id from Authorize; without it there
            // is nothing safe to sync against (keeps the pre-Checkout-Pro behavior).
            Err(err) => {
                Err(err).change_context(errors::ConnectorError::MissingConnectorTransactionID)
            }
        }
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
        let is_order = data
            .request
            .connector_transaction_id
            .get_connector_transaction_id()
            .is_ok_and(|id| orders::is_order_id(&id));
        if is_order {
            let response: orders::MercadopagoOrderResponse = res
                .response
                .parse_struct("MercadopagoOrderResponse")
                .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
            event_builder.map(|i| i.set_response_body(&response));
            router_env::logger::info!(connector_response=?response);
            let reported_activity = response.reported_activity(data.request.currency);
            let mut router_data = orders::sync_order_response(ResponseRouterData {
                response,
                data: data.clone(),
                http_code: res.status_code,
            });
            if let Some(reported_activity) = reported_activity {
                match router_data.connector_response.as_mut() {
                    Some(connector_response) => {
                        connector_response.set_reported_activity(reported_activity);
                    }
                    None => {
                        router_data.connector_response = Some(
                            hyperswitch_domain_models::router_data::ConnectorResponseData::with_reported_activity(
                                reported_activity,
                            ),
                        );
                    }
                }
            }
            return Ok(router_data);
        }
        let response: mercadopago::MercadopagoPSyncResponse = res
            .response
            .parse_struct("MercadopagoPSyncResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
        event_builder.map(|i| i.set_response_body(&response));
        router_env::logger::info!(connector_response=?response);

        // Built from the response BEFORE it is consumed by `try_from` below,
        // using the request's own currency (`data`, concretely typed here as
        // `PaymentsSyncRouterData`) rather than the connector's `currency_id`
        // string.
        let reported_activity = response
            .resolved_payment()
            .and_then(|payment| payment.reported_activity(data.request.currency));

        let mut router_data = RouterData::try_from(ResponseRouterData {
            response,
            data: data.clone(),
            http_code: res.status_code,
        })?;
        // Checkout Pro keeps its preference data in `connector_metadata`: the receipt of the
        // payment is added on top of it instead of replacing it.
        utils::keep_stored_metadata(&mut router_data, data.request.connector_meta.as_ref());

        if let Some(reported_activity) = reported_activity {
            // Merge into an existing `connector_response` (e.g. carried over
            // via `..item.data` from the request's `RouterData`) instead of
            // replacing it wholesale, so any other field already set on it
            // is never silently dropped.
            match router_data.connector_response.as_mut() {
                Some(connector_response) => {
                    connector_response.set_reported_activity(reported_activity);
                }
                None => {
                    router_data.connector_response = Some(
                        hyperswitch_domain_models::router_data::ConnectorResponseData::with_reported_activity(
                            reported_activity,
                        ),
                    );
                }
            }
        }

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

// ============================================================================
// Capture Flow - PUT /v1/payments/{id}
// ============================================================================

impl ConnectorIntegration<Capture, PaymentsCaptureData, PaymentsResponseData> for Mercadopago {
    fn get_headers(
        &self,
        req: &PaymentsCaptureRouterData,
        connectors: &Connectors,
    ) -> CustomResult<Vec<(String, hyperswitch_masking::Maskable<String>)>, errors::ConnectorError>
    {
        let mut headers = self.build_headers(req, connectors)?;
        headers.push((
            "X-Idempotency-Key".to_string(),
            format!("{}_capture", req.connector_request_reference_id).into(),
        ));
        Ok(headers)
    }

    fn get_content_type(&self) -> &'static str {
        self.common_get_content_type()
    }

    fn get_url(
        &self,
        req: &PaymentsCaptureRouterData,
        connectors: &Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        Ok(format!(
            "{}/v1/payments/{}",
            self.base_url(connectors),
            req.request.connector_transaction_id
        ))
    }

    fn get_request_body(
        &self,
        req: &PaymentsCaptureRouterData,
        _connectors: &Connectors,
    ) -> CustomResult<RequestContent, errors::ConnectorError> {
        let amount_to_capture = utils::convert_amount(
            self.amount_converter,
            req.request.minor_amount_to_capture,
            req.request.currency,
        )?;
        let connector_router_data =
            mercadopago::MercadopagoRouterData::from((amount_to_capture, req));
        let connector_req =
            mercadopago::MercadopagoCaptureRequest::try_from(&connector_router_data)?;
        Ok(RequestContent::Json(Box::new(connector_req)))
    }

    fn build_request(
        &self,
        req: &PaymentsCaptureRouterData,
        connectors: &Connectors,
    ) -> CustomResult<Option<Request>, errors::ConnectorError> {
        Ok(Some(
            RequestBuilder::new()
                .method(Method::Put)
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
        let response: mercadopago::MercadopagoPaymentsResponse = res
            .response
            .parse_struct("MercadopagoPaymentsResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
        event_builder.map(|i| i.set_response_body(&response));
        router_env::logger::info!(connector_response=?response);
        let mut router_data = RouterData::try_from(ResponseRouterData {
            response,
            data: data.clone(),
            http_code: res.status_code,
        })?;
        utils::keep_stored_metadata(&mut router_data, data.request.connector_meta.as_ref());
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

// ============================================================================
// Void Flow - PUT /v1/payments/{id} with status=cancelled
// ============================================================================

impl ConnectorIntegration<Void, PaymentsCancelData, PaymentsResponseData> for Mercadopago {
    fn get_headers(
        &self,
        req: &PaymentsCancelRouterData,
        connectors: &Connectors,
    ) -> CustomResult<Vec<(String, hyperswitch_masking::Maskable<String>)>, errors::ConnectorError>
    {
        let mut headers = self.build_headers(req, connectors)?;
        headers.push((
            "X-Idempotency-Key".to_string(),
            format!("{}_void", req.connector_request_reference_id).into(),
        ));
        Ok(headers)
    }

    fn get_content_type(&self) -> &'static str {
        self.common_get_content_type()
    }

    fn get_url(
        &self,
        req: &PaymentsCancelRouterData,
        connectors: &Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        Ok(format!(
            "{}{}",
            self.base_url(connectors),
            orders::void_path(&req.request.connector_transaction_id)
        ))
    }

    fn get_request_body(
        &self,
        _req: &PaymentsCancelRouterData,
        _connectors: &Connectors,
    ) -> CustomResult<RequestContent, errors::ConnectorError> {
        let connector_req = mercadopago::MercadopagoCancelRequest::default();
        Ok(RequestContent::Json(Box::new(connector_req)))
    }

    fn build_request(
        &self,
        req: &PaymentsCancelRouterData,
        connectors: &Connectors,
    ) -> CustomResult<Option<Request>, errors::ConnectorError> {
        // An order is cancelled with a bodyless POST; a payment with a PUT of its new status.
        if orders::is_order_id(&req.request.connector_transaction_id) {
            return Ok(Some(
                RequestBuilder::new()
                    .method(Method::Post)
                    .url(&types::PaymentsVoidType::get_url(self, req, connectors)?)
                    .attach_default_headers()
                    .headers(types::PaymentsVoidType::get_headers(self, req, connectors)?)
                    .build(),
            ));
        }
        Ok(Some(
            RequestBuilder::new()
                .method(Method::Put)
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
        if orders::is_order_id(&data.request.connector_transaction_id) {
            let response: orders::MercadopagoOrderResponse = res
                .response
                .parse_struct("MercadopagoOrderResponse")
                .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
            event_builder.map(|i| i.set_response_body(&response));
            router_env::logger::info!(connector_response=?response);
            return Ok(orders::sync_order_response(ResponseRouterData {
                response,
                data: data.clone(),
                http_code: res.status_code,
            }));
        }
        let response: mercadopago::MercadopagoPaymentsResponse = res
            .response
            .parse_struct("MercadopagoPaymentsResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
        event_builder.map(|i| i.set_response_body(&response));
        router_env::logger::info!(connector_response=?response);
        let mut router_data = RouterData::try_from(ResponseRouterData {
            response,
            data: data.clone(),
            http_code: res.status_code,
        })?;
        utils::keep_stored_metadata(&mut router_data, data.request.connector_meta.as_ref());
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

// ============================================================================
// Refund Execute Flow - POST /v1/payments/{id}/refunds
// ============================================================================

impl ConnectorIntegration<Execute, RefundsData, RefundsResponseData> for Mercadopago {
    fn get_headers(
        &self,
        req: &RefundsRouterData<Execute>,
        connectors: &Connectors,
    ) -> CustomResult<Vec<(String, hyperswitch_masking::Maskable<String>)>, errors::ConnectorError>
    {
        let mut headers = self.build_headers(req, connectors)?;
        headers.push((
            "X-Idempotency-Key".to_string(),
            req.request.refund_id.clone().into(),
        ));
        Ok(headers)
    }

    fn get_content_type(&self) -> &'static str {
        self.common_get_content_type()
    }

    fn get_url(
        &self,
        req: &RefundsRouterData<Execute>,
        connectors: &Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        Ok(format!(
            "{}{}",
            self.base_url(connectors),
            orders::refund_path(&req.request.connector_transaction_id)
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

        let connector_router_data = mercadopago::MercadopagoRouterData::from((refund_amount, req));
        if orders::is_order_id(&req.request.connector_transaction_id) {
            let connector_req =
                orders::MercadopagoOrderRefundRequest::try_from(&connector_router_data)?;
            return Ok(RequestContent::Json(Box::new(connector_req)));
        }
        let connector_req =
            mercadopago::MercadopagoRefundRequest::try_from(&connector_router_data)?;
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
        if orders::is_order_id(&data.request.connector_transaction_id) {
            let response: orders::MercadopagoOrderResponse = res
                .response
                .parse_struct("MercadopagoOrderResponse")
                .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
            event_builder.map(|i| i.set_response_body(&response));
            router_env::logger::info!(connector_response=?response);
            return RouterData::try_from(crate::types::RefundsResponseRouterData {
                response,
                data: data.clone(),
                http_code: res.status_code,
            });
        }
        let response: mercadopago::RefundResponse = res
            .response
            .parse_struct("MercadopagoRefundResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
        event_builder.map(|i| i.set_response_body(&response));
        router_env::logger::info!(connector_response=?response);
        RouterData::try_from(crate::types::RefundsResponseRouterData {
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

// ============================================================================
// Refund Sync Flow - GET /v1/payments/{payment_id}/refunds/{refund_id}
// ============================================================================

impl ConnectorIntegration<RSync, RefundsData, RefundsResponseData> for Mercadopago {
    fn get_headers(
        &self,
        req: &RefundSyncRouterData,
        connectors: &Connectors,
    ) -> CustomResult<Vec<(String, hyperswitch_masking::Maskable<String>)>, errors::ConnectorError>
    {
        self.build_headers(req, connectors)
    }

    fn get_content_type(&self) -> &'static str {
        self.common_get_content_type()
    }

    fn get_url(
        &self,
        req: &RefundSyncRouterData,
        connectors: &Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        Ok(format!(
            "{}{}",
            self.base_url(connectors),
            orders::refund_sync_path(
                &req.request.connector_transaction_id,
                &req.request.get_connector_refund_id()?
            )
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
                .build(),
        ))
    }

    fn handle_response(
        &self,
        data: &RefundSyncRouterData,
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<RefundSyncRouterData, errors::ConnectorError> {
        if orders::is_order_id(&data.request.connector_transaction_id) {
            let response: orders::MercadopagoOrderResponse = res
                .response
                .parse_struct("MercadopagoOrderResponse")
                .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
            event_builder.map(|i| i.set_response_body(&response));
            router_env::logger::info!(connector_response=?response);
            return RouterData::try_from(crate::types::RefundsResponseRouterData {
                response,
                data: data.clone(),
                http_code: res.status_code,
            });
        }
        let response: mercadopago::RefundResponse = res
            .response
            .parse_struct("MercadopagoRefundResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
        event_builder.map(|i| i.set_response_body(&response));
        router_env::logger::info!(connector_response=?response);
        RouterData::try_from(crate::types::RefundsResponseRouterData {
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

// ============================================================================
// Webhooks
// ============================================================================

/// Extract the id from query params (for IPN legacy notifications)
fn extract_ipn_id_from_query(query_params: &str) -> Option<String> {
    for param in query_params.split('&') {
        let mut kv = param.splitn(2, '=');
        if let (Some(key), Some(value)) = (kv.next(), kv.next()) {
            if key == "id" {
                return Some(value.to_string());
            }
        }
    }
    None
}

fn extract_query_param(query_params: &str, wanted: &str) -> Option<String> {
    query_params.split('&').find_map(|param| {
        let (key, value) = param.split_once('=')?;
        (key == wanted && !value.is_empty()).then(|| value.to_string())
    })
}

/// Extract the topic from query params (for IPN legacy notifications)
fn extract_topic_from_query(query_params: &str) -> Option<String> {
    for param in query_params.split('&') {
        let mut kv = param.splitn(2, '=');
        if let (Some(key), Some(value)) = (kv.next(), kv.next()) {
            if key == "topic" {
                return Some(value.to_string());
            }
        }
    }
    None
}

/// Classifies an incoming Mercado Pago webhook across every wire format: the
/// body first (Webhooks v1 / app-level chargeback push, or Feed v2), falling
/// back to the IPN legacy `topic`/`id` query params when the body doesn't
/// parse as either. `get_webhook_event_type` and `get_webhook_object_reference_id`
/// both go through this so they can never disagree with each other.
fn classify_mercadopago_webhook(
    request: &webhooks::IncomingWebhookRequestDetails<'_>,
) -> mercadopago::MercadopagoWebhookNotification {
    if let Ok(webhook_body) = request
        .body
        .parse_struct::<mercadopago::MercadopagoWebhookBodyEnum>("MercadopagoWebhookBodyEnum")
    {
        return webhook_body.classify();
    }

    // Orders API delivery: ?type=order&data.id=ORD...&data.external_reference=...
    if extract_query_param(&request.query_params, "type").as_deref() == Some("order") {
        if let Some(order_id) = extract_query_param(&request.query_params, "data.id") {
            return mercadopago::MercadopagoWebhookNotification::Order { order_id };
        }
    }

    // IPN legacy URL format: ?topic=payment&id=123456789
    let topic = extract_topic_from_query(&request.query_params);
    let id = extract_ipn_id_from_query(&request.query_params);
    match (topic.as_deref(), id) {
        (Some("payment"), Some(payment_id)) => {
            mercadopago::MercadopagoWebhookNotification::Payment { payment_id }
        }
        // The IPN chargeback notification carries only the chargeback id,
        // never the payment it applies to — never treat that id as a
        // payment id.
        (Some("chargebacks"), Some(_chargeback_id)) => {
            mercadopago::MercadopagoWebhookNotification::ChargebackWithoutPayment
        }
        _ => mercadopago::MercadopagoWebhookNotification::Unknown,
    }
}

#[async_trait::async_trait]
impl webhooks::IncomingWebhook for Mercadopago {
    /// Always `false`: Mercado Pago notifications carry only a resource id,
    /// never a status or amount, so their state is always fetched fresh from
    /// MP's own API using the merchant's credentials (see
    /// `classify_mercadopago_webhook`). Returning
    /// `true` here would make core treat the id-only webhook body itself as
    /// a PSync response via `HandleResponse` — which the PSync parser above
    /// cannot read (it expects the full payment object MP's API returns, not
    /// a webhook notification). Since every notification just triggers a
    /// live PSync regardless of its authenticity, an unverified notification
    /// can at worst cause one extra API read against MP.
    async fn verify_webhook_source(
        &self,
        _request: &webhooks::IncomingWebhookRequestDetails<'_>,
        _merchant_id: &common_utils::id_type::MerchantId,
        _connector_webhook_details: Option<common_utils::pii::SecretSerdeValue>,
        _connector_account_details: common_utils::crypto::Encryptable<
            hyperswitch_masking::Secret<serde_json::Value>,
        >,
        _connector_name: &str,
    ) -> CustomResult<bool, errors::ConnectorError> {
        Ok(false)
    }

    fn get_webhook_object_reference_id(
        &self,
        request: &webhooks::IncomingWebhookRequestDetails<'_>,
    ) -> CustomResult<api_models::webhooks::ObjectReferenceId, errors::ConnectorError> {
        classify_mercadopago_webhook(request)
            .payment_id_to_sync()
            .map(|payment_id| {
                api_models::webhooks::ObjectReferenceId::PaymentId(
                    api_models::payments::PaymentIdType::ConnectorTransactionId(
                        payment_id.to_string(),
                    ),
                )
            })
            .ok_or_else(|| errors::ConnectorError::WebhookReferenceIdNotFound.into())
    }

    fn get_webhook_event_type(
        &self,
        request: &webhooks::IncomingWebhookRequestDetails<'_>,
        _context: Option<&webhooks::WebhookContext>,
    ) -> CustomResult<api_models::webhooks::IncomingWebhookEvent, errors::ConnectorError> {
        Ok(api_models::webhooks::IncomingWebhookEvent::from(
            &classify_mercadopago_webhook(request),
        ))
    }

    fn get_webhook_resource_object(
        &self,
        request: &webhooks::IncomingWebhookRequestDetails<'_>,
    ) -> CustomResult<Box<dyn hyperswitch_masking::ErasedMaskSerialize>, errors::ConnectorError>
    {
        // Webhooks v1 (full) or Feed v2 (resource + topic) carry a JSON body; a
        // legacy IPN carries only `?topic=...&id=...`, so fall back to the query
        // (as `get_webhook_object_reference_id` does) instead of rejecting it.
        if let Ok(webhook_body) = request
            .body
            .parse_struct::<mercadopago::MercadopagoWebhookBodyEnum>("MercadopagoWebhookBodyEnum")
        {
            return Ok(Box::new(webhook_body.to_resource_object()));
        }

        match (
            extract_ipn_id_from_query(&request.query_params),
            extract_topic_from_query(&request.query_params),
        ) {
            (Some(resource_id), Some(topic)) => {
                Ok(Box::new(mercadopago::MercadopagoWebhookResourceObject {
                    resource_id,
                    topic,
                    action: None,
                }))
            }
            _ => Err(errors::ConnectorError::WebhookResourceObjectNotFound.into()),
        }
    }
}

// ============================================================================
// Connector Specifications
// ============================================================================

use std::sync::LazyLock;

use hyperswitch_domain_models::router_response_types::{
    ConnectorInfo, PaymentMethodDetails, SupportedPaymentMethods, SupportedPaymentMethodsExt,
};

static MERCADOPAGO_SUPPORTED_PAYMENT_METHODS: LazyLock<SupportedPaymentMethods> =
    LazyLock::new(|| {
        let mut supported_payment_methods = SupportedPaymentMethods::new();

        let supported_capture_methods = vec![
            enums::CaptureMethod::Automatic,
            enums::CaptureMethod::Manual,
        ];

        // Add Card Credit payment method
        supported_payment_methods.add(
            enums::PaymentMethod::Card,
            enums::PaymentMethodType::Credit,
            PaymentMethodDetails {
                mandates: enums::FeatureStatus::NotSupported,
                refunds: enums::FeatureStatus::Supported,
                supported_capture_methods: supported_capture_methods.clone(),
                specific_features: None,
            },
        );

        // Add Card Debit payment method
        supported_payment_methods.add(
            enums::PaymentMethod::Card,
            enums::PaymentMethodType::Debit,
            PaymentMethodDetails {
                mandates: enums::FeatureStatus::NotSupported,
                refunds: enums::FeatureStatus::Supported,
                supported_capture_methods,
                specific_features: None,
            },
        );

        // Checkout Pro (hosted checkout redirect). Auto-capture only: the payment is
        // created and captured by Mercado Pago on its hosted page. Without this entry
        // the router rejects wallet payments before reaching the connector
        // (validate_connector_against_payment_request).
        supported_payment_methods.add(
            enums::PaymentMethod::Wallet,
            enums::PaymentMethodType::MercadoPago,
            PaymentMethodDetails {
                mandates: enums::FeatureStatus::NotSupported,
                refunds: enums::FeatureStatus::Supported,
                supported_capture_methods: vec![enums::CaptureMethod::Automatic],
                specific_features: None,
            },
        );

        supported_payment_methods
    });

static MERCADOPAGO_CONNECTOR_INFO: ConnectorInfo = ConnectorInfo {
    display_name: "Mercado Pago",
    description: "Mercado Pago payment gateway for Latin America",
    connector_type: enums::HyperswitchConnectorCategory::PaymentGateway,
    integration_status: enums::ConnectorIntegrationStatus::Sandbox,
};

static MERCADOPAGO_SUPPORTED_WEBHOOK_FLOWS: [enums::EventClass; 2] =
    [enums::EventClass::Payments, enums::EventClass::Refunds];

impl ConnectorSpecifications for Mercadopago {
    fn get_connector_about(&self) -> Option<&'static ConnectorInfo> {
        Some(&MERCADOPAGO_CONNECTOR_INFO)
    }

    fn get_supported_payment_methods(&self) -> Option<&'static SupportedPaymentMethods> {
        Some(&*MERCADOPAGO_SUPPORTED_PAYMENT_METHODS)
    }

    fn get_supported_webhook_flows(&self) -> Option<&'static [enums::EventClass]> {
        Some(&MERCADOPAGO_SUPPORTED_WEBHOOK_FLOWS)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Classifies an IPN legacy notification given only its query params. An
    /// empty body always fails to parse as `MercadopagoWebhookBodyEnum`
    /// (neither the Full nor Feed shape matches), forcing
    /// `classify_mercadopago_webhook` into the query-params fallback these
    /// tests exercise.
    fn classify_ipn(query_params: &str) -> mercadopago::MercadopagoWebhookNotification {
        let headers = actix_web::http::header::HeaderMap::new();
        let request = webhooks::IncomingWebhookRequestDetails {
            method: http::Method::GET,
            uri: "/webhooks/mercadopago".parse().expect("valid test uri"),
            headers: &headers,
            body: b"",
            query_params: query_params.to_string(),
        };
        classify_mercadopago_webhook(&request)
    }

    #[test]
    fn ipn_resource_object_falls_back_to_query_params() {
        let headers = actix_web::http::header::HeaderMap::new();
        for body in [b"".as_slice(), b"{}".as_slice()] {
            let request = webhooks::IncomingWebhookRequestDetails {
                method: http::Method::POST,
                uri: "/webhooks/mercadopago".parse().expect("valid test uri"),
                headers: &headers,
                body,
                query_params: "topic=payment&id=150211668619".to_string(),
            };
            assert!(
                webhooks::IncomingWebhook::get_webhook_resource_object(
                    Mercadopago::new(),
                    &request
                )
                .is_ok(),
                "an IPN (query-only) notification must not be rejected"
            );
        }

        let request = webhooks::IncomingWebhookRequestDetails {
            method: http::Method::POST,
            uri: "/webhooks/mercadopago".parse().expect("valid test uri"),
            headers: &headers,
            body: b"{}",
            query_params: String::new(),
        };
        assert!(webhooks::IncomingWebhook::get_webhook_resource_object(
            Mercadopago::new(),
            &request
        )
        .is_err());
    }

    #[test]
    fn ipn_payment_topic_resyncs_that_payment_id() {
        let notification = classify_ipn("topic=payment&id=150211668619");
        assert_eq!(
            notification,
            mercadopago::MercadopagoWebhookNotification::Payment {
                payment_id: "150211668619".to_string()
            }
        );
        assert_eq!(notification.payment_id_to_sync(), Some("150211668619"));
        assert_eq!(
            api_models::webhooks::IncomingWebhookEvent::from(&notification),
            api_models::webhooks::IncomingWebhookEvent::PaymentIntentProcessing
        );
    }

    #[test]
    fn ipn_chargebacks_topic_is_not_supported_and_never_looked_up_by_id() {
        let notification = classify_ipn("topic=chargebacks&id=cb_123");
        assert_eq!(
            notification,
            mercadopago::MercadopagoWebhookNotification::ChargebackWithoutPayment
        );
        // The chargeback id must never be used as a payment id to sync.
        assert_eq!(notification.payment_id_to_sync(), None);
        assert_eq!(
            api_models::webhooks::IncomingWebhookEvent::from(&notification),
            api_models::webhooks::IncomingWebhookEvent::EventNotSupported
        );
    }

    #[test]
    fn ipn_missing_or_unknown_topic_is_not_supported() {
        for query in ["", "topic=something_else&id=1", "id=1"] {
            let notification = classify_ipn(query);
            assert_eq!(
                notification,
                mercadopago::MercadopagoWebhookNotification::Unknown,
                "query={query}"
            );
            assert_eq!(
                api_models::webhooks::IncomingWebhookEvent::from(&notification),
                api_models::webhooks::IncomingWebhookEvent::EventNotSupported
            );
        }
    }

    const ORDER_ID: &str = "ORDTST00000000000000000000000BBB";

    fn order_webhook_body(action: &str, status: &str) -> String {
        serde_json::json!({
            "action": action,
            "api_version": "v1",
            "application_id": "1111111111111111",
            "data": {
                "currency_id": "ARS",
                "external_reference": "pxs_1_1",
                "id": ORDER_ID,
                "status": status,
                "status_detail": status,
                "transactions": {"payments": [{"amount": "150.00", "id": "PAY1", "status": status}]},
                "type": "qr",
                "version": 3
            },
            "date_created": "2026-11-04T17:16:50.061675458Z",
            "live_mode": false,
            "type": "order",
            "user_id": "2222222222"
        })
        .to_string()
    }

    fn classify_body(
        body: &str,
        query_params: &str,
    ) -> mercadopago::MercadopagoWebhookNotification {
        let headers = actix_web::http::header::HeaderMap::new();
        let request = webhooks::IncomingWebhookRequestDetails {
            method: http::Method::POST,
            uri: "/webhooks/mercadopago".parse().expect("valid test uri"),
            headers: &headers,
            body: body.as_bytes(),
            query_params: query_params.to_string(),
        };
        classify_mercadopago_webhook(&request)
    }

    #[test]
    fn every_order_action_resyncs_the_order_id() {
        for (action, status) in [
            ("order.processed", "processed"),
            ("order.failed", "failed"),
            ("order.canceled", "canceled"),
            ("order.expired", "expired"),
            ("order.action_required", "action_required"),
            ("order.refunded", "refunded"),
            ("order.created", "created"),
        ] {
            let notification = classify_body(
                &order_webhook_body(action, status),
                &format!("data.external_reference=pxs_1_1&data.id={ORDER_ID}&type=order"),
            );
            assert_eq!(
                notification,
                mercadopago::MercadopagoWebhookNotification::Order {
                    order_id: ORDER_ID.to_string()
                },
                "{action}"
            );
            assert_eq!(notification.payment_id_to_sync(), Some(ORDER_ID));
            assert_eq!(
                api_models::webhooks::IncomingWebhookEvent::from(&notification),
                api_models::webhooks::IncomingWebhookEvent::PaymentIntentProcessing
            );
        }
    }

    #[test]
    fn order_webhook_reference_id_is_the_connector_transaction_id() {
        let headers = actix_web::http::header::HeaderMap::new();
        let body = order_webhook_body("order.processed", "processed");
        let request = webhooks::IncomingWebhookRequestDetails {
            method: http::Method::POST,
            uri: "/webhooks/mercadopago".parse().expect("valid test uri"),
            headers: &headers,
            body: body.as_bytes(),
            query_params: String::new(),
        };
        let reference = webhooks::IncomingWebhook::get_webhook_object_reference_id(
            Mercadopago::new(),
            &request,
        )
        .expect("order webhooks carry a reference");
        assert!(matches!(
            reference,
            api_models::webhooks::ObjectReferenceId::PaymentId(
                api_models::payments::PaymentIdType::ConnectorTransactionId(ref id)
            ) if id == ORDER_ID
        ));
    }

    #[test]
    fn order_webhook_status_in_the_body_is_never_trusted() {
        // Whatever the body claims, the notification only names the order to read back.
        let notification = classify_body(&order_webhook_body("order.processed", "failed"), "");
        assert_eq!(notification.payment_id_to_sync(), Some(ORDER_ID));
    }

    #[test]
    fn order_query_params_are_enough_when_the_body_is_empty() {
        let notification = classify_body(
            "",
            &format!("data.external_reference=pxs_1_1&data.id={ORDER_ID}&type=order"),
        );
        assert_eq!(notification.payment_id_to_sync(), Some(ORDER_ID));
        assert_eq!(
            classify_body("", "type=order"),
            mercadopago::MercadopagoWebhookNotification::Unknown
        );
    }

    /// The `X-meli-session-id` header (Mercado Pago's device fingerprint for anti-fraud) of
    /// a card charge with the given metadata, if any.
    fn device_session_header(
        metadata: Option<serde_json::Value>,
        frm_metadata: Option<serde_json::Value>,
    ) -> Option<String> {
        let router_data = mercadopago::test_support::authorize_router_data(metadata, frm_metadata);
        let headers =
            ConnectorIntegration::<Authorize, PaymentsAuthorizeData, PaymentsResponseData>::get_headers(
                Mercadopago::new(),
                &router_data,
                &Connectors::default(),
            )
            .expect("authorize headers build");
        headers
            .into_iter()
            .find(|(name, _)| name == "X-meli-session-id")
            .map(|(_, value)| value.into_inner())
    }

    #[test]
    fn device_session_header_reads_the_scoped_device_id() {
        // What api2 sends.
        let scoped = serde_json::json!({ "mercadopago": { "device_id": "dev-scoped" } });
        assert_eq!(
            device_session_header(Some(scoped), None).as_deref(),
            Some("dev-scoped")
        );

        // The scoped value wins over the flat one, like every other Mercado Pago key.
        let both = serde_json::json!({
            "device_id": "dev-flat",
            "mercadopago": { "device_id": "dev-scoped" }
        });
        assert_eq!(
            device_session_header(Some(both), None).as_deref(),
            Some("dev-scoped")
        );
    }

    #[test]
    fn device_session_header_reads_the_flat_device_id() {
        // What PPS sends: the device id flat, next to the scoped Mercado Pago object.
        let flat = serde_json::json!({
            "device_id": "dev-flat",
            "mercadopago": { "payment_method_id": "visa" }
        });
        assert_eq!(
            device_session_header(Some(flat), None).as_deref(),
            Some("dev-flat")
        );
    }

    #[test]
    fn device_session_header_is_absent_without_a_device_id() {
        assert_eq!(device_session_header(None, None), None);
        let without = serde_json::json!({ "mercadopago": { "payment_method_id": "visa" } });
        assert_eq!(device_session_header(Some(without), None), None);
    }

    #[test]
    fn device_session_header_survives_an_unrelated_key_of_unexpected_type() {
        let metadata = serde_json::json!({
            "device_id": "dev-flat",
            "installments": "three",
            "item": "not an object"
        });
        assert_eq!(
            device_session_header(Some(metadata), None).as_deref(),
            Some("dev-flat")
        );
    }

    #[test]
    fn device_session_header_falls_back_to_frm_metadata() {
        let frm = serde_json::json!({ "device_id": "dev-frm" });
        assert_eq!(
            device_session_header(None, Some(frm.clone())).as_deref(),
            Some("dev-frm")
        );
        let request = serde_json::json!({ "device_id": "dev-request" });
        assert_eq!(
            device_session_header(Some(request), Some(frm.clone())).as_deref(),
            Some("dev-request")
        );

        // api2's direct card flow (and the PMS charge): request metadata with the guest's
        // keys but no device id, the device id flat in frm_metadata.
        let guest = serde_json::json!({
            "email": "guest@example.com",
            "first_name": "Ana",
            "installments_info": { "original_amount": 1000 },
            "psp": { "name": "mercadopago", "metadata": {} }
        });
        assert_eq!(
            device_session_header(Some(guest), Some(frm)).as_deref(),
            Some("dev-frm")
        );
    }

    #[test]
    fn payment_webhooks_are_unaffected_by_order_support() {
        let body = r#"{"action":"payment.updated","api_version":"v1","data":{"id":"150211668619"},"live_mode":true,"type":"payment","date_created":"2026-11-04T00:00:00Z"}"#;
        assert_eq!(
            classify_body(body, ""),
            mercadopago::MercadopagoWebhookNotification::Payment {
                payment_id: "150211668619".to_string()
            }
        );
    }
}
