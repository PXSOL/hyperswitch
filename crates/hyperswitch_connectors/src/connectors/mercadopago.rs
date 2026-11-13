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
            || mercadopago::MercadopagoAuthorizeRequest::is_point(&req.request.payment_method_data)
        {
            // QR and Point are both orders; the body tells them apart.
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
        let is_point =
            mercadopago::MercadopagoAuthorizeRequest::is_point(&data.request.payment_method_data);
        if is_point
            || mercadopago::MercadopagoAuthorizeRequest::is_qr(&data.request.payment_method_data)
        {
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
            let item = ResponseRouterData {
                response,
                data: data.clone(),
                http_code: res.status_code,
            };
            if is_point {
                return Ok(orders::authorize_point_order_response(
                    item,
                    data.request.currency,
                    requested_amount,
                ));
            }
            return orders::authorize_order_response(item, data.request.currency, requested_amount);
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
            // An `ORD` id (QR, Point) syncs the order, a numeric id the payment.
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
            let mut router_data = orders::sync_order_response(
                ResponseRouterData {
                    response,
                    data: data.clone(),
                    http_code: res.status_code,
                },
                data.request.connector_meta.as_ref(),
            );
            // What a Point order returns is added to what its attempt already stores. A QR
            // order returns nothing, which leaves its stored metadata untouched.
            utils::keep_stored_metadata(&mut router_data, data.request.connector_meta.as_ref());
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
        // Only the cancel of a Point order carries it; a QR order is cancelled as before.
        if let Some((name, value)) =
            orders::point_cancel_header(req.request.connector_meta.as_ref())
        {
            headers.push((name.to_string(), value.to_string().into()));
        }
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
            let mut router_data = orders::sync_order_response(
                ResponseRouterData {
                    response,
                    data: data.clone(),
                    http_code: res.status_code,
                },
                data.request.connector_meta.as_ref(),
            );
            utils::keep_stored_metadata(&mut router_data, data.request.connector_meta.as_ref());
            return Ok(router_data);
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
        // An order Mercado Pago refuses to cancel is still alive and can be paid: the attempt
        // keeps waiting instead of taking the failure core gives a refused void. A body that
        // does not parse is reported by `build_error_response` below.
        let attempt_status = res
            .response
            .parse_struct::<mercadopago::MercadopagoErrorResponse>("MercadopagoErrorResponse")
            .ok()
            .and_then(|error| {
                orders::attempt_status_after_refused_order_cancel(res.status_code, &error)
            });
        let error = self.build_error_response(res, event_builder)?;
        Ok(ErrorResponse {
            attempt_status,
            ..error
        })
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

    // ------------------------------------------------------------------------
    // Point (card terminal) through the connector's own entry points. The order bodies keep
    // the fields recorded from the real N950 tests, with payer data left out.
    // ------------------------------------------------------------------------

    use common_utils::types::MinorUnit;
    use hyperswitch_domain_models::{
        payment_address::PaymentAddress,
        payment_method_data::{PaymentMethodData, WalletData},
        router_request_types::ResponseId,
    };
    use serde_json::json;

    const POINT_TERMINAL_ID: &str = "NEWLAND_N950__N950NCD600391917";
    const POINT_ORDER_ID: &str = "ORD01M765NPM84NTSPDZZ2GXEEH4R";
    const POINT_ORDER_PAYMENT_ID: &str = "PAY01M765NPM84NTSPDZZ2GXEEH4R";
    /// `transactions.payments[0].reference_id` of the charged order: its `/v1/payments` id,
    /// which the order's refund does not use.
    const POINT_PAYMENT_REFERENCE_ID: &str = "189097810220";
    /// ARS 15.00, the amount of the real charges.
    const POINT_MINOR_AMOUNT: i64 = 1_500;

    fn connector_response(status_code: u16, body: serde_json::Value) -> Response {
        Response {
            headers: None,
            response: bytes::Bytes::from(body.to_string()),
            status_code,
        }
    }

    fn account_metadata() -> serde_json::Value {
        json!({
            "account_name": "hotel",
            "qr_pos": {"external_pos_id": "PXSOLPOS1"},
            "point_terminal": {"terminal_id": POINT_TERMINAL_ID, "operating_mode": "PDV"}
        })
    }

    /// An in-person charge of ARS 15.00 with the given wallet.
    fn order_authorize_router_data(
        wallet: WalletData,
        metadata: Option<serde_json::Value>,
        account_metadata: Option<serde_json::Value>,
    ) -> PaymentsAuthorizeRouterData {
        let mut router_data = mercadopago::test_support::authorize_router_data(metadata, None);
        router_data.request.payment_method_data = PaymentMethodData::Wallet(wallet);
        router_data.request.amount = POINT_MINOR_AMOUNT;
        router_data.request.minor_amount = MinorUnit::new(POINT_MINOR_AMOUNT);
        router_data.payment_method = enums::PaymentMethod::Wallet;
        router_data.description = Some("Reservation 42".to_string());
        router_data.connector_meta_data = account_metadata.map(hyperswitch_masking::Secret::new);
        router_data
    }

    fn point_authorize_router_data(
        metadata: Option<serde_json::Value>,
    ) -> PaymentsAuthorizeRouterData {
        order_authorize_router_data(
            WalletData::MercadoPagoPoint {},
            metadata,
            Some(account_metadata()),
        )
    }

    fn authorize_body(
        router_data: &PaymentsAuthorizeRouterData,
    ) -> CustomResult<serde_json::Value, errors::ConnectorError> {
        ConnectorIntegration::<Authorize, PaymentsAuthorizeData, PaymentsResponseData>::get_request_body(
            Mercadopago::new(),
            router_data,
            &Connectors::default(),
        )
        .map(|content| {
            serde_json::from_str(content.get_inner_value().peek()).expect("a JSON body")
        })
    }

    fn authorize_response(
        router_data: &PaymentsAuthorizeRouterData,
        body: serde_json::Value,
    ) -> PaymentsAuthorizeRouterData {
        ConnectorIntegration::<Authorize, PaymentsAuthorizeData, PaymentsResponseData>::handle_response(
            Mercadopago::new(),
            router_data,
            None,
            connector_response(201, body),
        )
        .expect("the created order is handled")
    }

    /// A Point order in the given state, as `POST` and `GET /v1/orders/{id}` answer it.
    fn point_order_body(
        status: &str,
        status_detail: &str,
        payment: serde_json::Value,
    ) -> serde_json::Value {
        json!({
            "id": POINT_ORDER_ID,
            "type": "point",
            "external_reference": "pxs_mp_1",
            "status": status,
            "status_detail": status_detail,
            "currency": "ARS",
            "total_amount": "15.00",
            "integration_data": {"platform_id": PXSOL_PLATFORM_ID},
            "config": {"point": {"terminal_id": POINT_TERMINAL_ID, "print_on_terminal": "no_ticket"}},
            "transactions": {"payments": [payment]}
        })
    }

    fn point_payment(status: &str, status_detail: &str) -> serde_json::Value {
        json!({
            "id": POINT_ORDER_PAYMENT_ID,
            "amount": "15.00",
            "status": status,
            "status_detail": status_detail
        })
    }

    fn point_payment_with_reference(
        status: &str,
        status_detail: &str,
        reference_id: &str,
    ) -> serde_json::Value {
        let mut payment = point_payment(status, status_detail);
        payment["reference_id"] = json!(reference_id);
        payment
    }

    /// Order 1 once paid: `processed/accredited` with a prepaid Visa.
    fn charged_point_order_body() -> serde_json::Value {
        let mut payment =
            point_payment_with_reference("processed", "accredited", POINT_PAYMENT_REFERENCE_ID);
        payment["paid_amount"] = json!("15.00");
        payment["payment_method"] =
            json!({"id": "visa", "type": "prepaid_card", "installments": 1});
        let mut order = point_order_body("processed", "accredited", payment);
        order["total_paid_amount"] = json!("15.00");
        order
    }

    fn sync_order(body: serde_json::Value) -> PaymentsSyncRouterData {
        sync_order_with_stored(body, None)
    }

    /// Syncs an order whose attempt already stores `connector_meta`.
    fn sync_order_with_stored(
        body: serde_json::Value,
        connector_meta: Option<serde_json::Value>,
    ) -> PaymentsSyncRouterData {
        let request = PaymentsSyncData {
            connector_transaction_id: ResponseId::ConnectorTransactionId(
                POINT_ORDER_ID.to_string(),
            ),
            currency: enums::Currency::ARS,
            amount: MinorUnit::new(POINT_MINOR_AMOUNT),
            connector_meta,
            ..Default::default()
        };
        let data: PaymentsSyncRouterData =
            mercadopago::test_support::router_data(request, None, PaymentAddress::default());
        ConnectorIntegration::<PSync, PaymentsSyncData, PaymentsResponseData>::handle_response(
            Mercadopago::new(),
            &data,
            None,
            connector_response(200, body),
        )
        .expect("the order is handled")
    }

    /// The cancel of an order whose attempt stores `connector_meta`.
    fn void_router_data(connector_meta: Option<serde_json::Value>) -> PaymentsCancelRouterData {
        let request = PaymentsCancelData {
            connector_transaction_id: POINT_ORDER_ID.to_string(),
            connector_meta,
            ..Default::default()
        };
        mercadopago::test_support::router_data(request, None, PaymentAddress::default())
    }

    /// What the attempt of a Point order stores from its creation.
    fn point_attempt_metadata() -> serde_json::Value {
        json!({"mp_order_type": "point"})
    }

    /// What the attempt of a QR order stores from its creation.
    fn qr_attempt_metadata() -> serde_json::Value {
        json!({
            "image_data_url": "data:image/png;base64,AAAA",
            "raw_qr_data": "0002010102",
            "mp_payment_id": "PAY00000000000000000000000001"
        })
    }

    /// Name and value of every header of the cancel request, in order.
    fn void_headers(router_data: &PaymentsCancelRouterData) -> Vec<(String, String)> {
        ConnectorIntegration::<Void, PaymentsCancelData, PaymentsResponseData>::get_headers(
            Mercadopago::new(),
            router_data,
            &Connectors::default(),
        )
        .expect("the cancel headers build")
        .into_iter()
        .map(|(name, value)| (name, value.into_inner()))
        .collect()
    }

    /// The order id, metadata and reference stored by a successful payments response.
    fn stored_transaction<F, T>(
        router_data: &RouterData<F, T, PaymentsResponseData>,
    ) -> (String, Option<serde_json::Value>, Option<String>, bool) {
        match router_data.response.as_ref() {
            Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(order_id),
                connector_metadata,
                connector_response_reference_id,
                redirection_data,
                ..
            }) => (
                order_id.clone(),
                connector_metadata.clone(),
                connector_response_reference_id.clone(),
                redirection_data.is_some(),
            ),
            other => panic!("expected a transaction response, got {other:?}"),
        }
    }

    fn failure<F, T>(router_data: &RouterData<F, T, PaymentsResponseData>) -> &ErrorResponse {
        router_data
            .response
            .as_ref()
            .expect_err("the order is a failure")
    }

    fn refund_router_data(
        connector_metadata: Option<serde_json::Value>,
        refund_minor_amount: i64,
    ) -> RefundsRouterData<Execute> {
        let request = RefundsData {
            refund_id: "ref_mp_1".to_string(),
            connector_transaction_id: POINT_ORDER_ID.to_string(),
            connector_refund_id: None,
            currency: enums::Currency::ARS,
            payment_amount: POINT_MINOR_AMOUNT,
            reason: None,
            webhook_url: None,
            refund_amount: refund_minor_amount,
            connector_metadata,
            refund_connector_metadata: None,
            browser_info: None,
            split_refunds: None,
            minor_payment_amount: MinorUnit::new(POINT_MINOR_AMOUNT),
            minor_refund_amount: MinorUnit::new(refund_minor_amount),
            integrity_object: None,
            refund_status: enums::RefundStatus::Pending,
            merchant_account_id: None,
            merchant_config_currency: None,
            capture_method: None,
            additional_payment_method_data: None,
            payment_method_data: None,
            mandate_id: None,
            payment_connector_request_reference_id: None,
            payment_feature_metadata: None,
            feature_metadata: None,
        };
        mercadopago::test_support::router_data(request, None, PaymentAddress::default())
    }

    fn refund_body(
        router_data: &RefundsRouterData<Execute>,
    ) -> CustomResult<serde_json::Value, errors::ConnectorError> {
        ConnectorIntegration::<Execute, RefundsData, RefundsResponseData>::get_request_body(
            Mercadopago::new(),
            router_data,
            &Connectors::default(),
        )
        .map(|content| serde_json::from_str(content.get_inner_value().peek()).expect("a JSON body"))
    }

    #[test]
    fn point_charge_posts_an_order_for_the_terminal_without_a_fee() {
        let router_data = point_authorize_router_data(None);
        let url =
            ConnectorIntegration::<Authorize, PaymentsAuthorizeData, PaymentsResponseData>::get_url(
                Mercadopago::new(),
                &router_data,
                &Connectors::default(),
            )
            .expect("the url builds");
        assert!(url.ends_with("/v1/orders"), "{url}");

        let body = authorize_body(&router_data).expect("the Point order builds");
        assert_eq!(
            body,
            json!({
                "type": "point",
                "external_reference": "pxs_mp_1",
                "description": "Reservation 42",
                "expiration_time": "PT10M",
                "integration_data": {"platform_id": "dev_ab8e21775bb211ed88d80242ac130004"},
                "config": {"point": {
                    "terminal_id": POINT_TERMINAL_ID,
                    "print_on_terminal": "no_ticket"
                }},
                "transactions": {"payments": [{"amount": "15.00"}]}
            })
        );
        assert!(body.get("marketplace_fee").is_none());

        // The order is created once per attempt: the reference is the idempotency key.
        let headers =
            ConnectorIntegration::<Authorize, PaymentsAuthorizeData, PaymentsResponseData>::get_headers(
                Mercadopago::new(),
                &router_data,
                &Connectors::default(),
            )
            .expect("authorize headers build");
        assert!(headers
            .into_iter()
            .any(|(name, value)| name == "X-Idempotency-Key" && value.into_inner() == "pxs_mp_1"));
    }

    #[test]
    fn point_charge_with_an_application_fee_is_refused_before_reaching_mercado_pago() {
        for metadata in [
            json!({"application_fee": 0.1}),
            json!({"mercadopago": {"application_fee": 0.1}}),
        ] {
            let error = authorize_body(&point_authorize_router_data(Some(metadata.clone())))
                .expect_err("a fee cannot be collected on Point");
            assert!(
                matches!(
                    error.current_context(),
                    errors::ConnectorError::NotSupported { message, connector }
                        if message.contains("application_fee") && connector == "mercadopago"
                ),
                "{metadata}: {error:?}"
            );
        }
        // Other metadata does not get in the way.
        let body = authorize_body(&point_authorize_router_data(Some(
            json!({"mercadopago": {"device_id": "dev-1"}}),
        )))
        .expect("a Point order without a fee builds");
        assert_eq!(body["type"], "point");
    }

    #[test]
    fn point_charge_without_a_chosen_terminal_is_a_clear_error() {
        for account_metadata in [
            None,
            Some(json!({"qr_pos": {"external_pos_id": "PXSOLPOS1"}})),
        ] {
            let router_data = order_authorize_router_data(
                WalletData::MercadoPagoPoint {},
                None,
                account_metadata,
            );
            let error = authorize_body(&router_data).expect_err("there is no terminal");
            assert!(matches!(
                error.current_context(),
                errors::ConnectorError::MissingRequiredField { field_name }
                    if *field_name == "connector_meta_data.point_terminal.terminal_id"
            ));
        }
    }

    #[test]
    fn point_charge_with_manual_capture_is_refused() {
        let mut router_data = point_authorize_router_data(None);
        router_data.request.capture_method = Some(enums::CaptureMethod::Manual);
        let error = authorize_body(&router_data).expect_err("a terminal charge is captured");
        assert!(matches!(
            error.current_context(),
            errors::ConnectorError::NotImplemented(message) if message.contains("Point")
        ));
    }

    #[test]
    fn created_point_order_waits_for_the_customer_without_a_qr() {
        let router_data = point_authorize_router_data(None);
        // The create response is `created`; with the device idle it can already be `at_terminal`.
        // The second body has no `type`: the request, not the echo, says it is a Point order.
        let mut untyped = point_order_body(
            "at_terminal",
            "at_terminal",
            point_payment("at_terminal", "at_terminal"),
        );
        untyped.as_object_mut().expect("an object").remove("type");
        for body in [
            point_order_body("created", "created", point_payment("created", "created")),
            untyped,
        ] {
            let handled = authorize_response(&router_data, body);
            assert_eq!(handled.status, enums::AttemptStatus::AuthenticationPending);
            let (order_id, connector_metadata, reference, has_redirection) =
                stored_transaction(&handled);
            assert_eq!(order_id, POINT_ORDER_ID);
            // Only the marker: no QR to show and no payment id yet.
            assert_eq!(connector_metadata, Some(point_attempt_metadata()));
            assert!(
                serde_json::from_value::<api_models::payments::QrCodeInformation>(
                    point_attempt_metadata()
                )
                .is_err(),
                "the marker must not read as a QR next action"
            );
            assert_eq!(reference.as_deref(), Some("pxs_mp_1"));
            assert!(!has_redirection);
        }
    }

    #[test]
    fn point_order_created_in_another_currency_fails_the_attempt() {
        let router_data = point_authorize_router_data(None);
        let mut body = point_order_body("created", "created", point_payment("created", "created"));
        body["currency"] = json!("USD");
        let handled = authorize_response(&router_data, body);
        assert_eq!(handled.status, enums::AttemptStatus::Failure);
        let error = failure(&handled);
        assert_eq!(error.code, "order_mismatch");
        assert!(error.message.contains("USD") && error.message.contains("ARS"));
        assert_eq!(
            error.connector_transaction_id.as_deref(),
            Some(POINT_ORDER_ID)
        );
    }

    #[test]
    fn qr_charge_still_builds_and_stores_its_qr() {
        let router_data = order_authorize_router_data(
            WalletData::MercadoPagoQr {},
            Some(json!({"application_fee": 0.1})),
            Some(account_metadata()),
        );
        let body = authorize_body(&router_data).expect("the QR order builds");
        assert_eq!(
            body,
            json!({
                "type": "qr",
                "total_amount": "15.00",
                "currency": "ARS",
                "description": "Reservation 42",
                "items": [{
                    "title": "Reservation 42",
                    "unit_price": "15.00",
                    "quantity": 1,
                    "unit_measure": "unit"
                }],
                "external_reference": "pxs_mp_1",
                "expiration_time": "PT30M",
                "marketplace_fee": "0.10",
                "integration_data": {"platform_id": "dev_ab8e21775bb211ed88d80242ac130004"},
                "config": {"qr": {"external_pos_id": "PXSOLPOS1", "mode": "dynamic"}},
                "transactions": {"payments": [{"amount": "15.00"}]}
            })
        );

        let qr_data = "00020101021243650016com.mercadolibre0201306363044D91";
        let created = json!({
            "id": "ORDTST00000000000000000000000AAA",
            "type": "qr",
            "external_reference": "pxs_mp_1",
            "total_amount": "15.00",
            "status": "created",
            "status_detail": "created",
            "currency": "ARS",
            "transactions": {"payments": [
                {"id": "PAY00000000000000000000000001", "amount": "15.00",
                 "status": "created", "status_detail": "ready_to_process"}
            ]},
            "type_response": {"qr_data": qr_data}
        });
        let handled = authorize_response(&router_data, created.clone());
        assert_eq!(handled.status, enums::AttemptStatus::AuthenticationPending);
        let (order_id, connector_metadata, reference, _) = stored_transaction(&handled);
        assert_eq!(order_id, "ORDTST00000000000000000000000AAA");
        assert_eq!(reference.as_deref(), Some("pxs_mp_1"));
        let connector_metadata = connector_metadata.expect("the QR is stored");
        assert_eq!(connector_metadata["raw_qr_data"], qr_data);
        assert_eq!(
            connector_metadata["mp_payment_id"],
            "PAY00000000000000000000000001"
        );

        // A QR order still needs its `qr_data`, and still fails on a mismatch.
        let mut without_qr = created.clone();
        without_qr
            .as_object_mut()
            .expect("an object")
            .remove("type_response");
        assert!(ConnectorIntegration::<Authorize, PaymentsAuthorizeData, PaymentsResponseData>::handle_response(
            Mercadopago::new(),
            &router_data,
            None,
            connector_response(201, without_qr),
        )
        .is_err());
        let mut other_currency = created;
        other_currency["currency"] = json!("USD");
        let mismatched = authorize_response(&router_data, other_currency);
        assert_eq!(mismatched.status, enums::AttemptStatus::Failure);
        assert_eq!(failure(&mismatched).code, "order_mismatch");
    }

    #[test]
    fn point_order_at_the_terminal_keeps_waiting_for_the_customer() {
        let synced = sync_order(point_order_body(
            "at_terminal",
            "at_terminal",
            point_payment("at_terminal", "at_terminal"),
        ));
        assert_eq!(synced.status, enums::AttemptStatus::AuthenticationPending);
        let (order_id, connector_metadata, _, _) = stored_transaction(&synced);
        assert_eq!(order_id, POINT_ORDER_ID);
        assert_eq!(connector_metadata, Some(point_attempt_metadata()));
    }

    #[test]
    fn charged_point_order_seen_on_a_sync_stores_the_payment_to_refund() {
        let synced =
            sync_order_with_stored(charged_point_order_body(), Some(point_attempt_metadata()));
        assert_eq!(synced.status, enums::AttemptStatus::Charged);
        let (order_id, connector_metadata, reference, _) = stored_transaction(&synced);
        assert_eq!(order_id, POINT_ORDER_ID);
        assert_eq!(reference.as_deref(), Some("pxs_mp_1"));
        assert_eq!(
            connector_metadata,
            Some(json!({
                "mp_order_type": "point",
                "mp_payment_id": POINT_ORDER_PAYMENT_ID
            }))
        );

        // A later answer that no longer lists the payment does not lose the stored id.
        let mut without_payment = charged_point_order_body();
        without_payment["transactions"]["payments"] = json!([]);
        let synced_again = sync_order_with_stored(without_payment, connector_metadata.clone());
        assert_eq!(stored_transaction(&synced_again).1, connector_metadata);

        // That stored value is exactly what the refund of the order names: the order's own
        // payment, as on the real terminal, never the `reference_id` of `/v1/payments`.
        let body = refund_body(&refund_router_data(connector_metadata, 1_000))
            .expect("a charged order can be refunded");
        assert_eq!(
            body,
            json!({"transactions": [{"id": POINT_ORDER_PAYMENT_ID, "amount": "10.00"}]})
        );
        assert_ne!(POINT_ORDER_PAYMENT_ID, POINT_PAYMENT_REFERENCE_ID);
    }

    #[test]
    fn rejected_point_payment_is_a_failure_with_a_readable_message() {
        // Orders 8, 9 and 10: order failed/failed, payment failed with `in_review`.
        let synced = sync_order(point_order_body(
            "failed",
            "failed",
            point_payment_with_reference("failed", "in_review", "188034059899"),
        ));
        assert_eq!(synced.status, enums::AttemptStatus::Failure);
        let error = failure(&synced);
        assert_eq!(error.code, "point_payment_rejected");
        assert_eq!(
            error.message,
            "The payment was rejected on the terminal. Start a new charge to try again"
        );
        assert_eq!(error.reason.as_deref(), Some(error.message.as_str()));
        assert_eq!(error.attempt_status, Some(enums::AttemptStatus::Failure));
        assert_eq!(
            error.connector_transaction_id.as_deref(),
            Some(POINT_ORDER_ID)
        );
    }

    #[test]
    fn expired_and_cancelled_point_orders_are_final() {
        // Order 6: expired/expired, untouched on the device.
        let expired = sync_order(point_order_body(
            "expired",
            "expired",
            point_payment("expired", "expired"),
        ));
        assert_eq!(expired.status, enums::AttemptStatus::Failure);
        assert_eq!(failure(&expired).code, "expired");
        assert_eq!(failure(&expired).message, "Payment expired");

        // Order 5: cancelled by the operator on the device.
        let cancelled = sync_order(point_order_body(
            "canceled",
            "canceled",
            point_payment("canceled", "cancel_by_terminal"),
        ));
        assert_eq!(cancelled.status, enums::AttemptStatus::Voided);
        assert_eq!(
            stored_transaction(&cancelled).1,
            Some(point_attempt_metadata())
        );
    }

    #[test]
    fn point_order_in_action_required_is_unresolved_and_not_refundable() {
        let synced = sync_order(point_order_body(
            "action_required",
            "action_required",
            point_payment_with_reference("action_required", "action_required", "188034059899"),
        ));
        assert_eq!(synced.status, enums::AttemptStatus::Unresolved);
        let (order_id, connector_metadata, _, _) = stored_transaction(&synced);
        assert_eq!(order_id, POINT_ORDER_ID);
        assert_eq!(
            connector_metadata,
            Some(point_attempt_metadata()),
            "no payment id to refund against"
        );

        // Without a stored payment id the refund is refused while building it, before any call.
        let error = refund_body(&refund_router_data(connector_metadata, 1_500))
            .expect_err("an order that is not processed cannot be refunded");
        assert!(
            matches!(
                error.current_context(),
                errors::ConnectorError::NotSupported { message, connector }
                    if message.contains("without an approved payment") && connector == "mercadopago"
            ),
            "{error:?}"
        );
    }

    #[test]
    fn refunded_point_order_stays_charged() {
        // Order 1 after its full refund: refunded/refunded with one processed refund.
        let mut body = point_order_body(
            "refunded",
            "refunded",
            point_payment_with_reference("refunded", "refunded", POINT_PAYMENT_REFERENCE_ID),
        );
        body["transactions"]["refunds"] = json!([{
            "id": "REF01M765Y8SV4KKFSDTSBDFY3PFG",
            "transaction_id": POINT_ORDER_PAYMENT_ID,
            "reference_id": "3567405292",
            "amount": "15.00",
            "status": "processed"
        }]);
        let synced = sync_order(body);
        assert_eq!(synced.status, enums::AttemptStatus::Charged);
        let reported = synced
            .connector_response
            .as_ref()
            .and_then(|connector_response| connector_response.get_reported_activity())
            .expect("the refund seen on the order is reported");
        assert_eq!(reported.refunds.len(), 1);
        assert_eq!(
            reported.refunds[0].connector_refund_id,
            "REF01M765Y8SV4KKFSDTSBDFY3PFG"
        );
        assert_eq!(reported.refunds[0].amount, MinorUnit::new(1_500));
    }

    #[test]
    fn qr_order_sync_is_unchanged_by_point() {
        // A paid QR keeps its stored metadata (the QR and its `PAY` id) untouched.
        let paid = sync_order(json!({
            "id": "ORDTST00000000000000000000000AAA",
            "type": "qr",
            "external_reference": "pxs_mp_1",
            "status": "processed",
            "status_detail": "accredited",
            "transactions": {"payments": [{
                "id": "PAY00000000000000000000000001", "status": "processed",
                "status_detail": "accredited", "reference_id": "150211668619"
            }]}
        }));
        assert_eq!(paid.status, enums::AttemptStatus::Charged);
        assert_eq!(stored_transaction(&paid).1, None);
        let paid_with_stored = sync_order_with_stored(
            json!({
                "id": "ORDTST00000000000000000000000AAA",
                "type": "qr",
                "status": "processed",
                "transactions": {"payments": [{
                    "id": "PAY00000000000000000000000001", "status": "processed",
                    "reference_id": "150211668619"
                }]}
            }),
            Some(qr_attempt_metadata()),
        );
        assert_eq!(stored_transaction(&paid_with_stored).1, None);

        // Statuses only a terminal has stay Pending on an order that is not Point.
        for status in ["at_terminal", "action_required"] {
            let synced = sync_order(json!({
                "id": "ORDTST00000000000000000000000AAA", "type": "qr", "status": status
            }));
            assert_eq!(synced.status, enums::AttemptStatus::Pending, "{status}");
        }

        // `in_review` on a QR keeps the generic message.
        let failed = sync_order(json!({
            "id": "ORDTST00000000000000000000000AAA",
            "type": "qr",
            "status": "failed",
            "transactions": {"payments": [
                {"id": "PAY1", "status": "failed", "status_detail": "in_review"}
            ]}
        }));
        assert_eq!(failed.status, enums::AttemptStatus::Failure);
        assert_eq!(failure(&failed).code, "in_review");
        assert_eq!(failure(&failed).message, "Payment rejected: in_review");
    }

    #[test]
    fn point_order_cancel_allows_cancelling_at_the_terminal() {
        let router_data = void_router_data(Some(point_attempt_metadata()));
        let request =
            ConnectorIntegration::<Void, PaymentsCancelData, PaymentsResponseData>::build_request(
                Mercadopago::new(),
                &router_data,
                &Connectors::default(),
            )
            .expect("the cancel builds")
            .expect("there is a request");
        assert_eq!(request.method, Method::Post);
        assert!(
            request
                .url
                .ends_with(&format!("/v1/orders/{POINT_ORDER_ID}/cancel")),
            "{}",
            request.url
        );
        assert!(request.body.is_none());

        // The header lets the cancel reach an order the device already shows. The idempotency
        // key is the one every order cancel sends.
        let headers = void_headers(&router_data);
        assert!(headers.contains(&(
            "x-allow-cancelable-status".to_string(),
            "at_terminal".to_string()
        )));
        assert!(headers.contains(&("X-Idempotency-Key".to_string(), "pxs_mp_1_void".to_string())));
        // Charged or not, the attempt of a Point order keeps its marker.
        let charged = void_router_data(Some(json!({
            "mp_order_type": "point",
            "mp_payment_id": POINT_ORDER_PAYMENT_ID
        })));
        assert!(void_headers(&charged)
            .iter()
            .any(|(name, _)| name == "x-allow-cancelable-status"));

        // Orders 2 and 3: cancelled by API while still `created`, answered with the order.
        let cancelled =
            ConnectorIntegration::<Void, PaymentsCancelData, PaymentsResponseData>::handle_response(
                Mercadopago::new(),
                &router_data,
                None,
                connector_response(
                    200,
                    point_order_body("canceled", "canceled", point_payment("canceled", "canceled")),
                ),
            )
            .expect("the cancelled order is handled");
        assert_eq!(cancelled.status, enums::AttemptStatus::Voided);
        let (order_id, connector_metadata, _, _) = stored_transaction(&cancelled);
        assert_eq!(order_id, POINT_ORDER_ID);
        assert_eq!(connector_metadata, Some(point_attempt_metadata()));
    }

    #[test]
    fn qr_order_cancel_is_sent_as_before_without_the_terminal_header() {
        // A QR attempt, and one that stores nothing: neither is marked as Point.
        for connector_meta in [Some(qr_attempt_metadata()), None] {
            let router_data = void_router_data(connector_meta);
            assert_eq!(
                void_headers(&router_data),
                vec![
                    ("Content-Type".to_string(), "application/json".to_string()),
                    (
                        "Authorization".to_string(),
                        "Bearer TEST-access-token".to_string()
                    ),
                    ("X-Idempotency-Key".to_string(), "pxs_mp_1_void".to_string()),
                ]
            );

            let request =
                ConnectorIntegration::<Void, PaymentsCancelData, PaymentsResponseData>::build_request(
                    Mercadopago::new(),
                    &router_data,
                    &Connectors::default(),
                )
                .expect("the cancel builds")
                .expect("there is a request");
            assert_eq!(request.method, Method::Post);
            assert!(request
                .url
                .ends_with(&format!("/v1/orders/{POINT_ORDER_ID}/cancel")));
            assert!(request.body.is_none());
            assert!(!request
                .headers
                .iter()
                .any(|(name, _)| name.eq_ignore_ascii_case("x-allow-cancelable-status")));
        }

        // The cancelled QR order leaves its stored metadata untouched.
        let router_data = void_router_data(Some(qr_attempt_metadata()));
        let cancelled =
            ConnectorIntegration::<Void, PaymentsCancelData, PaymentsResponseData>::handle_response(
                Mercadopago::new(),
                &router_data,
                None,
                connector_response(
                    200,
                    json!({
                        "id": POINT_ORDER_ID, "type": "qr", "status": "canceled",
                        "status_detail": "canceled", "external_reference": "pxs_mp_1"
                    }),
                ),
            )
            .expect("the cancelled order is handled");
        assert_eq!(cancelled.status, enums::AttemptStatus::Voided);
        assert_eq!(stored_transaction(&cancelled).1, None);
    }

    /// What Mercado Pago answers to the cancel of an order it will not cancel: orders 4 and 5,
    /// and any terminal on firmware older than 12.3.18.
    fn refused_cancel_response() -> Response {
        connector_response(
            409,
            json!({"errors": [{
                "code": "cannot_cancel_order",
                "message": "The order must be in 'created' status to be canceled"
            }]}),
        )
    }

    fn void_error(response: Response) -> ErrorResponse {
        ConnectorIntegration::<Void, PaymentsCancelData, PaymentsResponseData>::get_error_response(
            Mercadopago::new(),
            response,
            None,
        )
        .expect("the refusal parses")
    }

    /// An error in the shape the Orders API answers with.
    fn orders_api_error(status_code: u16, code: &str, message: &str) -> Response {
        connector_response(
            status_code,
            json!({"errors": [{"code": code, "message": message}]}),
        )
    }

    #[test]
    fn order_cancel_mercado_pago_refuses_keeps_the_attempt_waiting() {
        // The refusal does not say which kind of order it was, so this is what the cancel of a
        // Point order and of a QR order both get: the order was not cancelled and can still be
        // paid, so the attempt keeps waiting for the customer instead of failing.
        let error = void_error(refused_cancel_response());
        assert_eq!(
            error.attempt_status,
            Some(enums::AttemptStatus::AuthenticationPending)
        );
        assert_eq!(error.status_code, 409);
        assert_eq!(error.code, "cannot_cancel_order");
        assert_eq!(
            error.message,
            "The order must be in 'created' status to be canceled"
        );
        assert_eq!(
            error.network_decline_code.as_deref(),
            Some("cannot_cancel_order")
        );
        assert_eq!(
            error.network_error_message.as_deref(),
            Some("The order must be in 'created' status to be canceled")
        );
    }

    #[test]
    fn any_refusal_of_an_order_cancel_keeps_the_attempt_waiting() {
        // Whatever the reason, an order Mercado Pago did not cancel can still be paid. These
        // are the refusals the Orders API itself answers, in its own error shape.
        for (status_code, code, message) in [
            (400, "header_value", "Invalid value for header"),
            (404, "order_not_found", "Order not found."),
            (
                409,
                "cannot_cancel_order",
                "The order must be in 'created' status to be canceled",
            ),
        ] {
            let error = void_error(orders_api_error(status_code, code, message));
            assert_eq!(
                error.attempt_status,
                Some(enums::AttemptStatus::AuthenticationPending),
                "{status_code}"
            );
            assert_eq!(error.status_code, status_code);
            assert_eq!(error.code, code);
            assert_eq!(error.message, message);
        }
    }

    #[test]
    fn authentication_failures_of_an_order_cancel_carry_no_status_from_the_connector() {
        // Real answers to `POST /v1/orders/{id}/cancel` with an invalid token and with none.
        // They come from Mercado Pago's authentication layer, not from the Orders API, so
        // nothing in them tells an order cancel from the void of a card payment and the
        // connector returns no status. Core keeps these attempts waiting by itself (it knows
        // the attempt is an order): see `refused_void_keeps_waiting` in the router.
        let invalid_token = void_error(connector_response(
            401,
            json!({"code": "unauthorized", "message": "user not found"}),
        ));
        assert_eq!(invalid_token.attempt_status, None);
        assert_eq!(invalid_token.status_code, 401);
        assert!(invalid_token.message.contains("user not found"));

        let no_token = void_error(connector_response(
            403,
            json!({
                "status": 403,
                "blocked_by": "PolicyAgent",
                "message": "At least one policy returned UNAUTHORIZED.",
                "code": "PA_UNAUTHORIZED_RESULT_FROM_POLICIES"
            }),
        ));
        assert_eq!(no_token.attempt_status, None);
        assert_eq!(no_token.status_code, 403);
        assert!(no_token
            .message
            .contains("At least one policy returned UNAUTHORIZED."));
    }

    #[test]
    fn a_server_error_on_an_order_cancel_is_left_to_core() {
        // A 5xx does not say whether the order was cancelled: core keeps it processing and the
        // next sync resolves it.
        for status_code in [500, 502, 503] {
            let error = ConnectorIntegration::<Void, PaymentsCancelData, PaymentsResponseData>::get_5xx_error_response(
                Mercadopago::new(),
                orders_api_error(status_code, "internal_error", "Internal server error"),
                None,
            )
            .expect("the failure is reported");
            assert_eq!(error.attempt_status, None, "{status_code}");
            assert_eq!(error.status_code, status_code);
        }
    }

    #[test]
    fn other_void_errors_and_other_flows_leave_the_attempt_status_to_core() {
        // The void of a card payment (`PUT /v1/payments/{id}`) fails in the Payments API shape,
        // which is how it is told apart from an order cancel: it keeps core's own handling.
        for (status_code, body) in [
            (
                400,
                json!({"message": "Invalid payment status", "error": "bad_request", "status": 400,
                       "cause": [{"code": 2063, "description": "The action requested is not valid"}]}),
            ),
            (
                404,
                json!({"message": "Payment not found", "error": "not_found", "status": 404, "cause": []}),
            ),
            // Not an Orders API error either: nothing to read in `errors`.
            (
                400,
                json!({"message": "bad", "error": "bad_request", "errors": []}),
            ),
            (
                400,
                json!({"message": "bad", "error": "bad_request", "errors": "nope"}),
            ),
        ] {
            let error = void_error(connector_response(status_code, body.clone()));
            assert_eq!(error.attempt_status, None, "{body}");
            assert_eq!(error.status_code, status_code);
        }

        // The same Orders API bodies outside a void are not a waiting order.
        for (status_code, code, message) in [
            (404, "order_not_found", "Order not found."),
            (
                409,
                "cannot_cancel_order",
                "The order must be in 'created' status to be canceled",
            ),
        ] {
            let on_sync = ConnectorIntegration::<PSync, PaymentsSyncData, PaymentsResponseData>::get_error_response(
                Mercadopago::new(),
                orders_api_error(status_code, code, message),
                None,
            )
            .expect("the refusal parses");
            assert_eq!(on_sync.attempt_status, None, "{status_code}");
            assert_eq!(on_sync.code, code);

            let on_refund = ConnectorIntegration::<Execute, RefundsData, RefundsResponseData>::get_error_response(
                Mercadopago::new(),
                orders_api_error(status_code, code, message),
                None,
            )
            .expect("the refusal parses");
            assert_eq!(on_refund.attempt_status, None, "{status_code}");

            let on_authorize = ConnectorIntegration::<
                Authorize,
                PaymentsAuthorizeData,
                PaymentsResponseData,
            >::get_error_response(
                Mercadopago::new(),
                orders_api_error(status_code, code, message),
                None,
            )
            .expect("the refusal parses");
            assert_eq!(on_authorize.attempt_status, None, "{status_code}");
        }
    }

    /// Real answer (HTTP 202) to the cancel of an order the terminal already shows, on firmware
    /// that accepts it: the order is still `at_terminal`, with the cancellation requested.
    fn cancel_requested_order_body() -> serde_json::Value {
        json!({
            "id": POINT_ORDER_ID,
            "type": "point",
            "processing_mode": "automatic",
            "external_reference": "pxs_mp_1",
            "expiration_time": "PT10M",
            "country_code": "ARG",
            "status": "at_terminal",
            "status_detail": "at_terminal",
            "currency": "ARS",
            "integration_data": {"platform_id": PXSOL_PLATFORM_ID},
            "config": {"point": {"terminal_id": POINT_TERMINAL_ID, "print_on_terminal": "no_ticket"}},
            "transactions": {"payments": [{
                "id": POINT_ORDER_PAYMENT_ID,
                "amount": "15.00",
                "status": "at_terminal",
                "status_detail": "cancellation_requested"
            }]}
        })
    }

    fn void_response(
        router_data: &PaymentsCancelRouterData,
        status_code: u16,
        body: serde_json::Value,
    ) -> PaymentsCancelRouterData {
        ConnectorIntegration::<Void, PaymentsCancelData, PaymentsResponseData>::handle_response(
            Mercadopago::new(),
            router_data,
            None,
            connector_response(status_code, body),
        )
        .expect("the answer to the cancel is handled")
    }

    #[test]
    fn cancel_requested_at_the_terminal_keeps_waiting_until_the_order_is_cancelled() {
        let router_data = void_router_data(Some(point_attempt_metadata()));
        let requested = void_response(&router_data, 202, cancel_requested_order_body());
        // Not voided yet: the terminal cancels the order about two seconds later.
        assert_eq!(
            requested.status,
            enums::AttemptStatus::AuthenticationPending
        );
        let (order_id, connector_metadata, _, _) = stored_transaction(&requested);
        assert_eq!(order_id, POINT_ORDER_ID);
        assert_eq!(connector_metadata, Some(point_attempt_metadata()));

        // The attempt says it is a Point order even when the answer does not echo its type.
        let mut untyped = cancel_requested_order_body();
        untyped.as_object_mut().expect("an object").remove("type");
        assert_eq!(
            void_response(&router_data, 202, untyped).status,
            enums::AttemptStatus::AuthenticationPending
        );

        // An order cancelled while still `created` can also be answered before it is final.
        let created = void_response(
            &router_data,
            202,
            point_order_body("created", "created", point_payment("created", "created")),
        );
        assert_eq!(created.status, enums::AttemptStatus::AuthenticationPending);

        // The next sync (or the `order.canceled` webhook, which triggers one) voids it.
        let synced = sync_order_with_stored(
            point_order_body(
                "canceled",
                "canceled",
                point_payment("canceled", "canceled_by_api"),
            ),
            Some(point_attempt_metadata()),
        );
        assert_eq!(synced.status, enums::AttemptStatus::Voided);
        assert_eq!(stored_transaction(&synced).0, POINT_ORDER_ID);
    }

    #[test]
    fn qr_cancel_is_mapped_from_the_order_it_answers_as_before() {
        let router_data = void_router_data(Some(qr_attempt_metadata()));
        let qr_order = |status: &str| {
            json!({
                "id": POINT_ORDER_ID, "type": "qr", "status": status,
                "status_detail": status, "external_reference": "pxs_mp_1"
            })
        };
        // A final `canceled` is voided, and the stored QR metadata is left untouched.
        let cancelled = void_response(&router_data, 200, qr_order("canceled"));
        assert_eq!(cancelled.status, enums::AttemptStatus::Voided);
        assert_eq!(stored_transaction(&cancelled).1, None);
        // An order still `created` keeps waiting, as its status always mapped.
        let created = void_response(&router_data, 200, qr_order("created"));
        assert_eq!(created.status, enums::AttemptStatus::AuthenticationPending);
        // `at_terminal` is not a QR status: it stays Pending for an attempt that is not Point.
        let at_terminal = void_response(&router_data, 200, qr_order("at_terminal"));
        assert_eq!(at_terminal.status, enums::AttemptStatus::Pending);
    }

    #[test]
    fn refund_of_a_point_order_names_the_stored_payment() {
        let stored = Some(json!({
            "mp_order_type": "point",
            "mp_payment_id": POINT_ORDER_PAYMENT_ID
        }));
        let router_data = refund_router_data(stored, 1_500);
        let url = ConnectorIntegration::<Execute, RefundsData, RefundsResponseData>::get_url(
            Mercadopago::new(),
            &router_data,
            &Connectors::default(),
        )
        .expect("the url builds");
        assert!(
            url.ends_with(&format!("/v1/orders/{POINT_ORDER_ID}/refund")),
            "{url}"
        );
        assert_eq!(
            refund_body(&router_data).expect("the refund builds"),
            json!({"transactions": [{"id": POINT_ORDER_PAYMENT_ID, "amount": "15.00"}]})
        );

        // Order 1: the full refund answered 201 with the order `refunded/refunded`.
        let mut body = point_order_body(
            "refunded",
            "refunded",
            point_payment_with_reference("refunded", "refunded", POINT_PAYMENT_REFERENCE_ID),
        );
        body["transactions"]["refunds"] = json!([{
            "id": "REF01M765Y8SV4KKFSDTSBDFY3PFG",
            "transaction_id": POINT_ORDER_PAYMENT_ID,
            "reference_id": "3567405292",
            "amount": "15.00",
            "status": "processed"
        }]);
        let refunded =
            ConnectorIntegration::<Execute, RefundsData, RefundsResponseData>::handle_response(
                Mercadopago::new(),
                &router_data,
                None,
                connector_response(201, body),
            )
            .expect("the refunded order is handled");
        let response = refunded.response.expect("the refund succeeded");
        assert_eq!(
            response.connector_refund_id,
            "REF01M765Y8SV4KKFSDTSBDFY3PFG"
        );
        assert_eq!(response.refund_status, enums::RefundStatus::Success);
    }

    #[test]
    fn refund_of_a_qr_order_still_names_its_stored_payment() {
        let stored = Some(json!({
            "image_data_url": "data:image/png;base64,AAAA",
            "raw_qr_data": "0002010102",
            "mp_payment_id": "PAY00000000000000000000000001"
        }));
        assert_eq!(
            refund_body(&refund_router_data(stored, 1_000)).expect("the refund builds"),
            json!({"transactions": [
                {"id": "PAY00000000000000000000000001", "amount": "10.00"}
            ]})
        );
    }

    #[test]
    fn refund_mercado_pago_refuses_keeps_its_code_and_message() {
        // Orders 1, 4 and 7: 422 for an amount the issuer does not let refund.
        let error =
            ConnectorIntegration::<Execute, RefundsData, RefundsResponseData>::get_error_response(
                Mercadopago::new(),
                connector_response(
                    422,
                    json!({"errors": [{
                        "code": "amount_not_refundable",
                        "message": "The amount may not be refunded"
                    }]}),
                ),
                None,
            )
            .expect("the refusal parses");
        assert_eq!(error.status_code, 422);
        assert_eq!(error.code, "amount_not_refundable");
        assert_eq!(error.message, "The amount may not be refunded");
    }

    #[test]
    fn point_order_webhooks_resync_the_order_like_any_other() {
        // Shape of the production `order.processed` notification of a Point order.
        let body = json!({
            "action": "order.processed",
            "api_version": "v1",
            "application_id": "1111111111111111",
            "data": {
                "external_reference": "pxs_mp_1",
                "id": POINT_ORDER_ID,
                "status": "processed",
                "status_detail": "accredited",
                "total_paid_amount": "15.00",
                "transactions": {"payments": [{
                    "paid_amount": "15.00",
                    "payment_method": {"id": "visa", "type": "prepaid_card", "installments": 1},
                    "reference": {"id": POINT_PAYMENT_REFERENCE_ID},
                    "status": "processed",
                    "status_detail": "accredited"
                }]},
                "type": "point"
            },
            "date_created": "2026-11-11T17:16:50.061675458Z",
            "live_mode": true,
            "type": "order",
            "user_id": "2222222222"
        })
        .to_string();
        let notification = classify_body(
            &body,
            &format!("data.external_reference=pxs_mp_1&data.id={POINT_ORDER_ID}&type=order"),
        );
        assert_eq!(
            notification,
            mercadopago::MercadopagoWebhookNotification::Order {
                order_id: POINT_ORDER_ID.to_string()
            }
        );
        assert_eq!(notification.payment_id_to_sync(), Some(POINT_ORDER_ID));
        assert_eq!(
            api_models::webhooks::IncomingWebhookEvent::from(&notification),
            api_models::webhooks::IncomingWebhookEvent::PaymentIntentProcessing
        );
    }
}
