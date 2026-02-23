pub mod transformers;

use common_enums::enums;
use common_utils::{
    errors::CustomResult,
    ext_traits::{ByteSliceExt, BytesExt},
    request::{Method, Request, RequestBuilder, RequestContent},
    types::{AmountConvertor, FloatMajorUnit, FloatMajorUnitForConnector},
};
use error_stack::ResultExt;
use crate::utils::RefundsRequestData;
use hyperswitch_domain_models::{
    payment_method_data::PaymentMethodData,
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
use masking::{Mask, PeekInterface};
use transformers as mercadopago;

use crate::{constants::headers, types::ResponseRouterData, utils};

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
}

impl<Flow, Request, Response> ConnectorCommonExt<Flow, Request, Response> for Mercadopago
where
    Self: ConnectorIntegration<Flow, Request, Response>,
{
    fn build_headers(
        &self,
        req: &RouterData<Flow, Request, Response>,
        _connectors: &Connectors,
    ) -> CustomResult<Vec<(String, masking::Maskable<String>)>, errors::ConnectorError> {
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
    ) -> CustomResult<Vec<(String, masking::Maskable<String>)>, errors::ConnectorError> {
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
        })
    }
}

impl ConnectorValidation for Mercadopago {
    fn validate_mandate_payment(
        &self,
        _pm_type: Option<enums::PaymentMethodType>,
        pm_data: PaymentMethodData,
    ) -> CustomResult<(), errors::ConnectorError> {
        match pm_data {
            PaymentMethodData::Wallet(_) => Ok(()),
            _ => Err(errors::ConnectorError::NotImplemented(
                "mandate payment not supported for this payment method".to_string(),
            )
            .into()),
        }
    }

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
    ) -> CustomResult<Vec<(String, masking::Maskable<String>)>, errors::ConnectorError> {
        let mut headers = self.build_headers(req, connectors)?;
        // Mercado Pago requires X-Idempotency-Key header
        headers.push((
            "X-Idempotency-Key".to_string(),
            req.connector_request_reference_id.clone().into(),
        ));
        Ok(headers)
    }

    fn get_content_type(&self) -> &'static str {
        self.common_get_content_type()
    }

    fn get_url(
        &self,
        _req: &PaymentsAuthorizeRouterData,
        connectors: &Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        Ok(format!("{}/v1/payments", self.base_url(connectors)))
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
            mercadopago::MercadopagoPaymentsRequest::try_from(&connector_router_data)?;
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
        let response: mercadopago::MercadopagoPaymentsResponse = res
            .response
            .parse_struct("MercadopagoPaymentsResponse")
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
    ) -> CustomResult<Vec<(String, masking::Maskable<String>)>, errors::ConnectorError> {
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
        let connector_payment_id = req
            .request
            .connector_transaction_id
            .get_connector_transaction_id()
            .change_context(errors::ConnectorError::MissingConnectorTransactionID)?;

        Ok(format!(
            "{}/v1/payments/{}",
            self.base_url(connectors),
            connector_payment_id
        ))
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
        let response: mercadopago::MercadopagoPaymentsResponse = res
            .response
            .parse_struct("MercadopagoPaymentsResponse")
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
// Capture Flow - PUT /v1/payments/{id}
// ============================================================================

impl ConnectorIntegration<Capture, PaymentsCaptureData, PaymentsResponseData> for Mercadopago {
    fn get_headers(
        &self,
        req: &PaymentsCaptureRouterData,
        connectors: &Connectors,
    ) -> CustomResult<Vec<(String, masking::Maskable<String>)>, errors::ConnectorError> {
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
        let connector_req = mercadopago::MercadopagoCaptureRequest::try_from(req)?;
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
// Void Flow - PUT /v1/payments/{id} with status=cancelled
// ============================================================================

impl ConnectorIntegration<Void, PaymentsCancelData, PaymentsResponseData> for Mercadopago {
    fn get_headers(
        &self,
        req: &PaymentsCancelRouterData,
        connectors: &Connectors,
    ) -> CustomResult<Vec<(String, masking::Maskable<String>)>, errors::ConnectorError> {
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
            "{}/v1/payments/{}",
            self.base_url(connectors),
            req.request.connector_transaction_id
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
        let response: mercadopago::MercadopagoPaymentsResponse = res
            .response
            .parse_struct("MercadopagoPaymentsResponse")
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
// Refund Execute Flow - POST /v1/payments/{id}/refunds
// ============================================================================

impl ConnectorIntegration<Execute, RefundsData, RefundsResponseData> for Mercadopago {
    fn get_headers(
        &self,
        req: &RefundsRouterData<Execute>,
        connectors: &Connectors,
    ) -> CustomResult<Vec<(String, masking::Maskable<String>)>, errors::ConnectorError> {
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
            "{}/v1/payments/{}/refunds",
            self.base_url(connectors),
            req.request.connector_transaction_id
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
    ) -> CustomResult<Vec<(String, masking::Maskable<String>)>, errors::ConnectorError> {
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
            "{}/v1/payments/{}/refunds/{}",
            self.base_url(connectors),
            req.request.connector_transaction_id,
            req.request.get_connector_refund_id()?
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

/// Parse the x-signature header from Mercado Pago
/// Format: ts=1704908010,v1=618c85345248dd820d5fd456117c2ab2ef8eda45a0282ff693eac24131a5e839
fn parse_mercadopago_signature_header(
    headers: &actix_web::http::header::HeaderMap,
) -> CustomResult<(String, String), errors::ConnectorError> {
    let signature_header = headers
        .get("x-signature")
        .and_then(|v| v.to_str().ok())
        .ok_or(errors::ConnectorError::WebhookSignatureNotFound)?;

    let mut ts = String::new();
    let mut v1 = String::new();

    for part in signature_header.split(',') {
        let mut kv = part.splitn(2, '=');
        if let (Some(key), Some(value)) = (kv.next(), kv.next()) {
            match key.trim() {
                "ts" => ts = value.trim().to_string(),
                "v1" => v1 = value.trim().to_string(),
                _ => {}
            }
        }
    }

    if ts.is_empty() || v1.is_empty() {
        return Err(errors::ConnectorError::WebhookSignatureNotFound.into());
    }

    Ok((ts, v1))
}

/// Extract the data.id from query params
fn extract_data_id_from_query(query_params: &str) -> Option<String> {
    for param in query_params.split('&') {
        let mut kv = param.splitn(2, '=');
        if let (Some(key), Some(value)) = (kv.next(), kv.next()) {
            if key == "data.id" {
                return Some(value.to_lowercase());
            }
        }
    }
    None
}

#[async_trait::async_trait]
impl webhooks::IncomingWebhook for Mercadopago {
    fn get_webhook_source_verification_algorithm(
        &self,
        _request: &webhooks::IncomingWebhookRequestDetails<'_>,
    ) -> CustomResult<Box<dyn common_utils::crypto::VerifySignature + Send>, errors::ConnectorError>
    {
        Ok(Box::new(common_utils::crypto::HmacSha256))
    }

    fn get_webhook_source_verification_signature(
        &self,
        request: &webhooks::IncomingWebhookRequestDetails<'_>,
        _connector_webhook_secrets: &api_models::webhooks::ConnectorWebhookSecrets,
    ) -> CustomResult<Vec<u8>, errors::ConnectorError> {
        let (_ts, v1) = parse_mercadopago_signature_header(request.headers)?;
        hex::decode(v1).change_context(errors::ConnectorError::WebhookSignatureNotFound)
    }

    fn get_webhook_source_verification_message(
        &self,
        request: &webhooks::IncomingWebhookRequestDetails<'_>,
        _merchant_id: &common_utils::id_type::MerchantId,
        _connector_webhook_secrets: &api_models::webhooks::ConnectorWebhookSecrets,
    ) -> CustomResult<Vec<u8>, errors::ConnectorError> {
        let (ts, _v1) = parse_mercadopago_signature_header(request.headers)?;

        let x_request_id = request
            .headers
            .get("x-request-id")
            .and_then(|v| v.to_str().ok())
            .ok_or(errors::ConnectorError::WebhookSignatureNotFound)?;

        // data.id can come from query params or from the body
        let data_id = extract_data_id_from_query(&request.query_params)
            .or_else(|| {
                request
                    .body
                    .parse_struct::<mercadopago::MercadopagoWebhookBody>("MercadopagoWebhookBody")
                    .ok()
                    .map(|body| body.data.id.to_lowercase())
            })
            .ok_or(errors::ConnectorError::WebhookSignatureNotFound)?;

        // Build the manifest: id:{data.id};request-id:{x-request-id};ts:{ts};
        let manifest = format!("id:{};request-id:{};ts:{};", data_id, x_request_id, ts);

        Ok(manifest.into_bytes())
    }

    fn get_webhook_object_reference_id(
        &self,
        request: &webhooks::IncomingWebhookRequestDetails<'_>,
    ) -> CustomResult<api_models::webhooks::ObjectReferenceId, errors::ConnectorError> {
        let webhook_body: mercadopago::MercadopagoWebhookBody = request
            .body
            .parse_struct("MercadopagoWebhookBody")
            .change_context(errors::ConnectorError::WebhookReferenceIdNotFound)?;

        // The webhook data.id contains the payment_id from Mercado Pago
        Ok(api_models::webhooks::ObjectReferenceId::PaymentId(
            api_models::payments::PaymentIdType::ConnectorTransactionId(
                webhook_body.data.id,
            ),
        ))
    }

    fn get_webhook_event_type(
        &self,
        request: &webhooks::IncomingWebhookRequestDetails<'_>,
    ) -> CustomResult<api_models::webhooks::IncomingWebhookEvent, errors::ConnectorError> {
        let webhook_body: mercadopago::MercadopagoWebhookBody = request
            .body
            .parse_struct("MercadopagoWebhookBody")
            .change_context(errors::ConnectorError::WebhookEventTypeNotFound)?;

        let action = mercadopago::MercadopagoWebhookAction::from(webhook_body.action.as_str());
        Ok(api_models::webhooks::IncomingWebhookEvent::from(action))
    }

    fn get_webhook_resource_object(
        &self,
        request: &webhooks::IncomingWebhookRequestDetails<'_>,
    ) -> CustomResult<Box<dyn masking::ErasedMaskSerialize>, errors::ConnectorError> {
        let webhook_body: mercadopago::MercadopagoWebhookBody = request
            .body
            .parse_struct("MercadopagoWebhookBody")
            .change_context(errors::ConnectorError::WebhookResourceObjectNotFound)?;

        Ok(Box::new(webhook_body))
    }
}

// ============================================================================
// Connector Specifications
// ============================================================================

use hyperswitch_domain_models::router_response_types::{
    ConnectorInfo, PaymentMethodDetails, SupportedPaymentMethods, SupportedPaymentMethodsExt,
};
use std::sync::LazyLock;

static MERCADOPAGO_SUPPORTED_PAYMENT_METHODS: LazyLock<SupportedPaymentMethods> =
    LazyLock::new(|| {
        let mut supported_payment_methods = SupportedPaymentMethods::new();

        // Add wallet payment method with MercadoPago type
        supported_payment_methods.add(
            enums::PaymentMethod::Wallet,
            enums::PaymentMethodType::MercadoPago,
            PaymentMethodDetails {
                mandates: enums::FeatureStatus::NotSupported,
                refunds: enums::FeatureStatus::Supported,
                supported_capture_methods: vec![
                    enums::CaptureMethod::Automatic,
                    enums::CaptureMethod::Manual,
                ],
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

static MERCADOPAGO_SUPPORTED_WEBHOOK_FLOWS: [enums::EventClass; 2] = [
    enums::EventClass::Payments,
    enums::EventClass::Refunds,
];

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
