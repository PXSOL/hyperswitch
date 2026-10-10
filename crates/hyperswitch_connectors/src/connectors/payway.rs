pub mod transformers;

use std::sync::LazyLock;

use common_enums::{enums, AttemptStatus};
use common_utils::{
    errors::CustomResult,
    ext_traits::BytesExt,
    request::{Method, Request, RequestBuilder, RequestContent},
    types::{AmountConvertor, StringMinorUnit, StringMinorUnitForConnector},
};
use error_stack::{report, ResultExt};
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
    router_response_types::{
        ConnectorInfo, PaymentMethodDetails, PaymentsResponseData, RefundsResponseData,
        SupportedPaymentMethods, SupportedPaymentMethodsExt,
    },
    types::{
        PaymentsAuthorizeRouterData, PaymentsCaptureRouterData, PaymentsSyncRouterData,
        RefundSyncRouterData, RefundsRouterData, TokenizationRouterData,
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
use hyperswitch_masking::{ExposeInterface, Mask};
use transformers as payway;

use crate::{
    constants::headers,
    types::ResponseRouterData,
    utils::{self, PaymentsSyncRequestData as _},
};

fn determine_endpoint(
    connectors: &Connectors,
    test_mode: Option<bool>,
) -> CustomResult<String, errors::ConnectorError> {
    if test_mode.unwrap_or(true) {
        Ok(connectors
            .payway
            .secondary_base_url
            .clone()
            .unwrap_or(connectors.payway.base_url.to_string()))
    } else {
        Ok(connectors.payway.base_url.to_string())
    }
}

#[derive(Clone)]
pub struct Payway {
    amount_converter: &'static (dyn AmountConvertor<Output = StringMinorUnit> + Sync),
}

impl Payway {
    pub fn new() -> &'static Self {
        &Self {
            amount_converter: &StringMinorUnitForConnector,
        }
    }

    fn x_source() -> &'static str {
        "eyJzZXJ2aWNlIjoiU0RLLVBIUCIsImdyb3VwZXIiOiIiLCJkZXZlbG9wZXIiOiIifQ=="
    }

    /// Headers of every call authenticated with the private (secret) key: payments, payment
    /// sync and refunds. The public key only tokenizes cards.
    fn private_key_headers(
        &self,
        auth_type: &ConnectorAuthType,
    ) -> CustomResult<Vec<(String, hyperswitch_masking::Maskable<String>)>, errors::ConnectorError>
    {
        let auth = payway::PaywayAuthType::try_from(auth_type)
            .change_context(errors::ConnectorError::FailedToObtainAuthType)?;
        Ok(vec![
            (
                headers::CONTENT_TYPE.to_string(),
                self.common_get_content_type().to_string().into(),
            ),
            ("apikey".to_string(), auth.secret_key.expose().into_masked()),
            ("X-Source".to_string(), Self::x_source().to_string().into()),
        ])
    }
}

impl api::Payment for Payway {}
impl api::PaymentSession for Payway {}
impl api::ConnectorAccessToken for Payway {}
impl api::MandateSetup for Payway {}
impl api::PaymentAuthorize for Payway {}
impl api::PaymentSync for Payway {}
impl api::PaymentCapture for Payway {}
impl api::PaymentVoid for Payway {}
impl api::Refund for Payway {}
impl api::RefundExecute for Payway {}
impl api::RefundSync for Payway {}
impl api::PaymentToken for Payway {}

impl ConnectorIntegration<PaymentMethodToken, PaymentMethodTokenizationData, PaymentsResponseData>
    for Payway
{
    fn get_headers(
        &self,
        req: &TokenizationRouterData,
        _connectors: &Connectors,
    ) -> CustomResult<Vec<(String, hyperswitch_masking::Maskable<String>)>, errors::ConnectorError>
    {
        let auth = payway::PaywayAuthType::try_from(&req.connector_auth_type)
            .change_context(errors::ConnectorError::FailedToObtainAuthType)?;
        Ok(vec![
            (
                headers::CONTENT_TYPE.to_string(),
                self.common_get_content_type().to_string().into(),
            ),
            ("apikey".to_string(), auth.public_key.expose().into_masked()),
            ("X-Source".to_string(), Self::x_source().to_string().into()),
        ])
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
            "{}/tokens",
            determine_endpoint(connectors, req.test_mode)?
        ))
    }

    fn get_request_body(
        &self,
        req: &TokenizationRouterData,
        _connectors: &Connectors,
    ) -> CustomResult<RequestContent, errors::ConnectorError> {
        Ok(RequestContent::Json(Box::new(
            payway::PaywayTokenRequest::try_from(req)?,
        )))
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
    ) -> CustomResult<TokenizationRouterData, errors::ConnectorError>
    where
        PaymentsResponseData: Clone,
    {
        let response: payway::PaywayTokenResponse = res
            .response
            .parse_struct("PaywayTokenResponse")
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

impl<Flow, Request, Response> ConnectorCommonExt<Flow, Request, Response> for Payway
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

impl ConnectorCommon for Payway {
    fn id(&self) -> &'static str {
        "payway"
    }

    fn get_currency_unit(&self) -> api::CurrencyUnit {
        api::CurrencyUnit::Minor
    }

    fn common_get_content_type(&self) -> &'static str {
        "application/json"
    }

    fn base_url<'a>(&self, connectors: &'a Connectors) -> &'a str {
        connectors.payway.base_url.as_ref()
    }

    fn get_auth_header(
        &self,
        auth_type: &ConnectorAuthType,
    ) -> CustomResult<Vec<(String, hyperswitch_masking::Maskable<String>)>, errors::ConnectorError>
    {
        let auth = payway::PaywayAuthType::try_from(auth_type)
            .change_context(errors::ConnectorError::FailedToObtainAuthType)?;
        Ok(vec![
            ("apikey".to_string(), auth.public_key.expose().into_masked()),
            (
                headers::AUTHORIZATION.to_string(),
                auth.secret_key.expose().into_masked(),
            ),
        ])
    }

    fn build_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        if res.status_code >= 500 {
            router_env::logger::error!(
                connector_error_response=?res,
                "Payway returned 5xx server error"
            );
            return Ok(ErrorResponse {
                status_code: res.status_code,
                code: "CE_00".to_string(),
                message: "connector internal server error".to_string(),
                reason: Some("connector_error".to_string()),
                attempt_status: Some(AttemptStatus::Failure),
                connector_transaction_id: None,
                network_advice_code: None,
                network_decline_code: Some("500".to_string()),
                network_error_message: Some("connector internal server error".to_string()),
                connector_metadata: None,
                connector_response_reference_id: None,
            });
        }

        if res.status_code == 401 {
            router_env::logger::warn!(
                status_code = res.status_code,
                "Payway authentication failed - Invalid credentials (401)"
            );
            return Ok(ErrorResponse {
                status_code: res.status_code,
                code: "CE_00".to_string(),
                message: "invalid authentication credentials".to_string(),
                reason: Some("connector_config_error".to_string()),
                attempt_status: Some(AttemptStatus::Failure),
                connector_transaction_id: None,
                network_advice_code: None,
                network_decline_code: Some("401".to_string()),
                network_error_message: Some("invalid authentication credentials".to_string()),
                connector_metadata: None,
                connector_response_reference_id: None,
            });
        }

        if res.status_code == 403 {
            router_env::logger::warn!(
                status_code=res.status_code,
                response_body=?res.response,
                "Payway access forbidden - Invalid or insufficient permissions (403)"
            );
            return Ok(ErrorResponse {
                status_code: res.status_code,
                code: "CE_00".to_string(),
                message: "invalid authentication credentials".to_string(),
                reason: Some("connector_config_error".to_string()),
                attempt_status: Some(AttemptStatus::Failure),
                connector_transaction_id: None,
                network_advice_code: None,
                network_decline_code: Some("403".to_string()),
                network_error_message: Some("invalid authentication credentials".to_string()),
                connector_metadata: None,
                connector_response_reference_id: None,
            });
        }

        if res.status_code == 400 {
            if let Ok(err_json) = res
                .response
                .parse_struct::<serde_json::Value>("PaywayErrorJson")
            {
                let err_type = err_json.get("error_type").and_then(|v| v.as_str());
                if matches!(err_type, Some("invalid_request_error")) {
                    let msgs: Vec<String> = err_json
                        .get("validation_errors")
                        .and_then(|v| v.as_array())
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|e| e.get("param").and_then(|p| p.as_str()))
                                .map(|p| format!("{} is invalid", p))
                                .collect()
                        })
                        .unwrap_or_default();

                    let message = if msgs.is_empty() {
                        "invalid request".to_string()
                    } else {
                        msgs.join(", ")
                    };

                    router_env::logger::warn!(
                        status_code=res.status_code,
                        validation_errors=?msgs,
                        error_message=%message,
                        "Payway validation error - Invalid request parameters (400)"
                    );

                    return Ok(ErrorResponse {
                        status_code: res.status_code,
                        code: "IR_19".to_string(),
                        message: message.clone(),
                        reason: Some("invalid_request_error".to_string()),
                        attempt_status: Some(AttemptStatus::Failure),
                        connector_transaction_id: None,
                        network_advice_code: None,
                        network_decline_code: Some(err_type.unwrap_or("400").to_string()),
                        network_error_message: Some(message),
                        connector_metadata: None,
                        connector_response_reference_id: None,
                    });
                }
            }
        }

        if res.status_code == 402 {
            if let Ok(err_json) = res
                .response
                .parse_struct::<serde_json::Value>("PaywayAuthRejectedJson")
            {
                let error_type = err_json
                    .get("status_details")
                    .and_then(|v| v.get("error"))
                    .and_then(|v| v.get("type"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("payment_error");

                let reason = err_json
                    .get("status_details")
                    .and_then(|v| v.get("error"))
                    .and_then(|v| v.get("reason"));

                let reason_id = reason
                    .and_then(|r| r.get("id"))
                    .and_then(|v| v.as_i64())
                    .map(|id| id.to_string())
                    .unwrap_or_default();

                let mut reason_desc = reason
                    .and_then(|r| r.get("description"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();

                if reason_id == "-1" && reason_desc.is_empty() {
                    if let Some(fraud_detection) = err_json
                        .get("fraud_detection")
                        .and_then(|fd| fd.get("status"))
                    {
                        let decision = fraud_detection
                            .get("decision")
                            .and_then(|v| v.as_str())
                            .unwrap_or("");
                        let reason_code = fraud_detection
                            .get("reason_code")
                            .and_then(|v| v.as_i64())
                            .map(|c| c.to_string())
                            .unwrap_or_default();
                        let description = fraud_detection
                            .get("description")
                            .and_then(|v| v.as_str())
                            .unwrap_or("");

                        if !decision.is_empty() && !reason_code.is_empty() {
                            reason_desc = format!(
                                "cyber_source {{status = {}}} {{code = {}}} {{desc = {}}}",
                                decision, reason_code, description
                            );
                        }
                    }
                }

                let message = if !reason_id.is_empty() && !reason_desc.is_empty() {
                    format!("[Code: {}] {}: {}", reason_id, error_type, reason_desc)
                } else if !reason_desc.is_empty() {
                    format!("{}: {}", error_type, reason_desc)
                } else {
                    error_type.to_string()
                };

                let external_transaction_id = err_json
                    .get("id")
                    .and_then(|v| v.as_i64())
                    .map(|id| id.to_string());

                router_env::logger::info!(
                    status_code=res.status_code,
                    error_type=%error_type,
                    reason_id=%reason_id,
                    reason_description=%reason_desc,
                    transaction_id=?external_transaction_id,
                    error_message=%message,
                    "Payway payment declined (402)"
                );

                return Ok(ErrorResponse {
                    status_code: res.status_code,
                    code: payway::declined_error_code(Some(&reason_id)),
                    message: message.clone(),
                    reason: Some(payway::DECLINED_REASON.to_string()),
                    attempt_status: Some(AttemptStatus::Failure),
                    connector_transaction_id: external_transaction_id,
                    network_advice_code: None,
                    network_decline_code: Some(reason_id).filter(|id| !id.is_empty()),
                    network_error_message: Some(if reason_desc.is_empty() {
                        message
                    } else {
                        reason_desc
                    }),
                    connector_metadata: None,
                    connector_response_reference_id: None,
                });
            }
        }

        let response: payway::PaywayErrorResponse = res
            .response
            .parse_struct("PaywayErrorResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        event_builder.map(|i| i.set_response_body(&response));
        router_env::logger::info!(connector_response=?response);

        Ok(ErrorResponse {
            status_code: res.status_code,
            code: "CE_00".to_string(),
            message: response.message,
            reason: Some("connector_error".to_string()),
            attempt_status: Some(AttemptStatus::Failure),
            connector_transaction_id: None,
            network_advice_code: None,
            network_decline_code: Some("unknown".to_string()),
            network_error_message: Some("unknown error".to_string()),
            connector_metadata: None,
            connector_response_reference_id: None,
        })
    }
}

impl ConnectorValidation for Payway {
    fn validate_psync_reference_id(
        &self,
        _data: &PaymentsSyncData,
        _is_three_ds: bool,
        _status: AttemptStatus,
        _connector_meta_data: Option<common_utils::pii::SecretSerdeValue>,
    ) -> CustomResult<(), errors::ConnectorError> {
        Ok(())
    }
}

impl ConnectorIntegration<Session, PaymentsSessionData, PaymentsResponseData> for Payway {
    fn build_request(
        &self,
        _req: &RouterData<Session, PaymentsSessionData, PaymentsResponseData>,
        _connectors: &Connectors,
    ) -> CustomResult<Option<Request>, errors::ConnectorError> {
        Err(errors::ConnectorError::NotSupported {
            message: "Payment sessions not supported".to_string(),
            connector: "Payway".into(),
        }
        .into())
    }
}

impl ConnectorIntegration<AccessTokenAuth, AccessTokenRequestData, AccessToken> for Payway {}

impl ConnectorIntegration<SetupMandate, SetupMandateRequestData, PaymentsResponseData> for Payway {}

impl ConnectorIntegration<Authorize, PaymentsAuthorizeData, PaymentsResponseData> for Payway {
    fn get_headers(
        &self,
        req: &PaymentsAuthorizeRouterData,
        _connectors: &Connectors,
    ) -> CustomResult<Vec<(String, hyperswitch_masking::Maskable<String>)>, errors::ConnectorError>
    {
        self.private_key_headers(&req.connector_auth_type)
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

        let connector_router_data = payway::PaywayRouterData::from((amount, req));
        let connector_req = payway::PaywayPaymentsRequest::try_from(&connector_router_data)?;
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
        let response: payway::PaywayAuthorizeResponse = res
            .response
            .parse_struct("PaywayAuthorizeResponse")
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

impl ConnectorIntegration<PSync, PaymentsSyncData, PaymentsResponseData> for Payway {
    fn get_headers(
        &self,
        req: &PaymentsSyncRouterData,
        _connectors: &Connectors,
    ) -> CustomResult<Vec<(String, hyperswitch_masking::Maskable<String>)>, errors::ConnectorError>
    {
        self.private_key_headers(&req.connector_auth_type)
    }

    fn get_content_type(&self) -> &'static str {
        self.common_get_content_type()
    }

    fn get_url(
        &self,
        req: &PaymentsSyncRouterData,
        connectors: &Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        // The id of the authorize response (`id` of the Payway payment).
        let payment_id = req.request.get_connector_transaction_id()?;
        Ok(payment_sync_url(
            &determine_endpoint(connectors, req.test_mode)?,
            &payment_id,
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
        let response: payway::PaywayPaymentsResponse = res
            .response
            .parse_struct("payway PaymentsSyncResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
        event_builder.map(|i| i.set_response_body(&response));
        router_env::logger::info!(connector_response=?response);

        let router_data = RouterData::try_from(ResponseRouterData {
            response: response.clone(),
            data: data.clone(),
            http_code: res.status_code,
        })?;
        Ok(payway::finish_payment_sync(
            router_data,
            data.status,
            &data.request.connector_transaction_id,
            data.request.amount,
            &response,
        ))
    }

    fn get_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, event_builder)
    }
}

/// URL of the payment sync: `GET {base}/payments/{payment_id}`.
fn payment_sync_url(base_url: &str, payment_id: &str) -> String {
    format!("{base_url}/payments/{payment_id}")
}

impl ConnectorIntegration<Capture, PaymentsCaptureData, PaymentsResponseData> for Payway {
    fn get_headers(
        &self,
        req: &PaymentsCaptureRouterData,
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
        _req: &PaymentsCaptureRouterData,
        _connectors: &Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        Err(errors::ConnectorError::NotImplemented("get_url method".to_string()).into())
    }

    fn get_request_body(
        &self,
        _req: &PaymentsCaptureRouterData,
        _connectors: &Connectors,
    ) -> CustomResult<RequestContent, errors::ConnectorError> {
        Err(errors::ConnectorError::NotImplemented("get_request_body method".to_string()).into())
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
        let response: payway::PaywayPaymentsResponse = res
            .response
            .parse_struct("Payway PaymentsCaptureResponse")
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

impl ConnectorIntegration<Void, PaymentsCancelData, PaymentsResponseData> for Payway {}

impl ConnectorIntegration<Execute, RefundsData, RefundsResponseData> for Payway {
    fn get_headers(
        &self,
        req: &RefundsRouterData<Execute>,
        _connectors: &Connectors,
    ) -> CustomResult<Vec<(String, hyperswitch_masking::Maskable<String>)>, errors::ConnectorError>
    {
        self.private_key_headers(&req.connector_auth_type)
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
            "{}/payments/{}/refunds",
            determine_endpoint(connectors, req.test_mode)?,
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

        let connector_router_data = payway::PaywayRouterData::from((refund_amount, req));
        let connector_req = payway::PaywayRefundRequest::try_from(&connector_router_data)?;
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
        let response: payway::RefundResponse =
            res.response
                .parse_struct("payway RefundResponse")
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

impl ConnectorIntegration<RSync, RefundsData, RefundsResponseData> for Payway {
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
        _req: &RefundSyncRouterData,
        _connectors: &Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        Err(errors::ConnectorError::NotImplemented("get_url method".to_string()).into())
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
                .set_body(types::RefundSyncType::get_request_body(
                    self, req, connectors,
                )?)
                .build(),
        ))
    }

    fn handle_response(
        &self,
        data: &RefundSyncRouterData,
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<RefundSyncRouterData, errors::ConnectorError> {
        let response: payway::RefundResponse = res
            .response
            .parse_struct("payway RefundSyncResponse")
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

#[async_trait::async_trait]
impl webhooks::IncomingWebhook for Payway {
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
    ) -> CustomResult<Box<dyn hyperswitch_masking::ErasedMaskSerialize>, errors::ConnectorError>
    {
        Err(report!(errors::ConnectorError::WebhooksNotImplemented))
    }
}

static PAYWAY_SUPPORTED_PAYMENT_METHODS: LazyLock<SupportedPaymentMethods> = LazyLock::new(|| {
    let mut methods = SupportedPaymentMethods::new();
    let supported_capture_methods = vec![
        enums::CaptureMethod::Automatic,
        enums::CaptureMethod::Manual,
    ];

    methods.add(
        enums::PaymentMethod::Card,
        common_enums::PaymentMethodType::Credit,
        PaymentMethodDetails {
            mandates: enums::FeatureStatus::NotSupported,
            refunds: enums::FeatureStatus::Supported,
            supported_capture_methods: supported_capture_methods.clone(),
            specific_features: None,
        },
    );

    methods.add(
        enums::PaymentMethod::Card,
        common_enums::PaymentMethodType::Debit,
        PaymentMethodDetails {
            mandates: enums::FeatureStatus::NotSupported,
            refunds: enums::FeatureStatus::Supported,
            supported_capture_methods,
            specific_features: None,
        },
    );

    methods
});

static PAYWAY_CONNECTOR_INFO: ConnectorInfo = ConnectorInfo {
    display_name: "Payway",
    description: "Payway connector",
    connector_type: enums::HyperswitchConnectorCategory::PaymentGateway,
    integration_status: enums::ConnectorIntegrationStatus::Beta,
};

static PAYWAY_SUPPORTED_WEBHOOK_FLOWS: [enums::EventClass; 0] = [];

impl ConnectorSpecifications for Payway {
    fn get_connector_about(&self) -> Option<&'static ConnectorInfo> {
        Some(&PAYWAY_CONNECTOR_INFO)
    }

    fn get_supported_payment_methods(&self) -> Option<&'static SupportedPaymentMethods> {
        Some(&*PAYWAY_SUPPORTED_PAYMENT_METHODS)
    }

    fn get_supported_webhook_flows(&self) -> Option<&'static [enums::EventClass]> {
        Some(&PAYWAY_SUPPORTED_WEBHOOK_FLOWS)
    }
}

#[cfg(test)]
mod payment_sync_tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::panic
    )]

    use std::marker::PhantomData;

    use common_enums::AttemptStatus;
    use common_utils::types::MinorUnit;
    use hyperswitch_domain_models::{
        payment_address::PaymentAddress,
        router_data::{ConnectorReportedActivity, ConnectorReportedRefund},
        router_request_types::{ResponseId, SyncRequestType},
    };
    use hyperswitch_interfaces::consts;
    use hyperswitch_masking::Secret;
    use serde_json::json;

    use super::*;
    use crate::connectors::payway::transformers::{
        finish_payment_sync, PaywayPaymentsResponse, PaywayStatus,
    };

    fn sync_router_data(status: AttemptStatus) -> PaymentsSyncRouterData {
        RouterData {
            flow: PhantomData,
            merchant_id: common_utils::id_type::MerchantId::default(),
            customer_id: None,
            connector_customer: None,
            connector: "payway".to_string(),
            payment_id: "pay_1".to_string(),
            attempt_id: "pay_1_1".to_string(),
            tenant_id: common_utils::id_type::TenantId::try_from_string("public".to_string())
                .unwrap(),
            status,
            payment_method: enums::PaymentMethod::Card,
            connector_auth_type: ConnectorAuthType::BodyKey {
                api_key: Secret::new("public_key".to_string()),
                key1: Secret::new("private_key".to_string()),
            },
            description: None,
            address: PaymentAddress::default(),
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
            request: PaymentsSyncData {
                connector_transaction_id: ResponseId::ConnectorTransactionId(
                    "15403386".to_string(),
                ),
                encoded_data: None,
                capture_method: None,
                connector_meta: None,
                sync_type: SyncRequestType::SinglePaymentSync,
                mandate_id: None,
                payment_method_type: None,
                currency: enums::Currency::ARS,
                payment_experience: None,
                split_payments: None,
                amount: MinorUnit::new(12050),
                integrity_object: None,
                connector_reference_id: None,
                setup_future_usage: None,
                feature_metadata: None,
                connector_mandate_id: None,
                enable_partial_authorization: None,
                is_overcapture_enabled: None,
            },
            response: Err(ErrorResponse::default()),
            connector_request_reference_id: "pay_1_1".to_string(),
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
            payment_method_type: None,
            payout_id: None,
            authorized_amount: None,
            accept_amount_mismatch: None,
            customer_document_details: None,
            customer_date_of_birth: None,
            feature_data: None,
            sender_payment_instrument_id: None,
            connector_returned_payment_method_details: None,
            raw_connector_response: None,
            is_payment_id_from_merchant: None,
        }
    }

    fn parse(body: serde_json::Value) -> PaywayPaymentsResponse {
        serde_json::from_value(body).unwrap()
    }

    fn with_status(status: &str) -> PaywayPaymentsResponse {
        parse(json!({"id": 15403386, "status": status, "amount": 12050}))
    }

    /// What a payment sync turns a response into for an attempt in `attempt_status`: the
    /// status, the id of the response and the reported activity.
    fn sync(
        response: &PaywayPaymentsResponse,
        attempt_status: AttemptStatus,
    ) -> (
        AttemptStatus,
        Result<Option<String>, String>,
        Option<ConnectorReportedActivity>,
    ) {
        let data = sync_router_data(attempt_status);
        let router_data = RouterData::try_from(ResponseRouterData {
            response: response.clone(),
            data,
            http_code: 200,
        })
        .unwrap();
        let attempt_id = ResponseId::ConnectorTransactionId("15403386".to_string());
        let router_data = finish_payment_sync(
            router_data,
            attempt_status,
            &attempt_id,
            MinorUnit::new(12050),
            response,
        );
        let id = match &router_data.response {
            Ok(PaymentsResponseData::TransactionResponse { resource_id, .. }) => {
                Ok(resource_id.get_connector_transaction_id().ok())
            }
            Ok(_) => Ok(None),
            Err(error) => Err(error.code.clone()),
        };
        let activity = router_data
            .connector_response
            .as_ref()
            .and_then(|response| response.get_reported_activity().cloned());
        (router_data.status, id, activity)
    }

    #[test]
    fn payment_sync_url_is_the_payment_resource() {
        assert_eq!(
            payment_sync_url("https://developers.decidir.com/api/v2", "15403386"),
            "https://developers.decidir.com/api/v2/payments/15403386"
        );
    }

    /// Name and plain value of every header, in order.
    fn plain(
        headers: Vec<(String, hyperswitch_masking::Maskable<String>)>,
    ) -> Vec<(String, String)> {
        headers
            .into_iter()
            .map(|(name, value)| (name, value.into_inner()))
            .collect()
    }

    fn private_key_header_set() -> Vec<(String, String)> {
        vec![
            ("Content-Type".to_string(), "application/json".to_string()),
            ("apikey".to_string(), "private_key".to_string()),
            ("X-Source".to_string(), Payway::x_source().to_string()),
        ]
    }

    #[test]
    fn private_key_headers_are_content_type_private_apikey_and_source() {
        let auth = sync_router_data(AttemptStatus::Pending).connector_auth_type;
        let headers = Payway::new().private_key_headers(&auth).unwrap();
        // The private key is masked, never exposed by the request logs.
        assert!(headers
            .iter()
            .any(|(name, value)| name == "apikey" && value.is_masked()));
        assert_eq!(plain(headers), private_key_header_set());
    }

    #[test]
    fn payment_sync_sends_the_same_headers_as_authorize_and_refunds() {
        // Authorize and refund get_headers are one-line calls to the same helper.
        let headers =
            ConnectorIntegration::<PSync, PaymentsSyncData, PaymentsResponseData>::get_headers(
                Payway::new(),
                &sync_router_data(AttemptStatus::Pending),
                &Connectors::default(),
            )
            .unwrap();
        assert_eq!(plain(headers), private_key_header_set());
    }

    #[test]
    fn a_real_shape_payment_response_parses() {
        let response = parse(json!({
            "id": 15403386,
            "site_transaction_id": "pay_123_1",
            "payment_method_id": 1,
            "card_brand": "Visa",
            "amount": 12050,
            "currency": "ars",
            "status": "approved",
            "status_details": {
                "ticket": "1560",
                "card_authorization_code": "180644",
                "address_validation_code": "VTE0011",
                "error": null
            },
            "date": "2026-03-13T18:06Z",
            "customer": null,
            "bin": "450799",
            "installments": 1,
            "first_installment_expiration_date": null,
            "payment_type": "single",
            "sub_payments": [],
            "site_id": "20240003",
            "fraud_detection": null,
            "aggregate_data": null,
            "establishment_name": null,
            "spv": null,
            "confirmed": null,
            "pan": "34a83988219caaca50432acd74c85cc193",
            "customer_token": null,
            "card_data": "/tokens/15403386",
            "token": "18167507-735f-4cb2-9ba6-a4751c661c7c",
            "a_field_added_later": {"x": 1}
        }));
        assert_eq!(response.payway_status(), PaywayStatus::Approved);
        let (status, id, activity) = sync(&response, AttemptStatus::Pending);
        assert_eq!(status, AttemptStatus::Charged);
        assert_eq!(id, Ok(Some("15403386".to_string())));
        assert!(activity.is_none());
    }

    #[test]
    fn statuses_map_like_authorize_in_both_vocabularies_and_any_casing() {
        for status in [
            "approved",
            "APPROVED",
            "Approved",
            "accredited",
            "ACCREDITED",
        ] {
            assert_eq!(
                sync(&with_status(status), AttemptStatus::Pending).0,
                AttemptStatus::Charged,
                "{status}"
            );
        }
        for status in ["pre_approved", "PRE_APPROVED", "PREAPPROVED"] {
            assert_eq!(
                sync(&with_status(status), AttemptStatus::Pending).0,
                AttemptStatus::Authorized,
                "{status}"
            );
        }
        for status in ["pending", "PROCESS", "REVIEW"] {
            assert_eq!(
                sync(&with_status(status), AttemptStatus::Authorizing).0,
                AttemptStatus::Pending,
                "{status}"
            );
        }
        for status in ["annulled", "ANNULLED", "annulment_approved", "cancelled"] {
            assert_eq!(
                sync(&with_status(status), AttemptStatus::Authorized).0,
                AttemptStatus::Voided,
                "{status}"
            );
        }
        // Money was taken: a refunded payment of an attempt not marked settled is Charged.
        for status in ["refunded", "REFUNDED_APPROVED", "approved_with_refund"] {
            let (status_after, _, _) = sync(&with_status(status), AttemptStatus::Pending);
            assert_eq!(status_after, AttemptStatus::Charged, "{status}");
        }
    }

    #[test]
    fn a_rejected_payment_is_a_failure_with_its_reason() {
        let response = parse(json!({
            "id": 15403386,
            "status": "rejected",
            "status_details": {"error": {"type": "invalid_card", "reason": {"id": 3, "description": "COD.} MONTO"}}}
        }));
        let (status, id, _) = sync(&response, AttemptStatus::Pending);
        assert_eq!(status, AttemptStatus::Failure);
        assert_eq!(id, Err("PD_3".to_string()));

        // The same rejection on an already charged attempt changes nothing.
        let (status, id, activity) = sync(&response, AttemptStatus::Charged);
        assert_eq!(status, AttemptStatus::Charged);
        assert_eq!(id, Ok(Some("15403386".to_string())));
        assert!(activity.is_none());
    }

    #[test]
    fn an_unknown_status_keeps_the_current_status() {
        for attempt_status in [
            AttemptStatus::Pending,
            AttemptStatus::Authorized,
            AttemptStatus::Charged,
        ] {
            let (status, _, activity) = sync(&with_status("brand_new_status"), attempt_status);
            assert_eq!(status, attempt_status);
            assert!(activity.is_none());
        }
        let missing = parse(json!({"id": 1}));
        assert_eq!(
            sync(&missing, AttemptStatus::Pending).0,
            AttemptStatus::Pending
        );
    }

    #[test]
    fn a_settled_attempt_never_gets_a_weaker_status() {
        for attempt_status in [AttemptStatus::Charged, AttemptStatus::PartialCharged] {
            for status in [
                "pending",
                "pre_approved",
                "annulled",
                "cancelled",
                "rejected",
                "unknown_thing",
            ] {
                assert_eq!(
                    sync(&with_status(status), attempt_status).0,
                    attempt_status,
                    "{status}"
                );
            }
        }
    }

    fn only_refund(activity: Option<ConnectorReportedActivity>) -> (String, bool) {
        let activity = activity.expect("an activity is reported");
        assert!(activity.dispute.is_none());
        assert_eq!(activity.refunds.len(), 1);
        let refund = &activity.refunds[0];
        assert_eq!(refund.status, enums::RefundStatus::Success);
        (
            refund.connector_refund_id.clone(),
            refund.amount_is_remaining_balance,
        )
    }

    #[test]
    fn a_settled_annulled_payment_reports_one_balance_refund() {
        for status in ["annulled", "ANNULMENT_APPROVED", "cancelled"] {
            let (attempt_status, _, activity) = sync(&with_status(status), AttemptStatus::Charged);
            assert_eq!(attempt_status, AttemptStatus::Charged, "{status}");
            assert_eq!(
                only_refund(activity),
                ("annulment_15403386".to_string(), true),
                "{status}"
            );
        }
    }

    #[test]
    fn a_settled_refunded_payment_reports_one_balance_refund() {
        for status in ["refunded", "REFUNDED", "refunded_approved"] {
            let (attempt_status, _, activity) = sync(&with_status(status), AttemptStatus::Charged);
            assert_eq!(attempt_status, AttemptStatus::Charged, "{status}");
            assert_eq!(
                only_refund(activity),
                ("refund_15403386".to_string(), true),
                "{status}"
            );
        }
    }

    #[test]
    fn a_settled_partially_refunded_payment_reports_nothing() {
        let (status, _, activity) =
            sync(&with_status("APPROVED_WITH_REFUND"), AttemptStatus::Charged);
        assert_eq!(status, AttemptStatus::Charged);
        assert!(activity.is_none());
    }

    #[test]
    fn a_settled_approved_payment_reports_nothing() {
        let (status, _, activity) = sync(&with_status("approved"), AttemptStatus::Charged);
        assert_eq!(status, AttemptStatus::Charged);
        assert!(activity.is_none());
    }

    #[test]
    fn a_string_id_is_accepted_too() {
        let response = parse(json!({"id": "15403386", "status": "annulled"}));
        let (_, _, activity) = sync(&response, AttemptStatus::Charged);
        assert_eq!(only_refund(activity).0, "annulment_15403386");
    }

    #[test]
    fn the_response_keeps_no_issuer_data_of_status_details() {
        let response = parse(json!({
            "id": 15403386,
            "status": "approved",
            "status_details": {
                "ticket": "1560",
                "card_authorization_code": "180644",
                "address_validation_code": "VTE0011",
                "error": null
            }
        }));
        let kept = format!("{response:?} {}", serde_json::to_string(&response).unwrap());
        for secret in ["1560", "180644", "VTE0011", "card_authorization_code"] {
            assert!(!kept.contains(secret), "{secret} leaked: {kept}");
        }
    }

    #[test]
    fn a_malformed_status_details_never_fails_the_response() {
        for details in [
            json!("oops"),
            json!(7),
            json!({"error": "oops"}),
            json!({"error": {"reason": 5}}),
        ] {
            let response = parse(json!({"id": 1, "status": "rejected", "status_details": details}));
            let (status, id, _) = sync(&response, AttemptStatus::Pending);
            assert_eq!(status, AttemptStatus::Failure);
            assert_eq!(id, Err(consts::NO_ERROR_CODE.to_string()));
        }
    }

    #[test]
    fn the_amount_is_read_leniently() {
        let amount = |value: serde_json::Value| {
            let response = parse(json!({"id": 1, "status": "approved", "amount": value}));
            // A bad amount never fails the sync.
            assert_eq!(
                sync(&response, AttemptStatus::Pending).0,
                AttemptStatus::Charged
            );
        };
        let reported = |value: serde_json::Value| {
            let response = parse(json!({"id": 1, "status": "refunded", "amount": value}));
            response
                .reported_activity(AttemptStatus::Charged, Some(MinorUnit::new(12050)))
                .unwrap()
                .refunds[0]
                .amount
        };
        amount(json!(12050));
        assert_eq!(reported(json!(12050)), MinorUnit::new(12050));
        assert_eq!(reported(json!(12050.0)), MinorUnit::new(12050));
        assert_eq!(reported(json!(120.5)), MinorUnit::new(121));
        assert_eq!(reported(json!("12050")), MinorUnit::new(12050));
        assert_eq!(reported(json!(" 12050.00 ")), MinorUnit::new(12050));
        for bad in [
            json!("abc"),
            json!(null),
            json!({"x": 1}),
            json!([1]),
            json!(true),
            json!(""),
        ] {
            assert_eq!(reported(bad.clone()), MinorUnit::new(0), "{bad}");
            amount(bad);
        }
    }

    #[test]
    fn a_rejection_without_reason_id_uses_the_standard_no_error_code() {
        let response = parse(json!({
            "id": 15403386,
            "status": "rejected",
            "status_details": {"error": {"type": "invalid_card", "reason": {"description": "COD.} MONTO"}}}
        }));
        let error = response.rejection(200);
        assert_eq!(error.code, consts::NO_ERROR_CODE);
        assert_eq!(error.network_decline_code, None);
        assert_eq!(error.reason.as_deref(), Some(payway::DECLINED_REASON));
        assert_eq!(error.message, "invalid_card: COD.} MONTO");

        let with_id = parse(json!({
            "id": 15403386,
            "status": "rejected",
            "status_details": {"error": {"reason": {"id": 3}}}
        }))
        .rejection(200);
        assert_eq!(with_id.code, "PD_3");
        assert_eq!(with_id.network_decline_code.as_deref(), Some("3"));
        assert_eq!(with_id.message, "payment_error");
    }

    #[test]
    fn the_declined_authorize_and_the_rejected_sync_share_the_code_format() {
        assert_eq!(payway::declined_error_code(Some("3")), "PD_3");
        assert_eq!(payway::declined_error_code(Some("-1")), "PD_-1");
        assert_eq!(payway::declined_error_code(Some("")), consts::NO_ERROR_CODE);
        assert_eq!(payway::declined_error_code(None), consts::NO_ERROR_CODE);
    }

    #[test]
    fn a_refund_made_before_the_first_sync_is_reported_when_the_sync_charges_the_attempt() {
        for attempt_status in [
            AttemptStatus::Pending,
            AttemptStatus::Authorizing,
            AttemptStatus::Authorized,
        ] {
            for (status, id) in [
                ("refunded", "refund_15403386"),
                ("REFUNDED_APPROVED", "refund_15403386"),
            ] {
                let (after, _, activity) = sync(&with_status(status), attempt_status);
                assert_eq!(after, AttemptStatus::Charged, "{status}");
                assert_eq!(only_refund(activity), (id.to_string(), true), "{status}");
            }
            // Partial refund: Charged, logged, nothing to report.
            let (after, _, activity) = sync(&with_status("approved_with_refund"), attempt_status);
            assert_eq!(after, AttemptStatus::Charged);
            assert!(activity.is_none());
            // Annulled: the payment never settled, so it is Voided with no refund.
            let (after, _, activity) = sync(&with_status("annulled"), attempt_status);
            assert_eq!(after, AttemptStatus::Voided);
            assert!(activity.is_none());
            // Approved or still pending: nothing to report.
            for status in ["approved", "pending", "rejected"] {
                assert!(
                    sync(&with_status(status), attempt_status).2.is_none(),
                    "{status}"
                );
            }
        }
    }

    fn handle_sync_response(
        attempt_status: AttemptStatus,
        body: serde_json::Value,
    ) -> PaymentsSyncRouterData {
        handle_sync_response_for(attempt_status, 12050, body)
    }

    /// Same, for an attempt whose original amount (minor units) is `original_amount`.
    fn handle_sync_response_for(
        attempt_status: AttemptStatus,
        original_amount: i64,
        body: serde_json::Value,
    ) -> PaymentsSyncRouterData {
        let mut data = sync_router_data(attempt_status);
        data.request.amount = MinorUnit::new(original_amount);
        ConnectorIntegration::<PSync, PaymentsSyncData, PaymentsResponseData>::handle_response(
            Payway::new(),
            &data,
            None,
            Response {
                headers: None,
                response: bytes::Bytes::from(body.to_string()),
                status_code: 200,
            },
        )
        .unwrap()
    }

    #[test]
    fn the_connector_reports_the_refund_of_a_charged_payment_and_keeps_its_status() {
        let data = handle_sync_response(
            AttemptStatus::Charged,
            json!({"id": 15403386, "status": "ANNULMENT_APPROVED", "amount": "12050",
                   "status_details": {"ticket": "1560", "error": null}}),
        );
        assert_eq!(data.status, AttemptStatus::Charged);
        assert!(matches!(
            &data.response,
            Ok(PaymentsResponseData::TransactionResponse { resource_id, .. })
                if resource_id.get_connector_transaction_id().ok().as_deref() == Some("15403386")
        ));
        let activity = data
            .connector_response
            .as_ref()
            .and_then(|response| response.get_reported_activity().cloned());
        assert_eq!(
            only_refund(activity),
            ("annulment_15403386".to_string(), true)
        );

        // Approved: nothing to report.
        let data = handle_sync_response(
            AttemptStatus::Charged,
            json!({"id": 15403386, "status": "approved"}),
        );
        assert_eq!(data.status, AttemptStatus::Charged);
        assert!(data.connector_response.is_none());
    }

    /// `GET /payments/{id}` as the Payway sandbox returned it (2026-10-05, ids and ticket data
    /// are sandbox values), reduced to the fields that matter.
    fn sandbox_payment(id: i64, status: &str, amount: i64) -> serde_json::Value {
        json!({
            "id": id,
            "site_transaction_id": "hs-e2e-1791207547883",
            "payment_method_id": 1,
            "card_brand": "Visa",
            "amount": amount,
            "currency": "ars",
            "status": status,
            "status_details": {
                "ticket": "3",
                "card_authorization_code": "103908",
                "address_validation_code": "VTE0011",
                "error": null
            },
            "payment_type": "single",
            "sub_payments": [],
            "site_id": "92014297",
            "fraud_detection": {"status": null}
        })
    }

    fn only_activity_refund(data: &PaymentsSyncRouterData) -> ConnectorReportedRefund {
        let activity = data
            .connector_response
            .as_ref()
            .and_then(|response| response.get_reported_activity().cloned())
            .expect("an activity is reported");
        assert!(activity.dispute.is_none());
        assert_eq!(activity.refunds.len(), 1);
        activity.refunds[0].clone()
    }

    #[test]
    fn a_partial_refund_before_the_batch_close_reports_one_cumulative_refund() {
        // Sandbox: 10000 approved, 3000 refunded in the panel -> still `approved`, amount 7000.
        let data = handle_sync_response_for(
            AttemptStatus::Charged,
            10_000,
            sandbox_payment(16132607, "approved", 7_000),
        );
        assert_eq!(data.status, AttemptStatus::Charged);
        let refund = only_activity_refund(&data);
        assert_eq!(refund.connector_refund_id, "partial_16132607_3000");
        assert_eq!(refund.amount, MinorUnit::new(3_000));
        assert_eq!(refund.status, enums::RefundStatus::Success);
        assert!(refund.amount_is_cumulative_total);
        assert!(!refund.amount_is_remaining_balance);

        // A second partial refund is a new cumulative value, hence a new id.
        let data = handle_sync_response_for(
            AttemptStatus::PartialCharged,
            10_000,
            sandbox_payment(16132607, "accredited", 5_000),
        );
        let refund = only_activity_refund(&data);
        assert_eq!(refund.connector_refund_id, "partial_16132607_5000");
        assert_eq!(refund.amount, MinorUnit::new(5_000));

        // `approved_with_refund` with a lower amount is the same report.
        let data = handle_sync_response_for(
            AttemptStatus::Charged,
            10_000,
            sandbox_payment(16132607, "APPROVED_WITH_REFUND", 7_000),
        );
        assert_eq!(
            only_activity_refund(&data).connector_refund_id,
            "partial_16132607_3000"
        );
    }

    #[test]
    fn the_refund_that_empties_the_payment_still_reports_a_balance_refund() {
        // Remainder refund: annulled, amount 0.
        let data = handle_sync_response_for(
            AttemptStatus::Charged,
            10_000,
            sandbox_payment(16132607, "annulled", 0),
        );
        assert_eq!(data.status, AttemptStatus::Charged);
        let refund = only_activity_refund(&data);
        assert_eq!(refund.connector_refund_id, "annulment_16132607");
        assert!(refund.amount_is_remaining_balance);
        assert!(!refund.amount_is_cumulative_total);

        // One-shot total refund: annulled, original amount kept.
        let data = handle_sync_response_for(
            AttemptStatus::Charged,
            10_000,
            sandbox_payment(16132608, "annulled", 10_000),
        );
        let refund = only_activity_refund(&data);
        assert_eq!(refund.connector_refund_id, "annulment_16132608");
        assert!(refund.amount_is_remaining_balance);
    }

    #[test]
    fn an_untouched_or_unusable_amount_reports_nothing() {
        // Approved with the original amount.
        let data = handle_sync_response_for(
            AttemptStatus::Charged,
            10_000,
            sandbox_payment(16132604, "approved", 10_000),
        );
        assert_eq!(data.status, AttemptStatus::Charged);
        assert!(data.connector_response.is_none());

        // An amount above the original is not a refund.
        let data = handle_sync_response_for(
            AttemptStatus::Charged,
            10_000,
            sandbox_payment(16132604, "approved", 12_000),
        );
        assert!(data.connector_response.is_none());

        // No amount at all.
        let data = handle_sync_response_for(
            AttemptStatus::Charged,
            10_000,
            json!({"id": 16132604, "status": "approved_with_refund"}),
        );
        assert!(data.connector_response.is_none());
    }

    #[test]
    fn a_partial_refund_is_reported_only_when_the_sync_leaves_the_attempt_settled() {
        let data = handle_sync_response_for(
            AttemptStatus::Pending,
            10_000,
            sandbox_payment(16132607, "approved", 7_000),
        );
        // The sync itself settles the attempt (same rule as the annulment balance refund).
        assert_eq!(data.status, AttemptStatus::Charged);
        assert_eq!(
            only_activity_refund(&data).connector_refund_id,
            "partial_16132607_3000"
        );
        // A sync that does not settle the attempt reports nothing.
        let data = handle_sync_response_for(
            AttemptStatus::Authorized,
            10_000,
            sandbox_payment(16132607, "pre_approved", 7_000),
        );
        assert!(data.connector_response.is_none());
    }
}
