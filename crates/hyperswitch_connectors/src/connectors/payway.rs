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
    router_response_types::{
        ConnectorInfo, PaymentsResponseData, RefundsResponseData, SupportedPaymentMethods,
        PaymentMethodDetails, SupportedPaymentMethodsExt,
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
    types::{self, Response,},
    webhooks,
};
use masking::{ExposeInterface, Mask};
use transformers as payway;

use crate::{constants::headers, types::ResponseRouterData, utils};

fn determine_endpoint(
    connectors: &Connectors,
    test_mode: Option<bool>,
) -> CustomResult<String, errors::ConnectorError> {
    if test_mode.unwrap_or(true) {
        Ok(connectors.payway.secondary_base_url.clone().unwrap_or(connectors.payway.base_url.to_string()))
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
    ) -> CustomResult<Vec<(String, masking::Maskable<String>)>, errors::ConnectorError> {
        let auth = payway::PaywayAuthType::try_from(&req.connector_auth_type)
            .change_context(errors::ConnectorError::FailedToObtainAuthType)?;
        Ok(vec![
            (headers::CONTENT_TYPE.to_string(), self.common_get_content_type().to_string().into()),
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
        Ok(format!("{}/tokens", determine_endpoint(connectors, req.test_mode)?))
    }

    fn get_request_body(
        &self,
        req: &TokenizationRouterData,
        _connectors: &Connectors,
    ) -> CustomResult<RequestContent, errors::ConnectorError> {
        Ok(RequestContent::Json(Box::new(payway::PaywayTokenRequest::try_from(req)?)))
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
                .set_body(types::TokenizationType::get_request_body(self, req, connectors)?)
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
    ) -> CustomResult<Vec<(String, masking::Maskable<String>)>, errors::ConnectorError> {
        let auth = payway::PaywayAuthType::try_from(auth_type)
            .change_context(errors::ConnectorError::FailedToObtainAuthType)?;
        Ok(vec![
            ("apikey".to_string(), auth.public_key.expose().into_masked()),
            (headers::AUTHORIZATION.to_string(), auth.secret_key.expose().into_masked()),
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
            });
        }

        if res.status_code == 401 {
            router_env::logger::warn!(
                status_code=res.status_code,
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
            });
        }

        if res.status_code == 400 {
            if let Ok(err_json) = res.response.parse_struct::<serde_json::Value>("PaywayErrorJson") {
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

                let reason_desc = reason
                    .and_then(|r| r.get("description"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("Payment declined");

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
                    code: format!("PD_{}", reason_id),
                    message,
                    reason: Some("payment_declined".to_string()),
                    attempt_status: Some(AttemptStatus::Failure),
                    connector_transaction_id: external_transaction_id,
                    network_advice_code: None,
                    network_decline_code: Some(reason_id),
                    network_error_message: Some(reason_desc.to_string()),
                    connector_metadata: None,
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
            network_decline_code: "unknown".to_string(),
            network_error_message: Some("unknown error".to_string()),
            connector_metadata: None,
        })
    }
}

impl ConnectorValidation for Payway {
    fn validate_mandate_payment(
        &self,
        _pm_type: Option<enums::PaymentMethodType>,
        pm_data: PaymentMethodData,
    ) -> CustomResult<(), errors::ConnectorError> {
        match pm_data {
            PaymentMethodData::Card(_) => Err(errors::ConnectorError::NotImplemented(
                "validate_mandate_payment does not support cards".to_string(),
            )
            .into()),
            _ => Ok(()),
        }
    }

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
            connector: "Payway",
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
    ) -> CustomResult<Vec<(String, masking::Maskable<String>)>, errors::ConnectorError> {
        let auth = payway::PaywayAuthType::try_from(&req.connector_auth_type)
            .change_context(errors::ConnectorError::FailedToObtainAuthType)?;
        Ok(vec![
            (headers::CONTENT_TYPE.to_string(), self.common_get_content_type().to_string().into()),
            ("apikey".to_string(), auth.secret_key.expose().into_masked()),
            ("X-Source".to_string(), Self::x_source().to_string().into()),
        ])
    }

    fn get_content_type(&self) -> &'static str {
        self.common_get_content_type()
    }

    fn get_url(
        &self,
        req: &PaymentsAuthorizeRouterData,
        connectors: &Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        Ok(format!("{}/payments", determine_endpoint(connectors, req.test_mode)?))
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
        connectors: &Connectors,
    ) -> CustomResult<Vec<(String, masking::Maskable<String>)>, errors::ConnectorError> {
        self.build_headers(req, connectors)
    }

    fn get_content_type(&self) -> &'static str {
        self.common_get_content_type()
    }

    fn get_url(
        &self,
        _req: &PaymentsSyncRouterData,
        _connectors: &Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        Err(errors::ConnectorError::NotImplemented("get_url method".to_string()).into())
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

impl ConnectorIntegration<Capture, PaymentsCaptureData, PaymentsResponseData> for Payway {
    fn get_headers(
        &self,
        req: &PaymentsCaptureRouterData,
        connectors: &Connectors,
    ) -> CustomResult<Vec<(String, masking::Maskable<String>)>, errors::ConnectorError> {
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
    ) -> CustomResult<Vec<(String, masking::Maskable<String>)>, errors::ConnectorError> {
        let auth = payway::PaywayAuthType::try_from(&req.connector_auth_type)
            .change_context(errors::ConnectorError::FailedToObtainAuthType)?;
        Ok(vec![
            (headers::CONTENT_TYPE.to_string(), types::RefundExecuteType::get_content_type(self).to_string().into()),
            ("apikey".to_string(), auth.secret_key.expose().into_masked()),
            ("X-Source".to_string(), Self::x_source().to_string().into()),
        ])
    }

    fn get_content_type(&self) -> &'static str {
        self.common_get_content_type()
    }

    fn get_url(
        &self,
        req: &RefundsRouterData<Execute>,
        connectors: &Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        Ok(format!("{}/payments/{}/refunds", determine_endpoint(connectors, req.test_mode)?, req.request.connector_transaction_id))
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
    ) -> CustomResult<Vec<(String, masking::Maskable<String>)>, errors::ConnectorError> {
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
    ) -> CustomResult<api_models::webhooks::IncomingWebhookEvent, errors::ConnectorError> {
        Err(report!(errors::ConnectorError::WebhooksNotImplemented))
    }

    fn get_webhook_resource_object(
        &self,
        _request: &webhooks::IncomingWebhookRequestDetails<'_>,
    ) -> CustomResult<Box<dyn masking::ErasedMaskSerialize>, errors::ConnectorError> {
        Err(report!(errors::ConnectorError::WebhooksNotImplemented))
    }
}

static PAYWAY_SUPPORTED_PAYMENT_METHODS: LazyLock<SupportedPaymentMethods> =
    LazyLock::new(|| {
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
