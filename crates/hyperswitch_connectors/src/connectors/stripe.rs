pub mod transformers;

use std::{collections::HashMap, sync::LazyLock};

use api_models::webhooks::IncomingWebhookEvent;
use common_enums::{
    CallConnectorAction, CaptureMethod, PaymentAction, PaymentChargeType, PaymentMethodType,
    PaymentResourceUpdateStatus, StripeChargeType,
};
use common_utils::{
    crypto,
    errors::CustomResult,
    ext_traits::{ByteSliceExt as _, BytesExt},
    request::{Method, Request, RequestBuilder, RequestContent},
    types::{
        AmountConvertor, MinorUnit, MinorUnitForConnector, StringMinorUnit,
        StringMinorUnitForConnector,
    },
};
use error_stack::ResultExt;
use hyperswitch_domain_models::{
    payment_method_data::{PaymentMethodData, WalletData},
    router_data::{AccessToken, ConnectorAuthType, ErrorResponse, RouterData},
    router_flow_types::{
        Accept, AccessTokenAuth, Authorize, Capture, CreateConnectorCustomer, Evidence, Execute,
        IncrementalAuthorization, PSync, PaymentMethodToken, RSync, Retrieve, Session,
        SetupMandate, UpdateMetadata, Upload, Void,
    },
    router_request_types::{
        AcceptDisputeRequestData, AccessTokenRequestData, ConnectorCustomerData,
        PaymentMethodTokenizationData, PaymentsAuthorizeData, PaymentsCancelData,
        PaymentsCaptureData, PaymentsIncrementalAuthorizationData, PaymentsSessionData,
        PaymentsSyncData, PaymentsUpdateMetadataData, RefundsData, RetrieveFileRequestData,
        SetupMandateRequestData, SplitRefundsRequest, SubmitEvidenceRequestData,
        UploadFileRequestData,
    },
    router_response_types::{
        AcceptDisputeResponse, ConnectorInfo, PaymentMethodDetails, PaymentsResponseData,
        RefundsResponseData, RetrieveFileResponse, SubmitEvidenceResponse, SupportedPaymentMethods,
        SupportedPaymentMethodsExt, UploadFileResponse,
    },
    types::{
        ConnectorCustomerRouterData, PaymentsAuthorizeRouterData, PaymentsCancelRouterData,
        PaymentsCaptureRouterData, PaymentsIncrementalAuthorizationRouterData,
        PaymentsSyncRouterData, PaymentsUpdateMetadataRouterData, RefundsRouterData,
        TokenizationRouterData,
    },
};
#[cfg(feature = "payouts")]
use hyperswitch_domain_models::{
    router_flow_types::{PoCancel, PoCreate, PoFulfill, PoRecipient, PoRecipientAccount},
    types::{PayoutsData, PayoutsResponseData, PayoutsRouterData},
};
#[cfg(feature = "payouts")]
use hyperswitch_interfaces::types::{
    PayoutCancelType, PayoutCreateType, PayoutFulfillType, PayoutRecipientAccountType,
    PayoutRecipientType,
};
use hyperswitch_interfaces::{
    api::{
        self,
        disputes::{AcceptDispute, Dispute, SubmitEvidence},
        files::{FilePurpose, FileUpload, RetrieveFile, UploadFile},
        ConnectorCommon, ConnectorCommonExt, ConnectorIntegration, ConnectorRedirectResponse,
        ConnectorSpecifications, ConnectorValidation, PaymentIncrementalAuthorization,
    },
    configs::Connectors,
    consts::{NO_ERROR_CODE, NO_ERROR_MESSAGE},
    disputes::DisputePayload,
    errors::ConnectorError,
    events::connector_api_logs::ConnectorEvent,
    types::{
        AcceptDisputeType, ConnectorCustomerType, IncrementalAuthorizationType,
        PaymentsAuthorizeType, PaymentsCaptureType, PaymentsSyncType, PaymentsUpdateMetadataType,
        PaymentsVoidType, RefundExecuteType, RefundSyncType, Response, RetrieveFileType,
        SubmitEvidenceType, TokenizationType, UploadFileType,
    },
    webhooks::{IncomingWebhook, IncomingWebhookRequestDetails, WebhookContext},
};
use hyperswitch_masking::{Mask as _, Maskable, PeekInterface};
use router_env::{instrument, tracing};
use stripe::auth_headers;

use self::transformers as stripe;
#[cfg(feature = "payouts")]
use crate::utils::{PayoutsData as OtherPayoutsData, RouterData as OtherRouterData};
use crate::{
    connectors::stripe::transformers::get_stripe_compatible_connect_account_header,
    constants::headers::{AUTHORIZATION, CONTENT_TYPE, STRIPE_COMPATIBLE_CONNECT_ACCOUNT},
    types::{
        AcceptDisputeRouterData, ResponseRouterData, RetrieveFileRouterData,
        SubmitEvidenceRouterData, UploadFileRouterData,
    },
    utils::{
        self, get_authorise_integrity_object, get_capture_integrity_object,
        get_refund_integrity_object, get_sync_integrity_object,
        RefundsRequestData as OtherRefundsRequestData,
    },
};
#[derive(Clone)]
pub struct Stripe {
    amount_converter: &'static (dyn AmountConvertor<Output = MinorUnit> + Sync),
    amount_converter_webhooks: &'static (dyn AmountConvertor<Output = StringMinorUnit> + Sync),
}

/// `true` for the hosted Checkout wallet, which goes through Checkout Sessions instead of
/// PaymentIntents.
fn is_stripe_checkout(payment_method_data: &PaymentMethodData) -> bool {
    matches!(
        payment_method_data,
        PaymentMethodData::Wallet(WalletData::StripeCheckout {})
    )
}

/// `true` when the connector response is a Checkout Session object.
fn is_checkout_session_body(res: &Response) -> CustomResult<bool, ConnectorError> {
    let kind: stripe::StripeObjectKind = res
        .response
        .parse_struct("StripeObjectKind")
        .change_context(ConnectorError::ResponseDeserializationFailed)?;
    Ok(kind.object.as_deref() == Some(stripe::CHECKOUT_SESSION_OBJECT))
}

impl Stripe {
    pub const fn new() -> &'static Self {
        &Self {
            amount_converter: &MinorUnitForConnector,
            amount_converter_webhooks: &StringMinorUnitForConnector,
        }
    }
}

impl<Flow, Request, Response> ConnectorCommonExt<Flow, Request, Response> for Stripe
where
    Self: ConnectorIntegration<Flow, Request, Response>,
{
    fn build_headers(
        &self,
        req: &RouterData<Flow, Request, Response>,
        _connectors: &Connectors,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, ConnectorError> {
        let mut header = vec![(
            CONTENT_TYPE.to_string(),
            Self::common_get_content_type(self).to_string().into(),
        )];
        let mut api_key = self.get_auth_header(&req.connector_auth_type)?;
        header.append(&mut api_key);
        Ok(header)
    }
}

impl ConnectorCommon for Stripe {
    fn id(&self) -> &'static str {
        "stripe"
    }

    fn common_get_content_type(&self) -> &'static str {
        "application/x-www-form-urlencoded"
    }

    fn base_url<'a>(&self, connectors: &'a Connectors) -> &'a str {
        // &self.base_url
        connectors.stripe.base_url.as_ref()
    }

    fn get_auth_header(
        &self,
        auth_type: &ConnectorAuthType,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, ConnectorError> {
        let auth = stripe::StripeAuthType::try_from(auth_type)
            .change_context(ConnectorError::FailedToObtainAuthType)?;
        Ok(vec![
            (
                AUTHORIZATION.to_string(),
                format!("Bearer {}", auth.api_key.peek()).into_masked(),
            ),
            (
                auth_headers::STRIPE_API_VERSION.to_string(),
                auth_headers::STRIPE_VERSION.to_string().into_masked(),
            ),
        ])
    }

    #[cfg(feature = "payouts")]
    fn build_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, ConnectorError> {
        use hyperswitch_interfaces::consts::NO_ERROR_CODE;

        if res.response.is_empty() {
            return Ok(ErrorResponse {
                status_code: res.status_code,
                code: NO_ERROR_CODE.to_string(),
                message: NO_ERROR_MESSAGE.to_string(),
                reason: None,
                attempt_status: None,
                connector_transaction_id: None,
                connector_response_reference_id: None,
                network_advice_code: None,
                network_decline_code: None,
                network_error_message: None,
                connector_metadata: None,
            });
        }

        let response: Result<stripe::StripeConnectErrorResponse, _> =
            res.response.parse_struct("StripeConnectErrorResponse");

        match response {
            Ok(response) => {
                event_builder.map(|i| i.set_error_response_body(&response));
                Ok(ErrorResponse {
                    status_code: res.status_code,
                    code: response
                        .error
                        .code
                        .unwrap_or_else(|| NO_ERROR_CODE.to_string()),
                    message: response
                        .error
                        .message
                        .clone()
                        .unwrap_or_else(|| NO_ERROR_MESSAGE.to_string()),
                    reason: response.error.message,
                    attempt_status: None,
                    connector_transaction_id: response.error.payment_intent.map(|pi| pi.id),
                    connector_response_reference_id: None,
                    network_advice_code: response.error.network_advice_code,
                    network_decline_code: response.error.network_decline_code,
                    network_error_message: response
                        .error
                        .decline_code
                        .or(response.error.advice_code),
                    connector_metadata: None,
                })
            }
            Err(error_msg) => {
                event_builder.map(|event| {
                    event.set_error(serde_json::json!({
                        "error": res.response.escape_ascii().to_string(),
                        "status_code": res.status_code,
                    }))
                });
                router_env::logger::error!(deserialization_error =? error_msg);
                utils::handle_json_response_deserialization_failure(res, "stripe")
            }
        }
    }
}

impl ConnectorValidation for Stripe {
    fn validate_connector_against_payment_request(
        &self,
        capture_method: Option<CaptureMethod>,
        _payment_method: common_enums::PaymentMethod,
        pmt: Option<PaymentMethodType>,
    ) -> CustomResult<(), ConnectorError> {
        let capture_method = capture_method.unwrap_or_default();
        // The hosted Checkout page charges as soon as the buyer pays: no manual capture.
        if pmt == Some(PaymentMethodType::StripeCheckout)
            && !matches!(
                capture_method,
                CaptureMethod::Automatic | CaptureMethod::SequentialAutomatic
            )
        {
            return Err(utils::construct_not_supported_error_report(
                capture_method,
                self.id(),
            ));
        }
        match capture_method {
            CaptureMethod::SequentialAutomatic
            | CaptureMethod::Automatic
            | CaptureMethod::Manual => Ok(()),
            CaptureMethod::ManualMultiple | CaptureMethod::Scheduled => Err(
                utils::construct_not_supported_error_report(capture_method, self.id()),
            ),
        }
    }
}

impl api::Payment for Stripe {}

impl api::PaymentAuthorize for Stripe {}
impl api::PaymentUpdateMetadata for Stripe {}
impl api::PaymentSync for Stripe {}
impl api::PaymentVoid for Stripe {}
impl api::PaymentCapture for Stripe {}
impl api::PaymentSession for Stripe {}
impl api::ConnectorAccessToken for Stripe {}

impl ConnectorIntegration<AccessTokenAuth, AccessTokenRequestData, AccessToken> for Stripe {
    // Not Implemented (R)
}

impl ConnectorIntegration<Session, PaymentsSessionData, PaymentsResponseData> for Stripe {
    // Not Implemented (R)
}

impl api::ConnectorCustomer for Stripe {}

impl ConnectorIntegration<CreateConnectorCustomer, ConnectorCustomerData, PaymentsResponseData>
    for Stripe
{
    fn get_headers(
        &self,
        req: &ConnectorCustomerRouterData,
        _connectors: &Connectors,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, ConnectorError> {
        let mut header = vec![(
            CONTENT_TYPE.to_string(),
            ConnectorCustomerType::get_content_type(self)
                .to_string()
                .into(),
        )];
        if let Some(common_types::payments::SplitPaymentsRequest::StripeSplitPayment(
            stripe_split_payment,
        )) = &req.request.split_payments
        {
            if stripe_split_payment.charge_type
                == PaymentChargeType::Stripe(StripeChargeType::Direct)
            {
                let mut customer_account_header = vec![(
                    STRIPE_COMPATIBLE_CONNECT_ACCOUNT.to_string(),
                    stripe_split_payment
                        .transfer_account_id
                        .clone()
                        .into_masked(),
                )];
                header.append(&mut customer_account_header);
            }
        }
        let mut api_key = self.get_auth_header(&req.connector_auth_type)?;
        header.append(&mut api_key);
        Ok(header)
    }

    fn get_content_type(&self) -> &'static str {
        self.common_get_content_type()
    }

    fn get_url(
        &self,
        _req: &ConnectorCustomerRouterData,
        connectors: &Connectors,
    ) -> CustomResult<String, ConnectorError> {
        Ok(format!("{}{}", self.base_url(connectors), "v1/customers"))
    }

    fn get_request_body(
        &self,
        req: &ConnectorCustomerRouterData,
        _connectors: &Connectors,
    ) -> CustomResult<RequestContent, ConnectorError> {
        let connector_req = stripe::CustomerRequest::try_from(req)?;
        Ok(RequestContent::FormUrlEncoded(Box::new(connector_req)))
    }

    fn build_request(
        &self,
        req: &ConnectorCustomerRouterData,
        connectors: &Connectors,
    ) -> CustomResult<Option<Request>, ConnectorError> {
        Ok(Some(
            RequestBuilder::new()
                .method(Method::Post)
                .url(&ConnectorCustomerType::get_url(self, req, connectors)?)
                .attach_default_headers()
                .headers(ConnectorCustomerType::get_headers(self, req, connectors)?)
                .set_body(ConnectorCustomerType::get_request_body(
                    self, req, connectors,
                )?)
                .build(),
        ))
    }

    fn handle_response(
        &self,
        data: &ConnectorCustomerRouterData,
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<ConnectorCustomerRouterData, ConnectorError>
    where
        PaymentsResponseData: Clone,
    {
        let response: stripe::StripeCustomerResponse = res
            .response
            .parse_struct("StripeCustomerResponse")
            .change_context(ConnectorError::ResponseDeserializationFailed)?;

        event_builder.map(|i| i.set_response_body(&response));
        router_env::logger::info!(connector_response=?response);

        RouterData::try_from(ResponseRouterData {
            response,
            data: data.clone(),
            http_code: res.status_code,
        })
        .change_context(ConnectorError::ResponseHandlingFailed)
    }

    fn get_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, ConnectorError> {
        if res.response.is_empty() {
            return Ok(ErrorResponse {
                status_code: res.status_code,
                code: NO_ERROR_CODE.to_string(),
                message: NO_ERROR_MESSAGE.to_string(),
                reason: None,
                attempt_status: None,
                connector_transaction_id: None,
                connector_response_reference_id: None,
                network_advice_code: None,
                network_decline_code: None,
                network_error_message: None,
                connector_metadata: None,
            });
        }

        let response: Result<stripe::ErrorResponse, _> = res.response.parse_struct("ErrorResponse");

        match response {
            Ok(response) => {
                event_builder.map(|i| i.set_error_response_body(&response));
                router_env::logger::info!(connector_response=?response);

                Ok(ErrorResponse {
                    status_code: res.status_code,
                    code: response
                        .error
                        .code
                        .unwrap_or_else(|| NO_ERROR_CODE.to_string()),
                    message: response
                        .error
                        .message
                        .clone()
                        .unwrap_or_else(|| NO_ERROR_MESSAGE.to_string()),
                    reason: response.error.message.map(|message| {
                        response
                            .error
                            .decline_code
                            .clone()
                            .map(|decline_code| {
                                format!("message - {message}, decline_code - {decline_code}")
                            })
                            .unwrap_or(message)
                    }),
                    attempt_status: None,
                    connector_transaction_id: response.error.payment_intent.map(|pi| pi.id),
                    connector_response_reference_id: None,
                    network_advice_code: response.error.network_advice_code,
                    network_decline_code: response.error.network_decline_code,
                    network_error_message: response
                        .error
                        .decline_code
                        .or(response.error.advice_code),
                    connector_metadata: None,
                })
            }
            Err(error_msg) => {
                event_builder.map(|event| {
                    event.set_error(serde_json::json!({
                        "error": res.response.escape_ascii().to_string(),
                        "status_code": res.status_code,
                    }))
                });
                router_env::logger::error!(deserialization_error =? error_msg);
                utils::handle_json_response_deserialization_failure(res, "stripe")
            }
        }
    }
}

impl api::PaymentToken for Stripe {}

impl ConnectorIntegration<PaymentMethodToken, PaymentMethodTokenizationData, PaymentsResponseData>
    for Stripe
{
    fn get_headers(
        &self,
        req: &TokenizationRouterData,
        _connectors: &Connectors,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, ConnectorError> {
        let mut header = vec![(
            CONTENT_TYPE.to_string(),
            TokenizationType::get_content_type(self).to_string().into(),
        )];
        if let Some(common_types::payments::SplitPaymentsRequest::StripeSplitPayment(
            stripe_split_payment,
        )) = &req.request.split_payments
        {
            if stripe_split_payment.charge_type
                == PaymentChargeType::Stripe(StripeChargeType::Direct)
            {
                let mut customer_account_header = vec![(
                    STRIPE_COMPATIBLE_CONNECT_ACCOUNT.to_string(),
                    stripe_split_payment
                        .transfer_account_id
                        .clone()
                        .into_masked(),
                )];
                header.append(&mut customer_account_header);
            }
        }
        let mut api_key = self.get_auth_header(&req.connector_auth_type)?;
        header.append(&mut api_key);
        Ok(header)
    }

    fn get_content_type(&self) -> &'static str {
        self.common_get_content_type()
    }

    fn get_url(
        &self,
        req: &TokenizationRouterData,
        connectors: &Connectors,
    ) -> CustomResult<String, ConnectorError> {
        if matches!(
            (
                req.request.split_payments.as_ref(),
                req.request.payment_method_data.clone()
            ),
            (
                Some(common_types::payments::SplitPaymentsRequest::StripeSplitPayment(_)),
                PaymentMethodData::Card(_)
                    | PaymentMethodData::CardDetailsForNetworkTransactionId(_)
            )
        ) {
            return Ok(format!(
                "{}{}",
                self.base_url(connectors),
                "v1/payment_methods"
            ));
        }
        Ok(format!("{}{}", self.base_url(connectors), "v1/tokens"))
    }

    fn get_request_body(
        &self,
        req: &TokenizationRouterData,
        _connectors: &Connectors,
    ) -> CustomResult<RequestContent, ConnectorError> {
        let connector_req = stripe::TokenRequest::try_from(req)?;
        Ok(RequestContent::FormUrlEncoded(Box::new(connector_req)))
    }

    fn build_request(
        &self,
        req: &TokenizationRouterData,
        connectors: &Connectors,
    ) -> CustomResult<Option<Request>, ConnectorError> {
        Ok(Some(
            RequestBuilder::new()
                .method(Method::Post)
                .url(&TokenizationType::get_url(self, req, connectors)?)
                .attach_default_headers()
                .headers(TokenizationType::get_headers(self, req, connectors)?)
                .set_body(TokenizationType::get_request_body(self, req, connectors)?)
                .build(),
        ))
    }

    fn handle_response(
        &self,
        data: &TokenizationRouterData,
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<TokenizationRouterData, ConnectorError>
    where
        PaymentsResponseData: Clone,
    {
        let response: stripe::StripeTokenResponse = res
            .response
            .parse_struct("StripeTokenResponse")
            .change_context(ConnectorError::ResponseDeserializationFailed)?;

        event_builder.map(|i| i.set_response_body(&response));
        router_env::logger::info!(connector_response=?response);

        RouterData::try_from(ResponseRouterData {
            response,
            data: data.clone(),
            http_code: res.status_code,
        })
        .change_context(ConnectorError::ResponseHandlingFailed)
    }

    fn get_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, ConnectorError> {
        if res.response.is_empty() {
            return Ok(ErrorResponse {
                status_code: res.status_code,
                code: NO_ERROR_CODE.to_string(),
                message: NO_ERROR_MESSAGE.to_string(),
                reason: None,
                attempt_status: None,
                connector_transaction_id: None,
                connector_response_reference_id: None,
                network_advice_code: None,
                network_decline_code: None,
                network_error_message: None,
                connector_metadata: None,
            });
        }

        let response: Result<stripe::ErrorResponse, _> = res.response.parse_struct("ErrorResponse");

        match response {
            Ok(response) => {
                event_builder.map(|i| i.set_error_response_body(&response));
                router_env::logger::info!(connector_response=?response);

                Ok(ErrorResponse {
                    status_code: res.status_code,
                    code: response
                        .error
                        .code
                        .unwrap_or_else(|| NO_ERROR_CODE.to_string()),
                    message: response
                        .error
                        .message
                        .clone()
                        .unwrap_or_else(|| NO_ERROR_MESSAGE.to_string()),
                    reason: response.error.message.map(|message| {
                        response
                            .error
                            .decline_code
                            .clone()
                            .map(|decline_code| {
                                format!("message - {message}, decline_code - {decline_code}")
                            })
                            .unwrap_or(message)
                    }),
                    attempt_status: None,
                    connector_transaction_id: response.error.payment_intent.map(|pi| pi.id),
                    connector_response_reference_id: None,
                    network_advice_code: response.error.network_advice_code,
                    network_decline_code: response.error.network_decline_code,
                    network_error_message: response
                        .error
                        .decline_code
                        .or(response.error.advice_code),
                    connector_metadata: None,
                })
            }
            Err(error_msg) => {
                event_builder.map(|event| {
                    event.set_error(serde_json::json!({
                        "error": res.response.escape_ascii().to_string(),
                        "status_code": res.status_code,
                    }))
                });
                router_env::logger::error!(deserialization_error =? error_msg);
                utils::handle_json_response_deserialization_failure(res, "stripe")
            }
        }
    }
}

impl api::MandateSetup for Stripe {}

impl ConnectorIntegration<Capture, PaymentsCaptureData, PaymentsResponseData> for Stripe {
    fn get_headers(
        &self,
        req: &PaymentsCaptureRouterData,
        _connectors: &Connectors,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, ConnectorError> {
        let mut header = vec![(
            CONTENT_TYPE.to_string(),
            Self::common_get_content_type(self).to_string().into(),
        )];
        let mut api_key = self.get_auth_header(&req.connector_auth_type)?;

        if let Some(common_types::payments::SplitPaymentsRequest::StripeSplitPayment(
            stripe_split_payment,
        )) = &req.request.split_payments
        {
            transformers::transform_headers_for_connect_platform(
                stripe_split_payment.charge_type.clone(),
                stripe_split_payment.transfer_account_id.clone(),
                &mut header,
            );
        }

        header.append(&mut api_key);
        Ok(header)
    }

    fn get_content_type(&self) -> &'static str {
        self.common_get_content_type()
    }

    fn get_url(
        &self,
        req: &PaymentsCaptureRouterData,
        connectors: &Connectors,
    ) -> CustomResult<String, ConnectorError> {
        let id = req.request.connector_transaction_id.as_str();
        Ok(format!(
            "{}{}/{}/capture",
            self.base_url(connectors),
            "v1/payment_intents",
            id
        ))
    }

    fn get_request_body(
        &self,
        req: &PaymentsCaptureRouterData,
        _connectors: &Connectors,
    ) -> CustomResult<RequestContent, ConnectorError> {
        let amount = utils::convert_amount(
            self.amount_converter,
            req.request.minor_amount_to_capture,
            req.request.currency,
        )?;
        let connector_req = stripe::CaptureRequest::try_from(amount)?;
        Ok(RequestContent::FormUrlEncoded(Box::new(connector_req)))
    }

    fn build_request(
        &self,
        req: &PaymentsCaptureRouterData,
        connectors: &Connectors,
    ) -> CustomResult<Option<Request>, ConnectorError> {
        Ok(Some(
            RequestBuilder::new()
                .method(Method::Post)
                .url(&PaymentsCaptureType::get_url(self, req, connectors)?)
                .attach_default_headers()
                .headers(PaymentsCaptureType::get_headers(self, req, connectors)?)
                .set_body(PaymentsCaptureType::get_request_body(
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
    ) -> CustomResult<PaymentsCaptureRouterData, ConnectorError>
    where
        PaymentsCaptureData: Clone,
        PaymentsResponseData: Clone,
    {
        let response: stripe::PaymentIntentResponse = res
            .response
            .parse_struct("PaymentIntentResponse")
            .change_context(ConnectorError::ResponseDeserializationFailed)?;

        let response_integrity_object = get_capture_integrity_object(
            self.amount_converter,
            response.amount_received,
            response.currency.clone(),
        )?;

        event_builder.map(|i| i.set_response_body(&response));
        router_env::logger::info!(connector_response=?response);

        let new_router_data = RouterData::try_from(ResponseRouterData {
            response,
            data: data.clone(),
            http_code: res.status_code,
        })
        .change_context(ConnectorError::ResponseHandlingFailed);

        new_router_data.map(|mut router_data| {
            router_data.request.integrity_object = Some(response_integrity_object);
            router_data
        })
    }

    fn get_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, ConnectorError> {
        if res.response.is_empty() {
            return Ok(ErrorResponse {
                status_code: res.status_code,
                code: NO_ERROR_CODE.to_string(),
                message: NO_ERROR_MESSAGE.to_string(),
                reason: None,
                attempt_status: None,
                connector_transaction_id: None,
                connector_response_reference_id: None,
                network_advice_code: None,
                network_decline_code: None,
                network_error_message: None,
                connector_metadata: None,
            });
        }

        let response: Result<stripe::ErrorResponse, _> = res.response.parse_struct("ErrorResponse");

        match response {
            Ok(response) => {
                event_builder.map(|i| i.set_error_response_body(&response));
                router_env::logger::info!(connector_response=?response);

                Ok(ErrorResponse {
                    status_code: res.status_code,
                    code: response
                        .error
                        .code
                        .unwrap_or_else(|| NO_ERROR_CODE.to_string()),
                    message: response
                        .error
                        .message
                        .clone()
                        .unwrap_or_else(|| NO_ERROR_MESSAGE.to_string()),
                    reason: response.error.message.map(|message| {
                        response
                            .error
                            .decline_code
                            .clone()
                            .map(|decline_code| {
                                format!("message - {message}, decline_code - {decline_code}")
                            })
                            .unwrap_or(message)
                    }),
                    attempt_status: None,
                    connector_transaction_id: response.error.payment_intent.map(|pi| pi.id),
                    connector_response_reference_id: None,
                    network_advice_code: response.error.network_advice_code,
                    network_decline_code: response.error.network_decline_code,
                    network_error_message: response
                        .error
                        .decline_code
                        .or(response.error.advice_code),
                    connector_metadata: None,
                })
            }
            Err(error_msg) => {
                event_builder.map(|event| {
                    event.set_error(serde_json::json!({
                        "error": res.response.escape_ascii().to_string(),
                        "status_code": res.status_code,
                    }))
                });
                router_env::logger::error!(deserialization_error =? error_msg);
                utils::handle_json_response_deserialization_failure(res, "stripe")
            }
        }
    }
}

impl ConnectorIntegration<PSync, PaymentsSyncData, PaymentsResponseData> for Stripe {
    fn get_headers(
        &self,
        req: &PaymentsSyncRouterData,
        _connectors: &Connectors,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, ConnectorError> {
        let mut header = vec![(
            CONTENT_TYPE.to_string(),
            PaymentsSyncType::get_content_type(self).to_string().into(),
        )];
        let mut api_key = self.get_auth_header(&req.connector_auth_type)?;
        header.append(&mut api_key);

        if let Some(common_types::payments::SplitPaymentsRequest::StripeSplitPayment(
            stripe_split_payment,
        )) = &req.request.split_payments
        {
            transformers::transform_headers_for_connect_platform(
                stripe_split_payment.charge_type.clone(),
                stripe_split_payment.transfer_account_id.clone(),
                &mut header,
            );
        }
        Ok(header)
    }

    fn get_content_type(&self) -> &'static str {
        self.common_get_content_type()
    }

    fn get_url(
        &self,
        req: &PaymentsSyncRouterData,
        connectors: &Connectors,
    ) -> CustomResult<String, ConnectorError> {
        let id = req.request.connector_transaction_id.clone();

        match id.get_connector_transaction_id() {
            // Expand the PaymentIntent so a completed session promotes it in one call.
            Ok(x) if stripe::is_checkout_session_id(&x) => Ok(stripe::checkout_session_sync_url(
                self.base_url(connectors),
                &x,
            )),
            Ok(x) if x.starts_with("set") => Ok(format!(
                "{}{}/{}?expand[0]=latest_attempt", // expand latest attempt to extract payment checks and three_d_secure data
                self.base_url(connectors),
                "v1/setup_intents",
                x,
            )),
            Ok(x) if x.starts_with("ch_") => Ok(format!(
                "{}{}/{}",
                self.base_url(connectors),
                "v1/charges",
                x,
            )),
            Ok(x) => Ok(payment_intent_sync_url(self.base_url(connectors), &x)),
            x => x.change_context(ConnectorError::MissingConnectorTransactionID),
        }
    }

    fn build_request(
        &self,
        req: &PaymentsSyncRouterData,
        connectors: &Connectors,
    ) -> CustomResult<Option<Request>, ConnectorError> {
        Ok(Some(
            RequestBuilder::new()
                .method(Method::Get)
                .url(&PaymentsSyncType::get_url(self, req, connectors)?)
                .attach_default_headers()
                .headers(PaymentsSyncType::get_headers(self, req, connectors)?)
                .build(),
        ))
    }

    fn handle_response(
        &self,
        data: &PaymentsSyncRouterData,
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<PaymentsSyncRouterData, ConnectorError>
    where
        PaymentsResponseData: Clone,
    {
        let id = data.request.connector_transaction_id.clone();
        match id.get_connector_transaction_id() {
            // A webhook-driven sync hands the PaymentIntent event object to an attempt that
            // still holds the session id: only a real `checkout.session` takes this branch.
            Ok(x) if stripe::is_checkout_session_id(&x) && is_checkout_session_body(&res)? => {
                let response: stripe::StripeCheckoutSessionResponse = res
                    .response
                    .parse_struct("StripeCheckoutSessionResponse")
                    .change_context(ConnectorError::ResponseDeserializationFailed)?;

                let response_integrity_object = response
                    .amount_and_currency()
                    .map(|(amount, currency)| {
                        get_sync_integrity_object(self.amount_converter, amount, currency)
                    })
                    .transpose()?;

                event_builder.map(|i| i.set_response_body(&response));
                router_env::logger::info!(connector_response=?response);

                RouterData::try_from(ResponseRouterData {
                    response,
                    data: data.clone(),
                    http_code: res.status_code,
                })
                .map(|mut router_data: PaymentsSyncRouterData| {
                    router_data.request.integrity_object = response_integrity_object;
                    router_data
                })
            }
            Ok(x) if x.starts_with("set") => {
                let response: stripe::SetupIntentResponse = res
                    .response
                    .parse_struct("SetupIntentSyncResponse")
                    .change_context(ConnectorError::ResponseDeserializationFailed)?;

                event_builder.map(|i| i.set_response_body(&response));
                router_env::logger::info!(connector_response=?response);

                RouterData::try_from(ResponseRouterData {
                    response,
                    data: data.clone(),
                    http_code: res.status_code,
                })
            }
            Ok(x) if x.starts_with("ch_") => {
                let response: stripe::ChargeSyncResponse = res
                    .response
                    .parse_struct("ChargeSyncResponse")
                    .change_context(ConnectorError::ResponseDeserializationFailed)?;

                event_builder.map(|i| i.set_response_body(&response));
                router_env::logger::info!(connector_response=?response);

                RouterData::try_from(ResponseRouterData {
                    response,
                    data: data.clone(),
                    http_code: res.status_code,
                })
            }
            Ok(_) => {
                let response: stripe::PaymentIntentSyncResponse = res
                    .response
                    .parse_struct("PaymentIntentSyncResponse")
                    .change_context(ConnectorError::ResponseDeserializationFailed)?;

                let response_integrity_object = get_sync_integrity_object(
                    self.amount_converter,
                    response.amount,
                    response.currency.clone(),
                )?;

                event_builder.map(|i| i.set_response_body(&response));
                router_env::logger::info!(connector_response=?response);

                // Built from the response BEFORE it is consumed by `try_from` below. The
                // charge refunds come with the `latest_charge.refunds` expansion of the sync
                // URL and include the refunds made outside Hyperswitch (Stripe dashboard).
                let reported_activity = response.reported_activity();

                let new_router_data = RouterData::try_from(ResponseRouterData {
                    response,
                    data: data.clone(),
                    http_code: res.status_code,
                });
                new_router_data.map(|mut router_data| {
                    router_data.request.integrity_object = Some(response_integrity_object);
                    stripe::finish_payment_intent_sync(
                        router_data,
                        data.status,
                        &data.request.connector_transaction_id,
                        reported_activity,
                    )
                })
            }
            Err(err) => Err(err).change_context(ConnectorError::MissingConnectorTransactionID),
        }
    }

    fn get_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, ConnectorError> {
        if res.response.is_empty() {
            return Ok(ErrorResponse {
                status_code: res.status_code,
                code: NO_ERROR_CODE.to_string(),
                message: NO_ERROR_MESSAGE.to_string(),
                reason: None,
                attempt_status: None,
                connector_transaction_id: None,
                connector_response_reference_id: None,
                network_advice_code: None,
                network_decline_code: None,
                network_error_message: None,
                connector_metadata: None,
            });
        }

        let response: Result<stripe::ErrorResponse, _> = res.response.parse_struct("ErrorResponse");

        match response {
            Ok(response) => {
                event_builder.map(|i| i.set_error_response_body(&response));
                router_env::logger::info!(connector_response=?response);

                Ok(ErrorResponse {
                    status_code: res.status_code,
                    code: response
                        .error
                        .code
                        .unwrap_or_else(|| NO_ERROR_CODE.to_string()),
                    message: response
                        .error
                        .message
                        .clone()
                        .unwrap_or_else(|| NO_ERROR_MESSAGE.to_string()),
                    reason: response.error.message.map(|message| {
                        response
                            .error
                            .decline_code
                            .clone()
                            .map(|decline_code| {
                                format!("message - {message}, decline_code - {decline_code}")
                            })
                            .unwrap_or(message)
                    }),
                    attempt_status: None,
                    connector_transaction_id: response.error.payment_intent.map(|pi| pi.id),
                    connector_response_reference_id: None,
                    network_advice_code: response.error.network_advice_code,
                    network_decline_code: response.error.network_decline_code,
                    network_error_message: response
                        .error
                        .decline_code
                        .or(response.error.advice_code),
                    connector_metadata: None,
                })
            }
            Err(error_msg) => {
                event_builder.map(|event| {
                    event.set_error(serde_json::json!({
                        "error": res.response.escape_ascii().to_string(),
                        "status_code": res.status_code,
                    }))
                });
                router_env::logger::error!(deserialization_error =? error_msg);
                utils::handle_json_response_deserialization_failure(res, "stripe")
            }
        }
    }
}

#[async_trait::async_trait]
impl ConnectorIntegration<Authorize, PaymentsAuthorizeData, PaymentsResponseData> for Stripe {
    fn get_headers(
        &self,
        req: &PaymentsAuthorizeRouterData,
        _connectors: &Connectors,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, ConnectorError> {
        let mut header = vec![(
            CONTENT_TYPE.to_string(),
            PaymentsAuthorizeType::get_content_type(self)
                .to_string()
                .into(),
        )];

        let mut api_key = self.get_auth_header(&req.connector_auth_type)?;
        header.append(&mut api_key);

        if let Some(id) = get_stripe_compatible_connect_account_header(req)? {
            let mut customer_account_header = vec![(
                STRIPE_COMPATIBLE_CONNECT_ACCOUNT.to_string(),
                id.into_masked(),
            )];
            header.append(&mut customer_account_header);
        }
        Ok(header)
    }

    fn get_content_type(&self) -> &'static str {
        self.common_get_content_type()
    }

    fn get_url(
        &self,
        req: &PaymentsAuthorizeRouterData,
        connectors: &Connectors,
    ) -> CustomResult<String, ConnectorError> {
        let path = if is_stripe_checkout(&req.request.payment_method_data) {
            "v1/checkout/sessions"
        } else {
            "v1/payment_intents"
        };
        Ok(format!("{}{}", self.base_url(connectors), path))
    }

    fn get_request_body(
        &self,
        req: &PaymentsAuthorizeRouterData,
        _connectors: &Connectors,
    ) -> CustomResult<RequestContent, ConnectorError> {
        let amount = utils::convert_amount(
            self.amount_converter,
            req.request.minor_amount,
            req.request.currency,
        )?;
        if is_stripe_checkout(&req.request.payment_method_data) {
            let connector_req = stripe::StripeCheckoutSessionRequest::try_from((req, amount))?;
            return Ok(RequestContent::FormUrlEncoded(Box::new(connector_req)));
        }
        let connector_req = stripe::PaymentIntentRequest::try_from((req, amount))?;

        Ok(RequestContent::FormUrlEncoded(Box::new(connector_req)))
    }

    fn build_request(
        &self,
        req: &PaymentsAuthorizeRouterData,
        connectors: &Connectors,
    ) -> CustomResult<Option<Request>, ConnectorError> {
        Ok(Some(
            RequestBuilder::new()
                .method(Method::Post)
                .url(&PaymentsAuthorizeType::get_url(self, req, connectors)?)
                .attach_default_headers()
                .headers(PaymentsAuthorizeType::get_headers(self, req, connectors)?)
                .set_body(PaymentsAuthorizeType::get_request_body(
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
    ) -> CustomResult<PaymentsAuthorizeRouterData, ConnectorError> {
        if is_stripe_checkout(&data.request.payment_method_data) {
            let response: stripe::StripeCheckoutSessionResponse = res
                .response
                .parse_struct("StripeCheckoutSessionResponse")
                .change_context(ConnectorError::ResponseDeserializationFailed)?;

            let response_integrity_object = match (response.amount_total, response.currency.clone())
            {
                (Some(amount), Some(currency)) => Some(get_authorise_integrity_object(
                    self.amount_converter,
                    amount,
                    currency,
                )?),
                _ => None,
            };

            event_builder.map(|i| i.set_response_body(&response));
            router_env::logger::info!(connector_response=?response);

            return RouterData::try_from(ResponseRouterData {
                response,
                data: data.clone(),
                http_code: res.status_code,
            })
            .change_context(ConnectorError::ResponseHandlingFailed)
            .map(|mut router_data: PaymentsAuthorizeRouterData| {
                router_data.request.integrity_object = response_integrity_object;
                router_data
            });
        }
        let response: stripe::PaymentIntentResponse = res
            .response
            .parse_struct("PaymentIntentResponse")
            .change_context(ConnectorError::ResponseDeserializationFailed)?;

        let response_integrity_object = get_authorise_integrity_object(
            self.amount_converter,
            response.amount,
            response.currency.clone(),
        )?;

        event_builder.map(|i| i.set_response_body(&response));
        router_env::logger::info!(connector_response=?response);

        let new_router_data = RouterData::try_from(ResponseRouterData {
            response,
            data: data.clone(),
            http_code: res.status_code,
        })
        .change_context(ConnectorError::ResponseHandlingFailed);

        new_router_data.map(|mut router_data| {
            router_data.request.integrity_object = Some(response_integrity_object);
            router_data
        })
    }

    fn get_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, ConnectorError> {
        if res.response.is_empty() {
            return Ok(ErrorResponse {
                status_code: res.status_code,
                code: NO_ERROR_CODE.to_string(),
                message: NO_ERROR_MESSAGE.to_string(),
                reason: None,
                attempt_status: None,
                connector_transaction_id: None,
                connector_response_reference_id: None,
                network_advice_code: None,
                network_decline_code: None,
                network_error_message: None,
                connector_metadata: None,
            });
        }

        let response: Result<stripe::ErrorResponse, _> = res.response.parse_struct("ErrorResponse");

        match response {
            Ok(response) => {
                event_builder.map(|i| i.set_error_response_body(&response));
                router_env::logger::info!(connector_response=?response);

                Ok(ErrorResponse {
                    status_code: res.status_code,
                    code: response
                        .error
                        .code
                        .unwrap_or_else(|| NO_ERROR_CODE.to_string()),
                    message: response
                        .error
                        .message
                        .clone()
                        .unwrap_or_else(|| NO_ERROR_MESSAGE.to_string()),
                    reason: response.error.message.map(|message| {
                        response
                            .error
                            .decline_code
                            .clone()
                            .map(|decline_code| {
                                format!("message - {message}, decline_code - {decline_code}")
                            })
                            .unwrap_or(message)
                    }),
                    attempt_status: None,
                    connector_transaction_id: response.error.payment_intent.map(|pi| pi.id),
                    connector_response_reference_id: None,
                    network_advice_code: response.error.network_advice_code,
                    network_decline_code: response.error.network_decline_code,
                    network_error_message: response
                        .error
                        .decline_code
                        .or(response.error.advice_code),
                    connector_metadata: None,
                })
            }
            Err(error_msg) => {
                event_builder.map(|event| {
                    event.set_error(serde_json::json!({
                        "error": res.response.escape_ascii().to_string(),
                        "status_code": res.status_code,
                    }))
                });
                router_env::logger::error!(deserialization_error =? error_msg);
                utils::handle_json_response_deserialization_failure(res, "stripe")
            }
        }
    }
}

impl PaymentIncrementalAuthorization for Stripe {}

impl
    ConnectorIntegration<
        IncrementalAuthorization,
        PaymentsIncrementalAuthorizationData,
        PaymentsResponseData,
    > for Stripe
{
    fn get_headers(
        &self,
        req: &PaymentsIncrementalAuthorizationRouterData,
        connectors: &Connectors,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, ConnectorError> {
        self.build_headers(req, connectors)
    }

    fn get_http_method(&self) -> Method {
        Method::Post
    }

    fn get_content_type(&self) -> &'static str {
        self.common_get_content_type()
    }

    fn get_url(
        &self,
        req: &PaymentsIncrementalAuthorizationRouterData,
        connectors: &Connectors,
    ) -> CustomResult<String, ConnectorError> {
        Ok(format!(
            "{}v1/payment_intents/{}/increment_authorization",
            self.base_url(connectors),
            req.request.connector_transaction_id,
        ))
    }

    fn get_request_body(
        &self,
        req: &PaymentsIncrementalAuthorizationRouterData,
        _connectors: &Connectors,
    ) -> CustomResult<RequestContent, ConnectorError> {
        let amount = utils::convert_amount(
            self.amount_converter,
            MinorUnit::new(req.request.total_amount),
            req.request.currency,
        )?;
        let connector_req = stripe::StripeIncrementalAuthRequest { amount }; // Incremental authorization can be done a maximum of 10 times in Stripe

        Ok(RequestContent::FormUrlEncoded(Box::new(connector_req)))
    }

    fn build_request(
        &self,
        req: &PaymentsIncrementalAuthorizationRouterData,
        connectors: &Connectors,
    ) -> CustomResult<Option<Request>, ConnectorError> {
        Ok(Some(
            RequestBuilder::new()
                .method(Method::Post)
                .url(&IncrementalAuthorizationType::get_url(
                    self, req, connectors,
                )?)
                .attach_default_headers()
                .headers(IncrementalAuthorizationType::get_headers(
                    self, req, connectors,
                )?)
                .set_body(IncrementalAuthorizationType::get_request_body(
                    self, req, connectors,
                )?)
                .build(),
        ))
    }

    fn handle_response(
        &self,
        data: &PaymentsIncrementalAuthorizationRouterData,
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<
        RouterData<
            IncrementalAuthorization,
            PaymentsIncrementalAuthorizationData,
            PaymentsResponseData,
        >,
        ConnectorError,
    > {
        let response: stripe::PaymentIntentResponse = res
            .response
            .parse_struct("PaymentIntentResponse")
            .change_context(ConnectorError::ResponseDeserializationFailed)?;

        event_builder.map(|i| i.set_response_body(&response));
        router_env::logger::info!(connector_response=?response);

        RouterData::try_from(ResponseRouterData {
            response,
            data: data.clone(),
            http_code: res.status_code,
        })
        .change_context(ConnectorError::ResponseHandlingFailed)
    }

    fn get_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, ConnectorError> {
        if res.response.is_empty() {
            return Ok(ErrorResponse {
                status_code: res.status_code,
                code: NO_ERROR_CODE.to_string(),
                message: NO_ERROR_MESSAGE.to_string(),
                reason: None,
                attempt_status: None,
                connector_transaction_id: None,
                connector_response_reference_id: None,
                network_advice_code: None,
                network_decline_code: None,
                network_error_message: None,
                connector_metadata: None,
            });
        }

        let response: Result<stripe::ErrorResponse, _> = res.response.parse_struct("ErrorResponse");

        match response {
            Ok(response) => {
                event_builder.map(|i| i.set_error_response_body(&response));
                router_env::logger::info!(connector_response=?response);

                Ok(ErrorResponse {
                    status_code: res.status_code,
                    code: response
                        .error
                        .code
                        .unwrap_or_else(|| NO_ERROR_CODE.to_string()),
                    message: response
                        .error
                        .message
                        .clone()
                        .unwrap_or_else(|| NO_ERROR_MESSAGE.to_string()),
                    reason: response.error.message.map(|message| {
                        response
                            .error
                            .decline_code
                            .clone()
                            .map(|decline_code| {
                                format!("message - {message}, decline_code - {decline_code}")
                            })
                            .unwrap_or(message)
                    }),
                    attempt_status: None,
                    connector_transaction_id: response.error.payment_intent.map(|pi| pi.id),
                    connector_response_reference_id: None,
                    network_advice_code: response.error.network_advice_code,
                    network_decline_code: response.error.network_decline_code,
                    network_error_message: response
                        .error
                        .decline_code
                        .or(response.error.advice_code),
                    connector_metadata: None,
                })
            }
            Err(error_msg) => {
                event_builder.map(|event| {
                    event.set_error(serde_json::json!({
                        "error": res.response.escape_ascii().to_string(),
                        "status_code": res.status_code,
                    }))
                });
                router_env::logger::error!(deserialization_error =? error_msg);
                utils::handle_json_response_deserialization_failure(res, "stripe")
            }
        }
    }
}

impl ConnectorIntegration<UpdateMetadata, PaymentsUpdateMetadataData, PaymentsResponseData>
    for Stripe
{
    fn get_headers(
        &self,
        req: &RouterData<UpdateMetadata, PaymentsUpdateMetadataData, PaymentsResponseData>,
        connectors: &Connectors,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, ConnectorError> {
        self.build_headers(req, connectors)
    }

    fn get_content_type(&self) -> &'static str {
        "application/x-www-form-urlencoded"
    }

    fn get_url(
        &self,
        req: &PaymentsUpdateMetadataRouterData,
        connectors: &Connectors,
    ) -> CustomResult<String, ConnectorError> {
        let payment_id = &req.request.connector_transaction_id;
        Ok(format!(
            "{}v1/payment_intents/{}",
            self.base_url(connectors),
            payment_id
        ))
    }

    fn get_request_body(
        &self,
        req: &PaymentsUpdateMetadataRouterData,
        _connectors: &Connectors,
    ) -> CustomResult<RequestContent, ConnectorError> {
        let connector_req = stripe::UpdateMetadataRequest::try_from(req)?;
        Ok(RequestContent::FormUrlEncoded(Box::new(connector_req)))
    }

    fn build_request(
        &self,
        req: &PaymentsUpdateMetadataRouterData,
        connectors: &Connectors,
    ) -> CustomResult<Option<Request>, ConnectorError> {
        let request = RequestBuilder::new()
            .method(Method::Post)
            .url(&PaymentsUpdateMetadataType::get_url(self, req, connectors)?)
            .attach_default_headers()
            .headers(PaymentsUpdateMetadataType::get_headers(
                self, req, connectors,
            )?)
            .set_body(PaymentsUpdateMetadataType::get_request_body(
                self, req, connectors,
            )?)
            .build();
        Ok(Some(request))
    }

    fn handle_response(
        &self,
        data: &PaymentsUpdateMetadataRouterData,
        _event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<PaymentsUpdateMetadataRouterData, ConnectorError> {
        router_env::logger::debug!("skipped parsing of the response");
        // If 200 status code, then metadata was updated successfully.
        let status = if res.status_code == 200 {
            PaymentResourceUpdateStatus::Success
        } else {
            PaymentResourceUpdateStatus::Failure
        };
        Ok(PaymentsUpdateMetadataRouterData {
            response: Ok(PaymentsResponseData::PaymentResourceUpdateResponse { status }),
            ..data.clone()
        })
    }

    fn get_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, ConnectorError> {
        self.build_error_response(res, event_builder)
    }
}

impl ConnectorIntegration<Void, PaymentsCancelData, PaymentsResponseData> for Stripe {
    fn get_headers(
        &self,
        req: &PaymentsCancelRouterData,
        _connectors: &Connectors,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, ConnectorError> {
        let mut header = vec![(
            CONTENT_TYPE.to_string(),
            PaymentsVoidType::get_content_type(self).to_string().into(),
        )];
        let mut api_key = self.get_auth_header(&req.connector_auth_type)?;

        if let Some(common_types::payments::SplitPaymentsRequest::StripeSplitPayment(
            stripe_split_payment,
        )) = &req.request.split_payments
        {
            transformers::transform_headers_for_connect_platform(
                stripe_split_payment.charge_type.clone(),
                stripe_split_payment.transfer_account_id.clone(),
                &mut header,
            );
        }

        header.append(&mut api_key);
        Ok(header)
    }

    fn get_content_type(&self) -> &'static str {
        self.common_get_content_type()
    }

    fn get_url(
        &self,
        req: &PaymentsCancelRouterData,
        connectors: &Connectors,
    ) -> CustomResult<String, ConnectorError> {
        let payment_id = &req.request.connector_transaction_id;
        if stripe::is_checkout_session_id(payment_id) {
            // An unpaid Checkout Session cannot be cancelled, it is expired instead.
            return Ok(stripe::checkout_session_expire_url(
                self.base_url(connectors),
                payment_id,
            ));
        }
        Ok(format!(
            "{}v1/payment_intents/{}/cancel",
            self.base_url(connectors),
            payment_id
        ))
    }

    fn get_request_body(
        &self,
        req: &PaymentsCancelRouterData,
        _connectors: &Connectors,
    ) -> CustomResult<RequestContent, ConnectorError> {
        if stripe::is_checkout_session_id(&req.request.connector_transaction_id) {
            return Ok(RequestContent::FormUrlEncoded(Box::new(
                stripe::StripeEmptyRequest::default(),
            )));
        }
        let connector_req = stripe::CancelRequest::try_from(req)?;
        Ok(RequestContent::FormUrlEncoded(Box::new(connector_req)))
    }

    fn build_request(
        &self,
        req: &PaymentsCancelRouterData,
        connectors: &Connectors,
    ) -> CustomResult<Option<Request>, ConnectorError> {
        let request = RequestBuilder::new()
            .method(Method::Post)
            .url(&PaymentsVoidType::get_url(self, req, connectors)?)
            .attach_default_headers()
            .headers(PaymentsVoidType::get_headers(self, req, connectors)?)
            .set_body(PaymentsVoidType::get_request_body(self, req, connectors)?)
            .build();
        Ok(Some(request))
    }

    fn handle_response(
        &self,
        data: &PaymentsCancelRouterData,
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<PaymentsCancelRouterData, ConnectorError> {
        if stripe::is_checkout_session_id(&data.request.connector_transaction_id) {
            let response: stripe::StripeCheckoutSessionVoidResponse = res
                .response
                .parse_struct("StripeCheckoutSessionVoidResponse")
                .change_context(ConnectorError::ResponseDeserializationFailed)?;

            event_builder.map(|i| i.set_response_body(&response));
            router_env::logger::info!(connector_response=?response);

            return RouterData::try_from(ResponseRouterData {
                response,
                data: data.clone(),
                http_code: res.status_code,
            })
            .change_context(ConnectorError::ResponseHandlingFailed);
        }
        let response: stripe::PaymentIntentResponse = res
            .response
            .parse_struct("PaymentIntentResponse")
            .change_context(ConnectorError::ResponseDeserializationFailed)?;

        event_builder.map(|i| i.set_response_body(&response));
        router_env::logger::info!(connector_response=?response);

        RouterData::try_from(ResponseRouterData {
            response,
            data: data.clone(),
            http_code: res.status_code,
        })
        .change_context(ConnectorError::ResponseHandlingFailed)
    }

    fn get_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, ConnectorError> {
        if res.response.is_empty() {
            return Ok(ErrorResponse {
                status_code: res.status_code,
                code: NO_ERROR_CODE.to_string(),
                message: NO_ERROR_MESSAGE.to_string(),
                reason: None,
                attempt_status: None,
                connector_transaction_id: None,
                connector_response_reference_id: None,
                network_advice_code: None,
                network_decline_code: None,
                network_error_message: None,
                connector_metadata: None,
            });
        }

        let response: Result<stripe::ErrorResponse, _> = res.response.parse_struct("ErrorResponse");

        match response {
            Ok(response) => {
                event_builder.map(|i| i.set_error_response_body(&response));
                router_env::logger::info!(connector_response=?response);

                Ok(ErrorResponse {
                    status_code: res.status_code,
                    code: response
                        .error
                        .code
                        .unwrap_or_else(|| NO_ERROR_CODE.to_string()),
                    message: response
                        .error
                        .message
                        .clone()
                        .unwrap_or_else(|| NO_ERROR_MESSAGE.to_string()),
                    reason: response.error.message.map(|message| {
                        response
                            .error
                            .decline_code
                            .clone()
                            .map(|decline_code| {
                                format!("message - {message}, decline_code - {decline_code}")
                            })
                            .unwrap_or(message)
                    }),
                    attempt_status: None,
                    connector_transaction_id: response.error.payment_intent.map(|pi| pi.id),
                    connector_response_reference_id: None,
                    network_advice_code: response.error.network_advice_code,
                    network_decline_code: response.error.network_decline_code,
                    network_error_message: response
                        .error
                        .decline_code
                        .or(response.error.advice_code),
                    connector_metadata: None,
                })
            }
            Err(error_msg) => {
                event_builder.map(|event| {
                    event.set_error(serde_json::json!({
                        "error": res.response.escape_ascii().to_string(),
                        "status_code": res.status_code,
                    }))
                });
                router_env::logger::error!(deserialization_error =? error_msg);
                utils::handle_json_response_deserialization_failure(res, "stripe")
            }
        }
    }
}

type Verify = dyn ConnectorIntegration<SetupMandate, SetupMandateRequestData, PaymentsResponseData>;
impl ConnectorIntegration<SetupMandate, SetupMandateRequestData, PaymentsResponseData> for Stripe {
    fn get_headers(
        &self,
        req: &RouterData<SetupMandate, SetupMandateRequestData, PaymentsResponseData>,
        _connectors: &Connectors,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, ConnectorError> {
        let mut header = vec![(
            CONTENT_TYPE.to_string(),
            Verify::get_content_type(self).to_string().into(),
        )];
        let mut api_key = self.get_auth_header(&req.connector_auth_type)?;

        if let Some(common_types::payments::SplitPaymentsRequest::StripeSplitPayment(
            stripe_split_payment,
        )) = &req.request.split_payments
        {
            transformers::transform_headers_for_connect_platform(
                stripe_split_payment.charge_type.clone(),
                stripe_split_payment.transfer_account_id.clone(),
                &mut header,
            );
        }
        header.append(&mut api_key);
        Ok(header)
    }

    fn get_content_type(&self) -> &'static str {
        self.common_get_content_type()
    }

    fn get_url(
        &self,
        _req: &RouterData<SetupMandate, SetupMandateRequestData, PaymentsResponseData>,
        connectors: &Connectors,
    ) -> CustomResult<String, ConnectorError> {
        Ok(format!(
            "{}{}",
            self.base_url(connectors),
            "v1/setup_intents"
        ))
    }

    fn get_request_body(
        &self,
        req: &RouterData<SetupMandate, SetupMandateRequestData, PaymentsResponseData>,
        _connectors: &Connectors,
    ) -> CustomResult<RequestContent, ConnectorError> {
        let connector_req = stripe::SetupIntentRequest::try_from(req)?;
        Ok(RequestContent::FormUrlEncoded(Box::new(connector_req)))
    }

    fn build_request(
        &self,
        req: &RouterData<SetupMandate, SetupMandateRequestData, PaymentsResponseData>,
        connectors: &Connectors,
    ) -> CustomResult<Option<Request>, ConnectorError> {
        Ok(Some(
            RequestBuilder::new()
                .method(Method::Post)
                .url(&Verify::get_url(self, req, connectors)?)
                .attach_default_headers()
                .headers(Verify::get_headers(self, req, connectors)?)
                .set_body(Verify::get_request_body(self, req, connectors)?)
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
        ConnectorError,
    >
    where
        SetupMandate: Clone,
        SetupMandateRequestData: Clone,
        PaymentsResponseData: Clone,
    {
        let response: stripe::SetupIntentResponse = res
            .response
            .parse_struct("SetupIntentResponse")
            .change_context(ConnectorError::ResponseDeserializationFailed)?;

        event_builder.map(|i| i.set_response_body(&response));
        router_env::logger::info!(connector_response=?response);

        RouterData::try_from(ResponseRouterData {
            response,
            data: data.clone(),
            http_code: res.status_code,
        })
        .change_context(ConnectorError::ResponseHandlingFailed)
    }

    fn get_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, ConnectorError> {
        if res.response.is_empty() {
            return Ok(ErrorResponse {
                status_code: res.status_code,
                code: NO_ERROR_CODE.to_string(),
                message: NO_ERROR_MESSAGE.to_string(),
                reason: None,
                attempt_status: None,
                connector_transaction_id: None,
                connector_response_reference_id: None,
                network_advice_code: None,
                network_decline_code: None,
                network_error_message: None,
                connector_metadata: None,
            });
        }

        let response: Result<stripe::ErrorResponse, _> = res.response.parse_struct("ErrorResponse");

        match response {
            Ok(response) => {
                event_builder.map(|i| i.set_error_response_body(&response));
                router_env::logger::info!(connector_response=?response);

                Ok(ErrorResponse {
                    status_code: res.status_code,
                    code: response
                        .error
                        .code
                        .unwrap_or_else(|| NO_ERROR_CODE.to_string()),
                    message: response
                        .error
                        .message
                        .clone()
                        .unwrap_or_else(|| NO_ERROR_MESSAGE.to_string()),
                    reason: response.error.message.map(|message| {
                        response
                            .error
                            .decline_code
                            .clone()
                            .map(|decline_code| {
                                format!("message - {message}, decline_code - {decline_code}")
                            })
                            .unwrap_or(message)
                    }),
                    attempt_status: None,
                    connector_transaction_id: response.error.payment_intent.map(|pi| pi.id),
                    connector_response_reference_id: None,
                    network_advice_code: response.error.network_advice_code,
                    network_decline_code: response.error.network_decline_code,
                    network_error_message: response
                        .error
                        .decline_code
                        .or(response.error.advice_code),
                    connector_metadata: None,
                })
            }
            Err(error_msg) => {
                event_builder.map(|event| {
                    event.set_error(serde_json::json!({
                        "error": res.response.escape_ascii().to_string(),
                        "status_code": res.status_code,
                    }))
                });
                router_env::logger::error!(deserialization_error =? error_msg);
                utils::handle_json_response_deserialization_failure(res, "stripe")
            }
        }
    }
}

impl api::Refund for Stripe {}
impl api::RefundExecute for Stripe {}
impl api::RefundSync for Stripe {}

impl ConnectorIntegration<Execute, RefundsData, RefundsResponseData> for Stripe {
    fn get_headers(
        &self,
        req: &RefundsRouterData<Execute>,
        _connectors: &Connectors,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, ConnectorError> {
        let mut header = vec![(
            CONTENT_TYPE.to_string(),
            RefundExecuteType::get_content_type(self).to_string().into(),
        )];
        let mut api_key = self.get_auth_header(&req.connector_auth_type)?;
        header.append(&mut api_key);

        if let Some(SplitRefundsRequest::StripeSplitRefund(ref stripe_split_refund)) =
            req.request.split_refunds.as_ref()
        {
            match &stripe_split_refund.charge_type {
                PaymentChargeType::Stripe(stripe_charge) => {
                    if stripe_charge == &StripeChargeType::Direct {
                        let mut customer_account_header = vec![(
                            STRIPE_COMPATIBLE_CONNECT_ACCOUNT.to_string(),
                            stripe_split_refund
                                .transfer_account_id
                                .clone()
                                .into_masked(),
                        )];
                        header.append(&mut customer_account_header);
                    }
                }
            }
        }
        Ok(header)
    }

    fn get_content_type(&self) -> &'static str {
        "application/x-www-form-urlencoded"
    }

    fn get_url(
        &self,
        _req: &RefundsRouterData<Execute>,
        connectors: &Connectors,
    ) -> CustomResult<String, ConnectorError> {
        Ok(format!("{}{}", self.base_url(connectors), "v1/refunds"))
    }

    fn get_request_body(
        &self,
        req: &RefundsRouterData<Execute>,
        _connectors: &Connectors,
    ) -> CustomResult<RequestContent, ConnectorError> {
        let refund_amount = utils::convert_amount(
            self.amount_converter,
            req.request.minor_refund_amount,
            req.request.currency,
        )?;
        let request_body = match req.request.split_refunds.as_ref() {
            // `ChargeRefundRequest` falls back to `payment_intent` when the charge id is unknown;
            // the `Stripe-Account` header added in `get_headers` is what routes either shape to
            // the connected account, which is what makes the refund resolvable at all.
            Some(SplitRefundsRequest::StripeSplitRefund(_)) => RequestContent::FormUrlEncoded(
                Box::new(stripe::ChargeRefundRequest::try_from(req)?),
            ),
            _ => RequestContent::FormUrlEncoded(Box::new(stripe::RefundRequest::try_from((
                req,
                refund_amount,
            ))?)),
        };
        Ok(request_body)
    }

    fn build_request(
        &self,
        req: &RefundsRouterData<Execute>,
        connectors: &Connectors,
    ) -> CustomResult<Option<Request>, ConnectorError> {
        let request = RequestBuilder::new()
            .method(Method::Post)
            .url(&RefundExecuteType::get_url(self, req, connectors)?)
            .attach_default_headers()
            .headers(RefundExecuteType::get_headers(self, req, connectors)?)
            .set_body(RefundExecuteType::get_request_body(self, req, connectors)?)
            .build();
        Ok(Some(request))
    }

    #[instrument(skip_all)]
    fn handle_response(
        &self,
        data: &RefundsRouterData<Execute>,
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<RefundsRouterData<Execute>, ConnectorError> {
        let response: stripe::RefundResponse =
            res.response
                .parse_struct("Stripe RefundResponse")
                .change_context(ConnectorError::ResponseDeserializationFailed)?;

        let response_integrity_object = get_refund_integrity_object(
            self.amount_converter,
            response.amount,
            response.currency.clone(),
        )?;

        event_builder.map(|i| i.set_response_body(&response));
        router_env::logger::info!(connector_response=?response);

        let new_router_data = RouterData::try_from(ResponseRouterData {
            response,
            data: data.clone(),
            http_code: res.status_code,
        });

        new_router_data
            .map(|mut router_data| {
                router_data.request.integrity_object = Some(response_integrity_object);
                router_data
            })
            .change_context(ConnectorError::ResponseHandlingFailed)
    }

    fn get_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, ConnectorError> {
        if res.response.is_empty() {
            return Ok(ErrorResponse {
                status_code: res.status_code,
                code: NO_ERROR_CODE.to_string(),
                message: NO_ERROR_MESSAGE.to_string(),
                reason: None,
                attempt_status: None,
                connector_transaction_id: None,
                connector_response_reference_id: None,
                network_advice_code: None,
                network_decline_code: None,
                network_error_message: None,
                connector_metadata: None,
            });
        }

        let response: Result<stripe::ErrorResponse, _> = res.response.parse_struct("ErrorResponse");

        match response {
            Ok(response) => {
                event_builder.map(|i| i.set_error_response_body(&response));
                router_env::logger::info!(connector_response=?response);

                Ok(ErrorResponse {
                    status_code: res.status_code,
                    code: response
                        .error
                        .code
                        .unwrap_or_else(|| NO_ERROR_CODE.to_string()),
                    message: response
                        .error
                        .message
                        .clone()
                        .unwrap_or_else(|| NO_ERROR_MESSAGE.to_string()),
                    reason: response.error.message.map(|message| {
                        response
                            .error
                            .decline_code
                            .clone()
                            .map(|decline_code| {
                                format!("message - {message}, decline_code - {decline_code}")
                            })
                            .unwrap_or(message)
                    }),
                    attempt_status: None,
                    connector_transaction_id: response.error.payment_intent.map(|pi| pi.id),
                    connector_response_reference_id: None,
                    network_advice_code: response.error.network_advice_code,
                    network_decline_code: response.error.network_decline_code,
                    network_error_message: response
                        .error
                        .decline_code
                        .or(response.error.advice_code),
                    connector_metadata: None,
                })
            }
            Err(error_msg) => {
                event_builder.map(|event| {
                    event.set_error(serde_json::json!({
                        "error": res.response.escape_ascii().to_string(),
                        "status_code": res.status_code,
                    }))
                });
                router_env::logger::error!(deserialization_error =? error_msg);
                utils::handle_json_response_deserialization_failure(res, "stripe")
            }
        }
    }
}

impl ConnectorIntegration<RSync, RefundsData, RefundsResponseData> for Stripe {
    fn get_headers(
        &self,
        req: &RouterData<RSync, RefundsData, RefundsResponseData>,
        _connectors: &Connectors,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, ConnectorError> {
        let mut header = vec![(
            CONTENT_TYPE.to_string(),
            RefundSyncType::get_content_type(self).to_string().into(),
        )];
        let mut api_key = self.get_auth_header(&req.connector_auth_type)?;
        header.append(&mut api_key);

        if let Some(SplitRefundsRequest::StripeSplitRefund(ref stripe_refund)) =
            req.request.split_refunds.as_ref()
        {
            transformers::transform_headers_for_connect_platform(
                stripe_refund.charge_type.clone(),
                stripe_refund.transfer_account_id.clone(),
                &mut header,
            );
        }
        Ok(header)
    }

    fn get_content_type(&self) -> &'static str {
        "application/x-www-form-urlencoded"
    }

    fn get_url(
        &self,
        req: &RefundsRouterData<RSync>,
        connectors: &Connectors,
    ) -> CustomResult<String, ConnectorError> {
        let id = req.request.get_connector_refund_id()?;
        Ok(format!("{}v1/refunds/{}", self.base_url(connectors), id))
    }

    fn build_request(
        &self,
        req: &RefundsRouterData<RSync>,
        connectors: &Connectors,
    ) -> CustomResult<Option<Request>, ConnectorError> {
        Ok(Some(
            RequestBuilder::new()
                .method(Method::Post)
                .url(&RefundSyncType::get_url(self, req, connectors)?)
                .attach_default_headers()
                .headers(RefundSyncType::get_headers(self, req, connectors)?)
                .build(),
        ))
    }

    #[instrument(skip_all)]
    fn handle_response(
        &self,
        data: &RefundsRouterData<RSync>,
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<RouterData<RSync, RefundsData, RefundsResponseData>, ConnectorError> {
        let response: stripe::RefundResponse =
            res.response
                .parse_struct("Stripe RefundResponse")
                .change_context(ConnectorError::ResponseDeserializationFailed)?;

        let response_integrity_object = get_refund_integrity_object(
            self.amount_converter,
            response.amount,
            response.currency.clone(),
        )?;

        event_builder.map(|i| i.set_response_body(&response));
        router_env::logger::info!(connector_response=?response);

        let new_router_data = RouterData::try_from(ResponseRouterData {
            response,
            data: data.clone(),
            http_code: res.status_code,
        });

        new_router_data
            .map(|mut router_data| {
                router_data.request.integrity_object = Some(response_integrity_object);
                router_data
            })
            .change_context(ConnectorError::ResponseHandlingFailed)
    }

    fn get_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, ConnectorError> {
        if res.response.is_empty() {
            return Ok(ErrorResponse {
                status_code: res.status_code,
                code: NO_ERROR_CODE.to_string(),
                message: NO_ERROR_MESSAGE.to_string(),
                reason: None,
                attempt_status: None,
                connector_transaction_id: None,
                connector_response_reference_id: None,
                network_advice_code: None,
                network_decline_code: None,
                network_error_message: None,
                connector_metadata: None,
            });
        }

        let response: Result<stripe::ErrorResponse, _> = res.response.parse_struct("ErrorResponse");

        match response {
            Ok(response) => {
                event_builder.map(|i| i.set_error_response_body(&response));
                router_env::logger::info!(connector_response=?response);

                Ok(ErrorResponse {
                    status_code: res.status_code,
                    code: response
                        .error
                        .code
                        .unwrap_or_else(|| NO_ERROR_CODE.to_string()),
                    message: response
                        .error
                        .message
                        .clone()
                        .unwrap_or_else(|| NO_ERROR_MESSAGE.to_string()),
                    reason: response.error.message.map(|message| {
                        response
                            .error
                            .decline_code
                            .clone()
                            .map(|decline_code| {
                                format!("message - {message}, decline_code - {decline_code}")
                            })
                            .unwrap_or(message)
                    }),
                    attempt_status: None,
                    connector_transaction_id: response.error.payment_intent.map(|pi| pi.id),
                    connector_response_reference_id: None,
                    network_advice_code: response.error.network_advice_code,
                    network_decline_code: response.error.network_decline_code,
                    network_error_message: response
                        .error
                        .decline_code
                        .or(response.error.advice_code),
                    connector_metadata: None,
                })
            }
            Err(error_msg) => {
                event_builder.map(|event| {
                    event.set_error(serde_json::json!({
                        "error": res.response.escape_ascii().to_string(),
                        "status_code": res.status_code,
                    }))
                });
                router_env::logger::error!(deserialization_error =? error_msg);
                utils::handle_json_response_deserialization_failure(res, "stripe")
            }
        }
    }
}

impl UploadFile for Stripe {}

#[async_trait::async_trait]
impl FileUpload for Stripe {
    fn validate_file_upload(
        &self,
        purpose: FilePurpose,
        file_size: i32,
        file_type: mime::Mime,
    ) -> CustomResult<(), ConnectorError> {
        match purpose {
            FilePurpose::DisputeEvidence => {
                let supported_file_types = ["image/jpeg", "image/png", "application/pdf"];
                // 5 Megabytes (MB)
                if file_size > 5000000 {
                    Err(ConnectorError::FileValidationFailed {
                        reason: "file_size exceeded the max file size of 5MB".to_owned(),
                    })?
                }
                if !supported_file_types.contains(&file_type.to_string().as_str()) {
                    Err(ConnectorError::FileValidationFailed {
                        reason: "file_type does not match JPEG, JPG, PNG, or PDF format".to_owned(),
                    })?
                }
            }
        }
        Ok(())
    }
}

impl ConnectorIntegration<Upload, UploadFileRequestData, UploadFileResponse> for Stripe {
    fn get_headers(
        &self,
        req: &RouterData<Upload, UploadFileRequestData, UploadFileResponse>,
        _connectors: &Connectors,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, ConnectorError> {
        self.get_auth_header(&req.connector_auth_type)
    }

    fn get_content_type(&self) -> &'static str {
        "multipart/form-data"
    }

    fn get_url(
        &self,
        _req: &UploadFileRouterData,
        connectors: &Connectors,
    ) -> CustomResult<String, ConnectorError> {
        Ok(format!(
            "{}{}",
            connectors.stripe.base_url_file_upload, "v1/files"
        ))
    }

    fn get_request_body(
        &self,
        req: &UploadFileRouterData,
        _connectors: &Connectors,
    ) -> CustomResult<RequestContent, ConnectorError> {
        transformers::construct_file_upload_request(req.clone())
    }

    fn build_request(
        &self,
        req: &UploadFileRouterData,
        connectors: &Connectors,
    ) -> CustomResult<Option<Request>, ConnectorError> {
        Ok(Some(
            RequestBuilder::new()
                .method(Method::Post)
                .url(&UploadFileType::get_url(self, req, connectors)?)
                .attach_default_headers()
                .headers(UploadFileType::get_headers(self, req, connectors)?)
                .set_body(UploadFileType::get_request_body(self, req, connectors)?)
                .build(),
        ))
    }

    #[instrument(skip_all)]
    fn handle_response(
        &self,
        data: &UploadFileRouterData,
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<RouterData<Upload, UploadFileRequestData, UploadFileResponse>, ConnectorError>
    {
        let response: stripe::FileUploadResponse = res
            .response
            .parse_struct("Stripe FileUploadResponse")
            .change_context(ConnectorError::ResponseDeserializationFailed)?;
        event_builder.map(|i| i.set_response_body(&response));
        router_env::logger::info!(connector_response=?response);
        Ok(UploadFileRouterData {
            response: Ok(UploadFileResponse {
                provider_file_id: response.file_id,
            }),
            ..data.clone()
        })
    }

    fn get_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, ConnectorError> {
        if res.response.is_empty() {
            return Ok(ErrorResponse {
                status_code: res.status_code,
                code: NO_ERROR_CODE.to_string(),
                message: NO_ERROR_MESSAGE.to_string(),
                reason: None,
                attempt_status: None,
                connector_transaction_id: None,
                connector_response_reference_id: None,
                network_advice_code: None,
                network_decline_code: None,
                network_error_message: None,
                connector_metadata: None,
            });
        }

        let response: Result<stripe::ErrorResponse, _> = res.response.parse_struct("ErrorResponse");

        match response {
            Ok(response) => {
                event_builder.map(|i| i.set_error_response_body(&response));
                router_env::logger::info!(connector_response=?response);

                Ok(ErrorResponse {
                    status_code: res.status_code,
                    code: response
                        .error
                        .code
                        .unwrap_or_else(|| NO_ERROR_CODE.to_string()),
                    message: response
                        .error
                        .message
                        .clone()
                        .unwrap_or_else(|| NO_ERROR_MESSAGE.to_string()),
                    reason: response.error.message.map(|message| {
                        response
                            .error
                            .decline_code
                            .clone()
                            .map(|decline_code| {
                                format!("message - {message}, decline_code - {decline_code}")
                            })
                            .unwrap_or(message)
                    }),
                    attempt_status: None,
                    connector_transaction_id: response.error.payment_intent.map(|pi| pi.id),
                    connector_response_reference_id: None,
                    network_advice_code: response.error.network_advice_code,
                    network_decline_code: response.error.network_decline_code,
                    network_error_message: response
                        .error
                        .decline_code
                        .or(response.error.advice_code),
                    connector_metadata: None,
                })
            }
            Err(error_msg) => {
                event_builder.map(|event| {
                    event.set_error(serde_json::json!({
                        "error": res.response.escape_ascii().to_string(),
                        "status_code": res.status_code,
                    }))
                });
                router_env::logger::error!(deserialization_error =? error_msg);
                utils::handle_json_response_deserialization_failure(res, "stripe")
            }
        }
    }
}

impl RetrieveFile for Stripe {}

impl ConnectorIntegration<Retrieve, RetrieveFileRequestData, RetrieveFileResponse> for Stripe {
    fn get_headers(
        &self,
        req: &RouterData<Retrieve, RetrieveFileRequestData, RetrieveFileResponse>,
        _connectors: &Connectors,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, ConnectorError> {
        self.get_auth_header(&req.connector_auth_type)
    }

    fn get_url(
        &self,
        req: &RetrieveFileRouterData,
        connectors: &Connectors,
    ) -> CustomResult<String, ConnectorError> {
        Ok(format!(
            "{}v1/files/{}/contents",
            connectors.stripe.base_url_file_upload, req.request.provider_file_id
        ))
    }

    fn build_request(
        &self,
        req: &RetrieveFileRouterData,
        connectors: &Connectors,
    ) -> CustomResult<Option<Request>, ConnectorError> {
        Ok(Some(
            RequestBuilder::new()
                .method(Method::Get)
                .url(&RetrieveFileType::get_url(self, req, connectors)?)
                .attach_default_headers()
                .headers(RetrieveFileType::get_headers(self, req, connectors)?)
                .build(),
        ))
    }

    #[instrument(skip_all)]
    fn handle_response(
        &self,
        data: &RetrieveFileRouterData,
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<RetrieveFileRouterData, ConnectorError> {
        let response = res.response;

        event_builder.map(|event| event.set_response_body(&serde_json::json!({"connector_response_type": "file", "status_code": res.status_code})));
        router_env::logger::info!(connector_response_type=?"file");

        Ok(RetrieveFileRouterData {
            response: Ok(RetrieveFileResponse {
                file_data: response.to_vec(),
            }),
            ..data.clone()
        })
    }

    fn get_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, ConnectorError> {
        if res.response.is_empty() {
            return Ok(ErrorResponse {
                status_code: res.status_code,
                code: NO_ERROR_CODE.to_string(),
                message: NO_ERROR_MESSAGE.to_string(),
                reason: None,
                attempt_status: None,
                connector_transaction_id: None,
                connector_response_reference_id: None,
                network_advice_code: None,
                network_decline_code: None,
                network_error_message: None,
                connector_metadata: None,
            });
        }

        let response: Result<stripe::ErrorResponse, _> = res.response.parse_struct("ErrorResponse");

        match response {
            Ok(response) => {
                event_builder.map(|i| i.set_error_response_body(&response));
                router_env::logger::info!(connector_response=?response);

                Ok(ErrorResponse {
                    status_code: res.status_code,
                    code: response
                        .error
                        .code
                        .unwrap_or_else(|| NO_ERROR_CODE.to_string()),
                    message: response
                        .error
                        .message
                        .clone()
                        .unwrap_or_else(|| NO_ERROR_MESSAGE.to_string()),
                    reason: response.error.message.map(|message| {
                        response
                            .error
                            .decline_code
                            .clone()
                            .map(|decline_code| {
                                format!("message - {message}, decline_code - {decline_code}")
                            })
                            .unwrap_or(message)
                    }),
                    attempt_status: None,
                    connector_transaction_id: response.error.payment_intent.map(|pi| pi.id),
                    connector_response_reference_id: None,
                    network_advice_code: response.error.network_advice_code,
                    network_decline_code: response.error.network_decline_code,
                    network_error_message: response
                        .error
                        .decline_code
                        .or(response.error.advice_code),
                    connector_metadata: None,
                })
            }
            Err(error_msg) => {
                event_builder.map(|event| {
                    event.set_error(serde_json::json!({
                        "error": res.response.escape_ascii().to_string(),
                        "status_code": res.status_code,
                    }))
                });
                router_env::logger::error!(deserialization_error =? error_msg);
                utils::handle_json_response_deserialization_failure(res, "stripe")
            }
        }
    }
}

impl Dispute for Stripe {}
impl AcceptDispute for Stripe {}

impl ConnectorIntegration<Accept, AcceptDisputeRequestData, AcceptDisputeResponse> for Stripe {
    fn get_headers(
        &self,
        req: &AcceptDisputeRouterData,
        _connectors: &Connectors,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, ConnectorError> {
        let mut headers = vec![(
            CONTENT_TYPE.to_string(),
            AcceptDisputeType::get_content_type(self).to_string().into(),
        )];
        headers.append(&mut self.get_auth_header(&req.connector_auth_type)?);
        Ok(headers)
    }

    fn get_content_type(&self) -> &'static str {
        "application/x-www-form-urlencoded"
    }

    fn get_url(
        &self,
        req: &AcceptDisputeRouterData,
        connectors: &Connectors,
    ) -> CustomResult<String, ConnectorError> {
        Ok(format!(
            "{}v1/disputes/{}/close",
            self.base_url(connectors),
            req.request.connector_dispute_id
        ))
    }

    fn build_request(
        &self,
        req: &AcceptDisputeRouterData,
        connectors: &Connectors,
    ) -> CustomResult<Option<Request>, ConnectorError> {
        Ok(Some(
            RequestBuilder::new()
                .method(Method::Post)
                .url(&AcceptDisputeType::get_url(self, req, connectors)?)
                .attach_default_headers()
                .headers(AcceptDisputeType::get_headers(self, req, connectors)?)
                .build(),
        ))
    }

    #[instrument(skip_all)]
    fn handle_response(
        &self,
        data: &AcceptDisputeRouterData,
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<AcceptDisputeRouterData, ConnectorError> {
        let response: stripe::DisputeObj = res
            .response
            .parse_struct("Stripe DisputeObj")
            .change_context(ConnectorError::ResponseDeserializationFailed)?;
        event_builder.map(|event| event.set_response_body(&response));
        router_env::logger::info!(connector_response=?response);

        Ok(AcceptDisputeRouterData {
            response: Ok(AcceptDisputeResponse {
                dispute_status: api_models::enums::DisputeStatus::DisputeAccepted,
                connector_status: Some(response.status),
            }),
            ..data.clone()
        })
    }

    fn get_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, ConnectorError> {
        SubmitEvidenceType::get_error_response(self, res, event_builder)
    }
}

impl SubmitEvidence for Stripe {}

impl ConnectorIntegration<Evidence, SubmitEvidenceRequestData, SubmitEvidenceResponse> for Stripe {
    fn get_headers(
        &self,
        req: &SubmitEvidenceRouterData,
        _connectors: &Connectors,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, ConnectorError> {
        let mut header = vec![(
            CONTENT_TYPE.to_string(),
            SubmitEvidenceType::get_content_type(self)
                .to_string()
                .into(),
        )];
        let mut api_key = self.get_auth_header(&req.connector_auth_type)?;
        header.append(&mut api_key);
        Ok(header)
    }

    fn get_content_type(&self) -> &'static str {
        "application/x-www-form-urlencoded"
    }

    fn get_url(
        &self,
        req: &SubmitEvidenceRouterData,
        connectors: &Connectors,
    ) -> CustomResult<String, ConnectorError> {
        Ok(format!(
            "{}{}{}",
            self.base_url(connectors),
            "v1/disputes/",
            req.request.connector_dispute_id
        ))
    }

    fn get_request_body(
        &self,
        req: &SubmitEvidenceRouterData,
        _connectors: &Connectors,
    ) -> CustomResult<RequestContent, ConnectorError> {
        let connector_req = stripe::Evidence::try_from(req)?;
        Ok(RequestContent::FormUrlEncoded(Box::new(connector_req)))
    }

    fn build_request(
        &self,
        req: &SubmitEvidenceRouterData,
        connectors: &Connectors,
    ) -> CustomResult<Option<Request>, ConnectorError> {
        let request = RequestBuilder::new()
            .method(Method::Post)
            .url(&SubmitEvidenceType::get_url(self, req, connectors)?)
            .attach_default_headers()
            .headers(SubmitEvidenceType::get_headers(self, req, connectors)?)
            .set_body(SubmitEvidenceType::get_request_body(self, req, connectors)?)
            .build();
        Ok(Some(request))
    }

    #[instrument(skip_all)]
    fn handle_response(
        &self,
        data: &SubmitEvidenceRouterData,
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<SubmitEvidenceRouterData, ConnectorError> {
        let response: stripe::DisputeObj = res
            .response
            .parse_struct("Stripe DisputeObj")
            .change_context(ConnectorError::ResponseDeserializationFailed)?;
        event_builder.map(|i| i.set_response_body(&response));
        router_env::logger::info!(connector_response=?response);
        Ok(SubmitEvidenceRouterData {
            response: Ok(SubmitEvidenceResponse {
                dispute_status: api_models::enums::DisputeStatus::DisputeChallenged,
                connector_status: Some(response.status),
            }),
            ..data.clone()
        })
    }

    fn get_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, ConnectorError> {
        if res.response.is_empty() {
            return Ok(ErrorResponse {
                status_code: res.status_code,
                code: NO_ERROR_CODE.to_string(),
                message: NO_ERROR_MESSAGE.to_string(),
                reason: None,
                attempt_status: None,
                connector_transaction_id: None,
                connector_response_reference_id: None,
                network_advice_code: None,
                network_decline_code: None,
                network_error_message: None,
                connector_metadata: None,
            });
        }

        let response: Result<stripe::ErrorResponse, _> = res.response.parse_struct("ErrorResponse");

        match response {
            Ok(response) => {
                event_builder.map(|i| i.set_error_response_body(&response));
                router_env::logger::info!(connector_response=?response);

                Ok(ErrorResponse {
                    status_code: res.status_code,
                    code: response
                        .error
                        .code
                        .unwrap_or_else(|| NO_ERROR_CODE.to_string()),
                    message: response
                        .error
                        .message
                        .clone()
                        .unwrap_or_else(|| NO_ERROR_MESSAGE.to_string()),
                    reason: response.error.message.map(|message| {
                        response
                            .error
                            .decline_code
                            .clone()
                            .map(|decline_code| {
                                format!("message - {message}, decline_code - {decline_code}")
                            })
                            .unwrap_or(message)
                    }),
                    attempt_status: None,
                    connector_transaction_id: response.error.payment_intent.map(|pi| pi.id),
                    connector_response_reference_id: None,
                    network_advice_code: response.error.network_advice_code,
                    network_decline_code: response.error.network_decline_code,
                    network_error_message: response
                        .error
                        .decline_code
                        .or(response.error.advice_code),
                    connector_metadata: None,
                })
            }
            Err(error_msg) => {
                event_builder.map(|event| {
                    event.set_error(serde_json::json!({
                        "error": res.response.escape_ascii().to_string(),
                        "status_code": res.status_code,
                    }))
                });
                router_env::logger::error!(deserialization_error =? error_msg);
                utils::handle_json_response_deserialization_failure(res, "stripe")
            }
        }
    }
}

/// URL of the payment intent sync. `latest_charge` is expanded for the updated payment id and
/// the payment method details; `latest_charge.refunds` is expanded too because since API
/// version 2022-11-15 a charge no longer lists its refunds by default, and they are how a
/// refund made outside Hyperswitch (Stripe dashboard) is discovered.
fn payment_intent_sync_url(base_url: &str, payment_intent_id: &str) -> String {
    format!(
        "{base_url}v1/payment_intents/{payment_intent_id}?expand[0]=latest_charge&expand[1]=latest_charge.refunds"
    )
}

/// Signature check that never succeeds.
///
/// Used for the `charge.refunded` events that are routed to a sync of the parent payment. When
/// the signature verifies, core consumes the webhook body as if it were the payment sync
/// response, but the body of these events is a charge, not a payment intent, and it carries
/// no refund list. Reporting the webhook as unverified makes core run a live
/// payment sync against Stripe instead, and that sync is the source of truth: the event only
/// tells that something changed, so an unauthenticated one can at worst cause one extra read
/// with the merchant's own credentials (same rule as Mercado Pago).
struct UnverifiedWebhook;

impl crypto::VerifySignature for UnverifiedWebhook {
    fn verify_signature(
        &self,
        _secret: &[u8],
        _signature: &[u8],
        _msg: &[u8],
    ) -> CustomResult<bool, common_utils::errors::CryptoError> {
        Ok(false)
    }
}

fn get_signature_elements_from_header(
    headers: &actix_web::http::header::HeaderMap,
) -> CustomResult<HashMap<String, Vec<u8>>, ConnectorError> {
    let security_header = headers
        .get("Stripe-Signature")
        .map(|header_value| {
            header_value
                .to_str()
                .map(String::from)
                .map_err(|_| ConnectorError::WebhookSignatureNotFound)
        })
        .ok_or(ConnectorError::WebhookSignatureNotFound)??;

    let props = security_header.split(',').collect::<Vec<&str>>();
    let mut security_header_kvs: HashMap<String, Vec<u8>> = HashMap::with_capacity(props.len());

    for prop_str in &props {
        let (prop_key, prop_value) = prop_str
            .split_once('=')
            .ok_or(ConnectorError::WebhookSourceVerificationFailed)?;

        security_header_kvs.insert(prop_key.to_string(), prop_value.bytes().collect());
    }

    Ok(security_header_kvs)
}

#[async_trait::async_trait]
impl IncomingWebhook for Stripe {
    fn get_webhook_source_verification_algorithm(
        &self,
        request: &IncomingWebhookRequestDetails<'_>,
    ) -> CustomResult<Box<dyn crypto::VerifySignature + Send>, ConnectorError> {
        let resyncs_parent_payment = request
            .body
            .parse_struct::<stripe::WebhookEventTypeBody>("WebhookEventTypeBody")
            .is_ok_and(|details| details.is_charge_refunded_on_known_payment());
        if resyncs_parent_payment {
            return Ok(Box::new(UnverifiedWebhook));
        }
        Ok(Box::new(crypto::HmacSha256))
    }

    fn get_webhook_source_verification_signature(
        &self,
        request: &IncomingWebhookRequestDetails<'_>,
        _connector_webhook_secrets: &api_models::webhooks::ConnectorWebhookSecrets,
    ) -> CustomResult<Vec<u8>, ConnectorError> {
        let mut security_header_kvs = get_signature_elements_from_header(request.headers)?;

        let signature = security_header_kvs
            .remove("v1")
            .ok_or(ConnectorError::WebhookSignatureNotFound)?;

        hex::decode(signature).change_context(ConnectorError::WebhookSignatureNotFound)
    }

    fn get_webhook_source_verification_message(
        &self,
        request: &IncomingWebhookRequestDetails<'_>,
        _merchant_id: &common_utils::id_type::MerchantId,
        _connector_webhook_secrets: &api_models::webhooks::ConnectorWebhookSecrets,
    ) -> CustomResult<Vec<u8>, ConnectorError> {
        let mut security_header_kvs = get_signature_elements_from_header(request.headers)?;

        let timestamp = security_header_kvs
            .remove("t")
            .ok_or(ConnectorError::WebhookSignatureNotFound)?;

        Ok(format!(
            "{}.{}",
            String::from_utf8_lossy(&timestamp),
            String::from_utf8_lossy(request.body)
        )
        .into_bytes())
    }

    fn get_webhook_object_reference_id(
        &self,
        request: &IncomingWebhookRequestDetails<'_>,
    ) -> CustomResult<api_models::webhooks::ObjectReferenceId, ConnectorError> {
        let details: stripe::WebhookEvent = request
            .body
            .parse_struct("WebhookEvent")
            .change_context(ConnectorError::WebhookReferenceIdNotFound)?;

        match details.event_data.event_object.object {
            stripe::WebhookEventObjectType::PaymentIntent => {
                match details
                    .event_data
                    .event_object
                    .metadata
                    .and_then(|meta_data| meta_data.order_id)
                {
                    // if order_id is present
                    Some(order_id) => Ok(api_models::webhooks::ObjectReferenceId::PaymentId(
                        api_models::payments::PaymentIdType::PaymentAttemptId(order_id),
                    )),
                    // else used connector_transaction_id
                    None => Ok(api_models::webhooks::ObjectReferenceId::PaymentId(
                        api_models::payments::PaymentIdType::ConnectorTransactionId(
                            details.event_data.event_object.id,
                        ),
                    )),
                }
            }
            stripe::WebhookEventObjectType::Charge => {
                match details
                    .event_data
                    .event_object
                    .metadata
                    .and_then(|meta_data| meta_data.order_id)
                {
                    // if order_id is present
                    Some(order_id) => Ok(api_models::webhooks::ObjectReferenceId::PaymentId(
                        api_models::payments::PaymentIdType::PaymentAttemptId(order_id),
                    )),
                    // else used connector_transaction_id
                    None => Ok(api_models::webhooks::ObjectReferenceId::PaymentId(
                        api_models::payments::PaymentIdType::ConnectorTransactionId(
                            details
                                .event_data
                                .event_object
                                .payment_intent
                                .ok_or(ConnectorError::WebhookReferenceIdNotFound)?,
                        ),
                    )),
                }
            }
            stripe::WebhookEventObjectType::Dispute => {
                Ok(api_models::webhooks::ObjectReferenceId::PaymentId(
                    api_models::payments::PaymentIdType::ConnectorTransactionId(
                        details
                            .event_data
                            .event_object
                            .payment_intent
                            .ok_or(ConnectorError::WebhookReferenceIdNotFound)?,
                    ),
                ))
            }
            stripe::WebhookEventObjectType::Source => {
                Err(ConnectorError::WebhookReferenceIdNotFound)?
            }
            stripe::WebhookEventObjectType::Refund => {
                match details
                    .event_data
                    .event_object
                    .metadata
                    .clone()
                    .and_then(|meta_data| meta_data.order_id)
                {
                    // if meta_data is present
                    Some(order_id) => {
                        // Issue: 2076
                        match details
                            .event_data
                            .event_object
                            .metadata
                            .and_then(|meta_data| meta_data.is_refund_id_as_reference)
                        {
                            // if the order_id is refund_id
                            Some(_) => Ok(api_models::webhooks::ObjectReferenceId::RefundId(
                                api_models::webhooks::RefundIdType::RefundId(order_id),
                            )),
                            // if the order_id is payment_id
                            // since payment_id was being passed before the deployment of this pr
                            _ => Ok(api_models::webhooks::ObjectReferenceId::RefundId(
                                api_models::webhooks::RefundIdType::ConnectorRefundId(
                                    details.event_data.event_object.id,
                                ),
                            )),
                        }
                    }
                    // else use connector_transaction_id
                    None => Ok(api_models::webhooks::ObjectReferenceId::RefundId(
                        api_models::webhooks::RefundIdType::ConnectorRefundId(
                            details.event_data.event_object.id,
                        ),
                    )),
                }
            }
            stripe::WebhookEventObjectType::Unknown => {
                Err(ConnectorError::WebhookReferenceIdNotFound.into())
            }
        }
    }

    fn get_webhook_event_type(
        &self,
        request: &IncomingWebhookRequestDetails<'_>,
        _context: Option<&WebhookContext>,
    ) -> CustomResult<IncomingWebhookEvent, ConnectorError> {
        if request.body.is_empty() {
            return Ok(IncomingWebhookEvent::EndpointVerification);
        }

        let details: stripe::WebhookEventTypeBody = request
            .body
            .parse_struct("WebhookEventTypeBody")
            .change_context(ConnectorError::WebhookReferenceIdNotFound)?;

        let status = details.event_data.event_object.status.clone();

        Ok(match details.event_type {
            stripe::WebhookEventType::PaymentIntentFailed => {
                IncomingWebhookEvent::PaymentIntentFailure
            }
            stripe::WebhookEventType::PaymentIntentSucceed => {
                IncomingWebhookEvent::PaymentIntentSuccess
            }
            stripe::WebhookEventType::PaymentIntentCanceled => {
                IncomingWebhookEvent::PaymentIntentCancelled
            }
            stripe::WebhookEventType::PaymentIntentAmountCapturableUpdated => {
                IncomingWebhookEvent::PaymentIntentAuthorizationSuccess
            }
            stripe::WebhookEventType::ChargeSucceeded => {
                if let Some(stripe::WebhookPaymentMethodDetails {
                    payment_method:
                        stripe::WebhookPaymentMethodType::AchCreditTransfer
                        | stripe::WebhookPaymentMethodType::MultibancoBankTransfers,
                }) = details.event_data.event_object.payment_method_details
                {
                    IncomingWebhookEvent::PaymentIntentSuccess
                } else {
                    IncomingWebhookEvent::EventNotSupported
                }
            }
            // `charge.refunded` of a known payment is routed to a sync of that payment, which
            // reads the refunds of the charge from Stripe: it creates the refunds made outside
            // Hyperswitch (Stripe dashboard) and updates the ones Hyperswitch already has.
            // `PaymentIntentProcessing` is only a routing label for the payments webhook flow,
            // it does not decide any outcome: the sync derives everything from Stripe and the
            // attempt, and the outgoing webhook comes from the resulting payment status.
            // Unlike `PaymentIntentSuccess` it triggers no mandate update.
            //
            // `charge.refund.updated` keeps the refund-id routing below on purpose: it updates
            // a refund Hyperswitch knows directly, whereas a payment sync only sees the first
            // page of `latest_charge.refunds` and would never update one beyond it.
            stripe::WebhookEventType::ChargeRefunded
                if details.is_charge_refunded_on_known_payment() =>
            {
                IncomingWebhookEvent::PaymentIntentProcessing
            }
            stripe::WebhookEventType::ChargeRefundUpdated => status
                .map(|s| match s {
                    stripe::WebhookEventStatus::Succeeded => IncomingWebhookEvent::RefundSuccess,
                    stripe::WebhookEventStatus::Failed => IncomingWebhookEvent::RefundFailure,
                    _ => IncomingWebhookEvent::EventNotSupported,
                })
                .unwrap_or(IncomingWebhookEvent::EventNotSupported),
            stripe::WebhookEventType::SourceChargeable => IncomingWebhookEvent::SourceChargeable,
            stripe::WebhookEventType::PaymentIntentPartiallyFunded => {
                IncomingWebhookEvent::PaymentIntentPartiallyFunded
            }
            stripe::WebhookEventType::PaymentIntentRequiresAction => {
                IncomingWebhookEvent::PaymentActionRequired
            }
            stripe::WebhookEventType::DisputeCreated
            | stripe::WebhookEventType::DisputeClosed
            | stripe::WebhookEventType::DisputeUpdated
            | stripe::WebhookEventType::ChargeDisputeFundsWithdrawn
            | stripe::WebhookEventType::ChargeDisputeFundsReinstated => {
                stripe::dispute_webhook_event(&details.event_type, status)
            }
            stripe::WebhookEventType::Unknown
            | stripe::WebhookEventType::ChargeCaptured
            | stripe::WebhookEventType::ChargeExpired
            | stripe::WebhookEventType::ChargeFailed
            | stripe::WebhookEventType::ChargePending
            | stripe::WebhookEventType::ChargeUpdated
            | stripe::WebhookEventType::ChargeRefunded
            | stripe::WebhookEventType::PaymentIntentCreated
            | stripe::WebhookEventType::PaymentIntentProcessing
            | stripe::WebhookEventType::SourceTransactionCreated => {
                IncomingWebhookEvent::EventNotSupported
            }
        })
    }

    fn get_webhook_resource_object(
        &self,
        request: &IncomingWebhookRequestDetails<'_>,
    ) -> CustomResult<Box<dyn hyperswitch_masking::ErasedMaskSerialize>, ConnectorError> {
        let details: stripe::WebhookEvent = request
            .body
            .parse_struct("WebhookEvent")
            .change_context(ConnectorError::WebhookBodyDecodingFailed)?;

        Ok(Box::new(details.event_data.event_object))
    }
    fn get_dispute_details(
        &self,
        request: &IncomingWebhookRequestDetails<'_>,
        _context: Option<&WebhookContext>,
    ) -> CustomResult<DisputePayload, ConnectorError> {
        let details: stripe::WebhookEvent = request
            .body
            .parse_struct("WebhookEvent")
            .change_context(ConnectorError::WebhookBodyDecodingFailed)?;
        let amt = details.event_data.event_object.amount.ok_or_else(|| {
            ConnectorError::MissingRequiredField {
                field_name: "amount".into(),
            }
        })?;

        Ok(DisputePayload {
            amount: utils::convert_amount(
                self.amount_converter_webhooks,
                amt,
                details.event_data.event_object.currency,
            )?,
            currency: details.event_data.event_object.currency,
            dispute_stage: api_models::enums::DisputeStage::Dispute,
            connector_dispute_id: details.event_data.event_object.id,
            connector_reason: details.event_data.event_object.reason,
            connector_reason_code: None,
            challenge_required_by: details
                .event_data
                .event_object
                .evidence_details
                .map(|payload| payload.due_by),
            connector_status: details
                .event_data
                .event_object
                .status
                .ok_or(ConnectorError::WebhookResourceObjectNotFound)?
                .to_string(),
            created_at: Some(details.event_data.event_object.created),
            updated_at: None,
            additional_details: details
                .event_data
                .event_object
                .network_details
                .and_then(Into::into),
        })
    }
}

impl ConnectorRedirectResponse for Stripe {
    fn get_flow_type(
        &self,
        _query_params: &str,
        _json_payload: Option<serde_json::Value>,
        action: PaymentAction,
    ) -> CustomResult<CallConnectorAction, ConnectorError> {
        match action {
            PaymentAction::PSync
            | PaymentAction::CompleteAuthorize
            | PaymentAction::PaymentAuthenticateCompleteAuthorize => {
                Ok(CallConnectorAction::Trigger)
            }
        }
    }
}

impl api::Payouts for Stripe {}
#[cfg(feature = "payouts")]
impl api::PayoutCancel for Stripe {}
#[cfg(feature = "payouts")]
impl api::PayoutCreate for Stripe {}
#[cfg(feature = "payouts")]
impl api::PayoutFulfill for Stripe {}
#[cfg(feature = "payouts")]
impl api::PayoutRecipient for Stripe {}
#[cfg(feature = "payouts")]
impl api::PayoutRecipientAccount for Stripe {}

#[cfg(feature = "payouts")]
impl ConnectorIntegration<PoCancel, PayoutsData, PayoutsResponseData> for Stripe {
    fn get_content_type(&self) -> &'static str {
        self.common_get_content_type()
    }

    fn get_url(
        &self,
        req: &PayoutsRouterData<PoCancel>,
        connectors: &Connectors,
    ) -> CustomResult<String, ConnectorError> {
        let transfer_id = req.request.get_transfer_id()?;
        Ok(format!(
            "{}v1/transfers/{}/reversals",
            connectors.stripe.base_url, transfer_id
        ))
    }

    fn get_headers(
        &self,
        req: &PayoutsRouterData<PoCancel>,
        _connectors: &Connectors,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, ConnectorError> {
        self.build_headers(req, _connectors)
    }

    fn get_request_body(
        &self,
        req: &RouterData<PoCancel, PayoutsData, PayoutsResponseData>,
        _connectors: &Connectors,
    ) -> CustomResult<RequestContent, ConnectorError> {
        let connector_req = stripe::StripeConnectReversalRequest::try_from(req)?;
        Ok(RequestContent::FormUrlEncoded(Box::new(connector_req)))
    }

    fn build_request(
        &self,
        req: &PayoutsRouterData<PoCancel>,
        connectors: &Connectors,
    ) -> CustomResult<Option<Request>, ConnectorError> {
        let request = RequestBuilder::new()
            .method(Method::Post)
            .url(&PayoutCancelType::get_url(self, req, connectors)?)
            .attach_default_headers()
            .headers(PayoutCancelType::get_headers(self, req, connectors)?)
            .set_body(PayoutCancelType::get_request_body(self, req, connectors)?)
            .build();

        Ok(Some(request))
    }

    fn handle_response(
        &self,
        data: &PayoutsRouterData<PoCancel>,
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<PayoutsRouterData<PoCancel>, ConnectorError> {
        let response: stripe::StripeConnectReversalResponse = res
            .response
            .parse_struct("StripeConnectReversalResponse")
            .change_context(ConnectorError::ResponseDeserializationFailed)?;
        event_builder.map(|i| i.set_error_response_body(&response));
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
    ) -> CustomResult<ErrorResponse, ConnectorError> {
        self.build_error_response(res, event_builder)
    }
}

#[cfg(feature = "payouts")]
impl ConnectorIntegration<PoCreate, PayoutsData, PayoutsResponseData> for Stripe {
    fn get_content_type(&self) -> &'static str {
        self.common_get_content_type()
    }

    fn get_url(
        &self,
        _req: &PayoutsRouterData<PoCreate>,
        connectors: &Connectors,
    ) -> CustomResult<String, ConnectorError> {
        Ok(format!("{}v1/transfers", connectors.stripe.base_url))
    }

    fn get_headers(
        &self,
        req: &PayoutsRouterData<PoCreate>,
        connectors: &Connectors,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, ConnectorError> {
        self.build_headers(req, connectors)
    }

    fn get_request_body(
        &self,
        req: &PayoutsRouterData<PoCreate>,
        _connectors: &Connectors,
    ) -> CustomResult<RequestContent, ConnectorError> {
        let connector_req = stripe::StripeConnectPayoutCreateRequest::try_from(req)?;
        Ok(RequestContent::FormUrlEncoded(Box::new(connector_req)))
    }

    fn build_request(
        &self,
        req: &PayoutsRouterData<PoCreate>,
        connectors: &Connectors,
    ) -> CustomResult<Option<Request>, ConnectorError> {
        let request = RequestBuilder::new()
            .method(Method::Post)
            .url(&PayoutCreateType::get_url(self, req, connectors)?)
            .attach_default_headers()
            .headers(PayoutCreateType::get_headers(self, req, connectors)?)
            .set_body(PayoutCreateType::get_request_body(self, req, connectors)?)
            .build();

        Ok(Some(request))
    }

    fn handle_response(
        &self,
        data: &PayoutsRouterData<PoCreate>,
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<PayoutsRouterData<PoCreate>, ConnectorError> {
        let response: stripe::StripeConnectPayoutCreateResponse = res
            .response
            .parse_struct("StripeConnectPayoutCreateResponse")
            .change_context(ConnectorError::ResponseDeserializationFailed)?;
        event_builder.map(|i| i.set_error_response_body(&response));
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
    ) -> CustomResult<ErrorResponse, ConnectorError> {
        self.build_error_response(res, event_builder)
    }
}

#[cfg(feature = "payouts")]
impl ConnectorIntegration<PoFulfill, PayoutsData, PayoutsResponseData> for Stripe {
    fn get_content_type(&self) -> &'static str {
        self.common_get_content_type()
    }

    fn get_url(
        &self,
        _req: &PayoutsRouterData<PoFulfill>,
        connectors: &Connectors,
    ) -> CustomResult<String, ConnectorError> {
        Ok(format!("{}v1/payouts", connectors.stripe.base_url,))
    }

    fn get_headers(
        &self,
        req: &PayoutsRouterData<PoFulfill>,
        connectors: &Connectors,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, ConnectorError> {
        let mut headers = self.build_headers(req, connectors)?;
        let customer_account = req.get_connector_customer_id()?;
        let mut customer_account_header = vec![(
            STRIPE_COMPATIBLE_CONNECT_ACCOUNT.to_string(),
            customer_account.into_masked(),
        )];
        headers.append(&mut customer_account_header);
        Ok(headers)
    }

    fn get_request_body(
        &self,
        req: &PayoutsRouterData<PoFulfill>,
        _connectors: &Connectors,
    ) -> CustomResult<RequestContent, ConnectorError> {
        let connector_req = stripe::StripeConnectPayoutFulfillRequest::try_from(req)?;
        Ok(RequestContent::FormUrlEncoded(Box::new(connector_req)))
    }

    fn build_request(
        &self,
        req: &PayoutsRouterData<PoFulfill>,
        connectors: &Connectors,
    ) -> CustomResult<Option<Request>, ConnectorError> {
        let request = RequestBuilder::new()
            .method(Method::Post)
            .url(&PayoutFulfillType::get_url(self, req, connectors)?)
            .attach_default_headers()
            .headers(PayoutFulfillType::get_headers(self, req, connectors)?)
            .set_body(PayoutFulfillType::get_request_body(self, req, connectors)?)
            .build();

        Ok(Some(request))
    }

    fn handle_response(
        &self,
        data: &PayoutsRouterData<PoFulfill>,
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<PayoutsRouterData<PoFulfill>, ConnectorError> {
        let response: stripe::StripeConnectPayoutFulfillResponse = res
            .response
            .parse_struct("StripeConnectPayoutFulfillResponse")
            .change_context(ConnectorError::ResponseDeserializationFailed)?;
        event_builder.map(|i| i.set_error_response_body(&response));
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
    ) -> CustomResult<ErrorResponse, ConnectorError> {
        self.build_error_response(res, event_builder)
    }
}

#[cfg(feature = "payouts")]
impl ConnectorIntegration<PoRecipient, PayoutsData, PayoutsResponseData> for Stripe {
    fn get_content_type(&self) -> &'static str {
        self.common_get_content_type()
    }

    fn get_url(
        &self,
        _req: &PayoutsRouterData<PoRecipient>,
        connectors: &Connectors,
    ) -> CustomResult<String, ConnectorError> {
        Ok(format!("{}v1/accounts", connectors.stripe.base_url))
    }

    fn get_headers(
        &self,
        req: &PayoutsRouterData<PoRecipient>,
        connectors: &Connectors,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, ConnectorError> {
        self.build_headers(req, connectors)
    }

    fn get_request_body(
        &self,
        req: &PayoutsRouterData<PoRecipient>,
        _connectors: &Connectors,
    ) -> CustomResult<RequestContent, ConnectorError> {
        let connector_req = stripe::StripeConnectRecipientCreateRequest::try_from(req)?;
        Ok(RequestContent::FormUrlEncoded(Box::new(connector_req)))
    }

    fn build_request(
        &self,
        req: &PayoutsRouterData<PoRecipient>,
        connectors: &Connectors,
    ) -> CustomResult<Option<Request>, ConnectorError> {
        let request = RequestBuilder::new()
            .method(Method::Post)
            .url(&PayoutRecipientType::get_url(self, req, connectors)?)
            .attach_default_headers()
            .headers(PayoutRecipientType::get_headers(self, req, connectors)?)
            .set_body(PayoutRecipientType::get_request_body(
                self, req, connectors,
            )?)
            .build();

        Ok(Some(request))
    }

    fn handle_response(
        &self,
        data: &PayoutsRouterData<PoRecipient>,
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<PayoutsRouterData<PoRecipient>, ConnectorError> {
        let response: stripe::StripeConnectRecipientCreateResponse = res
            .response
            .parse_struct("StripeConnectRecipientCreateResponse")
            .change_context(ConnectorError::ResponseDeserializationFailed)?;
        event_builder.map(|i| i.set_error_response_body(&response));
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
    ) -> CustomResult<ErrorResponse, ConnectorError> {
        self.build_error_response(res, event_builder)
    }
}

#[cfg(feature = "payouts")]
impl ConnectorIntegration<PoRecipientAccount, PayoutsData, PayoutsResponseData> for Stripe {
    fn get_content_type(&self) -> &'static str {
        self.common_get_content_type()
    }

    fn get_url(
        &self,
        req: &PayoutsRouterData<PoRecipientAccount>,
        connectors: &Connectors,
    ) -> CustomResult<String, ConnectorError> {
        let connector_customer_id = req.get_connector_customer_id()?;
        Ok(format!(
            "{}v1/accounts/{}/external_accounts",
            connectors.stripe.base_url, connector_customer_id
        ))
    }

    fn get_headers(
        &self,
        req: &PayoutsRouterData<PoRecipientAccount>,
        connectors: &Connectors,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, ConnectorError> {
        self.build_headers(req, connectors)
    }

    fn get_request_body(
        &self,
        req: &PayoutsRouterData<PoRecipientAccount>,
        _connectors: &Connectors,
    ) -> CustomResult<RequestContent, ConnectorError> {
        let connector_req = stripe::StripeConnectRecipientAccountCreateRequest::try_from(req)?;
        Ok(RequestContent::FormUrlEncoded(Box::new(connector_req)))
    }

    fn build_request(
        &self,
        req: &PayoutsRouterData<PoRecipientAccount>,
        connectors: &Connectors,
    ) -> CustomResult<Option<Request>, ConnectorError> {
        let request = RequestBuilder::new()
            .method(Method::Post)
            .url(&PayoutRecipientAccountType::get_url(self, req, connectors)?)
            .attach_default_headers()
            .headers(PayoutRecipientAccountType::get_headers(
                self, req, connectors,
            )?)
            .set_body(PayoutRecipientAccountType::get_request_body(
                self, req, connectors,
            )?)
            .build();

        Ok(Some(request))
    }

    fn handle_response(
        &self,
        data: &PayoutsRouterData<PoRecipientAccount>,
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<PayoutsRouterData<PoRecipientAccount>, ConnectorError> {
        let response: stripe::StripeConnectRecipientAccountCreateResponse = res
            .response
            .parse_struct("StripeConnectRecipientAccountCreateResponse")
            .change_context(ConnectorError::ResponseDeserializationFailed)?;
        event_builder.map(|i| i.set_error_response_body(&response));
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
    ) -> CustomResult<ErrorResponse, ConnectorError> {
        self.build_error_response(res, event_builder)
    }
}

static STRIPE_SUPPORTED_PAYMENT_METHODS: LazyLock<SupportedPaymentMethods> = LazyLock::new(|| {
    let default_capture_methods = vec![
        CaptureMethod::Automatic,
        CaptureMethod::Manual,
        CaptureMethod::SequentialAutomatic,
    ];

    let automatic_capture_supported =
        vec![CaptureMethod::Automatic, CaptureMethod::SequentialAutomatic];

    let supported_card_network = vec![
        common_enums::CardNetwork::Visa,
        common_enums::CardNetwork::Mastercard,
        common_enums::CardNetwork::AmericanExpress,
        common_enums::CardNetwork::Discover,
        common_enums::CardNetwork::JCB,
        common_enums::CardNetwork::DinersClub,
        common_enums::CardNetwork::UnionPay,
    ];

    let mut stripe_supported_payment_methods = SupportedPaymentMethods::new();

    stripe_supported_payment_methods.add(
        common_enums::PaymentMethod::Card,
        PaymentMethodType::Credit,
        PaymentMethodDetails {
            mandates: common_enums::FeatureStatus::Supported,
            refunds: common_enums::FeatureStatus::Supported,
            supported_capture_methods: default_capture_methods.clone(),
            specific_features: Some(
                api_models::feature_matrix::PaymentMethodSpecificFeatures::Card(
                    api_models::feature_matrix::CardSpecificFeatures {
                        three_ds: common_enums::FeatureStatus::Supported,
                        no_three_ds: common_enums::FeatureStatus::Supported,
                        supported_card_networks: supported_card_network.clone(),
                    },
                ),
            ),
        },
    );

    stripe_supported_payment_methods.add(
        common_enums::PaymentMethod::Card,
        PaymentMethodType::Debit,
        PaymentMethodDetails {
            mandates: common_enums::FeatureStatus::Supported,
            refunds: common_enums::FeatureStatus::Supported,
            supported_capture_methods: default_capture_methods.clone(),
            specific_features: Some(
                api_models::feature_matrix::PaymentMethodSpecificFeatures::Card(
                    api_models::feature_matrix::CardSpecificFeatures {
                        three_ds: common_enums::FeatureStatus::Supported,
                        no_three_ds: common_enums::FeatureStatus::Supported,
                        supported_card_networks: supported_card_network.clone(),
                    },
                ),
            ),
        },
    );

    stripe_supported_payment_methods.add(
        common_enums::PaymentMethod::PayLater,
        PaymentMethodType::Klarna,
        PaymentMethodDetails {
            mandates: common_enums::FeatureStatus::NotSupported,
            refunds: common_enums::FeatureStatus::Supported,
            supported_capture_methods: default_capture_methods.clone(),
            specific_features: None,
        },
    );

    stripe_supported_payment_methods.add(
        common_enums::PaymentMethod::PayLater,
        PaymentMethodType::Affirm,
        PaymentMethodDetails {
            mandates: common_enums::FeatureStatus::NotSupported,
            refunds: common_enums::FeatureStatus::Supported,
            supported_capture_methods: default_capture_methods.clone(),
            specific_features: None,
        },
    );

    stripe_supported_payment_methods.add(
        common_enums::PaymentMethod::PayLater,
        PaymentMethodType::AfterpayClearpay,
        PaymentMethodDetails {
            mandates: common_enums::FeatureStatus::NotSupported,
            refunds: common_enums::FeatureStatus::Supported,
            supported_capture_methods: default_capture_methods.clone(),
            specific_features: None,
        },
    );

    stripe_supported_payment_methods.add(
        common_enums::PaymentMethod::Wallet,
        PaymentMethodType::AliPay,
        PaymentMethodDetails {
            mandates: common_enums::FeatureStatus::NotSupported,
            refunds: common_enums::FeatureStatus::Supported,
            supported_capture_methods: default_capture_methods.clone(),
            specific_features: None,
        },
    );

    stripe_supported_payment_methods.add(
        common_enums::PaymentMethod::Wallet,
        PaymentMethodType::AmazonPay,
        PaymentMethodDetails {
            mandates: common_enums::FeatureStatus::Supported,
            refunds: common_enums::FeatureStatus::Supported,
            supported_capture_methods: default_capture_methods.clone(),
            specific_features: None,
        },
    );

    stripe_supported_payment_methods.add(
        common_enums::PaymentMethod::Wallet,
        PaymentMethodType::ApplePay,
        PaymentMethodDetails {
            mandates: common_enums::FeatureStatus::Supported,
            refunds: common_enums::FeatureStatus::Supported,
            supported_capture_methods: default_capture_methods.clone(),
            specific_features: None,
        },
    );

    stripe_supported_payment_methods.add(
        common_enums::PaymentMethod::Wallet,
        PaymentMethodType::GooglePay,
        PaymentMethodDetails {
            mandates: common_enums::FeatureStatus::Supported,
            refunds: common_enums::FeatureStatus::Supported,
            supported_capture_methods: default_capture_methods.clone(),
            specific_features: None,
        },
    );

    stripe_supported_payment_methods.add(
        common_enums::PaymentMethod::Wallet,
        PaymentMethodType::WeChatPay,
        PaymentMethodDetails {
            mandates: common_enums::FeatureStatus::NotSupported,
            refunds: common_enums::FeatureStatus::Supported,
            supported_capture_methods: automatic_capture_supported.clone(),
            specific_features: None,
        },
    );

    stripe_supported_payment_methods.add(
        common_enums::PaymentMethod::Wallet,
        PaymentMethodType::Cashapp,
        PaymentMethodDetails {
            mandates: common_enums::FeatureStatus::Supported,
            refunds: common_enums::FeatureStatus::Supported,
            supported_capture_methods: default_capture_methods.clone(),
            specific_features: None,
        },
    );

    // Hosted Checkout: the buyer pays on Stripe's page, which charges immediately.
    stripe_supported_payment_methods.add(
        common_enums::PaymentMethod::Wallet,
        PaymentMethodType::StripeCheckout,
        PaymentMethodDetails {
            mandates: common_enums::FeatureStatus::NotSupported,
            refunds: common_enums::FeatureStatus::Supported,
            supported_capture_methods: automatic_capture_supported.clone(),
            specific_features: None,
        },
    );

    stripe_supported_payment_methods.add(
        common_enums::PaymentMethod::Wallet,
        PaymentMethodType::RevolutPay,
        PaymentMethodDetails {
            mandates: common_enums::FeatureStatus::Supported,
            refunds: common_enums::FeatureStatus::Supported,
            supported_capture_methods: default_capture_methods.clone(),
            specific_features: None,
        },
    );

    stripe_supported_payment_methods.add(
        common_enums::PaymentMethod::BankDebit,
        PaymentMethodType::Becs,
        PaymentMethodDetails {
            mandates: common_enums::FeatureStatus::Supported,
            refunds: common_enums::FeatureStatus::Supported,
            supported_capture_methods: default_capture_methods.clone(),
            specific_features: None,
        },
    );

    stripe_supported_payment_methods.add(
        common_enums::PaymentMethod::BankDebit,
        PaymentMethodType::Ach,
        PaymentMethodDetails {
            mandates: common_enums::FeatureStatus::Supported,
            refunds: common_enums::FeatureStatus::Supported,
            supported_capture_methods: automatic_capture_supported.clone(),
            specific_features: None,
        },
    );

    stripe_supported_payment_methods.add(
        common_enums::PaymentMethod::BankDebit,
        PaymentMethodType::Sepa,
        PaymentMethodDetails {
            mandates: common_enums::FeatureStatus::Supported,
            refunds: common_enums::FeatureStatus::Supported,
            supported_capture_methods: automatic_capture_supported.clone(),
            specific_features: None,
        },
    );

    stripe_supported_payment_methods.add(
        common_enums::PaymentMethod::BankDebit,
        PaymentMethodType::Bacs,
        PaymentMethodDetails {
            mandates: common_enums::FeatureStatus::Supported,
            refunds: common_enums::FeatureStatus::Supported,
            supported_capture_methods: default_capture_methods.clone(),
            specific_features: None,
        },
    );

    stripe_supported_payment_methods.add(
        common_enums::PaymentMethod::BankRedirect,
        PaymentMethodType::BancontactCard,
        PaymentMethodDetails {
            mandates: common_enums::FeatureStatus::Supported,
            refunds: common_enums::FeatureStatus::Supported,
            supported_capture_methods: automatic_capture_supported.clone(),
            specific_features: None,
        },
    );

    stripe_supported_payment_methods.add(
        common_enums::PaymentMethod::BankRedirect,
        PaymentMethodType::Blik,
        PaymentMethodDetails {
            mandates: common_enums::FeatureStatus::NotSupported,
            refunds: common_enums::FeatureStatus::Supported,
            supported_capture_methods: automatic_capture_supported.clone(),
            specific_features: None,
        },
    );

    stripe_supported_payment_methods.add(
        common_enums::PaymentMethod::BankTransfer,
        PaymentMethodType::Ach,
        PaymentMethodDetails {
            mandates: common_enums::FeatureStatus::NotSupported,
            refunds: common_enums::FeatureStatus::Supported,
            supported_capture_methods: automatic_capture_supported.clone(),
            specific_features: None,
        },
    );

    stripe_supported_payment_methods.add(
        common_enums::PaymentMethod::BankTransfer,
        PaymentMethodType::SepaBankTransfer,
        PaymentMethodDetails {
            mandates: common_enums::FeatureStatus::NotSupported,
            refunds: common_enums::FeatureStatus::Supported,
            supported_capture_methods: automatic_capture_supported.clone(),
            specific_features: None,
        },
    );

    stripe_supported_payment_methods.add(
        common_enums::PaymentMethod::BankTransfer,
        PaymentMethodType::Bacs,
        PaymentMethodDetails {
            mandates: common_enums::FeatureStatus::NotSupported,
            refunds: common_enums::FeatureStatus::Supported,
            supported_capture_methods: automatic_capture_supported.clone(),
            specific_features: None,
        },
    );

    stripe_supported_payment_methods.add(
        common_enums::PaymentMethod::BankTransfer,
        PaymentMethodType::Multibanco,
        PaymentMethodDetails {
            mandates: common_enums::FeatureStatus::NotSupported,
            refunds: common_enums::FeatureStatus::Supported,
            supported_capture_methods: automatic_capture_supported.clone(),
            specific_features: None,
        },
    );

    stripe_supported_payment_methods.add(
        common_enums::PaymentMethod::BankRedirect,
        PaymentMethodType::Giropay,
        PaymentMethodDetails {
            mandates: common_enums::FeatureStatus::NotSupported,
            refunds: common_enums::FeatureStatus::NotSupported,
            supported_capture_methods: automatic_capture_supported.clone(),
            specific_features: None,
        },
    );

    stripe_supported_payment_methods.add(
        common_enums::PaymentMethod::BankRedirect,
        PaymentMethodType::Ideal,
        PaymentMethodDetails {
            mandates: common_enums::FeatureStatus::Supported,
            refunds: common_enums::FeatureStatus::Supported,
            supported_capture_methods: automatic_capture_supported.clone(),
            specific_features: None,
        },
    );

    stripe_supported_payment_methods.add(
        common_enums::PaymentMethod::BankRedirect,
        PaymentMethodType::Przelewy24,
        PaymentMethodDetails {
            mandates: common_enums::FeatureStatus::NotSupported,
            refunds: common_enums::FeatureStatus::Supported,
            supported_capture_methods: automatic_capture_supported.clone(),
            specific_features: None,
        },
    );

    stripe_supported_payment_methods.add(
        common_enums::PaymentMethod::BankRedirect,
        PaymentMethodType::Eps,
        PaymentMethodDetails {
            mandates: common_enums::FeatureStatus::NotSupported,
            refunds: common_enums::FeatureStatus::Supported,
            supported_capture_methods: automatic_capture_supported.clone(),
            specific_features: None,
        },
    );

    stripe_supported_payment_methods.add(
        common_enums::PaymentMethod::BankRedirect,
        PaymentMethodType::OnlineBankingFpx,
        PaymentMethodDetails {
            mandates: common_enums::FeatureStatus::NotSupported,
            refunds: common_enums::FeatureStatus::Supported,
            supported_capture_methods: automatic_capture_supported.clone(),
            specific_features: None,
        },
    );

    stripe_supported_payment_methods.add(
        common_enums::PaymentMethod::BankRedirect,
        PaymentMethodType::Sofort,
        PaymentMethodDetails {
            mandates: common_enums::FeatureStatus::Supported,
            refunds: common_enums::FeatureStatus::Supported,
            supported_capture_methods: automatic_capture_supported.clone(),
            specific_features: None,
        },
    );

    stripe_supported_payment_methods
});

static STRIPE_CONNECTOR_INFO: ConnectorInfo = ConnectorInfo {
    display_name: "Stripe",
    description: "Stripe is a payment processing platform that provides businesses with tools and APIs to accept payments online and manage their financial infrastructure",
    connector_type: common_enums::HyperswitchConnectorCategory::PaymentGateway,
    integration_status: common_enums::ConnectorIntegrationStatus::Live,
};

static STRIPE_SUPPORTED_WEBHOOK_FLOWS: [common_enums::EventClass; 3] = [
    common_enums::EventClass::Payments,
    common_enums::EventClass::Refunds,
    common_enums::EventClass::Disputes,
];

impl ConnectorSpecifications for Stripe {
    fn get_connector_about(&self) -> Option<&'static ConnectorInfo> {
        Some(&STRIPE_CONNECTOR_INFO)
    }

    fn get_supported_payment_methods(&self) -> Option<&'static SupportedPaymentMethods> {
        Some(&*STRIPE_SUPPORTED_PAYMENT_METHODS)
    }

    fn get_supported_webhook_flows(&self) -> Option<&'static [common_enums::EventClass]> {
        Some(&STRIPE_SUPPORTED_WEBHOOK_FLOWS)
    }

    fn should_call_connector_customer(
        &self,
        #[cfg(feature = "v1")]
        _payment_attempt: &hyperswitch_domain_models::payments::payment_attempt::PaymentAttempt,
    ) -> api::ConnectorCustomerAction {
        api::ConnectorCustomerAction::CallConnectorCustomer
    }
}

#[cfg(test)]
mod external_refund_tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::panic
    )]

    use api_models::{
        payments::PaymentIdType,
        webhooks::{ObjectReferenceId, RefundIdType},
    };
    use common_utils::crypto::SignMessage;
    use hyperswitch_interfaces::webhooks::IncomingWebhook;
    use serde_json::json;

    use super::*;

    const PI_ID: &str = "pi_3PxyzABCDEF";

    /// Real Stripe TEST `charge.refunded` delivery body, 2026-10-05.
    const REAL_CHARGE_REFUNDED: &str = r#"{"id":"evt_3UNBOCKMN9YFmEPb0WakgDBB","object":"event","api_version":"2022-11-15","created":1791204790,"data":{"object":{"id":"ch_3UNBOCKMN9YFmEPb0Nnv369X","object":"charge","amount":1000,"amount_captured":1000,"amount_refunded":300,"amount_updates":[],"application":null,"application_fee":null,"application_fee_amount":null,"balance_transaction":"txn_3UNBOCKMN9YFmEPb0EX62ia9","billing_details":{"address":{"city":null,"country":null,"line1":null,"line2":null,"postal_code":null,"state":null},"email":null,"name":null,"phone":null,"tax_id":null},"calculated_statement_descriptor":"PXSOL USA, INC.","captured":true,"created":1791204788,"currency":"usd","customer":null,"description":null,"destination":null,"dispute":null,"disputed":false,"failure_balance_transaction":null,"failure_code":null,"failure_message":null,"fraud_details":{},"invoice":null,"livemode":false,"metadata":{},"on_behalf_of":null,"order":null,"outcome":{"advice_code":null,"network_advice_code":null,"network_decline_code":null,"network_status":"approved_by_network","reason":null,"risk_level":"normal","risk_score":17,"seller_message":"Payment complete.","type":"authorized"},"paid":true,"payment_intent":"pi_3UNBOCKMN9YFmEPb0UTbEvFd","payment_method":"pm_1UNBOCKMN9YFmEPblrcIGABf","payment_method_details":{"card":{"amount_authorized":1000,"authorization_code":"464928","brand":"visa","checks":{"address_line1_check":null,"address_postal_code_check":null,"cvc_check":"pass"},"country":"US","electronic_commerce_indicator":"07","exp_month":10,"exp_year":2027,"extended_authorization":{"status":"disabled"},"fingerprint":"YBHgZOgYQ2qL2HRG","funding":"credit","incremental_authorization":{"status":"unavailable"},"installments":null,"last4":"4242","mandate":null,"multicapture":{"status":"unavailable"},"network":"visa","network_token":{"used":false},"network_transaction_id":"896672103907910","overcapture":{"maximum_amount_capturable":1000,"status":"unavailable"},"regulated_status":"unregulated","three_d_secure":null,"transaction_link_id":null,"wallet":null},"type":"card"},"radar_options":{},"receipt_email":null,"receipt_number":null,"receipt_url":"https://pay.stripe.com/receipts/REDACTED","refunded":false,"review":null,"shipping":null,"source":null,"source_transfer":null,"statement_descriptor":null,"statement_descriptor_suffix":null,"status":"succeeded","transfer_data":null,"transfer_group":null},"previous_attributes":{"amount_refunded":0,"receipt_url":"https://pay.stripe.com/receipts/REDACTED"}},"livemode":false,"pending_webhooks":4,"request":{"id":"req_D50QhO2NZoQSAX","idempotency_key":"f1356da8-3a23-4998-ab0c-7f76da16cb43"},"type":"charge.refunded"}"#;

    /// Real Stripe TEST `charge.dispute.created` delivery body, 2026-10-05.
    const REAL_DISPUTE_CREATED: &str = r#"{"id":"evt_1UNBOIKMN9YFmEPblvjH0obP","object":"event","api_version":"2022-11-15","created":1791204794,"data":{"object":{"id":"du_1UNBOHKMN9YFmEPb3cLJ7Uhs","object":"dispute","amount":1000,"balance_transaction":"txn_1UNBOIKMN9YFmEPbBE8pC9zL","balance_transactions":[{"available_on":1791331200,"created":1791204793,"net":-2500,"currency":"usd","source":"du_1UNBOHKMN9YFmEPb3cLJ7Uhs","reporting_category":"dispute","fee_details":[{"application":null,"amount":1500,"type":"stripe_fee","description":"Dispute fee","currency":"usd"}],"amount":-1000,"status":"pending","balance_type":"payments","object":"balance_transaction","id":"txn_1UNBOIKMN9YFmEPbBE8pC9zL","exchange_rate":null,"type":"adjustment","description":"Chargeback withdrawal for ch_3UNBOFKMN9YFmEPb0P8XvlDX","fee":1500}],"charge":"ch_3UNBOFKMN9YFmEPb0P8XvlDX","created":1791204793,"currency":"usd","enhanced_eligibility_types":[],"evidence":{"access_activity_log":null,"billing_address":null,"cancellation_policy":null,"cancellation_policy_disclosure":null,"cancellation_rebuttal":null,"customer_communication":null,"customer_email_address":null,"customer_name":null,"customer_purchase_ip":null,"customer_signature":null,"duplicate_charge_documentation":null,"duplicate_charge_explanation":null,"duplicate_charge_id":null,"enhanced_evidence":{},"product_description":null,"receipt":null,"refund_policy":null,"refund_policy_disclosure":null,"refund_refusal_explanation":null,"service_date":null,"service_documentation":null,"shipping_address":null,"shipping_carrier":null,"shipping_date":null,"shipping_documentation":null,"shipping_tracking_number":null,"uncategorized_file":null,"uncategorized_text":null},"evidence_details":{"due_by":1791935999,"enhanced_eligibility":{},"has_evidence":false,"past_due":false,"submission_count":0},"is_charge_refundable":false,"livemode":false,"metadata":{},"payment_intent":"pi_3UNBOFKMN9YFmEPb00WexzTQ","payment_method_details":{"card":{"brand":"visa","case_type":"chargeback","network":"visa","network_reason_code":"10.4"},"type":"card"},"reason":"fraudulent","status":"needs_response"}},"livemode":false,"pending_webhooks":6,"request":{"id":"req_gSJPUEqu7Hgkr6","idempotency_key":"03f4c5e3-c655-4a8e-bbc0-6e17d421c7e2"},"type":"charge.dispute.created"}"#;

    /// Real Stripe TEST `charge.dispute.funds_withdrawn` delivery body, 2026-10-05: same second as the creation, the dispute is still `needs_response`.
    const REAL_DISPUTE_FUNDS_WITHDRAWN: &str = r#"{"id":"evt_1UNBOIKMN9YFmEPbW3wvcwcY","object":"event","api_version":"2022-11-15","created":1791204794,"data":{"object":{"id":"du_1UNBOHKMN9YFmEPb3cLJ7Uhs","object":"dispute","amount":1000,"balance_transaction":"txn_1UNBOIKMN9YFmEPbBE8pC9zL","balance_transactions":[{"available_on":1791331200,"created":1791204793,"net":-2500,"currency":"usd","source":"du_1UNBOHKMN9YFmEPb3cLJ7Uhs","reporting_category":"dispute","fee_details":[{"application":null,"amount":1500,"type":"stripe_fee","description":"Dispute fee","currency":"usd"}],"amount":-1000,"status":"pending","balance_type":"payments","object":"balance_transaction","id":"txn_1UNBOIKMN9YFmEPbBE8pC9zL","exchange_rate":null,"type":"adjustment","description":"Chargeback withdrawal for ch_3UNBOFKMN9YFmEPb0P8XvlDX","fee":1500}],"charge":"ch_3UNBOFKMN9YFmEPb0P8XvlDX","created":1791204793,"currency":"usd","enhanced_eligibility_types":[],"evidence":{"access_activity_log":null,"billing_address":null,"cancellation_policy":null,"cancellation_policy_disclosure":null,"cancellation_rebuttal":null,"customer_communication":null,"customer_email_address":null,"customer_name":null,"customer_purchase_ip":null,"customer_signature":null,"duplicate_charge_documentation":null,"duplicate_charge_explanation":null,"duplicate_charge_id":null,"enhanced_evidence":{},"product_description":null,"receipt":null,"refund_policy":null,"refund_policy_disclosure":null,"refund_refusal_explanation":null,"service_date":null,"service_documentation":null,"shipping_address":null,"shipping_carrier":null,"shipping_date":null,"shipping_documentation":null,"shipping_tracking_number":null,"uncategorized_file":null,"uncategorized_text":null},"evidence_details":{"due_by":1791935999,"enhanced_eligibility":{},"has_evidence":false,"past_due":false,"submission_count":0},"is_charge_refundable":false,"livemode":false,"metadata":{},"payment_intent":"pi_3UNBOFKMN9YFmEPb00WexzTQ","payment_method_details":{"card":{"brand":"visa","case_type":"chargeback","network":"visa","network_reason_code":"10.4"},"type":"card"},"reason":"fraudulent","status":"needs_response"}},"livemode":false,"pending_webhooks":2,"request":{"id":"req_gSJPUEqu7Hgkr6","idempotency_key":"03f4c5e3-c655-4a8e-bbc0-6e17d421c7e2"},"type":"charge.dispute.funds_withdrawn"}"#;

    fn event(event_type: &str, object: serde_json::Value) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "id": "evt_1Pxyz",
            "object": "event",
            "api_version": "2022-11-15",
            "created": 1_700_000_200,
            "type": event_type,
            "data": {"object": object}
        }))
        .unwrap()
    }

    fn charge_object(with_payment_intent: bool) -> serde_json::Value {
        let mut charge = json!({
            "id": "ch_3Pxyz",
            "object": "charge",
            "amount": 10000,
            "amount_captured": 10000,
            "amount_refunded": 2500,
            "currency": "usd",
            "created": 1_700_000_000,
            "metadata": {},
            "refunded": false,
            "status": "succeeded"
        });
        if with_payment_intent {
            charge["payment_intent"] = json!(PI_ID);
        }
        charge
    }

    fn refund_object(with_payment_intent: bool, status: &str) -> serde_json::Value {
        let mut refund = json!({
            "id": "re_3PxyzDashboard",
            "object": "refund",
            "amount": 2500,
            "charge": "ch_3Pxyz",
            "created": 1_700_000_100,
            "currency": "usd",
            "metadata": {},
            "status": status
        });
        if with_payment_intent {
            refund["payment_intent"] = json!(PI_ID);
        }
        refund
    }

    fn dispute_object() -> serde_json::Value {
        json!({
            "id": "dp_1Pxyz",
            "object": "dispute",
            "amount": 10000,
            "charge": "ch_3Pxyz",
            "created": 1_700_000_000,
            "currency": "usd",
            "payment_intent": PI_ID,
            "reason": "fraudulent",
            "status": "needs_response",
            "evidence_details": {"due_by": 1_700_900_000}
        })
    }

    fn with_request<T>(
        body: &[u8],
        check: impl FnOnce(&IncomingWebhookRequestDetails<'_>) -> T,
    ) -> T {
        let headers = actix_web::http::header::HeaderMap::new();
        let request = IncomingWebhookRequestDetails {
            method: actix_web::http::Method::POST,
            uri: "/webhooks/stripe".parse().expect("valid test uri"),
            headers: &headers,
            body,
            query_params: String::new(),
        };
        check(&request)
    }

    fn event_type_of(body: &[u8]) -> IncomingWebhookEvent {
        with_request(body, |request| {
            Stripe::new().get_webhook_event_type(request).unwrap()
        })
    }

    fn reference_of(body: &[u8]) -> ObjectReferenceId {
        with_request(body, |request| {
            Stripe::new()
                .get_webhook_object_reference_id(request)
                .unwrap()
        })
    }

    fn assert_syncs_parent_payment(reference: ObjectReferenceId) {
        match reference {
            ObjectReferenceId::PaymentId(PaymentIdType::ConnectorTransactionId(id)) => {
                assert_eq!(id, PI_ID)
            }
            other => panic!("expected the parent payment intent, got {other:?}"),
        }
    }

    #[test]
    fn payment_intent_sync_url_expands_the_charge_and_its_refunds() {
        let url = payment_intent_sync_url("https://api.stripe.com/", PI_ID);
        assert_eq!(
            url,
            "https://api.stripe.com/v1/payment_intents/pi_3PxyzABCDEF?expand[0]=latest_charge&expand[1]=latest_charge.refunds"
        );
    }

    #[test]
    fn charge_refunded_syncs_the_parent_payment() {
        let body = event("charge.refunded", charge_object(true));
        assert_eq!(
            event_type_of(&body),
            IncomingWebhookEvent::PaymentIntentProcessing
        );
        assert_syncs_parent_payment(reference_of(&body));
        // The event must land in the payments flow.
        assert!(matches!(
            api_models::webhooks::WebhookFlow::from(event_type_of(&body)),
            api_models::webhooks::WebhookFlow::Payment
        ));
    }

    #[test]
    fn charge_refund_updated_keeps_the_refund_id_routing_with_or_without_a_payment_intent() {
        // A refund beyond the first page of `latest_charge.refunds` would never be updated
        // through a payment sync, so the event updates the known refund directly.
        for with_payment_intent in [false, true] {
            let body = event(
                "charge.refund.updated",
                refund_object(with_payment_intent, "succeeded"),
            );
            assert_eq!(event_type_of(&body), IncomingWebhookEvent::RefundSuccess);
            match reference_of(&body) {
                ObjectReferenceId::RefundId(RefundIdType::ConnectorRefundId(id)) => {
                    assert_eq!(id, "re_3PxyzDashboard")
                }
                other => panic!("expected the refund id, got {other:?}"),
            }
            assert!(matches!(
                api_models::webhooks::WebhookFlow::from(event_type_of(&body)),
                api_models::webhooks::WebhookFlow::Refund
            ));
            let failed = event(
                "charge.refund.updated",
                refund_object(with_payment_intent, "failed"),
            );
            assert_eq!(event_type_of(&failed), IncomingWebhookEvent::RefundFailure);
            for status in ["pending", "requires_action"] {
                let other = event(
                    "charge.refund.updated",
                    refund_object(with_payment_intent, status),
                );
                assert_eq!(
                    event_type_of(&other),
                    IncomingWebhookEvent::EventNotSupported,
                    "{status}"
                );
            }
        }
    }

    #[test]
    fn a_charge_refunded_without_a_payment_intent_has_nothing_to_sync() {
        let charge = event("charge.refunded", charge_object(false));
        assert_eq!(
            event_type_of(&charge),
            IncomingWebhookEvent::EventNotSupported
        );
    }

    fn dispute_with_status(status: &str) -> serde_json::Value {
        let mut dispute = dispute_object();
        dispute["status"] = json!(status);
        dispute
    }

    #[test]
    fn dispute_events_follow_the_dispute_status_not_the_event_name() {
        use IncomingWebhookEvent::{
            DisputeCancelled, DisputeChallenged, DisputeLost, DisputeOpened, DisputeWon,
        };
        let statuses = [
            ("warning_needs_response", DisputeOpened),
            ("needs_response", DisputeOpened),
            ("warning_under_review", DisputeChallenged),
            ("under_review", DisputeChallenged),
            ("won", DisputeWon),
            ("lost", DisputeLost),
            ("warning_closed", DisputeCancelled),
            ("prevented", DisputeCancelled),
        ];
        for event_type in [
            "charge.dispute.created",
            "charge.dispute.updated",
            "charge.dispute.closed",
            "charge.dispute.funds_withdrawn",
            "charge.dispute.funds_reinstated",
        ] {
            for (status, expected) in &statuses {
                let body = event(event_type, dispute_with_status(status));
                assert_eq!(event_type_of(&body), *expected, "{event_type}/{status}");
                assert_syncs_parent_payment(reference_of(&body));
            }
        }
    }

    #[test]
    fn dispute_events_with_an_unknown_status_fall_back_without_a_final_outcome() {
        for status in ["charge_refunded", "something_new"] {
            for (event_type, expected) in [
                (
                    "charge.dispute.created",
                    IncomingWebhookEvent::DisputeOpened,
                ),
                (
                    "charge.dispute.closed",
                    IncomingWebhookEvent::DisputeCancelled,
                ),
                (
                    "charge.dispute.updated",
                    IncomingWebhookEvent::EventNotSupported,
                ),
                (
                    "charge.dispute.funds_withdrawn",
                    IncomingWebhookEvent::DisputeOpened,
                ),
                (
                    "charge.dispute.funds_reinstated",
                    IncomingWebhookEvent::DisputeOpened,
                ),
            ] {
                let body = event(event_type, dispute_with_status(status));
                assert_eq!(event_type_of(&body), expected, "{event_type}/{status}");
            }
        }
        // No status at all behaves like an unknown one.
        let mut dispute = dispute_object();
        dispute.as_object_mut().unwrap().remove("status");
        let body = event("charge.dispute.funds_withdrawn", dispute);
        assert_eq!(event_type_of(&body), IncomingWebhookEvent::DisputeOpened);
    }

    #[test]
    fn dispute_status_is_still_reported_as_the_connector_status() {
        for (status, reported) in [
            ("needs_response", "NeedsResponse"),
            ("under_review", "UnderReview"),
            ("won", "Won"),
            ("lost", "Lost"),
        ] {
            let body = event(
                "charge.dispute.funds_withdrawn",
                dispute_with_status(status),
            );
            let details = with_request(&body, |request| {
                Stripe::new().get_dispute_details(request).unwrap()
            });
            assert_eq!(details.connector_status, reported);
        }
    }

    #[test]
    fn real_charge_refunded_syncs_the_parent_payment_and_is_not_signature_verified() {
        let body = REAL_CHARGE_REFUNDED.as_bytes();
        assert_eq!(
            event_type_of(body),
            IncomingWebhookEvent::PaymentIntentProcessing
        );
        match reference_of(body) {
            ObjectReferenceId::PaymentId(PaymentIdType::ConnectorTransactionId(id)) => {
                assert_eq!(id, "pi_3UNBOCKMN9YFmEPb0UTbEvFd")
            }
            other => panic!("expected the parent payment intent, got {other:?}"),
        }
        // A valid HMAC would verify a regular event; this one never does, so core syncs live.
        let secret = b"whsec_test";
        let message = b"1791204791.body";
        let signature = crypto::HmacSha256.sign_message(secret, message).unwrap();
        let verified = with_request(body, |request| {
            Stripe::new()
                .get_webhook_source_verification_algorithm(request)
                .unwrap()
                .verify_signature(secret, &signature, message)
                .unwrap()
        });
        assert!(!verified);
    }

    #[test]
    fn real_dispute_created_opens_the_dispute_and_parses_its_details() {
        let body = REAL_DISPUTE_CREATED.as_bytes();
        assert_eq!(event_type_of(body), IncomingWebhookEvent::DisputeOpened);
        match reference_of(body) {
            ObjectReferenceId::PaymentId(PaymentIdType::ConnectorTransactionId(id)) => {
                assert_eq!(id, "pi_3UNBOFKMN9YFmEPb00WexzTQ")
            }
            other => panic!("expected the parent payment intent, got {other:?}"),
        }
        let details = with_request(body, |request| {
            Stripe::new().get_dispute_details(request).unwrap()
        });
        assert_eq!(details.amount.to_string(), "1000");
        assert_eq!(details.currency, common_enums::Currency::USD);
        assert_eq!(details.connector_dispute_id, "du_1UNBOHKMN9YFmEPb3cLJ7Uhs");
        assert_eq!(details.connector_status, "NeedsResponse");
        assert_eq!(details.connector_reason.as_deref(), Some("fraudulent"));
    }

    #[test]
    fn real_dispute_funds_withdrawn_does_not_report_a_lost_dispute() {
        // Stripe withdraws the funds when the dispute opens, in the same second as
        // `charge.dispute.created`, while the dispute is still `needs_response`.
        let body = REAL_DISPUTE_FUNDS_WITHDRAWN.as_bytes();
        assert_eq!(event_type_of(body), IncomingWebhookEvent::DisputeOpened);
        let details = with_request(body, |request| {
            Stripe::new().get_dispute_details(request).unwrap()
        });
        assert_eq!(details.connector_dispute_id, "du_1UNBOHKMN9YFmEPb3cLJ7Uhs");
        assert_eq!(details.connector_status, "NeedsResponse");
    }

    #[test]
    fn payment_intent_events_keep_their_mapping() {
        let payment_intent = json!({
            "id": PI_ID,
            "object": "payment_intent",
            "amount": 10000,
            "currency": "usd",
            "created": 1_700_000_000,
            "metadata": {},
            "status": "succeeded"
        });
        let body = event("payment_intent.succeeded", payment_intent);
        assert_eq!(
            event_type_of(&body),
            IncomingWebhookEvent::PaymentIntentSuccess
        );
        assert_syncs_parent_payment(reference_of(&body));
    }

    #[test]
    fn only_the_parent_payment_sync_events_skip_the_signature_check() {
        // A valid HMAC signs the message: the regular events verify, `charge.refunded` of a
        // known payment never does, so core runs a live payment sync instead of consuming the
        // webhook body as a payment sync response.
        let secret = b"whsec_test";
        let message = b"1700000000.body";
        let signature = crypto::HmacSha256.sign_message(secret, message).unwrap();
        let verifies = |body: Vec<u8>| {
            with_request(&body, |request| {
                Stripe::new()
                    .get_webhook_source_verification_algorithm(request)
                    .unwrap()
                    .verify_signature(secret, &signature, message)
                    .unwrap()
            })
        };
        assert!(verifies(event(
            "payment_intent.succeeded",
            charge_object(true)
        )));
        assert!(verifies(event("charge.dispute.created", dispute_object())));
        assert!(verifies(event(
            "charge.refund.updated",
            refund_object(false, "succeeded")
        )));
        // `charge.refund.updated` keeps the HMAC verification, with or without the intent.
        assert!(verifies(event(
            "charge.refund.updated",
            refund_object(true, "succeeded")
        )));
        assert!(!verifies(event("charge.refunded", charge_object(true))));
        // Without a payment intent there is nothing to sync, so it verifies as usual.
        assert!(verifies(event("charge.refunded", charge_object(false))));
    }
}
