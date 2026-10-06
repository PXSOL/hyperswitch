pub mod transformers;

use api_models::webhooks::IncomingWebhookEvent;
use common_enums::enums;
use common_utils::{
    crypto,
    errors::CustomResult,
    ext_traits::{BytesExt, ValueExt},
    request::{Method, Request, RequestBuilder, RequestContent},
    types::{AmountConvertor, StringMajorUnit, StringMajorUnitForConnector},
};
use error_stack::ResultExt;
use hyperswitch_domain_models::{
    router_data::{AccessToken, ConnectorAuthType, ErrorResponse, RouterData},
    router_flow_types::{
        access_token_auth::AccessTokenAuth,
        payments::{
            Authorize, Capture, CompleteAuthorize, PSync, PaymentMethodToken, Session,
            SetupMandate, Void,
        },
        refunds::{Execute, RSync},
    },
    router_request_types::{
        AccessTokenRequestData, CompleteAuthorizeData, PaymentMethodTokenizationData,
        PaymentsAuthorizeData, PaymentsCancelData, PaymentsCaptureData, PaymentsSessionData,
        PaymentsSyncData, RefundsData, SetupMandateRequestData,
    },
    router_response_types::{
        ConnectorInfo, PaymentMethodDetails, PaymentsResponseData, RefundsResponseData,
        SupportedPaymentMethods, SupportedPaymentMethodsExt,
    },
    types::{
        PaymentsAuthorizeRouterData, PaymentsSyncRouterData, RefreshTokenRouterData,
        RefundSyncRouterData, RefundsRouterData,
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
    types::{
        PaymentsAuthorizeType, PaymentsSyncType, RefreshTokenType, RefundExecuteType,
        RefundSyncType, Response,
    },
    webhooks::{IncomingWebhook, IncomingWebhookRequestDetails},
};
use masking::{Mask, PeekInterface, Secret};
use std::sync::LazyLock;
use transformers as izipay;

use crate::{
    constants::headers,
    types::ResponseRouterData,
    utils::{self, RefundsRequestData},
};

const TRANSACTION_ID_HEADER: &str = "transactionId";

#[derive(Clone)]
pub struct Izipay {
    amount_converter: &'static (dyn AmountConvertor<Output = StringMajorUnit> + Sync),
}

impl Izipay {
    pub fn new() -> &'static Self {
        &Self {
            amount_converter: &StringMajorUnitForConnector,
        }
    }

    /// Headers of the calls that only generate a session token: no bearer, a fresh
    /// correlation id (the session token is bound to it).
    fn token_generate_headers(&self) -> Vec<(String, masking::Maskable<String>)> {
        vec![
            (
                headers::CONTENT_TYPE.to_string(),
                self.common_get_content_type().to_string().into(),
            ),
            (
                TRANSACTION_ID_HEADER.to_string(),
                izipay::new_transaction_id().into(),
            ),
        ]
    }

    /// Headers of every call authenticated with the session token the router fetched for this
    /// operation: Izipay requires the `transactionId` header to be the one the token was
    /// generated with.
    fn session_headers(
        &self,
        access_token: Option<&AccessToken>,
        expected_kind: izipay::IzipayTokenKind,
    ) -> CustomResult<Vec<(String, masking::Maskable<String>)>, errors::ConnectorError> {
        let packed = izipay::unpack_access_token(access_token, expected_kind)?;
        Ok(vec![
            (
                headers::CONTENT_TYPE.to_string(),
                self.common_get_content_type().to_string().into(),
            ),
            (
                headers::AUTHORIZATION.to_string(),
                format!("Bearer {}", packed.token.peek()).into_masked(),
            ),
            (
                TRANSACTION_ID_HEADER.to_string(),
                packed.transaction_id.into(),
            ),
        ])
    }
}

impl api::Payment for Izipay {}
impl api::PaymentSession for Izipay {}
impl api::ConnectorAccessToken for Izipay {}
impl api::MandateSetup for Izipay {}
impl api::PaymentAuthorize for Izipay {}
impl api::PaymentsCompleteAuthorize for Izipay {}
impl api::PaymentSync for Izipay {}
impl api::PaymentCapture for Izipay {}
impl api::PaymentVoid for Izipay {}
impl api::PaymentToken for Izipay {}
impl api::Refund for Izipay {}
impl api::RefundExecute for Izipay {}
impl api::RefundSync for Izipay {}

impl<Flow, Request, Response> ConnectorCommonExt<Flow, Request, Response> for Izipay where
    Self: ConnectorIntegration<Flow, Request, Response>
{
}

impl ConnectorCommon for Izipay {
    fn id(&self) -> &'static str {
        "izipay"
    }

    fn get_currency_unit(&self) -> api::CurrencyUnit {
        api::CurrencyUnit::Base
    }

    fn common_get_content_type(&self) -> &'static str {
        mime::APPLICATION_JSON.essence_str()
    }

    fn base_url<'a>(&self, connectors: &'a Connectors) -> &'a str {
        // Every flow resolves its host per request from the MCA `test_mode` (see
        // `get_izipay_base_url`); this is the production host.
        connectors.izipay.base_url.as_ref()
    }

    fn build_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        // Izipay's error bodies differ from one service to another and some failures are not
        // JSON at all (a gateway page during an outage), see `IzipayErrorResponse::parse`.
        match izipay::IzipayErrorResponse::parse(&res.response) {
            Some(response) => {
                event_builder.map(|i| i.set_error_response_body(&response));
                router_env::logger::info!(connector_response=?response);

                Ok(ErrorResponse {
                    status_code: res.status_code,
                    code: response.code,
                    message: response.message,
                    reason: response.reason,
                    // Left to the router: for a payment sync that failed with a non-2xx
                    // status (a 403 `MC` "transaction does not exist" because the buyer has
                    // not paid yet, or a 5xx) the attempt keeps the status it has.
                    attempt_status: None,
                    connector_transaction_id: None,
                    network_advice_code: None,
                    network_decline_code: None,
                    network_error_message: None,
                    connector_metadata: None,
                })
            }
            None => {
                event_builder.map(|event| {
                    event.set_error(serde_json::json!({
                        "error": res.response.escape_ascii().to_string(),
                        "status_code": res.status_code
                    }))
                });
                utils::handle_json_response_deserialization_failure(res, "izipay")
            }
        }
    }
}

impl ConnectorValidation for Izipay {}

/// Host for this request: sandbox when the MCA is in test mode, production otherwise (an unset
/// flag is production, so a live account is never sent to the sandbox).
fn get_izipay_base_url(
    connectors: &Connectors,
    test_mode: Option<bool>,
) -> CustomResult<&str, errors::ConnectorError> {
    match izipay::IzipayEnvironment::from_test_mode(test_mode) {
        izipay::IzipayEnvironment::Production => Ok(connectors.izipay.base_url.as_str()),
        izipay::IzipayEnvironment::Sandbox => {
            let secondary_base_url = connectors.izipay.secondary_base_url.as_str();
            if secondary_base_url.is_empty() {
                Err(errors::ConnectorError::InvalidConnectorConfig {
                    config: "izipay.secondary_base_url (required when test_mode is enabled)",
                }
                .into())
            } else {
                Ok(secondary_base_url)
            }
        }
    }
}

// ============================================================================
// Session / mandates / tokenization / capture / void: not supported
// ============================================================================

impl ConnectorIntegration<Session, PaymentsSessionData, PaymentsResponseData> for Izipay {}

impl ConnectorIntegration<PaymentMethodToken, PaymentMethodTokenizationData, PaymentsResponseData>
    for Izipay
{
}

impl ConnectorIntegration<CompleteAuthorize, CompleteAuthorizeData, PaymentsResponseData>
    for Izipay
{
}

impl ConnectorIntegration<SetupMandate, SetupMandateRequestData, PaymentsResponseData> for Izipay {
    fn build_request(
        &self,
        _req: &RouterData<SetupMandate, SetupMandateRequestData, PaymentsResponseData>,
        _connectors: &Connectors,
    ) -> CustomResult<Option<Request>, errors::ConnectorError> {
        Err(
            errors::ConnectorError::NotImplemented("Setup Mandate flow for Izipay".to_string())
                .into(),
        )
    }
}

impl ConnectorIntegration<Capture, PaymentsCaptureData, PaymentsResponseData> for Izipay {}

impl ConnectorIntegration<Void, PaymentsCancelData, PaymentsResponseData> for Izipay {}

// ============================================================================
// AccessTokenAuth: POST /security/v1/Token/Generate (generic token: the order number is the
// merchant code and the amount 0.00). Izipay session tokens are per operation, so the token
// is generated for the kind of operation that asked for it (refund or not) and packed with
// the correlation id it is bound to.
// ============================================================================

impl ConnectorIntegration<AccessTokenAuth, AccessTokenRequestData, AccessToken> for Izipay {
    fn get_headers(
        &self,
        _req: &RefreshTokenRouterData,
        _connectors: &Connectors,
    ) -> CustomResult<Vec<(String, masking::Maskable<String>)>, errors::ConnectorError> {
        Ok(self.token_generate_headers())
    }

    fn get_content_type(&self) -> &'static str {
        self.common_get_content_type()
    }

    fn get_url(
        &self,
        req: &RefreshTokenRouterData,
        connectors: &Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        let base_url = get_izipay_base_url(connectors, req.test_mode)?;
        Ok(format!("{base_url}/security/v1/Token/Generate"))
    }

    fn get_request_body(
        &self,
        req: &RefreshTokenRouterData,
        _connectors: &Connectors,
    ) -> CustomResult<RequestContent, errors::ConnectorError> {
        let connector_req = izipay::IzipayTokenRequest::try_from(req)?;
        Ok(RequestContent::Json(Box::new(connector_req)))
    }

    fn build_request(
        &self,
        req: &RefreshTokenRouterData,
        connectors: &Connectors,
    ) -> CustomResult<Option<Request>, errors::ConnectorError> {
        Ok(Some(
            RequestBuilder::new()
                .method(Method::Post)
                .url(&RefreshTokenType::get_url(self, req, connectors)?)
                .attach_default_headers()
                .headers(RefreshTokenType::get_headers(self, req, connectors)?)
                .set_body(RefreshTokenType::get_request_body(self, req, connectors)?)
                .build(),
        ))
    }

    fn handle_response(
        &self,
        data: &RefreshTokenRouterData,
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<RefreshTokenRouterData, errors::ConnectorError> {
        let response: izipay::IzipayTokenResponse = res
            .response
            .parse_struct("IzipayTokenResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
        // The session token is not logged.
        event_builder.map(|i| i.set_response_body(&serde_json::json!({ "code": response.code })));
        router_env::logger::info!(izipay_token_code=?response.code);
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
// Authorize: POST /security/v1/Token/Generate bound to the order number and amount. The
// response is turned into the page that opens Izipay's hosted checkout (Web SDK, redirect
// mode). The access token the router fetched first is not used here.
// ============================================================================

impl ConnectorIntegration<Authorize, PaymentsAuthorizeData, PaymentsResponseData> for Izipay {
    fn get_headers(
        &self,
        _req: &PaymentsAuthorizeRouterData,
        _connectors: &Connectors,
    ) -> CustomResult<Vec<(String, masking::Maskable<String>)>, errors::ConnectorError> {
        Ok(self.token_generate_headers())
    }

    fn get_content_type(&self) -> &'static str {
        self.common_get_content_type()
    }

    fn get_url(
        &self,
        req: &PaymentsAuthorizeRouterData,
        connectors: &Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        let base_url = get_izipay_base_url(connectors, req.test_mode)?;
        Ok(format!("{base_url}/security/v1/Token/Generate"))
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
        let connector_router_data = izipay::IzipayRouterData::from((amount, req));
        let connector_req = izipay::IzipayTokenRequest::try_from(&connector_router_data)?;
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
    ) -> CustomResult<PaymentsAuthorizeRouterData, errors::ConnectorError> {
        let response: izipay::IzipayTokenResponse = res
            .response
            .parse_struct("IzipayTokenResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
        // The session token is not logged.
        event_builder.map(|i| i.set_response_body(&serde_json::json!({ "code": response.code })));
        router_env::logger::info!(izipay_token_code=?response.code);
        let amount = utils::convert_amount(
            self.amount_converter,
            data.request.minor_amount,
            data.request.currency,
        )?;
        izipay::authorize_response(response, data.clone(), res.status_code, &amount)
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
// PSync: POST /orderinfo/v1/Transaction/Search by order number
// ============================================================================

impl ConnectorIntegration<PSync, PaymentsSyncData, PaymentsResponseData> for Izipay {
    fn get_headers(
        &self,
        req: &PaymentsSyncRouterData,
        _connectors: &Connectors,
    ) -> CustomResult<Vec<(String, masking::Maskable<String>)>, errors::ConnectorError> {
        self.session_headers(
            req.access_token.as_ref(),
            izipay::IzipayTokenKind::Ecommerce,
        )
    }

    fn get_content_type(&self) -> &'static str {
        self.common_get_content_type()
    }

    fn get_url(
        &self,
        req: &PaymentsSyncRouterData,
        connectors: &Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        let base_url = get_izipay_base_url(connectors, req.test_mode)?;
        Ok(format!("{base_url}/orderinfo/v1/Transaction/Search"))
    }

    fn get_request_body(
        &self,
        req: &PaymentsSyncRouterData,
        _connectors: &Connectors,
    ) -> CustomResult<RequestContent, errors::ConnectorError> {
        let connector_req = izipay::IzipaySearchRequest::try_from(req)?;
        Ok(RequestContent::Json(Box::new(connector_req)))
    }

    fn build_request(
        &self,
        req: &PaymentsSyncRouterData,
        connectors: &Connectors,
    ) -> CustomResult<Option<Request>, errors::ConnectorError> {
        Ok(Some(
            RequestBuilder::new()
                .method(Method::Post)
                .url(&PaymentsSyncType::get_url(self, req, connectors)?)
                .attach_default_headers()
                .headers(PaymentsSyncType::get_headers(self, req, connectors)?)
                .set_body(PaymentsSyncType::get_request_body(self, req, connectors)?)
                .build(),
        ))
    }

    fn handle_response(
        &self,
        data: &PaymentsSyncRouterData,
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<PaymentsSyncRouterData, errors::ConnectorError> {
        let response: izipay::IzipaySearchResponse = res
            .response
            .parse_struct("IzipaySearchResponse")
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
// Refund: POST /refund/v1/Transaction/Refund (REFUND session token). The merchant RUC comes
// from the MCA metadata and what identifies the payment from the metadata stored by the sync
// that charged it.
// ============================================================================

impl ConnectorIntegration<Execute, RefundsData, RefundsResponseData> for Izipay {
    fn get_headers(
        &self,
        req: &RefundsRouterData<Execute>,
        _connectors: &Connectors,
    ) -> CustomResult<Vec<(String, masking::Maskable<String>)>, errors::ConnectorError> {
        self.session_headers(req.access_token.as_ref(), izipay::IzipayTokenKind::Refund)
    }

    fn get_content_type(&self) -> &'static str {
        self.common_get_content_type()
    }

    fn get_url(
        &self,
        req: &RefundsRouterData<Execute>,
        connectors: &Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        let base_url = get_izipay_base_url(connectors, req.test_mode)?;
        Ok(format!("{base_url}/refund/v1/Transaction/Refund"))
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
        let connector_router_data = izipay::IzipayRouterData::from((refund_amount, req));
        let connector_req = izipay::IzipayRefundRequest::try_from(&connector_router_data)?;
        Ok(RequestContent::Json(Box::new(connector_req)))
    }

    fn build_request(
        &self,
        req: &RefundsRouterData<Execute>,
        connectors: &Connectors,
    ) -> CustomResult<Option<Request>, errors::ConnectorError> {
        Ok(Some(
            RequestBuilder::new()
                .method(Method::Post)
                .url(&RefundExecuteType::get_url(self, req, connectors)?)
                .attach_default_headers()
                .headers(RefundExecuteType::get_headers(self, req, connectors)?)
                .set_body(RefundExecuteType::get_request_body(self, req, connectors)?)
                .build(),
        ))
    }

    fn handle_response(
        &self,
        data: &RefundsRouterData<Execute>,
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<RefundsRouterData<Execute>, errors::ConnectorError> {
        let response: izipay::IzipayRefundResponse = res
            .response
            .parse_struct("IzipayRefundResponse")
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
// Refund sync: GET /refund/v1/refunds/status (REFUND session token)
// ============================================================================

impl ConnectorIntegration<RSync, RefundsData, RefundsResponseData> for Izipay {
    fn get_headers(
        &self,
        req: &RefundSyncRouterData,
        _connectors: &Connectors,
    ) -> CustomResult<Vec<(String, masking::Maskable<String>)>, errors::ConnectorError> {
        self.session_headers(req.access_token.as_ref(), izipay::IzipayTokenKind::Refund)
    }

    fn get_content_type(&self) -> &'static str {
        self.common_get_content_type()
    }

    fn get_url(
        &self,
        req: &RefundSyncRouterData,
        connectors: &Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        let base_url = get_izipay_base_url(connectors, req.test_mode)?;
        let auth = izipay::IzipayAuthType::try_from(&req.connector_auth_type)?;
        let connector_refund_id = req.request.get_connector_refund_id()?;
        Ok(format!(
            "{base_url}/refund/v1/refunds/status?refundId={}&merchantCode={}&language=ESP",
            urlencoding::encode(&connector_refund_id),
            urlencoding::encode(&auth.merchant_code),
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
                .url(&RefundSyncType::get_url(self, req, connectors)?)
                .attach_default_headers()
                .headers(RefundSyncType::get_headers(self, req, connectors)?)
                .build(),
        ))
    }

    fn handle_response(
        &self,
        data: &RefundSyncRouterData,
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<RefundSyncRouterData, errors::ConnectorError> {
        let response: izipay::IzipayRefundStatusResponse = res
            .response
            .parse_struct("IzipayRefundStatusResponse")
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
// Incoming notifications (IPN)
// ============================================================================

#[async_trait::async_trait]
impl IncomingWebhook for Izipay {
    /// The notification is signed with the merchant's "Clave Hash", which is part of the
    /// connector account credentials (not a separate webhook secret):
    /// `base64(HMAC-SHA256(payloadHttp, hash key)) == signature`.
    async fn verify_webhook_source(
        &self,
        request: &IncomingWebhookRequestDetails<'_>,
        _merchant_id: &common_utils::id_type::MerchantId,
        _connector_webhook_details: Option<common_utils::pii::SecretSerdeValue>,
        connector_account_details: crypto::Encryptable<Secret<serde_json::Value>>,
        _connector_label: &str,
    ) -> CustomResult<bool, errors::ConnectorError> {
        let connector_auth_type: ConnectorAuthType = connector_account_details
            .parse_value::<ConnectorAuthType>("ConnectorAuthType")
            .change_context(errors::ConnectorError::WebhookSourceVerificationFailed)?;
        let auth = izipay::IzipayAuthType::try_from(&connector_auth_type)
            .change_context(errors::ConnectorError::WebhookSourceVerificationFailed)?;
        let header_signature = request
            .headers
            .get("Signature")
            .and_then(|value| value.to_str().ok());
        izipay::verify_webhook_signature(request.body, header_signature, &auth.hash_key)
    }

    fn get_webhook_object_reference_id(
        &self,
        request: &IncomingWebhookRequestDetails<'_>,
    ) -> CustomResult<api_models::webhooks::ObjectReferenceId, errors::ConnectorError> {
        let payload = izipay::parse_signed_payload(request.body)
            .change_context(errors::ConnectorError::WebhookReferenceIdNotFound)?;
        let reference = izipay::webhook_reference(&payload)
            .ok_or(errors::ConnectorError::WebhookReferenceIdNotFound)?;
        Ok(api_models::webhooks::ObjectReferenceId::PaymentId(
            api_models::payments::PaymentIdType::ConnectorTransactionId(reference),
        ))
    }

    fn get_webhook_event_type(
        &self,
        request: &IncomingWebhookRequestDetails<'_>,
    ) -> CustomResult<IncomingWebhookEvent, errors::ConnectorError> {
        let payload = izipay::parse_signed_payload(request.body)
            .change_context(errors::ConnectorError::WebhookEventTypeNotFound)?;
        Ok(izipay::map_webhook_event(&payload))
    }

    fn get_webhook_resource_object(
        &self,
        request: &IncomingWebhookRequestDetails<'_>,
    ) -> CustomResult<Box<dyn masking::ErasedMaskSerialize>, errors::ConnectorError> {
        // Same shape as a Search response, so the PSync response handler parses it.
        Ok(Box::new(izipay::signed_payload_value(request.body)?))
    }
}

// ============================================================================
// Connector specifications
// ============================================================================

static IZIPAY_SUPPORTED_PAYMENT_METHODS: LazyLock<SupportedPaymentMethods> = LazyLock::new(|| {
    let mut supported_payment_methods = SupportedPaymentMethods::new();

    // Hosted checkout (redirect), which offers every method enabled for the merchant (cards,
    // Yape, Plin, QR, Apple Pay). Payments are captured automatically.
    supported_payment_methods.add(
        enums::PaymentMethod::Wallet,
        enums::PaymentMethodType::Izipay,
        PaymentMethodDetails {
            mandates: enums::FeatureStatus::NotSupported,
            refunds: enums::FeatureStatus::Supported,
            supported_capture_methods: vec![
                enums::CaptureMethod::Automatic,
                enums::CaptureMethod::SequentialAutomatic,
            ],
            specific_features: None,
        },
    );

    supported_payment_methods
});

static IZIPAY_CONNECTOR_INFO: ConnectorInfo = ConnectorInfo {
    display_name: "Izipay",
    description: "Izipay Peru hosted checkout (Web SDK redirect mode)",
    connector_type: enums::HyperswitchConnectorCategory::PaymentGateway,
    integration_status: enums::ConnectorIntegrationStatus::Sandbox,
};

static IZIPAY_SUPPORTED_WEBHOOK_FLOWS: [enums::EventClass; 1] = [enums::EventClass::Payments];

impl ConnectorSpecifications for Izipay {
    fn get_connector_about(&self) -> Option<&'static ConnectorInfo> {
        Some(&IZIPAY_CONNECTOR_INFO)
    }

    fn get_supported_payment_methods(&self) -> Option<&'static SupportedPaymentMethods> {
        Some(&*IZIPAY_SUPPORTED_PAYMENT_METHODS)
    }

    fn get_supported_webhook_flows(&self) -> Option<&'static [enums::EventClass]> {
        Some(&IZIPAY_SUPPORTED_WEBHOOK_FLOWS)
    }

    /// The order number sent to Izipay is derived from the attempt id (15 characters
    /// `[0-9A-Z]`), so it is the same on every call for the attempt and a sync can recompute
    /// it. The "payment id as connector request id" flag is ignored on purpose: a payment can
    /// have several attempts and each needs its own order number.
    #[cfg(feature = "v1")]
    fn generate_connector_request_reference_id(
        &self,
        _payment_intent: &hyperswitch_domain_models::payments::PaymentIntent,
        payment_attempt: &hyperswitch_domain_models::payments::payment_attempt::PaymentAttempt,
        _is_config_enabled_to_send_payment_id_as_connector_request_id: bool,
    ) -> String {
        izipay::order_number_from_attempt_id(&payment_attempt.attempt_id)
    }
}
