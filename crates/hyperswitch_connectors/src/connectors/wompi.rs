pub mod transformers;

use api_models::webhooks::IncomingWebhookEvent;
use common_enums::enums;
use common_utils::{
    crypto,
    errors::CustomResult,
    ext_traits::{ByteSliceExt, BytesExt},
    request::{Method, Request, RequestBuilder, RequestContent},
    types::{AmountConvertor, MinorUnitForConnector},
};
use error_stack::ResultExt;
use hyperswitch_domain_models::{
    payment_method_data::PaymentMethodData,
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
        PaymentsAuthorizeRouterData, PaymentsCompleteAuthorizeRouterData, PaymentsSyncRouterData,
        RefreshTokenRouterData, RefundSyncRouterData, RefundsRouterData, TokenizationRouterData,
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
        PaymentsAuthorizeType, PaymentsCompleteAuthorizeType, PaymentsSyncType, RefreshTokenType,
        RefundExecuteType, RefundSyncType, Response, TokenizationType,
    },
    webhooks::{IncomingWebhook, IncomingWebhookRequestDetails},
};
use masking::{Mask, PeekInterface};
use std::sync::LazyLock;
use transformers as wompi;

use crate::{
    constants::headers,
    types::ResponseRouterData,
    utils::{self, PaymentsSyncRequestData, RefundsRequestData},
};

#[derive(Clone)]
pub struct Wompi {
    amount_converter:
        &'static (dyn AmountConvertor<Output = common_utils::types::MinorUnit> + Sync),
}

impl Wompi {
    pub fn new() -> &'static Self {
        &Self {
            amount_converter: &MinorUnitForConnector,
        }
    }

    /// Headers signed with the PRIVATE key rather than the public key that
    /// `build_headers` (via `get_auth_header`) always sends: a PSync-by-reference
    /// search and both refund flows are merchant-to-Wompi calls that Wompi's docs
    /// require the private key for, unlike the buyer-facing card/tokenization/
    /// authorize calls, which use the public key.
    fn private_key_headers(
        &self,
        auth: &wompi::WompiAuthType,
    ) -> Vec<(String, masking::Maskable<String>)> {
        vec![
            (
                headers::CONTENT_TYPE.to_string(),
                self.common_get_content_type().to_string().into(),
            ),
            (
                headers::AUTHORIZATION.to_string(),
                format!("Bearer {}", auth.private_key.peek()).into_masked(),
            ),
        ]
    }
}

impl api::Payment for Wompi {}
impl api::PaymentSession for Wompi {}
impl api::ConnectorAccessToken for Wompi {}
impl api::MandateSetup for Wompi {}
impl api::PaymentAuthorize for Wompi {}
impl api::PaymentsCompleteAuthorize for Wompi {}
impl api::PaymentSync for Wompi {}
impl api::PaymentCapture for Wompi {}
impl api::PaymentVoid for Wompi {}
impl api::PaymentToken for Wompi {}
impl api::Refund for Wompi {}
impl api::RefundExecute for Wompi {}
impl api::RefundSync for Wompi {}

impl<Flow, Request, Response> ConnectorCommonExt<Flow, Request, Response> for Wompi
where
    Self: ConnectorIntegration<Flow, Request, Response>,
{
    fn build_headers(
        &self,
        req: &RouterData<Flow, Request, Response>,
        _connectors: &Connectors,
    ) -> CustomResult<Vec<(String, masking::Maskable<String>)>, errors::ConnectorError> {
        let mut headers = vec![(
            headers::CONTENT_TYPE.to_string(),
            self.get_content_type().to_string().into(),
        )];
        let mut auth_header = self.get_auth_header(&req.connector_auth_type)?;
        headers.append(&mut auth_header);
        Ok(headers)
    }
}

impl ConnectorCommon for Wompi {
    fn id(&self) -> &'static str {
        "wompi"
    }

    fn get_currency_unit(&self) -> api::CurrencyUnit {
        api::CurrencyUnit::Minor
    }

    fn common_get_content_type(&self) -> &'static str {
        mime::APPLICATION_JSON.essence_str()
    }

    fn base_url<'a>(&self, connectors: &'a Connectors) -> &'a str {
        // The environment (sandbox/production) actually used for every request is
        // resolved per-call from the public key prefix (`get_wompi_base_url` below),
        // never from this fixed method: Wompi rejects a key used against the wrong
        // host with a 401, so this connector never trusts a single static base url.
        connectors.wompi.base_url.as_ref()
    }

    fn get_auth_header(
        &self,
        auth_type: &ConnectorAuthType,
    ) -> CustomResult<Vec<(String, masking::Maskable<String>)>, errors::ConnectorError> {
        // Default (public-key) credential, for the calls Wompi documents with the
        // public key (merchant lookup, card tokenization, transaction creation).
        // Every server-side read of a transaction or refund overrides `get_headers`
        // with the private key instead (see the PSync impl for why).
        let auth = wompi::WompiAuthType::try_from(auth_type)?;
        Ok(vec![(
            headers::AUTHORIZATION.to_string(),
            format!("Bearer {}", auth.public_key.peek()).into_masked(),
        )])
    }

    fn build_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        let response: CustomResult<wompi::WompiErrorResponse, common_utils::errors::ParsingError> =
            res.response.parse_struct("WompiErrorResponse");

        match response {
            Ok(response) => {
                event_builder.map(|i| i.set_error_response_body(&response));
                router_env::logger::info!(connector_response=?response);

                Ok(ErrorResponse {
                    status_code: res.status_code,
                    code: response.error.error_type.clone(),
                    message: response.error.combined_reason(),
                    reason: Some(response.error.combined_reason()),
                    attempt_status: None,
                    connector_transaction_id: None,
                    network_advice_code: None,
                    network_decline_code: None,
                    network_error_message: None,
                    connector_metadata: None,
                })
            }
            // Not every error Wompi can return is JSON (e.g. an HTML 502 from its
            // edge/proxy layer during an outage), so a body that fails to parse as
            // `WompiErrorResponse` is not necessarily a bug in this connector.
            Err(error) => {
                event_builder.map(|event| {
                    event.set_error(serde_json::json!({
                        "error": res.response.escape_ascii().to_string(),
                        "status_code": res.status_code
                    }))
                });
                router_env::logger::error!(deserialization_error=?error);
                utils::handle_json_response_deserialization_failure(res, "wompi")
            }
        }
    }
}

impl ConnectorValidation for Wompi {
    fn validate_psync_reference_id(
        &self,
        _data: &PaymentsSyncData,
        _is_three_ds: bool,
        _status: enums::AttemptStatus,
        _connector_meta_data: Option<common_utils::pii::SecretSerdeValue>,
    ) -> CustomResult<(), errors::ConnectorError> {
        // A hosted-checkout (wallet) attempt syncs by `connector_request_reference_id`
        // (GET /transactions?reference=...) and has no connector_transaction_id until
        // the buyer pays. A CARD attempt can also reach PSync without one (its POST
        // /transactions timed out after Wompi accepted it), and is resolved the same
        // way. So having a connector_transaction_id is never a precondition for PSync
        // here (see `syncs_by_reference`).
        Ok(())
    }
}

/// Resolves the host to call for this request from the auth keys' environment prefix
/// (never from `test_mode`): used by every flow's `get_url` so environment selection has
/// exactly one implementation. See `transformers::resolve_environment` for why the prefix
/// (not `test_mode`) is the source of truth.
fn get_wompi_base_url<'a>(
    auth: &wompi::WompiAuthType,
    connectors: &'a Connectors,
) -> CustomResult<&'a str, errors::ConnectorError> {
    match wompi::resolve_environment(auth)? {
        wompi::WompiEnvironment::Production => Ok(connectors.wompi.base_url.as_str()),
        wompi::WompiEnvironment::Sandbox => Ok(connectors.wompi.secondary_base_url.as_str()),
    }
}

/// True when this PSync must search `GET /transactions?reference=` instead of
/// trusting a known connector transaction id: the hosted-checkout flow always does
/// (it never has one until the buyer pays), and so does a CARD attempt whose POST
/// /transactions timed out after Wompi accepted it — a retry that trusted the
/// (missing) id would have nothing to sync, and a retry that resubmitted the same
/// `reference` to POST /transactions again would get a 422 from Wompi, so this
/// searches for whatever Wompi ended up creating instead.
fn syncs_by_reference(req: &PaymentsSyncRouterData) -> bool {
    req.payment_method == enums::PaymentMethod::Wallet
        || req.request.get_connector_transaction_id().is_err()
}

// ============================================================================
// Session — not implemented
// ============================================================================

impl ConnectorIntegration<Session, PaymentsSessionData, PaymentsResponseData> for Wompi {}

// ============================================================================
// PaymentMethodToken — POST /tokens/cards (public key)
// ============================================================================

impl ConnectorIntegration<PaymentMethodToken, PaymentMethodTokenizationData, PaymentsResponseData>
    for Wompi
{
    fn get_headers(
        &self,
        req: &TokenizationRouterData,
        connectors: &Connectors,
    ) -> CustomResult<Vec<(String, masking::Maskable<String>)>, errors::ConnectorError> {
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
        let auth = wompi::WompiAuthType::try_from(&req.connector_auth_type)?;
        let base_url = get_wompi_base_url(&auth, connectors)?;
        Ok(format!("{base_url}/tokens/cards"))
    }

    fn get_request_body(
        &self,
        req: &TokenizationRouterData,
        _connectors: &Connectors,
    ) -> CustomResult<RequestContent, errors::ConnectorError> {
        let connector_req = wompi::WompiCardTokenRequest::try_from(req)?;
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
    ) -> CustomResult<TokenizationRouterData, errors::ConnectorError> {
        let response: wompi::WompiCardTokenResponse = res
            .response
            .parse_struct("WompiCardTokenResponse")
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
// AccessTokenAuth — GET /merchants/{public_key} (no Authorization header: the
// key is already in the path, and this endpoint does not require one)
// ============================================================================

impl ConnectorIntegration<AccessTokenAuth, AccessTokenRequestData, AccessToken> for Wompi {
    fn get_http_method(&self) -> Method {
        Method::Get
    }

    fn get_headers(
        &self,
        _req: &RefreshTokenRouterData,
        _connectors: &Connectors,
    ) -> CustomResult<Vec<(String, masking::Maskable<String>)>, errors::ConnectorError> {
        Ok(vec![(
            headers::CONTENT_TYPE.to_string(),
            self.common_get_content_type().to_string().into(),
        )])
    }

    fn get_content_type(&self) -> &'static str {
        self.common_get_content_type()
    }

    fn get_url(
        &self,
        req: &RefreshTokenRouterData,
        connectors: &Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        let auth = wompi::WompiAuthType::try_from(&req.connector_auth_type)?;
        let base_url = get_wompi_base_url(&auth, connectors)?;
        Ok(format!("{base_url}/merchants/{}", auth.public_key.peek()))
    }

    fn build_request(
        &self,
        req: &RefreshTokenRouterData,
        connectors: &Connectors,
    ) -> CustomResult<Option<Request>, errors::ConnectorError> {
        Ok(Some(
            RequestBuilder::new()
                .method(Method::Get)
                .url(&RefreshTokenType::get_url(self, req, connectors)?)
                .attach_default_headers()
                .headers(RefreshTokenType::get_headers(self, req, connectors)?)
                .build(),
        ))
    }

    fn handle_response(
        &self,
        data: &RefreshTokenRouterData,
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<RefreshTokenRouterData, errors::ConnectorError> {
        let response: wompi::WompiMerchantResponse = res
            .response
            .parse_struct("WompiMerchantResponse")
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
// SetupMandate — not implemented (Wompi has no mandate/COF flow wired here)
// ============================================================================

impl ConnectorIntegration<SetupMandate, SetupMandateRequestData, PaymentsResponseData> for Wompi {
    fn build_request(
        &self,
        _req: &RouterData<SetupMandate, SetupMandateRequestData, PaymentsResponseData>,
        _connectors: &Connectors,
    ) -> CustomResult<Option<Request>, errors::ConnectorError> {
        Err(
            errors::ConnectorError::NotImplemented("Setup Mandate flow for Wompi".to_string())
                .into(),
        )
    }
}

// ============================================================================
// Authorize — card: POST /transactions (public key) ; hosted checkout:
// GET /merchants/{public_key} (validates key/env/active, then redirects)
// ============================================================================

impl ConnectorIntegration<Authorize, PaymentsAuthorizeData, PaymentsResponseData> for Wompi {
    fn get_headers(
        &self,
        req: &PaymentsAuthorizeRouterData,
        connectors: &Connectors,
    ) -> CustomResult<Vec<(String, masking::Maskable<String>)>, errors::ConnectorError> {
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
        let auth = wompi::WompiAuthType::try_from(&req.connector_auth_type)?;
        let base_url = get_wompi_base_url(&auth, connectors)?;
        if wompi::is_hosted_checkout(&req.request.payment_method_data)
            || wompi::is_card_three_ds(&req.request.payment_method_data, req.auth_type)
        {
            Ok(format!("{base_url}/merchants/{}", auth.public_key.peek()))
        } else {
            Ok(format!("{base_url}/transactions"))
        }
    }

    fn get_request_body(
        &self,
        req: &PaymentsAuthorizeRouterData,
        _connectors: &Connectors,
    ) -> CustomResult<RequestContent, errors::ConnectorError> {
        match &req.request.payment_method_data {
            PaymentMethodData::Card(_) if req.auth_type == enums::AuthenticationType::NoThreeDs => {
                let amount = utils::convert_amount(
                    self.amount_converter,
                    req.request.minor_amount,
                    req.request.currency,
                )?;
                let connector_router_data = wompi::WompiRouterData::from((amount, req));
                let connector_req =
                    wompi::WompiTransactionsRequest::try_from(&connector_router_data)?;
                Ok(RequestContent::Json(Box::new(connector_req)))
            }
            // A card being authenticated with 3DS takes the merchant-lookup GET branch
            // below (see `build_request`), just like hosted checkout: this body is never
            // sent for either, but every flow must return something for the trait.
            _ => Ok(RequestContent::Json(Box::new(serde_json::json!({})))),
        }
    }

    fn build_request(
        &self,
        req: &PaymentsAuthorizeRouterData,
        connectors: &Connectors,
    ) -> CustomResult<Option<Request>, errors::ConnectorError> {
        let method = if wompi::is_hosted_checkout(&req.request.payment_method_data)
            || wompi::is_card_three_ds(&req.request.payment_method_data, req.auth_type)
        {
            Method::Get
        } else {
            Method::Post
        };
        let mut builder = RequestBuilder::new()
            .method(method)
            .url(&PaymentsAuthorizeType::get_url(self, req, connectors)?)
            .attach_default_headers()
            .headers(PaymentsAuthorizeType::get_headers(self, req, connectors)?);
        if method == Method::Post {
            builder = builder.set_body(PaymentsAuthorizeType::get_request_body(
                self, req, connectors,
            )?);
        }
        Ok(Some(builder.build()))
    }

    fn handle_response(
        &self,
        data: &PaymentsAuthorizeRouterData,
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<PaymentsAuthorizeRouterData, errors::ConnectorError> {
        if wompi::is_hosted_checkout(&data.request.payment_method_data) {
            let response: wompi::WompiMerchantResponse = res
                .response
                .parse_struct("WompiMerchantResponse")
                .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
            event_builder.map(|i| i.set_response_body(&response));
            router_env::logger::info!(connector_response=?response);
            RouterData::try_from(ResponseRouterData {
                response,
                data: data.clone(),
                http_code: res.status_code,
            })
        } else if wompi::is_card_three_ds(&data.request.payment_method_data, data.auth_type) {
            let response: wompi::WompiMerchantResponse = res
                .response
                .parse_struct("WompiMerchantResponse")
                .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
            event_builder.map(|i| i.set_response_body(&response));
            router_env::logger::info!(connector_response=?response);
            wompi::build_card_three_ds_authorize_response(ResponseRouterData {
                response,
                data: data.clone(),
                http_code: res.status_code,
            })
        } else {
            let response: wompi::WompiTransactionResponse = res
                .response
                .parse_struct("WompiTransactionResponse")
                .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
            event_builder.map(|i| i.set_response_body(&response));
            router_env::logger::info!(connector_response=?response);
            RouterData::try_from(ResponseRouterData {
                response,
                data: data.clone(),
                http_code: res.status_code,
            })
        }
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
// CompleteAuthorize — card 3DS v2, deferred one-shot `POST /transactions`
//
// Two physical round-trips reuse this SAME flow, distinguished by what is already stashed in
// `connector_meta` (never by the `wompi3ds` marker alone — see
// `wompi::determine_complete_authorize_stage`):
//   - `Create`: page A (browser info) has just posted back for the first time. Builds the
//     one-shot `POST /transactions` with `is_three_ds` and the stashed card token/customer
//     data; the card token never survives past this call.
//   - `Poll`: a transaction already exists (the real hit 2 from page B's `done` navigation, or
//     page A double-submitting while one already exists). Reads it back with the PRIVATE key,
//     exactly like PSync.
// ============================================================================

impl ConnectorIntegration<CompleteAuthorize, CompleteAuthorizeData, PaymentsResponseData>
    for Wompi
{
    fn get_headers(
        &self,
        req: &PaymentsCompleteAuthorizeRouterData,
        connectors: &Connectors,
    ) -> CustomResult<Vec<(String, masking::Maskable<String>)>, errors::ConnectorError> {
        match wompi::determine_complete_authorize_stage(req)? {
            wompi::WompiCompleteAuthorizeStage::Create(_) => self.build_headers(req, connectors),
            wompi::WompiCompleteAuthorizeStage::Poll { .. } => {
                let auth = wompi::WompiAuthType::try_from(&req.connector_auth_type)?;
                Ok(self.private_key_headers(&auth))
            }
        }
    }

    fn get_content_type(&self) -> &'static str {
        self.common_get_content_type()
    }

    fn get_url(
        &self,
        req: &PaymentsCompleteAuthorizeRouterData,
        connectors: &Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        let auth = wompi::WompiAuthType::try_from(&req.connector_auth_type)?;
        let base_url = get_wompi_base_url(&auth, connectors)?;
        match wompi::determine_complete_authorize_stage(req)? {
            wompi::WompiCompleteAuthorizeStage::Create(_) => Ok(format!("{base_url}/transactions")),
            wompi::WompiCompleteAuthorizeStage::Poll {
                wompi_transaction_id,
                ..
            } => Ok(format!("{base_url}/transactions/{wompi_transaction_id}")),
        }
    }

    fn get_request_body(
        &self,
        req: &PaymentsCompleteAuthorizeRouterData,
        _connectors: &Connectors,
    ) -> CustomResult<RequestContent, errors::ConnectorError> {
        match wompi::determine_complete_authorize_stage(req)? {
            wompi::WompiCompleteAuthorizeStage::Create(stash) => {
                let browser_info =
                    wompi::parse_browser_info_payload(req.request.redirect_response.as_ref())?;
                let connector_req =
                    wompi::build_three_ds_transaction_request(req, &stash, browser_info)?;
                Ok(RequestContent::Json(Box::new(connector_req)))
            }
            // `Poll` is a GET (see `build_request`): this body is never sent.
            wompi::WompiCompleteAuthorizeStage::Poll { .. } => {
                Ok(RequestContent::Json(Box::new(serde_json::json!({}))))
            }
        }
    }

    fn build_request(
        &self,
        req: &PaymentsCompleteAuthorizeRouterData,
        connectors: &Connectors,
    ) -> CustomResult<Option<Request>, errors::ConnectorError> {
        let method = match wompi::determine_complete_authorize_stage(req)? {
            wompi::WompiCompleteAuthorizeStage::Create(_) => Method::Post,
            wompi::WompiCompleteAuthorizeStage::Poll { .. } => Method::Get,
        };
        let mut builder = RequestBuilder::new()
            .method(method)
            .url(&PaymentsCompleteAuthorizeType::get_url(
                self, req, connectors,
            )?)
            .attach_default_headers()
            .headers(PaymentsCompleteAuthorizeType::get_headers(
                self, req, connectors,
            )?);
        if method == Method::Post {
            builder = builder.set_body(PaymentsCompleteAuthorizeType::get_request_body(
                self, req, connectors,
            )?);
        }
        Ok(Some(builder.build()))
    }

    fn handle_response(
        &self,
        data: &PaymentsCompleteAuthorizeRouterData,
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<PaymentsCompleteAuthorizeRouterData, errors::ConnectorError> {
        let stage = wompi::determine_complete_authorize_stage(data)?;
        let response: wompi::WompiTransactionResponse = res
            .response
            .parse_struct("WompiTransactionResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
        event_builder.map(|i| i.set_response_body(&response));
        router_env::logger::info!(connector_response=?response);

        let auth = wompi::WompiAuthType::try_from(&data.connector_auth_type)?;
        let public_key = auth.public_key.peek().clone();
        let polling_host = wompi::public_polling_host(&auth)?;
        let complete_authorize_url = data.request.complete_authorize_url.clone().ok_or(
            errors::ConnectorError::MissingRequiredField {
                field_name: "complete_authorize_url",
            },
        )?;

        match stage {
            wompi::WompiCompleteAuthorizeStage::Create(_) => wompi::three_ds_create_response(
                response.data,
                data.clone(),
                res.status_code,
                &public_key,
                polling_host,
                &complete_authorize_url,
            ),
            wompi::WompiCompleteAuthorizeStage::Poll { keep_polling, .. } => {
                wompi::three_ds_poll_response(
                    response.data,
                    data.clone(),
                    res.status_code,
                    keep_polling,
                    &public_key,
                    polling_host,
                    &complete_authorize_url,
                )
            }
        }
    }

    fn get_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        let mut error = self.build_error_response(res, event_builder)?;
        if wompi::is_duplicate_reference_error(&error) {
            router_env::logger::info!(
                "wompi: duplicate 3DS transaction reference (422); deferring to PSync search-by-reference"
            );
            error.attempt_status = Some(enums::AttemptStatus::Pending);
        }
        Ok(error)
    }
}

// ============================================================================
// PSync — card (known id): GET /transactions/{id} ; hosted, and a card attempt
// with no known id yet (see `syncs_by_reference`): ALWAYS
// GET /transactions?reference={connector_request_reference_id}, never the
// buyer-controllable redirect `?id=`. Both with the private key.
// ============================================================================

impl ConnectorIntegration<PSync, PaymentsSyncData, PaymentsResponseData> for Wompi {
    fn get_headers(
        &self,
        req: &PaymentsSyncRouterData,
        _connectors: &Connectors,
    ) -> CustomResult<Vec<(String, masking::Maskable<String>)>, errors::ConnectorError> {
        // Private key for both shapes: in production `GET /transactions/{id}` with
        // the public key answers 404 once a transaction is a few days old (seen on
        // transactions it had returned the same day), while the private key keeps
        // returning them.
        let auth = wompi::WompiAuthType::try_from(&req.connector_auth_type)?;
        Ok(self.private_key_headers(&auth))
    }

    fn get_content_type(&self) -> &'static str {
        self.common_get_content_type()
    }

    fn get_url(
        &self,
        req: &PaymentsSyncRouterData,
        connectors: &Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        let auth = wompi::WompiAuthType::try_from(&req.connector_auth_type)?;
        let base_url = get_wompi_base_url(&auth, connectors)?;
        if syncs_by_reference(req) {
            // A retry can supersede an earlier PENDING attempt with a new connector
            // transaction id under the same reference (or, for a card, simply never
            // produce one because the POST timed out after Wompi accepted it), so
            // this always searches by reference (private key) rather than trusting a
            // previously-seen id.
            Ok(format!(
                "{base_url}/transactions?reference={}",
                req.connector_request_reference_id
            ))
        } else {
            let connector_transaction_id = req.request.get_connector_transaction_id()?;
            Ok(format!(
                "{base_url}/transactions/{connector_transaction_id}"
            ))
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
    ) -> CustomResult<PaymentsSyncRouterData, errors::ConnectorError> {
        if data.payment_method == enums::PaymentMethod::Wallet {
            let response: wompi::WompiSearchResponse = res
                .response
                .parse_struct("WompiSearchResponse")
                .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
            event_builder.map(|i| i.set_response_body(&response));
            router_env::logger::info!(connector_response=?response);
            RouterData::try_from(ResponseRouterData {
                response,
                data: data.clone(),
                http_code: res.status_code,
            })
        } else if syncs_by_reference(data) {
            // A CARD retried by reference must NOT apply the hosted-checkout buyer-
            // retry window: there is no buyer retry to wait out here, POST
            // /transactions either created the charge or it did not.
            let response: wompi::WompiSearchResponse = res
                .response
                .parse_struct("WompiSearchResponse")
                .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
            event_builder.map(|i| i.set_response_body(&response));
            router_env::logger::info!(connector_response=?response);
            Ok(wompi::card_sync_by_reference_response(
                response.data,
                data.clone(),
                res.status_code,
            ))
        } else {
            let response: wompi::WompiTransactionResponse = res
                .response
                .parse_struct("WompiTransactionResponse")
                .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;
            event_builder.map(|i| i.set_response_body(&response));
            router_env::logger::info!(connector_response=?response);
            RouterData::try_from(ResponseRouterData {
                response,
                data: data.clone(),
                http_code: res.status_code,
            })
        }
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
// Capture / Void — not implemented
// (Wompi is auto-capture only here; no cancel/void flow is wired)
// ============================================================================

impl ConnectorIntegration<Capture, PaymentsCaptureData, PaymentsResponseData> for Wompi {}

impl ConnectorIntegration<Void, PaymentsCancelData, PaymentsResponseData> for Wompi {}

// ============================================================================
// Refunds Execute — POST /transactions/{id}/void (private key, not the public
// key `Authorize` and tokenization use)
//
// Wompi confirmed in writing that its API only supports VOIDING a card
// payment; it has no refund API a merchant can call. A void always releases
// the FULL amount of the original transaction and takes no body at all.
// `validate_void_refund` rejects up front what a void can never do (a
// currency other than COP, a partial amount, or a payment remembered as
// something other than a card); anything it lets through still goes to
// Wompi, which stays the final authority — see the doc comment on
// `wompi::validate_void_refund` for why.
// ============================================================================

impl ConnectorIntegration<Execute, RefundsData, RefundsResponseData> for Wompi {
    fn get_headers(
        &self,
        req: &RefundsRouterData<Execute>,
        _connectors: &Connectors,
    ) -> CustomResult<Vec<(String, masking::Maskable<String>)>, errors::ConnectorError> {
        let auth = wompi::WompiAuthType::try_from(&req.connector_auth_type)?;
        Ok(self.private_key_headers(&auth))
    }

    fn get_content_type(&self) -> &'static str {
        self.common_get_content_type()
    }

    fn get_url(
        &self,
        req: &RefundsRouterData<Execute>,
        connectors: &Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        let auth = wompi::WompiAuthType::try_from(&req.connector_auth_type)?;
        let base_url = get_wompi_base_url(&auth, connectors)?;
        Ok(format!(
            "{base_url}/transactions/{}/void",
            req.request.connector_transaction_id
        ))
    }

    fn build_request(
        &self,
        req: &RefundsRouterData<Execute>,
        connectors: &Connectors,
    ) -> CustomResult<Option<Request>, errors::ConnectorError> {
        wompi::validate_void_refund(
            req.request.connector_metadata.as_ref(),
            req.request.minor_refund_amount,
            req.request.minor_payment_amount,
            req.request.currency,
        )?;

        // No body: the void endpoint releases the full original transaction
        // implicitly.
        Ok(Some(
            RequestBuilder::new()
                .method(Method::Post)
                .url(&RefundExecuteType::get_url(self, req, connectors)?)
                .attach_default_headers()
                .headers(RefundExecuteType::get_headers(self, req, connectors)?)
                .build(),
        ))
    }

    fn handle_response(
        &self,
        data: &RefundsRouterData<Execute>,
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<RefundsRouterData<Execute>, errors::ConnectorError> {
        let response: wompi::WompiVoidResponse = res
            .response
            .parse_struct("WompiVoidResponse")
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
// Refunds RSync — GET /transactions/{id} (private key)
//
// Every refund this connector creates is void-routed, so RSync always reads
// back the ORIGINAL transaction rather than a (nonexistent) Wompi refund
// object; `strip_void_refund_id` recovers that transaction id from the
// `void_`-prefixed `connector_refund_id` refund Execute minted.
// ============================================================================

impl ConnectorIntegration<RSync, RefundsData, RefundsResponseData> for Wompi {
    fn get_headers(
        &self,
        req: &RefundSyncRouterData,
        _connectors: &Connectors,
    ) -> CustomResult<Vec<(String, masking::Maskable<String>)>, errors::ConnectorError> {
        let auth = wompi::WompiAuthType::try_from(&req.connector_auth_type)?;
        Ok(self.private_key_headers(&auth))
    }

    fn get_content_type(&self) -> &'static str {
        self.common_get_content_type()
    }

    fn get_url(
        &self,
        req: &RefundSyncRouterData,
        connectors: &Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        let auth = wompi::WompiAuthType::try_from(&req.connector_auth_type)?;
        let base_url = get_wompi_base_url(&auth, connectors)?;
        let connector_refund_id = req.request.get_connector_refund_id()?;
        let transaction_id = wompi::strip_void_refund_id(&connector_refund_id)
            .unwrap_or(connector_refund_id.as_str());
        Ok(format!("{base_url}/transactions/{transaction_id}"))
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
        let response: wompi::WompiTransactionResponse = res
            .response
            .parse_struct("WompiTransactionResponse")
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
// Incoming webhooks — transaction.updated
// ============================================================================

#[async_trait::async_trait]
impl IncomingWebhook for Wompi {
    fn get_webhook_source_verification_algorithm(
        &self,
        _request: &IncomingWebhookRequestDetails<'_>,
    ) -> CustomResult<Box<dyn crypto::VerifySignature + Send>, errors::ConnectorError> {
        Ok(Box::new(crypto::Sha256))
    }

    fn get_webhook_source_verification_signature(
        &self,
        request: &IncomingWebhookRequestDetails<'_>,
        _connector_webhook_secrets: &api_models::webhooks::ConnectorWebhookSecrets,
    ) -> CustomResult<Vec<u8>, errors::ConnectorError> {
        // `signature.checksum` arrives in the body AND (redundantly) in the
        // `X-Event-Checksum` header per Wompi's docs; read leniently from either so a
        // future payload variation that drops one still verifies against the other.
        let raw: serde_json::Value = serde_json::from_slice(request.body)
            .change_context(errors::ConnectorError::WebhookSignatureNotFound)?;
        let checksum = raw
            .get("signature")
            .and_then(|signature| signature.get("checksum"))
            .and_then(|checksum| checksum.as_str())
            .map(str::to_string)
            .or_else(|| {
                request
                    .headers
                    .get("X-Event-Checksum")
                    .and_then(|value| value.to_str().ok())
                    .map(str::to_string)
            })
            .ok_or(errors::ConnectorError::WebhookSignatureNotFound)?;
        // `hex::decode` accepts either case, matching Wompi's uppercase-hex example
        // checksum against our lowercase-hex `hex::encode` digest.
        hex::decode(checksum).change_context(errors::ConnectorError::WebhookSignatureNotFound)
    }

    fn get_webhook_source_verification_message(
        &self,
        request: &IncomingWebhookRequestDetails<'_>,
        _merchant_id: &common_utils::id_type::MerchantId,
        connector_webhook_secrets: &api_models::webhooks::ConnectorWebhookSecrets,
    ) -> CustomResult<Vec<u8>, errors::ConnectorError> {
        let webhook_body: wompi::WompiWebhookBody =
            request
                .body
                .parse_struct("WompiWebhookBody")
                .change_context(errors::ConnectorError::WebhookSignatureNotFound)?;
        Ok(wompi::build_webhook_message(
            &webhook_body,
            &connector_webhook_secrets.secret,
        ))
    }

    fn get_webhook_object_reference_id(
        &self,
        request: &IncomingWebhookRequestDetails<'_>,
    ) -> CustomResult<api_models::webhooks::ObjectReferenceId, errors::ConnectorError> {
        let webhook_body: wompi::WompiWebhookBody =
            request
                .body
                .parse_struct("WompiWebhookBody")
                .change_context(errors::ConnectorError::WebhookReferenceIdNotFound)?;
        let payment_id_type = match wompi::webhook_payment_reference(&webhook_body)? {
            // `connector_request_reference_id` defaults to the payment ATTEMPT id
            // (`generate_connector_request_reference_id`, v1, config disabled by
            // default), which is exactly what we sent Wompi as `reference` — but this
            // is only trustworthy when `signature.properties` itself lists
            // `transaction.reference`, since that is what makes it SIGNED data.
            wompi::WompiWebhookReference::AttemptReference(reference) => {
                api_models::payments::PaymentIdType::PaymentAttemptId(reference)
            }
            // `transaction.reference` is not signed in this payload but `transaction.id`
            // is, so look the attempt up by Wompi's own id rather than trust an
            // editable field (see `webhook_payment_reference`).
            wompi::WompiWebhookReference::ConnectorTransactionId(id) => {
                api_models::payments::PaymentIdType::ConnectorTransactionId(id)
            }
        };
        Ok(api_models::webhooks::ObjectReferenceId::PaymentId(
            payment_id_type,
        ))
    }

    fn get_webhook_event_type(
        &self,
        request: &IncomingWebhookRequestDetails<'_>,
    ) -> CustomResult<IncomingWebhookEvent, errors::ConnectorError> {
        let webhook_body: wompi::WompiWebhookBody =
            request
                .body
                .parse_struct("WompiWebhookBody")
                .change_context(errors::ConnectorError::WebhookEventTypeNotFound)?;
        wompi::map_webhook_event(&webhook_body)
    }

    fn get_webhook_resource_object(
        &self,
        request: &IncomingWebhookRequestDetails<'_>,
    ) -> CustomResult<Box<dyn masking::ErasedMaskSerialize>, errors::ConnectorError> {
        let webhook_body: wompi::WompiWebhookBody =
            request
                .body
                .parse_struct("WompiWebhookBody")
                .change_context(errors::ConnectorError::WebhookResourceObjectNotFound)?;
        // Wrapped as `{"data": transaction}` so the same PSync response parser
        // (`WompiTransactionResponse`) can be reused to turn this into a payments
        // response object.
        let transaction = webhook_body
            .data
            .get("transaction")
            .cloned()
            .ok_or(errors::ConnectorError::WebhookResourceObjectNotFound)?;
        Ok(Box::new(serde_json::json!({ "data": transaction })))
    }
}

// ============================================================================
// Connector Specifications
// ============================================================================

static WOMPI_SUPPORTED_PAYMENT_METHODS: LazyLock<SupportedPaymentMethods> = LazyLock::new(|| {
    let mut supported_payment_methods = SupportedPaymentMethods::new();

    // Wompi is auto-capture only here (no Capture flow is implemented). Refunds
    // (Execute + RSync) are wired for every payment method below.
    let supported_capture_methods = vec![
        enums::CaptureMethod::Automatic,
        enums::CaptureMethod::SequentialAutomatic,
    ];

    // Card networks Wompi's own docs list as supported (§7.1): Visa, Mastercard and
    // American Express (all require CVC). DinersClub is added per the connector contract;
    // Wompi's docs do not explicitly confirm it, but the enum allows it and the router
    // does not distinguish "unlisted" from "unsupported" for card networks it forwards.
    let supported_card_networks = vec![
        enums::CardNetwork::Visa,
        enums::CardNetwork::Mastercard,
        enums::CardNetwork::AmericanExpress,
        enums::CardNetwork::DinersClub,
    ];
    let card_specific_features = Some(
        api_models::feature_matrix::PaymentMethodSpecificFeatures::Card(
            api_models::feature_matrix::CardSpecificFeatures {
                // Direct card 3DS v2 (doc §11): deferred one-shot `POST /transactions`,
                // implemented via the CompleteAuthorize flow (see wompi/transformers.rs).
                three_ds: enums::FeatureStatus::Supported,
                no_three_ds: enums::FeatureStatus::Supported,
                supported_card_networks,
            },
        ),
    );

    supported_payment_methods.add(
        enums::PaymentMethod::Card,
        enums::PaymentMethodType::Credit,
        PaymentMethodDetails {
            mandates: enums::FeatureStatus::NotSupported,
            refunds: enums::FeatureStatus::Supported,
            supported_capture_methods: supported_capture_methods.clone(),
            specific_features: card_specific_features.clone(),
        },
    );

    supported_payment_methods.add(
        enums::PaymentMethod::Card,
        enums::PaymentMethodType::Debit,
        PaymentMethodDetails {
            mandates: enums::FeatureStatus::NotSupported,
            refunds: enums::FeatureStatus::Supported,
            supported_capture_methods: supported_capture_methods.clone(),
            specific_features: card_specific_features,
        },
    );

    // Hosted checkout (redirect). Without this entry the router rejects a wallet
    // payment before it ever reaches the connector
    // (`validate_connector_against_payment_request`).
    supported_payment_methods.add(
        enums::PaymentMethod::Wallet,
        enums::PaymentMethodType::Wompi,
        PaymentMethodDetails {
            mandates: enums::FeatureStatus::NotSupported,
            refunds: enums::FeatureStatus::Supported,
            supported_capture_methods,
            specific_features: None,
        },
    );

    supported_payment_methods
});

static WOMPI_CONNECTOR_INFO: ConnectorInfo = ConnectorInfo {
    display_name: "Wompi",
    description: "Wompi Colombia (Bancolombia) payment gateway: direct card payments and a hosted checkout covering PSE, Nequi, Bot\u{f3}n Bancolombia, Bancolombia QR, cash correspondents and cards.",
    connector_type: enums::HyperswitchConnectorCategory::PaymentGateway,
    integration_status: enums::ConnectorIntegrationStatus::Sandbox,
};

static WOMPI_SUPPORTED_WEBHOOK_FLOWS: [enums::EventClass; 1] = [enums::EventClass::Payments];

impl ConnectorSpecifications for Wompi {
    fn get_connector_about(&self) -> Option<&'static ConnectorInfo> {
        Some(&WOMPI_CONNECTOR_INFO)
    }

    fn get_supported_payment_methods(&self) -> Option<&'static SupportedPaymentMethods> {
        Some(&*WOMPI_SUPPORTED_PAYMENT_METHODS)
    }

    fn get_supported_webhook_flows(&self) -> Option<&'static [enums::EventClass]> {
        Some(&WOMPI_SUPPORTED_WEBHOOK_FLOWS)
    }
}
