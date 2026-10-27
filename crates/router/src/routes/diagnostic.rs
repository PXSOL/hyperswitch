//! Endpoint de diagnóstico para monitoreo de payment_attempt (Hyperswitch).
//! GET /diagnostic/hyperswitch/payment-attempt/health

use actix_web::{web, HttpRequest};
use api_models::diagnostic::{PaymentAttemptHealthQuery, PaymentAttemptHealthResponse};
use async_trait::async_trait;
use common_utils::date_time;
use error_stack::report;
use router_env::{instrument, logger, tracing, Flow};

use super::app;
use crate::{
    core::{api_locking, diagnostic},
    errors::{self, RouterResponse},
    routes::metrics,
    services::{
        api,
        authentication::{AuthenticateAndFetch, AuthenticationType},
    },
};

const DIAGNOSTIC_KEY_HEADER: &str = "x-diagnostic-key";

/// Guards the diagnostic endpoints with the `x-diagnostic-key` header, checked
/// against `diagnostic.api_key`. The endpoints are disabled while no key is
/// configured.
struct DiagnosticKeyAuth;

#[async_trait]
impl AuthenticateAndFetch<(), app::SessionState> for DiagnosticKeyAuth {
    async fn authenticate_and_fetch(
        &self,
        request_headers: &actix_web::http::header::HeaderMap,
        state: &app::SessionState,
    ) -> errors::RouterResult<((), AuthenticationType)> {
        let presented = request_headers
            .get(DIAGNOSTIC_KEY_HEADER)
            .and_then(|value| value.to_str().ok());
        if diagnostic::diagnostic_key_matches(state.conf.diagnostic.api_key.as_ref(), presented) {
            Ok(((), AuthenticationType::NoAuth))
        } else {
            Err(report!(errors::ApiErrorResponse::Unauthorized))
        }
    }
}

#[instrument(skip_all, fields(flow = ?Flow::HealthCheck))]
pub async fn payment_attempt_health(
    state: web::Data<app::AppState>,
    request: HttpRequest,
    query: web::Query<PaymentAttemptHealthQuery>,
) -> impl actix_web::Responder {
    metrics::HEALTH_METRIC.add(1, &[]);

    let flow = Flow::HealthCheck;

    Box::pin(api::server_wrap(
        flow,
        state,
        &request,
        query.into_inner(),
        |state, _: (), query_params, _| payment_attempt_health_func(state, query_params),
        &DiagnosticKeyAuth,
        api_locking::LockAction::NotApplicable,
    ))
    .await
}

async fn payment_attempt_health_func(
    state: app::SessionState,
    query: PaymentAttemptHealthQuery,
) -> RouterResponse<PaymentAttemptHealthResponse> {
    diagnostic::validate_window_minutes(query.window_minutes)
        .map_err(|message| errors::ApiErrorResponse::InvalidRequestData { message })?;

    logger::info!(
        window_minutes = query.window_minutes,
        merchant_id = ?query.merchant_id,
        profile_id = ?query.profile_id,
        "Payment attempt health diagnostic called"
    );

    let window_minutes = i64::from(query.window_minutes);
    let now = date_time::now();
    let from_time = now.saturating_sub(time::Duration::minutes(window_minutes));

    let (attempts, total_successes) = tokio::try_join!(
        state.store.get_failed_attempts_in_window(
            window_minutes,
            query.merchant_id.as_deref(),
            query.profile_id.as_deref(),
        ),
        state.store.count_successes_in_window(
            window_minutes,
            query.merchant_id.as_deref(),
            query.profile_id.as_deref(),
        ),
    )
    .map_err(|error| {
        let message = error.to_string();
        logger::error!(error = %message, "Database error in payment attempt health diagnostic");
        error.change_context(errors::ApiErrorResponse::InternalServerError)
    })?;

    let response = diagnostic::evaluate_payment_attempt_health(
        attempts,
        u64::try_from(total_successes).unwrap_or(0),
        query.window_minutes,
        from_time,
        now,
    );

    Ok(api::ApplicationResponse::Json(response))
}
