//! Endpoint de diagnóstico para monitoreo de payment_attempt (Hyperswitch).
//! GET /diagnostic/hyperswitch/payment-attempt/health

use actix_web::{web, HttpRequest};
use api_models::diagnostic::{PaymentAttemptHealthQuery, PaymentAttemptHealthResponse};
use common_utils::date_time;
use router_env::{instrument, logger, tracing, Flow};

use super::app;
use crate::{
    core::{api_locking, diagnostic},
    errors::{self, RouterResponse},
    routes::metrics,
    services::{api, authentication as auth},
};

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
        &auth::NoAuth,
        api_locking::LockAction::NotApplicable,
    ))
    .await
}

async fn payment_attempt_health_func(
    state: app::SessionState,
    query: PaymentAttemptHealthQuery,
) -> RouterResponse<PaymentAttemptHealthResponse> {
    logger::info!(
        window_minutes = query.window_minutes,
        merchant_id = ?query.merchant_id,
        profile_id = ?query.profile_id,
        "Payment attempt health diagnostic called"
    );

    let window_minutes = query.window_minutes as i64;
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
        total_successes.max(0) as u64,
        query.window_minutes,
        from_time,
        now,
    );

    Ok(api::ApplicationResponse::Json(response))
}
