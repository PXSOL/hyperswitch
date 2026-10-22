//! Lógica de evaluación de reglas para el monitoreo de payment_attempt.
//! Replica la categorización de errores del workflow n8n.
//! Incluye patrones por proveedor: Stripe, PayPal, MercadoPago, Payway.

use api_models::diagnostic::{
    AlertRule, ErrorCategoryCounts, FailureDetail, HealthStatus, PaymentAttemptHealthResponse,
    PaymentAttemptMetrics, TimeWindow,
};
use hyperswitch_masking::PeekInterface;
use router_env::logger;

use crate::db::diagnostic::FailureAttemptData;

/// Largest `window_minutes` the diagnostic endpoint accepts (7 days).
pub const MAX_WINDOW_MINUTES: u32 = 7 * 24 * 60;

/// Constant-time check of the presented `x-diagnostic-key` against the
/// configured one. An unset or empty configured key never matches, so the
/// endpoint stays disabled until a key is provisioned. Both values go through
/// a fixed-length MAC first, so the comparison does not leak the key length.
pub fn diagnostic_key_matches(
    configured: Option<&hyperswitch_masking::Secret<String>>,
    presented: Option<&str>,
) -> bool {
    let (Some(configured), Some(presented)) = (configured, presented) else {
        return false;
    };
    let configured = configured.peek().as_bytes();
    if configured.is_empty() {
        return false;
    }
    // MAC the same message under both keys and let `hmac::verify` do the
    // constant-time tag comparison.
    const PROBE: &[u8] = b"diagnostic-key-check";
    let configured_key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, configured);
    let presented_key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, presented.as_bytes());
    let presented_tag = ring::hmac::sign(&presented_key, PROBE);
    ring::hmac::verify(&configured_key, PROBE, presented_tag.as_ref()).is_ok()
}

/// Rejects windows larger than [`MAX_WINDOW_MINUTES`].
pub fn validate_window_minutes(window_minutes: u32) -> Result<(), String> {
    if window_minutes > MAX_WINDOW_MINUTES {
        return Err(format!(
            "window_minutes must not exceed {MAX_WINDOW_MINUTES} (7 days)"
        ));
    }
    Ok(())
}

/// Errores de usuario/negocio (ruido, no requieren acción) - comunes a todos
const USER_ERROR_PATTERNS: &[&str] = &[
    "denegada",
    "invalid_card",
    "insufficient_funds",
    "declined",
    "expired",
    "fondos insuficientes",
    "51",
    "5",
    "payee_not_enabled_for_card_processing",
    // Stripe/PayPal issuer_error_message
    "incorrect_number",
    "generic_decline",
    "live_mode_test_card",
    // MercadoPago issuer_error_code
    "cc_rejected_insufficient_amount",
    "cc_rejected_call_for_authorize",
    "cc_rejected_bad_filled_security_code",
    "cc_rejected_high_risk",
    "cc_rejected_bad_filled_card_number",
    "cc_rejected_bad_filled_date",
    "cc_rejected_bad_filled_other",
    "cc_rejected_blacklist",
    "cc_rejected_card_disabled",
    "cc_rejected_duplicated_payment",
    "cc_rejected_max_attempts",
    "cc_rejected_card_error",
    "cc_rejected_other_reason",
    // MercadoPago API Code 2131 (payment methods inference)
    "code 2131",
    "payment methods inference error",
    "cannot infer payment method",
    // Payway error_message
    "invalid_request_error",
    "payment_declined",
];

/// Errores de sistema/configuración (requieren acción)
const SYSTEM_ERROR_PATTERNS: &[&str] = &[
    // Stripe error_code
    "amount_too_small",
    // Stripe error_message
    "invalid api key",
    "invalid api key provided",
    // MercadoPago bad_request (error_code + error_message)
    "code 2034",
    "invalid users involved",
    "code 3003",
    "invalid card_token_id",
    "code 2006",
    "code 3008",
    "card token not found",
    "not found cardtoken",
    "code 2062",
    "invalid card token",
    "invalid card_token_id",
    // MercadoPago UNKNOWN_ERROR
    "invalid access token",
    // Genéricos
    "unauthorized",
    "not authorized",
    "connector_error",
    "processing_error",
    "timeout",
    "500",
    "connector_config_error",
    // Payway issuer_error_code 96 (error procesador de pagos)
    "96",
];

/// Umbral de ratio de fallos para warning (ej: 0.3 = 30%)
const FAILURE_RATIO_WARNING_THRESHOLD: f64 = 0.3;

/// Minutos por defecto para considerar "sin actividad esperada"
const EXPECTED_TRAFFIC_WINDOW_MINUTES: i64 = 60;

pub fn evaluate_payment_attempt_health(
    attempts: Vec<FailureAttemptData>,
    total_successes: u64,
    window_minutes: u32,
    from_time: time::PrimitiveDateTime,
    to_time: time::PrimitiveDateTime,
) -> PaymentAttemptHealthResponse {
    let total = u32::try_from(attempts.len()).unwrap_or(u32::MAX);

    let failures: Vec<FailureDetail> = attempts
        .iter()
        .map(|a| FailureDetail {
            payment_id: a.payment_id.clone(),
            provider: a.connector.clone(),
            error_message: a.error_message.clone(),
            issuer_error_message: a.issuer_error_message.clone(),
            error_code: a.error_code.clone(),
            error_reason: a.error_reason.clone(),
            unified_code: a.unified_code.clone(),
            issuer_error_code: a.issuer_error_code.clone(),
            amount: a.amount,
            currency: a.currency.clone(),
        })
        .collect();

    let mut user_errors = 0u32;
    let mut system_errors = 0u32;
    let mut unknown_errors = 0u32;
    let mut with_error_details = 0u32;

    for a in &attempts {
        if a.error_code.is_some() || a.error_message.is_some() || a.issuer_error_message.is_some() {
            with_error_details += 1;
        }

        let (reason_context, technical_context) = build_context(a);
        let category = categorize_error(&reason_context, &technical_context);

        match category {
            ErrorCategory::User => user_errors += 1,
            ErrorCategory::System => system_errors += 1,
            ErrorCategory::Unknown => unknown_errors += 1,
        }
    }

    let health_score_pct = user_errors
        .saturating_mul(100)
        .checked_div(total)
        .map_or_else(|| "100%".to_string(), |pct| format!("{pct}%"));

    let metrics = PaymentAttemptMetrics {
        total_successes,
        total_failures: total,
        by_category: ErrorCategoryCounts {
            user_errors,
            system_errors,
            unknown_errors,
        },
        with_error_details,
        health_score_pct,
    };

    let mut alerts = Vec::new();

    // Regla: critical si no hay actividad y se esperaba tráfico (simplificado: si window >= 60 min y total == 0)
    if i64::from(window_minutes) >= EXPECTED_TRAFFIC_WINDOW_MINUTES && total == 0 {
        alerts.push(AlertRule {
            rule_id: "no_activity_in_window".to_string(),
            severity: HealthStatus::Critical,
            message: format!(
                "No se detectó actividad de pagos fallidos en la ventana de {} minutos. Se esperaba tráfico.",
                window_minutes
            ),
        });
    }

    // Regla: warning si ratio de errores de sistema/desconocidos supera umbral
    let actionable_ratio = if total > 0 {
        f64::from(system_errors + unknown_errors) / f64::from(total)
    } else {
        0.0
    };
    if total > 0 && actionable_ratio >= FAILURE_RATIO_WARNING_THRESHOLD {
        let failure_ids: Vec<String> = failures.iter().map(|f| f.payment_id.clone()).collect();
        let ids_preview = if failure_ids.len() <= 5 {
            failure_ids.join(", ")
        } else {
            format!(
                "{}... (+{} más)",
                failure_ids.get(..5).unwrap_or(&failure_ids).join(", "),
                failure_ids.len() - 5
            )
        };
        alerts.push(AlertRule {
            rule_id: "high_actionable_failure_ratio".to_string(),
            severity: HealthStatus::Warning,
            message: format!(
                "Ratio de errores que requieren acción (sistema/desconocidos) es {:.1}% (umbral: {}%). Exitosos: {}, Fallidos: {} (Sistema: {}, Desconocidos: {}). IDs: [{}]",
                actionable_ratio * 100.0,
                FAILURE_RATIO_WARNING_THRESHOLD * 100.0,
                total_successes,
                total,
                system_errors,
                unknown_errors,
                ids_preview
            ),
        });
    }

    let status = if alerts.iter().any(|a| a.severity == HealthStatus::Critical) {
        HealthStatus::Critical
    } else if alerts.iter().any(|a| a.severity == HealthStatus::Warning) {
        HealthStatus::Warning
    } else {
        HealthStatus::Ok
    };

    let window = TimeWindow {
        from: format_primitive_datetime(&from_time),
        to: format_primitive_datetime(&to_time),
    };

    logger::info!(
        status = ?status,
        total = total,
        user_errors = user_errors,
        system_errors = system_errors,
        unknown_errors = unknown_errors,
        "Payment attempt health evaluation completed"
    );

    PaymentAttemptHealthResponse {
        status,
        window,
        metrics,
        failures,
        alerts,
    }
}

fn build_context(a: &FailureAttemptData) -> (String, String) {
    let reason_context = [
        a.error_message.as_deref().unwrap_or(""),
        a.issuer_error_message.as_deref().unwrap_or(""),
        a.error_reason.as_deref().unwrap_or(""),
    ]
    .join(" ")
    .to_lowercase();

    let technical_context = [
        a.unified_code.as_deref().unwrap_or(""),
        a.error_code.as_deref().unwrap_or(""),
        a.issuer_error_code.as_deref().unwrap_or(""),
    ]
    .join(" ")
    .to_lowercase();

    (reason_context, technical_context)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ErrorCategory {
    User,
    System,
    Unknown,
}

fn format_primitive_datetime(dt: &time::PrimitiveDateTime) -> String {
    dt.to_string()
}

fn categorize_error(reason_context: &str, technical_context: &str) -> ErrorCategory {
    let combined = format!("{} {}", reason_context, technical_context);

    // SYSTEM primero: "500", "5" en Payway, etc. para evitar que "5" matchee antes que "500"
    if SYSTEM_ERROR_PATTERNS.iter().any(|p| combined.contains(p)) {
        return ErrorCategory::System;
    }
    if technical_context.contains("ue_9000") {
        return ErrorCategory::System;
    }
    if USER_ERROR_PATTERNS.iter().any(|p| combined.contains(p)) {
        return ErrorCategory::User;
    }
    ErrorCategory::Unknown
}

#[cfg(test)]
mod diagnostic_auth_tests {
    use hyperswitch_masking::Secret;

    use super::*;

    #[test]
    fn key_matches_only_the_configured_key() {
        let configured = Secret::new("s3cret-key".to_string());
        assert!(diagnostic_key_matches(
            Some(&configured),
            Some("s3cret-key")
        ));
        assert!(!diagnostic_key_matches(
            Some(&configured),
            Some("s3cret-kez")
        ));
        assert!(!diagnostic_key_matches(
            Some(&configured),
            Some("s3cret-key ")
        ));
        assert!(!diagnostic_key_matches(Some(&configured), Some("")));
        assert!(!diagnostic_key_matches(Some(&configured), None));
    }

    #[test]
    fn unset_or_empty_configured_key_disables_the_endpoint() {
        let empty = Secret::new(String::new());
        assert!(!diagnostic_key_matches(None, Some("anything")));
        assert!(!diagnostic_key_matches(None, Some("")));
        assert!(!diagnostic_key_matches(Some(&empty), Some("")));
        assert!(!diagnostic_key_matches(Some(&empty), Some("anything")));
    }

    #[test]
    fn window_minutes_is_capped_at_seven_days() {
        assert!(validate_window_minutes(0).is_ok());
        assert!(validate_window_minutes(10).is_ok());
        assert!(validate_window_minutes(MAX_WINDOW_MINUTES).is_ok());
        assert_eq!(MAX_WINDOW_MINUTES, 10080);
        assert!(validate_window_minutes(MAX_WINDOW_MINUTES + 1).is_err());
        assert!(validate_window_minutes(u32::MAX).is_err());
    }
}
