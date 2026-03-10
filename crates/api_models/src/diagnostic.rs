//! DTOs para el endpoint de monitoreo de payment_attempt (Hyperswitch)
//!
//! Replica la lógica del workflow n8n para pagos fallidos.

use common_utils::events::ApiEventMetric;
use serde::{Deserialize, Serialize};

/// Query params para GET /diagnostic/hyperswitch/payment-attempt/health
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct PaymentAttemptHealthQuery {
    /// Ventana de tiempo en minutos para evaluar (default: 10)
    #[serde(default = "default_window_minutes")]
    pub window_minutes: u32,
    /// Filtrar por merchant_id (opcional)
    pub merchant_id: Option<String>,
    /// Filtrar por profile_id (opcional)
    pub profile_id: Option<String>,
}

fn default_window_minutes() -> u32 {
    10
}

/// Estado operativo del monitoreo
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HealthStatus {
    Ok,
    Warning,
    Critical,
}

/// Rango temporal evaluado
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeWindow {
    pub from: String,
    pub to: String,
}

/// Detalle de un pago fallido para diagnóstico
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FailureDetail {
    /// ID del pago
    pub payment_id: String,
    /// Connector/proveedor (ej: stripe, mercadopago)
    pub provider: Option<String>,
    /// Mensaje de error principal
    pub error_message: Option<String>,
    /// Mensaje de error del emisor
    pub issuer_error_message: Option<String>,
    /// Código de error
    pub error_code: Option<String>,
    /// Razón del error
    pub error_reason: Option<String>,
    /// Código unificado
    pub unified_code: Option<String>,
    /// Código de error del emisor
    pub issuer_error_code: Option<String>,
    /// Monto (en unidades menores)
    pub amount: Option<i64>,
    /// Moneda
    pub currency: Option<String>,
}

/// Métricas de payment attempts en la ventana
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentAttemptMetrics {
    /// Total de pagos exitosos en la ventana (Charged, PartialCharged)
    pub total_successes: u64,
    /// Total de intentos fallidos en la ventana
    pub total_failures: u32,
    /// Distribución por categoría de error
    pub by_category: ErrorCategoryCounts,
    /// Cantidad con error_code o error_message presente
    pub with_error_details: u32,
    /// Health score: % de errores de usuario sobre total (100% = todo ruido de negocio)
    pub health_score_pct: String,
}

/// Conteo por categoría de error (replica lógica n8n)
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ErrorCategoryCounts {
    /// Errores de negocio/usuario (fondos insuficientes, tarjeta inválida, etc.)
    pub user_errors: u32,
    /// Errores de sistema/configuración (requieren acción)
    pub system_errors: u32,
    /// Errores desconocidos (investigar)
    pub unknown_errors: u32,
}

/// Regla de alerta incumplida
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertRule {
    pub rule_id: String,
    pub severity: HealthStatus,
    pub message: String,
}

/// Respuesta del endpoint de health de payment attempts
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentAttemptHealthResponse {
    pub status: HealthStatus,
    pub window: TimeWindow,
    pub metrics: PaymentAttemptMetrics,
    /// Detalle de cada pago fallido (payment_id, provider, campos de error)
    pub failures: Vec<FailureDetail>,
    pub alerts: Vec<AlertRule>,
}

impl ApiEventMetric for PaymentAttemptHealthQuery {}
impl ApiEventMetric for PaymentAttemptHealthResponse {}
