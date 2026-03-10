//! Interface para consultas de diagnóstico de payment_attempt.
//! Usado por el endpoint GET /diagnostic/hyperswitch/payment-attempt/health.

use diesel_models::payment_attempt::PaymentAttempt;
use error_stack::ResultExt;
use router_env::{instrument, logger, tracing};

use super::{MockDb, Store};
use crate::{
    connection,
    core::errors::{self, CustomResult},
};

/// Datos mínimos de un payment attempt para evaluación de reglas
#[derive(Debug, Clone)]
pub struct FailureAttemptData {
    pub payment_id: String,
    pub connector: Option<String>,
    pub error_message: Option<String>,
    pub issuer_error_message: Option<String>,
    pub error_code: Option<String>,
    pub error_reason: Option<String>,
    pub unified_code: Option<String>,
    pub issuer_error_code: Option<String>,
    pub amount: Option<i64>,
    pub currency: Option<String>,
}

impl From<&PaymentAttempt> for FailureAttemptData {
    fn from(pa: &PaymentAttempt) -> Self {
        Self {
            payment_id: pa.payment_id.get_string_repr().to_string(),
            connector: pa.connector.clone(),
            error_message: pa.error_message.clone(),
            issuer_error_message: pa.issuer_error_message.clone(),
            error_code: pa.error_code.clone(),
            error_reason: pa.error_reason.clone(),
            unified_code: pa.unified_code.clone(),
            issuer_error_code: pa.issuer_error_code.clone(),
            amount: Some(pa.amount.get_amount_as_i64()),
            currency: pa.currency.as_ref().map(|c| c.to_string()),
        }
    }
}

#[async_trait::async_trait]
pub trait PaymentAttemptDiagnosticInterface {
    async fn get_failed_attempts_in_window(
        &self,
        window_minutes: i64,
        merchant_id: Option<&str>,
        profile_id: Option<&str>,
    ) -> CustomResult<Vec<FailureAttemptData>, errors::StorageError>;

    async fn count_successes_in_window(
        &self,
        window_minutes: i64,
        merchant_id: Option<&str>,
        profile_id: Option<&str>,
    ) -> CustomResult<i64, errors::StorageError>;
}

#[async_trait::async_trait]
impl PaymentAttemptDiagnosticInterface for Store {
    #[instrument(skip_all)]
    async fn get_failed_attempts_in_window(
        &self,
        window_minutes: i64,
        merchant_id: Option<&str>,
        profile_id: Option<&str>,
    ) -> CustomResult<Vec<FailureAttemptData>, errors::StorageError> {
        let conn = connection::pg_connection_read(self)
            .await
            .change_context(errors::StorageError::DatabaseConnectionError)?;

        let attempts = PaymentAttempt::find_failures_in_window(
            &conn,
            window_minutes,
            merchant_id,
            profile_id,
        )
        .await
        .change_context(errors::StorageError::DatabaseConnectionError)?;

        let data: Vec<FailureAttemptData> = attempts.iter().map(FailureAttemptData::from).collect();
        logger::debug!(count = data.len(), "Retrieved failed payment attempts for diagnostic");
        Ok(data)
    }

    #[instrument(skip_all)]
    async fn count_successes_in_window(
        &self,
        window_minutes: i64,
        merchant_id: Option<&str>,
        profile_id: Option<&str>,
    ) -> CustomResult<i64, errors::StorageError> {
        let conn = connection::pg_connection_read(self)
            .await
            .change_context(errors::StorageError::DatabaseConnectionError)?;

        PaymentAttempt::count_successes_in_window(&conn, window_minutes, merchant_id, profile_id)
            .await
            .change_context(errors::StorageError::DatabaseConnectionError)
    }
}

#[async_trait::async_trait]
impl PaymentAttemptDiagnosticInterface for MockDb {
    async fn get_failed_attempts_in_window(
        &self,
        _window_minutes: i64,
        _merchant_id: Option<&str>,
        _profile_id: Option<&str>,
    ) -> CustomResult<Vec<FailureAttemptData>, errors::StorageError> {
        Ok(vec![])
    }

    async fn count_successes_in_window(
        &self,
        _window_minutes: i64,
        _merchant_id: Option<&str>,
        _profile_id: Option<&str>,
    ) -> CustomResult<i64, errors::StorageError> {
        Ok(0)
    }
}
