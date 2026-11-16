//! TEMPORARY: remove after the processor account identity backfill (odd/tasks/processor-account-identity.md)

use actix_web::{web, HttpRequest, HttpResponse};
use router_env::{instrument, tracing, Flow};

use super::app::AppState;
use crate::{
    core::api_locking,
    services::{api, authentication as auth},
};

/// Processor account identity of a connector account
///
/// Returns the display name of the processor account the connector account is connected to
/// and, for Mercado Pago, that account's identity fields; never a credential. Admin API key
/// only: it is called by the one-time backfill and then removed.
#[instrument(skip_all, fields(flow = ?Flow::MerchantConnectorAccountIdentity))]
pub async fn connector_account_identity(
    state: web::Data<AppState>,
    req: HttpRequest,
    path: web::Path<(
        common_utils::id_type::MerchantId,
        common_utils::id_type::MerchantConnectorAccountId,
    )>,
) -> HttpResponse {
    let flow = Flow::MerchantConnectorAccountIdentity;
    let (merchant_id, merchant_connector_id) = path.into_inner();

    Box::pin(api::server_wrap(
        flow,
        state,
        &req,
        (),
        |state, _, _, _| {
            crate::core::connector_account_identity::retrieve_connector_account_identity(
                state,
                &merchant_id,
                &merchant_connector_id,
            )
        },
        &auth::AdminApiAuth,
        api_locking::LockAction::NotApplicable,
    ))
    .await
}
