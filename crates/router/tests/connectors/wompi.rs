use hyperswitch_domain_models::{
    payment_method_data::{PaymentMethodData, WalletData},
    router_response_types::RedirectForm,
};
use router::types::{self, api, storage::enums};
use test_utils::connector_auth;

use crate::utils::{self, ConnectorActions};

#[derive(Clone, Copy)]
struct WompiTest;
impl ConnectorActions for WompiTest {}
impl utils::Connector for WompiTest {
    fn get_data(&self) -> api::ConnectorData {
        use router::connector::Wompi;
        utils::construct_connector_data_old(
            Box::new(Wompi::new()),
            types::Connector::Wompi,
            api::GetToken::Connector,
            None,
        )
    }

    fn get_auth_token(&self) -> types::ConnectorAuthType {
        utils::to_connector_auth_type(
            connector_auth::ConnectorAuthentication::new()
                .wompi
                .expect("Missing connector authentication configuration")
                .into(),
        )
    }

    fn get_name(&self) -> String {
        "wompi".to_string()
    }
}

static CONNECTOR: WompiTest = WompiTest {};

fn get_default_payment_info() -> Option<utils::PaymentInfo> {
    None
}

// Card flows (Authorize/PSync) go through the router's own access-token fetch and
// connector-tokenization step before ever reaching this connector, and every Wompi
// transaction starts PENDING regardless of card validity anyway — none of which this
// harness (which calls Authorize directly, skipping both prerequisites) can
// reproduce. Card behavior is exercised end to end through the full router instead;
// here we only drive what this harness genuinely can run standalone.

// Hosted checkout Authorize is a self-contained GET /merchants/{public_key} lookup:
// it needs neither an access token nor a payment method token, so this harness can
// call it directly and get a real response back from Wompi.
#[actix_web::test]
#[ignore = "needs Wompi sandbox keys in sample_auth.toml"]
async fn should_authorize_hosted_checkout_payment() {
    let authorize_response = CONNECTOR
        .make_payment(
            Some(types::PaymentsAuthorizeData {
                payment_method_data: PaymentMethodData::Wallet(WalletData::WompiCheckout {}),
                currency: enums::Currency::COP,
                amount: 150000,
                minor_amount: types::MinorUnit::new(150000),
                router_return_url: Some("https://hyperswitch.io/return".to_string()),
                ..utils::PaymentAuthorizeType::default().0
            }),
            get_default_payment_info(),
        )
        .await
        .unwrap();

    assert_eq!(
        authorize_response.status,
        enums::AttemptStatus::AuthenticationPending
    );

    match authorize_response
        .response
        .expect("hosted checkout must return a TransactionResponse")
    {
        types::PaymentsResponseData::TransactionResponse {
            redirection_data, ..
        } => match *redirection_data {
            Some(RedirectForm::Form { endpoint, .. }) => {
                assert_eq!(endpoint, "https://checkout.wompi.co/p/");
            }
            other => panic!("expected a RedirectForm::Form, got {other:?}"),
        },
        other => panic!("expected a TransactionResponse, got {other:?}"),
    }
}

// PSync-by-id only needs the public key (no access token/pm token prerequisite), so
// this harness can also drive it directly: a bogus connector transaction id must
// fail the sync.
// Captures a payment using invalid connector payment id (PSync on a
// non-existent transaction id should fail).
#[actix_web::test]
async fn should_fail_sync_for_invalid_payment() {
    let response = CONNECTOR
        .sync_payment(
            Some(types::PaymentsSyncData {
                connector_transaction_id: types::ResponseId::ConnectorTransactionId(
                    "123456789".to_string(),
                ),
                ..Default::default()
            }),
            get_default_payment_info(),
        )
        .await
        .unwrap();
    assert!(response.response.is_err());
}

// Connector dependent test cases goes here
//
// Wompi is auto-capture only and refunds are not wired yet, so the
// manual-capture/void/refund template tests from connector-template/test.rs are
// intentionally omitted here.
