use common_utils::pii::Email;
use hyperswitch_domain_models::{
    address::{Address, AddressDetails, PhoneDetails},
    payment_address::PaymentAddress,
    payment_method_data::{PaymentMethodData, WalletData},
    router_response_types::RedirectForm,
};
use masking::Secret;
use router::types::{self, api, storage::enums};
use std::str::FromStr;
use test_utils::connector_auth;

use crate::utils::{self, ConnectorActions};

#[derive(Clone, Copy)]
struct IzipayTest;
impl ConnectorActions for IzipayTest {}
impl utils::Connector for IzipayTest {
    fn get_data(&self) -> api::ConnectorData {
        use router::connector::Izipay;
        utils::construct_connector_data_old(
            Box::new(Izipay::new()),
            types::Connector::Izipay,
            api::GetToken::Connector,
            None,
        )
    }

    fn get_auth_token(&self) -> types::ConnectorAuthType {
        utils::to_connector_auth_type(
            connector_auth::ConnectorAuthentication::new()
                .izipay
                .expect("Missing connector authentication configuration")
                .into(),
        )
    }

    fn get_name(&self) -> String {
        "izipay".to_string()
    }
}

static CONNECTOR: IzipayTest = IzipayTest {};

fn get_default_payment_info() -> Option<utils::PaymentInfo> {
    Some(utils::PaymentInfo {
        address: Some(PaymentAddress::new(
            None,
            Some(Address {
                address: Some(AddressDetails {
                    first_name: Some(Secret::new("Lucho".to_string())),
                    last_name: Some(Secret::new("Torres".to_string())),
                    line1: Some(Secret::new("Av. Jorge Chavez 275".to_string())),
                    city: Some("Lima".to_string()),
                    state: Some(Secret::new("Lima".to_string())),
                    zip: Some(Secret::new("15074".to_string())),
                    country: Some(enums::CountryAlpha2::PE),
                    ..Default::default()
                }),
                phone: Some(PhoneDetails {
                    number: Some(Secret::new("989897960".to_string())),
                    country_code: Some("+51".to_string()),
                }),
                email: Email::from_str("buyer@example.com").ok(),
            }),
            None,
            None,
        )),
        ..Default::default()
    })
}

// Authorize only generates a session token (Token/Generate) and builds the page that opens the
// hosted checkout, so this harness (which calls Authorize directly, without the router's
// access token step) can run it against the sandbox.
#[actix_web::test]
#[ignore = "needs Izipay sandbox keys in sample_auth.toml"]
async fn should_authorize_hosted_checkout_payment() {
    let authorize_response = CONNECTOR
        .make_payment(
            Some(types::PaymentsAuthorizeData {
                payment_method_data: PaymentMethodData::Wallet(WalletData::IzipayCheckout {}),
                currency: enums::Currency::PEN,
                amount: 199,
                minor_amount: types::MinorUnit::new(199),
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
            Some(RedirectForm::Html { html_data }) => {
                assert!(html_data.contains("sandbox-checkout.izipay.pe"));
            }
            other => panic!("expected a RedirectForm::Html, got {other:?}"),
        },
        other => panic!("expected a TransactionResponse, got {other:?}"),
    }
}

// Izipay is auto-capture only (hosted checkout) and its status, refund and notification flows
// need the router's access token step, so the manual-capture/void/sync template tests of
// connector-template/test.rs are intentionally omitted here.
