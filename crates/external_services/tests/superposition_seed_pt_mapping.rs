//! Regression test for the payment sync (psync) process tracker mapping in
//! `config/superposition_seed.toml`.
//!
//! The client is built like in production: the HTTP source is unreachable, so the
//! seed file is used as the fallback data source.
#![cfg(feature = "superposition")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use external_services::superposition::{
    ConfigContext, SuperpositionClient, SuperpositionClientConfig,
};
use hyperswitch_masking::Secret;
use serde_json::{json, Value};

const KEY: &str = "process_tracker.pt_mapping_payment_sync";
const REFUND_KEY: &str = "process_tracker.pt_mapping_refund_sync";

// OpenFeature keeps a global provider, so both lookups share one client in one test.
#[tokio::test]
async fn connector_overrides_apply_and_other_connectors_keep_default() {
    let config = SuperpositionClientConfig {
        endpoint: "http://127.0.0.1:9".to_string(),
        token: Secret::new("unused".to_string()),
        org_id: "pxsol".to_string(),
        workspace_id: "default".to_string(),
        polling_interval: 3600,
        request_timeout: Some(2),
        backup_file_path: Some(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../config/superposition_seed.toml"),
        ),
    };
    let client = SuperpositionClient::new(config, "test")
        .await
        .expect("client should fall back to the seed file");

    let ctx = |connector: &str| {
        ConfigContext::new()
            .with("processor_merchant_id", "PXSOL_7472")
            .with("connector", connector)
    };

    let paypal: Value = client
        .get_config_value(KEY, Some(&ctx("paypal")), None)
        .await
        .expect("paypal psync mapping");
    assert_eq!(
        paypal,
        json!({
            "default_mapping": {
                "start_after": 180,
                "frequencies": [[180, 9], [300, 12], [3600, 23], [86400, 29]]
            },
            "max_retries_count": 73
        })
    );

    let stripe: Value = client
        .get_config_value(KEY, Some(&ctx("stripe")), None)
        .await
        .expect("stripe psync mapping");
    assert_eq!(
        stripe,
        json!({
            "default_mapping": { "start_after": 60, "frequencies": [[300, 5]] },
            "max_retries_count": 5
        })
    );

    // Izipay bans clients that query too often: the IPN is the primary sync.
    let izipay_psync: Value = client
        .get_config_value(KEY, Some(&ctx("izipay")), None)
        .await
        .expect("izipay psync mapping");
    assert_eq!(
        izipay_psync,
        json!({
            "default_mapping": { "start_after": 1200, "frequencies": [[2400, 1]] },
            "max_retries_count": 1
        })
    );

    let izipay_refund: Value = client
        .get_config_value(REFUND_KEY, Some(&ctx("izipay")), None)
        .await
        .expect("izipay refund sync mapping");
    assert_eq!(
        izipay_refund,
        json!({
            "default_mapping": { "start_after": 21600, "frequencies": [[64800, 1]] },
            "max_retries_count": 1
        })
    );

    // The other connectors keep the global refund mapping and the Izipay one does not leak.
    let stripe_refund: Value = client
        .get_config_value(REFUND_KEY, Some(&ctx("stripe")), None)
        .await
        .expect("stripe refund sync mapping");
    assert_ne!(stripe_refund, izipay_refund);
    let paypal_refund: Value = client
        .get_config_value(REFUND_KEY, Some(&ctx("paypal")), None)
        .await
        .expect("paypal refund sync mapping");
    assert_eq!(paypal_refund, stripe_refund);
}
