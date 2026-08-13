//! SCRATCH / no productivo. Dumpea a disco los payloads que el conector genera para los casos
//! del checklist de homologación, para poder mandarlos al gateway de certificación tal cual
//! salen del conector. Se corre con:
//!
//!   cargo test -p hyperswitch_connectors --lib --features v1 \
//!       fiservemea::cert_payloads -- --nocapture
//!
//! Directorio de salida: $FISERVEMEA_DUMP_DIR (default /tmp/fiservemea_payloads).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::too_many_arguments,
    clippy::indexing_slicing
)]

use std::{collections::HashMap, marker::PhantomData, str::FromStr};

use common_enums::enums;
use common_utils::{request::RequestContent, types::MinorUnit};
use hyperswitch_domain_models::{
    payment_address::PaymentAddress,
    payment_method_data::{Card, PaymentMethodData},
    router_data::{ConnectorAuthType, ErrorResponse, PaymentMethodToken, RouterData},
    router_flow_types::{
        payments::{Authorize, PaymentMethodToken as PmTokenFlow, SetupMandate},
        refunds::Execute,
        CompleteAuthorize, Void,
    },
    router_request_types::{
        CompleteAuthorizeData, CompleteAuthorizeRedirectResponse, PaymentMethodTokenizationData,
        PaymentsAuthorizeData, PaymentsCancelData, RefundsData, SetupMandateRequestData,
    },
    router_response_types::PaymentsResponseData,
};
use hyperswitch_masking::{ExposeInterface, Secret};
use serde_json::json;

use super::transformers as fiservemea;
use crate::connectors::Fiservemea;

// ---------------------------------------------------------------- infra de dump

fn dump_dir() -> std::path::PathBuf {
    let dir = std::env::var("FISERVEMEA_DUMP_DIR")
        .unwrap_or_else(|_| "/tmp/fiservemea_payloads".to_string());
    std::fs::create_dir_all(&dir).unwrap();
    std::path::PathBuf::from(dir)
}

/// Serializa el body tal como lo haría el conector (`RequestContent::Json` ->
/// `get_inner_value`, que es exactamente lo que sale por el cable) y lo escribe.
fn dump(case: &str, method: &str, path: &str, body: RequestContent) {
    assert!(
        matches!(body, RequestContent::Json(_)),
        "fiservemea no debería producir otro RequestContent"
    );
    let raw = body.get_inner_value().expose();
    let json_body: serde_json::Value = serde_json::from_str(&raw).unwrap();
    write_case(case, method, path, Some(json_body));
}

fn write_case(case: &str, method: &str, path: &str, body: Option<serde_json::Value>) {
    let dir = dump_dir();
    let entry = json!({
        "case": case,
        "method": method,
        "path": path,
        "body": body,
    });
    std::fs::write(
        dir.join(format!("{case}.json")),
        serde_json::to_string_pretty(&entry).unwrap(),
    )
    .unwrap();
    println!("[dump] {case} -> {method} {path}");
}

// ---------------------------------------------------------------- constructores

const STORE_AR: &str = "5926072901";
const STORE_TOKEN_GW: &str = "5926072902";

fn auth(store: &str) -> ConnectorAuthType {
    ConnectorAuthType::SignatureKey {
        api_key: Secret::new(std::env::var("AR_KEY").unwrap_or_else(|_| "k".into())),
        key1: Secret::new(store.to_string()),
        api_secret: Secret::new(std::env::var("AR_SECRET").unwrap_or_else(|_| "s".into())),
    }
}

fn card(number: &str) -> Card {
    Card {
        card_number: cards::CardNumber::from_str(number).unwrap(),
        card_exp_month: Secret::new("12".to_string()),
        card_exp_year: Secret::new("2029".to_string()),
        card_cvc: Secret::new("123".to_string()),
        card_issuer: None,
        card_network: None,
        card_type: None,
        card_issuing_country: None,
        bank_code: None,
        nick_name: None,
        card_holder_name: Some(Secret::new("PXSOL TEST".to_string())),
        co_badged_card_data: None,
        card_issuing_country_code: None,
    }
}

fn authorize_data(
    number: &str,
    currency: enums::Currency,
    amount_minor: i64,
    metadata: Option<serde_json::Value>,
    three_ds: bool,
) -> PaymentsAuthorizeData {
    PaymentsAuthorizeData {
        payment_method_data: PaymentMethodData::Card(card(number)),
        amount: amount_minor,
        minor_amount: MinorUnit::new(amount_minor),
        order_tax_amount: None,
        email: None,
        customer_name: None,
        currency,
        confirm: true,
        capture_method: Some(enums::CaptureMethod::Automatic),
        router_return_url: None,
        webhook_url: None,
        complete_authorize_url: three_ds
            .then(|| "https://www.pxsol.com/3ds/return".to_string()),
        setup_future_usage: None,
        mandate_id: None,
        off_session: None,
        customer_acceptance: None,
        setup_mandate_details: None,
        browser_info: None,
        order_details: None,
        order_category: None,
        session_token: None,
        enrolled_for_3ds: three_ds,
        related_transaction_id: None,
        payment_experience: None,
        payment_method_type: None,
        surcharge_details: None,
        customer_id: None,
        request_incremental_authorization: false,
        metadata,
        authentication_data: None,
        request_extended_authorization: None,
        split_payments: None,
        merchant_order_reference_id: None,
        integrity_object: None,
        shipping_cost: None,
        additional_payment_method_data: None,
        merchant_account_id: None,
        merchant_config_currency: None,
        connector_testing_data: None,
        order_id: None,
        locale: None,
        payment_channel: None,
        enable_overcapture: None,
        ucs_authentication_data: None,
        guest_customer: None,
        is_stored_credential: None,
        mit_category: None,
        enable_partial_authorization: None,
        partner_merchant_identifier_details: None,
        billing_descriptor: None,
        tokenization: None,
        feature_metadata: None,
        installment_details: None,
        connector_intent_metadata: None,
    }
}

#[allow(clippy::too_many_arguments)]
fn router_data<Flow, Req, Res>(
    request: Req,
    store: &str,
    order_id: &str,
    three_ds: bool,
    pm_token: Option<String>,
) -> RouterData<Flow, Req, Res> {
    RouterData {
        flow: PhantomData,
        merchant_id: common_utils::id_type::MerchantId::try_from(std::borrow::Cow::from(
            "fiservemea",
        ))
        .unwrap(),
        customer_id: None,
        connector_customer: None,
        connector: "fiservemea".to_string(),
        payment_id: order_id.to_string(),
        attempt_id: order_id.to_string(),
        tenant_id: common_utils::id_type::TenantId::try_from_string("public".to_string()).unwrap(),
        status: enums::AttemptStatus::default(),
        payment_method: enums::PaymentMethod::Card,
        connector_auth_type: auth(store),
        description: None,
        address: PaymentAddress::default(),
        auth_type: if three_ds {
            enums::AuthenticationType::ThreeDs
        } else {
            enums::AuthenticationType::NoThreeDs
        },
        connector_meta_data: None,
        connector_wallets_details: None,
        amount_captured: None,
        access_token: None,
        session_token: None,
        reference_id: None,
        payment_method_token: pm_token.map(|t| PaymentMethodToken::Token(Secret::new(t))),
        recurring_mandate_payment_data: None,
        preprocessing_id: None,
        payment_method_balance: None,
        connector_api_version: None,
        request,
        response: Err(ErrorResponse::default()),
        connector_request_reference_id: order_id.to_string(),
        #[cfg(feature = "payouts")]
        payout_method_data: None,
        #[cfg(feature = "payouts")]
        quote_id: None,
        test_mode: Some(true),
        connector_http_status_code: None,
        external_latency: None,
        apple_pay_flow: None,
        frm_metadata: None,
        dispute_id: None,
        refund_id: None,
        connector_response: None,
        payment_method_status: None,
        minor_amount_captured: None,
        minor_amount_capturable: None,
        integrity_check: Ok(()),
        additional_merchant_data: None,
        header_payload: None,
        connector_mandate_request_reference_id: None,
        l2_l3_data: None,
        authentication_id: None,
        psd2_sca_exemption_type: None,
        raw_connector_response: None,
        is_payment_id_from_merchant: None,
        payment_method_type: None,
        payout_id: None,
        authorized_amount: None,
        customer_document_details: None,
        feature_data: None,
        sender_payment_instrument_id: None,
    }
}

/// `order_id` estable-por-corrida, con el mismo formato que usa el harness.
fn order_id(tag: &str) -> String {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    format!("HS-{ts}-{tag}").chars().take(40).collect()
}

/// Construye y dumpea un Authorize pasando por el mismo camino que el conector real:
/// `convert_amount` -> `FiservemeaRouterData` -> `FiservemeaPaymentsRequest`.
fn dump_authorize(
    case: &str,
    store: &str,
    number: &str,
    currency: enums::Currency,
    amount_minor: i64,
    metadata: Option<serde_json::Value>,
    three_ds: bool,
    pm_token: Option<String>,
) {
    let oid = order_id(case);
    let request = authorize_data(number, currency, amount_minor, metadata, three_ds);
    let rd: RouterData<Authorize, _, _> = router_data(request, store, &oid, three_ds, pm_token);
    let amount = crate::utils::convert_amount(
        Fiservemea::new().amount_converter,
        rd.request.minor_amount,
        rd.request.currency,
    )
    .unwrap();
    let crd = fiservemea::FiservemeaRouterData::from((amount, &rd));
    let req = fiservemea::FiservemeaPaymentsRequest::try_from(&crd).unwrap();
    dump(case, "POST", "/payments", RequestContent::Json(Box::new(req)));
}

// ---------------------------------------------------------------- fase 1

#[test]
fn dump_phase1_payloads() {
    // 1. sale 1 pago (ARS)
    dump_authorize(
        "sale-1pago",
        STORE_AR,
        "5165850000000008",
        enums::Currency::ARS,
        100_000,
        None,
        false,
        None,
    );

    // 2. sale USD
    dump_authorize(
        "sale-usd",
        STORE_AR,
        "5165850000000008",
        enums::Currency::USD,
        100_000,
        None,
        false,
        None,
    );

    // 3. sale en cuotas (6)
    dump_authorize(
        "sale-cuotas6",
        STORE_AR,
        "5165850000000008",
        enums::Currency::ARS,
        100_000,
        Some(json!({ "installments": 6 })),
        false,
        None,
    );

    // 4. dynamic merchant name
    dump_authorize(
        "sale-dmn",
        STORE_AR,
        "5165850000000008",
        enums::Currency::ARS,
        100_000,
        Some(json!({ "dynamic_merchant_name": "PXSOL*Reservas" })),
        false,
        None,
    );

    // 5. zero auth (SetupMandate)
    {
        let oid = order_id("zeroauth");
        let request = SetupMandateRequestData {
            currency: enums::Currency::ARS,
            payment_method_data: PaymentMethodData::Card(card("5165850000000008")),
            amount: 0,
            confirm: true,
            customer_acceptance: None,
            mandate_id: None,
            setup_future_usage: None,
            off_session: None,
            setup_mandate_details: None,
            router_return_url: None,
            webhook_url: None,
            browser_info: None,
            email: None,
            customer_name: None,
            return_url: None,
            payment_method_type: None,
            request_incremental_authorization: false,
            metadata: None,
            complete_authorize_url: None,
            capture_method: None,
            enrolled_for_3ds: false,
            related_transaction_id: None,
            minor_amount: MinorUnit::zero(),
            shipping_cost: None,
            connector_testing_data: None,
            customer_id: None,
            payment_channel: None,
            feature_metadata: None,
            is_stored_credential: None,
            billing_descriptor: None,
            split_payments: None,
            tokenization: None,
            authentication_data: None,
            connector_intent_metadata: None,
            merchant_order_reference_id: None,
            mit_category: None,
            enable_partial_authorization: None,
            partner_merchant_identifier_details: None,
        };
        let rd: RouterData<SetupMandate, _, _> = router_data(request, STORE_AR, &oid, false, None);
        let req = fiservemea::FiservemeaPaymentsRequest::try_from(&rd).unwrap();
        dump(
            "zeroauth",
            "POST",
            "/payments",
            RequestContent::Json(Box::new(req)),
        );
    }

    // 6. create token GW (tienda de tokens)
    {
        let oid = order_id("tokengw-create");
        let request = PaymentMethodTokenizationData {
            payment_method_data: PaymentMethodData::Card(card("5165850000000008")),
            browser_info: None,
            currency: enums::Currency::ARS,
            amount: Some(100_000),
            split_payments: None,
            customer_acceptance: None,
            setup_future_usage: None,
            setup_mandate_details: None,
            mandate_id: None,
            payment_method_type: None,
            router_return_url: None,
            capture_method: None,
        };
        let rd: RouterData<PmTokenFlow, _, _> =
            router_data(request, STORE_TOKEN_GW, &oid, false, None);
        let req = fiservemea::FiservemeaCreateTokenRequest::try_from(&rd).unwrap();
        dump(
            "tokengw-create",
            "POST",
            "/payment-tokens",
            RequestContent::Json(Box::new(req)),
        );
    }

    // 7. 3DS frictionless (Authenticated) — init
    dump_authorize(
        "3ds-fric-y",
        STORE_AR,
        "4147463011110083",
        enums::Currency::ARS,
        100_000,
        None,
        true,
        None,
    );

    // 8. 3DSMethod (Authenticated) — init
    dump_authorize(
        "3ds-mth-y",
        STORE_AR,
        "4099000000001978",
        enums::Currency::ARS,
        100_000,
        None,
        true,
        None,
    );

    // 8b. 3DSMethod (Authenticated) — segunda transacción, para probar la variante en la que el
    // retorno SÍ trae `threeDSMethodData` y el conector emite `RECEIVED`.
    dump_authorize(
        "3ds-mth-y-received",
        STORE_AR,
        "4099000000001978",
        enums::Currency::ARS,
        100_000,
        None,
        true,
        None,
    );

    // 9. Challenge configurable — init
    dump_authorize(
        "3ds-cha-1",
        STORE_AR,
        "4147463011110059",
        enums::Currency::ARS,
        100_000,
        None,
        true,
        None,
    );

    // 10. Challenge+Method configurable — init
    dump_authorize(
        "3ds-chm-1",
        STORE_AR,
        "4265880000000064",
        enums::Currency::ARS,
        100_000,
        None,
        true,
        None,
    );

    // 11. Data Only (Mastercard, messageCategory 80) — init
    dump_authorize(
        "3ds-dataonly",
        STORE_AR,
        "5239290700000028",
        enums::Currency::ARS,
        100_000,
        Some(json!({ "three_ds_data_only": true })),
        true,
        None,
    );
}

/// Segunda fase: paga con el token GW recién creado por la fase 1. El valor lo deja el script
/// de Python en `token_gw.txt`.
#[test]
fn dump_phase2_token_sale() {
    let path = dump_dir().join("token_gw.txt");
    let Ok(token) = std::fs::read_to_string(&path) else {
        println!("[skip] no hay token_gw.txt todavía");
        return;
    };
    let token = token.trim().to_string();
    if token.is_empty() {
        println!("[skip] token_gw.txt vacío");
        return;
    }
    dump_authorize(
        "tokengw-sale-cuotas6",
        STORE_TOKEN_GW,
        "5165850000000008",
        enums::Currency::ARS,
        100_000,
        Some(json!({ "installments": 6 })),
        false,
        Some(token),
    );
}

/// Plantillas de continuación 3DS, generadas por el conector a partir de un `redirect_response`
/// sintético (no leído de disco), para poder mandarlas SIN el hueco de varios minutos que mete
/// tener que volver a correr `cargo test` entre el init y el PATCH. El cuerpo del PATCH sólo
/// depende de (storeId, estado): no lleva el `ipgTransactionId`, que va en la URL.
#[test]
fn dump_phase5_continuation_templates() {
    let cases: [(&str, Option<&str>, Option<serde_json::Value>); 3] = [
        // Retorno por la termURL sin `threeDSMethodData`: lo que pasa de verdad en el flujo del
        // conector, porque la notificación del ACS entra por la methodNotificationURL.
        ("tmpl-cont-expected", Some("fiservemea3ds=term"), None),
        // Retorno por la termURL que además trae la notificación: la única forma de que el
        // conector emita RECEIVED.
        (
            "tmpl-cont-received",
            Some("fiservemea3ds=term"),
            Some(json!({ "threeDSMethodData": "PLACEHOLDER" })),
        ),
        // Retorno del desafío con el cRes.
        (
            "tmpl-cont-cres",
            Some("fiservemea3ds=term"),
            Some(json!({ "cres": "CRES_PLACEHOLDER" })),
        ),
    ];
    for (case, params, payload) in cases {
        let redirect_response = CompleteAuthorizeRedirectResponse {
            params: params.map(|p| Secret::new(p.to_string())),
            payload: payload.map(Secret::new),
        };
        let request = CompleteAuthorizeData {
            payment_method_data: None,
            amount: 100_000,
            email: None,
            currency: enums::Currency::ARS,
            confirm: true,
            statement_descriptor_suffix: None,
            capture_method: Some(enums::CaptureMethod::Automatic),
            setup_future_usage: None,
            mandate_id: None,
            off_session: None,
            setup_mandate_details: None,
            redirect_response: Some(redirect_response),
            browser_info: None,
            connector_transaction_id: Some("TEMPLATE".to_string()),
            connector_meta: None,
            complete_authorize_url: Some("https://www.pxsol.com/3ds/return".to_string()),
            metadata: None,
            customer_acceptance: None,
            minor_amount: MinorUnit::new(100_000),
            merchant_account_id: None,
            merchant_config_currency: None,
            threeds_method_comp_ind: None,
            request_incremental_authorization: false,
            authentication_data: None,
            payment_method_type: None,
            is_stored_credential: None,
            tokenization: None,
            router_return_url: None,
            merchant_order_reference_id: None,
        };
        let rd: RouterData<CompleteAuthorize, _, _> =
            router_data(request, STORE_AR, case, true, None);
        let req = fiservemea::FiservemeaCompleteAuthorizeRequest::try_from(&rd).unwrap();
        dump(case, "PATCH", "/payments/{ipg}", RequestContent::Json(Box::new(req)));
    }
}

/// Inits 3DS extra, con `orderId` propio, para que el driver de Python pueda correr cada flujo
/// de punta a punta en segundos usando las plantillas de arriba.
#[test]
fn dump_phase5_fast_inits() {
    for (case, number) in [
        ("fast-mth-expected", "4099000000001978"),
        ("fast-mth-received", "4099000000001978"),
        ("fast-chm-1", "4265880000000064"),
        ("fast-cha-1", "4147463011110059"),
    ] {
        dump_authorize(
            case,
            STORE_AR,
            number,
            enums::Currency::ARS,
            100_000,
            None,
            true,
            None,
        );
    }
}

/// Tercera fase: continuaciones 3DS. El script de Python deja en `acs/<case>.json` lo que el ACS
/// devolvió de verdad (`{"ipg": ..., "params": "<query string>"}` o `{"payload": {...}}`), y acá se
/// construye el `CompleteAuthorizeRouterData` con eso, para que el body del PATCH lo genere el
/// conector.
#[test]
fn dump_phase3_continuations() {
    let acs_dir = dump_dir().join("acs");
    let Ok(entries) = std::fs::read_dir(&acs_dir) else {
        println!("[skip] no hay acs/ todavía");
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let raw: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let case = path.file_stem().unwrap().to_str().unwrap().to_string();
        let ipg = raw["ipg"].as_str().unwrap().to_string();
        let redirect_response = CompleteAuthorizeRedirectResponse {
            params: raw
                .get("params")
                .and_then(|v| v.as_str())
                .map(|s| Secret::new(s.to_string())),
            payload: raw
                .get("payload")
                .filter(|v| !v.is_null())
                .map(|v| Secret::new(v.clone())),
        };
        let store = raw
            .get("store")
            .and_then(|v| v.as_str())
            .unwrap_or(STORE_AR)
            .to_string();
        let request = CompleteAuthorizeData {
            payment_method_data: None,
            amount: 100_000,
            email: None,
            currency: enums::Currency::ARS,
            confirm: true,
            statement_descriptor_suffix: None,
            capture_method: Some(enums::CaptureMethod::Automatic),
            setup_future_usage: None,
            mandate_id: None,
            off_session: None,
            setup_mandate_details: None,
            redirect_response: Some(redirect_response),
            browser_info: None,
            connector_transaction_id: Some(ipg.clone()),
            connector_meta: None,
            complete_authorize_url: Some("https://www.pxsol.com/3ds/return".to_string()),
            metadata: None,
            customer_acceptance: None,
            minor_amount: MinorUnit::new(100_000),
            merchant_account_id: None,
            merchant_config_currency: None,
            threeds_method_comp_ind: None,
            request_incremental_authorization: false,
            authentication_data: None,
            payment_method_type: None,
            is_stored_credential: None,
            tokenization: None,
            router_return_url: None,
            merchant_order_reference_id: None,
        };
        let rd: RouterData<CompleteAuthorize, _, _> = router_data(
            request,
            &store,
            raw.get("order_id").and_then(|v| v.as_str()).unwrap_or(&case),
            true,
            None,
        );
        // Espeja `build_request` del conector: la notificación del 3DSMethod se degrada a GET
        // sin cuerpo; la continuación real es un PATCH con cuerpo.
        if fiservemea::is_acs_method_notification(rd.request.redirect_response.as_ref().unwrap()) {
            write_case(
                &format!("cont-{case}"),
                "GET",
                &format!("/payments/{ipg}?storeId={store}"),
                None,
            );
        } else {
            let req = fiservemea::FiservemeaCompleteAuthorizeRequest::try_from(&rd).unwrap();
            dump(
                &format!("cont-{case}"),
                "PATCH",
                &format!("/payments/{ipg}"),
                RequestContent::Json(Box::new(req)),
            );
        }
    }
}

/// Cierra el círculo: cada respuesta REAL que el gateway devolvió a los payloads del conector
/// tiene que poder deserializarse con los tipos del conector. Sin esto, un payload aceptado
/// puede igual terminar en `ResponseDeserializationFailed`.
#[test]
fn parse_every_live_response() {
    let dir = dump_dir().join("responses");
    let Ok(entries) = std::fs::read_dir(&dir) else {
        println!("[skip] no hay responses/ todavía");
        return;
    };
    let mut checked = 0usize;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let raw: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let case = raw["case"].as_str().unwrap().to_string();
        let body = raw["response"].clone();
        let http = raw["http"].as_u64().unwrap_or(0);
        let kind = body["type"].as_str().unwrap_or("");
        let result: Result<String, String> = if http != 200 {
            serde_json::from_value::<fiservemea::FiservemeaErrorResponse>(body.clone())
                .map(|_| "FiservemeaErrorResponse".to_string())
                .map_err(|e| e.to_string())
        } else if kind == "orderResponse" || kind == "transactionResponse" {
            serde_json::from_value::<fiservemea::FiservemeaSyncResponse>(body.clone())
                .map(|_| "FiservemeaSyncResponse".to_string())
                .map_err(|e| e.to_string())
        } else if kind == "paymentTokenizationResponse" {
            serde_json::from_value::<fiservemea::FiservemeaTokenResponse>(body.clone())
                .map(|_| "FiservemeaTokenResponse".to_string())
                .map_err(|e| e.to_string())
        } else {
            serde_json::from_value::<fiservemea::FiservemeaPaymentsResponse>(body.clone())
                .map(|_| "FiservemeaPaymentsResponse".to_string())
                .map_err(|e| e.to_string())
        };
        match result {
            Ok(as_type) => println!("[parse ok] {case} ({http}) -> {as_type}"),
            Err(err) => panic!("[parse FALLA] {case} ({http}) type={kind}: {err}\n{body:#}"),
        }
        checked += 1;
    }
    println!("[parse] {checked} respuestas reales verificadas");
    assert!(checked > 0, "no se verificó ninguna respuesta");
}

/// Pre-auth + captura + anulación de pre-auth. No están en el checklist de homologación pero sí
/// en el conector (`capture_method: Manual` -> `PaymentCardPreAuthTransaction`), y un rechazo acá
/// también sería bloqueante. Los cuerpos de captura/anulación no dependen del `ipgTransactionId`
/// (va en la URL), así que se dumpean como plantilla.
#[test]
fn dump_phase7_preauth_capture() {
    use hyperswitch_domain_models::{
        router_flow_types::payments::Capture, router_request_types::PaymentsCaptureData,
    };

    // pre-auth: capture_method Manual
    let oid = order_id("preauth");
    let mut request = authorize_data("5165850000000008", enums::Currency::ARS, 100_000, None, false);
    request.capture_method = Some(enums::CaptureMethod::Manual);
    let rd: RouterData<Authorize, _, _> = router_data(request, STORE_AR, &oid, false, None);
    let amount = crate::utils::convert_amount(
        Fiservemea::new().amount_converter,
        rd.request.minor_amount,
        rd.request.currency,
    )
    .unwrap();
    let crd = fiservemea::FiservemeaRouterData::from((amount.clone(), &rd));
    let req = fiservemea::FiservemeaPaymentsRequest::try_from(&crd).unwrap();
    dump("preauth", "POST", "/payments", RequestContent::Json(Box::new(req)));

    // segundo pre-auth, para probar la anulación de un pre-auth sin capturar
    let oid2 = order_id("preauth-void");
    let mut request2 =
        authorize_data("5165850000000008", enums::Currency::ARS, 100_000, None, false);
    request2.capture_method = Some(enums::CaptureMethod::Manual);
    let rd2: RouterData<Authorize, _, _> = router_data(request2, STORE_AR, &oid2, false, None);
    let crd2 = fiservemea::FiservemeaRouterData::from((amount.clone(), &rd2));
    let req2 = fiservemea::FiservemeaPaymentsRequest::try_from(&crd2).unwrap();
    dump("preauth-void", "POST", "/payments", RequestContent::Json(Box::new(req2)));

    // captura
    let capture_request = PaymentsCaptureData {
        amount_to_capture: 100_000,
        currency: enums::Currency::ARS,
        connector_transaction_id: "TEMPLATE".to_string(),
        payment_amount: 100_000,
        multiple_capture_data: None,
        connector_meta: None,
        browser_info: None,
        metadata: None,
        capture_method: Some(enums::CaptureMethod::Manual),
        minor_payment_amount: MinorUnit::new(100_000),
        minor_amount_to_capture: MinorUnit::new(100_000),
        integrity_object: None,
        webhook_url: None,
        split_payments: None,
        order_tax_amount: None,
        merchant_order_reference_id: None,
    };
    let crd3: RouterData<Capture, _, PaymentsResponseData> =
        router_data(capture_request, STORE_AR, "capture", false, None);
    let crd3 = fiservemea::FiservemeaRouterData::from((amount, &crd3));
    let cap = fiservemea::FiservemeaCaptureRequest::try_from(&crd3).unwrap();
    dump(
        "tmpl-capture",
        "POST",
        "/payments/{ipg}",
        RequestContent::Json(Box::new(cap)),
    );

    // anulación de un pre-auth sin capturar
    let cancel_request = PaymentsCancelData {
        amount: Some(100_000),
        currency: Some(enums::Currency::ARS),
        connector_transaction_id: "TEMPLATE".to_string(),
        cancellation_reason: None,
        connector_meta: None,
        browser_info: None,
        metadata: None,
        minor_amount: Some(MinorUnit::new(100_000)),
        webhook_url: None,
        capture_method: Some(enums::CaptureMethod::Manual),
        split_payments: None,
        merchant_order_reference_id: None,
        payment_method_type: None,
        feature_metadata: None,
    };
    let rd4: RouterData<Void, _, _> =
        router_data(cancel_request, STORE_AR, "void-preauth", false, None);
    let v = fiservemea::FiservemeaVoidRequest::try_from(&rd4).unwrap();
    dump(
        "tmpl-void-preauth",
        "POST",
        "/payments/{ipg}",
        RequestContent::Json(Box::new(v)),
    );
}

/// URL de consulta que el conector arma con `build_sync_url`. Es la que usa el PSync y, sobre
/// todo, la que usa el CompleteAuthorize cuando el callback es la notificación del 3DSMethod
/// (ahí el conector degrada el PATCH a un GET). `IPGID` se sustituye por el id real.
#[test]
fn dump_phase6_sync_urls() {
    use hyperswitch_domain_models::router_request_types::ResponseId;
    let by_txn = super::build_sync_url(
        "https://cert.api.firstdata.com/gateway/v2",
        &ResponseId::ConnectorTransactionId("IPGID".to_string()),
        "ORDERID",
        STORE_AR,
    )
    .unwrap();
    let by_order = super::build_sync_url(
        "https://cert.api.firstdata.com/gateway/v2",
        &ResponseId::NoResponseId,
        "ORDERID",
        STORE_AR,
    )
    .unwrap();
    let strip = |url: String| {
        url.trim_start_matches("https://cert.api.firstdata.com/gateway/v2")
            .to_string()
    };
    write_case("tmpl-sync-by-transaction", "GET", &strip(by_txn), None);
    write_case("tmpl-sync-by-order", "GET", &strip(by_order), None);
}

/// Cuarta fase: void y refund sobre una transacción aprobada real. Los ids los deja Python.
#[test]
fn dump_phase4_void_refund() {
    let dir = dump_dir();
    let mut targets: HashMap<String, String> = HashMap::new();
    if let Ok(raw) = std::fs::read_to_string(dir.join("post_ops.json")) {
        let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
        for (k, val) in v.as_object().unwrap() {
            targets.insert(k.clone(), val.as_str().unwrap().to_string());
        }
    } else {
        println!("[skip] no hay post_ops.json todavía");
        return;
    }

    if let Some(ipg) = targets.get("void") {
        let request = PaymentsCancelData {
            amount: Some(100_000),
            currency: Some(enums::Currency::ARS),
            connector_transaction_id: ipg.clone(),
            cancellation_reason: None,
            connector_meta: None,
            browser_info: None,
            metadata: None,
            minor_amount: Some(MinorUnit::new(100_000)),
            webhook_url: None,
            capture_method: Some(enums::CaptureMethod::Automatic),
            split_payments: None,
            merchant_order_reference_id: None,
            payment_method_type: None,
            feature_metadata: None,
        };
        let rd: RouterData<Void, _, _> = router_data(request, STORE_AR, "void-op", false, None);
        let req = fiservemea::FiservemeaVoidRequest::try_from(&rd).unwrap();
        dump(
            "void",
            "POST",
            &format!("/payments/{ipg}"),
            RequestContent::Json(Box::new(req)),
        );
    }

    for (key, amount_minor) in [("return-total", 100_000_i64), ("return-parcial", 50_000)] {
        if let Some(ipg) = targets.get(key) {
            let request = RefundsData {
                refund_id: key.to_string(),
                connector_transaction_id: ipg.clone(),
                connector_refund_id: None,
                currency: enums::Currency::ARS,
                payment_amount: 100_000,
                reason: None,
                webhook_url: None,
                refund_amount: amount_minor,
                connector_metadata: None,
                refund_connector_metadata: None,
                browser_info: None,
                split_refunds: None,
                minor_payment_amount: MinorUnit::new(100_000),
                minor_refund_amount: MinorUnit::new(amount_minor),
                integrity_object: None,
                refund_status: enums::RefundStatus::Pending,
                merchant_account_id: None,
                merchant_config_currency: None,
                capture_method: Some(enums::CaptureMethod::Automatic),
                additional_payment_method_data: None,
            };
            let rd: RouterData<Execute, _, _> = router_data(request, STORE_AR, key, false, None);
            let amount = crate::utils::convert_amount(
                Fiservemea::new().amount_converter,
                rd.request.minor_refund_amount,
                rd.request.currency,
            )
            .unwrap();
            let crd = fiservemea::FiservemeaRouterData::from((amount, &rd));
            let req = fiservemea::FiservemeaRefundRequest::try_from(&crd).unwrap();
            dump(
                key,
                "POST",
                &format!("/payments/{ipg}"),
                RequestContent::Json(Box::new(req)),
            );
        }
    }
}
