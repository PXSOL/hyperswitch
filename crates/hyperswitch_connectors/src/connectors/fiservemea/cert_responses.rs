//! Tests de PARSEO de las respuestas REALES del gateway de certificación de Fiserv IPG.
//!
//! Todos los payloads de este módulo son cuerpos que el gateway devolvió de verdad, copiados de
//! la evidencia de homologación (`fiserv_homologacion_logs/*/evidencia.jsonl`, 579 respuestas) o
//! traídos en vivo de `https://cert.api.firstdata.com/gateway/v2`. Cada fixture dice de dónde
//! salió y con qué `apiTraceId`.
//!
//! A diferencia de los tests del módulo `transformers`, que ejercitan `map_status` sobre los
//! campos ya deserializados, acá la respuesta cruda pasa por **todo** el camino de conversión
//! (`serde` -> `TryFrom<ResponseRouterData<..>>` / `build_error_response`) y se verifica lo que
//! termina viendo Hyperswitch: `AttemptStatus`, `Ok`/`Err`, código y mensaje de error,
//! `connector_transaction_id`, `network_txn_id`, `connector_metadata` y `mandate_reference`.
//!
//! Se corre con:
//!   cargo test -p hyperswitch_connectors --lib --features v1 fiservemea::cert_responses

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::print_stderr
)]

use std::marker::PhantomData;

use common_enums::enums;
use hyperswitch_domain_models::{
    payment_address::PaymentAddress,
    router_data::{ConnectorAuthType, ErrorResponse, RouterData},
    router_request_types::ResponseId,
    router_response_types::{PaymentsResponseData, RedirectForm},
};
use hyperswitch_interfaces::{api::ConnectorCommon, types::Response};
use masking::{PeekInterface, Secret};
use serde_json::json;

use super::transformers as fiservemea;
use crate::{connectors::Fiservemea, types::ResponseRouterData};

/// `RouterData` mínimo. La conversión de respuesta es genérica en `Flow`/`Request`
/// (`impl<F, T> TryFrom<ResponseRouterData<F, FiservemeaPaymentsResponse, T, PaymentsResponseData>>`),
/// así que se instancia con `()` en los dos: no hace falta armar un request de ningún flujo para
/// ejercitar el parseo de la respuesta, que es lo único que se mide acá.
type TestRouterData = RouterData<(), (), PaymentsResponseData>;

fn empty_router_data<F>() -> RouterData<F, (), PaymentsResponseData> {
    RouterData {
        flow: PhantomData,
        merchant_id: common_utils::id_type::MerchantId::default(),
        customer_id: None,
        connector_customer: None,
        connector: "fiservemea".to_string(),
        payment_id: "pay_cert".to_string(),
        attempt_id: "att_cert".to_string(),
        tenant_id: common_utils::id_type::TenantId::try_from_string("public".to_string()).unwrap(),
        status: enums::AttemptStatus::Pending,
        payment_method: enums::PaymentMethod::Card,
        connector_auth_type: ConnectorAuthType::SignatureKey {
            api_key: Secret::new("key".to_string()),
            key1: Secret::new("store".to_string()),
            api_secret: Secret::new("secret".to_string()),
        },
        description: None,
        address: PaymentAddress::default(),
        auth_type: enums::AuthenticationType::NoThreeDs,
        connector_meta_data: None,
        connector_wallets_details: None,
        amount_captured: None,
        access_token: None,
        session_token: None,
        reference_id: None,
        payment_method_token: None,
        recurring_mandate_payment_data: None,
        preprocessing_id: None,
        payment_method_balance: None,
        connector_api_version: None,
        request: (),
        response: Err(ErrorResponse::default()),
        connector_request_reference_id: "ref_cert".to_string(),
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
    }
}

/// Camino completo de una respuesta 2xx de pago: deserializa y convierte.
///
/// El `expect` sobre el `from_value` es el test de deserialización: si alguna respuesta real del
/// gateway no parseara, el fallo se ve acá con el payload que lo produjo.
fn convert(raw: serde_json::Value, http_code: u16) -> TestRouterData {
    let response: fiservemea::FiservemeaPaymentsResponse = serde_json::from_value(raw.clone())
        .unwrap_or_else(|err| panic!("la respuesta real del gateway no deserializó: {err}\n{raw:#}"));
    RouterData::try_from(ResponseRouterData {
        response,
        data: empty_router_data::<()>(),
        http_code,
    })
    .expect("la conversión de una respuesta real no debe fallar")
}

/// Camino del PSync: discrimina por `type` entre `transactionResponse` y `orderResponse`, reduce a
/// una transacción y recién después convierte, igual que `handle_response` del PSync.
fn convert_sync(raw: serde_json::Value, http_code: u16) -> TestRouterData {
    let sync: fiservemea::FiservemeaSyncResponse = serde_json::from_value(raw.clone())
        .unwrap_or_else(|err| panic!("la respuesta real del PSync no deserializó: {err}\n{raw:#}"));
    let response = sync.into_transaction().expect("orden sin transacciones");
    RouterData::try_from(ResponseRouterData {
        response,
        data: empty_router_data::<()>(),
        http_code,
    })
    .expect("la conversión de una respuesta real de PSync no debe fallar")
}

/// Camino de las respuestas NO-2xx: el router manda todo lo que no sea 2xx a `get_error_response`
/// (crates/router/src/services/api.rs, brazo `Err(body)`), que en este conector es
/// `build_error_response`. Los 107 rechazos con HTTP 409/400 de la evidencia pasan por acá y NO
/// por el `TryFrom` de `FiservemeaPaymentsResponse`.
fn error_response(raw: serde_json::Value, status_code: u16) -> ErrorResponse {
    Fiservemea::new()
        .build_error_response(
            Response {
                headers: None,
                response: serde_json::to_vec(&raw).unwrap().into(),
                status_code,
            },
            None,
        )
        .expect("un rechazo real del gateway debe parsear")
}

fn transaction_response(data: &TestRouterData) -> &PaymentsResponseData {
    data.response
        .as_ref()
        .unwrap_or_else(|err| panic!("se esperaba Ok, salió Err: {err:?}"))
}

/// Desarma el `PaymentsResponseData::TransactionResponse` en los campos que interesan acá.
struct Parsed<'a> {
    resource_id: &'a ResponseId,
    redirection: &'a Option<RedirectForm>,
    mandate_id: Option<&'a String>,
    metadata: &'a Option<serde_json::Value>,
    network_txn_id: &'a Option<String>,
    reference_id: &'a Option<String>,
}

fn parsed(data: &TestRouterData) -> Parsed<'_> {
    match transaction_response(data) {
        PaymentsResponseData::TransactionResponse {
            resource_id,
            redirection_data,
            mandate_reference,
            connector_metadata,
            network_txn_id,
            connector_response_reference_id,
            ..
        } => Parsed {
            resource_id,
            redirection: redirection_data,
            mandate_id: mandate_reference
                .as_ref()
                .as_ref()
                .and_then(|reference| reference.connector_mandate_id.as_ref()),
            metadata: connector_metadata,
            network_txn_id,
            reference_id: connector_response_reference_id,
        },
        other => panic!("se esperaba TransactionResponse, salió {other:?}"),
    }
}

fn connector_transaction_id(data: &TestRouterData) -> Option<String> {
    match parsed(data).resource_id {
        ResponseId::ConnectorTransactionId(id) => Some(id.clone()),
        ResponseId::NoResponseId => None,
        other => panic!("resource_id inesperado: {other:?}"),
    }
}

// =============================================================================================
//  Fixtures: cuerpos REALES del gateway de certificación, verbatim.
//
//  Generados a partir de `fiserv_homologacion_logs/*/evidencia.jsonl` y de consultas en vivo a
//  https://cert.api.firstdata.com/gateway/v2. NADA está escrito a mano: cada campo, incluidos
//  `apiTraceId` y `clientRequestId`, es el que devolvió el gateway. El doc comment de cada
//  fixture dice de qué corrida/línea salió.
// =============================================================================================

/// `POST /payments` — venta aprobada de 1000.00 ARS con la Mastercard AR de la guía.
/// Evidencia 20260806-215656 línea 1, caso "AR SALE 1 pago", `apiTraceId`
/// anUDKXbyIFesn-w_H27JzQAAA9E.
fn approved_sale() -> serde_json::Value {
    json!({
        "type": "transactionResponse",
        "clientRequestId": "d0479c7c-ed0b-4628-86f4-5d9cdee57a30",
        "apiTraceId": "anUDKXbyIFesn-w_H27JzQAAA9E",
        "ipgTransactionId": "84667286258",
        "orderId": "PX-1786053416-01-sale",
        "transactionType": "SALE",
        "paymentToken": {
            "reusable": true,
            "declineDuplicates": false,
            "brand": "MASTERCARD",
            "type": "PAYMENT_CARD"
        },
        "transactionOrigin": "ECOM",
        "paymentMethodDetails": {
            "paymentCard": {
                "expiryDate": {
                    "month": "12",
                    "year": "2029"
                },
                "fundingCardNumber": {
                    "bin": "516585",
                    "last4": "0008"
                },
                "cardFunction": "CREDIT",
                "bin": "516585",
                "last4": "0008",
                "brand": "MASTERCARD",
                "commercialCard": "NON_CORPORATE"
            },
            "paymentMethodType": "PAYMENT_CARD",
            "paymentMethodBrand": "MASTERCARD"
        },
        "country": "Argentina",
        "terminalId": "98000002",
        "merchantId": "00000014",
        "merchantTransactionId": "PX-1786053416-01-sale",
        "transactionTime": 1_786_053_417_i64,
        "approvedAmount": {
            "total": 1000.0,
            "currency": "ARS",
            "components": {
                "subtotal": 1000.0
            }
        },
        "transactionAmount": {
            "total": 1000.0,
            "currency": "ARS",
            "components": {
                "subtotal": 1000.0
            }
        },
        "transactionStatus": "APPROVED",
        "transactionResult": "APPROVED",
        "approvalCode": "Y:943616:4667286258:PPXX:9476656675",
        "transactionState": "CAPTURED",
        "processor": {
            "referenceNumber": "000000019357",
            "authorizationCode": "943616",
            "responseCode": "00",
            "responseMessage": "Function performed error-free",
            "avsResponse": {
                "streetMatch": "NO_INPUT_DATA",
                "postalCodeMatch": "NO_INPUT_DATA"
            },
            "securityCodeResponse": "NOT_CHECKED",
            "taxRefundData": {}
        },
        "globallyUniqueIdentifier": "d6a1a93a-fbfb-4f3d-9246-4ce298bfb9ea"
    })
}

/// `POST /payment-tokens` — creación del token de gateway (Hosted Data ID).
/// Evidencia 20260806-181533 línea 1, caso "AR CREATE TOKEN GW", `apiTraceId`
/// anTPR6AlKqWK06UtlmLTrAAAA74.
fn tokenization_response() -> serde_json::Value {
    json!({
        "type": "paymentTokenizationResponse",
        "clientRequestId": "5fd71636-ea19-494d-9a8a-eb6860573105",
        "apiTraceId": "anTPR6AlKqWK06UtlmLTrAAAA74",
        "requestStatus": "SUCCESS",
        "requestTime": 1_786_040_135_003_i64,
        "country": "Argentina",
        "paymentToken": {
            "value": "323106FA-6229-4BE7-B3B7-FDAABAD6CA21",
            "reusable": true,
            "declineDuplicates": false,
            "last4": "0008",
            "brand": "MASTERCARD",
            "type": "PAYMENT_CARD"
        },
        "orderId": "R-f992fe14-7c6f-410d-b497-24bcd452fe0d",
        "ipgTransactionId": "84667273490"
    })
}

/// `POST /payments` con `paymentToken` — venta en cuotas cobrada con el token de gateway. La
/// respuesta ECOA el `paymentToken.value`, que es el Hosted Data ID reusable para Card on File.
/// Evidencia 20260806-215656 línea 16, caso "AR SALE cuotas TOKEN GW", `apiTraceId`
/// anUDQfEpXVh-8FB-wNPYUQAAA6A.
fn approved_sale_with_gateway_token() -> serde_json::Value {
    json!({
        "type": "transactionResponse",
        "clientRequestId": "b6f60038-24d9-4260-8b76-ac4693a0d4fa",
        "apiTraceId": "anUDQfEpXVh-8FB-wNPYUQAAA6A",
        "ipgTransactionId": "84667286313",
        "orderId": "PX-1786053439-10-tokgw",
        "transactionType": "SALE",
        "paymentToken": {
            "value": "CF49734F-986F-4FD1-8040-9A16657E9B3E",
            "reusable": true,
            "declineDuplicates": false,
            "brand": "MASTERCARD",
            "type": "PAYMENT_CARD"
        },
        "transactionOrigin": "ECOM",
        "paymentMethodDetails": {
            "paymentCard": {
                "expiryDate": {
                    "month": "12",
                    "year": "2029"
                },
                "fundingCardNumber": {
                    "bin": "516585",
                    "last4": "0008"
                },
                "cardFunction": "CREDIT",
                "bin": "516585",
                "last4": "0008",
                "brand": "MASTERCARD",
                "commercialCard": "NON_CORPORATE"
            },
            "paymentMethodType": "PAYMENT_CARD",
            "paymentMethodBrand": "MASTERCARD"
        },
        "country": "Argentina",
        "terminalId": "98000001",
        "merchantId": "00000014",
        "merchantTransactionId": "PX-1786053439-10-tokgw",
        "transactionTime": 1_786_053_441_i64,
        "approvedAmount": {
            "total": 1000.0,
            "currency": "ARS",
            "components": {
                "subtotal": 1000.0
            }
        },
        "transactionAmount": {
            "total": 1000.0,
            "currency": "ARS",
            "components": {
                "subtotal": 1000.0
            }
        },
        "transactionStatus": "APPROVED",
        "transactionResult": "APPROVED",
        "approvalCode": "Y:503198:4667286313:PPXX:9476918438",
        "transactionState": "CAPTURED",
        "processor": {
            "referenceNumber": "000000019371",
            "authorizationCode": "503198",
            "responseCode": "00",
            "responseMessage": "Function performed error-free",
            "avsResponse": {
                "streetMatch": "NO_INPUT_DATA",
                "postalCodeMatch": "NO_INPUT_DATA"
            },
            "securityCodeResponse": "NOT_CHECKED",
            "taxRefundData": {}
        },
        "globallyUniqueIdentifier": "fd6c9fca-78d1-4fa3-b302-7c5959f943cb"
    })
}

/// `POST /payments` con Network Token de la marca (flujo MTRG OnTheGo, 1 pago). El gateway
/// sustituyó el PAN: el `bin`/`last4` procesado (432312/7867) NO es el que fondea (462294/2366).
/// Evidencia 20260806-192716 línea 4, caso "AR SALE TOKEN MTRG 1 pago", `apiTraceId`
/// anTgGxdinKHsuo_YUYBb-AAAA40.
fn approved_sale_with_network_token() -> serde_json::Value {
    json!({
        "type": "transactionResponse",
        "clientRequestId": "6608736b-9735-4eb7-9f32-6e1bf1309236",
        "apiTraceId": "anTgGxdinKHsuo_YUYBb-AAAA40",
        "ipgTransactionId": "84667279454",
        "orderId": "PX-1786044441-03-mtrg",
        "transactionType": "SALE",
        "paymentToken": {
            "reusable": true,
            "declineDuplicates": false,
            "brand": "VISA",
            "type": "PAYMENT_CARD"
        },
        "transactionOrigin": "ECOM",
        "paymentMethodDetails": {
            "paymentCard": {
                "expiryDate": {
                    "month": "12",
                    "year": "2029"
                },
                "fundingCardNumber": {
                    "bin": "462294",
                    "last4": "2366"
                },
                "bin": "432312",
                "last4": "7867",
                "brand": "VISA"
            },
            "paymentMethodType": "PAYMENT_CARD",
            "paymentMethodBrand": "VISA"
        },
        "terminalId": "98000001",
        "merchantId": "00000014",
        "merchantTransactionId": "PX-1786044441-03-mtrg",
        "transactionTime": 1_786_044_443_i64,
        "approvedAmount": {
            "total": 1000.0,
            "currency": "ARS",
            "components": {
                "subtotal": 1000.0
            }
        },
        "transactionAmount": {
            "total": 1000.0,
            "currency": "ARS",
            "components": {
                "subtotal": 1000.0
            }
        },
        "transactionStatus": "APPROVED",
        "transactionResult": "APPROVED",
        "approvalCode": "Y:459498:4667279454:PPXX:9437378384",
        "transactionState": "CAPTURED",
        "processor": {
            "referenceNumber": "000000018480",
            "authorizationCode": "459498",
            "responseCode": "00",
            "responseMessage": "Function performed error-free",
            "avsResponse": {
                "streetMatch": "NO_INPUT_DATA",
                "postalCodeMatch": "NO_INPUT_DATA"
            },
            "securityCodeResponse": "NOT_CHECKED",
            "taxRefundData": {}
        },
        "globallyUniqueIdentifier": "a0623fcb-6b16-4e05-9fd7-553170ac9b9a"
    })
}

/// `POST /payments` 3DS Frictionless **Authenticated**: aprobada con `responseCode3dSecure: "1"`.
/// Evidencia 20260806-215656 línea 19, caso "3DS Frictionless Authenticated [init]", `apiTraceId`
/// anUDSfEpXVh-8FB-wNPYZgAAA7M.
fn frictionless_authenticated() -> serde_json::Value {
    json!({
        "type": "transactionResponse",
        "clientRequestId": "f4b82e47-a010-4d7b-be34-140383f1b52c",
        "apiTraceId": "anUDSfEpXVh-8FB-wNPYZgAAA7M",
        "ipgTransactionId": "84667286316",
        "orderId": "PX-1786053447-13-3ds-fric-y",
        "transactionType": "SALE",
        "paymentToken": {
            "reusable": true,
            "declineDuplicates": false,
            "brand": "VISA",
            "type": "PAYMENT_CARD"
        },
        "transactionOrigin": "ECOM",
        "paymentMethodDetails": {
            "paymentCard": {
                "expiryDate": {
                    "month": "12",
                    "year": "2029"
                },
                "fundingCardNumber": {
                    "bin": "414746",
                    "last4": "0083"
                },
                "cardFunction": "CREDIT",
                "bin": "414746",
                "last4": "0083",
                "brand": "VISA",
                "commercialCard": "NON_CORPORATE"
            },
            "paymentMethodType": "PAYMENT_CARD",
            "paymentMethodBrand": "VISA"
        },
        "country": "Singapore",
        "terminalId": "98000003",
        "merchantId": "00000014",
        "merchantTransactionId": "PX-1786053447-13-3ds-fric-y",
        "transactionTime": 1_786_053_451_i64,
        "approvedAmount": {
            "total": 1000.0,
            "currency": "ARS",
            "components": {
                "subtotal": 1000.0
            }
        },
        "transactionAmount": {
            "total": 1000.0,
            "currency": "ARS",
            "components": {
                "subtotal": 1000.0
            }
        },
        "transactionStatus": "APPROVED",
        "transactionResult": "APPROVED",
        "approvalCode": "Y:594622:4667286316:PPXX:9476976645",
        "transactionState": "CAPTURED",
        "secure3dResponse": {
            "responseCode3dSecure": "1"
        },
        "processor": {
            "referenceNumber": "000000019373",
            "authorizationCode": "594622",
            "responseCode": "00",
            "responseMessage": "Function performed error-free",
            "avsResponse": {
                "streetMatch": "NO_INPUT_DATA",
                "postalCodeMatch": "NO_INPUT_DATA"
            },
            "securityCodeResponse": "NOT_CHECKED",
            "taxRefundData": {}
        },
        "globallyUniqueIdentifier": "f1aedeb7-a315-4747-a508-5ba5cc6792aa"
    })
}

/// `POST /payments` 3DS **Rejected Authentication** por el flujo 3DSMethod: el gateway APRUEBA el
/// cobro (HTTP 200, APPROVED/CAPTURED) y sólo informa el rechazo de la autenticación en
/// `secure3dResponse.responseCode3dSecure: "6"`. Además viene con sustitución por Network Token
/// (bin 441591 procesado vs 401636 que fondea). Evidencia 20260806-215656 línea 30, caso
/// "3DS 3DSMethod Rejected Authentication [init]", `apiTraceId` anUDdW3QaeZP532udpl7ugAAA7s.
fn three_ds_rejected_but_approved() -> serde_json::Value {
    json!({
        "type": "transactionResponse",
        "clientRequestId": "67b3abfc-28bc-4443-8559-0c8c292985d9",
        "apiTraceId": "anUDdW3QaeZP532udpl7ugAAA7s",
        "ipgTransactionId": "84667286430",
        "orderId": "PX-1786053491-21-3ds-mth-r",
        "transactionType": "SALE",
        "paymentToken": {
            "reusable": true,
            "declineDuplicates": false,
            "brand": "VISA",
            "type": "PAYMENT_CARD"
        },
        "transactionOrigin": "ECOM",
        "paymentMethodDetails": {
            "paymentCard": {
                "expiryDate": {
                    "month": "12",
                    "year": "2029"
                },
                "fundingCardNumber": {
                    "bin": "401636",
                    "last4": "0085"
                },
                "cardFunction": "CREDIT",
                "bin": "441591",
                "last4": "0153",
                "brand": "VISA",
                "commercialCard": "NON_CORPORATE"
            },
            "paymentMethodType": "PAYMENT_CARD",
            "paymentMethodBrand": "VISA"
        },
        "country": "Singapore",
        "terminalId": "98000003",
        "merchantId": "00000014",
        "merchantTransactionId": "PX-1786053491-21-3ds-mth-r",
        "transactionTime": 1_786_053_493_i64,
        "approvedAmount": {
            "total": 1000.0,
            "currency": "ARS",
            "components": {
                "subtotal": 1000.0
            }
        },
        "transactionAmount": {
            "total": 1000.0,
            "currency": "ARS",
            "components": {
                "subtotal": 1000.0
            }
        },
        "transactionStatus": "APPROVED",
        "transactionResult": "APPROVED",
        "approvalCode": "Y:277699:4667286430:PPXX:9477696647",
        "transactionState": "CAPTURED",
        "secure3dResponse": {
            "responseCode3dSecure": "6",
            "transactionStatusReason": "8"
        },
        "processor": {
            "referenceNumber": "000000019381",
            "authorizationCode": "277699",
            "responseCode": "00",
            "responseMessage": "Function performed error-free",
            "avsResponse": {
                "streetMatch": "NO_INPUT_DATA",
                "postalCodeMatch": "NO_INPUT_DATA"
            },
            "securityCodeResponse": "NOT_CHECKED",
            "taxRefundData": {}
        },
        "globallyUniqueIdentifier": "7b5c2dbc-3654-452a-8163-5318beac2995"
    })
}

/// `POST /payments` 3DS, primer paso: `WAITING` en los tres campos de estado y un
/// `secure3dMethod.methodForm` para el fingerprint del emisor. Evidencia 20260806-215656 línea 24,
/// caso "3DS 3DSMethod Authenticated [init]", `apiTraceId` anUDWRdinKHsuo_YUYCB_QAAA48.
fn waiting_with_three_ds_method() -> serde_json::Value {
    json!({
        "type": "transactionResponse",
        "clientRequestId": "5bf8c7fd-20a1-4b44-980e-a26fe2929a22",
        "apiTraceId": "anUDWRdinKHsuo_YUYCB_QAAA48",
        "ipgTransactionId": "84667286332",
        "orderId": "PX-1786053463-18-3ds-mth-y",
        "transactionType": "SALE",
        "paymentToken": {
            "reusable": true,
            "declineDuplicates": false,
            "brand": "VISA",
            "type": "PAYMENT_CARD"
        },
        "transactionOrigin": "ECOM",
        "paymentMethodDetails": {
            "paymentCard": {
                "expiryDate": {
                    "month": "12",
                    "year": "2029"
                },
                "fundingCardNumber": {
                    "bin": "409900",
                    "last4": "1978"
                },
                "cardFunction": "DEBIT",
                "bin": "409900",
                "last4": "1978",
                "brand": "VISA"
            },
            "paymentMethodType": "PAYMENT_CARD",
            "paymentMethodBrand": "VISA"
        },
        "country": "India",
        "merchantTransactionId": "PX-1786053463-18-3ds-mth-y",
        "transactionTime": 1_786_053_466_i64,
        "transactionAmount": {
            "total": 1000.0,
            "currency": "ARS",
            "components": {
                "subtotal": 1000.0
            }
        },
        "transactionStatus": "WAITING",
        "transactionResult": "WAITING",
        "approvalCode": "?:waiting 3dsecureMethod",
        "transactionState": "WAITING",
        "authenticationResponse": {
            "type": "3D_SECURE",
            "version": "2.2",
            "secure3dMethod": {
                "methodForm": "<iframe id=\"tdsMmethodTgtFrame\" name=\"tdsMmethodTgtFrame\" style=\"visibility: hidden; width: 1px; height: 1px;\" xmlns=\"http://www.w3.org/1999/xhtml\">    <!--.--></iframe><form id=\"tdsMmethodForm\" name=\"tdsMmethodForm\" action=\"https://3ds-acs.test.modirum.com/mdpayacs/3ds-method\" method=\"post\" target=\"tdsMmethodTgtFrame\" xmlns=\"http://www.w3.org/1999/xhtml\">    <input type=\"hidden\" name=\"3DSMethodData\" value=\"eyAidGhyZWVEU1NlcnZlclRyYW5zSUQiIDogImVkMjNkYzI4LTRkYmMtNTBlMC04MDAwLTAwMDAwNDRmNzhmMyIsICJ0aHJlZURTTWV0aG9kTm90aWZpY2F0aW9uVVJMIiA6ICJodHRwczovL3d3dy5weHNvbC5jb20vM2RzL21ldGhvZD9yZWY9UFgtMTc4NjA1MzQ2My0xOC0zZHMtbXRoLXkiIH0\"/>    <input type=\"hidden\" name=\"threeDSMethodData\" value=\"eyAidGhyZWVEU1NlcnZlclRyYW5zSUQiIDogImVkMjNkYzI4LTRkYmMtNTBlMC04MDAwLTAwMDAwNDRmNzhmMyIsICJ0aHJlZURTTWV0aG9kTm90aWZpY2F0aW9uVVJMIiA6ICJodHRwczovL3d3dy5weHNvbC5jb20vM2RzL21ldGhvZD9yZWY9UFgtMTc4NjA1MzQ2My0xOC0zZHMtbXRoLXkiIH0\"/>    <script type=\"text/javascript\">\t\t\t\tdocument.getElementById(\"tdsMmethodForm\").submit();\t\t\t</script></form>",
                "secure3dTransId": "72317171"
            }
        },
        "globallyUniqueIdentifier": "8df6c8c4-c1e5-4210-b95d-16697cdc2799"
    })
}

/// `POST /payments` 3DS, paso de desafío: `WAITING` con `params` para postear al ACS.
///
/// El gateway de cert **no** manda `sessionData` en este bloque (verificado sobre las 76
/// respuestas con `params` de la evidencia): sólo `acsURL`, `cReq` y `termURL`. Evidencia
/// 20260806-215656 línea 33, caso "3DS Challenge - R [init]", `apiTraceId`
/// anUDfvEpXVh-8FB-wNPZowAAA60.
fn waiting_with_challenge_params() -> serde_json::Value {
    json!({
        "type": "transactionResponse",
        "clientRequestId": "2c35f767-0beb-40c2-ab4a-d3aa4e1e8063",
        "apiTraceId": "anUDfvEpXVh-8FB-wNPZowAAA60",
        "ipgTransactionId": "84667286470",
        "orderId": "PX-1786053500-23-3ds-cha-r",
        "transactionType": "SALE",
        "paymentToken": {
            "reusable": true,
            "declineDuplicates": false,
            "brand": "VISA",
            "type": "PAYMENT_CARD"
        },
        "transactionOrigin": "ECOM",
        "paymentMethodDetails": {
            "paymentCard": {
                "expiryDate": {
                    "month": "12",
                    "year": "2029"
                },
                "fundingCardNumber": {
                    "bin": "414746",
                    "last4": "0034"
                },
                "cardFunction": "CREDIT",
                "bin": "414746",
                "last4": "0034",
                "brand": "VISA",
                "commercialCard": "NON_CORPORATE"
            },
            "paymentMethodType": "PAYMENT_CARD",
            "paymentMethodBrand": "VISA"
        },
        "country": "Singapore",
        "merchantTransactionId": "PX-1786053500-23-3ds-cha-r",
        "transactionTime": 1_786_053_503_i64,
        "transactionAmount": {
            "total": 1000.0,
            "currency": "ARS",
            "components": {
                "subtotal": 1000.0
            }
        },
        "transactionStatus": "WAITING",
        "transactionResult": "WAITING",
        "approvalCode": "?:waiting 3dsecure",
        "transactionState": "WAITING",
        "authenticationResponse": {
            "type": "3D_SECURE",
            "version": "2.2",
            "params": {
                "termURL": "https://www.pxsol.com/3ds/return?ref=PX-1786053500-23-3ds-cha-r",
                "acsURL": "https://3ds-acs.test.modirum.com/mdpayacs/creq;token=377138781.1786053503.T6iezYS8mm-1VUzwEOLZaNsthnKNMdqTYCk6tIxJ0PE",
                "cReq": "ewogICAgImFjc1RyYW5zSUQiOiAiMzRmZDc5YzAtZTlkYS00MTY5LWE1NjItOGE0MmE3MDFkNjYyIiwKICAgICJjaGFsbGVuZ2VXaW5kb3dTaXplIjogIjA1IiwKICAgICJtZXNzYWdlVHlwZSI6ICJDUmVxIiwKICAgICJtZXNzYWdlVmVyc2lvbiI6ICIyLjIuMCIsCiAgICAidGhyZWVEU1NlcnZlclRyYW5zSUQiOiAiMjVjZGJiODktZTBkYS01M2ViLTgwMDAtMDAwMDA0NGY3OTQzIgp9"
            }
        },
        "globallyUniqueIdentifier": "7744fa73-770f-4387-97e1-55ba678f6614"
    })
}

/// `POST /payments/{id}` — anulación aprobada. Devuelve un `ipgTransactionId` NUEVO (el de la
/// transacción VOID) y `transactionType: VOID`. Evidencia 20260806-215656 línea 10, caso
/// "AR VOID (anulación)", `apiTraceId` anUDNnbyIFesn-w_H27KIAAAA9A.
fn approved_void() -> serde_json::Value {
    json!({
        "type": "transactionResponse",
        "clientRequestId": "88d88a30-a92d-4b4f-bc47-817c4a756f7a",
        "apiTraceId": "anUDNnbyIFesn-w_H27KIAAAA9A",
        "ipgTransactionId": "84667286297",
        "orderId": "PX-1786053427-07-void",
        "transactionType": "VOID",
        "paymentToken": {
            "reusable": true,
            "declineDuplicates": false,
            "brand": "MASTERCARD",
            "type": "PAYMENT_CARD"
        },
        "transactionOrigin": "ECOM",
        "paymentMethodDetails": {
            "paymentCard": {
                "expiryDate": {
                    "month": "12",
                    "year": "2029"
                },
                "fundingCardNumber": {
                    "bin": "516585",
                    "last4": "0008"
                },
                "cardFunction": "CREDIT",
                "bin": "516585",
                "last4": "0008",
                "brand": "MASTERCARD",
                "commercialCard": "NON_CORPORATE"
            },
            "paymentMethodType": "PAYMENT_CARD",
            "paymentMethodBrand": "MASTERCARD"
        },
        "country": "Argentina",
        "terminalId": "98000002",
        "merchantId": "00000014",
        "transactionTime": 1_786_053_430_i64,
        "approvedAmount": {
            "total": 1000,
            "currency": "ARS",
            "components": {
                "subtotal": 1000
            }
        },
        "transactionAmount": {
            "total": 1000,
            "currency": "ARS",
            "components": {
                "subtotal": 1000
            }
        },
        "transactionStatus": "APPROVED",
        "transactionResult": "APPROVED",
        "approvalCode": "Y:470405:4667286297:PPXX:9476816680",
        "transactionState": "VOIDED",
        "processor": {
            "referenceNumber": "000000019365",
            "authorizationCode": "470405",
            "responseCode": "00",
            "responseMessage": "Function performed error-free",
            "taxRefundData": {}
        },
        "globallyUniqueIdentifier": "752d6538-9bb9-404e-8e6f-3afbfde0f8e3"
    })
}

/// `GET /payments/{id}?storeId=...` — consulta de una venta aprobada. **No trae
/// `transactionStatus`**: el estado sale de `transactionResult` + `transactionType`. Es la forma
/// de las 12 respuestas de INQUIRY de la evidencia. Evidencia 20260806-215656 línea 7, caso
/// "AR INQUIRY by transactionId", `apiTraceId` anUDMnbyIFesn-w_H27J_QAAA-Y.
fn sync_approved_sale() -> serde_json::Value {
    json!({
        "type": "transactionResponse",
        "clientRequestId": "3940f40b-e666-4a3a-9186-fa647f48bfc1",
        "apiTraceId": "anUDMnbyIFesn-w_H27J_QAAA-Y",
        "ipgTransactionId": "84667286294",
        "orderId": "PX-1786053423-06-inq",
        "transactionType": "SALE",
        "paymentToken": {
            "last4": "0008",
            "brand": "MASTERCARD"
        },
        "transactionOrigin": "ECOM",
        "paymentMethodDetails": {
            "paymentCard": {
                "expiryDate": {
                    "month": "12",
                    "year": "2029"
                },
                "cardFunction": "CREDIT",
                "bin": "516585",
                "last4": "0008",
                "brand": "MASTERCARD"
            },
            "paymentMethodType": "PAYMENT_CARD",
            "paymentMethodBrand": "MASTERCARD"
        },
        "country": "Argentina",
        "terminalId": "98000002",
        "merchantId": "00000014",
        "merchantTransactionId": "PX-1786053423-06-inq",
        "transactionTime": 1_786_053_424_i64,
        "approvedAmount": {
            "total": 1000,
            "currency": "ARS",
            "components": {
                "subtotal": 1000
            }
        },
        "transactionAmount": {
            "total": 1000,
            "currency": "ARS",
            "components": {
                "subtotal": 1000
            }
        },
        "transactionResult": "APPROVED",
        "approvalCode": "Y:412380:4667286294:PPXX:9476776678",
        "transactionState": "CAPTURED",
        "processor": {
            "referenceNumber": "000000019363",
            "authorizationCode": "412380",
            "responseCode": "00",
            "responseMessage": "Function performed error-free",
            "avsResponse": {
                "streetMatch": "NO_INPUT_DATA",
                "postalCodeMatch": "NO_INPUT_DATA"
            },
            "securityCodeResponse": "NOT_CHECKED"
        },
        "globallyUniqueIdentifier": "eb400f16-0fcd-407c-805f-3134db9894ce"
    })
}

/// `GET /orders/{orderId}?storeId=...` — consulta por orden: los datos van dentro de
/// `transactions`. Evidencia 20260806-215656 línea 8, caso "AR INQUIRY ORDER", `apiTraceId`
/// anUDM3byIFesn-w_H27KCQAAA90.
fn sync_order_response() -> serde_json::Value {
    json!({
        "type": "orderResponse",
        "clientRequestId": "6f5a66d2-eb70-4b80-82b1-c921bebeea58",
        "apiTraceId": "anUDM3byIFesn-w_H27KCQAAA90",
        "orderId": "PX-1786053423-06-inq",
        "transactions": [
            {
                "type": "transactionResponse",
                "ipgTransactionId": "84667286294",
                "transactionType": "SALE",
                "paymentToken": {
                    "last4": "0008",
                    "brand": "MASTERCARD"
                },
                "transactionOrigin": "ECOM",
                "paymentMethodDetails": {
                    "paymentCard": {
                        "expiryDate": {
                            "month": "12",
                            "year": "2029"
                        },
                        "cardFunction": "CREDIT",
                        "bin": "516585",
                        "last4": "0008",
                        "brand": "MASTERCARD"
                    },
                    "paymentMethodType": "PAYMENT_CARD",
                    "paymentMethodBrand": "MASTERCARD"
                },
                "country": "Argentina",
                "terminalId": "98000002",
                "merchantId": "00000014",
                "merchantTransactionId": "PX-1786053423-06-inq",
                "transactionTime": 1_786_053_424_i64,
                "approvedAmount": {
                    "total": 1000,
                    "currency": "ARS",
                    "components": {
                        "subtotal": 1000
                    }
                },
                "transactionAmount": {
                    "total": 1000,
                    "currency": "ARS",
                    "components": {
                        "subtotal": 1000
                    }
                },
                "transactionResult": "APPROVED",
                "approvalCode": "Y:412380:4667286294:PPXX:9476776678",
                "transactionState": "CAPTURED",
                "processor": {
                    "referenceNumber": "000000019363",
                    "authorizationCode": "412380",
                    "responseCode": "00",
                    "responseMessage": "Function performed error-free",
                    "avsResponse": {
                        "streetMatch": "NO_INPUT_DATA",
                        "postalCodeMatch": "NO_INPUT_DATA"
                    },
                    "securityCodeResponse": "NOT_CHECKED"
                },
                "globallyUniqueIdentifier": "eb400f16-0fcd-407c-805f-3134db9894ce"
            }
        ]
    })
}

/// `GET /orders/{orderId}?storeId=...` sobre la orden de una venta ANULADA.
///
/// Traído en vivo del gateway de cert el 2026-08-13 (`apiTraceId` an0QkyR5qsxv6kPs1WoIvAAAAdk).
/// Dos transacciones: primero la SALE, después el VOID. La SALE llega
/// `transactionResult: APPROVED` / `transactionType: SALE` y el único campo que dice que la plata
/// se liberó es `transactionState: VOIDED`.
fn sync_order_of_a_voided_sale() -> serde_json::Value {
    json!({
        "type": "orderResponse",
        "clientRequestId": "0233f9b0-2dfc-4ad9-9eea-04bdc5e46d82",
        "apiTraceId": "an0QkyR5qsxv6kPs1WoIvAAAAdk",
        "orderId": "PX-1786053427-07-void",
        "transactions": [
            {
                "type": "transactionResponse",
                "ipgTransactionId": "84667286296",
                "transactionType": "SALE",
                "paymentToken": {
                    "last4": "0008",
                    "brand": "MASTERCARD"
                },
                "transactionOrigin": "ECOM",
                "paymentMethodDetails": {
                    "paymentCard": {
                        "expiryDate": {
                            "month": "12",
                            "year": "2029"
                        },
                        "cardFunction": "CREDIT",
                        "bin": "516585",
                        "last4": "0008",
                        "brand": "MASTERCARD"
                    },
                    "paymentMethodType": "PAYMENT_CARD",
                    "paymentMethodBrand": "MASTERCARD"
                },
                "country": "Argentina",
                "terminalId": "98000002",
                "merchantId": "00000014",
                "merchantTransactionId": "PX-1786053427-07-void",
                "transactionTime": 1_786_053_429_i64,
                "approvedAmount": {
                    "total": 1000,
                    "currency": "ARS",
                    "components": {
                        "subtotal": 1000
                    }
                },
                "transactionAmount": {
                    "total": 1000,
                    "currency": "ARS",
                    "components": {
                        "subtotal": 1000
                    }
                },
                "transactionResult": "APPROVED",
                "approvalCode": "Y:986494:4667286296:PPXX:9476796679",
                "transactionState": "VOIDED",
                "processor": {
                    "referenceNumber": "000000019364",
                    "authorizationCode": "986494",
                    "responseCode": "00",
                    "responseMessage": "Function performed error-free",
                    "avsResponse": {
                        "streetMatch": "NO_INPUT_DATA",
                        "postalCodeMatch": "NO_INPUT_DATA"
                    },
                    "securityCodeResponse": "NOT_CHECKED"
                },
                "globallyUniqueIdentifier": "ae96ccd1-b53e-4687-939c-a5a02bc67679"
            },
            {
                "type": "transactionResponse",
                "ipgTransactionId": "84667286297",
                "transactionType": "VOID",
                "paymentToken": {
                    "last4": "0008",
                    "brand": "MASTERCARD"
                },
                "transactionOrigin": "ECOM",
                "paymentMethodDetails": {
                    "paymentCard": {
                        "expiryDate": {
                            "month": "12",
                            "year": "2029"
                        },
                        "cardFunction": "CREDIT",
                        "bin": "516585",
                        "last4": "0008",
                        "brand": "MASTERCARD"
                    },
                    "paymentMethodType": "PAYMENT_CARD",
                    "paymentMethodBrand": "MASTERCARD"
                },
                "country": "Argentina",
                "terminalId": "98000002",
                "merchantId": "00000014",
                "transactionTime": 1_786_053_430_i64,
                "approvedAmount": {
                    "total": 1000,
                    "currency": "ARS",
                    "components": {
                        "subtotal": 1000
                    }
                },
                "transactionAmount": {
                    "total": 1000,
                    "currency": "ARS",
                    "components": {
                        "subtotal": 1000
                    }
                },
                "transactionResult": "APPROVED",
                "approvalCode": "Y:470405:4667286296:PPXX:9476816680",
                "transactionState": "VOIDED",
                "processor": {
                    "referenceNumber": "000000019365",
                    "authorizationCode": "470405",
                    "responseCode": "00",
                    "responseMessage": "Function performed error-free",
                    "avsResponse": {
                        "streetMatch": "NO_INPUT_DATA",
                        "postalCodeMatch": "NO_INPUT_DATA"
                    },
                    "securityCodeResponse": "NOT_CHECKED"
                },
                "globallyUniqueIdentifier": "752d6538-9bb9-404e-8e6f-3afbfde0f8e3"
            }
        ]
    })
}

/// `GET /payments/84667286296?storeId=...` — consulta de la venta ANULADA por su propio id.
///
/// Traído en vivo del gateway de cert el 2026-08-13 (`apiTraceId` an0QkuOTJZTvEmGNMGmHtAAAAvs).
/// Es la misma trampa que la orden de arriba, pero por el camino principal del PSync:
/// `transactionResult: APPROVED`, `transactionType: SALE`, sin `transactionStatus`, y
/// `transactionState: VOIDED`.
fn sync_of_a_voided_sale() -> serde_json::Value {
    json!({
        "type": "transactionResponse",
        "clientRequestId": "bfd2190a-a484-4ad9-9c32-aaae446c04f5",
        "apiTraceId": "an0QkuOTJZTvEmGNMGmHtAAAAvs",
        "ipgTransactionId": "84667286296",
        "orderId": "PX-1786053427-07-void",
        "transactionType": "SALE",
        "paymentToken": {
            "last4": "0008",
            "brand": "MASTERCARD"
        },
        "transactionOrigin": "ECOM",
        "paymentMethodDetails": {
            "paymentCard": {
                "expiryDate": {
                    "month": "12",
                    "year": "2029"
                },
                "cardFunction": "CREDIT",
                "bin": "516585",
                "last4": "0008",
                "brand": "MASTERCARD"
            },
            "paymentMethodType": "PAYMENT_CARD",
            "paymentMethodBrand": "MASTERCARD"
        },
        "country": "Argentina",
        "terminalId": "98000002",
        "merchantId": "00000014",
        "merchantTransactionId": "PX-1786053427-07-void",
        "transactionTime": 1_786_053_429_i64,
        "approvedAmount": {
            "total": 1000,
            "currency": "ARS",
            "components": {
                "subtotal": 1000
            }
        },
        "transactionAmount": {
            "total": 1000,
            "currency": "ARS",
            "components": {
                "subtotal": 1000
            }
        },
        "transactionResult": "APPROVED",
        "approvalCode": "Y:986494:4667286296:PPXX:9476796679",
        "transactionState": "VOIDED",
        "processor": {
            "referenceNumber": "000000019364",
            "authorizationCode": "986494",
            "responseCode": "00",
            "responseMessage": "Function performed error-free",
            "avsResponse": {
                "streetMatch": "NO_INPUT_DATA",
                "postalCodeMatch": "NO_INPUT_DATA"
            },
            "securityCodeResponse": "NOT_CHECKED"
        },
        "globallyUniqueIdentifier": "ae96ccd1-b53e-4687-939c-a5a02bc67679"
    })
}

/// `GET /payments/{id}?storeId=...` — consulta de una venta RECHAZADA por el gateway.
///
/// Traído en vivo el 2026-08-13 (`apiTraceId` an0Qlp2Cn6oVn4oVRUTafQAAAxA, transacción
/// 84667287090, el rechazo 11101 de cuotas). Llega **con HTTP 200**: sin `transactionStatus`, sin
/// `errorMessage`, y con un bloque `processor` que trae SÓLO `avsResponse` — o sea sin
/// `responseCode` ni `responseMessage`. El único motivo que sobrevive está en `approvalCode`.
fn sync_of_a_declined_sale() -> serde_json::Value {
    json!({
        "type": "transactionResponse",
        "clientRequestId": "fe5fc865-ea80-4e1b-bb93-8b66f2bbe520",
        "apiTraceId": "an0Qlp2Cn6oVn4oVRUTafQAAAxA",
        "ipgTransactionId": "84667287090",
        "orderId": "PX-1786053663-53-diag",
        "transactionType": "SALE",
        "paymentToken": {
            "last4": "0153",
            "brand": "VISA"
        },
        "transactionOrigin": "ECOM",
        "paymentMethodDetails": {
            "paymentCard": {
                "expiryDate": {
                    "month": "12",
                    "year": "2029"
                },
                "bin": "441591",
                "last4": "0153",
                "brand": "VISA"
            },
            "paymentMethodType": "PAYMENT_CARD",
            "paymentMethodBrand": "VISA"
        },
        "country": "Singapore",
        "terminalId": "98000003",
        "merchantId": "00000014",
        "merchantTransactionId": "PX-1786053663-53-diag",
        "transactionTime": 1_786_053_664_i64,
        "transactionAmount": {
            "total": 1000,
            "currency": "ARS",
            "components": {
                "subtotal": 1000
            }
        },
        "transactionResult": "FAILED",
        "approvalCode": "N:-11101:installment not supported",
        "transactionState": "DECLINED",
        "processor": {
            "avsResponse": {
                "streetMatch": "NO_INPUT_DATA",
                "postalCodeMatch": "NO_INPUT_DATA"
            }
        },
        "globallyUniqueIdentifier": "47f4ef64-1941-483c-89dc-e73a7b54e3ee"
    })
}

/// `POST /payments` — rechazo del EMISOR con HTTP **422** / `responseType: EndpointDeclined`.
///
/// Traído en vivo del gateway de cert el 2026-08-13 (monto 1005.00 ARS con la Mastercard AR;
/// `apiTraceId` an0Q352Cn6oVn4oVRUTc0QAAAxQ, transacción 84668174890). Es la forma del rechazo
/// más común en producción, y la única que trae el bloque `processor` completo con el código ISO
/// del emisor. No está en `evidencia.jsonl` porque el harness no corre este caso.
fn issuer_decline_422() -> serde_json::Value {
    json!({
        "type": "TransactionErrorResponse",
        "clientRequestId": "8b400364-35a2-447e-8c8b-8a033ad78836",
        "apiTraceId": "an0Q352Cn6oVn4oVRUTc0QAAAxQ",
        "responseType": "EndpointDeclined",
        "ipgTransactionId": "84668174890",
        "orderId": "PX-1786581214-01-decl422",
        "transactionType": "SALE",
        "paymentToken": {
            "reusable": true,
            "declineDuplicates": false,
            "brand": "MASTERCARD",
            "type": "PAYMENT_CARD"
        },
        "transactionOrigin": "ECOM",
        "paymentMethodDetails": {
            "paymentCard": {
                "expiryDate": {
                    "month": "12",
                    "year": "2029"
                },
                "fundingCardNumber": {
                    "bin": "516585",
                    "last4": "0008"
                },
                "cardFunction": "CREDIT",
                "bin": "516585",
                "last4": "0008",
                "brand": "MASTERCARD",
                "commercialCard": "NON_CORPORATE"
            },
            "paymentMethodType": "PAYMENT_CARD",
            "paymentMethodBrand": "MASTERCARD"
        },
        "country": "Argentina",
        "terminalId": "98000001",
        "merchantId": "00000014",
        "merchantTransactionId": "PX-1786581214-01-decl422",
        "transactionTime": 1_786_581_215_i64,
        "transactionAmount": {
            "total": 1005.0,
            "currency": "ARS",
            "components": {
                "subtotal": 1005.0
            }
        },
        "transactionStatus": "DECLINED",
        "transactionResult": "DECLINED",
        "approvalCode": "N:05:Do not honour",
        "errorMessage": "50005: Do not honour",
        "transactionState": "DECLINED",
        "processor": {
            "referenceNumber": "000000066269",
            "authorizationCode": "846443",
            "responseCode": "05",
            "responseMessage": "Do not honour",
            "avsResponse": {
                "streetMatch": "NO_INPUT_DATA",
                "postalCodeMatch": "NO_INPUT_DATA"
            },
            "securityCodeResponse": "NOT_CHECKED",
            "taxRefundData": {}
        },
        "globallyUniqueIdentifier": "dd848282-c561-44d4-b54e-ab4005c8e6fd",
        "error": {
            "code": "50005",
            "message": "Do not honour"
        }
    })
}

/// `GET /payments/84668174890?storeId=...` — el MISMO rechazo del emisor visto por el PSync.
///
/// Traído en vivo el 2026-08-13 (`apiTraceId` an0Q4Xrd5Cb_7xaduYWo5wAAAzo). Llega con **HTTP
/// 200**, `transactionResult: DECLINED` (no `FAILED`) y —al revés que el PSync de un rechazo del
/// gateway— con `processor.responseCode` y `responseMessage` completos.
fn sync_of_an_issuer_declined_sale() -> serde_json::Value {
    json!({
        "type": "transactionResponse",
        "clientRequestId": "f059eac8-4a7f-4656-bc64-f71d2664670f",
        "apiTraceId": "an0Q4Xrd5Cb_7xaduYWo5wAAAzo",
        "ipgTransactionId": "84668174890",
        "orderId": "PX-1786581214-01-decl422",
        "transactionType": "SALE",
        "paymentToken": {
            "last4": "0008",
            "brand": "MASTERCARD"
        },
        "transactionOrigin": "ECOM",
        "paymentMethodDetails": {
            "paymentCard": {
                "expiryDate": {
                    "month": "12",
                    "year": "2029"
                },
                "cardFunction": "CREDIT",
                "bin": "516585",
                "last4": "0008",
                "brand": "MASTERCARD"
            },
            "paymentMethodType": "PAYMENT_CARD",
            "paymentMethodBrand": "MASTERCARD"
        },
        "country": "Argentina",
        "terminalId": "98000001",
        "merchantId": "00000014",
        "merchantTransactionId": "PX-1786581214-01-decl422",
        "transactionTime": 1_786_581_215_i64,
        "transactionAmount": {
            "total": 1005,
            "currency": "ARS",
            "components": {
                "subtotal": 1005
            }
        },
        "transactionResult": "DECLINED",
        "approvalCode": "N:05:Do not honour",
        "transactionState": "DECLINED",
        "processor": {
            "referenceNumber": "000000066269",
            "authorizationCode": "846443",
            "responseCode": "05",
            "responseMessage": "Do not honour",
            "avsResponse": {
                "streetMatch": "NO_INPUT_DATA",
                "postalCodeMatch": "NO_INPUT_DATA"
            }
        },
        "globallyUniqueIdentifier": "dd848282-c561-44d4-b54e-ab4005c8e6fd"
    })
}

/// `POST /payments` — rechazo de 3DS con HTTP **409**. Trae `secure3dResponse` con el
/// `responseCode3dSecure` que explica por qué se cayó la autenticación, y NO trae bloque
/// `processor`. Evidencia 20260806-215656 línea 22, caso
/// "3DS Frictionless Rejected Authentication [init]", `apiTraceId` anUDUyKQSojaSWQEaFJT7wAAA9I.
fn declined_3ds_409() -> serde_json::Value {
    json!({
        "type": "TransactionErrorResponse",
        "clientRequestId": "c256932c-cfd9-457d-9884-3efe69bb66dc",
        "apiTraceId": "anUDUyKQSojaSWQEaFJT7wAAA9I",
        "responseType": "GatewayDeclined",
        "ipgTransactionId": "84667286319",
        "orderId": "PX-1786053458-16-3ds-fric-r",
        "transactionType": "SALE",
        "paymentToken": {
            "reusable": true,
            "declineDuplicates": false,
            "brand": "VISA",
            "type": "PAYMENT_CARD"
        },
        "transactionOrigin": "ECOM",
        "paymentMethodDetails": {
            "paymentCard": {
                "expiryDate": {
                    "month": "12",
                    "year": "2029"
                },
                "fundingCardNumber": {
                    "bin": "414746",
                    "last4": "0042"
                },
                "cardFunction": "CREDIT",
                "bin": "414746",
                "last4": "0042",
                "brand": "VISA",
                "commercialCard": "NON_CORPORATE"
            },
            "paymentMethodType": "PAYMENT_CARD",
            "paymentMethodBrand": "VISA"
        },
        "country": "Singapore",
        "merchantTransactionId": "PX-1786053458-16-3ds-fric-r",
        "transactionTime": 1_786_053_460_i64,
        "transactionAmount": {
            "total": 1000.0,
            "currency": "ARS",
            "components": {
                "subtotal": 1000.0
            }
        },
        "transactionStatus": "VALIDATION_FAILED",
        "transactionResult": "FAILED",
        "approvalCode": "N:-50716:3D Secure authentication failed",
        "errorMessage": "50716: Transaction declined. 3D Secure authentication failed.",
        "transactionState": "DECLINED",
        "secure3dResponse": {
            "responseCode3dSecure": "3",
            "transactionStatusReason": "2"
        },
        "globallyUniqueIdentifier": "a102adff-a7ac-46b8-b8a6-5e78ddad203e",
        "error": {
            "code": "50716",
            "message": "Transaction declined. 3D Secure authentication failed."
        }
    })
}

/// `PATCH /payments/{id}` — rechazo de 3DS con HTTP 409 en la continuación, con `cardholderInfo`
/// (el texto que el emisor quiere que se le muestre al comprador). Evidencia 20260806-215656
/// línea 27, caso "3DS 3DSMethod Not Authenticated [methodNotificationStatus]", `apiTraceId`
/// anUDbKTdM6YRPnGROVIJJwAAA6k.
fn declined_3ds_409_with_cardholder_info() -> serde_json::Value {
    json!({
        "type": "TransactionErrorResponse",
        "clientRequestId": "28378a74-8a5a-40a9-8ed8-22619d6a49c5",
        "apiTraceId": "anUDbKTdM6YRPnGROVIJJwAAA6k",
        "responseType": "GatewayDeclined",
        "ipgTransactionId": "84667286333",
        "orderId": "PX-1786053474-19-3ds-mth-n",
        "transactionType": "SALE",
        "paymentToken": {
            "reusable": true,
            "declineDuplicates": false,
            "brand": "VISA",
            "type": "PAYMENT_CARD"
        },
        "transactionOrigin": "ECOM",
        "paymentMethodDetails": {
            "paymentCard": {
                "expiryDate": {
                    "month": "12",
                    "year": "2029"
                },
                "fundingCardNumber": {
                    "bin": "426588",
                    "last4": "0015"
                },
                "cardFunction": "DEBIT",
                "bin": "426588",
                "last4": "0015",
                "brand": "VISA"
            },
            "paymentMethodType": "PAYMENT_CARD",
            "paymentMethodBrand": "VISA"
        },
        "country": "India",
        "merchantTransactionId": "PX-1786053474-19-3ds-mth-n",
        "transactionTime": 1_786_053_476_i64,
        "transactionAmount": {
            "total": 1000,
            "currency": "ARS",
            "components": {
                "subtotal": 1000
            }
        },
        "transactionStatus": "VALIDATION_FAILED",
        "transactionResult": "FAILED",
        "approvalCode": "N:-50716:3D Secure authentication failed",
        "errorMessage": "50716: Transaction declined. 3D Secure authentication failed.",
        "transactionState": "DECLINED",
        "secure3dResponse": {
            "responseCode3dSecure": "3",
            "cardholderInfo": "Your card has not been configured to support EMV 3-D Secure, please contact your bank.",
            "transactionStatusReason": "12"
        },
        "globallyUniqueIdentifier": "4d963fe8-6c47-4575-addc-a91ea7a5342a",
        "error": {
            "code": "50716",
            "message": "Transaction declined. 3D Secure authentication failed."
        }
    })
}

/// `POST /payments` — rechazo Data Only con HTTP 409 **sin `ipgTransactionId`**: el gateway falla
/// antes de crear la transacción. Evidencia 20260806-215656 línea 58, caso
/// "3DS DataOnly (Mastercard, messageCategory 80) [init]", `apiTraceId`
/// anUD4RdinKHsuo_YUYCCjQAAA5M.
fn declined_data_only_without_transaction_id() -> serde_json::Value {
    json!({
        "type": "TransactionErrorResponse",
        "clientRequestId": "496db1e7-352f-46ea-9946-3b1c8c57d2ea",
        "apiTraceId": "anUD4RdinKHsuo_YUYCCjQAAA5M",
        "responseType": "GatewayDeclined",
        "orderId": "PX-1786053599-33-3ds-dataonly",
        "paymentToken": {
            "reusable": true,
            "declineDuplicates": false,
            "type": "PAYMENT_CARD"
        },
        "transactionTime": 1_786_053_601_i64,
        "transactionStatus": "VALIDATION_FAILED",
        "transactionResult": "FAILED",
        "approvalCode": "N:-50655:Unable to verify card enrollment",
        "errorMessage": "50655: Unable to verify card enrollment",
        "secure3dResponse": {
            "responseCode3dSecure": "8"
        },
        "error": {
            "code": "50655",
            "message": "Unable to verify card enrollment"
        }
    })
}

/// `POST /payments` — HTTP **400** `INVALID_INPUT` con `details`. Es la única respuesta de la
/// evidencia con `type: errorResponse` y sin `responseType`. Evidencia 20260806-181513 línea 5,
/// caso "AR DYNAMIC MERCHANT NAME" (cuando el `softDescriptor` todavía iba al nivel equivocado),
/// `apiTraceId` anTPN3byIFesn-w_H26txgAAA-I.
fn invalid_input_400() -> serde_json::Value {
    json!({
        "type": "errorResponse",
        "clientRequestId": "84cde100-3a04-485c-afb8-69e1b8ee499e",
        "apiTraceId": "anTPN3byIFesn-w_H26txgAAA-I",
        "error": {
            "code": "INVALID_INPUT",
            "message": "Invalid request input. Please see details below.",
            "details": [
                {
                    "field": "softDescriptor",
                    "message": "No field named 'softDescriptor' exists for class PaymentCardSaleTransaction"
                }
            ]
        }
    })
}

// =============================================================================================
//  1. Toda respuesta real deserializa
// =============================================================================================

#[test]
fn every_real_payment_response_shape_deserializes() {
    // Las formas de respuesta de pago que el gateway devolvió en las 579 respuestas capturadas,
    // una por cada grupo. Si el conector deja de parsear alguna, un cobro real se convierte en
    // `ResponseDeserializationFailed`.
    for (name, raw, http) in [
        ("sale aprobada", approved_sale(), 200),
        ("sale con token GW", approved_sale_with_gateway_token(), 200),
        ("sale con network token", approved_sale_with_network_token(), 200),
        ("3DS frictionless autenticada", frictionless_authenticated(), 200),
        ("3DS rechazada pero aprobada", three_ds_rejected_but_approved(), 200),
        ("WAITING con 3DSMethod", waiting_with_three_ds_method(), 200),
        ("WAITING con params de desafío", waiting_with_challenge_params(), 200),
        ("void aprobado", approved_void(), 200),
        ("PSync de venta aprobada", sync_approved_sale(), 200),
        ("PSync de venta anulada", sync_of_a_voided_sale(), 200),
        ("PSync de venta rechazada", sync_of_a_declined_sale(), 200),
        ("409 3DS rechazado", declined_3ds_409(), 409),
        ("409 3DS con cardholderInfo", declined_3ds_409_with_cardholder_info(), 409),
        ("409 Data Only sin id", declined_data_only_without_transaction_id(), 409),
        ("422 rechazo del emisor", issuer_decline_422(), 422),
        ("PSync del rechazo del emisor", sync_of_an_issuer_declined_sale(), 200),
    ] {
        let parsed: Result<fiservemea::FiservemeaPaymentsResponse, _> =
            serde_json::from_value(raw.clone());
        assert!(
            parsed.is_ok(),
            "{name} no deserializó: {:?}\n{raw:#}",
            parsed.err()
        );
        // Y la conversión completa tampoco puede fallar (el `convert` hace el `expect`).
        let _ = convert(raw, http);
    }
}

#[test]
fn every_real_sync_response_shape_deserializes() {
    for (name, raw) in [
        ("transactionResponse", sync_approved_sale()),
        ("orderResponse", sync_order_response()),
        ("orderResponse de una anulación", sync_order_of_a_voided_sale()),
    ] {
        let parsed: Result<fiservemea::FiservemeaSyncResponse, _> =
            serde_json::from_value(raw.clone());
        assert!(
            parsed.is_ok(),
            "{name} no deserializó como FiservemeaSyncResponse: {:?}\n{raw:#}",
            parsed.err()
        );
    }
}

#[test]
fn tokenization_response_yields_the_hosted_data_id() {
    let response: fiservemea::FiservemeaTokenResponse =
        serde_json::from_value(tokenization_response()).expect("la respuesta real debe parsear");
    let data: RouterData<
        hyperswitch_domain_models::router_flow_types::payments::PaymentMethodToken,
        (),
        PaymentsResponseData,
    > = RouterData::try_from(ResponseRouterData {
        response,
        data: empty_router_data(),
        http_code: 200,
    })
    .expect("la conversión del token no debe fallar");
    match data.response.as_ref().unwrap() {
        PaymentsResponseData::TokenizationResponse { token } => {
            assert_eq!(token, "323106FA-6229-4BE7-B3B7-FDAABAD6CA21");
        }
        other => panic!("se esperaba TokenizationResponse, salió {other:?}"),
    }
}

/// Los fixtures de este módulo tienen que ser IDÉNTICOS al cuerpo que el gateway devolvió, no una
/// versión abreviada ni retocada: cada uno se compara contra la línea exacta de la evidencia de la
/// que salió. Si alguien edita un fixture "para simplificarlo", este test lo detecta.
///
/// Los cuatro fixtures traídos en vivo (`sync_of_a_voided_sale`, `sync_order_of_a_voided_sale`,
/// `issuer_decline_422`, `sync_of_an_issuer_declined_sale`) no están en la evidencia y no se
/// pueden verificar acá; su procedencia está en el doc comment de cada uno.
#[test]
fn the_fixtures_are_verbatim_copies_of_the_evidence() {
    let Some(root) = evidence_root() else {
        return;
    };
    #[rustfmt::skip]
    let expected: [(&str, &str, usize, serde_json::Value); 15] = [
        ("approved_sale", "20260806-215656", 0, approved_sale()),
        ("tokenization_response", "20260806-181533", 0, tokenization_response()),
        ("approved_sale_with_gateway_token", "20260806-215656", 15, approved_sale_with_gateway_token()),
        ("approved_sale_with_network_token", "20260806-192716", 3, approved_sale_with_network_token()),
        ("frictionless_authenticated", "20260806-215656", 18, frictionless_authenticated()),
        ("three_ds_rejected_but_approved", "20260806-215656", 29, three_ds_rejected_but_approved()),
        ("waiting_with_three_ds_method", "20260806-215656", 23, waiting_with_three_ds_method()),
        ("waiting_with_challenge_params", "20260806-215656", 32, waiting_with_challenge_params()),
        ("approved_void", "20260806-215656", 9, approved_void()),
        ("sync_approved_sale", "20260806-215656", 6, sync_approved_sale()),
        ("sync_order_response", "20260806-215656", 7, sync_order_response()),
        ("declined_3ds_409", "20260806-215656", 21, declined_3ds_409()),
        ("declined_3ds_409_with_cardholder_info", "20260806-215656", 26, declined_3ds_409_with_cardholder_info()),
        ("declined_data_only_without_transaction_id", "20260806-215656", 57, declined_data_only_without_transaction_id()),
        ("invalid_input_400", "20260806-181513", 4, invalid_input_400()),
    ];
    for (name, run, line_index, fixture) in expected {
        let path = root.join(run).join("evidencia.jsonl");
        let file = std::fs::read_to_string(&path)
            .unwrap_or_else(|err| panic!("{name}: no se pudo leer {path:?}: {err}"));
        let line = file
            .lines()
            .nth(line_index)
            .unwrap_or_else(|| panic!("{name}: {path:?} no tiene la línea {line_index}"));
        let step: serde_json::Value = serde_json::from_str(line).unwrap();
        assert_eq!(
            step["response"], fixture,
            "el fixture `{name}` dejó de ser el cuerpo real de {run} línea {}",
            line_index + 1
        );
    }
}

/// Raíz de la evidencia de homologación, o `None` cuando no está (está gitignoreada).
fn evidence_root() -> Option<std::path::PathBuf> {
    match std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fiserv_homologacion_logs")
        .canonicalize()
    {
        Ok(root) => Some(root),
        Err(_) => {
            eprintln!("evidencia de homologación ausente (gitignoreada); test salteado");
            None
        }
    }
}

/// Barrido sobre TODA la evidencia de homologación: cada cuerpo que el gateway devolvió alguna
/// vez tiene que deserializar en la struct que le corresponde por `type`, y las de pago tienen
/// que atravesar la conversión completa sin errores.
///
/// La evidencia está gitignoreada (`/fiserv_homologacion_logs/`), así que si no está el test se
/// salta en vez de fallar. Con la evidencia presente cubre las 579 respuestas reales.
#[test]
fn the_whole_homologation_evidence_deserializes() {
    let Some(root) = evidence_root() else {
        return;
    };
    let mut runs: Vec<_> = std::fs::read_dir(&root)
        .unwrap()
        .filter_map(Result::ok)
        .map(|entry| entry.path().join("evidencia.jsonl"))
        .filter(|path| path.is_file())
        .collect();
    runs.sort();
    if runs.is_empty() {
        eprintln!("no hay evidencia.jsonl en {root:?}; test salteado");
        return;
    }

    let mut checked = 0_usize;
    for run in &runs {
        for (line_no, line) in std::fs::read_to_string(run).unwrap().lines().enumerate() {
            let step: serde_json::Value = serde_json::from_str(line).unwrap();
            let Some(body) = step.get("response").filter(|body| body.is_object()) else {
                continue;
            };
            let where_ = format!(
                "{}:{} caso {:?} {} {}",
                run.display(),
                line_no + 1,
                step["case"],
                step["method"],
                step["path"]
            );
            let http = step["http"]
                .as_u64()
                .and_then(|code| u16::try_from(code).ok())
                .unwrap_or(0);
            checked += 1;
            match body["type"].as_str() {
                // Consulta por orden: sólo el PSync la recibe.
                Some("orderResponse") => {
                    let sync: fiservemea::FiservemeaSyncResponse =
                        serde_json::from_value(body.clone())
                            .unwrap_or_else(|err| panic!("{where_}: {err}\n{body:#}"));
                    let response = sync
                        .into_transaction()
                        .unwrap_or_else(|err| panic!("{where_}: {err:?}"));
                    RouterData::try_from(ResponseRouterData {
                        response,
                        data: empty_router_data::<()>(),
                        http_code: http,
                    })
                    .unwrap_or_else(|err| panic!("{where_}: {err:?}"));
                }
                // Creación de token: struct propia.
                Some("paymentTokenizationResponse") => {
                    let _: fiservemea::FiservemeaTokenResponse =
                        serde_json::from_value(body.clone())
                            .unwrap_or_else(|err| panic!("{where_}: {err}\n{body:#}"));
                }
                // El resto son respuestas de transacción, aprobadas o rechazadas.
                Some("transactionResponse") | Some("TransactionErrorResponse") => {
                    let response: fiservemea::FiservemeaPaymentsResponse =
                        serde_json::from_value(body.clone())
                            .unwrap_or_else(|err| panic!("{where_}: {err}\n{body:#}"));
                    RouterData::try_from(ResponseRouterData {
                        response,
                        data: empty_router_data::<()>(),
                        http_code: http,
                    })
                    .unwrap_or_else(|err| panic!("{where_}: {err:?}"));
                    // Y los rechazos, además, por el camino real de los no-2xx.
                    if !(200..300).contains(&http) {
                        let _ = error_response(body.clone(), http);
                    }
                }
                // `errorResponse` (400 de validación) o cuerpos sin `type` (el `{}` que devuelve
                // el ACS, que no es del gateway): sólo los que tengan `error` van por
                // `build_error_response`.
                _ => {
                    if body.get("error").is_some() {
                        let _ = error_response(body.clone(), http);
                    }
                }
            }
        }
    }
    eprintln!(
        "respuestas reales barridas: {checked} (en {} corridas)",
        runs.len()
    );
    assert!(
        checked > 500,
        "se esperaba barrer las ~579 respuestas de la evidencia, se barrieron {checked}"
    );
}

// =============================================================================================
//  2. Estados y datos de las respuestas aprobadas
// =============================================================================================

#[test]
fn approved_sale_is_charged_with_its_transaction_id() {
    let data = convert(approved_sale(), 200);
    assert_eq!(data.status, enums::AttemptStatus::Charged);
    assert_eq!(
        connector_transaction_id(&data).as_deref(),
        Some("84667286258")
    );
    let parsed = parsed(&data);
    assert_eq!(parsed.reference_id.as_deref(), Some("PX-1786053416-01-sale"));
    assert!(parsed.redirection.is_none());
    // Sin `paymentToken.value` no hay nada que guardar como mandato: publicar uno vacío haría
    // que Card on File intentara cobrar contra un token inexistente.
    assert_eq!(parsed.mandate_id, None);
    // El gateway de cert NUNCA devuelve `schemeTransactionId` (0 de 579 respuestas), así que la
    // recurrencia Visa no puede armarse con lo que hoy vuelve del gateway.
    assert_eq!(parsed.network_txn_id, &None);
    // Los dos BIN coinciden: no hubo sustitución por Network Token, así que no se afirma una.
    assert_eq!(parsed.metadata, &None);
}

#[test]
fn gateway_token_is_published_as_the_mandate_reference() {
    // Es lo que permite volver a cobrar la tarjeta guardada: sin esto el Hosted Data ID vive
    // sólo dentro de la ejecución que lo creó.
    let data = convert(approved_sale_with_gateway_token(), 200);
    assert_eq!(data.status, enums::AttemptStatus::Charged);
    assert_eq!(
        parsed(&data).mandate_id.map(String::as_str),
        Some("CF49734F-986F-4FD1-8040-9A16657E9B3E")
    );
}

#[test]
fn network_token_pairing_travels_in_connector_metadata() {
    let data = convert(approved_sale_with_network_token(), 200);
    assert_eq!(data.status, enums::AttemptStatus::Charged);
    assert_eq!(
        parsed(&data).metadata,
        &Some(json!({
            "networkTokenPairing": {
                "networkTokenBin": "432312",
                "networkTokenLast4": "7867",
                "fundingCardBin": "462294",
                "fundingCardLast4": "2366"
            }
        }))
    );
}

#[test]
fn frictionless_3ds_code_travels_in_connector_metadata() {
    let data = convert(frictionless_authenticated(), 200);
    assert_eq!(data.status, enums::AttemptStatus::Charged);
    assert_eq!(
        parsed(&data).metadata,
        &Some(json!({ "responseCode3dSecure": "1" }))
    );
}

#[test]
fn a_rejected_authentication_that_the_gateway_still_approved_is_charged() {
    // Caso real incómodo: el 3DS terminó en "Rejected" (`responseCode3dSecure: "6"`) y aun así
    // el gateway devolvió APPROVED/CAPTURED con HTTP 200. El estado lo manda el resultado de la
    // transacción, no el de la autenticación: la plata se cobró.
    let data = convert(three_ds_rejected_but_approved(), 200);
    assert_eq!(data.status, enums::AttemptStatus::Charged);
    let metadata = parsed(&data).metadata.clone().expect("debe haber metadata");
    assert_eq!(metadata["responseCode3dSecure"], "6");
    // Esta misma respuesta trae sustitución por Network Token (bin 441591 vs 401636): los dos
    // datos tienen que convivir en el mismo objeto.
    assert_eq!(metadata["networkTokenPairing"]["fundingCardBin"], "401636");
}

#[test]
fn approved_void_is_voided() {
    let data = convert(approved_void(), 200);
    assert_eq!(data.status, enums::AttemptStatus::Voided);
    // Ojo: el id que vuelve es el de la transacción VOID, no el de la venta anulada.
    assert_eq!(
        connector_transaction_id(&data).as_deref(),
        Some("84667286297")
    );
}

// =============================================================================================
//  3. 3DS: los dos pasos intermedios producen redirect y AuthenticationPending
// =============================================================================================

#[test]
fn waiting_with_method_form_is_authentication_pending_with_an_html_redirect() {
    let data = convert(waiting_with_three_ds_method(), 200);
    assert_eq!(data.status, enums::AttemptStatus::AuthenticationPending);
    match parsed(&data).redirection {
        Some(RedirectForm::Html { html_data }) => {
            assert!(html_data.contains("mdpayacs/3ds-method"));
        }
        other => panic!("se esperaba un redirect HTML, salió {other:?}"),
    }
    // Y el id tiene que estar para poder mandar el PATCH de continuación.
    assert_eq!(
        connector_transaction_id(&data).as_deref(),
        Some("84667286332")
    );
}

#[test]
fn waiting_with_challenge_params_posts_the_creq_to_the_acs() {
    let data = convert(waiting_with_challenge_params(), 200);
    assert_eq!(data.status, enums::AttemptStatus::AuthenticationPending);
    match parsed(&data).redirection {
        Some(RedirectForm::Form {
            endpoint,
            method,
            form_fields,
        }) => {
            assert!(endpoint.starts_with("https://3ds-acs.test.modirum.com/mdpayacs/creq;token="));
            assert_eq!(*method, common_utils::request::Method::Post);
            assert!(form_fields.contains_key("creq"));
            // El gateway de cert no manda `sessionData`, así que el campo no debe inventarse.
            assert!(!form_fields.contains_key("threeDSSessionData"));
        }
        other => panic!("se esperaba un form al ACS, salió {other:?}"),
    }
}

// =============================================================================================
//  4. PSync
// =============================================================================================

#[test]
fn psync_without_transaction_status_still_reads_as_charged() {
    // Las 12 respuestas de INQUIRY de la evidencia llegan SIN `transactionStatus`. Si el estado
    // dependiera de ese campo, toda venta cobrada se sincronizaría como Pending para siempre.
    let data = convert_sync(sync_approved_sale(), 200);
    assert_eq!(data.status, enums::AttemptStatus::Charged);
    assert_eq!(
        connector_transaction_id(&data).as_deref(),
        Some("84667286294")
    );
}

#[test]
fn psync_by_order_reads_the_transaction_out_of_the_array() {
    let data = convert_sync(sync_order_response(), 200);
    assert_eq!(data.status, enums::AttemptStatus::Charged);
    assert_eq!(
        connector_transaction_id(&data).as_deref(),
        Some("84667286294"),
        "el orderResponse no puede perder el ipgTransactionId que trae adentro"
    );
}

#[test]
fn psync_of_an_order_with_two_transactions_keeps_the_primary_one() {
    // La orden de una anulación trae [SALE, VOID]. Quedarse con la última mapearía el VOID.
    let data = convert_sync(sync_order_of_a_voided_sale(), 200);
    assert_eq!(
        connector_transaction_id(&data).as_deref(),
        Some("84667286296"),
        "se debe sincronizar con la transacción primaria (la SALE), no con el VOID"
    );
}

#[test]
fn psync_of_a_declined_sale_fails_with_the_only_reason_the_gateway_left() {
    // Traído en vivo: el PSync de un rechazo llega con HTTP 200, sin `transactionStatus`, sin
    // `errorMessage` y con un `processor` que sólo trae `avsResponse`. Todo el motivo está en
    // `approvalCode`, así que el fallback sobre ese campo es lo único que evita que el rechazo
    // llegue al comercio sin código ni texto.
    let data = convert_sync(sync_of_a_declined_sale(), 200);
    assert_eq!(data.status, enums::AttemptStatus::Failure);
    let error = data
        .response
        .as_ref()
        .expect_err("un rechazo debe salir por Err");
    assert_eq!(error.code, "-11101");
    assert_eq!(error.message, "installment not supported");
    assert_eq!(error.reason.as_deref(), Some("installment not supported"));
    assert_eq!(error.attempt_status, Some(enums::AttemptStatus::Failure));
    // El id tiene que sobrevivir al rechazo: sin él no se puede volver a consultar ni conciliar.
    assert_eq!(
        error.connector_transaction_id.as_deref(),
        Some("84667287090")
    );
    // El `processor` real no trae `responseCode`/`responseMessage`, así que no se puede inventar
    // un código de red: los tres campos quedan vacíos.
    assert_eq!(error.network_decline_code, None);
    assert_eq!(error.network_advice_code, None);
    assert_eq!(error.network_error_message, None);
}

/// FALLA CONOCIDA (documentada, no arreglada acá): el PSync de una venta ANULADA vuelve
/// `Charged`.
///
/// El gateway devuelve `transactionType: SALE` + `transactionResult: APPROVED` y avisa que la
/// plata se liberó **sólo** en `transactionState: VOIDED`, que `map_status` no mira. Verificado
/// en vivo el 2026-08-12 contra cert por los dos caminos del PSync (por `ipgTransactionId` y por
/// `orderId`).
///
/// Este test fija el comportamiento ACTUAL para que el arreglo lo rompa a propósito. Lo correcto
/// sería `Voided`.
#[test]
fn psync_of_a_voided_sale_reports_voided_not_charged() {
    // Verificado en vivo contra certificación: al consultar una venta que después se anuló, el
    // gateway devuelve el tipo y el estado de la VENTA (`transactionType: SALE`,
    // `transactionStatus: APPROVED`) pero con `transactionState: VOIDED`. Ignorar ese campo
    // reportaba el pago como cobrado — plata que el comercio cree haber cobrado y no cobró.
    let by_transaction = convert_sync(sync_of_a_voided_sale(), 200);
    assert_eq!(by_transaction.status, enums::AttemptStatus::Voided);

    // Lo mismo por la consulta por orden, que es la otra vía del PSync.
    let by_order = convert_sync(sync_order_of_a_voided_sale(), 200);
    assert_eq!(by_order.status, enums::AttemptStatus::Voided);
}

// =============================================================================================
//  5. Rechazos que NO pasan por el TryFrom: HTTP 409 / 400 -> build_error_response
// =============================================================================================

#[test]
fn declined_3ds_409_keeps_the_gateway_code_and_transaction_id() {
    let error = error_response(declined_3ds_409(), 409);
    assert_eq!(error.code, "50716");
    assert_eq!(error.status_code, 409);
    assert_eq!(
        error.connector_transaction_id.as_deref(),
        Some("84667286319"),
        "sin el id el rechazo no se puede consultar ni conciliar"
    );
    assert_eq!(
        error.reason.as_deref(),
        Some("Transaction declined. 3D Secure authentication failed.")
    );
    // Este 409 no trae bloque `processor`, así que no hay códigos de red que publicar.
    assert_eq!(error.network_decline_code, None);
    assert_eq!(error.network_error_message, None);
}

/// FALLA CONOCIDA (documentada, no arreglada acá): en el camino de error, el `message` que ve el
/// comercio es el `responseType` genérico (`GatewayDeclined`) y el motivo real queda sólo en
/// `reason`. `payment_response.rs` guarda `err.message` en `error_message` del intento, así que
/// los 107 rechazos 409/400 de la evidencia llegan al comercio etiquetados "GatewayDeclined".
///
/// El camino hermano (rechazo con HTTP 2xx, dentro del `TryFrom`) hace lo contrario: pone el
/// texto real en `message`. Este test fija la asimetría actual.
#[test]
fn declined_message_is_the_generic_response_type_bug() {
    let error = error_response(declined_3ds_409(), 409);
    assert_eq!(
        error.message, "GatewayDeclined",
        "comportamiento actual; el texto útil está en `reason`"
    );

    // Mismo problema por el 400 de validación, que además no trae `responseType`: ahí el
    // `message` termina siendo la constante genérica del repo.
    let error = error_response(invalid_input_400(), 400);
    assert_eq!(error.code, "INVALID_INPUT");
    assert_eq!(error.message, hyperswitch_interfaces::consts::NO_ERROR_MESSAGE);
    // El detalle sí sobrevive, con el campo que el gateway señaló.
    let reason = error.reason.expect("el detalle del 400 no puede perderse");
    assert!(reason.contains("softDescriptor"));
    assert!(reason.contains("Invalid request input"));
}

/// FALLA CONOCIDA (documentada, no arreglada acá): el `responseCode3dSecure` se descarta en el
/// camino de error.
///
/// `FiservemeaErrorResponse` no declara `secure3dResponse` y `build_error_response` fija
/// `connector_metadata: None`. Los 409 son el desenlace de 51+19+16 = 86 respuestas reales con
/// `secure3dResponse`, o sea que justamente en los rechazos de 3DS —donde el código de
/// autenticación es el dato que explica el rechazo— no queda registrado en ninguna parte. En el
/// camino 2xx sí se publica (ver `frictionless_3ds_code_travels_in_connector_metadata`).
#[test]
fn three_ds_response_code_survives_the_error_path() {
    // 11 de las 22 filas 3DS del checklist terminan en este camino (HTTP 409), y el
    // `responseCode3dSecure` es justamente el dato que Fiserv pide informar por caso: si el
    // conector lo descarta, la evidencia de homologación no se puede armar desde Hyperswitch.
    for raw in [
        declined_3ds_409(),
        declined_3ds_409_with_cardholder_info(),
        declined_data_only_without_transaction_id(),
    ] {
        let esperado = raw["secure3dResponse"]["responseCode3dSecure"]
            .as_str()
            .unwrap()
            .to_string();
        let error = error_response(raw, 409);
        let metadata = error
            .connector_metadata
            .expect("el responseCode3dSecure tiene que llegar al ErrorResponse");
        assert_eq!(
            metadata.peek()["responseCode3dSecure"].as_str(),
            Some(esperado.as_str())
        );
    }
}

/// El `cardholderInfo` que el emisor manda para mostrarle al comprador también se descarta:
/// `FiservemeaSecure3dResponse` sólo declara `responseCode3dSecure`.
#[test]
fn cardholder_info_is_not_surfaced_anywhere_bug() {
    let raw = declined_3ds_409_with_cardholder_info();
    let expected = raw["secure3dResponse"]["cardholderInfo"]
        .as_str()
        .unwrap()
        .to_string();
    let error = error_response(raw, 409);
    let seen = format!("{} {:?}", error.message, error.reason);
    assert!(
        !seen.contains(&expected),
        "comportamiento actual: el texto para el comprador no se publica"
    );
}

#[test]
fn the_issuer_decline_422_publishes_the_iso_code_for_the_retry_engine() {
    // Es el rechazo más común en producción y el único que trae el `processor` completo. Los
    // códigos de red son los que gobiernan los reintentos: sin ellos el motor de recovery
    // reintenta contra un "Do not honour" definitivo.
    let error = error_response(issuer_decline_422(), 422);
    assert_eq!(error.status_code, 422);
    // Ojo: `code` es el código del GATEWAY (50005), no el ISO del emisor (05). El ISO viaja
    // aparte, en `network_decline_code`.
    assert_eq!(error.code, "50005");
    assert_eq!(error.reason.as_deref(), Some("Do not honour"));
    assert_eq!(error.network_decline_code.as_deref(), Some("05"));
    assert_eq!(error.network_error_message.as_deref(), Some("Do not honour"));
    assert_eq!(error.network_advice_code, None);
    assert_eq!(
        error.connector_transaction_id.as_deref(),
        Some("84668174890")
    );
    // Misma asimetría que en el 409: el `message` es el `responseType` genérico.
    assert_eq!(error.message, "EndpointDeclined");
}

#[test]
fn psync_of_an_issuer_decline_carries_the_iso_code_as_the_error_code() {
    // Por el camino 2xx (el PSync) el `processor` viene completo, así que acá sí el código que
    // ve el comercio es el ISO del emisor y el texto es el del procesador.
    let data = convert_sync(sync_of_an_issuer_declined_sale(), 200);
    assert_eq!(data.status, enums::AttemptStatus::Failure);
    let error = data.response.as_ref().expect_err("debe ser Err");
    assert_eq!(error.code, "05");
    assert_eq!(error.message, "Do not honour");
    assert_eq!(error.network_decline_code.as_deref(), Some("05"));
    assert_eq!(error.network_error_message.as_deref(), Some("Do not honour"));
    assert_eq!(
        error.connector_transaction_id.as_deref(),
        Some("84668174890")
    );
}

#[test]
fn a_decline_without_a_transaction_id_still_carries_its_reason() {
    // El Data Only rechazado falla antes de crear la transacción: no hay `ipgTransactionId`.
    // El conector cae al `orderId` para el PSync (ver `build_sync_url`), pero el `ErrorResponse`
    // se queda sin id, así que el código y el motivo son lo único que le llega al comercio.
    let error = error_response(declined_data_only_without_transaction_id(), 409);
    assert_eq!(error.code, "50655");
    assert_eq!(error.connector_transaction_id, None);
    assert_eq!(error.reason.as_deref(), Some("Unable to verify card enrollment"));
}

#[test]
fn no_real_decline_arrives_without_a_code_or_a_reason() {
    // Barrido sobre todas las formas de rechazo capturadas, por los dos caminos: ninguna puede
    // terminar en el `NO_ERROR_CODE`/`NO_ERROR_MESSAGE` genérico, porque un rechazo sin motivo
    // es un rechazo que el comercio no puede explicarle a su cliente.
    for (name, raw, status) in [
        ("409 3DS", declined_3ds_409(), 409),
        (
            "409 3DS con cardholderInfo",
            declined_3ds_409_with_cardholder_info(),
            409,
        ),
        (
            "409 Data Only",
            declined_data_only_without_transaction_id(),
            409,
        ),
        ("422 rechazo del emisor", issuer_decline_422(), 422),
    ] {
        let error = error_response(raw, status);
        assert_ne!(
            error.code,
            hyperswitch_interfaces::consts::NO_ERROR_CODE,
            "{name} llegó sin código"
        );
        assert!(
            error.reason.is_some(),
            "{name} llegó sin motivo"
        );
    }

    // Y el rechazo que llega con HTTP 2xx (el PSync de una venta rechazada), que sale por el
    // `TryFrom`.
    let data = convert_sync(sync_of_a_declined_sale(), 200);
    let error = data.response.as_ref().expect_err("debe ser Err");
    assert_ne!(error.code, hyperswitch_interfaces::consts::NO_ERROR_CODE);
    assert_ne!(
        error.message,
        hyperswitch_interfaces::consts::NO_ERROR_MESSAGE
    );
}

// =============================================================================================
//  6. Ninguna respuesta aprobada se queda sin id para sincronizar
// =============================================================================================

#[test]
fn every_approved_response_carries_an_id_to_sync_with() {
    for (name, raw) in [
        ("sale aprobada", approved_sale()),
        ("sale con token GW", approved_sale_with_gateway_token()),
        ("sale con network token", approved_sale_with_network_token()),
        ("3DS frictionless", frictionless_authenticated()),
        ("3DS rechazado pero aprobado", three_ds_rejected_but_approved()),
        ("void", approved_void()),
        ("WAITING con 3DSMethod", waiting_with_three_ds_method()),
        ("WAITING con desafío", waiting_with_challenge_params()),
    ] {
        let data = convert(raw, 200);
        assert!(
            connector_transaction_id(&data).is_some(),
            "{name} quedó sin connector_transaction_id: el pago no se puede sincronizar"
        );
    }
}
