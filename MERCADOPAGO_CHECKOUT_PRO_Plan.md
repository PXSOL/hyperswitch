# Mercado Pago Checkout Pro — Plan de Implementación en Hyperswitch

> **Companion de:** `MERCADOPAGO_CHECKOUT_PRO_Documentacion.md` (manual del API).
> **Estado (actualizado 2026-08-15): IMPLEMENTADO en branch `enzodossantos/mercadopago-checkout-pro`** (37 archivos; sin commitear aún) y **validado en vivo contra MP** con el dev server: Authorize crea la preferencia real (payload auditado en logs: monto 150000→1500.00 OK, external_reference=attempt_id, back_urls públicas con base_url ngrok / omitidas con localhost, auto_return, notification_url), `requires_customer_action` + startpay→init_point real, force-sync por search (vacío→pendiente, sin error), retorno simulado con `payment_id=null` → PSync + 302 firmado al return_url del merchant. `cargo check` connectors+router OK, 5/5 tests unitarios nuevos OK. Falta: pago real con tarjeta APRO (navegador) para la pata pagada + refund.
> **Code review (2026-08-15, subagente + verificación adversarial): 5 hallazgos MP, 4 arreglados y re-validados en vivo:** (1) el PSync ya NO usa el `payment_id` del query string del retorno (input del comprador → sustitución de pagos / kill con ids truchos): la promoción va SOLO por búsqueda de `external_reference` — verificado con retorno atacante simulado (0 fetches del id trucho); (2) un pago Rejected/Cancelled en la búsqueda NO se promueve ni marca Failure (la sesión hosted permite reintentar; un Failure además bloquea syncs futuros) → queda esperando; (3) la búsqueda vacía preserva el status actual y el fallback aplica solo a attempts wallet (un card-flow sin txn id vuelve a dar MissingConnectorTransactionID, no resucita); (4) `filter_public_url` parsea el host (url::Url + loopback/privadas/*.localhost) en vez de substring, con warn al descartar; PII del payer de la preferencia en `Secret`. **Aceptado como limitación documentada:** webhooks `payment` que llegan antes de la promoción del id no correlacionan (el body solo trae `data.id`; sin llamada de red no hay mapeo) — mitigado por retries de MP + el force-sync de api2. La review también encontró 4 hallazgos de fiservemea ya mergeado (fuera de alcance acá — ver reporte de sesión). Verificado contra el código el 2026-07-30 y pasado por revisión adversarial (hallazgos incorporados). **Novedad:** el lado api2 ya está implementado (worktree `api2-wt-mp-checkout-pro`): OAuth multi-app con la 2.ª app de MP, medio de pago `MercadoPagoV2CheckoutPro`, y el MCA que api2 crea en Hyperswitch ya viene con `wallet/mercado_pago` habilitado — este plan es el que hace que ese MCA pueda cobrar. Branch sugerido: `enzodossantos/mercadopago-checkout-pro`.
> **Regla de la sesión:** no ejecutar `cargo build/test` pesados en esta máquina; la verificación de compilación queda para CI o para una corrida explícita del usuario.

---

## 1. Contexto

El fork ya tiene un connector `mercadopago` completo para el flujo **API con token de tarjeta** (tokenización `/v1/card_tokens` + `POST /v1/payments`, PSync, capture, void, refunds, webhooks firmados). Se necesita agregar **Checkout Pro**: crear una *preferencia* (`POST /checkout/preferences`), redirigir al comprador al `init_point` (página alojada de MP donde puede pagar con dinero en cuenta, tarjetas, efectivo o cuotas sin tarjeta) y resolver el resultado de forma asíncrona.

La dificultad central: **el `payment_id` de MP no existe hasta que el comprador paga**. El connector debe devolver un redirect sin transaction id (`ResponseId::NoResponseId`) y "promover" el id real en el primer PSync exitoso. Este patrón ya existe en el repo (zen, mifinity, iatapay) y toda la mecánica del router fue verificada (ver §6).

## 2. Decisión de diseño

**Elegido:** nueva variante wallet sin campos `WalletData::MercadoPagoCheckoutPro {}` que mapea al `PaymentMethodType::MercadoPago` **ya existente** (`common_enums/src/enums.rs:2025`). El merchant confirma con:

```json
{
  "payment_method": "wallet",
  "payment_method_type": "mercado_pago",
  "payment_method_data": { "wallet": { "mercado_pago_checkout_pro": {} } }
}
```

Alternativas descartadas:
- **Flag en metadata sobre el flujo card**: el merchant no tiene datos de tarjeta para mandar en `payment_method_data`, y el pago final puede ser wallet/efectivo → semánticamente incorrecto e invisible para routing/dashboard.
- **Reutilizar `MercadoPagoSdk` con `token` opcional**: contamina el contrato del flujo SDK existente y vuelve ambiguo el branching.

Como el PMT ya existe, **no se toca** common_enums, euclid, kgraph, payment_methods/helpers ni los mapeos PMT→PM. El costo real es la variante en api_models/domain_models + ~46 match arms mecánicos (10 core + 36 en connectors; lista exacta en §3.1).

### 2.1 Flujo end-to-end: quién recibe cada redirect (Pxsol ↔ Hyperswitch ↔ MP)

Pregunta clave del equipo: *"Hyperswitch me devuelve una URL, redirijo al user; cuando vuelve, ¿lo manda a mi API o a Hyperswitch?"* — Respuesta: **el comprador siempre vuelve primero a Hyperswitch**; Pxsol lo recibe recién después, con el pago ya sincronizado. Nadie de Pxsol habla con MP.

```
api2 (gateway)                Hyperswitch                    Mercado Pago            Comprador
  │ POST /payments                │                                │                     │
  │  return_url = URL de Pxsol ──►│                                │                     │
  │                               │ POST /checkout/preferences ───►│                     │
  │                               │   back_urls = router_return_url│                     │
  │                               │◄── { init_point } ─────────────│                     │
  │◄─ next_action.redirect_to_url │                                │                     │
  │   (URL startpay de HS)        │                                │                     │
  │── 302 comprador a startpay ────────────────────────────────────────────────────────►│
  │                               │◄── GET startpay ───────────────────────────────────│
  │                               │─── 302 a init_point ──────────────────────────────►│
  │                               │                                │◄──── paga ─────────│
  │                               │◄── 302 back_url (payment_id, status, ext_ref…) ────│
  │                               │ [PSync: search por external_reference,             │
  │                               │  persiste el payment_id real]  │                     │
  │◄──────────────────────────────│─── 302 a return_url de Pxsol (payment_id HS, status)│
  │ GET /payments/{id}?force_sync │                                │                     │
  │ (InteractsWithHyperswitch) ──►│                                │                     │
```

1. **api2 crea el payment** en Hyperswitch (`payment_method: wallet`, `payment_method_type: mercado_pago`, `payment_method_data.wallet.mercado_pago_checkout_pro: {}`) con `return_url` = la página post-pago de Pxsol.
2. Hyperswitch responde `next_action.redirect_to_url` — es la **URL startpay de Hyperswitch**, no el `init_point` (verificado: `core/payments/transformers.rs:3147-3164`). Pxsol solo redirige ahí; Hyperswitch reenvía a MP.
3. El connector pone en `back_urls` de la preferencia el **`router_return_url`**, que Hyperswitch construye como `{hs_base}/payments/{payment_id}/{merchant_id}/redirect/response/mercadopago` (verificado: `create_redirect_url`, `core/payments/helpers.rs:1224-1232`). **El comprador vuelve de MP a Hyperswitch, no a Pxsol.**
4. En ese endpoint Hyperswitch dispara el **PSync** automáticamente (macro default `Trigger`) → el connector busca el pago por `external_reference` / parsea los query params → persiste el `payment_id` real y el estado.
5. Recién entonces Hyperswitch hace 302 del navegador al `return_url` de Pxsol (el del paso 1) con `payment_id` (el de Hyperswitch) y `status` como query params → webroot muestra el checkout post-pago.
6. Confirmación server-side: api2 hace `GET {mithras}/payments/{id}?force_sync=true` contra **Hyperswitch** (el `InteractsWithHyperswitch::reconcile` que ya usan Payway/Stripe/MP-card) — nunca contra MP.
7. Red de seguridad para el comprador que no vuelve: webhook de MP → Hyperswitch (ya implementado en el connector) + el PSync bajo demanda de api2.

### 2.2 Referencia: cómo lo hace PayPal wallet (y en qué nos apartamos)

`WalletData::PaypalRedirect` es el análogo más cercano en el repo y sirve de molde para la variante, el `AuthenticationPending` y el redirect. Pero hay una diferencia estructural que cambia el post-retorno:

| | PayPal wallet | MP Checkout Pro (este plan) |
|---|---|---|
| Variante | `WalletData::PaypalRedirect` (`paypal/transformers.rs:991`) | `WalletData::MercadoPagoCheckoutPro {}` (nueva) |
| Al autorizar crea | una **order** de PayPal → el txn id existe ya (`ConnectorTransactionId`) | una **preferencia** → el `payment_id` NO existe hasta que el comprador paga (`NoResponseId`) |
| URL de retorno que le pasa al PSP | `complete_authorize_url` (`paypal/transformers.rs:996-1000`) | `router_return_url` (back_urls) |
| Al volver el comprador | **CompleteAuthorize**: 2.º call server-to-server para capturar la order aprobada | **PSync**: no hay 2.º call de captura — MP ya creó y capturó el pago solo; solo hay que encontrarlo (search por `external_reference`) y promover el id |
| `ConnectorRedirectResponse` | impl explícito, devuelve `Trigger` para todo (`paypal.rs:2224-2239`) | no hace falta: el macro default ya devuelve `Trigger` (verificado §6) |

Moraleja: copiamos de PayPal la **forma** (variante wallet fieldless + `AuthenticationPending` + `redirection_data`), pero el post-retorno se modela como **zen/mifinity** (sync por referencia + promoción del id), no como PayPal (CompleteAuthorize), porque en Checkout Pro el pago se completa dentro de MP sin intervención nuestra.

## 3. Cambios — inventario por fase

### Fase 1 — Variante `WalletData` (plomería mecánica)

⚠️ **Sintaxis del pattern:** la variante es *struct fieldless*, así que los arms nuevos son `WalletData::MercadoPagoCheckoutPro {}` (o `{ .. }`) — **`(_)` no compila** sobre una variante struct.

**Core (10 sitios, todos exhaustivos sin wildcard):**

| Archivo | Cambio |
|---|---|
| `crates/api_models/src/payments.rs` | (a) variante `MercadoPagoCheckoutPro {}` en `enum WalletData` (junto a `MercadoPagoSdk` `:3901`, con `#[schema(title = "MercadoPagoCheckoutPro")]`); (b) arm en `get_payment_method_type()` `:2892` → `PaymentMethodType::MercadoPago`; (c) sumar al `\|`-chain `=> None` de `get_billing_address` (termina `:3992`) |
| `crates/hyperswitch_domain_models/src/payment_method_data.rs` | variante espejo `:304`; arm en `From<api WalletData>` `:1264`; arm en `get_payment_method_type()` `:2122` |
| `crates/hyperswitch_connectors/src/utils.rs` | variante en `PaymentMethodDataType` `:5562`; arm en `From<PaymentMethodData>` (sub-match wallet termina `:5709`) |
| `crates/router/src/connector/utils.rs` | ídem: variante `:2577`; arm `:2712` |

Nota: `get_wallet_token` en ambos utils tiene `_ => Err(...)` (`hyperswitch_connectors/utils.rs:5926`) — no requiere cambio.

**Connectors (36 sitios en 28 archivos):** casi todos son `| WalletData::X... => Err(NotImplemented)` de un token, con **tres excepciones a mirar**:
- `amazonpay.rs:396` y `novalnet/transformers.rs:413,1679` usan el alias **`WalletDataPaymentMethod::`** (no `WalletData::`).
- `payme/transformers.rs:436` usa `ConnectorError::NotSupported` (no `NotImplemented`).

Lista completa (bajo `crates/hyperswitch_connectors/src/connectors/`):
`aci/transformers.rs:203` · `adyen/transformers.rs:2378` · `airwallex/transformers.rs:834` · `amazonpay.rs:396`* · `authorizedotnet/transformers.rs:546,2258` · `bankofamerica/transformers.rs:327,1115` · `barclaycard/transformers.rs:1562` · `bluesnap/transformers.rs:405` · `boku/transformers.rs:209` · `checkout/transformers.rs:142` · `cybersource/transformers.rs:320,2518` · `fiuu/transformers.rs:592` · `globepay/transformers.rs:92` · `mifinity/transformers.rs:194` · `multisafepay/transformers.rs:555,627,806` · `nexinets/transformers.rs:738` · `nmi/transformers.rs:653` · `noon/transformers.rs:354` · `novalnet/transformers.rs:413,1679`* · `nuvei/transformers.rs:1610` · `payme/transformers.rs:436`* · `paypal/transformers.rs:1103` · `shift4/transformers.rs:426` · `square/transformers.rs:142` · `stripe/transformers.rs:1214,1694` · `wellsfargo/transformers.rs:241,1331` · `worldpay/transformers.rs:190` · `zen/transformers.rs:519`

(Verificado por cross-check: todo match exhaustivo de `WalletData` en el repo ya tiene arm de `MercadoPagoSdk`, así que esa lista ES el blast radius completo. klarna no matchea `WalletData`.)

### Fase 2 — Connector `mercadopago`: flujo Checkout Pro

Todo en `crates/hyperswitch_connectors/src/connectors/mercadopago.rs` y `mercadopago/transformers.rs`.

**2.0 `ConnectorSpecifications` — PRIMERO, es un gate duro del router.** `validate_connector_against_payment_request` (default en `hyperswitch_interfaces/src/api.rs:619-658`, invocado desde `authorize_flow.rs:350-357`) rechaza con `NotSupported` cualquier Authorize cuyo `PaymentMethod::Wallet` / `PaymentMethodType::MercadoPago` no figure en `MERCADOPAGO_SUPPORTED_PAYMENT_METHODS` (`mercadopago.rs:1071-1105`, hoy solo Card). **Sin esta entrada, el connector nunca recibe la llamada.** Agregar (con vec propio — el vec existente se *mueve* al entry de Debit en `:1099`):

```rust
supported_payment_methods.add(
    enums::PaymentMethod::Wallet,
    enums::PaymentMethodType::MercadoPago,
    PaymentMethodDetails {
        mandates: enums::FeatureStatus::NotSupported,
        refunds: enums::FeatureStatus::Supported,
        supported_capture_methods: vec![enums::CaptureMethod::Automatic],
        specific_features: None,
    },
);
```

Corolarios verificados:
- **No hace falta validar capture manual en `try_from`**: el gate de arriba ya rechaza `Manual` a nivel flow (la lista solo tiene `Automatic`).
- `SequentialAutomatic` queda afuera a propósito (las entradas Card existentes tienen la misma limitación).

**2.1 Authorize — branch por payment method**

- `get_url`: si `req.request.payment_method_data` es `Wallet(MercadoPagoCheckoutPro {})` → `{base_url}/checkout/preferences`; si no, `/v1/payments` (actual).
- `get_request_body`: nuevo `MercadopagoPreferenceRequest`:
  - `items: [MercadopagoPreferenceItem]` — un ítem: `title` (description del payment o metadata `item.title`), `quantity: 1`, `unit_price` (`FloatMajorUnit` ya convertido), `currency_id` (`req.request.currency.to_string()`), `category_id` opcional desde metadata.
  - `external_reference: connector_request_reference_id` (igual que el flujo actual, `transformers.rs:530`). Estabilidad verificada: en v1 es `payment_attempt.attempt_id` (`hyperswitch_interfaces/src/api.rs:402-414`), idéntico entre Authorize y PSync del mismo attempt.
  - `back_urls { success, pending, failure }` — las tres = `router_data.request.router_return_url` (getter `get_router_return_url`, `utils.rs:1854`), **filtrando localhost** con el mismo criterio que hoy usa `notification_url` (`transformers.rs:423-429`); si queda `None`, omitir `back_urls` y `auto_return`.
  - `auto_return: "approved"` (solo si hay back_urls).
  - `notification_url` — reutilizar la lógica existente.
  - `payer { email, name, surname }` desde `request.email` / billing si están.
  - `statement_descriptor`, `binary_mode`, `payment_methods { installments, excluded_payment_types }`, `expiration_date_to` — opcionales, alimentados por `MercadopagoMetadata` extendida con `checkout_pro: Option<CheckoutProOptions>` (structs nuevos; sin campos obligatorios).
  - **Importante**: el branch por `PaymentMethodData` va ANTES del requisito de `payment_method_token` — hoy `MercadopagoPaymentsRequest::try_from` exige token (`transformers.rs:359-369`) y explotaría para wallet. El flujo wallet NO pasa por tokenización (gate verificado: `[tokenization] mercadopago = { payment_method = "card" }`, `config/development.toml:1012` + `core/payments.rs:6906-6909`; además `PaymentMethodTokenizationData::try_from` es infalible para wallets) → **no cambiar** ese config.
- `get_headers`: sin cambios (ya manda `X-Idempotency-Key` + `x-platform-id`).
- `handle_response`: parsear enum untagged (patrón `ZenPaymentsResponse`, declarado en `zen/transformers.rs:867-872`, dispatch `:904-915`):
  ```rust
  #[serde(untagged)]
  enum MercadopagoAuthorizeResponse {
      Payment(MercadopagoPaymentsResponse),      // actual: { id: i64, status, ... }
      Preference(MercadopagoPreferenceResponse), // { id: String, init_point: String, ... }
  }
  ```
  Seguro en ambos órdenes **solo si** `MercadopagoPreferenceResponse.init_point` e `id` son campos requeridos (NO `Option`/`default`): preference falla `id: i64`, payment falla por falta de `init_point`.
  Branch `Preference` → RouterData con:
  - `status: AttemptStatus::AuthenticationPending`
  - `resource_id: ResponseId::NoResponseId`
  - `redirection_data: Box::new(Some(RedirectForm::Form { endpoint: init_point, method: Method::Get, form_fields: HashMap::new() }))` — ojo: el campo es `Box<Option<RedirectForm>>` (iatapay `transformers.rs:381-391`); evita parsear `url::Url`.
  - `connector_metadata: Some(json!({ "preference_id": id }))`
  - `connector_response_reference_id: Some(external_reference)`
- **Imports nuevos en `mercadopago/transformers.rs`**: `common_utils::request::Method`, `hyperswitch_domain_models::router_response_types::RedirectForm`, `std::collections::HashMap`, y `PaymentsSyncRouterData` en el import de `types::{...}` (hoy no está).

**2.2 PSync — búsqueda por referencia + promoción del id**

Reemplazar el `get_url` actual (`mercadopago.rs:413-429`, hoy hard-fail sin txn id) por cascada:

1. `connector_transaction_id` disponible → `GET /v1/payments/{id}` (actual).
2. Si no, `encoded_data` (query string crudo del retorno, verificado `payment_status.rs:308` → `PaymentsSyncData.encoded_data`, `router_request_types.rs:813-814`) contiene `payment_id`/`collection_id` válido (≠ `"null"`, numérico) → `GET /v1/payments/{payment_id}`. Parsear con `serde_urlencoded` (patrón adyen `adyen.rs:689-698`).
3. Si no → `GET /v1/payments/search?external_reference={connector_request_reference_id}&sort=date_created&criteria=desc` (`connector_request_reference_id` está en `RouterData` root, `router_data.rs:65`).

Nota load-bearing ya existente: `validate_psync_reference_id` de mercadopago ya devuelve `Ok(())` incondicional (`mercadopago.rs:258-266`) — con el default del trait, un attempt `NoResponseId` ni llegaría al connector. **No tocar.**

`handle_response` con enum untagged:
```rust
#[serde(untagged)]
enum MercadopagoPSyncResponse {
    Search(MercadopagoSearchResponse), // { paging, results: Vec<MercadopagoPaymentsResponse> }
    Payment(MercadopagoPaymentsResponse),
}
```
⚠️ **Trampa serde (hallazgo de review):** `Search` va primero y `results` debe ser **requerido** (sin `#[serde(default)]`). Si `results` tuviera default, cualquier respuesta de pago individual deserializaría como `Search { results: [] }` y todos los PSync devolverían "el comprador no pagó" silenciosamente.
- `Search` con `results` vacío → `status: AuthenticationPending`, `resource_id: NoResponseId` (el comprador aún no pagó; **no** es error).
- `Search` con resultados → tomar `results[0]` y seguir el camino normal.
- El `resource_id: ConnectorTransactionId(id)` devuelto **se persiste** en el attempt (verificado: `payment_response.rs:1709-1731` + `:1917-1919`, `PaymentAttemptUpdate::ResponseUpdate`) → capture/void/refund/webhooks siguientes ya tienen el id real. Patrón de promoción: `mifinity/transformers.rs:349-388`. Verificado también que un PSync posterior con `authentication_data: None` **no** pisa el redirect guardado (AsChangeset sin `treat_none_as_null`, `diesel_models/payment_attempt.rs:1018-1020`).
- Diagnóstico: un 200 con shape inesperado cae en "data did not match any variant" (`ResponseDeserializationFailed`) sin detalle de campos — costo conocido del patrón untagged (zen lo acepta igual).

**2.3 Redirect return**: **sin cambios** — mercadopago ya recibe `CallConnectorAction::Trigger` por `default_imp_for_connector_redirect_response!` (`default_implementations.rs:1559-1574`, mercadopago listado en `:1636`), que dispara el PSync al volver el comprador. No implementar `ConnectorRedirectResponse`.

**2.4 Webhooks**: **sin cambios necesarios** (la revisión refutó la necesidad que planteaba el borrador). El topic `merchant_order` ya cae en `MercadopagoWebhookAction::Unknown` → `IncomingWebhookEvent::EventNotSupported` (`transformers.rs:1128`, vía `mercadopago.rs:1025-1046`), y el router responde 200 limpio sin procesar (`core/webhooks/incoming.rs:289-302,345-360`) — `get_webhook_event_type` corre antes de la verificación de firma y del reference-id lookup. El topic `payment` matchea por `ConnectorTransactionId` una vez promovido el id; si llega antes, MP reintenta con backoff (el PSync del redirect suele ganar la carrera). Gap menor preexistente, no bloqueante: un body que no parsea como ninguno de los dos formatos y sin `topic` en query → `WebhookEventTypeNotFound` (`mercadopago.rs:1045`). Opcional: agregar variante explícita `MerchantOrderUpdated` solo por legibilidad — cero cambio observable.

**2.5 Void**: sin cambios de código. Con `NoResponseId` el void falla con `MissingConnectorTransactionID` — comportamiento aceptado: la preferencia expira sola (configurable vía `expiration_date_to`). Documentado en §5.

**2.6 Detalle cosmético preexistente**: `get_currency_unit()` devuelve `Minor` (`mercadopago.rs:186-190`) pero el converter real es `FloatMajorUnitForConnector` — verificado que `get_currency_unit` no tiene consumidores (metadata muerta); `convert_amount` usa el converter directo. No es bug, pero el comentario en el código engaña; opcional corregirlo a `Base`.

### Fase 3 — Configuración

| Archivo | Cambio |
|---|---|
| `crates/connector_configs/toml/{development,sandbox,production}.toml` | En el bloque `[mercadopago]` (dev `:6852`, sandbox `:6835`, prod `:5521`) agregar habilitación dashboard: `[[mercadopago.wallet]]` con `payment_method_type = "mercado_pago"` (plantilla: `[[bluecode.wallet]]` dev `:6760-6762`). `payment_experience = "redirect_to_url"` aparece en bloques `pay_later` (flexiti `:6786-6788`) — antes de copiarlo a un bloque wallet, grep por un `*.wallet` existente que lo use; si ninguno lo lleva, omitirlo |
| `config/*.toml` | **Nada obligatorio**: `base_url` ya apunta a `https://api.mercadopago.com` (preferences vive ahí mismo) y el gate de tokenización debe quedar `payment_method = "card"`. Opcional: `[pm_filters.mercadopago]` si se quiere filtrar por país/moneda |
| `crates/payment_methods/src/configs/payment_connector_required_fields.rs` | Opcional (hoy no hay entrada mercadopago); útil si se quiere exigir `email` en dashboard |
| `crates/openapi` | La variante fieldless no necesita registro de schema nuevo; la regeneración del spec (`cargo r -p openapi`) queda **diferida** (regla no-cargo) |

### Fase 4 — Tests y muestras (opcional, no bloqueante)

- `crates/test_utils/src/connector_auth.rs`: no existe campo `mercadopago` (el test actual `crates/router/tests/connectors/mercadopago.rs` está roto de antes: usa `Connector::Plaid` en `:16` y un campo auth inexistente). Arreglarlo es deuda separada; no lo bloquea este plan.
- Agregar ejemplo curl de preferencia a la doc (ya está en `MERCADOPAGO_CHECKOUT_PRO_Documentacion.md` §4).

## 4. Orden de implementación sugerido

1. Fase 1 core (api_models + domain_models + 2 utils)
2. Fase 1 connectors (36 arms — ojo con los 3 sitios con alias/`NotSupported`)
3. **Fase 2.0 `ConnectorSpecifications`** (gate duro — sin esto nada llega al connector)
4. Fase 2.1 Authorize
5. Fase 2.2 PSync
6. Fase 3 configs
7. Commit por fase (`feat(mercadopago): add checkout pro wallet variant`, `feat(mercadopago): checkout pro preference flow`, etc.).

## 5. Riesgos y edge cases

| Caso | Comportamiento planificado |
|---|---|
| Comprador nunca paga / cierra navegador | Attempt queda `AuthenticationPending`; PSync (manual o scheduler) busca por `external_reference` y devuelve vacío → sigue pendiente hasta expirar |
| Comprador vuelve con `payment_id=null` (abandono) | Parser de `encoded_data` descarta `"null"` → cae a búsqueda por referencia → vacío → pendiente |
| Webhook `payment` antes de la promoción del id | Lookup por `ConnectorTransactionId` falla → MP reintenta; el PSync del redirect resuelve primero en el caso típico |
| Dos pagos con el mismo `external_reference` (retry del comprador dentro del checkout) | Search ordenado `date_created desc` → toma el más reciente |
| `router_return_url` = localhost en dev | Se omite `back_urls`/`auto_return` (MP los rechaza); el resultado llega solo por webhook/PSync — para probar retorno usar túnel público |
| Capture manual solicitado | Rechazado a nivel flow por `validate_connector_against_payment_request` (`NotSupported`) — la lista wallet solo declara `Automatic` |
| Pagos `ticket` (Rapipago/Pago Fácil) quedan `pending` días | Default: permitirlos; excluibles vía metadata `checkout_pro.excluded_payment_types = ["ticket"]` |
| Refund de pago checkout pro | Sin cambios: una vez promovido el id, `POST /v1/payments/{id}/refunds` funciona igual |
| 200 con JSON inesperado en Authorize/PSync | `ResponseDeserializationFailed` genérico (limitación del untagged enum, igual que zen) |

## 6. Evidencia de verificación (mecánica del router)

| Suposición | Veredicto | Evidencia |
|---|---|---|
| Query params del retorno llegan al PSync del connector | ✅ | `routes/payments.rs:1211` → `payments.rs:3253` → `operations/payment_status.rs:308` → `transformers.rs:4332` (`PaymentsSyncData.encoded_data`) |
| Force-sync se dispara con attempt en `AuthenticationPending` | ✅ | `payment_status.rs:522-526` + `helpers.rs:3075-3085` (no está excluido) |
| `resource_id` de PSync persiste `connector_transaction_id` | ✅ | `payment_response.rs:548-578`, `:1709-1731`, `:1917-1919`; `diesel_models/payment_attempt.rs:3192-3226` |
| PSync posterior no borra `authentication_data` | ✅ | AsChangeset sin `treat_none_as_null`, `diesel_models/payment_attempt.rs:1018-1020` |
| Redirect return dispara PSync sin implementar `ConnectorRedirectResponse` | ✅ | macro default `Trigger`: `default_implementations.rs:1559-1574` (mercadopago `:1636`); consumo `payments.rs:3011-3029`; `services/api.rs:248` |
| Wallet no pasa por tokenización | ✅ | `config/development.toml:1012` + `core/payments.rs:6894-6925` (gate por `payment_method`) |
| `AuthenticationPending` → intent `RequiresCustomerAction` + `next_action.redirect_to_url` (startpay propio) | ✅ | `common_enums/transformers.rs:2106-2108`; `core/payments/transformers.rs:3102` + `:3147-3164`; `payment_response.rs:1741-1746` |
| `EventNotSupported` → ack 200 sin procesar | ✅ | `core/webhooks/incoming.rs:289-302, 345-360`; default `StatusOk` en `hyperswitch_interfaces/webhooks.rs:226-232` |
| `external_reference` estable entre Authorize y PSync | ✅ | = `attempt_id`, `hyperswitch_interfaces/api.rs:402-414` |
| Gate `validate_connector_against_payment_request` exige entry Wallet en specs | ✅ | `authorize_flow.rs:350-357` + `hyperswitch_interfaces/api.rs:619-658, 728-753` |
| Blast radius variante = 10 core + 36 connector arms (28 archivos) | ✅ | cross-check Mifinity vs MercadoPagoSdk arms = conjunto idéntico |

## 7. Verificación post-implementación (sin cargo pesado en esta máquina)

1. **Compilación**: correr en CI o cuando el usuario lo pida: `bash -lc 'cargo check -p api_models -p hyperswitch_domain_models -p hyperswitch_connectors'` (los 36 arms + core). No correr localmente sin aviso.
2. **Smoke del API MP (sin Hyperswitch)** — requiere access token TEST de MP:
   ```bash
   curl -X POST https://api.mercadopago.com/checkout/preferences \
     -H "Authorization: Bearer TEST-..." -H "Content-Type: application/json" \
     -d '{"items":[{"title":"Test","quantity":1,"currency_id":"ARS","unit_price":100.0}],
          "external_reference":"test-001","back_urls":{"success":"https://example.com/r","pending":"https://example.com/r","failure":"https://example.com/r"},"auto_return":"approved"}'
   ```
   → esperar `201` con `init_point`; abrir `init_point` y pagar con test user comprador; luego `GET /v1/payments/search?external_reference=test-001`.
3. **E2E Hyperswitch** (cuando haya entorno): crear MCA mercadopago con token TEST → payments/confirm con `mercado_pago_checkout_pro` → verificar `next_action.redirect_to_url` (URL startpay de Hyperswitch que reenvía a `init_point`) → pagar → verificar retorno + PSync promueve el id → refund.
4. **Webhooks**: exponer webhook por túnel, pagar, verificar firma OK y ack 200 de `merchant_order`.

## 8. Bloqueantes / pendientes del lado del usuario

1. **Credenciales**: ✅ resuelto 2026-07-30 — el usuario proveyó credenciales de prueba de MP Argentina (app 4173688184123580, test user vendedor `TESTUSER1627531232` / User ID 1963547549, site MLA) y se validaron en vivo contra el API: `GET /users/me` OK, `POST /checkout/preferences` → 201 con `init_point` real (preference id formato `{collector_id}-{uuid}`, o sea `id: String` — confirma el discriminador del enum untagged de §2.1), y `GET /v1/payments/search?external_reference=...` → 200 `{"results":[],"paging":{...}}` (confirma el shape asumido en §2.2: `results` presente aun vacío). Comprador de prueba también provisto: `TESTUSER1424056866` (User ID 1966179562) + tarjetas de prueba (ver Apéndice A de la Documentación). Hallazgo adicional validado: `POST /v1/payments` directo devuelve 401 `Unauthorized use of live credentials` con esta app (producto Checkout Pro solamente) — **no afecta este plan**, pero el flujo de tarjeta existente del connector necesitaría una app con Checkout API habilitado. El E2E del checkout se prueba en navegador (init_point + tarjeta titular `APRO`). (Las credenciales Fiserv provistas antes eran de fiservemea, ya aclarado.)
2. Confirmar defaults de producto: ¿excluir `ticket`? ¿`binary_mode`? ¿máximo de cuotas? (todos quedan configurables por metadata; defaults propuestos: no excluir, `binary_mode=false`, cuotas sin tope).
3. URL pública (ngrok/cloudflared) para probar `back_urls` y webhooks en dev.
