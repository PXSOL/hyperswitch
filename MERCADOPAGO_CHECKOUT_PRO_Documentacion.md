# Mercado Pago — Checkout Pro · Manual de Integración

> **Fuente:** Documentación oficial de Mercado Pago Developers (Checkout Pro, Preferencias, Notificaciones) — https://www.mercadopago.com.ar/developers/es/docs/checkout-pro/overview
> **Alcance:** Argentina (ARS) y demás países donde opera Mercado Pago (AR, BR, CL, CO, MX, PE, UY).
> **Nota:** Este documento resume el API de Checkout Pro para su implementación en Hyperswitch como flujo redirect del connector `mercadopago` existente. El diseño de integración Hyperswitch está en la sección 8 y el plan de implementación en `MERCADOPAGO_CHECKOUT_PRO_Plan.md`.

---

## Tabla de contenidos

1. [Introducción — qué es Checkout Pro](#1-introducción--qué-es-checkout-pro)
2. [Flujo end-to-end](#2-flujo-end-to-end)
3. [Credenciales y entorno de pruebas](#3-credenciales-y-entorno-de-pruebas)
4. [Crear preferencia — POST /checkout/preferences](#4-crear-preferencia--post-checkoutpreferences)
5. [Redirección y retorno del comprador (back_urls)](#5-redirección-y-retorno-del-comprador-back_urls)
6. [Notificaciones (Webhooks / IPN / merchant_orders)](#6-notificaciones-webhooks--ipn--merchant_orders)
7. [Consulta y post-procesamiento del pago](#7-consulta-y-post-procesamiento-del-pago)
8. [Diseño de integración en Hyperswitch](#8-diseño-de-integración-en-hyperswitch)

---

## 1. Introducción — qué es Checkout Pro

**Checkout Pro** es la solución *hosted checkout* de Mercado Pago: el comercio crea una **preferencia de pago** vía API y redirige al comprador a una página de pago alojada por Mercado Pago (`init_point`). Allí el comprador puede pagar con:

- Dinero en cuenta de Mercado Pago (wallet)
- Tarjetas de crédito y débito (con cuotas)
- Efectivo (Rapipago, Pago Fácil — según país)
- Cuotas sin tarjeta (Mercado Crédito)

Diferencias con la integración API actual del connector (`/v1/payments` + tokenización):

| | API (actual) | Checkout Pro (a agregar) |
|---|---|---|
| Captura de datos | Formulario propio + token de tarjeta | Página alojada por Mercado Pago |
| Medios de pago | Solo tarjeta | Wallet, tarjetas, efectivo, cuotas sin tarjeta |
| PCI | SAQ A-EP (token SDK) | SAQ A (todo en MP) |
| Flujo | Síncrono (respuesta inmediata) | Asíncrono (redirect + webhook/sync) |
| ID de pago | Conocido al autorizar | **Desconocido hasta que el comprador paga** |

---

## 2. Flujo end-to-end

```
Comercio                        Mercado Pago                     Comprador
   |                                 |                               |
   |-- POST /checkout/preferences -->|                               |
   |<-- { id, init_point } ----------|                               |
   |                                 |                               |
   |-- redirect 302 a init_point ------------------------------------>
   |                                 |<---- paga en página MP ------->|
   |                                 |                               |
   |<== webhook (topic=payment) =====|                               |
   |<-- redirect a back_url?payment_id=...&status=... ---------------|
   |                                 |                               |
   |-- GET /v1/payments/{id} ------->|   (confirmación server-side)  |
   |   o /v1/payments/search?external_reference=...                  |
```

Puntos críticos:

1. La creación de la preferencia **no crea un pago**: devuelve `id` (preference id, formato `{collector_id}-{uuid}`) e `init_point`. El `payment_id` recién existe cuando el comprador paga.
2. El resultado llega por **dos canales independientes**: el redirect de vuelta (`back_urls` con query params) y las notificaciones asíncronas (webhooks). Ninguno es garantizado por sí solo (el comprador puede cerrar el navegador), por eso la confirmación siempre debe validarse server-side.
3. La correlación entre la preferencia y el pago se hace vía **`external_reference`** (lo setea el comercio en la preferencia y MP lo copia al pago resultante).

---

## 3. Credenciales y entorno de pruebas

- **Autenticación:** `Authorization: Bearer {ACCESS_TOKEN}` — el mismo access token que ya usa el connector (`MercadopagoAuthType.api_key`). No se requieren credenciales adicionales.
- **Producción:** access token `APP_USR-...`.
- **Pruebas:** access token de **credenciales de prueba** (`TEST-...`) o de un **usuario de prueba** (test user). Con credenciales de prueba, `init_point` ya apunta al entorno de test — `sandbox_init_point` es legacy y no debe usarse.
- Para pagar en el checkout de prueba se necesita un **segundo test user** (comprador) o las tarjetas de prueba documentadas (APRO, CONT, OTHE, etc. como nombre del titular).

> ⚠️ **Importante para probar:** las credenciales Fiserv/FirstData (`cert.api.firstdata.com`) NO sirven para Mercado Pago. Se necesita un access token de MP (TEST- o de test user) desde https://www.mercadopago.com.ar/developers/panel/app → Credenciales.

> ⚠️ **back_urls no acepta `localhost`/`127.0.0.1`** — para probar el retorno del comprador en desarrollo se necesita una URL pública (p. ej. túnel ngrok/cloudflared). El connector actual ya filtra localhost en `notification_url` (`transformers.rs`), y el mismo criterio aplica a `back_urls`.

---

## 4. Crear preferencia — POST /checkout/preferences

```
POST https://api.mercadopago.com/checkout/preferences
Authorization: Bearer {ACCESS_TOKEN}
Content-Type: application/json
X-Idempotency-Key: {referencia única}
```

### Request — campos relevantes

```json
{
  "items": [
    {
      "id": "reserva-1234",
      "title": "Reserva Hotel — 2 noches",
      "description": "Habitación doble superior",
      "category_id": "travels",
      "quantity": 1,
      "currency_id": "ARS",
      "unit_price": 150000.00
    }
  ],
  "payer": {
    "name": "Juan",
    "surname": "Pérez",
    "email": "comprador@test.com",
    "identification": { "type": "DNI", "number": "12345678" }
  },
  "external_reference": "pay_XXXX_1",
  "back_urls": {
    "success": "https://comercio.com/retorno",
    "pending": "https://comercio.com/retorno",
    "failure": "https://comercio.com/retorno"
  },
  "auto_return": "approved",
  "notification_url": "https://comercio.com/webhooks/mercadopago",
  "statement_descriptor": "MI COMERCIO",
  "binary_mode": false,
  "expires": true,
  "expiration_date_to": "2026-08-01T12:00:00.000-03:00",
  "payment_methods": {
    "excluded_payment_types": [ { "id": "ticket" } ],
    "excluded_payment_methods": [],
    "installments": 12,
    "default_installments": 1
  },
  "metadata": {}
}
```

| Campo | Oblig. | Notas |
|---|---|---|
| `items[]` | ✅ | `title`, `quantity`, `unit_price` obligatorios. `unit_price` en **unidades mayores** (float). `currency_id` ISO-4217 (`ARS`, `UYU`). |
| `external_reference` | Recomendado | Clave de correlación con el pago. MP lo copia al objeto payment resultante. |
| `back_urls` | Recomendado | Ver §5. Sin `back_urls.success` no se puede usar `auto_return`. |
| `auto_return` | Opcional | `"approved"`: redirige solo pagos aprobados automáticamente (~40 s); pending/failure muestran botón "Volver al sitio". `"all"` también existe. |
| `notification_url` | Recomendado | URL de webhook específica de esta preferencia (además de la configurada a nivel aplicación). Máx 248 caracteres, https. |
| `binary_mode` | Opcional | `true` = sin estados intermedios (aprueba o rechaza); deshabilita medios de pago offline. |
| `expires` / `expiration_date_from/to` | Opcional | Ventana de validez del link (ISO-8601 con offset). |
| `payment_methods.excluded_payment_types` | Opcional | Ej. excluir `ticket` (efectivo) para evitar pagos pendientes de días. Tipos: `credit_card`, `debit_card`, `ticket`, `bank_transfer`, `account_money`, `digital_currency`, etc. |
| `payment_methods.installments` | Opcional | Máximo de cuotas ofrecidas. |
| `statement_descriptor` | Opcional | Texto en resumen de tarjeta. |
| `payer` | Opcional | Precarga datos en el checkout y mejora aprobación. |

### Response (201)

```json
{
  "id": "202809963-920c288b-4ebb-40be-966f-700250fa5370",
  "init_point": "https://www.mercadopago.com.ar/checkout/v1/redirect?pref_id=202809963-920c288b-...",
  "sandbox_init_point": "https://sandbox.mercadopago.com.ar/checkout/v1/redirect?pref_id=...",
  "collector_id": 202809963,
  "external_reference": "pay_XXXX_1",
  "date_created": "2026-07-30T10:00:00.000-04:00",
  "items": [ ... ],
  "back_urls": { ... },
  "notification_url": "..."
}
```

- **`init_point`** — URL a la que se redirige al comprador (GET). Con credenciales TEST ya opera en modo prueba.
- **`id`** — preference id. Sirve para auditoría y para el widget JS, **no** para consultar el pago.

---

## 5. Redirección y retorno del comprador (back_urls)

Al finalizar (o abandonar con "Volver al sitio"), MP redirige al comprador a la `back_url` correspondiente **agregando query params**:

| Param | Contenido |
|---|---|
| `payment_id` / `collection_id` | **ID del pago** creado (el que sirve para `GET /v1/payments/{id}`) |
| `status` / `collection_status` | `approved` / `pending` / `in_process` / `rejected` / `null` |
| `external_reference` | El valor enviado en la preferencia |
| `payment_type` | `credit_card`, `account_money`, `ticket`, ... |
| `merchant_order_id` | ID de la merchant order generada |
| `preference_id` | ID de la preferencia |
| `site_id` | `MLA` (Argentina), `MLU` (Uruguay), ... |
| `processing_mode` | `aggregator` |

Si el comprador **no vuelve** (cierra el navegador después de pagar), el único canal es el webhook + la búsqueda por `external_reference`.

---

## 6. Notificaciones (Webhooks / IPN / merchant_orders)

- **Webhooks (recomendado):** topic `payment` con `data.id` = payment id. Firma HMAC-SHA256 en header `x-signature` (`ts=...,v1=...`), manifest `id:{data.id};request-id:{x-request-id};ts:{ts};` — **exactamente lo que ya implementa el connector** (`mercadopago.rs`, `IncomingWebhook`).
- **Topic `merchant_order`:** notifica creación/cierre de la orden. `GET /merchant_orders/{id}` devuelve `external_reference`, `preference_id` y el array `payments[]`. Útil como canal alternativo; el `topic_to_action` actual del connector no lo mapea (solo `payment` y `chargebacks`).
- **IPN (legacy, en discontinuación):** query params `?topic=payment&id=...` — el connector ya tiene fallback para este formato.

---

## 7. Consulta y post-procesamiento del pago

Una vez que existe el `payment_id`, el pago de Checkout Pro es un **payment normal de MP** — aplican los endpoints que el connector ya implementa:

| Operación | Endpoint | Estado en el connector |
|---|---|---|
| Consultar pago | `GET /v1/payments/{id}` | ✅ ya implementado (PSync) |
| **Buscar pago por referencia** | `GET /v1/payments/search?external_reference={ref}&sort=date_created&criteria=desc` | ❌ a implementar (clave para PSync pre-redirect). Shape verificado en vivo (2026-07-30): `200 {"results":[...],"paging":{...}}`, `results` presente aun sin pagos |
| Reembolso total/parcial | `POST /v1/payments/{id}/refunds` | ✅ ya implementado |
| Consultar reembolso | `GET /v1/payments/{id}/refunds/{rid}` | ✅ ya implementado |
| Cancelar pago pendiente | `PUT /v1/payments/{id}` `{"status":"cancelled"}` | ✅ ya implementado (solo aplica a pagos `pending`/`in_process`, p. ej. ticket no pagado) |
| Consultar merchant order | `GET /merchant_orders/{id}` | ❌ opcional |

**Capture manual:** Checkout Pro **no soporta** captura manual — los pagos se capturan automáticamente. La preferencia no tiene equivalente de `capture: false`.

**Estados del pago** (`status`): `pending`, `approved`, `authorized`, `in_process`, `in_mediation`, `rejected`, `cancelled`, `refunded`, `charged_back` — el mapping ya existe en `MercadopagoPaymentStatus` (`transformers.rs`). Para Checkout Pro se agrega el estado **pre-pago** (preferencia creada, esperando al comprador) → `AuthenticationPending` en Hyperswitch.

---

## 8. Diseño de integración en Hyperswitch

> Resumen del diseño; el detalle ejecutable está en `MERCADOPAGO_CHECKOUT_PRO_Plan.md`.

### Modelado del payment method

Ya existen en el fork `PaymentMethodType::MercadoPago` (`common_enums`) y `WalletData::MercadoPagoSdk` (SDK tokenizado). Checkout Pro se modela como **una nueva variante wallet redirect sin campos**:

- `WalletData::MercadoPagoCheckoutPro {}` (api_models + domain_models) → mapea al mismo `PaymentMethodType::MercadoPago`.
- El merchant pide un pago con `payment_method: wallet`, `payment_method_type: mercado_pago` y `payment_method_data.wallet.mercado_pago_checkout_pro: {}`.

### Flujo Authorize (crear preferencia + redirect)

1. `MercadopagoPaymentsRequest::try_from` pasa a matchear sobre `PaymentMethodData`:
   - `Wallet(MercadoPagoCheckoutPro)` → nuevo request `MercadopagoPreferenceRequest` → `POST /checkout/preferences`.
   - Camino existente (token de tarjeta) → `POST /v1/payments` sin cambios.
2. La preferencia se arma con: `items[0]` (monto total, título desde description), `external_reference = connector_request_reference_id`, `back_urls` (las tres = `router_return_url`), `auto_return: "approved"`, `notification_url` (webhook url, filtrando localhost como hoy), `payer.email`, y opcionales vía metadata (`installments`, `excluded_payment_types`, `binary_mode`, `expiration`, `statement_descriptor`).
3. Respuesta → `status = AuthenticationPending`, `redirection_data = RedirectForm` (GET a `init_point`), `resource_id = NoResponseId` (el payment id no existe aún), preference id guardado en `connector_metadata` / `connector_response_reference_id`.

### PSync post-redirect (el problema del payment id desconocido)

Cuando el comprador vuelve, Hyperswitch dispara PSync automáticamente (el default por macro de `ConnectorRedirectResponse` ya devuelve `Trigger` — no hay que implementar nada), pero el attempt no tiene `connector_transaction_id`. Cascada verificada contra el router:

1. Hay transaction id → `GET /v1/payments/{id}` (comportamiento actual).
2. No hay, pero el query string del retorno (llega crudo en `PaymentsSyncData.encoded_data`) trae `payment_id`/`collection_id` válido → `GET /v1/payments/{payment_id}`.
3. Si no → `GET /v1/payments/search?external_reference={connector_request_reference_id}` y se toma el pago más reciente.

- El `resource_id` devuelto por PSync **se persiste** en el attempt (verificado en `payment_response.rs`) → los webhooks siguientes (que llegan con `data.id` = payment id) matchean por `ConnectorTransactionId` como hasta ahora.
- Si la búsqueda devuelve vacío (comprador no pagó todavía) → sigue `AuthenticationPending` (no es error).

### Webhooks

Sin cambios: el topic `payment` ya está cubierto, y `merchant_order` ya cae en `Unknown` → `EventNotSupported`, que el router responde con 200 limpio sin procesar (verificado en `core/webhooks/incoming.rs`). Los webhooks de `payment` matchean por `ConnectorTransactionId` una vez que el PSync promovió el id real; si llegan antes, MP reintenta con backoff.

### Capture / Void / Refunds

- **Capture:** no aplica (solo Automatic para el PM type wallet en `ConnectorSpecifications`).
- **Void:** el `PUT {status: cancelled}` existente solo sirve para pagos pendientes; cancelar una preferencia no paga es un no-op (expira sola).
- **Refunds:** funcionan sin cambios una vez que existe payment id.

---

## Apéndice A. Datos de prueba (validados 2026-07-30, Argentina / MLA)

**Aplicación de prueba:** `4173688184123580` — vendedor (collector) test user `TESTUSER1627531232` (User ID `1963547549`). Access token y public key en el panel de developers (Credenciales de prueba). Comprador: test user `TESTUSER1424056866` (User ID `1966179562`); contraseñas en el panel/gestor del equipo.

**Validado en vivo contra el API:**

| Endpoint | Resultado |
|---|---|
| `GET /users/me` | ✅ 200 — identifica al vendedor test |
| `POST /checkout/preferences` | ✅ 201 — `init_point` real, acepta back_urls/auto_return/installments |
| `GET /v1/payments/search?external_reference=...` | ✅ 200 — `{"results":[],"paging":{...}}` |
| `POST /v1/card_tokens` (public key) | ✅ 201 |
| `POST /v1/payments` (pago directo) | ❌ 401 `"Unauthorized use of live credentials"` (code 7) — la app es de producto **Checkout Pro**; el Checkout API directo no está habilitado para esta app. **No afecta a Checkout Pro** (el pago lo crea MP en la página hosteada). El flujo de tarjeta del connector actual requiere una app con Checkout API habilitado. |

**Tarjetas de prueba (venc. 11/30):**

| Tarjeta | Número | CVV |
|---|---|---|
| Mastercard | 5031 7557 3453 0604 | 123 |
| Visa | 4509 9535 6623 3704 | 123 |
| American Express | 3711 803032 57522 | 1234 |
| Mastercard Débito | 5287 3383 1025 3304 | 123 |
| Visa Débito | 4002 7686 9439 5619 | 123 |

**Resultado según nombre del titular:** `APRO` aprobado (DNI 12345678) · `CONT` pendiente · `OTHE` rechazo general (DNI 12345678) · `CALL` rechazo c/validación · `FUND` fondos insuficientes · `SECU` CVV inválido · `EXPI` vencimiento · `FORM` error de formulario.

**Cómo probar el E2E manual hoy (sin código):** crear preferencia (curl del §4 o la ya creada), abrir `init_point` en el navegador, pagar como guest con la Mastercard titular `APRO` (o logueado como el test user comprador), y volver a correr el search por `external_reference` → debe aparecer el pago `approved` con `id` numérico.
