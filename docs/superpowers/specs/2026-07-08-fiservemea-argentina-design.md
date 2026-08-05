# Diseño: Completar `fiservemea` para Argentina/Uruguay (Fiserv IPG REST v2)

- **Fecha:** 2026-07-08
- **Conector:** `fiservemea` (Fiserv IPG / "payments-gateway v2")
- **Rama:** `enzodossantos/fiservemea-argentina`
- **Doc de referencia del proveedor:** `IPG_API_REST_Documentacion.md` (Guía de Integración API Rest Argentina 2026, v2.0)
- **Conectores de referencia en el repo:** `payway` (cuotas por metadata), `mercadopago` (cuotas por metadata), `shift4` (3DS nativo vía CompleteAuthorize), `stripe` (mecánica de `redirection_data`/`AuthenticationPending`)

## 1. Objetivo y alcance

Extender el conector `fiservemea` para cubrir el caso de uso Argentina/Uruguay:

1. **Pagar** (ya existe — se revisa/endurece).
2. **Pagar en cuotas** (nuevo).
3. **Devolver total o parcial** (ya existe — se revisa/endurece).
4. **Consultar estado de pago** (ya existe — se revisa/endurece).
5. **3DS opcional, nativo** (nuevo) — solo cuando el merchant lo pide (`auth_type = ThreeDs`).
6. **Fix de Void/anulación** (bug fix).
7. **Tax Refund Uruguay** (add-on chico).

**Repos:** la implementación es **solo del conector Hyperswitch** (`crates/hyperswitch_connectors`). Los cambios necesarios en la app cliente (`/home/enzods/api2`, Hyperswitch codenamed "Mithras") se **documentan** en §7 pero **no** se implementan en esta etapa.

**Fuera de alcance (explícito):** tokenización IPG/passthrough, token payments, pagos recurrentes/MIT-CIT, Payment Facilitator/submerchant, Wallet LATAM QR (MODO), Payment URL (link de pago), 3DS passthrough (proveedor externo), 3DS v1 (Secure3D10 — solo si aparece la necesidad; el sandbox es 2.x), y todo cambio en `api2` (ver §7).

## 2. Estado actual (baseline)

Archivos: `crates/hyperswitch_connectors/src/connectors/fiservemea.rs` y `.../fiservemea/transformers.rs`.

Ya implementado y funcionando: Authorize (Sale/PreAuth según `capture_method`), Capture (`PostAuthTransaction`), Void (**solo** `VoidPreAuthTransactions`), Refund (`ReturnTransaction`, total y parcial), PSync (GET), RSync (GET). Auth `BodyKey` (api_key + key1), firma `Message-Signature` (HMAC-SHA256/Base64 de `api_key+request_id+timestamp_ms+payload`). Monto `StringMajorUnit`. Base URL `.../ipp/payments-gateway/v2`.

Contrato confirmado idéntico al del doc (envoltorio `requestType` PascalCase, `transactionAmount`, `paymentMethod.paymentCard`, respuesta con `ipgTransactionId`/`apiTraceId`).

**Cómo lo invoca la app (`api2`), confirmado por lectura del código cliente:**
- El `POST /payments` manda `amount` en **minor units** (entero, ×100), `currency` ISO upper, `confirm:true`, `capture_method:"automatic"`, `payment_method:"card"`, `payment_method_data.card.*`, `description`, y un objeto **`metadata`** (bag con `installments`, `installments_info`, datos de cliente/dirección). El desglose minor→major-string lo hace **Hyperswitch** vía el `amount_converter` del conector — el conector no cambia por esto.
- El literal `connector_metadata` **no** viaja al wire; solo llegan `metadata` (siempre) y `frm_metadata` (estilo MercadoPago). Por eso el conector lee su metadata de **`request.metadata` con fallback a `request.frm_metadata`**.
- Hoy la app **no** manda `authentication_type` ni maneja redirects de card (todo one-step). El 3DS requiere cambios companion en `api2` (§7).
- La app no llama al cancel/void de Hyperswitch (cancela en su propia DB).

## 3. Workstreams

### 3.1 Cuotas (installments)

**Fuente del dato:** el conector lee el objeto **`metadata`** del `POST /payments` (→ `PaymentsAuthorizeData.metadata`, `router_request_types.rs:65`). No hay campo first-class de cuotas en Hyperswitch. Para ser **resiliente** (la app tuvo fricción para sumar keys custom), se lee de **dos fuentes con fallback**: `request.metadata` y luego `request.frm_metadata` — el patrón exacto de **MercadoPago** (`mercadopago/transformers.rs:374-379`). La app ya transporta `metadata.installments` (entero) dentro de su `customer_metadata`.

**Cambios en `transformers.rs`:**
- Nuevo `FiservemeaMetadataObject` (`#[derive(Default, Deserialize)]`, `#[serde(default)]`, tolerante a keys desconocidas):
  - `installments: Option<i32>` con `#[serde(alias = "number_of_installments")]`
  - `installment_interest: Option<bool>`
  - `tax_refund_legal_framework: Option<FiservemeaLegalFramework>` con `#[serde(alias = "legal_framework")]` (ver §3.2)
  - Constructor helper que intenta `request.metadata` y hace merge/fallback con `request.frm_metadata` (`serde_json::from_value` tolerante, patrón MercadoPago). Ambas fuentes se soportan **a propósito**.
- Nuevo `FiservemeaInstallmentOptions { number_of_installments: i32, #[serde(skip_serializing_if = "Option::is_none")] interest: Option<bool> }`.
- Extender `FiservemeaOrder` (hoy `{ order_id }`) con `#[serde(skip_serializing_if = "Option::is_none")] installment_options: Option<FiservemeaInstallmentOptions>`. El `rename_all="camelCase"` ya produce `installmentOptions`/`numberOfInstallments`.
- En `FiservemeaPaymentsRequest::try_from` (auth): leer el metadata; si `installments > 1`, poblar `installment_options`. Aplica a Sale y PreAuth.

**JSON resultante:** `order.installmentOptions.numberOfInstallments` (+ `Interest`). (Doc §7.2 líneas 147-151; Apéndice III 1767-1770; ejemplo Apéndice VI 1938-1944.)

**Nota:** no hace falta config de dashboard (`connector_configs`) para cuotas porque el valor llega por `metadata`/`frm_metadata` en cada pago.

### 3.2 Tax Refund Uruguay

**Fuente:** el mismo `FiservemeaMetadataObject` (§3.1), leído de `metadata`/`frm_metadata`, key `tax_refund_legal_framework` (alias `legal_framework`).

> **Caveat (importante):** la app reportó fricción para agregar keys custom a su request. `legal_framework` es una key **nueva** (no existe hoy en `api2`). Alternativas si no puede agregarse per-pago: (a) leerlo como **default a nivel merchant** desde el metadata de la cuenta de conector (`MerchantConnectorAccount.metadata`) — a confirmar en el plan; (b) diferir Tax Refund UY (recordar: "no es tan fuerte"). El código del conector queda listo igual; lo único externo es que el valor llegue por alguna de las fuentes soportadas.

**Cambios en `transformers.rs`:**
- Nuevo enum `FiservemeaLegalFramework` con los 6 valores (serializados verbatim): `NoTaxRefund` → `NO_TAX_REFUND`, `UryReturnsIvaLaw17934` → `URY_RETURNS_IVA_LAW_17934`, `UryReturnsImesiLaw18083`, `UryReturnsAfamLaw18910`, `UryTaxRefundLaw18999`, `UryReturnsIvaLaw19210` (usar `#[serde(rename="...")]` explícito por valor).
- Nuevos structs `FiservemeaAdditionalDetails { tax_refund_request_data: Option<FiservemeaTaxRefundRequestData> }` y `FiservemeaTaxRefundRequestData { legal_framework: FiservemeaLegalFramework }`.
- Extender `FiservemeaOrder` con `additional_details: Option<FiservemeaAdditionalDetails>`.
- (Opcional) `transactionAmount.components` (`subtotal`, `vatAmount`, `tip`, `surcharge`): mandar **solo si** Hyperswitch trae el desglose (`req.request.order_tax_amount`/`surcharge_details`); si no, se omite y el gateway usa `total`.

**JSON:** `order.additionalDetails.taxRefundRequestData.legalFramework`. (Doc §13 líneas 1548-1590.)

### 3.3 Fix de Void/anulación

**Problema:** hoy `FiservemeaVoidRequest` manda siempre `VoidPreAuthTransactions` (`transformers.rs:408-415`), por lo que no puede anular una venta/captura (el doc exige `VoidTransaction` para sale/postauth; `VoidPreAuthTransactions` solo para pre-auth). Doc líneas 130-137.

**Solución:** elegir el `requestType` según el contexto de captura:
- `VoidPreAuthTransactions` cuando se anula un pre-auth no capturado (manual capture, estado Authorized).
- `VoidTransaction` cuando se anula una venta/captura.

**A verificar en el plan:** qué campos expone `PaymentsCancelData` para distinguir (¿`capture_method`? ¿estado previo?). Si no hay señal suficiente en `PaymentsCancelData`, definir default: dado que en Hyperswitch el flujo Void se invoca típicamente sobre pagos autorizados-no-capturados, `VoidPreAuthTransactions` sigue siendo el default, y `VoidTransaction` se usa cuando exista señal de auto-capture/sale. Documentar la regla elegida.

> **Nota:** la app `api2` **no** llama hoy al void de Hyperswitch (cancela en su DB). Este fix es de **corrección/futuro** del conector; no está en el camino crítico del flujo actual, pero se incluye porque fue pedido y es barato.

### 3.4 3DS opcional — nativo (conector-driven)

**Gatillo:** solo si `item.router_data.is_three_ds()` (`utils.rs:980-982`). La rama `NoThreeDs` deja el request **idéntico** al actual (3DS opcional de verdad).

**Patrón Hyperswitch:** `CompleteAuthorize` (referencia `shift4.rs:547-635`), porque la continuación IPG es un segundo llamado server (`PATCH`). Mecánica de redirect: `PaymentsResponseData::TransactionResponse.redirection_data: Box<Option<RedirectForm>>` (`router_response_types.rs:29`) + `AttemptStatus::AuthenticationPending`.

**Flujo IPG nativo (2.1), peor caso (challenge):**

1. **Authorize** → `POST .../payments` con `authenticationRequest` agregado al payload de venta/pre-auth:
   ```json
   "authenticationRequest": {
     "authenticationType": "Secure3D21AuthenticationRequest",
     "termURL": "<complete_authorize_url>",
     "methodNotificationURL": "<complete_authorize_url>",
     "challengeIndicator": "01",
     "challengeWindowSize": "01"
   }
   ```
   `termURL`/`methodNotificationURL` = `req.request.complete_authorize_url` (`router_request_types.rs:47`; siempre poblado por el router). (Doc 526-578.)
   - **Respuesta:** `transactionStatus=WAITING` + `authenticationResponse.secure3dMethod.methodForm` (HTML iframe oculto) → devolver `RedirectForm::Html { html_data: methodForm }` + `AuthenticationPending`. Si el tarjetahabiente no está enrolado → `APPROVED/DECLINED` inmediato (sin redirect). (Doc 582-617.)

2. **Browser:** renderiza el `methodForm` (device fingerprint); el ACS notifica a `methodNotificationURL` → el browser vuelve a `complete_authorize_url` → dispara **CompleteAuthorize #1**.

3. **CompleteAuthorize #1** → `PATCH .../payments/{ipgTransactionId}`:
   ```json
   { "authenticationType": "Secure3D21AuthenticationUpdateRequest", "methodNotificationStatus": "RECEIVED" }
   ```
   (Doc 656-672.) `methodNotificationStatus` derivado de lo recibido (`RECEIVED` / `EXPECTED_BUT_NOT_RECEIVED`).
   - **Respuesta frictionless:** `APPROVED/DECLINED` + `secure3dResponse.responseCode3dSecure` → estado terminal. (Doc 674-693.)
   - **Respuesta challenge:** `WAITING` + `authenticationResponse.params { acsURL, cReq, termURL, sessiondata }` → devolver `RedirectForm::Form { endpoint: acsURL, method: Post, form_fields: { creq: cReq, threeDSSessionData: sessiondata } }` + `AuthenticationPending`. (Doc 709-756.)

4. **Browser:** challenge en `acsURL`; el ACS postea `cRes` al `termURL` → vuelve → dispara **CompleteAuthorize #2**.

5. **CompleteAuthorize #2** → `PATCH .../payments/{ipgTransactionId}`:
   ```json
   { "authenticationType": "Secure3D21AuthenticationUpdateRequest", "acsResponse": { "cRes": "<cRes>" } }
   ```
   → estado terminal (`APPROVED/DECLINED`). (Doc 758-804.)

**Cambios de código:**
- `fiservemea.rs`: `impl api::PaymentsCompleteAuthorize for Fiservemea {}`; nuevo `impl ConnectorIntegration<CompleteAuthorize, CompleteAuthorizeData, PaymentsResponseData>` (get_headers/content_type/url/request_body/build_request con `Method::Patch`/handle_response/get_error_response). URL de continuación: `{base}/ipp/payments-gateway/v2/payments/{connector_transaction_id}`. Imports de `CompleteAuthorize`/`CompleteAuthorizeData`/`PaymentsCompleteAuthorizeRouterData`/`PaymentsCompleteAuthorizeType` (ver `shift4.rs:20-33`).
- `transformers.rs`: nuevos structs `FiservemeaAuthenticationRequest`, `FiservemeaAuthenticationUpdateRequest` (method status y acsResponse), parsing de `authenticationResponse` (`secure3dMethod.methodForm`, `params.{acsURL,cReq,sessiondata}`), lectura de `req.request.redirect_response.{params,payload}` (`router_request_types.rs:790,804-808`) para extraer `methodNotificationStatus`/`cRes`. Rama `AuthenticationPending` en `map_status` para `WAITING` con datos de 3DS.
- `get_supported_payment_methods`: `three_ds: NotSupported → Supported` (`fiservemea.rs:822-823`).

**A verificar en el plan:** nombres exactos de campos del formulario ACS (`creq`/`cReq`, `threeDSSessionData`/`sessiondata`), si `methodNotificationURL` es obligatorio, y si se puede simplificar el paso de fingerprint (mandar `EXPECTED_BUT_NOT_RECEIVED` sin renderizar el iframe) — decisión interna, no afecta la interfaz.

> **⚠️ Dependencia cross-repo:** el código 3DS del conector es necesario **pero no suficiente** para 3DS funcionando punta a punta. Hoy `api2` no manda `authentication_type` ni maneja el redirect de card. Sin los cambios companion de §7, el flujo 3DS del conector **no se ejercita** desde la app (sí se puede testear vía los flujos propios de Hyperswitch). El conector se implementa igual y queda listo.

### 3.5 Revisión/endurecimiento de lo existente

- Agregar **integrity objects** de monto en authorize/capture/refund/rsync (patrón `fiserv.rs`: `connector_utils::get_authorise_integrity_object`/`get_capture_integrity_object`/`get_refund_integrity_object` con `self.amount_converter`). Hoy `fiservemea` no los tiene.
- Revisar `map_status`/`map_refund_status` (uso de `transaction_status` deprecado vs `transaction_result`), refund parcial (`Partial → PartialCharged`), y mapeo de errores (`build_error_response`).

## 4. Criterios de aceptación

- Pago simple sin cuotas y sin 3DS: comportamiento **sin cambios**.
- Pago con `metadata.number_of_installments = N`: el request incluye `order.installmentOptions.numberOfInstallments = N`.
- Pago con `metadata.legal_framework`: el request incluye `order.additionalDetails.taxRefundRequestData.legalFramework`.
- Refund total y parcial: correctos (incl. estado `PartialCharged`/`Pending`).
- PSync/RSync: reflejan el estado final del gateway.
- Void: usa `VoidTransaction` vs `VoidPreAuthTransactions` según la regla documentada.
- Pago con `auth_type = ThreeDs`: dispara el flujo nativo (frictionless y challenge) y termina en `Charged`/`Authorized`/`Failure`; con `NoThreeDs` no cambia nada.
- `cargo check`/`clippy` del workspace sin errores; tests unitarios de transformers verdes.

## 5. Testing

- **Unit (transformers):** serialización de request con/sin cuotas, con/sin tax refund, con/sin 3DS; mapeo de estados (incl. `AuthenticationPending`); void según contexto.
- **Integración:** extender/crear el test file del conector (`crates/router/tests/connectors/fiservemea.rs` si existe) con las tarjetas de test del doc (Apéndices IV y V).
- Verificación manual contra sandbox (`prod.emea.api.fiservapps.com/sandbox`) donde sea posible.

## 6. Preguntas abiertas (a resolver en el plan)

1. `PaymentsCancelData`: ¿expone `capture_method`/estado para decidir el tipo de void?
2. 3DS: nombres exactos de `form_fields` del ACS y obligatoriedad de `methodNotificationURL`; ¿simplificar fingerprint?
3. Tax refund: mapeo de `components` desde campos de Hyperswitch (`order_tax_amount`/surcharge) — ¿incluir en esta etapa o solo `legalFramework`?
4. ¿Override de `tax_refund_legal_framework` por pago vs default a nivel merchant (`MerchantConnectorAccount.metadata`)?
5. 3DS: ¿el `merchant_connector_id`/profile de `fiservemea` en Mithras ya está creado para poder testear el redirect?

## 7. Cambios companion requeridos en `api2` (documentados — FUERA de alcance de implementación)

Estos cambios viven en `/home/enzods/api2` (Hyperswitch = "Mithras", base `MITHRAS_PAY_V2_BASE_URL`). Se listan para que el conector sea usable; **no** se implementan acá.

1. **Nuevo `FiservEmeaGateway`** (clonar `PaywayGateway`/`StripeGateway`), con `routing.data.connector = 'fiservemea'` y el connector name `fiservemea` (debe matchear el `id()` del conector Rust).
2. **Registrar el provider**: `case 'FiservEmea'` en `PaymentGatewayFactory::create` (`PaymentGatewayFactory.php:16-34`) y en los bloques de `ApiJsonValidator.php` + valores de `PaymentMeans`/`MerchantConnectors`.
3. **Cuotas / Tax Refund**: incluir `installments` (ya lo hace vía `customer_metadata` → `metadata`) y, para UY, `tax_refund_legal_framework` dentro de `metadata` (o `frm_metadata`). Nada más: el conector ya lee ambas fuentes.
4. **3DS (opt-in)**: cuando el pago requiera 3DS, el gateway debe:
   - mandar `authentication_type: "three_ds"` en el `POST /payments` (hoy no se manda ninguno);
   - mandar `return_url` (URL de retorno del comercio);
   - leer `next_action.type == "redirect_to_url"` + `next_action.redirect_to_url` de la respuesta y redirigir al cliente (el patrón ya existe **comentado** en `PayPalGateway.php:289-297`), en lugar de asumir `url_to_pay = null`;
   - tras el retorno, consultar el estado con `GET /payments/{id}` para el resultado final.
5. **Void (opcional)**: si se quiere anular vía Hyperswitch en lugar de solo local, agregar la llamada `POST /payments/{id}/cancel`.

### 7.1 Estado de implementación (actualizado)

**Conector (este repo):** 3DS nativo completo a fidelidad de spec — frictionless + challenge, `methodNotificationStatus` correcto (`RECEIVED`/`EXPECTED_BUT_NOT_RECEIVED`), `responseCode3dSecure` parseado y surfacedo en `connector_metadata`, `cardholderName`, `challengeWindowSize=05`, tests de fixture con el JSON del doc. Diferidos (niche): Data-Only Mastercard (`messageCategory:80`, §10.1.6) y 3DS v1 (`Secure3D10`). Nota: `CompleteAuthorizeData` no expone `integrity_object`, así que el cargo terminal 3DS no lleva integrity check (limitación de plataforma).

**api2 (companion):** IMPLEMENTADO en la rama `enzodossantos/fiservemea-3ds` (off `master`, NO mergeada): `FiservEmeaGateway` + registro en factory + validator (`three_ds` boolean, `FiservEmea` en `Rule::in`) + `PROVIDERS_BASE_CURRENCIES['fiservemea']=['ARS','UYU']`. `php -l` OK. **NO testeado en runtime** — validar en staging.

### 7.2 Checklist de validación en staging (antes de producción)

1. **Prerequisito ops:** crear el merchant-connector `fiservemea` en Mithras/Hyperswitch (profile_id + merchant_connector_id + api_key/key1 de Fiserv IPG, 3DS habilitado).
2. **Timing de finalización 3DS (RIESGO #1):** confirmar que Hyperswitch corre CompleteAuthorize y deja el pago en estado terminal **antes** de redirigir al `return_url`. Si `pay()` puede ejecutarse con estado `requires_customer_action`, el `GET /payments/{id}` devolvería no-terminal y el pago se marcaría fallido/cancelado prematuramente. (Es el supuesto central del flujo.)
3. **Cuotas:** confirmar que Fiserv/el conector aplica el interés de cuotas nativamente (api2 NO multiplica el monto localmente para evitar doble cobro).
4. **Casing 3DS:** capturar una respuesta real del sandbox y confirmar el casing de `secure3dMethod`/`sessiondata`/`acsURL` (mitigado con serde aliases, pero conviene verificar).
5. **Currency base ARS/UYU:** confirmar que es lo correcto para este connector (dispara FX si el budget viene en otra moneda).
