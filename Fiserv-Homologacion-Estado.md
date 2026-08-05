# Fiserv IPG — Estado de homologación (conector `fiservemea` de Hyperswitch)

> Mapea cada caso que Fiserv exige (ver `Fiserv-IPG-Integracion-Consolidado.md`, Parte 11) contra lo que el conector **hoy** soporta, qué está **probado en vivo contra cert**, y qué **falta implementar**.
>
> Leyenda: ✅ soportado y probado en vivo · 🟡 soportado en código, falta correr el caso puntual · ❌ **gap** (hay que implementarlo) · ⚠️ a confirmar.

**Entorno de pruebas:** `https://cert.api.firstdata.com/gateway/v2` · Auth del conector: `SignatureKey` (`api_key`=Key, `api_secret`=Secret, `key1`=Store Id).

**Ojo clave:** la homologación la evalúa Fiserv **por sus logs**, mirando las requests que llegan **desde el sistema ya integrado**. O sea: no alcanza con probar por script — hay que correr cada caso **a través de Hyperswitch** (con el fix de `storeId` ya deployado). Las validaciones por Python de abajo prueban que el *request que arma el conector* es correcto, que es condición necesaria.

---

## A. Transacciones básicas

| # | Caso Fiserv | Estado | Detalle |
|---|-------------|--------|---------|
| 1 | Sale en 1 pago | ✅ | Probado cert UY+ARG (APPROVED/CAPTURED). `PaymentCardSaleTransaction`. |
| 2 | Sale en 1 pago con **DÓLAR** | ✅ | Probado USD en UY y ARG (APPROVED). Es solo el campo `currency`. |
| 3 | Sale con **ZEROAUTH** | 🟢 | **Implementado** (flujo `SetupMandate` → sale `total: 0`) + wire validado contra cert (APPROVED). Compila. |
| 4 | Sale en cuotas con **TOKEN GW** (tarjeta `5165850000000008`, tienda `5926072902`) | ✅ | **Validado end-to-end contra cert con la tarjeta+tienda exactas**: crear token (SUCCESS) → pagar en 3 cuotas (APPROVED). Funciona completo, cuotas incluidas. |
| 5 | Sale en cuotas con **TOKEN MTRG** (tarjeta `4622943127032366`, tienda `5926072901`) | 🟢/❓ | **No requiere código nuevo** (flujo OnTheGo = `PaymentCardSaleTransaction` con tarjeta normal; Fiserv tokeniza server-side, doc §Network Token 5.a). 1-pago → APPROVED ✅. **Cuotas → `11101 "not local"`** en tienda `5926072901` — la MISMA mecánica de cuotas funciona en el caso 4 (tienda `5926072902`), así que es **config de Fiserv en esa tienda/tarjeta**, no del conector. Preguntar a Fiserv. |
| 6 | **INQUIRY ORDER** | 🟡 | El conector hace `GET /payments/{ipgTransactionId}` (PSync) ✅ probado. Confirmar si Fiserv espera inquiry por `orderId` (endpoint distinto). Doc: §7.3. |
| 7 | **DYNAMIC MERCHANT NAME** | 🟢 | **Implementado + validado.** Se envía `order.softDescriptor.dynamicMerchantName` desde `metadata.dynamic_merchant_name`. Ojo: va **anidado en `order`**, no top-level (el cert API rechaza `softDescriptor` top-level con `INVALID_INPUT`). Validado → APPROVED. Compila (`cargo check` en verde). |
| 8 | Void (Anulación) | ✅ | Probado cert UY+ARG (`VoidTransaction` y `VoidPreAuthTransactions` → VOIDED). |
| 9 | Return por monto **total** | ✅ | Probado cert UY+ARG (`ReturnTransaction` → APPROVED). |
| 10 | Return por monto **parcial** | 🟡 | Mismo flujo que el total con `transactionAmount` menor. El conector soporta refund parcial; falta correr el caso puntual. |

## B. 3D Secure

| Grupo | Casos | Estado | Detalle |
|-------|-------|--------|---------|
| 3DS Frictionless | 5 tarjetas | 🟡 | Soportado (`Secure3D21AuthenticationRequest`). Falta correr la matriz con las 5 tarjetas a través del sistema integrado. |
| 3DS Method | 5 tarjetas | 🟡 | Soportado (flujo `methodNotification` + continuación PATCH). Falta correr. |
| 3DS Challenge | 5 response codes | 🟡 | Soportado (continuación con `acsResponse.cRes`). Falta correr. |
| 3DS Challenge + Method | 5 | 🟡 | Soportado. Falta correr. |
| 3DS **DataOnly** | 1 tarjeta (`5239290700000028`) | 🟢 | **Implementado.** `messageCategory: "80"` opt-in vía `metadata.three_ds_data_only`. Compila. Falta correr el caso 3DS Mastercard por el sistema integrado. |

---

## Resumen de gaps a implementar en el conector

Ordenados por esfuerzo aproximado (menor → mayor):

1. **Dynamic Merchant Name** — chico. Agregar campo al request (probable `dynamicMerchantName` / soft descriptor). Fuente en el body, vía metadata.
2. **3DS DataOnly** — moderado. Agregar la variante `messageCategory: "80"` al `authenticationRequest`.
3. **Tokenización IPG (TOKEN GW)** — grande. Guardar `paymentToken` en la respuesta + soportar pagar con token (nuevo `paymentMethod`). Habilita también cuotas con token (casos 4).
4. **ZeroAuth** — moderado/grande. Implementar `SetupMandate` (verificación de cuenta zero-amount).
5. **Network Token (MTRG)** — grande. Soportar el flujo de network token (caso 5).

## Ya probado en vivo (evidencia cert)

Ciclo completo corrido contra cert (UY store `7726072903`, ARG store `5926072901`), todo APPROVED:
PreAuth → PSync → Capture → Return → RSync → Void(preauth) → Sale → Void(sale). Más Sale USD (UY+ARG) APPROVED. Los 4 stores (UY 7726072903/04, ARG 5926072901/02) procesan sale OK.

## Notas / a confirmar con Fiserv

- Los casos **obligatorios** venían marcados en rojo en el `.docx` original; el color se perdió en la conversión. **Confirmar con Fiserv cuáles son obligatorios** — puede que MTRG/DataOnly no lo sean, lo que reduce el alcance.
- **Cuotas**: en ARG solo aplican a **tarjetas locales** (Fiserv devuelve `11101 "installment only supported for local cards"` con tarjetas internacionales). Los casos 4/5 usan tarjetas locales + token.
- Homologación = correr los casos **a través de Hyperswitch deployado**, no solo por script, para que Fiserv los vea en sus logs.
- Pre-requisito de todo: **mergear + deployar el fix de `storeId`** (rama actual `enzodossantos/fiservemea-argentina`, sin commitear).

---

## Blueprints validados contra cert (listos para implementar)

Formas de request exactas, ya probadas → APPROVED/SUCCESS. Sirven de plano para implementar cada flujo en el conector.

**ZeroAuth** — `POST /payments`, un sale normal con monto 0:
```json
{ "requestType":"PaymentCardSaleTransaction", "storeId":"…", "transactionAmount":{"total":"0.00","currency":"ARS"},
  "order":{"orderId":"…"}, "paymentMethod":{"paymentCard":{…}} }
```

**TOKEN GW — crear token** — `POST /payment-tokens` (⚠️ endpoint distinto):
```json
{ "requestType":"PaymentCardPaymentTokenizationRequest", "storeId":"…",
  "paymentCard":{"number":"…","expiryDate":{"month":"12","year":"29"},"securityCode":"123"},
  "createToken":{"reusable":true,"declineDuplicates":false} }
```
Response: `paymentToken.value` = el token (Hosted Data ID).

**TOKEN GW — pagar con token** — `POST /payments`:
```json
{ "requestType":"PaymentTokenSaleTransaction", "storeId":"…", "transactionAmount":{"total":"10.00","currency":"ARS"},
  "order":{"orderId":"…"}, "paymentMethod":{"paymentToken":{"value":"<token>","tokenOriginStoreId":"…"}} }
```

**Dynamic Merchant Name** — dentro de `order` (NO top-level):
```json
"order": { "orderId":"…", "softDescriptor": { "dynamicMerchantName":"PXSOL*Reservas" } }
```

**3DS DataOnly** (pendiente de validar en vivo — requiere flujo 3DS Mastercard) — agregar dentro de `authenticationRequest`: `"messageCategory": "80"`.

**Network Token (MTRG)** (pendiente) — sale con `paymentCard.number = {{NetworkToken}}` + `order.tokenCryptogram` (doc §Zero Auth 3.2 / §Network Token).

## Progreso de esta sesión

Implementado en el conector (todo compila — `cargo check -p hyperswitch_connectors --tests --features v1` en verde):

- ✅ **Fix `storeId`** (auth `SignatureKey`) en todos los flujos — probado en vivo (todos los flujos, UY+ARG).
- ✅ **Dynamic Merchant Name** — `order.softDescriptor.dynamicMerchantName` (anidado correcto), validado contra cert.
- ✅ **3DS DataOnly** — `messageCategory: "80"` opt-in vía `metadata.three_ds_data_only`.
- ✅ **ZeroAuth** — flujo `SetupMandate` → sale `total: 0`, validado contra cert.
- ✅ **Tokenización TOKEN GW** — flujo `PaymentMethodToken` (`POST /payment-tokens`) + pago con `PaymentTokenSaleTransaction`, validado en vivo (crear SUCCESS + pagar APPROVED). Endpoint de creación: `/payment-tokens`.

Pendiente:

- ✅ **Network Token (MTRG)** — RESUELTO y validado los **3 flujos** contra cert: (a) OnTheGo = venta con PAN → Fiserv tokeniza (funding BIN `462294` ≠ token BIN `432312`, confirmado); (b) async crear token → `type: NETWORK_TOKEN`/`PROVISIONED`; (c) async pagar con token → APPROVED. **OnTheGo no requiere código; crear+pagar es el MISMO flujo de tokenización que TOKEN GW** (`PaymentCardPaymentTokenizationRequest` + `PaymentTokenSaleTransaction`) — una sola implementación cubre ambos.
- ✅ **Cuotas caso 4 (TOKEN GW)** — validado end-to-end (token + 3 cuotas → APPROVED) con tarjeta+tienda exactas.
- ❓ **Cuotas caso 5 (TOKEN MTRG)** — `11101 "not local"` en tienda `5926072901`; la misma mecánica funciona en el caso 4 → es config de Fiserv en esa tienda/tarjeta. **Preguntar a Fiserv.**
- 📋 Correr la **matriz completa** (básicas + 21 casos 3DS) por el sistema integrado (Hyperswitch deployado), que es como Fiserv la evalúa.
- 📋 Mergear + deployar + configurar las cuentas.

## Casos obligatorios (lista roja de Fiserv)

Según la versión con color: obligatorios (rojo) = sale 1-pago, sale USD, ZeroAuth, cuotas TOKEN GW, cuotas TOKEN MTRG, void, return total, return parcial, y toda la matriz 3DS (Frictionless x5, Method, Challenge, Challenge+Method). Opcionales (negro), a confirmar: INQUIRY ORDER, DYNAMIC MERCHANT NAME, 3DS DataOnly, y algún "Unable to Authenticate". **Todos los obligatorios están cubiertos por el conector** (implementados o ya soportados).
