# Payway Argentina — Relevamiento de documentación (tarjetas / QR / redirección / bines / promociones)

> Relevado el 2026-08-07 desde las dos webs de desarrolladores de Payway (ex Prisma / Decidir):
> - **https://docs.payway.com.ar** → documentación *nueva* de producto (Pagos Online + Terminal integrada).
> - **https://developers.payway.com.ar** → *Portal de APIs* (catálogo API Program, 33 APIs con Swagger).
>
> Ambas son SPAs de Next.js: el contenido **no** está en el HTML, se carga por API. Al final está la receta exacta para volver a extraerlo.

---

## 0. Resumen ejecutivo — qué hay y qué NO hay

| Tema | ¿Existe documentado? | Dónde |
|---|---|---|
| **Tarjetas** (crédito/débito/prepaga) | ✅ Sí, completo | `docs.payway.com.ar` → *Pagos Online* (Payway Gateway API v2) |
| **QR** | ✅ Sí, en 5 APIs distintas | `developers.payway.com.ar` (Decidir QR, Acquiring QR, Prisma Wallet QR) + POS integrado |
| **Redirección / hosted checkout** | ❌ **NO existe API documentada** | Ver §4 — Payway online es **100% server-to-server** |
| **Bines** | ✅ Sí, dos usos distintos | API `Bin Services` + campo `bin` obligatorio en `/payments` |
| **Promociones / cuotas** | ⚠️ Parcial y fragmentado | Solo en el mundo **QR/wallet** y en `Quota Calculator`. En ecommerce **no hay API de promociones** |

**Los tres hallazgos que más impactan una integración:**

1. **No hay checkout con redirección.** Ni link de pago por API, ni iframe, ni hosted page. El SDK JavaScript de Payway (`sdk-javascript-ventaonline`) es **solo tokenización** en el browser, no un formulario embebido. El "link de pago" y el "botón de pago" que promociona payway.com.ar se generan desde el panel *Mi Payway*, sin API pública.
2. **No hay 3DS en la API online.** Cero menciones a 3DS / ACS / challenge / `redirect_url` en todo el spec de Payway Gateway API ni en los 23 documentos de *Pagos Online*. El único antifraude es CyberSource (device fingerprinting desde el SDK JS) y el response trae `fraud_detection`.
3. **`bin` es obligatorio en `POST /payments`** — hay que mandar los primeros 6 dígitos del PAN aparte del token/card_data. Es un campo `required` del `PaymentRequest`.

---

## 1. Mapa de los dos sitios

### 1.1 `docs.payway.com.ar` — documentación de producto

Dos productos, ambos versión `v1`:

| Producto | Slug | Categoría |
|---|---|---|
| **Pagos Online** | `ventas-online` | ECOMMERCE |
| **Terminal integrada vía API** (POS integrado) | `pos-integrado-documentation` | PRESENT |

**Pagos Online — 23 docs + 1 OpenAPI** (`/docs/ventas-online/<slug>`):

```
overview · requisitos-tecnicos
Paso a paso: diagramas-de-secuencia · crear-orden-interna · capturar-datos ·
             validar-en-backend · ejecutar-pago · procesar-respuesta · responder-al-usuario
Funcionalidades adicionales: transaccion-distribuida · preautorizacion ·
             tokenizacion-payway · payfac
Gestión: anulacion · devolucion
Testing: casos-de-prueba · tarjetas-de-prueba · medios-de-pago · errores
Producción: despliegue
Otros: cierre-de-lote · estado-de-transacciones · glosario
API Reference: payway-gateway-api  (OpenAPI 3.0.3, sandbox habilitado)
```

Ofertas listadas en el menú del producto: `TX_SIMPLE` (Pago Simple), `TX_DISTRIBUIDA` (Pago distribuido), `PREAUTH` (Preautorización), `PAYFAC` (agregador).

**POS integrado — 19 docs + 5 OpenAPI** (`oauth-api`, `payments`, `refunds`, `reversals`, `settlements`).

### 1.2 `developers.payway.com.ar` — Portal de APIs (API Program)

**33 APIs** en el catálogo, todas con `securityLevel: OAuth2.2legged` (salvo una con Apikey), gateway en `https://api-sandbox.payway.com.ar`. Listado completo en §7.

---

## 2. TARJETAS

### 2.1 Payway Gateway API v2 (ecommerce)

**Entornos** (ojo: el propio OpenAPI tiene los `description` de los servers **invertidos** — la doc funcional manda):

| Entorno | Base URL |
|---|---|
| Sandbox | `https://developers-ventasonline.payway.com.ar` |
| Producción | `https://ventasonline.payway.com.ar` |

Path base: `/api/v2`. Headers obligatorios: `Content-Type: application/json` + `apikey: <API Key>`.

**Tres API Keys según modelo:**

| Modelo | Keys | Uso |
|---|---|---|
| **PCI** | API Key PCI | `POST /payments` directo con `card_data` |
| **NO PCI** | Public API Key + Private API Key | Public → `POST /tokens` (desde frontend); Private → `POST /payments` con `token` |

**Endpoints** (`payway-gateway-api`, OpenAPI 3.0.3):

| Método | Path | Descripción |
|---|---|---|
| POST | `/tokens` | Crear token de pago |
| POST | `/payments` | Crear pago / autorizar |
| GET | `/payments` | Listar pagos |
| GET | `/payments/{payment_id}` | Detalle de un pago |
| PUT | `/payments/{payment_id}` | **Captura** (2º paso de preautorización) |
| POST | `/payments/{payment_id}/refunds` | Devolución |
| DELETE | `/payments/{payment_id}/refunds/{refund_id}` | Anular devolución |
| GET | `/usersite/{user_id}/cardtokens` | Listar tarjetas guardadas del usuario |
| DELETE | `/cardtokens/{token}` | Eliminar tarjeta guardada |

### 2.2 `PaymentRequest` — campos

Requeridos: `site_transaction_id`, `payment_method_id`, **`bin`**, `amount`, `currency`, `installments`, `payment_type`, `sub_payments`.

| Campo | Tipo | Notas |
|---|---|---|
| `site_transaction_id` | string ≤40 | ID único del comercio |
| `token` | uuid (36) | NO PCI — token de `/tokens` |
| `card_data` | object | PCI — `card_number`, `card_expiration_month/year`, `security_code`, `card_holder_name`, `card_holder_identification`, `card_holder_birthday`, `card_holder_door_number`, `ip_address`, `last_four_digits` |
| `card_token_data` | `{token ≤64, security_code}` | Pago con tarjeta guardada (Tokenización Payway) |
| `token_card_data` | object | **Network token de marca**: `token`, `eci` (0/2/5/6/7), `cryptogram` (Visa 40 / MC 28), `expiration_month/year`, `device_type` (solo MC), `token_requestor_id` (solo MC), `remote_commerce_acceptor_identifier` (solo MC) |
| `payment_method_id` | integer | Ver tabla §2.4 |
| `bin` | string `^\d{6}$` | **Obligatorio siempre** |
| `amount` | integer 1..999999999999 | En centavos (últimos 2 dígitos = decimales) |
| `currency` | enum | `ars`/`ARS`/`usd`/`USD` |
| `installments` | integer 1..99 | Cuotas |
| `payment_type` | enum | `single` \| `distributed` |
| `sub_payments` | array | `[]` en pago simple; `{site_id ≤8, amount, installments}` en distribuido |
| `aggregate_data` | object | Payfac/agregador — 20 campos requeridos (MCC, CUIT del comercio final, dirección, etc.) |
| `customer` | object | Necesario para guardar tarjeta → devuelve `customer_token` |
| `user_id`, `description` | string | Opcionales |

**`TokenResponse`**: `id` (uuid), `status` (`active`/`used`/`expired`), `bin` (`^\d{6,8}$`), `last_four_digits`, `expiration_month/year`, `card_number_length`, `security_code_length` (3\|4), `date_created`, `date_due`, `cardholder`.

### 2.3 Estados de transacción

`PROCESS → PREAPPROVED → APPROVED → ACCREDITED`, con ramas `ANNULLED / ANNULMENT_APPROVED`, `REFUNDED / REFUNDED_APPROVED / APPROVED_WITH_REFUND`, y para distribuidas `GROUP_REJECTED` / `GROUP_ANNULLED`.
Al usuario final se le muestran solo tres: **Approved / Rejected / Review**. El pasaje `APPROVED → ACCREDITED` lo hace el **cierre de lote** (batch).

### 2.4 Medios de pago (`payment_method_id`)

**Crédito:** Visa `1`, Diners `8`, Shopping `23`, Naranja `24`, Italcred `29`, ArgenCard `30`, CoopePlus `34`, Nexo `37`, Credimás `38`, Nevada `39`, Nativa `42`, Cencosud `43`, Carrefour/Cetelem `44`, PymeNación `45`, VisaAgro `49`, BBPS `50`, Qida `52`, Grupar `54`, Patagonia 365 `55`, Club Día `56`, Tuya `59`, Distribution `60`, La Anónima `61`, CrediGuía `62`, **Cabal Payway `63`**, SOL `64`, **Amex `65`** (15 dígitos, CVV 4), **Mastercard Payway `104`**, Nativa Payway `109`, Amex Payway `111`.

**Débito:** Visa Débito `31`, Mastercard Debit Payway `105`, Maestro Payway `106` (18 dígitos), Cabal Débito Payway `108`.

**Prepagas:** Visa Prepaga `114`, Mastercard Prepaga `116`, Master Prepaga Fiserv `142` (18 dígitos).

**Offline (cupón):** PagoFácil `25`, RapiPago `26`, Caja de Pagos `48`, Cobro Express `51`.

### 2.5 Tarjetas de prueba

| Escenario | Medio | `payment_method_id` | Tarjeta | Vto | CVV |
|---|---|---|---|---|---|
| Aprobado | Visa crédito | 1 | `4507990000004905` | 08/30 | 123 |
| Rechazo (05) denegada | Visa crédito | 1 | `4546400044997331` | 08/30 | 123 |
| Rechazo (51) sin fondos | Visa crédito | 1 | `4258210000474094` | 08/30 | 123 |
| Aprobado | Visa débito | 31 | `4517721004856075` | 08/30 | 123 |
| Rechazo (51) | Visa débito | 31 | `4517720194823929` | 08/30 | 123 |
| Aprobado | Mastercard | 104 | `5299910010000015` | 08/30 | 123 |
| Rechazo (05) | Mastercard | 104 | `5455330200000016` | 08/30 | 123 |
| Rechazo (51) | Mastercard | 104 | `5204230010000012` | 08/30 | 123 |
| Aprobado | Cabal crédito | 63 | `5896570000000008` | 08/30 | 123 |

### 2.6 Tokenización

Dos mecanismos **distintos**, no confundir:

1. **Tokenización Payway** (card-on-file del gateway) — se manda `customer` en el `POST /payments`; el response trae `customer_token`. Después se listan con `GET /usersite/{user_id}/cardtokens` y se cobra con `card_token_data.{token, security_code}`. Se borra con `DELETE /cardtokens/{token}`.
2. **Token Requestor Services** (network tokens de marca, API aparte del portal) — `POST /tokens`, `/tokens/token_details`, `/tokens/token_deletion`, `PUT /visa`, `PUT /masterSCOF`, `POST /transactions`, `DELETE /device_binding/{token_id}/{device_id}`. Base: `https://api-sandbox.payway.com.ar/v1/tokenization_services/token_requestor_services`. Se consume desde `/payments` vía `token_card_data`.
   Complemento: **Token Requestor Notification Services** (`/subscriptions`, `/token_changes_notifications`, `/merchant_changes_notifications`, `/notify-binding-creation`…) para recibir actualizaciones de token (Account Updater).

### 2.7 Tarjetas en POS integrado

`POST /payments` con `terminal_operation_method: "CARD"` (default) o `"QR_CODE"`. APIs: `paystore_terminals_payments_v1`, `_refunds_v1`, `_reversals_v1`, `_settlements_v1` + `oauth-api`.

---

## 3. QR

Cinco APIs distintas, según quién es el actor. Todas bajo `https://api-sandbox.payway.com.ar`.

### 3.1 `payments_decidir_qr_services_v1` — la más completa
`/v1/decidir_qr_services` · categoría Pagos · para Bancos / Freelance / Wallets.
Headers: `apikey` + `Cuit-Owner` (delegation API).

**Sistema de conexión directa** (billetera propia):
```
GET  /direct_connection_system/intentions          obtener intención originada en sistema propio
POST /direct_connection_system/payments            generar compra
GET  /direct_connection_system/payments            consultar compra
POST /direct_connection_system/encrypted/payments  compra con datos de tarjeta cifrados
POST /direct_connection_system/annulments          anular
GET  /direct_connection_system/annulments
POST /direct_connection_system/encrypted/annulments
POST /direct_connection_system/refunds             devolver
GET  /direct_connection_system/refunds
POST /direct_connection_system/encrypted/refunds
GET  /wallet/healthcheck/status
```
`DirectConnectionPaymentRequest`: `intention_id`, `cuit`, `branch_office`, `checkout`, `payment_method_information {scheme, type}`, `card_information` (**oneOf**: `RawCardData` | `TokenizedCardData` | `EncryptedCardData`), `bank_information`, `amount`, `currency` (solo `ARS`), `installments`.

`payment_method_information.scheme` (enum de 34 marcas): VISA, DINERS, SHOPPING, NARANJA, PAGOFACIL, RAPIPAGO, CABAL, ITALCRED, ARGENCARD, COOPERPLUS, NEXO, CREDIMAS, NEVADA, NATIVA, CENCOSUD, CARREFOUR, CETELEM, PYME_NACION, CAJA_DE_PAGOS, BBPS, COBRO_EXPRESS, QIDA, GRUPAR, PATAGONIA_365, CLUB_DIA, TUYA, DISTRIBUCION, LA_ANONIMA, CRED_GUIA, CABAL_PRISMA, SOL, AMEX, FAVACARD, MASTERCARD, MAESTRO, **TRANSFERENCIAS_30**. `type`: `CREDITO` | `DEBITO`.

**Large business** (integrador tercero) — *acá se cruzan QR + bines + promociones*:
```
GET /large_business/intentions       ?cuit&checkout&branch_office
PUT /large_business/intentions       ← "put bines to the generated intention"
POST /large_business/payments
GET  /large_business/{operation}     payments|annulments|refunds
```

### 3.2 `payments_acquiring_qr_services_v1` — parseo de QR adquirente
`/v1/acquiring_qr_services` · `POST /details` con `{qr_raw}` → devuelve `qr_id`, `operation_type` (`PURCHASE`\|`ANNULMENT`\|`REFUND`), `pos_type` (`com.adq`\|`com.spr`\|`com.pp`), `amount`, `installments`, `transaction_datetime`, `payment_mode` (`ACQUIRING_COMMERCE`), `hash`, `establishment_data`.

### 3.3 `prisma_wallet_qr_services_v2` — parseo de QR con promociones
`/v2/prisma_wallet/qr_services` · `POST /qr/details` con `{qr_raw}` (QR EMVCo con tags `com.adq` / `com.pp` / `com.spr`). **Es el endpoint que devuelve cuotas y descuentos** — ver §6.

### 3.4 Resto de Prisma Wallet
- `prisma_wallet_payment_services_v2` y `_v3` — `POST /proprietary/payments`, `POST /proprietary/payments/{payment_id}/reimbursements`, `GET /proprietary/{account_id}/operations/{payment_id}`.
- `prisma_wallet_proprietary_intentions_services_v2` — `POST /accounts/{accountId}/intentions/{intentionId}/wallet`, `GET /intentions/{intentionId}`.
- `prisma_wallet_proprietary_payments_services_v2` / `_reimbursements_services_v2`.
- `prisma_wallet_account_services_v2`, `_methods_services_v2`, `_transaction_data_services_v2`, `_acquirer_details_services_v2`.

### 3.5 QR en POS integrado
`POST /payments` con `terminal_operation_method: "QR_CODE"` (si no se informa, default `CARD`).

---

## 4. REDIRECCIÓN — hallazgo negativo

**No hay ninguna API de checkout con redirección en ninguno de los dos sitios.** Lo verificado:

- El spec `payway-gateway-api` no tiene ningún campo `redirect_url`, `return_url`, `success_url`, `callback_url`, `init_point` ni similar.
- No hay endpoints de "preference", "checkout", "payment link" ni "payment intent con URL".
- Los 23 documentos de *Pagos Online* no mencionan 3DS, ACS, challenge ni redirección. "Checkout" aparece 3 veces y siempre significa **"el checkout del comercio"**.
- `Requisitos Técnicos` es explícito: *"El comercio debe contar con un back-end que realice las operaciones de pago mediante requests HTTPS directos hacia los endpoints de Payway, bajo una modalidad **server-to-server**"*.
- El SDK de frontend (`payway-ar/sdk-javascript-ventaonline`) hace **solo tokenización** (`createToken(form, callback)`), no renderiza formulario ni redirige. Endpoints: `https://developers.decidir.com/api/v2` (sandbox) / `https://ventasonline.payway.com.ar/api/v2` (prod).

**Lo que sí existe, pero fuera de la API:**
- **Link de pago**: se genera desde el panel *Mi Payway* y se comparte por WhatsApp/mail/redes. Sin API pública documentada.
- **Botón de pago / plugins**: Magento, WooCommerce y PrestaShop (repos `payway-ar/plugin-*`). Internamente usan el mismo `/api/v2`, no redirigen.
- El campo `checkout` que aparece en las APIs QR **no es un hosted checkout**: es el identificador de la caja/punto de cobro del comercio (≤25 chars), junto con `cuit` y `branch_office`.

> Conclusión práctica: para Hyperswitch, Payway online modela **solo** `PaymentMethodData::Card` con flujo directo (Authorize server-to-server). No hay `RedirectForm`, no hay `AuthenticationPending`, no hay wallet redirect.

---

## 5. BINES

Dos usos totalmente distintos:

### 5.1 `bin` como campo obligatorio de la transacción
En `POST /payments` el `bin` (6 dígitos, `^\d{6}$`) es **required**, incluso cuando se paga con `token` o `card_token_data`. En NO PCI el backend nunca ve el PAN completo, pero **igual tiene que tener los 6 primeros dígitos** — el `TokenResponse` los devuelve en `bin` (ahí acepta `^\d{6,8}$`).

BINs que aparecen en los ejemplos de la doc: `450799` (Visa crédito), `450792`, `411612`, `451772` (Visa débito), `529991`/`545533`/`520423` (Mastercard), `589657` (Cabal).

### 5.2 `Bin Services` — API de rangos de bines
`bin_services_proxy_v1` · categoría *Servicios* · para **Comercios** · `https://api-sandbox.payway.com.ar/v1/ds-bin-integration`

```
POST /public/reduced-bin-list   "Get bins with all available information with reduced info"
GET  /public/liveness
```

**Request `GetAllBinRequest`** (requeridos `binRangeCount` + `binRangeSearchIndex`):

| Campo | Tipo | Notas |
|---|---|---|
| `binRangeCount` | int | **100..1000** — paginado, fuera de rango da 400 |
| `binRangeSearchIndex` | int | offset de la página |
| `paymentAccountType` | string `^[PT]$` | |
| `brand` | enum | `VISA`, `AMEX`, `MASTERCARD`, `DISCOVER`, `UNION_PAY`, `CABAL` |
| `countryAlpha2` | enum ISO-2 | ~250 valores |
| `fundingSource` | enum | `CREDIT`, `DEFERRED_DEBIT`, `CHARGE_CARD`, `DEBIT`, `PREPAID` |
| `status` | `^(DELETED\|ACTIVE)$` | |

**Response `ReducedBinDTO`**: `binRangeMinNum`, `binRangeMaxNum`, `brand`, `paymentAccountType`, `fundingSource`, `status`, `currencyCode`, `gamblingBlockEnabled`, `costumerName`, `productId`, `productDescription`, `accountCountryISO`.

Es una API de **descarga masiva de rangos** (min/max, no BIN suelto) — sirve para armar una tabla local BIN→marca/tipo, no para consultar un PAN puntual. Ejemplos de la doc: `{binRangeCount: 100, binRangeSearchIndex: 0}` → 200; `{binRangeCount: 400}` → 400 Bad Request (llamativo, pero es lo que dice el ejemplo del portal).

### 5.3 Bines en el flujo QR
`PUT /large_business/intentions` — *"put bines to the generated intention"*. La billetera manda los bines de las tarjetas del usuario a la intención de pago y Payway responde con los **beneficios aplicables a cada una**:

```jsonc
// request: ModelServiceCustomerCardsBinesRequest
{
  "benefits_methods_data": [ { "benefits_card": { "card_number": "...", "code": "...", "description": "..." } } ],  // requerido
  "payment_methods_data":  [ { "bank_ids": [...], "payment_method_scheme": "...", "payment_method_type": "..." } ]
}
```
La intención (`IntentionResponseDTO`) devuelve además **`bins_max_quantity`** — tope de bines que se pueden enviar.

---

## 6. PROMOCIONES / CUOTAS

Es el tema más fragmentado. **No existe una "API de Promociones" para ecommerce.**

### 6.1 En ecommerce: no hay
En Payway Gateway API lo único relacionado es `installments` (1..99). No hay endpoint para consultar planes, cuotas sin interés, CFT/TNA ni descuentos. Los plugins oficiales resuelven esto **del lado del comercio**: `plugin-magento-promotions` (módulo aparte con tablas `promotions_bank` / `promotions_card` / `promotions_rule`), `plugin-woocommerce` (`class-payway-promotion-factory.php`, `admin-promotions-plans.js`), `plugin-prestashop` (`AdminPaywayPromotions`). Es decir: **el comercio carga sus propias reglas banco+tarjeta+cuotas**.

### 6.2 En QR/wallet: sí, y con bastante detalle
`POST /qr/details` de `prisma_wallet_qr_services_v2` devuelve, dentro de `data.intention`:

```jsonc
{
  "installment_rules": [{
    "payment_method_id": "29",
    "brand": 1,
    "bank_installments": {
      "default": [ { "quantity": 1, "total_amount": 1200, "cft": 0, "tna": 0 } ]
    },
    "datetime": "...", "trace_number": "54335"
  }],
  "benefits_methods_data": [{
    "establishment_id": null,
    "benefits_card": { "code": "CC", "description": "Clarin classic" },
    "discount": { "percentage": 10, "maximum_discount_amount": 50 }
  }]
}
```
- **Cuotas** → `installment_rules[].bank_installments.default[]` con `quantity`, `total_amount`, **`cft`** y **`tna`** (costo financiero total y tasa nominal anual — obligatorio mostrarlos en AR).
- **Descuentos / tarjetas de beneficio** → `benefits_methods_data[]` con `benefits_card {code, description}` y `discount {percentage, maximum_discount_amount}`.
- También `loyalty_program {id, name, establishment}` y `payment_methods[] {id, require_cvv, banks[]}`.

Al cobrar (`POST /large_business/payments`) se devuelve el beneficio elegido:
```jsonc
"benefits_data": { "original_amount": 1000, "discounted_amount": 900,
                   "benefits_card": { "code": "CC", "description": "Clarin classic" } }
```

### 6.3 `Quota Calculator Proxy` — calculadora de costo financiero
`proxy_quota_calculator_v1` · *"Swagger - financial cost calculator"* · para **Partners**
`GET https://api-sandbox.payway.com.ar/v1/quota_calculator_services/`

Query params (todos opcionales): `ticket` (monto), `metodo` (medio de pago), `plazo_pago` (default `2`), `arancel`, `getMetodos` (bool — devuelve el listado de métodos). El response no está tipado en el spec.

Es una calculadora **comercial** (cuánto cobra el comercio según arancel y plazo de acreditación), no un motor de promociones al comprador.

### 6.4 `Opps Agreements Proxy` — única API en categoría "Promociones"
`proxy_opps_agreements_v1` · para Partners · `POST /agreements` (baja de convenio), `POST /limit` (modificación de límite de convenio). Es **gestión de convenios**, no consulta de promos.

---

## 7. Catálogo completo del portal (33 APIs)

Todas en `https://api-sandbox.payway.com.ar`, `OAuth2 2-legged` salvo indicado.

| API | Path base | Categoría | Para |
|---|---|---|---|
| **Bin Services** | `/v1/ds-bin-integration` | Servicios | Comercios |
| **Payments - Decidir QR Services** | `/v1/decidir_qr_services` | Pagos | Bancos/Freelance/Wallets |
| **Payments - Acquiring QR Services** | `/v1/acquiring_qr_services` | Wallets, Pagos | Bancos/Empresas/Freelancers |
| **Prisma Wallet - Qr Services** | `/v2/prisma_wallet/qr_services` | Billetera | Bancos |
| Prisma Wallet - Payments Services v2 / v3 | `/v2` · `/v3 /prisma_wallet/payment_services` | Pagos | Bancos |
| Prisma Wallet - Account Services | `/v2/prisma_wallet/account_services` | Billetera | Bancos |
| Prisma Wallet - Payment Methods Services | `/v2/prisma_wallet/wallet_services` | Billetera | Bancos |
| Prisma Wallet - Proprietary Intentions / Payments / Reimbursements | `/v2/prisma_wallet/proprietary_*` | Billetera | Bancos |
| Prisma Wallet - Transaction Data Services | `/v2/prisma_wallet/transaction_data_services` | Billetera | Bancos |
| Prisma Wallet - Acquirer Details Services | `/v2/prisma_wallet/acquirer_details_services` | Billetera | Bancos |
| Paystore Terminals - Payments | `/v1/paystore_terminals/terminal_payments` | Pagos | Comercios |
| Paystore Terminals - Refunds | `/v1/paystore_terminals/terminal_refunds` | Pagos | Comercios |
| Paystore Terminals - Reversals | `/v1/paystore_terminals/terminal_reversals` | Pagos | Comercios |
| Paystore Terminals - Settlements | `/v1/paystore_terminals/terminal_settlements` | Pagos | Comercios |
| **Token Requestor Services** | `/v1/tokenization_services/token_requestor_services` | Servicios | Comercios/PSP |
| **Token Requestor Notification Services** | `/v1/tokenization_services/notifications` | Servicios Salientes | Comercios/PSP |
| **Quota Calculator Proxy** | `/v1/quota_calculator_services` | Gestión y consulta | Partners |
| **Opps Agreements Proxy** | `/v1/opps_agreements_services` | **Promociones** | Partners |
| SEM (Banks Merchant Administration) | `/v1/sem` | Gestión y consulta | Bancos |
| SEM Partners | `/v1/sem_partners` | Gestión y consulta | Partners |
| api-moviliq | `/v1/api-moviliq` | Gestión y consulta | Comercios/Bancos |
| Consulta de transacciones real time | `/v1/concentrador-tx` | Servicios Salientes | Partners |
| Controversies Integration Interface (Apikey) | `/v1/controversies-data` | Servicios | Partners |
| API Documentation Proxy | `/v1/ms-documentation-proxy` | Servicios | Bancos |
| Virtual Account | `/v1/virtual-account` | Servicios Salientes | Partners |
| Funded Natives Proxy | `/v1/funded-natives-services` | Gestión y consulta | Partners |
| Salesforce Connector / ms-salesforce / apip-ms-salesforce | `/v1/salesforce_connector`, `/v1/ms-salesforce`, `/v1/apip-ms-salesforce` | Servicios | Bancos/Partners |

---

## 8. Cómo volver a extraer todo (las dos webs son SPA)

Ambos sitios devuelven solo el shell de Next.js. **Hace falta User-Agent de browser** o el CDN devuelve el shell hasta para los `.js`.

```bash
UA='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36'

# ---------- docs.payway.com.ar (BFF público) ----------
BFF=https://backend.portaldevelopers.payway.com.ar/bff2/api
curl -sA "$UA" $BFF/products                                  # 2 productos
curl -sA "$UA" $BFF/products/ventas-online/documents          # árbol + s3_url de cada .md
curl -sA "$UA" $BFF/products/ventas-online/payway-gateway-api # OpenAPI en .raw_spec
# los markdown se bajan directo:
curl -sA "$UA" https://docs.payway.com.ar/docs/ventas-online/v1/docs/Pago_simple.md

# ---------- developers.payway.com.ar (requiere Referer) ----------
API=https://portal.developers.payway.com.ar/apiportal-api
REF='Referer: https://developers.payway.com.ar/catalog'
curl -sA "$UA" -H "$REF" "$API/products?limit=100"                                       # 33 APIs
curl -sA "$UA" -H "$REF" "$API/products/Bin%20Services/version/bin_services_proxy_v1/swagger"
curl -sA "$UA" -H "$REF" "$API/products/Bin%20Services/version/bin_services_proxy_v1/documentation"
# patrón: /products/{displayName urlencoded}/version/{name}/{swagger|documentation}
```

URLs útiles de la UI:
- Doc funcional: `https://docs.payway.com.ar/docs/ventas-online/<slug>`
- API Reference con operación: `https://docs.payway.com.ar/api-reference/ventas-online/payway-gateway-api?path=%2Fpayments&method=POST`
- Catálogo: `https://developers.payway.com.ar/catalog` · ficha: `/catalog/doc/<name>`

Repos oficiales: `github.com/payway-ar` → `sdk-java-ventaonline`, `sdk-net-ventaonline`, `sdk-node-ventaonline`, `sdk-php-ventaonline`, `sdk-javascript-ventaonline`, `plugin-woocommerce`, `plugin-prestashop`, `plugin-magento-promotions`, `docs`.

---

## 9. Pendientes / lo que no pude ver

- El **catálogo del portal expone Swagger sin login**, pero el **"Sandbox / Ejecutar caso de prueba"** y el alta de proyectos requieren cuenta registrada + token OAuth. Para probar contra `api-sandbox.payway.com.ar` hay que registrarse en `developers.payway.com.ar`, crear equipo/proyecto y pedir acceso a cada API (`requestAccessApi`).
- El response del **Quota Calculator** no está tipado en el spec — habría que ejecutarlo con token para ver la estructura real.
- El OpenAPI de Payway Gateway se llama internamente `Decidir_202600406_URLMock_SinTokenPCI - V6.yml` — es un mock/URL de referencia; conviene contrastar contra el ambiente real antes de fijar contratos.
- API Keys de sandbox se piden a **soporte@payway.com.ar**.

---

## 10. Verificación empírica contra sandbox (2026-08-07)

Probado con las keys DEV de ventas online del comercio.

| Prueba | Resultado |
|---|---|
| `POST /api/v2/tokens` con `api_key` | **201** → es la **Public API Key** |
| `POST /api/v2/tokens` con `key1` | 403 `"You cannot consume this service"` |
| `GET /api/v2/payments` con `key1` | **200**, devuelve transacciones reales → `key1` es la **Private API Key** |
| `GET /v1/oauth/accesstoken` (Basic `api_key:key1`, y al revés) en `api-homo` y `api-sandbox` | 401 `OAU-401 CREDENTIAL NO EXIST` → **las keys de ventas online NO son credenciales OAuth del API Program** |
| `POST /v1/ds-bin-integration/public/reduced-bin-list` con `apikey` / `Authorization: Bearer` / `x-api-key`, ambas keys | 401 `APIM-401 Unauthorized` en los 5 intentos |
| `GET /v1/quota_calculator_services/` con `apikey` / `Bearer` | 401 `APIM-401 Unauthorized` |
| Sondeo de 21 paths en el gateway (`/bines`, `/bin/450799`, `/promotions`, `/payment-methods`, `/installments`, `/cuotas`, `/plans`, `/promotions/plans`, …) con ambas keys | **404 en todos**; control `/usersite/{id}/cardtokens` → 200 |

**Conclusiones confirmadas:**

1. Son **dos planos de autenticación distintos**. El gateway de ecommerce (`*-ventasonline.payway.com.ar/api/v2`) va con header `apikey`; el API Program (`api-sandbox.payway.com.ar`) va con `Authorization: Bearer` de un token OAuth2 client-credentials emitido por **proyecto** en el portal. Las credenciales no son intercambiables.
2. **El gateway de ecommerce no expone nada de bines ni promociones** (§5.1 y §6.1 quedan verificados, no inferidos).
3. Lo único BIN-like disponible con las keys de comercio es la respuesta de `POST /tokens`, que devuelve `bin` (6), `card_number_length`, `security_code_length` y `last_four_digits`. Verificado:

   | Tarjeta de prueba | `bin` | `card_number_length` | `security_code_length` |
   |---|---|---|---|
   | Visa crédito `4507990000004905` | `450799` | 16 | 3 |
   | Mastercard `5299910010000015` | `529991` | 16 | 3 |
   | Cabal `5896570000000008` | `589657` | 16 | 3 |
   | Visa débito `4517721004856075` | `451772` | 16 | 3 |

   No devuelve marca, tipo (crédito/débito) ni banco: para eso hace falta `Bin Services`.
4. Las promociones de los plugins son **100 % locales**: `WC_Payway_Promotion_Factory::get_required_fields()` pide `rule_name`, `bank_id`, `card_id`, `from_date`, `to_date`, `applicable_days`. Ninguna llamada HTTP a Payway, ni uso de `bin`.

**Para probar Bin Services y Quota Calculator hace falta:** cuenta en `developers.payway.com.ar` → equipo → proyecto → solicitar acceso a esas dos APIs → obtener `client_id`/`client_secret` del proyecto. Después:

```bash
PW_CLIENT_ID=... PW_CLIENT_SECRET=... ./payway_apim_test.sh     # sandbox
PW_ENV=prod PW_CLIENT_ID=... PW_CLIENT_SECRET=... ./payway_apim_test.sh
```
(script en la raíz del repo; hace el `GET /v1/oauth/accesstoken` y con el Bearer pega a los dos endpoints, incluido el caso de error de `binRangeCount` fuera de 100..1000).
