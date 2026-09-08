# Wompi Colombia — Documentación técnica de la API

> Consolidado de la documentación oficial `https://docs.wompi.co/docs/colombia/`, el centro de ayuda `soporte.wompi.co` y la especificación OpenAPI oficial (SwaggerHub `waybox/wompi` 1.2.0). Fecha de extracción: **2026-07-31**. Todo lo aquí descrito aplica a **Colombia** (moneda `COP`).

## Índice

1. [Resumen general](#1-resumen-general)
2. [Ambientes y hosts](#2-ambientes-y-hosts)
3. [Credenciales: llaves y secretos](#3-credenciales-llaves-y-secretos)
4. [Tokens de aceptación](#4-tokens-de-aceptación--get-merchantsllave_publica)
5. [Firma de integridad](#5-firma-de-integridad-signature)
6. [Transacciones](#6-transacciones)
7. [Métodos de pago](#7-métodos-de-pago)
8. [Cuotas (installments)](#8-cuotas-installments)
9. [Tokenización](#9-tokenización)
10. [Fuentes de pago y pagos recurrentes](#10-fuentes-de-pago-y-pagos-recurrentes)
11. [3D Secure v2](#11-3d-secure-v2)
12. [Anulaciones y devoluciones](#12-anulaciones-void-y-devolucionesreembolsos)
13. [Eventos (webhooks)](#13-eventos-webhooks)
14. [Seguimiento de transacciones y reintento de pago](#14-seguimiento-de-transacciones-y-reintento-de-pago)
15. [Sandbox: datos de prueba](#15-sandbox-datos-de-prueba)
16. [Errores](#16-errores)
17. [Impuestos](#17-impuestos-taxes)
18. [Links de pago](#18-links-de-pago--payment_links)
19. [Widget y Checkout Web](#19-widget-y-checkout-web)
20. [Cifrado JWE](#20-cifrado-jwe)
21. [Pagos a terceros (payouts)](#21-pagos-a-terceros-payouts--api-separada)
22. [Planes y comisiones](#22-planes-y-comisiones)
23. [Vacíos documentales y notas de implementación](#23-vacíos-documentales-y-notas-de-implementación)
24. [Fuentes](#24-fuentes)

---

## 1. Resumen general

- **Wompi** es la pasarela de pagos de Bancolombia. Tres vías de integración: **Widget & Checkout Web** (embebido o redirección), **plugins eCommerce** (WooCommerce, Shopify, Jumpseller, Magento, PrestaShop, VTEX) y **API REST**.
- **Modelo 100 % asíncrono:** ninguna transacción retorna resultado síncrono. Toda transacción nace en `PENDING` y se resuelve por **polling** (`GET /transactions/{id}`) o por **webhook** (`transaction.updated`).
- **Moneda:** solo `COP`. **Montos siempre en centavos** (`amount_in_cents`; ej. `$95.000 COP` → `9500000`).
- **`acceptance_token` es obligatorio** para crear transacciones y fuentes de pago.
- **Idempotencia:** no hay header de idempotencia; el mecanismo efectivo es la **unicidad de `reference`** (repetida → `422 INPUT_VALIDATION_ERROR` "La referencia ya ha sido usada").

## 2. Ambientes y hosts

| Ambiente | Base URL API | Uso |
|---|---|---|
| **Sandbox** | `https://sandbox.wompi.co/v1` | Pruebas, sin dinero real |
| **Producción** | `https://production.wompi.co/v1` | Dinero real |

Otros hosts:

| Host | Uso |
|---|---|
| `https://checkout.wompi.co` | Widget (`/widget.js`), Checkout Web (`/p/`), links de pago (`/l/{id}`) |
| `https://comercios.wompi.co` | Dashboard del comercio: llaves, secretos, URL de eventos, reportes |

> ⚠️ **Inconsistencia de la doc oficial:** la página de *Métodos de pago* dice literalmente "Para Colombia usa `https://api.wompi.co/v1` como `BASE_URL` en los ejemplos", mientras que *Ambientes y llaves* define `sandbox.wompi.co/v1` / `production.wompi.co/v1`. En la práctica `api.wompi.co/v1` funciona como alias de producción; para integración usa los hosts explícitos por ambiente (`sandbox` / `production`).

**Regla crítica:** "cuando usas la URL de un entorno, debes usar sus respectivas llaves". Llave de un ambiente contra el host del otro → `401 INVALID_ACCESS_TOKEN`.

No hay proceso de activación de producción documentado en la página de ambientes; las llaves de producción se obtienen al completar el registro del comercio en `comercios.wompi.co`.

## 3. Credenciales: llaves y secretos

Se obtienen en `comercios.wompi.co` → **Desarrolladores → Secretos para integración técnica**. Son 4 credenciales, cada una con variante por ambiente:

| Credencial | Prefijo sandbox | Prefijo producción | Ejemplo (de la doc) | Uso |
|---|---|---|---|---|
| **Llave pública** | `pub_test_` | `pub_prod_` | `pub_prod_Kw4a…` | Tokenizar tarjetas/Nequi, crear transacciones, `GET /merchants`, `GET /transactions/{id}`, PSE instituciones, Widget/Checkout |
| **Llave privada** | `prv_test_` | `prv_prod_` | `prv_prod_4340…` | Fuentes de pago, búsqueda de transacciones, anulaciones (void), links de pago |
| **Secreto de eventos** | `test_events_` | `prod_events_` | `prod_events_Y49r…` | Validar el checksum de los webhooks |
| **Secreto de integridad** | `test_integrity_` | `prod_integrity_` | `prod_integrity_ep4b…` | Calcular la firma `signature` de transacciones/checkout |

**Autenticación HTTP:** header `Authorization: Bearer <llave>` (pública o privada según el endpoint).

Resumen de qué llave usa cada endpoint:

| Endpoint | Llave |
|---|---|
| `GET /merchants/{pub_key}` | pública (en la ruta) |
| `POST /tokens/cards`, `POST /tokens/nequi`, `POST /tokens/daviplata`, `POST /tokens/bancolombia_transfer` | pública |
| `POST /transactions` | pública |
| `GET /transactions/{id}` | pública |
| `GET /pse/financial_institutions` | pública |
| `GET /transactions` (búsqueda con filtros) | **privada** |
| `POST /transactions/{id}/void` | **privada** |
| `POST /payment_sources`, `GET /payment_sources/{id}`, `PUT /payment_sources/{id}/void` | **privada** |
| `POST /payment_links`, `PATCH /payment_links/{id}` | **privada** (`GET /payment_links/{id}` es público) |

## 4. Tokens de aceptación — `GET /merchants/{llave_publica}`

Sin body. Devuelve la info del comercio y **dos tokens prefirmados** (JWT con claim `exp`; TTL exacto no publicado):

```json
{
  "data": {
    "id": 1234,
    "name": "Mi Comercio",
    "legal_name": "Mi Comercio SAS",
    "legal_id": "900123456",
    "legal_id_type": "NIT",
    "active": true,
    "public_key": "pub_prod_...",
    "accepted_payment_methods": ["CARD", "NEQUI", "PSE", "BANCOLOMBIA_TRANSFER", "..."],
    "accepted_currencies": ["COP"],
    "presigned_acceptance": {
      "acceptance_token": "eyJhbGciOiJIUzI1NiJ9...",
      "permalink": "https://wompi.co/wp-content/uploads/2019/09/TERMINOS-Y-CONDICIONES-DE-USO-USUARIOS-WOMPI.pdf",
      "type": "END_USER_POLICY"
    },
    "presigned_personal_data_auth": {
      "acceptance_token": "eyJhbGciOiJIUzI1NiJ9...",
      "permalink": "https://wompi.com/assets/downloadble/autorizacion-administracion-datos-personales.pdf",
      "type": "PERSONAL_DATA_AUTH"
    }
  }
}
```

- `presigned_acceptance.acceptance_token` → se envía como **`acceptance_token`** en `POST /transactions` y `POST /payment_sources` (términos y condiciones, `END_USER_POLICY`).
- `presigned_personal_data_auth.acceptance_token` → se envía como **`accept_personal_auth`** (tratamiento de datos personales, `PERSONAL_DATA_AUTH`).
- El `permalink` (PDF del contrato) debe mostrarse al usuario final.
- Errores: `404 NOT_FOUND_ERROR` si la llave no existe.

## 5. Firma de integridad (`signature`)

**SHA-256 en hexadecimal** (64 chars, minúsculas) de la concatenación **sin separadores, en este orden exacto**:

```text
<reference><amount_in_cents><currency>[<expiration_time>]<secreto_integridad>
```

- `expiration_time` entra en la cadena **solo si se usa** (ISO 8601 UTC, ej. `2023-06-09T20:28:50.000Z`).
- **Ejemplo oficial:** reference `sk8-438k4-xmxm392-sn2m`, monto `2490000`, `COP`, secreto `prod_integrity_Z5mM…`:

```text
Cadena:  "sk8-438k4-xmxm392-sn2m2490000COPprod_integrity_Z5mM…"
SHA-256: 3a4bd1f3e3edb5e88284c8e1e9a191fdf091ef0dfca9f057cb8f408667f054d0
```

Implementaciones:

```javascript
// Node/Web Crypto
const enc = new TextEncoder().encode(cadenaConcatenada);
const buf = await crypto.subtle.digest("SHA-256", enc);
const hex = Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, "0")).join("");
```

```php
hash("sha256", $cadena);           // PHP
```
```ruby
Digest::SHA2.hexdigest(cadena)     # Ruby
```
```python
hashlib.sha256(cadena.encode()).hexdigest()  # Python
```

- **Calcular siempre en el servidor** — nunca exponer el secreto de integridad en el frontend.
- En Widget/Checkout Web se pasa como `data-signature:integrity` / `signature: { integrity }`.
- Se usa en `POST /transactions` (campo `signature`) y en cobros recurrentes con `payment_source_id`.

## 6. Transacciones

### 6.1 Crear — `POST /transactions`

Auth: **llave pública** (Bearer). Respuesta exitosa: **HTTP 201** con la transacción en `PENDING`.

| Campo | Tipo | Obligatorio | Detalle |
|---|---|---|---|
| `acceptance_token` | string (JWT) | Sí | De `presigned_acceptance` |
| `accept_personal_auth` | string (JWT) | Sí | De `presigned_personal_data_auth` |
| `amount_in_cents` | integer | Sí | Centavos. Mín 1, máx 1e12 (swagger) |
| `currency` | string | Sí | Solo `"COP"` |
| `signature` | string | Sí | Firma de integridad (§5) |
| `customer_email` | string | Sí | Email del pagador (recibe comprobante) |
| `reference` | string | Sí | **Única** por transacción (máx 255 chars); duplicada → 422 |
| `payment_method` | object | Condicional | Obligatorio si NO se envía `payment_source_id` (estructura por método, §7) |
| `payment_source_id` | integer | Condicional | Para pagos con fuente guardada (§10) |
| `redirect_url` | string (URL) | No | Redirección post-pago (métodos asíncronos) |
| `expiration_time` | string ISO 8601 UTC | No | Fecha límite de pago; **si se usa, entra en la firma** |
| `ip` | string | No | IP del dispositivo del pagador |
| `recurrent` | boolean | No | COF: `true` = recurrencia periódica de montos iguales; `false` = COF almacenada (montos variables). Solo Visa/Mastercard con procesador RBM |
| `taxes` | array | No | §17 |
| `customer_data` | object | No* | `full_name` (requerido dentro del objeto), `phone_number`, `legal_id`, `legal_id_type` (`CC`/`CE`/`NIT`/`PP`/`TI`/`DNI`/`RG`/`OTHER`). *Requerido para PSE, PCOL y 3DS |
| `shipping_address` | object | No | `address_line_1` (req.), `address_line_2`, `country` (req., ISO 3166-1 alpha-2), `region` (req.), `city` (req.), `name`, `phone_number`, `postal_code` |
| `is_three_ds` | boolean | No | Activa 3DS v2 (§11) |
| `three_ds_auth_type` | string | Solo sandbox | Fuerza escenario 3DS (§11.4); **omitir en producción** |

Ejemplo (tarjeta):

```json
POST /v1/transactions        Authorization: Bearer pub_prod_xxx
{
  "amount_in_cents": 50000,
  "currency": "COP",
  "customer_email": "juan@example.com",
  "payment_method": { "type": "CARD", "token": "tok_prod_1_BBb...", "installments": 1 },
  "signature": "37c8407747e595535433ef8f6a811d853cd943046624a0ec04662b17bbf33bf5",
  "reference": "ORDER-2024-001",
  "acceptance_token": "eyJhbGciOiJIUzI1NiJ9...",
  "accept_personal_auth": "eyJhbGciOiJIUzI1NiJ9..."
}
```

Respuesta 201 (`data`): `id` (formato `1292-1602113476-10985`), `created_at`, `finalized_at`, `amount_in_cents`, `reference`, `currency`, `customer_email`, `payment_method_type`, `payment_method` (incluye `extra`: `brand`, `last_four`, `async_payment_url`, etc.), `status` (`PENDING`), `status_message`, `redirect_url`, `shipping_address`, `payment_link_id` (nullable), `payment_source_id` (nullable), `merchant {id, name, legal_name}`.

> Nota: varios ejemplos oficiales duplican el tipo en `payment_method_type` a nivel raíz además de `payment_method.type` (visto en DAVIPLATA, SU_PLUS, BNPL).

### 6.2 Consultar — `GET /transactions/{transaction_id}`

Con **llave pública**. `200 → {data: Transaction}`; `404 → NOT_FOUND_ERROR`. Es el endpoint de **polling** para resolver el estado final.

### 6.3 Buscar — `GET /transactions` (llave privada)

| Query param | Detalle |
|---|---|
| `reference` | Búsqueda por referencia (suficiente por sí sola) |
| `from_date`, `until_date` | Ej. `2018-07-01`; requeridos junto con `page`/`page_size` si no hay `reference` |
| `page`, `page_size` | Paginación (única documentada en el API) |
| `id` | ID de transacción |
| `payment_method_type` | `CARD`/`NEQUI`/`PSE`/`BANCOLOMBIA_TRANSFER`/`BANCOLOMBIA_COLLECT`/`BANCOLOMBIA_QR`/... |
| `status` | `PENDING`/`APPROVED`/`DECLINED`/`ERROR`/`VOIDED` |
| `customer_email` | email |
| `order_by`, `order` | ej. `created_at`, `DESC`/`ASC` |

### 6.4 Estados de la transacción

| Estado | ¿Final? | Significado |
|---|---|---|
| `PENDING` | No | Creada, en proceso (esperando pago/confirmación) |
| `APPROVED` | Sí | Aprobada y completada |
| `DECLINED` | Sí | Rechazada (fondos insuficientes, datos inválidos, no autenticada, etc.) |
| `VOIDED` | Sí | Anulada — **solo tarjetas** |
| `ERROR` | Sí | Error interno del proveedor del método de pago al autorizar |

**Rate limits:** no documentados públicamente.

## 7. Métodos de pago

Índice oficial (10 métodos): `CARD`, `BANCOLOMBIA_TRANSFER`, `BANCOLOMBIA_QR`, `NEQUI`, `PSE`, `BANCOLOMBIA_COLLECT`, `PCOL`, `BANCOLOMBIA_BNPL`, `DAVIPLATA`, `SU_PLUS`. (BRE-B **no** aparece como método de cobro.)

Patrón común de los métodos asíncronos con redirección: crear transacción → polling hasta que `payment_method.extra.async_payment_url` aparezca → redirigir al cliente → polling/webhook hasta estado final.

### 7.1 Tarjetas — `CARD`

```json
"payment_method": {
  "type": "CARD",
  "token": "tok_prod_1_BBb749EAB32e97a2D058Dd538a608301",
  "installments": 2
}
```

- Requiere token previo de `POST /tokens/cards` (§9.1).
- Marcas: Visa, Mastercard, American Express (todas requieren CVC).
- Único método que soporta `VOIDED` (anulación).
- 3DS v2 disponible (§11).

### 7.2 PSE — `PSE`

Primero obtener la lista de bancos: **`GET /pse/financial_institutions`** (llave pública) → array `[{financial_institution_code, financial_institution_name}]`; se usa el `code` como `financial_institution_code`.

```json
{
  "customer_email": "cliente@example.com",
  "payment_method": {
    "type": "PSE",
    "user_type": 0,
    "user_legal_id_type": "CC",
    "user_legal_id": "1099888777",
    "financial_institution_code": "1",
    "payment_description": "Pago a Tienda Wompi, ref: JD38USJW2XPLQA",
    "reference_one": "192.168.0.1",
    "reference_two": "20240101",
    "reference_three": "123456"
  },
  "customer_data": { "phone_number": "573145678901", "full_name": "Nombre Apellido" }
}
```

| Campo | Valores / restricción |
|---|---|
| `user_type` | `0` = persona natural, `1` = persona jurídica (entero) |
| `user_legal_id_type` | `CC`, `NIT` |
| `user_legal_id` | Número de documento (string) |
| `financial_institution_code` | `code` del banco (endpoint de instituciones) |
| `payment_description` | Máx. 30 caracteres según la página de sandbox; la de métodos de pago dice 64 — **inconsistencia de la doc; usar ≤30 es lo seguro** |
| `customer_data.full_name` y `phone_number` | **Requeridos** para PSE |
| `reference_one/two/three` | Opcionales antifraude (IP, fecha apertura `yyyymmdd`, ID beneficiario); cifrables con JWE (§20) |

Redirección: polling hasta `payment_method.extra.async_payment_url` → redirigir al banco. Estados: `PENDING` → `APPROVED`/`DECLINED`/`ERROR`.

### 7.3 Nequi — `NEQUI`

```json
"payment_method": { "type": "NEQUI", "phone_number": "3107654321" }
```

- Celular colombiano de 10 dígitos registrado en Nequi (app instalada).
- Flujo: `PENDING` → **notificación push** en la app Nequi → el cliente acepta/rechaza → estado final "en segundos".
- Suscripción/tokenización para recurrencia: §9.2.

### 7.4 Botón Bancolombia — `BANCOLOMBIA_TRANSFER`

```json
"payment_method": {
  "type": "BANCOLOMBIA_TRANSFER",
  "payment_description": "Pago a Tienda Wompi",
  "ecommerce_url": "https://comercio.co/thankyou_page"
}
```

- `payment_description`: máx. 64 caracteres, **sin comillas simples**.
- `ecommerce_url` (opcional): permite saltar la pantalla resumen de Wompi.
- Solo personas naturales hoy (`user_type: "PERSON"` aparece en ejemplos de PCOL hijo).
- Redirección vía `extra.async_payment_url`.
- Recurrente: con fuente de pago aprobada, enviar `payment_source_id` — se ejecuta **sin autenticación del cliente**.

### 7.5 Bancolombia QR — `BANCOLOMBIA_QR`

```json
"payment_method": {
  "type": "BANCOLOMBIA_QR",
  "payment_description": "Pago a Tienda Wompi",
  "sandbox_status": "APPROVED"
}
```

- `sandbox_status` (solo pruebas): `APPROVED` | `DECLINED` | `ERROR`.
- Polling hasta obtener el QR en `extra`:

```json
"extra": {
  "qr_id": "a3827b90-501b-11ed-ae9b-3156df51ed75",
  "qr_image": "PD94bWwgdmVyc2lvbj0iK.....",
  "external_identifier": "d00000000000"
}
```

- Render: `<img src="data:image/svg+xml;base64,${qr_image}"/>` (SVG en base64).

### 7.6 Efectivo (corresponsal bancario Bancolombia) — `BANCOLOMBIA_COLLECT`

```json
"payment_method": { "type": "BANCOLOMBIA_COLLECT" }
```

Polling hasta `extra`:

```json
"extra": {
  "business_agreement_code": "12345",
  "payment_intention_identifier": "65770204276"
}
```

El cliente presenta el **número de convenio** (`business_agreement_code`) y la **intención de pago** en cualquiera de los ~17.600 corresponsales Bancolombia y paga en efectivo.

### 7.7 Puntos Colombia — `PCOL` (flujo en 3 pasos)

1. **Crear transacción** con `payment_method: {"type": "PCOL"}` + `customer_data` → polling hasta `extra.async_payment_url` → redirigir al portal de redención de puntos.
2. **Validar redención** (nuevo polling), `extra` trae `points_redeemed`, `remaining_amount_in_cents`, `redeemed_amount_in_cents_pcol`:
   - `remaining_amount_in_cents = 0` + `APPROVED` → pagado 100 % con puntos.
   - `remaining_amount_in_cents = 0` + `ERROR`/`DECLINED` → sin redención; cobrar todo con segundo medio.
   - `remaining_amount_in_cents > 0` → pago parcial; completar con segundo medio.
3. **Segunda transacción** por el remanente con `"parent_transaction_id": "<id transacción PCOL>"` (ejemplos oficiales con CARD, BANCOLOMBIA_TRANSFER, NEQUI y PSE).

Vinculación: el padre PCOL expone `extra.child_transaction_id` y la hija `extra.parent_transaction_id`.

### 7.8 BNPL Bancolombia — `BANCOLOMBIA_BNPL`

```json
{
  "amount_in_cents": 10000000,
  "currency": "COP",
  "customer_email": "myemail@mail.com",
  "reference": "{{REFERENCE}}",
  "payment_method": {
    "type": "BANCOLOMBIA_BNPL",
    "name": "Pedro",
    "last_name": "Perez",
    "user_legal_id_type": "CC",
    "user_legal_id": "12345678",
    "phone_number": "3222222222",
    "phone_code": "+57",
    "redirect_url": "https://www.wompi.com",
    "payment_description": "Pago a Tienda Wompi"
  },
  "acceptance_token": "{{ACCEPTANCE_TOKEN}}",
  "payment_method_type": "BANCOLOMBIA_BNPL"
}
```

- Todos los campos del `payment_method` son requeridos. `payment_description` máx. **30** caracteres.
- **Monto mínimo $100.000 COP.** Hasta 4 cuotas sin intereses (según página de planes).
- Respuesta `PENDING` con `extra.url` (experiencia BNPL), `extra.steps: ["ProvideAuthenticate"]`. Redirigir a `extra.url`; retorna por `redirect_url`.

### 7.9 Daviplata — `DAVIPLATA`

```json
"payment_method": {
  "type": "DAVIPLATA",
  "user_legal_id": "1134568019",
  "user_legal_id_type": "CC",
  "payment_description": "Pago a Tienda Wompi"
}
```

- `payment_description` máx. **30** caracteres; `user_legal_id_type`: `CC`/`NIT`.
- Flujo OTP: respuesta `PENDING` con `extra.url` (interfaz OTP) y `extra.url_services`:

```json
"url_services": {
  "token": "token",
  "code_otp_send": "https://...",
  "code_otp_validate": "https://..."
}
```

- Reenvío de OTP: `POST` a `code_otp_send` (respuesta incluye `attempts` con límites).
- Validación: `POST` a `code_otp_validate` con `{ "code": 123456 }` → respuesta con `transaction.steps.ConfirmIntention[]` (`idTransaccionAutorizador`, `estado: "Aprobado"`, `numAprobacion`).
- Final `APPROVED` con `extra.external_identifier` y `extra.daviplata_transaction_id`.
- Tokenización para recurrencia: §9.3.

### 7.10 SU+ Pay — `SU_PLUS`

```json
"payment_method": {
  "type": "SU_PLUS",
  "user_legal_id_type": "CC",
  "user_legal_id": "1284952"
}
```

- **Monto mínimo $35.000 COP, máximo $5.000.000 COP.** 1–12 cuotas (según página de planes).
- Respuesta `PENDING` con `extra.url` (experiencia SU+; en sandbox la URL trae `code_approved`, `code_declined`, `code_cancel`, `code_error`), `extra.steps: ["Create"]`.
- Final `APPROVED` con `extra.external_identifier` y `extra.su_plus_transaction_id`.

## 8. Cuotas (installments)

- Se envían como **entero** en `payment_method.installments` (solo tarjetas; también en cobros recurrentes: `"payment_method": { "installments": 2 }` junto a `payment_source_id`).
- **La doc no publica el rango permitido** (no aparece "1 a 36" ni similar) **ni existe endpoint documentado de consulta de cuotas/financial data**.
- BNPL Bancolombia: hasta 4 cuotas sin intereses. SU+ Pay: 1–12 cuotas. (Datos de la página de planes.)
- Las cuotas las financia el banco emisor de la tarjeta; el comercio recibe el total.

## 9. Tokenización

### 9.1 Tarjetas — `POST /tokens/cards` (llave pública)

```json
{
  "number": "4242424242424242",
  "cvc": "123",
  "exp_month": "08",
  "exp_year": "28",
  "card_holder": "José Pérez"
}
```

Respuesta:

```json
{
  "status": "CREATED",
  "data": {
    "id": "tok_prod_1_BBb749EAB32e97a2D058Dd538a608301",
    "created_at": "2020-01-02T18:52:35.850+00:00",
    "brand": "VISA",
    "name": "VISA-4242",
    "last_four": "4242",
    "bin": "424242",
    "exp_year": "28",
    "exp_month": "08",
    "card_holder": "José Pérez",
    "expires_at": "2020-06-30T18:52:35.000Z"
  }
}
```

- Prefijos: `tok_prod_...` / `tok_test_...`. El token tiene su propia expiración (`expires_at`).
- Advertencias literales: "Desaconsejamos completamente que guardes información sensible de tarjetas" (PCI DSS) y **"¡No uses un token más de dos veces!"**.
- Opcional: payload cifrado con **JWE RSA-OAEP-256 + AES-GCM-256**; llave pública en `GET /tokens/keys/tokenization`.

### 9.2 Nequi — `POST /tokens/nequi` (llave pública)

```json
{ "phone_number": "3017654321" }
```

Respuesta inicial: `{"data": {"id": "nequi_prod_RQkUiuv3lEnDLiSao2Cz0iQLdFlyQOI5", "status": "PENDING", "phone_number": "...", "name": "..."}}`.

- El cliente **aprueba la suscripción por push** en su app → token pasa a `APPROVED`.
- Consultar: `GET /tokens/nequi/{token_id}` o webhook `nequi_token.updated`.
- Prefijos: `nequi_prod_...` / `nequi_devtest_...`.

### 9.3 Daviplata — `POST /tokens/daviplata`

```json
{ "type_document": "CC", "number_document": "1122233", "product_number": "3991111111" }
```

Respuesta: `id` (`daviplata_devtest_...`), `status: "PENDING"` y `url_services` (`token`, `code_otp_send`, `code_otp_validate`). El token confirma por OTP. Estados: `PENDING → APPROVED → VOIDED` (desuscripción).

### 9.4 Botón Bancolombia — `POST /tokens/bancolombia_transfer`

Dos modos vía `type_auth`:

```json
{ "redirect_url": "https://www.redirect_url_example.com", "type_auth": "TRANSACTION" }
```

- `TRANSACTION`: autorización durante la transacción; respuesta con `status: "AVAILABLE"`, `bank_account_type`, `bank_account_last_four`, `authorization_url` vacío.
- `TOKEN`: autorización previa; la respuesta incluye **`authorization_url`** a la que se redirige al cliente para autorizar en Bancolombia.
- Webhook asociado: `bancolombia_transfer_token.updated`.

## 10. Fuentes de pago y pagos recurrentes

### 10.1 Crear — `POST /payment_sources` (llave privada)

| Campo | Obligatorio | Detalle |
|---|---|---|
| `type` | Sí | `CARD`, `NEQUI`, `DAVIPLATA`, `BANCOLOMBIA_TRANSFER` |
| `token` | Sí | Token de §9 (`tok_...`, `nequi_...`, `daviplata_...`, id token Bancolombia). Para Nequi/Daviplata debe estar `APPROVED` |
| `customer_email` | Sí | |
| `acceptance_token` | Sí | §4 |
| `accept_personal_auth` | Sí | §4 |
| `payment_description` | — | Solo `BANCOLOMBIA_TRANSFER` |

Ejemplo (CARD):

```json
{
  "type": "CARD",
  "token": "tok_prod_1_BBb749EAB32e97a2D058Dd538a608301",
  "customer_email": "pepito_perez@example.com",
  "acceptance_token": "eyJhbGciOiJIUzI1NiJ9...",
  "accept_personal_auth": "eyJhbGciOiJIUzI1NiJ9..."
}
```

Respuesta 201: `{"data": {"id": 3891, "type": "CARD", "status": "AVAILABLE", "public_data": {...}}}`.

`public_data` por tipo: CARD `{type}`; NEQUI `{type, phone_number}`; DAVIPLATA `{type_document, number_document, phone_number}`; BANCOLOMBIA_TRANSFER `{payment_description, bank_account_type: "CUENTA AHORROS", bank_account_last_four: "***1234"}`.

**Estados de la fuente:** `AVAILABLE` (operativa), `PENDING` (validación en curso), `VOIDED` (desuscrita). (Flujos Bancolombia usan también `APPROVED`.)

Consulta: `GET /payment_sources/{id}` (llave privada).

### 10.2 Cobro recurrente — `POST /transactions` con `payment_source_id`

```json
{
  "amount_in_cents": 4990000,
  "currency": "COP",
  "signature": "37c8407747e595535433ef8f6a811d853cd943046624a0ec04662b17bbf33bf5",
  "customer_email": "example@gmail.com",
  "payment_method": { "installments": 2 },
  "reference": "sJK4489dDjkd390ds02",
  "payment_source_id": 3891,
  "recurrent": true
}
```

- `recurrent: true` → COF de recurrencia periódica (montos iguales); `false` → COF almacenada (montos variables). **Solo Mastercard/Visa con procesador RBM.**
- La transacción se ejecuta **sin autenticación del cliente** (para Bancolombia Transfer, la fuente debe estar aprobada).

### 10.3 Cancelar fuente — `PUT /payment_sources/{id}/void`

Devuelve la fuente con `status: "VOIDED"`.

## 11. 3D Secure v2

Redes soportadas: **Mastercard y Visa** (disponibilidad varía por modelo Gateway vs Agregador).

### 11.1 Transacción con 3DS — campos adicionales en `POST /transactions`

| Campo | Tipo | Obligatorio | Descripción |
|---|---|---|---|
| `is_three_ds` | boolean | Sí (para activar) | Activa el flujo 3DS (sandbox y producción) |
| `three_ds_auth_type` | string | **Solo sandbox** | Fuerza el escenario simulado. **Omitir en producción** |
| `customer_data.full_name` | string | Sí | |
| `customer_data.phone_number` | string | Sí | |
| `customer_data.browser_info` | object | Sí | Datos del navegador para el ACS — **todos strings** |

`browser_info` (aplicar `.toString()` a cada valor):

| Campo | Fuente JS | Ejemplo |
|---|---|---|
| `browser_color_depth` | `window.screen.colorDepth` | `"24"` |
| `browser_screen_height` | `window.screen.height` | `"1050"` |
| `browser_screen_width` | `window.screen.width` | `"1680"` |
| `browser_language` | `window.navigator.language` | `"en-US"` |
| `browser_user_agent` | `window.navigator.userAgent` | `"Mozilla/5.0 ..."` |
| `browser_tz` | `new Date().getTimezoneOffset()` | `"-300"` (minutos, puede ser negativo) |

### 11.2 Respuesta: objeto `three_ds_auth`

En `data.payment_method.extra.three_ds_auth` (junto a `extra.is_three_ds` y `extra.three_ds_auth_type`):

| Campo | Valores |
|---|---|
| `current_step` | `AUTHENTICATION`, `CHALLENGE`, `SUPPORTED_VERSION` (+ `BROWSER_INFO`, `FINGERPRINT` en payment sources) |
| `current_step_status` | `PENDING`, `COMPLETED`, `Non-Authenticated` (literal), `ERROR` (+ `ABANDONED` en payment sources) |
| `three_ds_method_data` | HTML del challenge **escapado con entidades HTML**; presente solo cuando hay paso pendiente |

**No hay POST adicional tras crear la transacción**: todo se resuelve por **polling** `GET /transactions/{id}` cada 2–3 s, timeout recomendado 5 min. La respuesta **no expone** `eci`/`cavv`/`ds_transaction_id` (los maneja Wompi internamente).

### 11.3 Matriz de escenarios

| `three_ds_auth_type` (sandbox) | `current_step` | `current_step_status` | Estado final |
|---|---|---|---|
| `no_challenge_success` (frictionless OK) | `AUTHENTICATION` | `COMPLETED` | `APPROVED` |
| `challenge_denied` (frictionless rechazado) | `AUTHENTICATION` | `Non-Authenticated` | `DECLINED` |
| `challenge_v2` (challenge requerido) | `CHALLENGE` | `PENDING` (+ `three_ds_method_data`) | `PENDING` → tras challenge: `APPROVED`/`DECLINED`/`ERROR` |
| `supported_version_error` | `SUPPORTED_VERSION` | `ERROR` | `ERROR` (tarjeta no compatible) |
| `authentication_error` | `AUTHENTICATION` | `ERROR` | `ERROR` |

### 11.4 Renderizado del challenge

`three_ds_method_data` llega HTML-escapado (`&lt;` etc.) — decodificar antes de renderizar:

```javascript
const parser = new DOMParser();
const decodedHtml = parser.parseFromString(
  `<!doctype html><body>${escapedHtml}`, 'text/html'
).body.textContent;
```

Reglas críticas:
- Usar **`srcDoc`** del iframe (nunca `src`).
- Altura mínima del iframe: 400–500 px; debe estar visible.
- Renderizar cuando `current_step: "CHALLENGE"` y `current_step_status: "PENDING"`.
- **Obligatorio por políticas de Mastercard:** mostrar el logo **Mastercard ID Check** al recibir `three_ds_auth` y al finalizar el challenge.

### 11.5 Fuentes de pago con 3DS (3RI)

- Requiere **activación previa por el equipo de gestión de fraude de Wompi** (no hay flag de API; se activa a nivel de cuenta).
- Creación de fuentes 3DS: Mastercard y Visa. Cobros automáticos bajo **3RI**: **solo Mastercard**.
- El request de `POST /payment_sources` es idéntico al normal (sin campos 3DS); el flujo 3DS aparece en el polling de `GET /payment_sources/{id}` cada 2 s.
- Pasos secuenciales con HTML a renderizar (todos vía `three_ds_method_data`, escapado):

| `current_step` | Interacción del usuario |
|---|---|
| `BROWSER_INFO` | No (se ejecuta solo, hay que renderizarlo) |
| `FINGERPRINT` | No (ídem) |
| `CHALLENGE` | **Sí** (HTML del banco emisor) |
| `AUTHENTICATION` | Paso final con el resultado |

- `current_step_status` añade **`ABANDONED`**: si se excede el tiempo límite (duración no publicada), la fuente queda `ERROR`.
- BIN no soportado por 3DS → fuente `DECLINED` antes de `BROWSER_INFO`.
- Estados finales de la fuente: `AVAILABLE` (lista para 3RI), `DECLINED`, `ERROR`.
- El cobro recurrente posterior usa el `payment_source_id` normal (la protección 3RI es implícita).

### 11.6 3DS externo (MPI propio)

Solo para `POST /transactions` (no payment sources). Se envía `is_three_ds: true` a nivel raíz **sin** `browser_info`, y dentro de `payment_method` el objeto **`extra_three_ds_aut_external_provider`** (nombre literal, "aut" sin "h") — 5 campos, todos strings y obligatorios:

| Campo | Ejemplo | Notas |
|---|---|---|
| `trans_status` | `"Y"` | Estado de la autenticación (set completo Y/N/A/U/R/C no documentado) |
| `three_ds_server_trans_id` | `"d873-abc123-ghr678..."` | ID del 3DS Server (no hay campo separado para `ds_trans_id` ni `xid`) |
| `message_version` | `"2.0"` | Versión del protocolo |
| `authentication_value` | `"BwABApFSYsssd4l2eQQFJjAAAAAAA="` | CAVV/AAV en base64 (no hay campo `cavv` separado) |
| `eci` | `"02"` | Electronic Commerce Indicator |

```json
{
  "acceptance_token": "...",
  "amount_in_cents": 1000000,
  "currency": "COP",
  "customer_email": "pepito_perez@example.com",
  "reference": "AHJDFDSFK184",
  "payment_method": {
    "type": "CARD",
    "token": "token_val_12345...",
    "installments": 1,
    "extra_three_ds_aut_external_provider": {
      "eci": "001",
      "trans_status": "Y",
      "message_version": "v1",
      "authentication_value": "g5f4d3s2a1",
      "three_ds_server_trans_id": "A1S2D3FG4H5"
    }
  },
  "is_three_ds": true
}
```

La transacción se crea `PENDING` y se resuelve por polling normal.

## 12. Anulaciones (void) y devoluciones/reembolsos

### 12.1 Anulación — `POST /transactions/{transaction_id}/void`

```bash
curl -X POST "https://production.wompi.co/v1/transactions/1292-1602113476-10985/void" \
  -H "Authorization: Bearer prv_prod_xxx"
```

| Aspecto | Detalle |
|---|---|
| Auth | **Llave privada** (Bearer) |
| Aplica a | Transacciones **APPROVED** — **solo tarjetas** (`CARD`) |
| Resultado | Estado `VOIDED`; respuesta **201** "Transacción anulada" (esquema de respuesta no publicado) |
| Ventana | **Mismo día**, antes de la liquidación (los pagos con tarjeta se liquidan/concilian ~24 h después). Pasada la liquidación el endpoint ya no aplica |
| Parcial | La guía documenta solo anulación **total**; el swagger oficial acepta body opcional `{ "amount_in_cents": 3000000 }` para anulación parcial — **contradicción de la doc, validar con Wompi antes de depender de parciales** |
| Impuestos | En anulación los impuestos nunca se liquidan |

### 12.2 Devoluciones/reembolsos — **NO hay endpoint de refund en la API**

- No existe `POST /refunds` ni equivalente en el API público v1. El modelo oficial es: **void por API (mismo día, solo tarjetas) + reembolsos por panel/soporte**.
- **Anulación vs reembolso** (definición oficial): en la anulación la liquidación no se hace efectiva; en el reembolso la compra ya fue liquidada y desembolsada.
- **Cómo se solicita:** por las opciones habilitadas en la Wompi Cuenta (`comercios.wompi.co`) o canales de soporte (formulario "Escríbenos" / WhatsApp +57 322 2804391).
- **Requisito:** el comercio debe tener **saldo disponible** en su cuenta Wompi para cubrir el reembolso.
- **Cobertura:** tarjetas Visa, Mastercard y Amex con autorizadores Redeban/Credibanco.
- **Parciales vs totales:** para autorizadores **RBM, API Nequi y Botón Bancolombia solo se permiten reembolsos TOTALES**.
- **Comisiones:** en un reembolso total se devuelven los impuestos, **excepto la comisión de Wompi y su IVA** (el reembolso es una transacción independiente).
- **Reversión post-liquidación (tarjeta):** vía soporte con código de autorización, fecha, últimos dígitos y valor; respuesta en máx. **10 días hábiles**; puede rechazarse si hay contracargo; no garantizada.

## 13. Eventos (webhooks)

### 13.1 Configuración

- Wompi hace **`POST` HTTP** a la URL de eventos del comercio. Se recomienda HTTPS.
- **Una URL por ambiente** (Sandbox y Producción por separado), configuradas en `comercios.wompi.co`.

### 13.2 Tipos de evento

| Evento | Descripción |
|---|---|
| `transaction.updated` | La transacción cambió de estado (usualmente a final: `APPROVED`, `VOIDED`, `DECLINED`, `ERROR`) |
| `nequi_token.updated` | Token Nequi cambió de estado (`APPROVED`/`DECLINED`) |
| `bancolombia_transfer_token.updated` | Token Bancolombia cambió de estado (`APPROVED`/`DECLINED`) |

> La doc advierte que la lista **puede crecer** — no tratar el tipo de evento como enum cerrado. Solo `transaction.updated` tiene payload de ejemplo publicado.

### 13.3 Payload de `transaction.updated`

```json
{
  "event": "transaction.updated",
  "data": {
    "transaction": {
      "id": "1234-1610641025-49201",
      "amount_in_cents": 4490000,
      "reference": "MZQ3X2DE2SMX",
      "customer_email": "juan.perez@gmail.com",
      "currency": "COP",
      "payment_method_type": "NEQUI",
      "redirect_url": "https://mitienda.com.co/pagos/redireccion",
      "status": "APPROVED",
      "shipping_address": null,
      "payment_link_id": null,
      "payment_source_id": null
    }
  },
  "environment": "prod",
  "signature": {
    "properties": ["transaction.id", "transaction.status", "transaction.amount_in_cents"],
    "checksum": "3476DDA50F64CD7CBD160689640506FEBEA93239BC524FC0469B2C68A3CC8BD0"
  },
  "timestamp": 1530291411,
  "sent_at": "2018-07-20T16:45:05.000Z"
}
```

| Campo | Significado |
|---|---|
| `environment` | `"test"` (sandbox) o `"prod"` (producción) |
| `signature.properties` | Rutas (dot-notation dentro de `data`) usadas en el checksum, **en orden** |
| `signature.checksum` | SHA-256 hex para verificar autenticidad |
| `timestamp` | Epoch UNIX — **entra en el cálculo del checksum** |
| `sent_at` | Fecha de la **primera** notificación del evento |

### 13.4 Verificación de autenticidad (checksum) — paso a paso

1. Concatenar los **valores** de las propiedades listadas en `signature.properties`, en el **orden exacto del array**, extraídos de `data`:
   `1234-1610641025-49201` + `APPROVED` + `4490000` → `1234-1610641025-49201APPROVED4490000`
2. Concatenar el `timestamp`: `...44900001530291411`
3. Concatenar el **secreto de eventos** (`prod_events_...`): `...1530291411prod_events_OcHn…`
4. **SHA-256** (hex) del string → `3476DDA50F64CD7CBD160689640506FEBEA93239BC524FC0469B2C68A3CC8BD0`
5. Comparar con `signature.checksum` **o** con el header HTTP **`X-Event-Checksum`** (llega en ambos sitios).

```php
hash("sha256", "1234-1610641025-49201APPROVED44900001530291411prod_events_OcHn…");
```

> ⚠️ **`signature.properties` puede variar en el tiempo y entre eventos** — la doc pide explícitamente NO asumirlo como arreglo fijo: iterar dinámicamente sobre el array recibido, no hardcodear `[id, status, amount_in_cents]`.

### 13.5 Respuesta esperada y reintentos de entrega

| Aspecto | Detalle |
|---|---|
| Respuesta esperada | HTTP **200** (el cuerpo es irrelevante) |
| Si no hay 200 | Máx. **3 reintentos** en 24 h: a los **30 min**, a las **3 h** y a las **24 h** |

Implicación: el webhook no es garantizado al 100 % — complementar con polling de conciliación.

## 14. Seguimiento de transacciones y reintento de pago

- Al completarse una transacción, comercio y usuario reciben **notificación por e-mail**.
- Formas de conocer el estado final: (a) polling `GET /transactions/{id}`, (b) webhook `transaction.updated`, (c) `redirect_url` — Wompi redirige agregando **`?id=<id_transaccion>`** (ej. `https://midominio.com/pagos/respuesta?id=01-1531231271-19365`). **No confiar solo en el redirect/callback**: validar siempre por API o webhook.
- Campos clave para conciliar: `id`, `reference` (única), `customer_email`, `amount_in_cents`, `created_at`, `finalized_at`, `payment_method_type`.

**Reintento de pago** (funcionalidad del checkout de Wompi, no un endpoint):
- Si el primer intento falla, el cliente puede reintentar **con otro medio de pago** dentro de una ventana de **3 minutos**.
- En el dashboard se ve como una transacción `DECLINED` seguida de una `APPROVED` con la **misma `reference`**.
- Implicación de integración: pueden llegar múltiples eventos `transaction.updated` con la **misma `reference` pero distinto `id` y distinto `payment_method_type`** — la conciliación por `reference` debe tolerar un DECLINED previo seguido de un APPROVED.

## 15. Sandbox: datos de prueba

### 15.1 Tarjetas

| Número | Marca | Resultado |
|---|---|---|
| `4242 4242 4242 4242` | Visa | **APPROVED** |
| `4111 1111 1111 1111` | Visa | **DECLINED** |
| Cualquier otro número | — | **ERROR** |

Fecha de expiración: cualquier futura. CVC: cualquier 3 dígitos. (No hay tarjetas Mastercard/Amex de prueba ni montos especiales documentados.)

### 15.2 Tarjetas 3DS

| Número | Comportamiento |
|---|---|
| `2303779951000446` | Challenge requerido |
| `2303779951000297` | Frictionless exitoso |
| `2303779951000453` | Frictionless rechazado |
| `2303779951000354` | Error de autenticación |
| `2303779951000347` | Versión no soportada |
| `4242424242424242` | Multi-escenario (forzar con `three_ds_auth_type`, solo sandbox) |

En sandbox, el iframe del challenge muestra botones **APPROVED / DECLINED / ERROR** para elegir el resultado. Para fuentes de pago 3DS: `2303 7799 5100 0446` (challenge), `...0354` (error autenticación), `...0347` (error de versión).

### 15.3 Nequi

| Celular | Resultado |
|---|---|
| `3991111111` | APPROVED |
| `3992222222` | DECLINED |
| Cualquier otro | ERROR |

### 15.4 PSE

| `financial_institution_code` | Resultado |
|---|---|
| `"1"` | APPROVED |
| `"2"` | DECLINED |

### 15.5 Daviplata

Pago simple (OTP): `574829` APPROVED · `932015` DECLINED · `186743` DECLINED (sin saldo) · `999999` ERROR.

Tokenización — teléfonos: `3991111111` (transacciones APPROVED) · `3992222222` (DECLINED) · `3993333333` (DECLINED, billetera inválida). OTPs de confirmación del token: `574829` APPROVED · `932016` DECLINED (suscripción existente).

### 15.6 Bancolombia QR / Botón / BNPL / SU+ / Puntos Colombia

- **Bancolombia QR:** `"payment_method": { "sandbox_status": "APPROVED" }` (`APPROVED` | `DECLINED` | `ERROR`).
- **Botón Bancolombia:** en sandbox redirige a una página donde se elige manualmente el estado final (valores exactos de `sandbox_status` no documentados).
- **BNPL Bancolombia y SU+ Pay:** redirigen a páginas donde se elige el estado final.
- **Puntos Colombia** — valores de `sandbox_status`: `APPROVED_ONLY_POINTS` (100 % puntos) · `APPROVED_HALF_POINTS` (50 % puntos) · `DECLINED` · `ERROR`.

## 16. Errores

Formato general: objeto `error` con `type`, `reason` (string) y/o `messages` (hash campo → array de mensajes).

| HTTP | `type` | Cuándo | Ejemplo |
|---|---|---|---|
| 401 | `INVALID_ACCESS_TOKEN` | Llave inválida o de otro ambiente | `{"error": {"type": "INVALID_ACCESS_TOKEN", "reason": "La llave proporcionada no corresponde a este ambiente."}}` |
| 404 | `NOT_FOUND_ERROR` | Entidad inexistente | `{"error": {"type": "NOT_FOUND_ERROR", "reason": "La entidad solicitada no existe"}}` |
| 422 | `INPUT_VALIDATION_ERROR` | Campos inválidos; `messages` mapea campo → errores | `{"error": {"type": "INPUT_VALIDATION_ERROR", "messages": {"reference": ["La referencia ya ha sido usada"]}}}` |

Casos 422 típicos: referencia duplicada, `amount_in_cents` no entero positivo, `payment_method` incompleto, token de aceptación inválido/vencido. La doc no publica códigos de declinación de negocio adicionales.

## 17. Impuestos (`taxes`)

Array en `POST /transactions` (y links de pago):

| Campo | Valores |
|---|---|
| `type` | `"VAT"` (IVA) o `"CONSUMPTION"` (impoconsumo) |
| `amount_in_cents` | Monto del impuesto en centavos (en links de monto abierto se usa `percentage`) |

**Regla crítica:** los impuestos **NO se suman** al total — son informativos; el impuesto ya debe venir incluido en `amount_in_cents`. Ej.: total $119.000 (base $100.000 + IVA $19.000):

```json
{
  "amount_in_cents": 11900000,
  "taxes": [ { "type": "VAT", "amount_in_cents": 1900000 } ]
}
```

En el Widget: `data-tax-in-cents:vat` y `data-tax-in-cents:consumption`. En anulaciones los impuestos nunca se liquidan; en reembolsos totales se devuelven al comprador.

## 18. Links de pago — `/payment_links`

### `POST /payment_links` (llave privada)

| Campo | Tipo | Obligatorio | Notas |
|---|---|---|---|
| `name` | string | Sí | Nombre del link |
| `description` | string | Sí | Descripción del pago |
| `single_use` | boolean | Sí | `true`: deja de aceptar pagos tras la primera transacción APPROVED |
| `collect_shipping` | boolean | Sí | Pide datos de envío en el checkout |
| `currency` | string | No | Solo `COP` |
| `amount_in_cents` | integer\|null | No | `null` = **monto abierto** (lo define el pagador); con monto fijo debe **incluir impuestos** |
| `expires_at` | string ISO 8601 | No | En UTC (hora Colombia +5 h) |
| `redirect_url` | string | No | Redirección post-pago |
| `image_url` | string | No | Imagen del link |
| `sku` | string | No | Máx. 36 caracteres |
| `collect_customer_legal_id` | boolean | No | Pide documento de identidad (aparece en el swagger; no en la tabla de la guía) |
| `customer_data.customer_references` | array | No | Máx. **2** campos custom: `{label (máx 24 chars), is_required}` |
| `taxes[]` | array | No | `type`: `VAT`/`CONSUMPTION`; `amount_in_cents` (monto fijo) o `percentage` (monto abierto) |

Respuesta 201: `data` con `id` (ej. `"3Z0Cfi"`), campos anteriores más `active`, `created_at`, `updated_at`, `merchant_public_key`.

- **URL pública:** `https://checkout.wompi.co/l/{id}` → ej. `https://checkout.wompi.co/l/3Z0Cfi`
- `GET /payment_links/{id}`: sin autenticación.
- `PATCH /payment_links/{id}` (llave privada): `{"active": true|false}` para activar/desactivar.
- Las transacciones originadas en un link traen `payment_link_id`.

## 19. Widget y Checkout Web

Misma parametría; cambia el mecanismo:

| Modalidad | Mecanismo | Nomenclatura |
|---|---|---|
| **Widget** (modal embebido) | Script `https://checkout.wompi.co/widget.js` | Atributos `data-*` o claves camelCase en `new WidgetCheckout({...})` |
| **Checkout Web** (redirección) | Form `GET` a `https://checkout.wompi.co/p/` | `name="..."` en inputs (equivale a query params) |

### 19.1 Parámetros obligatorios

| Widget (`data-*`) / Checkout (`name`) | JS | Descripción |
|---|---|---|
| `public-key` | `publicKey` | Llave pública |
| `currency` | `currency` | `COP` |
| `amount-in-cents` | `amountInCents` | Monto en centavos |
| `reference` | `reference` | Referencia única |
| `signature:integrity` | `signature.integrity` | Firma de integridad (§5) |

### 19.2 Parámetros opcionales

`redirect-url`, `expiration-time` (ISO 8601 UTC — si se usa, entra en la firma), `tax-in-cents:vat`, `tax-in-cents:consumption`, `customer-data:email`, `customer-data:full-name`, `customer-data:phone-number`, `customer-data:phone-number-prefix` (`+57`), `customer-data:legal-id`, `customer-data:legal-id-type` (`CC`/`CE`/`NIT`/`PP`/`TI`/`DNI`/`RG`/`OTHER`), `shipping-address:address-line-1`, `shipping-address:address-line-2`, `shipping-address:country` (`CO`), `shipping-address:city`, `shipping-address:region`, `shipping-address:phone-number`, `shipping-address:postal-code`, `shipping-address:name`, `collect-shipping`, `collect-customer-legal-id`, `payment-method:reference-one/-two/-three` (PSE antifraude, §20).

> **No existe parámetro documentado** para filtrar los métodos de pago mostrados: el checkout muestra los habilitados en la cuenta.

### 19.3 Widget con botón autogenerado

```html
<form>
  <script
    src="https://checkout.wompi.co/widget.js"
    data-render="button"
    data-public-key="pub_prod_XXXXXXXX"
    data-currency="COP"
    data-amount-in-cents="4950000"
    data-reference="REF_UNICA_123"
    data-signature:integrity="<SHA256>"
  ></script>
</form>
```

### 19.4 Widget con botón propio (API JavaScript)

```javascript
var checkout = new WidgetCheckout({
  currency: 'COP',
  amountInCents: 2490000,
  reference: 'AD002901221',
  publicKey: 'pub_...',
  signature: { integrity: '3a4bd1f3e3edb5e88284c8e1e9a191fdf091ef0dfca9f057cb8f408667f054d0' },
  redirectUrl: 'https://transaction-redirect.wompi.co/check',
  expirationTime: '2023-06-09T20:28:50.000Z',
  taxInCents: { vat: 1900, consumption: 800 },
  customerData: { email: 'lola@gmail.com', fullName: 'Lola Flores',
    phoneNumber: '3040777777', phoneNumberPrefix: '+57', legalId: '123456789', legalIdType: 'CC' },
  shippingAddress: { addressLine1: 'Calle 123 # 4-5', city: 'Bogota',
    phoneNumber: '3019444444', region: 'Cundinamarca', country: 'CO' }
});

checkout.open(function (result) {
  var transaction = result.transaction;  // objeto transacción completo
  console.log('Transaction ID:', transaction.id);
});
```

### 19.5 Checkout Web (redirección)

```html
<form action="https://checkout.wompi.co/p/" method="GET">
  <input type="hidden" name="public-key" value="pub_..." />
  <input type="hidden" name="currency" value="COP" />
  <input type="hidden" name="amount-in-cents" value="4950000" />
  <input type="hidden" name="reference" value="REF_UNICA_123" />
  <input type="hidden" name="signature:integrity" value="<SHA256>" />
  <input type="hidden" name="redirect-url" value="https://midominio.com/pagos/respuesta" />
  <button type="submit">Pagar con Wompi</button>
</form>
```

Equivale a la URL `https://checkout.wompi.co/p/?public-key=...&currency=COP&amount-in-cents=...&reference=...&signature:integrity=...`.

### 19.6 Retorno

Wompi redirige al `redirect-url` con `?id=<id_transaccion>`. Consultar el estado real con `GET /v1/transactions/{id}` y/o esperar el webhook — **nunca confiar solo en el redirect o el callback del widget**.

## 20. Cifrado JWE

### 20.1 PSE — campos antifraude (`reference_one/two/three`)

- Exclusivo de PSE Colombia. Cifrado **opcional** (se pueden mezclar campos cifrados y en claro; Wompi detecta el formato JWE automáticamente).
- Algoritmos: `alg: RSA-OAEP`, `enc: A256GCM`. Formato compacto JWE: `BASE64URL(Header).BASE64URL(EncryptedKey).BASE64URL(IV).BASE64URL(Ciphertext).BASE64URL(AuthTag)`.
- Llave pública RSA 4096 en formato PEM, publicada en la propia página de docs.
- **Cifrar siempre en backend**, nunca en frontend.

```javascript
const { importSPKI, CompactEncrypt } = require('jose'); // jose v5

async function cifrarReferencia(valor, llavePublicaPem) {
  const publicKey = await importSPKI(llavePublicaPem, 'RSA-OAEP');
  return new CompactEncrypt(new TextEncoder().encode(valor))
    .setProtectedHeader({ alg: 'RSA-OAEP', enc: 'A256GCM' })
    .encrypt(publicKey);
}
```

Uso: `"payment_method": { "type": "PSE", "reference_one": "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ...", ... }`. Vía Widget: `data-payment-method:reference-one/-two/-three`.

### 20.2 Tokenización de tarjetas

Opcionalmente el payload de `POST /tokens/cards` puede cifrarse con **JWE RSA-OAEP-256 + AES-GCM-256**; la llave pública se obtiene en `GET /tokens/keys/tokenization`.

## 21. Pagos a terceros (Payouts) — API separada

API independiente del API de cobros, para **dispersar pagos a cuentas bancarias** en Colombia mediante lotes.

- **Autenticación por headers** (no Bearer): `x-api-key: <API_KEY>` + `user-principal-id: <ID_USUARIO_PRINCIPAL>`, obtenidos en el dashboard (variantes sandbox/producción; hosts parametrizados como `{{DOMAIN}}`/`{{DOMAIN-SANDBOX}}` en la colección Postman oficial — la URL concreta se entrega al habilitar el producto).
- **Endpoints principales:** `GET /banks` (bancos con `bankId`), `GET /accounts` (cuentas origen con `balanceInCents`), `GET /limits`, `POST /payouts` (pago individual o lote JSON: `reference`, `accountId`, `paymentType` p.ej. `PAYROLL`, array `transactions[]` con `legalIdType/legalId`, `bankId`, `accountType` `AHORROS`/corriente, `accountNumber`, `name`, `amount`, `personType` `NATURAL`, `email`), `POST /payouts/file` (lote por archivo: formatos Wompi, PAB, SAP-Bancolombia, DISFON, Occidente FC, Davivienda), `GET /payouts`, `GET /payouts/{payoutId}`, `GET /payouts/{payoutId}/transactions[/{transactionId}]`, `GET /transactions/{reference}`, `GET /health`. Sandbox extra: `POST /accounts/balance-recharge`, `GET /reports/presigned_url`.
- **Webhooks** en cada cambio del ciclo de vida del pago.
- **Flujo:** credenciales → crear lote (JSON o archivo) → validación → aprobación (roles `PreparadorPagosTerceros`/`AprobadorPagosTerceros` en el panel) → dispersión → consulta/webhooks/reportes.
- **Límites:** COP $1.500.000.000 diarios, máx. 3.800 lotes/día.

## 22. Planes y comisiones

(De `wompi.com/es/co/planes-tarifas/`; la página de docs solo enlaza allí.)

| Aspecto | Plan Avanzado | Avanzado + Puntos Colombia | Plan Gateway |
|---|---|---|---|
| Comisión | 2,65 % + $700 COP + IVA por transacción exitosa | Ídem + 1,44 % cuando el cliente gana Puntos (débito, crédito, PSE) | Sin comisión Wompi; tarifa negociada con Bancolombia |
| Medios de pago | 9 (tarjetas, Botón Bancolombia, QR, Nequi, BNPL, efectivo, PSE, Daviplata, SU+Pay) | 10 (+ Puntos Colombia) | 5 (Puntos Colombia, tarjetas, Botón Bancolombia, Nequi, PSE) |
| Requisitos | — | — | >2.000 transacciones/mes + contrato de aceptación con Bancolombia |
| Dispersión | Día hábil siguiente a la venta | Ídem | — |

## 23. Vacíos documentales y notas de implementación

Confirmados con barridos específicos — cosas que la doc pública **no** define:

- **Rango permitido de `installments`** para tarjeta y endpoint de consulta de cuotas: no documentados.
- **Rate limits** del API: no publicados.
- **TTL exacto de los tokens de aceptación** (solo el claim `exp` del JWT).
- **Tiempos de expiración de transacciones `PENDING`** por método de pago.
- **`session_id`** (fingerprint antifraude): aparece en algunas integraciones pero no está en las páginas públicas actuales ni en el swagger 1.2.0.
- **Valores exactos de `sandbox_status` para Botón Bancolombia**; datos de prueba para efectivo/corresponsal.
- **Esquema de respuesta del void** (solo "201 Transacción anulada").
- **Set completo de `trans_status`/`eci`/`message_version`** para 3DS externo, y duración del timeout `ABANDONED` en 3DS.
- **Payloads de ejemplo de los eventos de token** (`nequi_token.updated`, `bancolombia_transfer_token.updated`).
- **BRE-B** no existe como método de cobro en el API (solo como dispersión en Pagos a Terceros).

Inconsistencias detectadas en la doc oficial (documentadas arriba en su sección):
1. Base URL: `api.wompi.co/v1` (página métodos de pago) vs `production.wompi.co/v1`/`sandbox.wompi.co/v1` (página ambientes). Usar los hosts por ambiente.
2. `payment_description` de PSE: máx. 30 (página sandbox) vs 64 (página métodos). Usar ≤30.
3. Void parcial: swagger lo acepta (`amount_in_cents` en el body), la guía solo documenta total.

Recomendaciones de diseño para un conector:
- Tratar el flujo como **siempre asíncrono**: crear → `PENDING` → polling/webhook.
- Conciliar por `reference` tolerando reintento de pago (DECLINED + APPROVED con misma `reference`, distinto `id`/método).
- Verificar webhooks con `X-Event-Checksum`/`signature.checksum` iterando `signature.properties` dinámicamente.
- No reutilizar tokens de tarjeta (máx. 1 uso recomendado, "no más de dos").
- Refunds: solo void mismo día por API; el resto es proceso manual (panel/soporte) — modelarlo como no soportado vía API.

## 24. Fuentes

- Docs oficiales: [inicio-rapido](https://docs.wompi.co/docs/colombia/inicio-rapido/) · [ambientes-y-llaves](https://docs.wompi.co/docs/colombia/ambientes-y-llaves/) · [datos-de-prueba-en-sandbox](https://docs.wompi.co/docs/colombia/datos-de-prueba-en-sandbox/) · [tokens-de-aceptacion](https://docs.wompi.co/docs/colombia/tokens-de-aceptacion/) · [transacciones](https://docs.wompi.co/docs/colombia/transacciones/) · [metodos-de-pago](https://docs.wompi.co/docs/colombia/metodos-de-pago/) · [fuentes-de-pago](https://docs.wompi.co/docs/colombia/fuentes-de-pago/) · [fuentes-de-pago-3ds](https://docs.wompi.co/docs/colombia/fuentes-de-pago-3ds/) · [fuentes-de-pago-3ds-sandbox](https://docs.wompi.co/docs/colombia/fuentes-de-pago-3ds-sandbox/) · [transacciones-con-3d-secure-v2](https://docs.wompi.co/docs/colombia/transacciones-con-3d-secure-v2/) · [integracion-3ds-externo](https://docs.wompi.co/docs/colombia/integracion-3ds-externo/) · [eventos](https://docs.wompi.co/docs/colombia/eventos/) · [seguimiento-de-transacciones](https://docs.wompi.co/docs/colombia/seguimiento-de-transacciones/) · [reintento-de-pago](https://docs.wompi.co/docs/colombia/reintento-de-pago/) · [errores](https://docs.wompi.co/docs/colombia/errores/) · [impuestos](https://docs.wompi.co/docs/colombia/impuestos/) · [links-de-pago](https://docs.wompi.co/docs/colombia/links-de-pago/) · [cifrado-jwe-pse](https://docs.wompi.co/docs/colombia/cifrado-jwe-pse/) · [widget-checkout-web](https://docs.wompi.co/docs/colombia/widget-checkout-web/) · [referencia](https://docs.wompi.co/docs/colombia/referencia/) · [introduccion-pagos-a-terceros](https://docs.wompi.co/docs/colombia/introduccion-pagos-a-terceros/)
- OpenAPI oficial: [SwaggerHub waybox/wompi 1.2.0](https://api.swaggerhub.com/apis/waybox/wompi/1.2.0) · [Payouts 1.0.0](https://app.swaggerhub.com/apis-docs/wompi/Payouts/1.0.0/)
- Soporte oficial: [reembolso total](https://soporte.wompi.co/hc/es-419/articles/1500009267322) · [impuestos en reembolsos/anulaciones](https://soporte.wompi.co/hc/es-419/articles/1500009267462) · [reversión tarjeta de crédito](https://soporte.wompi.co/hc/es-419/articles/360046916653) · [anular trx con tarjeta](https://soporte.wompi.co/hc/es-419/articles/24298764333971) · [solicitar reversión de un pago](https://soporte.wompi.co/hc/es-419/articles/1500007683101)
- Planes: [wompi.com/es/co/planes-tarifas](https://wompi.com/es/co/planes-tarifas/)
