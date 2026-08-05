# fiservemea Argentina/Uruguay — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extender el conector Hyperswitch `fiservemea` para soportar cuotas, 3DS nativo opcional, anulación (void) correcta, Tax Refund Uruguay, y endurecer los flujos existentes (pago/refund/estado).

**Architecture:** El conector ya implementa el contrato Fiserv IPG v2 (`requestType`-discriminated, firma `Message-Signature`, `StringMajorUnit`). Se extiende el request builder para leer metadata (cuotas + tax refund, con fallback `metadata`→`frm_metadata`), se corrige el `requestType` de void, se agrega 3DS nativo vía el patrón `CompleteAuthorize` (redirect + PATCH de continuación), y se agregan integrity objects de monto.

**Tech Stack:** Rust, workspace `hyperswitch`, crate `hyperswitch_connectors`. Cargo vive en `~/.cargo/bin` y **no** está en el PATH del tool Bash → usar `bash -lc 'cargo ...'`.

**Spec de referencia:** `docs/superpowers/specs/2026-07-08-fiservemea-argentina-design.md`.

**Conectores de referencia (leer para copiar idioms exactos):**
- `crates/hyperswitch_connectors/src/connectors/mercadopago/transformers.rs:374-379` — lectura de metadata con fallback `metadata`→`frm_metadata`.
- `crates/hyperswitch_connectors/src/connectors/payway/transformers.rs:472-499` — patrón metadata object.
- `crates/hyperswitch_connectors/src/connectors/shift4.rs:547-635` y `shift4/transformers.rs:575-591` — 3DS nativo opcional vía CompleteAuthorize.
- `crates/hyperswitch_connectors/src/connectors/stripe/transformers.rs:2940-3011` — construir `redirection_data` + `AuthenticationPending`.
- `crates/hyperswitch_connectors/src/connectors/fiserv.rs:412-431,514-534,652-671,754-777` — integrity objects de monto.

## Global Constraints

- **Alcance: solo el conector Hyperswitch.** No tocar `api2`. No tocar otros conectores.
- **3DS opcional real:** la rama `NoThreeDs` debe dejar el request/response **idéntico** al actual. El 3DS solo se activa con `req.is_three_ds()`.
- **Resiliencia de metadata:** leer cuotas y `legal_framework` de `request.metadata` con fallback a `request.frm_metadata`; aceptar aliases de nombre. Campos faltantes ⇒ no romper (todo `Option`).
- **Compila y clippy limpio:** cada tarea termina con `bash -lc 'cargo check -p hyperswitch_connectors'` y, al final, `bash -lc 'cargo clippy -p hyperswitch_connectors --all-targets'` sin warnings nuevos.
- **Sin cambios de comportamiento no pedidos:** montos siguen en `StringMajorUnit`; el `amount_converter` no cambia.
- **Commits frecuentes**, uno por tarea, mensaje `feat(fiservemea): ...` / `fix(fiservemea): ...`, cerrando con `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`.

---

## File Structure

- **Modify:** `crates/hyperswitch_connectors/src/connectors/fiservemea/transformers.rs` — structs de request/response, metadata, enums, mapeos. (Núcleo de la mayoría de las tareas.)
- **Modify:** `crates/hyperswitch_connectors/src/connectors/fiservemea.rs` — trait impls (`CompleteAuthorize`), imports, `get_supported_payment_methods`, integrity objects en `handle_response`.
- **Test:** módulo `#[cfg(test)]` al final de `transformers.rs` para serialización de requests (cuotas, tax refund, void, 3DS request).

Todas las tareas editan estos 2 archivos ⇒ **ejecución secuencial** (no paralela).

---

### Task 1: Metadata plumbing + cuotas

**Files:**
- Modify: `crates/hyperswitch_connectors/src/connectors/fiservemea/transformers.rs`
- Test: `#[cfg(test)]` en el mismo archivo

**Interfaces:**
- Produces: `FiservemeaMetadataObject { installments: Option<i32>, installment_interest: Option<bool>, tax_refund_legal_framework: Option<FiservemeaLegalFramework> }`; `FiservemeaLegalFramework` (enum); `FiservemeaInstallmentOptions`; campo `installment_options` en `FiservemeaOrder`; helper de lectura dual-source.
- Consumes: nada (primera tarea).

- [ ] **Step 1: Definir el enum `FiservemeaLegalFramework`** (usado por el metadata object; el wiring de tax refund es Task 2)

```rust
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum FiservemeaLegalFramework {
    #[serde(rename = "NO_TAX_REFUND")]
    NoTaxRefund,
    #[serde(rename = "URY_RETURNS_IVA_LAW_17934")]
    UryReturnsIvaLaw17934,
    #[serde(rename = "URY_RETURNS_IMESI_LAW_18083")]
    UryReturnsImesiLaw18083,
    #[serde(rename = "URY_RETURNS_AFAM_LAW_18910")]
    UryReturnsAfamLaw18910,
    #[serde(rename = "URY_TAX_REFUND_LAW_18999")]
    UryTaxRefundLaw18999,
    #[serde(rename = "URY_RETURNS_IVA_LAW_19210")]
    UryReturnsIvaLaw19210,
}
```

- [ ] **Step 2: Definir el metadata object + lectura dual-source**

```rust
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct FiservemeaMetadataObject {
    #[serde(alias = "number_of_installments")]
    pub installments: Option<i32>,
    pub installment_interest: Option<bool>,
    #[serde(alias = "legal_framework")]
    pub tax_refund_legal_framework: Option<FiservemeaLegalFramework>,
}

impl FiservemeaMetadataObject {
    /// Lee de `request.metadata` y, para cada campo ausente, cae a `request.frm_metadata`.
    /// Ambas fuentes se soportan a propósito (ver spec §3.1). Tolerante a JSON inválido/ausente.
    fn from_sources(
        metadata: Option<&serde_json::Value>,
        frm_metadata: Option<&serde_json::Value>,
    ) -> Self {
        let primary = metadata
            .and_then(|v| serde_json::from_value::<Self>(v.clone()).ok())
            .unwrap_or_default();
        let fallback = frm_metadata
            .and_then(|v| serde_json::from_value::<Self>(v.clone()).ok())
            .unwrap_or_default();
        Self {
            installments: primary.installments.or(fallback.installments),
            installment_interest: primary.installment_interest.or(fallback.installment_interest),
            tax_refund_legal_framework: primary
                .tax_refund_legal_framework
                .or(fallback.tax_refund_legal_framework),
        }
    }
}
```

> **Nota para el implementador:** verificar el tipo exacto de `request.frm_metadata` en `PaymentsAuthorizeData` (probablemente `Option<Secret<serde_json::Value>>`); si es `Secret`, usar `.peek()`/`.expose()` para obtener `&Value`. Ver el patrón en `mercadopago/transformers.rs:374-379`. `request.metadata` es `Option<serde_json::Value>` (`router_request_types.rs:65`).

- [ ] **Step 3: Definir `FiservemeaInstallmentOptions` y extender `FiservemeaOrder`**

```rust
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaInstallmentOptions {
    number_of_installments: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    interest: Option<bool>,
}
```

Modificar `FiservemeaOrder` (actualmente `{ order_id }`) para agregar:

```rust
    #[serde(skip_serializing_if = "Option::is_none")]
    installment_options: Option<FiservemeaInstallmentOptions>,
```

> `FiservemeaOrder` ya tiene `#[serde(rename_all = "camelCase")]`, así que `installment_options`→`installmentOptions`. **Ojo:** `FiservemeaOrder` deriva `Deserialize`; al agregar el campo `Option` con `skip_serializing_if`, agregar `#[serde(default)]` al campo o al struct para no romper la deserialización.

- [ ] **Step 4: Wire en `FiservemeaPaymentsRequest::try_from` (auth)**

En el `TryFrom<&FiservemeaRouterData<&PaymentsAuthorizeRouterData>>`, antes de construir el `Ok(Self{...})`:

```rust
let fiservemea_meta = FiservemeaMetadataObject::from_sources(
    item.router_data.request.metadata.as_ref(),
    item.router_data.request.frm_metadata.as_ref().map(/* -> &Value, expose si Secret */),
);
let installment_options = fiservemea_meta.installments.and_then(|n| {
    (n > 1).then_some(FiservemeaInstallmentOptions {
        number_of_installments: n,
        interest: fiservemea_meta.installment_interest,
    })
});
```

y en el `FiservemeaOrder { order_id, .. }` pasar `installment_options`.

- [ ] **Step 5: Test de serialización de cuotas**

Agregar (o crear) el módulo de test al final del archivo:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn installments_serialize_into_order() {
        let order = FiservemeaOrder {
            order_id: "ord_1".to_string(),
            installment_options: Some(FiservemeaInstallmentOptions {
                number_of_installments: 6,
                interest: Some(true),
            }),
        };
        let json = serde_json::to_value(&order).unwrap();
        assert_eq!(json["installmentOptions"]["numberOfInstallments"], 6);
        assert_eq!(json["installmentOptions"]["Interest"], true);
    }

    #[test]
    fn metadata_reads_from_frm_fallback() {
        let frm = serde_json::json!({ "installments": 3 });
        let meta = FiservemeaMetadataObject::from_sources(None, Some(&frm));
        assert_eq!(meta.installments, Some(3));
    }
}
```

> **Ojo con el naming del doc:** el doc usa `Interest` con mayúscula (Apéndice III). Si el campo se serializa como `interest` por `camelCase`, forzar `#[serde(rename = "Interest")]` en `FiservemeaInstallmentOptions::interest` para matchear el doc. Ajustar el test en consecuencia.

- [ ] **Step 6: Compilar + test + commit**

```bash
bash -lc 'cd /home/enzods/hyperswitch && cargo test -p hyperswitch_connectors fiservemea 2>&1 | tail -30'
```
Esperado: los 2 tests pasan; el crate compila.

```bash
git add crates/hyperswitch_connectors/src/connectors/fiservemea/transformers.rs
git commit -m "feat(fiservemea): installments via metadata/frm_metadata"
```

---

### Task 2: Tax Refund Uruguay

**Files:**
- Modify: `crates/hyperswitch_connectors/src/connectors/fiservemea/transformers.rs`

**Interfaces:**
- Consumes: `FiservemeaLegalFramework`, `FiservemeaMetadataObject` (Task 1), `FiservemeaOrder`.
- Produces: `FiservemeaAdditionalDetails`, `FiservemeaTaxRefundRequestData`; campo `additional_details` en `FiservemeaOrder`.

- [ ] **Step 1: Definir structs de additionalDetails**

```rust
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaTaxRefundRequestData {
    legal_framework: FiservemeaLegalFramework,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaAdditionalDetails {
    #[serde(skip_serializing_if = "Option::is_none")]
    tax_refund_request_data: Option<FiservemeaTaxRefundRequestData>,
}
```

- [ ] **Step 2: Extender `FiservemeaOrder`**

Agregar:
```rust
    #[serde(skip_serializing_if = "Option::is_none", default)]
    additional_details: Option<FiservemeaAdditionalDetails>,
```

- [ ] **Step 3: Wire en `FiservemeaPaymentsRequest::try_from` (auth)**

Reusar `fiservemea_meta` de Task 1:
```rust
let additional_details = fiservemea_meta
    .tax_refund_legal_framework
    .map(|lf| FiservemeaAdditionalDetails {
        tax_refund_request_data: Some(FiservemeaTaxRefundRequestData { legal_framework: lf }),
    });
```
y pasarlo al `FiservemeaOrder { .., additional_details }`.

- [ ] **Step 4: Test**

```rust
    #[test]
    fn tax_refund_legal_framework_serializes() {
        let details = FiservemeaAdditionalDetails {
            tax_refund_request_data: Some(FiservemeaTaxRefundRequestData {
                legal_framework: FiservemeaLegalFramework::UryReturnsIvaLaw19210,
            }),
        };
        let json = serde_json::to_value(&details).unwrap();
        assert_eq!(
            json["taxRefundRequestData"]["legalFramework"],
            "URY_RETURNS_IVA_LAW_19210"
        );
    }
```

- [ ] **Step 5: Compilar + test + commit**

```bash
bash -lc 'cd /home/enzods/hyperswitch && cargo test -p hyperswitch_connectors fiservemea 2>&1 | tail -20'
git add -A && git commit -m "feat(fiservemea): Tax Refund Uruguay legalFramework"
```

---

### Task 3: Fix de Void/anulación

**Files:**
- Modify: `crates/hyperswitch_connectors/src/connectors/fiservemea/transformers.rs` (`FiservemeaVoidRequest`)

**Interfaces:**
- Consumes: `PaymentsCancelRouterData` / `PaymentsCancelData`.
- Produces: `FiservemeaVoidRequest` que elige el `requestType` correcto.

- [ ] **Step 1: Investigar `PaymentsCancelData`**

```bash
bash -lc "grep -n 'pub struct PaymentsCancelData' -A 20 /home/enzods/hyperswitch/crates/hyperswitch_domain_models/src/router_request_types.rs"
```
Determinar si expone `capture_method` u otra señal para distinguir venta/pre-auth. Documentar el hallazgo como comentario en el código.

- [ ] **Step 2: Implementar la selección de requestType**

Regla: si hay señal de auto-capture/sale ⇒ `VoidTransaction`; si es pre-auth no capturado (o no hay señal) ⇒ `VoidPreAuthTransactions` (default seguro, comportamiento actual).

```rust
impl TryFrom<&PaymentsCancelRouterData> for FiservemeaVoidRequest {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(item: &PaymentsCancelRouterData) -> Result<Self, Self::Error> {
        // Si PaymentsCancelData expone capture_method:
        let request_type = match item.request.capture_method {
            Some(enums::CaptureMethod::Automatic)
            | Some(enums::CaptureMethod::SequentialAutomatic) => {
                FiservemeaRequestType::VoidTransaction
            }
            _ => FiservemeaRequestType::VoidPreAuthTransactions,
        };
        Ok(Self { request_type })
    }
}
```

> Si `PaymentsCancelData` **no** expone `capture_method`, mantener `VoidPreAuthTransactions` como default y dejar un comentario `// TODO(fiservemea): no capture signal available; defaults to preauth void`. Agregar la variante `VoidTransaction` al enum `FiservemeaRequestType` (ya existe `VoidPreAuthTransactions`).

- [ ] **Step 3: Agregar `VoidTransaction` al enum `FiservemeaRequestType`**

```rust
pub enum FiservemeaRequestType {
    PaymentCardSaleTransaction,
    PaymentCardPreAuthTransaction,
    PostAuthTransaction,
    VoidTransaction,
    VoidPreAuthTransactions,
    ReturnTransaction,
}
```

- [ ] **Step 4: Test (si hay señal de capture_method)**

```rust
    // Solo si PaymentsCancelData expone capture_method; si no, omitir este test.
    // Verifica que auto-capture ⇒ VoidTransaction.
```

- [ ] **Step 5: Compilar + commit**

```bash
bash -lc 'cd /home/enzods/hyperswitch && cargo check -p hyperswitch_connectors 2>&1 | tail -20'
git add -A && git commit -m "fix(fiservemea): choose VoidTransaction vs VoidPreAuthTransactions"
```

---

### Task 4: 3DS nativo — request de Authorize + parsing de respuesta

**Files:**
- Modify: `crates/hyperswitch_connectors/src/connectors/fiservemea/transformers.rs`

**Interfaces:**
- Consumes: `FiservemeaPaymentsRequest`, `is_three_ds()` (`crate::utils::RouterData` trait, `utils.rs:980`), `req.request.complete_authorize_url`, `RedirectForm` (`hyperswitch_domain_models::router_response_types`), `AttemptStatus::AuthenticationPending`.
- Produces: `FiservemeaAuthenticationRequest`; parsing de `authenticationResponse` (`secure3dMethod.methodForm`, `params`); campo `authentication_request` en `FiservemeaPaymentsRequest`; rama 3DS en la construcción de la respuesta de Authorize.

- [ ] **Step 1: Structs de `authenticationRequest`** (referencia doc líneas 526-578)

```rust
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaAuthenticationRequest {
    authentication_type: String, // "Secure3D21AuthenticationRequest"
    term_url: String,
    method_notification_url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    challenge_indicator: Option<String>, // "01"
    #[serde(skip_serializing_if = "Option::is_none")]
    challenge_window_size: Option<String>, // "01"
}
```

Agregar a `FiservemeaPaymentsRequest`:
```rust
    #[serde(skip_serializing_if = "Option::is_none")]
    authentication_request: Option<FiservemeaAuthenticationRequest>,
```

- [ ] **Step 2: Poblar el authenticationRequest solo si `is_three_ds()`**

En `FiservemeaPaymentsRequest::try_from` (auth), usando `use crate::utils::RouterData as _;` (trait con `is_three_ds`):

```rust
let authentication_request = if item.router_data.is_three_ds() {
    let return_url = item.router_data.request.complete_authorize_url.clone().ok_or(
        errors::ConnectorError::MissingRequiredField { field_name: "complete_authorize_url" },
    )?;
    Some(FiservemeaAuthenticationRequest {
        authentication_type: "Secure3D21AuthenticationRequest".to_string(),
        term_url: return_url.clone(),
        method_notification_url: return_url,
        challenge_indicator: Some("01".to_string()),
        challenge_window_size: Some("01".to_string()),
    })
} else {
    None
};
```
La rama `NoThreeDs` deja `authentication_request: None` ⇒ request idéntico al actual.

- [ ] **Step 3: Structs de parsing de `authenticationResponse`** (doc 599-617, 709-740)

```rust
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaSecure3dMethod {
    method_form: Option<String>,
    secure3d_trans_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaAcsParams {
    #[serde(rename = "acsURL")]
    acs_url: Option<String>,
    #[serde(rename = "cReq")]
    c_req: Option<String>,
    #[serde(rename = "termURL")]
    term_url: Option<String>,
    sessiondata: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaAuthenticationResponse {
    #[serde(rename = "type")]
    auth_type: Option<String>,
    version: Option<String>,
    secure3d_method: Option<FiservemeaSecure3dMethod>,
    params: Option<FiservemeaAcsParams>,
}
```

Agregar `authentication_response: Option<FiservemeaAuthenticationResponse>` a `FiservemeaPaymentsResponse`.

- [ ] **Step 4: `map_status`: rama `AuthenticationPending`**

Cuando `transaction_status == WAITING` **y** hay `authentication_response` con `methodForm` o `params.acsURL`, mapear a `common_enums::AttemptStatus::AuthenticationPending`. (Hoy `WAITING`→`Pending`; mantener `Pending` cuando no hay datos 3DS.)

> Requiere pasar el flag de "tiene datos 3DS" a `map_status`, o hacer el mapeo en el `TryFrom` de Authorize. Implementar en el `TryFrom<ResponseRouterData<...>>` de Authorize (no en el genérico), para no afectar capture/void/refund.

- [ ] **Step 5: Construir `redirection_data` en la respuesta de Authorize**

En el `TryFrom` de la respuesta de Authorize (el genérico actual `transformers.rs:352-378` puede necesitar especializarse para Authorize), cuando haya `authentication_response`:
- Si hay `secure3d_method.method_form` (HTML) ⇒ `RedirectForm::Html { html_data: method_form }`.
- Si hay `params.acs_url` ⇒ `RedirectForm::Form { endpoint: acs_url, method: Method::Post, form_fields: {"creq": c_req, "threeDSSessionData": sessiondata} }`.
- Setear `redirection_data: Box::new(Some(...))` y `status = AuthenticationPending`.

> **Verificar** nombres exactos de `form_fields` contra el doc (`creq`/`threeDSSessionData`). Referencia de construcción: `stripe/transformers.rs:2940-3011` y `RedirectForm` en `router_response_types.rs:258-335`.

- [ ] **Step 6: Compilar + commit**

```bash
bash -lc 'cd /home/enzods/hyperswitch && cargo check -p hyperswitch_connectors 2>&1 | tail -30'
git add -A && git commit -m "feat(fiservemea): 3DS authorize request + redirection parsing"
```

---

### Task 5: 3DS nativo — CompleteAuthorize (continuación PATCH)

**Files:**
- Modify: `crates/hyperswitch_connectors/src/connectors/fiservemea.rs`
- Modify: `crates/hyperswitch_connectors/src/connectors/fiservemea/transformers.rs`

**Interfaces:**
- Consumes: `CompleteAuthorize`, `CompleteAuthorizeData`, `PaymentsCompleteAuthorizeRouterData`, `PaymentsCompleteAuthorizeType`, `api::PaymentsCompleteAuthorize`, `req.request.redirect_response.{params,payload}`, structs de Task 4.
- Produces: `impl ConnectorIntegration<CompleteAuthorize, ...>` para `Fiservemea`; `FiservemeaCompleteAuthorizeRequest`; mapeo de respuesta a estado terminal.

- [ ] **Step 1: Imports + marker trait** (referencia `shift4.rs:20-33,159`)

En `fiservemea.rs` agregar imports de `CompleteAuthorize` (router_flow_types), `CompleteAuthorizeData` (router_request_types), `PaymentsCompleteAuthorizeRouterData` (types), `PaymentsCompleteAuthorizeType` (interfaces types). Agregar `impl api::PaymentsCompleteAuthorize for Fiservemea {}` en el bloque de markers (`fiservemea.rs:90-101`).

- [ ] **Step 2: Request de continuación** (doc 656-672 method-status, 758-783 acsResponse)

En `transformers.rs`:
```rust
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaCompleteAuthorizeRequest {
    authentication_type: String, // "Secure3D21AuthenticationUpdateRequest"
    #[serde(skip_serializing_if = "Option::is_none")]
    method_notification_status: Option<String>, // "RECEIVED" / "EXPECTED_BUT_NOT_RECEIVED"
    #[serde(skip_serializing_if = "Option::is_none")]
    acs_response: Option<FiservemeaAcsResponse>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FiservemeaAcsResponse {
    #[serde(rename = "cRes")]
    c_res: String,
}
```

`TryFrom<&PaymentsCompleteAuthorizeRouterData>`: leer `req.request.redirect_response`:
- Si el payload de retorno trae `cres`/`cRes` ⇒ construir `acs_response` (paso final).
- Si no (retorno del methodForm) ⇒ `method_notification_status: Some("RECEIVED")` (o `EXPECTED_BUT_NOT_RECEIVED`).

> Extraer los datos del retorno de `redirect_response.params` (query string) y `redirect_response.payload` (JSON). Referencia: `router_request_types.rs:790,804-808` y cómo shift4 lee `redirect_response` en `shift4.rs:570-583`.

- [ ] **Step 3: `impl ConnectorIntegration<CompleteAuthorize, ...>`** (modelar en `shift4.rs:547-635`)

Métodos: `get_headers` (=`build_headers`), `get_content_type`, `get_url` = `{base}/ipp/payments-gateway/v2/payments/{connector_transaction_id}`, `get_request_body` (`FiservemeaCompleteAuthorizeRequest`), `build_request` con **`.method(Method::Patch)`**, `handle_response` (parsear `FiservemeaPaymentsResponse`; si vuelve `WAITING`+`params` ⇒ otro `redirection_data`+`AuthenticationPending`; si terminal ⇒ Charged/Authorized/Failure), `get_error_response`.

> `build_headers` ya calcula la firma sobre el body para POST/PATCH (`fiservemea.rs:146` maneja `Method::Post | Put | Delete | Patch`). Confirmar que `get_http_method` default sea POST y que el PATCH se setee en `build_request`.

- [ ] **Step 4: Habilitar 3DS en supported payment methods**

En `fiservemea.rs` `FISERVEMEA_SUPPORTED_PAYMENT_METHODS` (líneas ~812-848): cambiar `three_ds: FeatureStatus::NotSupported` ⇒ `Supported` para Credit y Debit.

- [ ] **Step 5: Compilar + commit**

```bash
bash -lc 'cd /home/enzods/hyperswitch && cargo check -p hyperswitch_connectors 2>&1 | tail -40'
git add -A && git commit -m "feat(fiservemea): native 3DS CompleteAuthorize (PATCH continuation)"
```

---

### Task 6: Endurecimiento — integrity objects + revisión de mapeos

**Files:**
- Modify: `crates/hyperswitch_connectors/src/connectors/fiservemea.rs`

**Interfaces:**
- Consumes: `connector_utils::{get_authorise_integrity_object, get_capture_integrity_object, get_refund_integrity_object, get_sync_integrity_object}` (usados en `fiserv.rs`), `self.amount_converter`.

- [ ] **Step 1: Integrity objects en `handle_response`**

Replicar el patrón de `fiserv.rs` en `fiservemea.rs` para Authorize/Capture/PSync/Refund/RSync: extraer `approved_amount`/`transaction_amount` + currency de `FiservemeaPaymentsResponse`, construir el integrity object con `self.amount_converter`, y setear `router_data.request.integrity_object = Some(...)`.

> El monto en la respuesta de fiservemea es `f64` (`approved_amount.total`/`transaction_amount.total`). Convertir a `MinorUnit`/lo que espere `get_*_integrity_object`. Ver firmas en `crates/hyperswitch_connectors/src/utils.rs` (las mismas que usa `fiserv.rs:412-431`).

- [ ] **Step 2: Revisar mapeos**

Confirmar: refund parcial (`Partial`→`PartialCharged`), `map_status`/`map_refund_status` usan `transaction_result` con fallback a `transaction_status`, y `build_error_response` cubre los casos. Ajustar solo si hay bug; documentar.

- [ ] **Step 3: Compilar + commit**

```bash
bash -lc 'cd /home/enzods/hyperswitch && cargo check -p hyperswitch_connectors 2>&1 | tail -20'
git add -A && git commit -m "feat(fiservemea): amount integrity objects + mapping review"
```

---

### Task 7: Verificación final (compile + clippy + tests)

**Files:** ninguno (solo verificación / fixes menores)

- [ ] **Step 1: Clippy del crate**

```bash
bash -lc 'cd /home/enzods/hyperswitch && cargo clippy -p hyperswitch_connectors --all-targets 2>&1 | tail -40'
```
Esperado: sin warnings nuevos de `fiservemea`. Corregir los que aparezcan.

- [ ] **Step 2: Tests del conector**

```bash
bash -lc 'cd /home/enzods/hyperswitch && cargo test -p hyperswitch_connectors fiservemea 2>&1 | tail -30'
```
Esperado: todos verdes.

- [ ] **Step 3: Commit final (si hubo fixes de clippy)**

```bash
git add -A && git commit -m "chore(fiservemea): clippy + test cleanup"
```

---

## Self-Review (cobertura vs spec)

- §3.1 Cuotas → Task 1 ✓
- §3.2 Tax Refund UY → Task 2 ✓
- §3.3 Fix Void → Task 3 ✓
- §3.4 3DS nativo → Tasks 4 y 5 ✓
- §3.5 Endurecimiento → Task 6 ✓
- Compila/clippy → Task 7 ✓

**Riesgos conocidos (a resolver por el implementador con `cargo`):** tipo exacto de `frm_metadata` (Secret vs Value); si `PaymentsCancelData` expone `capture_method`; si el `TryFrom` genérico de respuesta necesita especializarse para no romper capture/void/refund al agregar la rama 3DS de Authorize; nombres exactos de `form_fields` del ACS. Todos verificables leyendo los conectores de referencia + compilando.
