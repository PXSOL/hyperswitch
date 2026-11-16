//! TEMPORARY: remove after the processor account identity backfill (odd/tasks/processor-account-identity.md)
//!
//! The processor account a connector account (MCA) is connected to: a display name and, for
//! Mercado Pago, the account's identity fields. The key names are the contract with api2's
//! backfill.

use hyperswitch_masking::Secret;
use serde::{Deserialize, Serialize};

/// Where the display name comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectorAccountIdentitySource {
    /// Mercado Pago `GET /users/me` → `company.brand_name`, else `nickname`.
    MercadopagoUsersMe,
    /// Stripe `GET /v1/account` → dashboard display name, else business profile name.
    StripeAccount,
    /// Wompi `GET /merchants/{public_key}` → `name`, else `legal_name`.
    WompiMerchant,
    /// Fiserv IPG store id from the connector account, no processor call.
    FiservStore,
    /// No identity source for this connector.
    Unsupported,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectorAccountIdentityError {
    /// The processor could not be reached, refused the credentials, or answered without a name.
    Unavailable,
}

/// The tax identification of a Mercado Pago account (`/users/me` `identification`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MercadopagoAccountIdentification {
    /// For example `CUIT` or `DNI`.
    #[serde(rename = "type")]
    pub identification_type: String,
    /// Exactly as Mercado Pago returns it. Masked in logs and API events.
    pub number: Secret<String>,
}

/// The Mercado Pago account (`/users/me`) a connector account is connected to. Each field is
/// `null` when Mercado Pago leaves it empty.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MercadopagoAccountIdentity {
    /// The Mercado Pago user id.
    pub id: u64,
    pub nickname: Option<String>,
    /// `company.corporate_name`.
    pub corporate_name: Option<String>,
    /// Masked in logs and API events.
    pub email: Option<Secret<String>>,
    /// `null` when the type or the number is missing.
    pub identification: Option<MercadopagoAccountIdentification>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectorAccountIdentityResponse {
    pub connector_name: String,
    pub display_name: Option<String>,
    pub source: ConnectorAccountIdentitySource,
    /// Mercado Pago only; `null` for every other connector and whenever `error` is set.
    pub account: Option<MercadopagoAccountIdentity>,
    pub error: Option<ConnectorAccountIdentityError>,
}
