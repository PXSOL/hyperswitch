//! Store and point of sale (POS) setup for Mercado Pago in-person QR payments.

use serde::{Deserialize, Serialize};

/// Where the seller's store is. Mercado Pago validates `city_name` against its own list
/// (departments, not towns) and answers with the valid values when it is wrong.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MercadopagoPosLocation {
    pub street_number: String,
    pub street_name: String,
    pub city_name: String,
    pub state_name: String,
    pub latitude: f64,
    pub longitude: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reference: Option<String>,
}

/// With `existing_pos_id` the seller's own POS is adopted and the other fields are ignored;
/// without it `store_name`, `pos_name` and `location` are required and a store and POS are created.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MercadopagoPosSetupRequest {
    #[serde(default)]
    pub store_name: Option<String>,
    #[serde(default)]
    pub pos_name: Option<String>,
    #[serde(default)]
    pub location: Option<MercadopagoPosLocation>,
    /// Id of a POS the seller already has at Mercado Pago (digits only).
    #[serde(default)]
    pub existing_pos_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MercadopagoPosSetupResponse {
    pub store_id: String,
    pub external_store_id: String,
    pub pos_id: String,
    pub external_pos_id: String,
    /// Plain URLs Mercado Pago serves for the POS's fixed QR.
    pub qr_image: Option<String>,
    pub qr_template_document: Option<String>,
    pub qr_template_image: Option<String>,
}

/// One POS of the seller, as listed by `GET .../connectors/mercadopago/pos/{id}`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MercadopagoPosSummary {
    pub pos_id: String,
    pub name: Option<String>,
    pub store_id: Option<String>,
    pub store_name: Option<String>,
    /// Whether the POS already has an `external_id` (so adopting it changes nothing there).
    pub has_external_id: bool,
    pub qr_image: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MercadopagoPosListResponse {
    pub pos: Vec<MercadopagoPosSummary>,
}
