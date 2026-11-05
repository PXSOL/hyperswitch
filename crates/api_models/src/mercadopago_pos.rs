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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MercadopagoPosSetupRequest {
    pub store_name: String,
    pub pos_name: String,
    pub location: MercadopagoPosLocation,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MercadopagoPosSetupResponse {
    pub store_id: String,
    pub external_store_id: String,
    pub pos_id: String,
    pub external_pos_id: String,
}
