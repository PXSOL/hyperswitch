//! Terminal setup for Mercado Pago Point (in-person card terminal) payments.

use serde::{Deserialize, Serialize};

/// One Point terminal of the seller, as listed by
/// `GET .../connectors/mercadopago/terminals/{id}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MercadopagoTerminalSummary {
    /// Mercado Pago's id of the device, e.g. `NEWLAND_N950__N950NCD600391917`.
    pub terminal_id: String,
    pub pos_id: Option<String>,
    pub store_id: Option<String>,
    pub external_pos_id: Option<String>,
    /// The mode Mercado Pago reports for the device: `PDV` once it takes charges from an
    /// integration, `STANDALONE` while it only charges from its own keypad.
    pub operating_mode: Option<String>,
    /// Whether this is the terminal the connector account charges on.
    pub selected: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MercadopagoTerminalListResponse {
    pub terminals: Vec<MercadopagoTerminalSummary>,
    /// The terminal saved for the connector account, also when Mercado Pago no longer lists it.
    pub selected_terminal_id: Option<String>,
}

/// Chooses the terminal the connector account charges on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MercadopagoTerminalSetupRequest {
    /// One of the ids listed for the seller.
    pub terminal_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MercadopagoTerminalSetupResponse {
    pub terminal_id: String,
    /// The mode the terminal was switched to.
    pub operating_mode: String,
    /// The device only applies a new mode after it is restarted. `false` when Mercado Pago
    /// already reported the terminal in that mode before this call.
    pub restart_required: bool,
}
