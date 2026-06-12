mod decoy;
mod drag;
mod history;
mod init;
mod phish;
mod utils;

pub use decoy::{inject_decoy_overlay, on_template_change, remove_decoy_overlay, update_decoy_opacity};
pub use phish::{inject_phish_overlay, remove_phish_overlay};

use wasm_bindgen::prelude::*;

/// Entry point called automatically after the WASM module is instantiated.
///
/// type="module" scripts execute after the HTML document has finished parsing,
/// so the DOM is fully available here without a DOMContentLoaded listener.
#[wasm_bindgen(start)]
pub fn start() {
    init::setup_dom_listeners();
}
