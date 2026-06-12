use wasm_bindgen::JsValue;
use web_sys::{Document, Window};

/// Returns the global window object, or an error if it is not available.
pub fn window() -> Result<Window, JsValue> {
    web_sys::window().ok_or_else(|| JsValue::from_str("no global window"))
}

/// Returns the current page document, or an error if it is not available.
pub fn document() -> Result<Document, JsValue> {
    window()?.document().ok_or_else(|| JsValue::from_str("no document on window"))
}

/// Calls `f` and logs any returned error to the browser console.
///
/// Used to bridge between Result-returning internal functions and
/// #[wasm_bindgen] exported functions that cannot return Result.
pub fn run_or_log<F: FnOnce() -> Result<(), JsValue>>(f: F) {
    if let Err(e) = f() {
        web_sys::console::error_1(&e);
    }
}
