use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use web_sys::{HtmlElement, HtmlInputElement, HtmlSelectElement, HtmlTextAreaElement};

use clickjack_core::DecoyTemplate;

use crate::drag::{cleanup_drag, make_overlay_interactive};
use crate::utils::{document, run_or_log};

/// Injects the draggable decoy overlay using the currently selected template.
///
/// Calling this when a decoy overlay already exists is a no-op.
#[wasm_bindgen]
pub fn inject_decoy_overlay(template_key: &str) {
    run_or_log(|| do_inject(template_key));
}

/// Removes the decoy overlay and resets all related controls.
#[wasm_bindgen]
pub fn remove_decoy_overlay() {
    run_or_log(do_remove);
}

/// Updates the opacity of the decoy overlay from a 0-100 slider value.
#[wasm_bindgen]
pub fn update_decoy_opacity(val: f64) {
    run_or_log(|| {
        let doc = document()?;
        if let Some(overlay) = doc.get_element_by_id("decoy-overlay") {
            overlay
                .dyn_into::<HtmlElement>()?
                .style()
                .set_property("opacity", &format!("{:.2}", val / 100.0))?;
        }
        if let Some(label) = doc.get_element_by_id("opacity-value") {
            label
                .dyn_into::<HtmlElement>()?
                .set_inner_text(&format!("{:.0}%", val));
        }
        Ok(())
    });
}

/// Responds to a template selector change: swaps content and shows/hides
/// the custom HTML input row.
#[wasm_bindgen]
pub fn on_template_change() {
    run_or_log(do_template_change);
}

fn do_inject(template_key: &str) -> Result<(), JsValue> {
    let doc = document()?;

    if doc.get_element_by_id("decoy-overlay").is_some() {
        return Ok(());
    }

    let wrapper = doc
        .get_element_by_id("wrapper")
        .ok_or_else(|| JsValue::from_str("no #wrapper element"))?
        .dyn_into::<HtmlElement>()?;

    let overlay = doc
        .create_element("div")?
        .dyn_into::<HtmlElement>()?;
    overlay.set_id("decoy-overlay");

    // Default position: 5% from the left, 22% from the top of the wrapper.
    let style = overlay.style();
    style.set_property("left", &format!("{}px", (wrapper.offset_width() as f64 * 0.05).round()))?;
    style.set_property("top", &format!("{}px", (wrapper.offset_height() as f64 * 0.22).round()))?;
    style.set_property("width", "240px")?;
    style.set_property("height", "100px")?;

    let dragbar = doc.create_element("div")?.dyn_into::<HtmlElement>()?;
    dragbar.set_class_name("overlay-dragbar");
    // Use a middle dot to separate the two instructions, not a dash.
    dragbar.set_inner_text("\u{283f} Drag to reposition \u{00b7} resize from edges");

    let content = doc.create_element("div")?.dyn_into::<HtmlElement>()?;
    content.set_id("decoy-content");

    overlay.append_child(&dragbar)?;
    overlay.append_child(&content)?;
    wrapper.append_child(&overlay)?;

    apply_template(template_key, &content)?;
    make_overlay_interactive(overlay.clone())?;

    set_decoy_controls_visible(true)?;

    // Reset the opacity slider to 100%.
    if let Some(slider) = doc.get_element_by_id("opacity-slider") {
        slider.dyn_into::<HtmlInputElement>()?.set_value("100");
    }
    if let Some(label) = doc.get_element_by_id("opacity-value") {
        label.dyn_into::<HtmlElement>()?.set_inner_text("100%");
    }
    overlay.style().set_property("opacity", "1")?;

    Ok(())
}

fn do_remove() -> Result<(), JsValue> {
    let doc = document()?;

    if let Some(overlay) = doc.get_element_by_id("decoy-overlay") {
        cleanup_drag();
        overlay.remove();
    }

    set_decoy_controls_visible(false)?;

    // Reset the template selector back to the default.
    if let Some(select) = doc.get_element_by_id("decoy-template") {
        select
            .dyn_into::<HtmlSelectElement>()?
            .set_value("fake-button");
    }

    // Hide the custom HTML row.
    if let Some(row) = doc.get_element_by_id("custom-html-row") {
        row.dyn_into::<HtmlElement>()?
            .style()
            .set_property("display", "none")?;
    }

    Ok(())
}

fn do_template_change() -> Result<(), JsValue> {
    let doc = document()?;

    let select = doc
        .get_element_by_id("decoy-template")
        .ok_or_else(|| JsValue::from_str("no #decoy-template element"))?
        .dyn_into::<HtmlSelectElement>()?;

    let key = select.value();

    // Show the custom HTML input row only when the custom template is selected.
    if let Some(row) = doc.get_element_by_id("custom-html-row") {
        row.dyn_into::<HtmlElement>()?
            .style()
            .set_property("display", if key == "custom" { "flex" } else { "none" })?;
    }

    // Swap the content if the overlay is currently active.
    if let Some(content) = doc.get_element_by_id("decoy-content") {
        let content_el = content.dyn_into::<HtmlElement>()?;
        apply_template(&key, &content_el)?;
    }

    Ok(())
}

fn apply_template(key: &str, content: &HtmlElement) -> Result<(), JsValue> {
    let html: std::borrow::Cow<str> = if key == "custom" {
        // Read the current value of the custom HTML textarea.
        let doc = document()?;
        let textarea_val = doc
            .get_element_by_id("custom-html-input")
            .and_then(|el| el.dyn_into::<HtmlTextAreaElement>().ok())
            .map(|ta| ta.value())
            .unwrap_or_default();
        std::borrow::Cow::Owned(textarea_val)
    } else {
        match DecoyTemplate::from_key(key) {
            Some(tmpl) => tmpl.html(),
            // Unknown key: clear the content area.
            None => std::borrow::Cow::Borrowed(""),
        }
    };

    content.set_inner_html(&html);
    Ok(())
}

fn set_decoy_controls_visible(visible: bool) -> Result<(), JsValue> {
    let doc = document()?;

    if let Some(btn) = doc.get_element_by_id("decoy-reset") {
        btn.dyn_into::<HtmlElement>()?
            .style()
            .set_property("display", if visible { "inline-block" } else { "none" })?;
    }

    if let Some(controls) = doc.get_element_by_id("opacity-controls") {
        controls
            .dyn_into::<HtmlElement>()?
            .style()
            .set_property("display", if visible { "contents" } else { "none" })?;
    }

    Ok(())
}
