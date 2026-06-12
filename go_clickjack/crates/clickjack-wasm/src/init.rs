use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use web_sys::{HtmlElement, HtmlIFrameElement, HtmlInputElement};

use crate::decoy::{inject_decoy_overlay, on_template_change, remove_decoy_overlay, update_decoy_opacity};
use crate::history::add_to_history;
use crate::phish::{inject_phish_overlay, remove_phish_overlay};
use crate::utils::{document, run_or_log};

/// Wires all button and input listeners for the main application UI.
///
/// Called once from `start()` after the WASM module has been instantiated.
/// Because the module is loaded as type="module", the DOM is already parsed.
pub fn setup_dom_listeners() {
    run_or_log(do_setup);
}

fn do_setup() -> Result<(), JsValue> {
    let doc = document()?;

    let iframe = doc
        .query_selector(r#"iframe[name="website"]"#)?
        .ok_or_else(|| JsValue::from_str("no iframe[name=website]"))?
        .dyn_into::<HtmlIFrameElement>()?;

    let web_input = doc
        .query_selector(r#"input[name="webInput"]"#)?
        .ok_or_else(|| JsValue::from_str("no input[name=webInput]"))?
        .dyn_into::<HtmlInputElement>()?;

    // If the iframe was pre-loaded with a URL (from the server template),
    // register it in history so it appears in the panel on first load.
    let initial_src = iframe.src();
    if !initial_src.is_empty() && initial_src != "about:blank" {
        let page_origin = doc
            .location()
            .and_then(|l| l.href().ok())
            .unwrap_or_default();
        if initial_src != page_origin {
            let _ = add_to_history(&initial_src);
        }
    }

    // URL submit button and Enter key in the input field.
    {
        let iframe_ref = iframe.clone();
        let input_ref = web_input.clone();
        let on_submit = Closure::<dyn Fn()>::new(move || {
            run_or_log(|| load_url(&input_ref, &iframe_ref));
        });
        doc.get_element_by_id("submit-btn")
            .ok_or_else(|| JsValue::from_str("no #submit-btn"))?
            .add_event_listener_with_callback("click", on_submit.as_ref().unchecked_ref())?;
        on_submit.forget();
    }
    {
        let iframe_ref = iframe.clone();
        let input_ref = web_input.clone();
        let on_keydown = Closure::<dyn Fn(web_sys::KeyboardEvent)>::new(move |e: web_sys::KeyboardEvent| {
            if e.key() == "Enter" {
                run_or_log(|| load_url(&input_ref, &iframe_ref));
            }
        });
        web_input.add_event_listener_with_callback("keydown", on_keydown.as_ref().unchecked_ref())?;
        on_keydown.forget();
    }

    // Phishing overlay controls.
    wire_click("phish-btn", &doc, move || inject_phish_overlay())?;
    wire_click("overlay-reset", &doc, move || remove_phish_overlay())?;

    // Decoy overlay controls.
    {
        let doc2 = doc.clone();
        wire_click("decoy-btn", &doc, move || {
            let key = doc2
                .get_element_by_id("decoy-template")
                .and_then(|el| el.dyn_into::<web_sys::HtmlSelectElement>().ok())
                .map(|sel| sel.value())
                .unwrap_or_else(|| "fake-button".to_owned());
            inject_decoy_overlay(&key);
        })?;
    }
    wire_click("decoy-reset", &doc, move || remove_decoy_overlay())?;
    wire_event("decoy-template", "change", &doc, move || on_template_change())?;

    // Opacity slider.
    {
        let on_input = Closure::<dyn Fn(web_sys::Event)>::new(move |e: web_sys::Event| {
            if let Some(input) = e.target().and_then(|t| t.dyn_into::<HtmlInputElement>().ok()) {
                if let Ok(val) = input.value().parse::<f64>() {
                    update_decoy_opacity(val);
                }
            }
        });
        if let Some(slider) = doc.get_element_by_id("opacity-slider") {
            slider.add_event_listener_with_callback("input", on_input.as_ref().unchecked_ref())?;
        }
        on_input.forget();
    }

    // Fullscreen toggle button.
    {
        let doc_fs = doc.clone();
        wire_click("fullscreen-btn", &doc, move || {
            run_or_log(|| toggle_fullscreen(&doc_fs));
        })?;
    }

    // Escape key exits fullscreen from anywhere on the page.
    {
        let doc_esc = doc.clone();
        let on_keydown = Closure::<dyn Fn(web_sys::KeyboardEvent)>::new(move |e: web_sys::KeyboardEvent| {
            if e.key() == "Escape" {
                run_or_log(|| exit_fullscreen(&doc_esc));
            }
        });
        doc.add_event_listener_with_callback("keydown", on_keydown.as_ref().unchecked_ref())?;
        on_keydown.forget();
    }

    Ok(())
}

fn load_url(input: &HtmlInputElement, iframe: &HtmlIFrameElement) -> Result<(), JsValue> {
    let url = input.value();
    let url = url.trim();
    if url.is_empty() {
        return Ok(());
    }
    iframe.set_src(url);
    add_to_history(url)?;
    Ok(())
}

fn toggle_fullscreen(doc: &web_sys::Document) -> Result<(), JsValue> {
    let body = doc
        .body()
        .ok_or_else(|| JsValue::from_str("no body element"))?;
    let classes = body.class_list();
    if classes.contains("ui-fullscreen") {
        exit_fullscreen(doc)?;
    } else {
        classes.add_1("ui-fullscreen")?;
        // Update button label.
        if let Some(btn) = doc.get_element_by_id("fullscreen-btn") {
            btn.dyn_into::<HtmlElement>()?.set_inner_text("Exit");
        }
    }
    Ok(())
}

fn exit_fullscreen(doc: &web_sys::Document) -> Result<(), JsValue> {
    if let Some(body) = doc.body() {
        body.class_list().remove_1("ui-fullscreen")?;
    }
    if let Some(btn) = doc.get_element_by_id("fullscreen-btn") {
        btn.dyn_into::<HtmlElement>()?.set_inner_text("Fullscreen");
    }
    Ok(())
}

/// Attaches a click listener to an element by id.
fn wire_click<F>(id: &str, doc: &web_sys::Document, f: F) -> Result<(), JsValue>
where
    F: Fn() + 'static,
{
    let cb = Closure::<dyn Fn()>::new(f);
    if let Some(el) = doc.get_element_by_id(id) {
        el.add_event_listener_with_callback("click", cb.as_ref().unchecked_ref())?;
    }
    cb.forget();
    Ok(())
}

/// Attaches an arbitrary event listener to an element by id.
fn wire_event<F>(id: &str, event: &str, doc: &web_sys::Document, f: F) -> Result<(), JsValue>
where
    F: Fn() + 'static,
{
    let cb = Closure::<dyn Fn()>::new(f);
    if let Some(el) = doc.get_element_by_id(id) {
        el.add_event_listener_with_callback(event, cb.as_ref().unchecked_ref())?;
    }
    cb.forget();
    Ok(())
}
