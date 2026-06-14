use wasm_bindgen::JsCast;
use wasm_bindgen::JsValue;
use web_sys::{HtmlElement, HtmlIFrameElement, HtmlInputElement, HtmlUListElement};

use crate::utils::document;

const HISTORY_LIMIT: u32 = 20;

/// Prepends a URL entry to the session history list.
///
/// Duplicate URLs are silently ignored. The list is capped at HISTORY_LIMIT
/// entries; the oldest entry is removed when the cap is reached.
pub fn add_to_history(url: &str) -> Result<(), JsValue> {
    let doc = document()?;

    let list = doc
        .get_element_by_id("url-history")
        .ok_or_else(|| JsValue::from_str("no #url-history element"))?
        .dyn_into::<HtmlUListElement>()?;

    // Reject duplicates.
    let items = list.query_selector_all("li")?;
    for i in 0..items.length() {
        if let Some(node) = items.get(i) {
            let el = node.dyn_into::<HtmlElement>()?;
            if el.dataset().get("url").as_deref() == Some(url) {
                return Ok(());
            }
        }
    }

    // Remove the oldest entry when the list is full.
    if items.length() >= HISTORY_LIMIT {
        if let Some(last) = list.last_element_child() {
            list.remove_child(&last)?;
        }
    }

    let li = doc
        .create_element("li")?
        .dyn_into::<HtmlElement>()?;
    li.dataset().set("url", url)?;
    li.set_title(url);

    let label = doc.create_element("span")?.dyn_into::<HtmlElement>()?;
    label.set_class_name("url-label");
    label.set_inner_text(url);

    let btn = doc.create_element("button")?.dyn_into::<HtmlElement>()?;
    btn.set_class_name("url-load");
    btn.set_inner_text("Load");

    // Wire the load button. The closure is leaked because history entries
    // persist for the page session.
    let url_owned = url.to_owned();
    let on_click = wasm_bindgen::closure::Closure::<dyn Fn()>::new(move || {
        crate::utils::run_or_log(|| {
            let doc = crate::utils::document()?;
            if let Some(input) = doc.query_selector(r#"input[name="webInput"]"#)? {
                input
                    .dyn_into::<HtmlInputElement>()?
                    .set_value(&url_owned);
            }
            if let Some(frame) = doc.query_selector(r#"iframe[name="website"]"#)? {
                frame
                    .dyn_into::<HtmlIFrameElement>()?
                    .set_src(&url_owned);
            }
            Ok(())
        });
    });
    btn.add_event_listener_with_callback("click", on_click.as_ref().unchecked_ref())?;
    on_click.forget();

    li.append_child(&label)?;
    li.append_child(&btn)?;

    // Prepend so the newest entry appears at the top.
    list.insert_before(&li, list.first_child().as_ref())?;

    Ok(())
}
