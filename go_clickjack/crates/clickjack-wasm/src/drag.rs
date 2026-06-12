use std::cell::RefCell;
use std::rc::Rc;

use gloo_events::EventListener;
use gloo_timers::callback::Timeout;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use web_sys::{HtmlElement, MouseEvent};

use crate::utils::document;

const MIN_W: f64 = 80.0;
const MIN_H: f64 = 40.0;
const HINT_DELAY_MS: u32 = 10_000;

struct DragState {
    is_dragging: bool,
    is_resizing: bool,
    resize_n: bool,
    resize_s: bool,
    resize_e: bool,
    resize_w: bool,
    start_x: f64,
    start_y: f64,
    start_left: f64,
    start_top: f64,
    start_w: f64,
    start_h: f64,
}

impl Default for DragState {
    fn default() -> Self {
        Self {
            is_dragging: false,
            is_resizing: false,
            resize_n: false,
            resize_s: false,
            resize_e: false,
            resize_w: false,
            start_x: 0.0,
            start_y: 0.0,
            start_left: 0.0,
            start_top: 0.0,
            start_w: 0.0,
            start_h: 0.0,
        }
    }
}

/// Owns all event listeners attached by `make_overlay_interactive`.
///
/// Dropping this value removes all listeners and cancels any pending hint timer.
/// The document-level mousemove/mouseup and the per-handle mousedown listeners
/// are all stored here to avoid leaking their closures.
pub struct DragCleanup {
    _dragbar: EventListener,
    _handles: Vec<EventListener>,
    _mousemove: EventListener,
    _mouseup: EventListener,
}

thread_local! {
    /// Active drag cleanup for the single decoy overlay.
    static DRAG_CLEANUP: RefCell<Option<DragCleanup>> = RefCell::new(None);
    /// Pending hint-fade timer; cancelled on the next drag or resize interaction.
    static HINT_TIMER: RefCell<Option<Timeout>> = RefCell::new(None);
}

/// Attaches drag and resize behaviour to an overlay element.
pub fn make_overlay_interactive(overlay: HtmlElement) -> Result<(), JsValue> {
    let doc = document()?;

    let dragbar = overlay
        .query_selector(".overlay-dragbar")?
        .ok_or_else(|| JsValue::from_str("overlay has no .overlay-dragbar child"))?
        .dyn_into::<HtmlElement>()?;

    let iframe = doc
        .query_selector(r#"iframe[name="website"]"#)?
        .ok_or_else(|| JsValue::from_str("no iframe[name=website] found"))?
        .dyn_into::<HtmlElement>()?;

    let state = Rc::new(RefCell::new(DragState::default()));

    schedule_hint_fade(overlay.clone());

    // Dragbar initiates a move. Using EventListener so the listener is removed
    // when DragCleanup is dropped (avoids leaking the closure allocation).
    let dragbar_listener = {
        let state = Rc::clone(&state);
        let overlay_ref = overlay.clone();
        let iframe_ref = iframe.clone();
        EventListener::new(&dragbar, "mousedown", move |e| {
            let e = match e.dyn_ref::<MouseEvent>() {
                Some(m) => m,
                None => return,
            };
            restore_hint(&overlay_ref);
            {
                let mut s = state.borrow_mut();
                s.is_dragging = true;
                s.start_x = e.client_x() as f64;
                s.start_y = e.client_y() as f64;
                s.start_left = overlay_ref.offset_left() as f64;
                s.start_top = overlay_ref.offset_top() as f64;
            }
            let _ = iframe_ref.style().set_property("pointer-events", "none");
            e.prevent_default();
        })
    };

    // Resize handles for each of the eight compass directions.
    // All listeners are stored so they are removed when DragCleanup is dropped.
    let mut handle_listeners: Vec<EventListener> = Vec::with_capacity(8);
    for dir in &["nw", "n", "ne", "e", "se", "s", "sw", "w"] {
        let handle = doc
            .create_element("div")?
            .dyn_into::<HtmlElement>()?;
        handle.set_class_name(&format!("resize-handle resize-{dir}"));

        let listener = {
            let state_ref = Rc::clone(&state);
            let overlay_ref = overlay.clone();
            let iframe_ref = iframe.clone();
            let dir_owned = dir.to_string();
            EventListener::new(&handle, "mousedown", move |e| {
                let e = match e.dyn_ref::<MouseEvent>() {
                    Some(m) => m,
                    None => return,
                };
                restore_hint(&overlay_ref);
                {
                    let mut s = state_ref.borrow_mut();
                    s.is_resizing = true;
                    s.resize_n = dir_owned.contains('n');
                    s.resize_s = dir_owned.contains('s');
                    s.resize_e = dir_owned.contains('e');
                    s.resize_w = dir_owned.contains('w');
                    s.start_x = e.client_x() as f64;
                    s.start_y = e.client_y() as f64;
                    s.start_left = overlay_ref.offset_left() as f64;
                    s.start_top = overlay_ref.offset_top() as f64;
                    s.start_w = overlay_ref.offset_width() as f64;
                    s.start_h = overlay_ref.offset_height() as f64;
                }
                let _ = iframe_ref.style().set_property("pointer-events", "none");
                e.prevent_default();
            })
        };

        overlay.append_child(&handle)?;
        handle_listeners.push(listener);
    }

    // Document-level mousemove drives both dragging and resizing.
    let state_move = Rc::clone(&state);
    let overlay_move = overlay.clone();
    let mousemove = EventListener::new(&doc, "mousemove", move |e| {
        let e = match e.dyn_ref::<MouseEvent>() {
            Some(m) => m,
            None => return,
        };

        // Extract all state in one borrow, then release before any DOM calls.
        let snapshot = {
            let s = state_move.borrow();
            if !s.is_dragging && !s.is_resizing {
                return;
            }
            (
                s.is_dragging,
                s.resize_n,
                s.resize_s,
                s.resize_e,
                s.resize_w,
                e.client_x() as f64 - s.start_x,
                e.client_y() as f64 - s.start_y,
                s.start_left,
                s.start_top,
                s.start_w,
                s.start_h,
            )
        };
        let (is_dragging, rn, rs, re, rw, dx, dy, sl, st, sw, sh) = snapshot;
        let style = overlay_move.style();

        if is_dragging {
            let _ = style.set_property("left", &px(sl + dx));
            let _ = style.set_property("top", &px(st + dy));
            return;
        }

        if re {
            let _ = style.set_property("width", &px(f64::max(MIN_W, sw + dx)));
        }
        if rs {
            let _ = style.set_property("height", &px(f64::max(MIN_H, sh + dy)));
        }
        if rw {
            let new_w = f64::max(MIN_W, sw - dx);
            let _ = style.set_property("left", &px(sl + sw - new_w));
            let _ = style.set_property("width", &px(new_w));
        }
        if rn {
            let new_h = f64::max(MIN_H, sh - dy);
            let _ = style.set_property("top", &px(st + sh - new_h));
            let _ = style.set_property("height", &px(new_h));
        }
    });

    // Document-level mouseup ends a drag or resize session.
    let state_up = Rc::clone(&state);
    let overlay_up = overlay.clone();
    let iframe_up = iframe;
    let mouseup = EventListener::new(&doc, "mouseup", move |_| {
        let was_active = {
            let s = state_up.borrow();
            s.is_dragging || s.is_resizing
        };
        {
            let mut s = state_up.borrow_mut();
            s.is_dragging = false;
            s.is_resizing = false;
        }
        let _ = iframe_up.style().set_property("pointer-events", "");
        if was_active {
            schedule_hint_fade(overlay_up.clone());
        }
    });

    DRAG_CLEANUP.with(|cell| {
        *cell.borrow_mut() = Some(DragCleanup {
            _dragbar: dragbar_listener,
            _handles: handle_listeners,
            _mousemove: mousemove,
            _mouseup: mouseup,
        });
    });

    Ok(())
}

/// Removes all drag listeners and cancels any pending hint timer.
///
/// Call this when the overlay is removed from the DOM.
pub fn cleanup_drag() {
    DRAG_CLEANUP.with(|cell| {
        *cell.borrow_mut() = None;
    });
    HINT_TIMER.with(|cell| {
        *cell.borrow_mut() = None;
    });
}

fn schedule_hint_fade(overlay: HtmlElement) {
    HINT_TIMER.with(|cell| {
        *cell.borrow_mut() = Some(Timeout::new(HINT_DELAY_MS, move || {
            let _ = overlay.class_list().add_1("overlay--faded");
        }));
    });
}

fn restore_hint(overlay: &HtmlElement) {
    HINT_TIMER.with(|cell| {
        *cell.borrow_mut() = None;
    });
    let _ = overlay.class_list().remove_1("overlay--faded");
}

fn px(value: f64) -> String {
    format!("{value}px")
}
