//! The Control center's live view of the broker's browser, which runs hidden by default.
//!
//! While the Control center is on screen this touches `watching` in the broker's
//! preview folder ($XDG_RUNTIME_DIR/passbroker/preview), and the broker writes a
//! masked JPEG of every bot's tab plus `sessions.json` about once a second (see
//! preview.py). Nothing is written while nobody watches. View-only.

use crate::{toast, wiz, AppWindow, PreviewTab, Shared, CONTROL_CENTER};
use serde_json::Value;
use slint::{ComponentHandle, Image, Model, ModelRc, Rgba8Pixel, SharedPixelBuffer, VecModel};
use std::fs::OpenOptions;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// An index older than this means the broker stopped writing (stopped, crashed, or not watching yet).
const STALE: Duration = Duration::from_secs(6);
static IN_FLIGHT: AtomicBool = AtomicBool::new(false);
/// The frame on screen, so an unchanged file isn't decoded again.
static SHOWN: Mutex<Option<(PathBuf, SystemTime)>> = Mutex::new(None);

fn folder() -> Option<PathBuf> {
    std::env::var_os("XDG_RUNTIME_DIR").map(|d| PathBuf::from(d).join("passbroker").join("preview"))
}

pub fn wire(app: &Shared, ui: &AppWindow) {
    wiz(ui).set_browser_window(app.state.lock().unwrap().settings.browser_window);
    wiz(ui).on_set_browser_window({
        let (a, w) = (app.clone(), ui.as_weak());
        move |on| {
            let Some(ui) = w.upgrade() else { return };
            if crate::svc_mode::running(&a) {
                wiz(&ui).set_browser_window(!on);
                toast(&ui, "Stop the broker before changing how its browser is shown.", true);
                return;
            }
            let mut st = a.state.lock().unwrap();
            st.settings.browser_window = on;
            st.save();
        }
    });
    wiz(ui).on_select_preview({
        let (a, w) = (app.clone(), ui.as_weak());
        move |key| {
            let Some(ui) = w.upgrade() else { return };
            wiz(&ui).set_preview_selected(key);
            *SHOWN.lock().unwrap() = None;
            tick(&a, &ui);
        }
    });
}

struct Tab {
    key: String,
    bot: String,
    withheld: bool,
    busy: bool,
    caption: String,
}

enum Picture {
    Keep,
    Clear,
    New(SharedPixelBuffer<Rgba8Pixel>),
}

/// Called every second; does nothing unless the Control center shows a running broker.
pub fn tick(app: &Shared, ui: &AppWindow) {
    let shown = wiz(ui).get_current() == CONTROL_CENTER && crate::svc_mode::running(app);
    let Some(dir) = folder().filter(|_| shown) else {
        if wiz(ui).get_preview_image().size().width != 0 || wiz(ui).get_preview_tabs().row_count() != 0 {
            apply(ui, Vec::new(), String::new(), Picture::Clear);
        }
        return;
    };
    if IN_FLIGHT.swap(true, Ordering::SeqCst) {
        return;
    }
    let selected = wiz(ui).get_preview_selected().to_string();
    let weak = ui.as_weak();
    std::thread::spawn(move || {
        let (tabs, selected, picture) = load(&dir, selected);
        let _ = weak.upgrade_in_event_loop(move |ui| {
            IN_FLIGHT.store(false, Ordering::SeqCst);
            apply(&ui, tabs, selected, picture);
        });
    });
}

fn load(dir: &Path, mut selected: String) -> (Vec<Tab>, String, Picture) {
    if !dir.is_dir() {
        return (Vec::new(), selected, Picture::Clear);
    }
    if let Ok(f) = OpenOptions::new().create(true).truncate(false).write(true).mode(0o600).open(dir.join("watching")) {
        let _ = f.set_modified(SystemTime::now());
    }
    let index: Value = std::fs::read(dir.join("sessions.json")).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default();
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs_f64();
    if now - index["updated"].as_f64().unwrap_or(0.0) > STALE.as_secs_f64() {
        return (Vec::new(), selected, Picture::Clear);
    }
    let text = |v: &Value| v.as_str().unwrap_or("").to_string();
    let entries = index["sessions"].as_array().cloned().unwrap_or_default();
    let tabs: Vec<Tab> = entries
        .iter()
        .map(|e| Tab {
            key: text(&e["key"]),
            bot: text(&e["bot"]),
            withheld: e["withheld"].as_bool().unwrap_or(false),
            busy: e["busy"].as_bool().unwrap_or(false),
            caption: [text(&e["title"]), text(&e["url"])].into_iter().filter(|s| !s.is_empty()).collect::<Vec<_>>().join("  ·  "),
        })
        .collect();
    if !tabs.iter().any(|t| t.key == selected) {
        selected = tabs.first().map(|t| t.key.clone()).unwrap_or_default();
    }
    let Some(i) = tabs.iter().position(|t| t.key == selected) else { return (tabs, selected, Picture::Clear) };
    if tabs[i].withheld {
        return (tabs, selected, Picture::Clear);
    }
    let path = dir.join(text(&entries[i]["file"]));
    let Some(mtime) = std::fs::metadata(&path).and_then(|m| m.modified()).ok() else { return (tabs, selected, Picture::Clear) };
    if SHOWN.lock().unwrap().as_ref() == Some(&(path.clone(), mtime)) {
        return (tabs, selected, Picture::Keep);
    }
    let picture = match std::fs::read(&path).ok().and_then(|b| image::load_from_memory_with_format(&b, image::ImageFormat::Jpeg).ok()) {
        Some(img) => {
            let rgba = img.to_rgba8();
            *SHOWN.lock().unwrap() = Some((path, mtime));
            Picture::New(SharedPixelBuffer::clone_from_slice(rgba.as_raw(), rgba.width(), rgba.height()))
        }
        None => Picture::Keep, // caught mid-replace; the next tick gets it
    };
    (tabs, selected, picture)
}

fn apply(ui: &AppWindow, tabs: Vec<Tab>, selected: String, picture: Picture) {
    let caption = match tabs.iter().find(|t| t.key == selected) {
        Some(t) if t.withheld => "Hidden: this page is showing a secret as text, so no picture of it is taken.".to_string(),
        Some(t) => t.caption.clone(),
        None => String::new(),
    };
    let rows: Vec<PreviewTab> = tabs
        .into_iter()
        .map(|t| PreviewTab { key: t.key.into(), bot: t.bot.into(), withheld: t.withheld, busy: t.busy })
        .collect();
    wiz(ui).set_preview_tabs(ModelRc::new(VecModel::from(rows)));
    wiz(ui).set_preview_selected(selected.into());
    wiz(ui).set_preview_caption(caption.into());
    match picture {
        Picture::Keep => {}
        Picture::Clear => {
            *SHOWN.lock().unwrap() = None;
            wiz(ui).set_preview_image(Image::default());
        }
        Picture::New(buf) => wiz(ui).set_preview_image(Image::from_rgba8(buf)),
    }
}
