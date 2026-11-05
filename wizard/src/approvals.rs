//! Allow / Deny inside the app, alongside the desktop notification.
//!
//! The broker writes each waiting approval to `$XDG_RUNTIME_DIR/passbroker/approvals/<id>.json`
//! (see approvals.py) and also shows a notification. This shows the oldest one as a dialog and
//! answers by writing `<id>.answer`; whichever answer arrives first counts. A request that
//! disappears was answered in the notification or timed out, so the dialog closes.

use crate::{wiz, AppWindow};
use serde_json::Value;
use slint::ComponentHandle;
use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

/// Requests answered here, so one isn't shown again in the moment before the broker removes it.
static ANSWERED: Mutex<Vec<String>> = Mutex::new(Vec::new());

struct Pending {
    id: String,
    title: String,
    body: String,
    expires: f64,
}

fn folder() -> Option<PathBuf> {
    std::env::var_os("XDG_RUNTIME_DIR").map(|d| PathBuf::from(d).join("passbroker").join("approvals"))
}

fn now() -> f64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs_f64()
}

/// Requests still waiting, oldest first.
fn pending() -> Vec<Pending> {
    let Some(dir) = folder() else { return Vec::new() };
    let Ok(entries) = fs::read_dir(&dir) else { return Vec::new() };
    let mut out: Vec<Pending> = entries
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().ends_with(".json"))
        .filter_map(|e| serde_json::from_slice::<Value>(&fs::read(e.path()).ok()?).ok())
        .filter_map(|v| {
            let text = |k: &str| v[k].as_str().unwrap_or("").to_string();
            let id = text("id");
            let ok = !id.is_empty() && id.chars().all(|c| c.is_ascii_hexdigit());
            ok.then(|| Pending { id, title: text("title"), body: text("body"), expires: v["expires"].as_f64().unwrap_or(0.0) })
        })
        .filter(|p| p.expires > now())
        .collect();
    let mut answered = ANSWERED.lock().unwrap();
    answered.retain(|id| out.iter().any(|p| &p.id == id));
    out.retain(|p| !answered.contains(&p.id));
    out.sort_by(|a, b| a.expires.total_cmp(&b.expires));
    out
}

/// Called twice a second: show the oldest waiting request, or close the dialog.
pub fn tick(ui: &AppWindow) {
    let waiting = pending();
    let g = wiz(ui);
    match waiting.first() {
        Some(p) => {
            if g.get_approval_id() != p.id.as_str() {
                g.set_approval_id(p.id.clone().into());
                g.set_approval_title(p.title.clone().into());
                g.set_approval_body(p.body.clone().into());
            }
            g.set_approval_seconds((p.expires - now()).max(0.0).round() as i32);
            g.set_approval_queue(waiting.len() as i32);
        }
        None => g.set_approval_id("".into()),
    }
}

fn answer(id: &str, allow: bool) -> std::io::Result<()> {
    let dir = folder().ok_or_else(|| std::io::Error::other("no runtime folder"))?;
    let tmp = dir.join(format!("{id}.answer.tmp"));
    let mut f = fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp)?;
    f.write_all(if allow { b"allow" } else { b"deny" })?;
    fs::rename(&tmp, dir.join(format!("{id}.answer")))
}

pub fn wire(ui: &AppWindow) {
    wiz(ui).on_approval_answer({
        let w = ui.as_weak();
        move |allow| {
            let Some(ui) = w.upgrade() else { return };
            let id = wiz(&ui).get_approval_id().to_string();
            if id.is_empty() {
                return;
            }
            ANSWERED.lock().unwrap().push(id.clone());
            if let Err(e) = answer(&id, allow) {
                crate::toast(&ui, format!("Couldn't send your answer ({e}); use the notification instead."), true);
            }
            wiz(&ui).set_approval_id("".into());
        }
    });
}
