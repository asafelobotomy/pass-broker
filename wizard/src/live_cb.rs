//! Callbacks for connected apps, bots, local assistants and the broker controls.

use crate::api::{args, s};
use crate::{bg, toast, wiz, AppWindow, Shared};
use slint::ComponentHandle;
use crate::broker_proc::{start_broker, stop_broker_blocking_app};
use crate::state::ASSISTANTS;
use crate::view::*;
use std::time::Duration;
use arboard::SetExtLinux;

const CLIPBOARD_CLEAR: Duration = Duration::from_secs(60);

pub fn wire_live(app: &Shared, ui: &AppWindow) {
    let a = app.clone();
    // assistants
    wiz(ui).on_revoke({
        let (a, w) = (a.clone(), ui.as_weak());
        move |id| {
            let Some(ui) = w.upgrade() else { return };
            let id = id.to_string();
            bg(&a, &ui, "Revoking…", move |app| app.cli.call(&["revoke".into(), id], None), |ui, app, r| {
                match r { Ok(_) => toast(ui, "Revoked. It stops working on its next request.", false), Err(e) => toast(ui, e, true) }
                poll_live(app, ui);
            });
        }
    });
    wiz(ui).on_toggle_bot({
        let (a, w) = (a.clone(), ui.as_weak());
        move |name, on| {
            let Some(ui) = w.upgrade() else { return };
            let mut cmd = vec!["bot-enable".to_string(), name.to_string()];
            if !on { cmd.push("--off".into()); }
            let label = if on { "Turning bot on…" } else { "Turning bot off…" };
            bg(&a, &ui, label, move |app| app.cli.call(&cmd, None), move |ui, app, r| {
                match r {
                    Ok(_) => toast(ui, if on { format!("{name} can use Pass Broker again.") } else { format!("{name} is switched off; its calls are refused from now on.") }, false),
                    Err(e) => toast(ui, e, true),
                }
                poll_live(app, ui);
            });
        }
    });
    wiz(ui).on_forget_bot({
        let (a, w) = (a.clone(), ui.as_weak());
        move |name| {
            let Some(ui) = w.upgrade() else { return };
            let n = name.to_string();
            bg(&a, &ui, "Forgetting bot…", move |app| app.cli.call(&["bot-forget".into(), n], None), |ui, app, r| {
                if let Err(e) = r { toast(ui, e, true); }
                poll_live(app, ui);
            });
        }
    });
    wiz(ui).on_add_client({
        let (a, w) = (a.clone(), ui.as_weak());
        move |name| {
            let Some(ui) = w.upgrade() else { return };
            let name = name.trim().to_string();
            bg(&a, &ui, "Creating token…", move |app| app.cli.call(&["add-client".into(), name], None), |ui, app, r| {
                match r {
                    Ok(v) => { wiz(ui).set_new_token_name(s(&v["name"]).into()); wiz(ui).set_copy_note("".into()); wiz(ui).set_new_token(s(&v["token"]).into()); }
                    Err(e) => toast(ui, e, true),
                }
                poll_live(app, ui);
            });
        }
    });
    wiz(ui).on_remove_client({
        let (a, w) = (a.clone(), ui.as_weak());
        move |name| {
            let Some(ui) = w.upgrade() else { return };
            let name = name.to_string();
            bg(&a, &ui, "Removing…", move |app| app.cli.call(&["remove-client".into(), name], None), |ui, app, r| {
                if let Err(e) = r { toast(ui, e, true); }
                poll_live(app, ui);
            });
        }
    });
    wiz(ui).on_close_token({ let w = ui.as_weak(); move || { if let Some(ui) = w.upgrade() { wiz(&ui).set_new_token("".into()); wiz(&ui).set_copy_note("".into()); } } });
    wiz(ui).on_copy({
        let (a, w) = (a.clone(), ui.as_weak());
        move |text, sensitive| {
            let Some(ui) = w.upgrade() else { return };
            copy_text(&a, &ui, text.to_string(), sensitive);
        }
    });

    // broker
    wiz(ui).on_start_broker({ let (a, w) = (a.clone(), ui.as_weak()); move || { if let Some(ui) = w.upgrade() { start_broker(&a, &ui); } } });
    wiz(ui).on_stop_broker({
        let (a, w) = (a.clone(), ui.as_weak());
        move || {
            let Some(ui) = w.upgrade() else { return };
            if a.state.lock().unwrap().settings.service_mode {
                crate::svc_mode::stop(&a, &ui);
                return;
            }
            wiz(&ui).set_broker_state("stopping".into());
            bg(&a, &ui, "Stopping…", stop_broker_blocking_app, |ui, app, _| { wiz(ui).set_broker_state("stopped".into()); render_steps(app, ui); });
        }
    });
    wiz(ui).on_emergency_stop({
        let (a, w) = (a.clone(), ui.as_weak());
        move || {
            let Some(ui) = w.upgrade() else { return };
            wiz(&ui).set_broker_state("stopping".into());
            bg(&a, &ui, "Emergency stop…", |app| {
                let revoked = app.cli.call(&args(["revoke-all"]), None);
                stop_broker_blocking_app(app);
                let cleared = app.cli.call(&args(["clear-browser"]), None);
                (revoked, cleared)
            }, |ui, app, (revoked, cleared)| {
                wiz(ui).set_broker_state("stopped".into());
                let n = revoked.as_ref().map(|v| s(&v["revoked"])).unwrap_or_default();
                match (revoked, cleared) {
                    (Ok(_), Ok(_)) => toast(ui, format!("Stopped. Revoked {n} connected app(s) and signed the browser out of everything."), false),
                    (r, c) => toast(ui, format!("Stopped, but: {}{}", r.err().unwrap_or_default(), c.err().map(|e| format!(" {e}")).unwrap_or_default()), true),
                }
                {
                    let mut st = app.state.lock().unwrap();
                    st.invalidate(ASSISTANTS);
                    st.save();
                }
                poll_live(app, ui);
                render_steps(app, ui);
            });
        }
    });
    wiz(ui).on_probe({
        let (a, w) = (a.clone(), ui.as_weak());
        move || {
            let Some(ui) = w.upgrade() else { return };
            let host = wiz(&ui).get_broker_url().trim_start_matches("https://").split('/').next().unwrap_or("").to_string();
            bg(&a, &ui, "Testing from the internet…", move |app| app.cli.call(&["probe".into(), host], None), |ui, _, r| {
                wiz(ui).set_probe_result(match r { Ok(v) => s(&v["detail"]), Err(e) => e }.into());
            });
        }
    });
    let _ = a;
}


pub fn copy_text(app: &Shared, ui: &AppWindow, text: String, sensitive: bool) {
    let mut guard = app.clipboard.lock().unwrap();
    let Some(cb) = guard.as_mut() else {
        toast(ui, "No clipboard available; select the text and press Ctrl+C.", true);
        return;
    };
    // Secrets are marked so clipboard managers (KDE's Klipper and others that honour
    // x-kde-passwordManagerHint) leave them out of their saved history.
    let set = if sensitive { cb.set().exclude_from_history().text(text.clone()) } else { cb.set_text(text.clone()) };
    if set.is_err() {
        toast(ui, "Couldn't copy; select the text and press Ctrl+C.", true);
        return;
    }
    drop(guard);
    if sensitive {
        wiz(ui).set_copy_note(format!("Copied. The clipboard clears itself in {} seconds.", CLIPBOARD_CLEAR.as_secs()).into());
        let app = app.clone();
        std::thread::spawn(move || {
            std::thread::sleep(CLIPBOARD_CLEAR);
            if let Some(cb) = app.clipboard.lock().unwrap().as_mut()
                && cb.get_text().map(|t| t == text).unwrap_or(false) {
                    let _ = cb.clear();
                }
        });
    } else {
        toast(ui, "Copied.", false);
    }
}

