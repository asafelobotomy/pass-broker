//! Step 5 tabs: encryption keys, home-device actions and email-code settings.

use crate::api::{args, s};
use crate::{bg, toast, wiz, AppWindow, DeviceRow, KeyRow, Shared};
use serde_json::{json, Value};
use slint::{ComponentHandle, ModelRc, VecModel};

const KINDS: [&str; 3] = ["wol", "ssh", "http"];
const AUTHS: [&str; 4] = ["none", "basic", "bearer", "body"];

pub fn wire_extras(app: &Shared, ui: &AppWindow) {
    wiz(ui).on_key_add({
        let (a, w) = (app.clone(), ui.as_weak());
        move || {
            let Some(ui) = w.upgrade() else { return };
            let g = wiz(&ui);
            let items = a.state.lock().unwrap().unlock_item_titles.clone();
            let Some(item) = items.get(g.get_k_item() as usize).cloned() else {
                toast(&ui, "Pick the vault item that holds the passphrase.", true);
                return;
            };
            let body = json!({"name": g.get_k_name().trim().to_lowercase(), "item": item, "note": g.get_k_note().trim()}).to_string();
            save(&a, &ui, "keys", body, |ui| wiz(ui).set_k_name("".into()));
        }
    });
    wiz(ui).on_device_add({
        let (a, w) = (app.clone(), ui.as_weak());
        move || {
            let Some(ui) = w.upgrade() else { return };
            let g = wiz(&ui);
            let items = a.state.lock().unwrap().unlock_item_titles.clone();
            // index 0 of the device item list is "(none)"
            let item = if g.get_d_item() > 0 { items.get(g.get_d_item() as usize - 1).cloned().unwrap_or_default() } else { String::new() };
            let kind = KINDS[g.get_d_kind().clamp(0, 2) as usize];
            let body = json!({
                "name": g.get_d_name().trim().to_lowercase(),
                "kind": kind,
                "description": g.get_d_description().trim(),
                "mac": g.get_d_mac().trim(),
                "host": if kind == "ssh" { g.get_d_host().trim().to_string() } else { String::new() },
                "user": g.get_d_user().trim(),
                "command": g.get_d_command().trim(),
                "url": g.get_d_url().trim(),
                "auth": AUTHS[g.get_d_auth().clamp(0, 3) as usize],
                "username": g.get_d_username().trim(),
                "body": g.get_d_body().trim(),
                "insecure_tls": g.get_d_insecure(),
                "plain_http_ok": g.get_d_plain_http(),
                "item": item,
                "return_output": g.get_d_return(),
            })
            .to_string();
            save(&a, &ui, "devices", body, |ui| wiz(ui).set_d_name("".into()));
        }
    });
    for kind in ["keys", "devices"] {
        let (a, w) = (app.clone(), ui.as_weak());
        let remove = move |name: slint::SharedString| {
            let Some(ui) = w.upgrade() else { return };
            let cmd = vec!["config-remove".to_string(), kind.to_string(), name.to_string()];
            bg(&a, &ui, "Removing…", move |app| app.cli.call(&cmd, None), |ui, app, r| {
                if let Err(e) = r {
                    toast(ui, e, true);
                }
                refresh(app, ui);
            });
        };
        if kind == "keys" { wiz(ui).on_key_remove(remove) } else { wiz(ui).on_device_remove(remove) }
    }
    let save_mail = |a: &Shared, ui: &AppWindow, repin: bool| {
            let g = wiz(ui);
            let items = a.state.lock().unwrap().unlock_item_titles.clone();
            let item = if g.get_mail_item() > 0 { items.get(g.get_mail_item() as usize - 1).cloned().unwrap_or_default() } else { String::new() };
            // repin: record Bridge's certificate afresh (after Bridge was reinstalled); otherwise the first one is kept.
            let body = json!({"item": item, "host": g.get_mail_host().trim(), "port": g.get_mail_port(), "max_age_minutes": g.get_mail_age(), "repin": repin}).to_string();
            bg(a, ui, "Saving (and recording Bridge's certificate)…", move |app| app.cli.call(&args(["mail-set"]), Some(&body)), |ui, app, r| {
                wiz(ui).set_extras_note(match r {
                    Ok(v) if !s(&v["pinned"]).is_empty() => format!("Saved. Bridge's certificate is pinned (SHA-256 {}).", s(&v["pinned"])).into(),
                    Ok(_) => "Email-code settings saved.".into(),
                    Err(e) => e.into(),
                });
                refresh(app, ui);
            });
    };
    wiz(ui).on_mail_save({
        let (a, w) = (app.clone(), ui.as_weak());
        move || { if let Some(ui) = w.upgrade() { save_mail(&a, &ui, false); } }
    });
    wiz(ui).on_mail_repin({
        let (a, w) = (app.clone(), ui.as_weak());
        move || { if let Some(ui) = w.upgrade() { save_mail(&a, &ui, true); } }
    });
}

fn save(app: &Shared, ui: &AppWindow, kind: &'static str, body: String, clear: fn(&AppWindow)) {
    bg(app, ui, "Saving…", move |app| app.cli.call(&["config-add".into(), kind.into()], Some(&body)), move |ui, app, r| {
        match r {
            Ok(v) => {
                clear(ui);
                let pinned = s(&v["pinned"]);
                let note = if pinned.is_empty() { "Added.".to_string() } else { format!("Added. The device's certificate is pinned (SHA-256 {pinned}).") };
                wiz(ui).set_extras_note(note.into());
            }
            Err(e) => wiz(ui).set_extras_note(e.into()),
        }
        refresh(app, ui);
    });
}

/// Keys, device actions and email settings, from `api config`.
pub fn refresh(app: &Shared, ui: &AppWindow) {
    bg(app, ui, "Loading…", |app| app.cli.call(&args(["config"]), None), |ui, app, r| {
        let Ok(v) = r else { return };
        let g = wiz(ui);
        let keys: Vec<KeyRow> = v["keys"].as_array().into_iter().flatten()
            .map(|k| KeyRow { name: s(&k["name"]).into(), item: s(&k["item"]).into(), note: s(&k["note"]).into() })
            .collect();
        g.set_keys(ModelRc::new(VecModel::from(keys)));
        let devices: Vec<DeviceRow> = v["devices"].as_array().into_iter().flatten().map(device_row).collect();
        g.set_devices(ModelRc::new(VecModel::from(devices)));
        let items = app.state.lock().unwrap().unlock_item_titles.clone();
        let mail_item = s(&v["mail"]["item"]);
        g.set_mail_item(items.iter().position(|t| *t == mail_item).map(|i| i as i32 + 1).unwrap_or(0));
        g.set_mail_host(s(&v["mail"]["host"]).into());
        g.set_mail_port(v["mail"]["port"].as_i64().unwrap_or(1143) as i32);
        g.set_mail_age(v["mail"]["max_age_minutes"].as_i64().unwrap_or(10) as i32);
    });
}

fn device_row(d: &Value) -> DeviceRow {
    let kind = s(&d["kind"]);
    let target = match kind.as_str() {
        "wol" => format!("wake {}", s(&d["mac"])),
        "ssh" => format!("{} on {}", s(&d["command"]), s(&d["host"])),
        _ => format!("{} {}", s(&d["method"]), s(&d["url"])),
    };
    DeviceRow {
        name: s(&d["name"]).into(),
        kind: kind.into(),
        target: target.into(),
        item: s(&d["item"]).into(),
        returns: d["return_output"].as_bool().unwrap_or(false),
    }
}
