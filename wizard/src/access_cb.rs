//! The per-bot Access… dialog, and opening the pairing window for a new app.

use crate::api::{args, s};
use crate::{bg, toast, wiz, AccessItem, AppWindow, Shared};
use serde_json::{json, Value};
use slint::{ComponentHandle, Model, ModelRc, VecModel};

pub fn wire_access(app: &Shared, ui: &AppWindow) {
    wiz(ui).on_open_access({
        let (a, w) = (app.clone(), ui.as_weak());
        move |bot| {
            let Some(ui) = w.upgrade() else { return };
            let bot = bot.to_string();
            let vault = a.state.lock().unwrap().settings.vault.clone();
            bg(&a, &ui, "Loading what can be granted…", move |app| {
                let bots = app.cli.call(&args(["bots"]), None);
                let unl = app.cli.call(&args(["unlockers"]), None);
                let cfg = app.cli.call(&args(["config"]), None);
                let vlt = app.cli.call(&["check-vault".into(), "--vault".into(), vault], None);
                (bot, bots, unl, cfg, vlt)
            }, |ui, _app, (bot, bots, unl, cfg, vlt)| {
                let (Ok(bots), Ok(unl), Ok(cfg), Ok(vlt)) = (bots, unl, cfg, vlt) else {
                    toast(ui, "Couldn't load the vault or settings; try again.", true);
                    return;
                };
                let current = bots["bots"].as_array().into_iter().flatten().find(|b| s(&b["name"]) == bot).map(|b| b["access"].clone()).unwrap_or(Value::Null);
                let has = |kind: &str, name: &str| current[kind].as_array().map(|l| l.iter().any(|x| s(x) == name)).unwrap_or(false);
                let mut items = Vec::new();
                let mut push = |kind: &str, label: &str, name: String| {
                    items.push(AccessItem { on: has(kind, &name), kind: kind.into(), label: format!("{label}: {name}").into(), name: name.into() });
                };
                for l in vlt["logins"].as_array().into_iter().flatten().filter(|l| l["fillable"] == true) {
                    push("logins", "Login", s(&l["title"]));
                }
                for x in unl["actions"].as_array().into_iter().flatten() {
                    push("unlock", "Unlock files", s(&x["name"]));
                }
                for x in cfg["keys"].as_array().into_iter().flatten() {
                    push("keys", "Key", s(&x["name"]));
                }
                for x in cfg["devices"].as_array().into_iter().flatten() {
                    push("devices", "Device action", s(&x["name"]));
                }
                let g = wiz(ui);
                g.set_access_email(current["email_codes"].as_bool().unwrap_or(false));
                g.set_access_items(ModelRc::new(VecModel::from(items)));
                g.set_access_bot(bot.into());
            });
        }
    });
    wiz(ui).on_access_toggle({
        let w = ui.as_weak();
        move |i, on| {
            let Some(ui) = w.upgrade() else { return };
            let model = wiz(&ui).get_access_items();
            if let Some(mut row) = model.row_data(i as usize) {
                row.on = on;
                model.set_row_data(i as usize, row);
            }
        }
    });
    wiz(ui).on_close_access({
        let w = ui.as_weak();
        move || {
            if let Some(ui) = w.upgrade() {
                wiz(&ui).set_access_bot("".into());
            }
        }
    });
    wiz(ui).on_save_access({
        let (a, w) = (app.clone(), ui.as_weak());
        move || {
            let Some(ui) = w.upgrade() else { return };
            let g = wiz(&ui);
            let bot = g.get_access_bot().to_string();
            let mut access = json!({"logins": [], "unlock": [], "keys": [], "devices": [], "email_codes": g.get_access_email()});
            for row in g.get_access_items().iter().filter(|r| r.on) {
                if let Some(list) = access[row.kind.as_str()].as_array_mut() {
                    list.push(json!(row.name.as_str()));
                }
            }
            let body = access.to_string();
            let cmd = vec!["bot-access".to_string(), bot.clone()];
            bg(&a, &ui, "Saving access…", move |app| app.cli.call(&cmd, Some(&body)), move |ui, app, r| {
                match r {
                    Ok(_) => {
                        wiz(ui).set_access_bot("".into());
                        toast(ui, format!("Saved what {bot} can use."), false);
                    }
                    Err(e) => toast(ui, e, true),
                }
                crate::view::poll_live(app, ui);
            });
        }
    });
    wiz(ui).on_open_pairing({
        let (a, w) = (app.clone(), ui.as_weak());
        move || {
            let Some(ui) = w.upgrade() else { return };
            bg(&a, &ui, "Opening the pairing window…", |app| app.cli.call(&args(["pair"]), None), |ui, _, r| {
                let note = match r {
                    Ok(_) => format!("Pairing is open until {}. Ask Grok to connect now; one app can connect, then it closes.", in_minutes(10)),
                    Err(e) => e,
                };
                wiz(ui).set_pairing_note(note.into());
            });
        }
    });
}

fn in_minutes(m: i64) -> String {
    let now = crate::state::now();
    let (date, time) = now.split_once(' ').unwrap_or(("", "00:00"));
    let (h, mi) = time.split_once(':').unwrap_or(("0", "0"));
    let total = h.parse::<i64>().unwrap_or(0) * 60 + mi.parse::<i64>().unwrap_or(0) + m;
    let _ = date;
    format!("{:02}:{:02}", (total / 60) % 24, total % 60)
}
