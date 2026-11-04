//! Step 5: file-unlock actions (which vault item may open which folder's files, and how).

use crate::api::{args, s};
use crate::{bg, strings, toast, wiz, AppWindow, Shared, UnlockAction};
use slint::ComponentHandle;
use serde_json::{json, Value};
use slint::{ModelRc, VecModel};

pub fn wire_unlock(app: &Shared, ui: &AppWindow) {
    wiz(ui).on_unlock_refresh({
        let (a, w) = (app.clone(), ui.as_weak());
        move || {
            if let Some(ui) = w.upgrade() {
                refresh(&a, &ui);
            }
        }
    });
    wiz(ui).on_unlock_add({
        let (a, w) = (app.clone(), ui.as_weak());
        move || {
            let Some(ui) = w.upgrade() else { return };
            let g = wiz(&ui);
            let keys = a.state.lock().unwrap().unlock_preset_keys.clone();
            let items = a.state.lock().unwrap().unlock_item_titles.clone();
            let (Some(preset), Some(item)) = (keys.get(g.get_ua_preset() as usize), items.get(g.get_ua_item() as usize)) else {
                toast(&ui, "Pick a tool and a passphrase item first.", true);
                return;
            };
            let action = json!({
                "name": g.get_ua_name().trim().to_lowercase(),
                "preset": preset,
                "item": item,
                "folders": [g.get_ua_folder().trim()],
                "output_dir": g.get_ua_output().trim(),
                "return_output": g.get_ua_return(),
            })
            .to_string();
            bg(&a, &ui, "Saving action…", move |app| app.cli.call(&args(["unlocker-add"]), Some(&action)), |ui, app, r| {
                match r {
                    Ok(_) => {
                        wiz(ui).set_ua_name("".into());
                        wiz(ui).set_unlock_note("Added.".into());
                    }
                    Err(e) => wiz(ui).set_unlock_note(e.into()),
                }
                refresh(app, ui);
            });
        }
    });
    wiz(ui).on_unlock_remove({
        let (a, w) = (app.clone(), ui.as_weak());
        move |name| {
            let Some(ui) = w.upgrade() else { return };
            let name = name.to_string();
            bg(&a, &ui, "Removing action…", move |app| app.cli.call(&["unlocker-remove".into(), name], None), |ui, app, r| {
                if let Err(e) = r {
                    toast(ui, e, true);
                }
                refresh(app, ui);
            });
        }
    });
}

/// Load actions, installed tools, and the vault's item titles (items without a website first).
pub fn refresh(app: &Shared, ui: &AppWindow) {
    let vault = app.state.lock().unwrap().settings.vault.clone();
    bg(app, ui, "Loading unlock actions…", move |app| {
        let unl = app.cli.call(&args(["unlockers"]), None);
        let items = app.cli.call(&["check-vault".into(), "--vault".into(), vault], None);
        (unl, items)
    }, |ui, app, (unl, items)| {
        let g = wiz(ui);
        match unl {
            Ok(v) => {
                let presets: Vec<&Value> = v["presets"].as_array().into_iter().flatten().filter(|p| p["installed"] == true).collect();
                let labels: Vec<&Value> = v["presets"].as_array().into_iter().flatten().collect();
                let label_of = |key: &str| labels.iter().find(|p| p["key"] == key).map(|p| s(&p["label"])).unwrap_or(key.to_string());
                app.state.lock().unwrap().unlock_preset_keys = presets.iter().map(|p| s(&p["key"])).collect();
                g.set_unlock_preset_labels(strings(presets.iter().map(|p| s(&p["label"]))));
                g.set_unlock_preset_notes(strings(presets.iter().map(|p| s(&p["description"]))));
                let actions: Vec<UnlockAction> = v["actions"].as_array().into_iter().flatten().map(|a| UnlockAction {
                    name: s(&a["name"]).into(),
                    tool: label_of(&s(&a["preset"])).into(),
                    item: s(&a["item"]).into(),
                    folders: a["folders"].as_array().map(|f| f.iter().map(s).collect::<Vec<_>>().join(", ")).unwrap_or_default().into(),
                    output: s(&a["output_dir"]).into(),
                    returns: a["return_output"].as_bool().unwrap_or(false),
                }).collect();
                g.set_unlock_actions(ModelRc::new(VecModel::from(actions)));
            }
            Err(e) => toast(ui, format!("Couldn't load unlock actions: {e}"), true),
        }
        match items {
            Ok(v) => {
                let mut logins: Vec<(bool, String)> = v["logins"].as_array().into_iter().flatten()
                    .map(|l| (l["fillable"].as_bool().unwrap_or(false), s(&l["title"]))).collect();
                logins.sort_by_key(|(fillable, title)| (*fillable, title.to_lowercase()));
                app.state.lock().unwrap().unlock_item_titles = logins.iter().map(|(_, t)| t.clone()).collect();
                let labels: Vec<String> = logins.into_iter().map(|(fillable, t)| if fillable { format!("{t}  (has a website)") } else { t }).collect();
                g.set_device_items(strings(std::iter::once("(none)".to_string()).chain(labels.iter().cloned())));
                g.set_unlock_items(strings(labels.into_iter()));
            }
            Err(e) => g.set_unlock_note(format!("Couldn't read the vault: {e}").into()),
        }
        crate::extras_cb::refresh(app, ui);
    });
}
