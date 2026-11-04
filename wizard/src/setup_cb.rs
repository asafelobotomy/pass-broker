//! Callbacks for steps 1-4: navigation, locking, requirements, token, vault.

use crate::api::{args, s};
use crate::{bg, open_url, toast, wiz, App, AppWindow, Shared};
use crate::LoginRow;
use slint::{ComponentHandle, ModelRc, VecModel};
use std::sync::atomic::Ordering;
use crate::state::{ACCESS, ASSISTANTS, REQUIREMENTS, STEPS, TOKEN, UNLOCK, VAULT};
use crate::view::*;
use crate::{CONTROL_CENTER, EXPIRATIONS, TITLES};

pub fn wire_setup(app: &Shared, ui: &AppWindow) {
    let a = app.clone();
    wiz(ui).on_dismiss_toast({
        let w = ui.as_weak();
        move || { if let Some(ui) = w.upgrade() { wiz(&ui).set_toast("".into()); } }
    });

    wiz(ui).on_go({
        let (a, w) = (a.clone(), ui.as_weak());
        move |i| {
            let Some(ui) = w.upgrade() else { return };
            let st = a.state.lock().unwrap();
            let ok = if i == CONTROL_CENTER { st.setup_done() } else { st.reachable(i as usize) };
            drop(st);
            if ok {
                wiz(&ui).set_current(i);
                if i == 3 { refresh_status(&a, &ui); }
                if i == UNLOCK as i32 { crate::unlock_cb::refresh(&a, &ui); }
                if i >= ASSISTANTS as i32 { poll_live(&a, &ui); }
            }
        }
    });

    wiz(ui).on_complete_step({
        let (a, w) = (a.clone(), ui.as_weak());
        move |i| {
            let Some(ui) = w.upgrade() else { return };
            complete_step(&a, &ui, i as usize);
        }
    });

    wiz(ui).on_unlock_step({
        let (a, w) = (a.clone(), ui.as_weak());
        move |i| {
            let Some(ui) = w.upgrade() else { return };
            if a.broker.lock().unwrap().is_some() {
                toast(&ui, "Stop the broker before changing setup.", true);
                return;
            }
            a.state.lock().unwrap().unlock(i as usize);
            a.state.lock().unwrap().save();
            render_steps(&a, &ui);
        }
    });

    wiz(ui).on_recheck({ let (a, w) = (a.clone(), ui.as_weak()); move || { if let Some(ui) = w.upgrade() { refresh_status(&a, &ui); } } });
    wiz(ui).on_refresh_tailscale({ let (a, w) = (a.clone(), ui.as_weak()); move || { if let Some(ui) = w.upgrade() { refresh_status(&a, &ui); } } });

    wiz(ui).on_fix({
        let (a, w) = (a.clone(), ui.as_weak());
        move |what| {
            let Some(ui) = w.upgrade() else { return };
            if what == "browser" {
                bg(&a, &ui, "Installing Chromium…", |app| app.cli.stream(&args(["install-browser"]), |_| {}), |ui, app, r| {
                    match r { Ok(_) => toast(ui, "Browser installed.", false), Err(e) => toast(ui, format!("Install failed: {e}"), true) }
                    refresh_status(app, ui);
                });
            }
        }
    });

    // token
    wiz(ui).on_open_url(|u| open_url(&u));
    wiz(ui).on_sign_in({
        let (a, w) = (a.clone(), ui.as_weak());
        move || {
            let Some(ui) = w.upgrade() else { return };
            wiz(&ui).set_login_state("Starting sign-in…".into());
            let weak = ui.as_weak();
            bg(&a, &ui, "Waiting for you to sign in to Proton…", move |app| {
                app.cli.stream(&args(["login", "--sign-out-agent"]), |ev| {
                    if ev["event"] == "url" {
                        let url = s(&ev["url"]);
                        open_url(&url);
                        let _ = weak.upgrade_in_event_loop(move |ui| {
                            wiz(&ui).set_login_url(url.into());
                            wiz(&ui).set_login_state("Finish signing in in your browser.".into());
                        });
                    }
                })
            }, |ui, app, r| {
                wiz(ui).set_login_url("".into());
                match r {
                    Ok(_) => wiz(ui).set_login_state("Signed in as yourself. Now create the token.".into()),
                    Err(e) => wiz(ui).set_login_state(e.into()),
                }
                refresh_status(app, ui);
            });
        }
    });

    wiz(ui).on_create_token({
        let (a, w) = (a.clone(), ui.as_weak());
        move || {
            let Some(ui) = w.upgrade() else { return };
            save_settings_from_ui(&a, &ui);
            let (name, exp, vault) = {
                let st = a.state.lock().unwrap();
                (st.settings.token_name.clone(), EXPIRATIONS[st.settings.token_expiry.clamp(0, 5) as usize].to_string(), st.settings.vault.clone())
            };
            bg(&a, &ui, "Creating the agent token…", move |app| {
                app.cli.call(&["create-token".into(), "--name".into(), name, "--expiration".into(), exp, "--vault".into(), vault], None)
            }, |ui, app, r| {
                match r {
                    Ok(v) => { token_changed(app); toast(ui, format!("Agent token created and saved to your keyring ({}). pass-cli was signed out of your account.", s(&v["keyring"])), false); }
                    Err(e) => toast(ui, e, true),
                }
                refresh_status(app, ui);
            });
        }
    });

    wiz(ui).on_save_pasted({
        let (a, w) = (a.clone(), ui.as_weak());
        move |token| {
            let Some(ui) = w.upgrade() else { return };
            let token = token.to_string();
            bg(&a, &ui, "Saving to keyring…", move |app| app.cli.call(&args(["store-token"]), Some(&token)), |ui, app, r| {
                match r {
                    Ok(v) => { token_changed(app); toast(ui, format!("Token saved to your keyring ({}).", s(&v["keyring"])), false); }
                    Err(e) => toast(ui, e, true),
                }
                refresh_status(app, ui);
            });
        }
    });

    wiz(ui).on_remove_token({
        let (a, w) = (a.clone(), ui.as_weak());
        move || {
            let Some(ui) = w.upgrade() else { return };
            bg(&a, &ui, "Removing token…", |app| app.cli.call(&args(["delete-token"]), None), |ui, app, r| {
                match r {
                    Ok(_) => {
                        let mut st = app.state.lock().unwrap();
                        st.invalidate(TOKEN);
                        st.invalidate(VAULT);
                        st.save();
                        drop(st);
                        toast(ui, "Token removed from your keyring.", false);
                    }
                    Err(e) => toast(ui, e, true),
                }
                refresh_status(app, ui);
            });
        }
    });

    // vault
    wiz(ui).on_check_vault({
        let (a, w) = (a.clone(), ui.as_weak());
        move || {
            let Some(ui) = w.upgrade() else { return };
            save_settings_from_ui(&a, &ui);
            let vault = a.state.lock().unwrap().settings.vault.clone();
            let v2 = vault.clone();
            bg(&a, &ui, "Reading the vault (no passwords)…", move |app| app.cli.call(&["check-vault".into(), "--vault".into(), v2], None), move |ui, app, r| {
                match r {
                    Ok(v) => {
                        let rows: Vec<LoginRow> = v["logins"].as_array().into_iter().flatten().map(|l| LoginRow {
                            title: s(&l["title"]).into(),
                            sites: l["urls"].as_array().map(|u| u.iter().map(s).collect::<Vec<_>>().join(", ")).filter(|x| !x.is_empty()).unwrap_or("—".into()).into(),
                            user: { let u = s(&l["username"]); if u.is_empty() { "—".into() } else { u.into() } },
                            totp: match l["has_totp"].as_bool() { Some(true) => "yes".into(), Some(false) => "".into(), None => "?".into() },
                            fillable: l["fillable"].as_bool().unwrap_or(false),
                        }).collect();
                        let fillable = rows.iter().filter(|r| r.fillable).count();
                        let summary = format!("{} logins in “{}”, {} can be filled.", rows.len(), vault, fillable);
                        let mut st = app.state.lock().unwrap();
                        st.vault_ok = fillable > 0;
                        st.vault_summary = summary.clone();
                        st.save();
                        drop(st);
                        wiz(ui).set_vault_ok(fillable > 0);
                        wiz(ui).set_vault_summary(summary.into());
                        wiz(ui).set_logins(ModelRc::new(VecModel::from(rows)));
                    }
                    Err(e) => { wiz(ui).set_vault_ok(false); wiz(ui).set_vault_summary(format!("Couldn't read the vault: {e}").into()); }
                }
            });
        }
    });

}

pub fn token_changed(app: &App) {
    let mut st = app.state.lock().unwrap();
    st.invalidate(VAULT);
    st.vault_ok = false;
    st.vault_summary.clear();
    st.save();
}

pub fn complete_step(app: &Shared, ui: &AppWindow, i: usize) {
    save_settings_from_ui(app, ui);
    let ts_host = app.ts_host.lock().unwrap().clone();
    let mut st = app.state.lock().unwrap();
    let ok = match i {
        REQUIREMENTS => app.requirements_ok.load(Ordering::SeqCst),
        TOKEN => app.token_stored.load(Ordering::SeqCst),
        VAULT => st.vault_ok,
        ACCESS => wiz(ui).get_access_ok(),
        UNLOCK => true,
        ASSISTANTS => app.has_assistant.load(Ordering::SeqCst),
        _ => false,
    };
    if !ok {
        drop(st);
        toast(ui, "This step isn't complete yet.", true);
        return;
    }
    let mut note = String::new();
    if i == ACCESS {
        let address = st.address(&ts_host);
        if !st.locked_address.is_empty() && st.locked_address != address && st.steps[ASSISTANTS].completed {
            st.invalidate(ASSISTANTS);
            note = " The address changed, so connected apps must connect again (step 5).".into();
        }
        st.locked_address = address;
    }
    st.lock(i);
    st.save();
    drop(st);
    render_steps(app, ui);
    toast(ui, format!("“{}” is locked.{note}", TITLES[i]), false);
    wiz(ui).set_current(if i + 1 < STEPS { (i + 1) as i32 } else { CONTROL_CENTER });
    if i + 1 == UNLOCK { crate::unlock_cb::refresh(app, ui); }
    if i + 1 >= ASSISTANTS { poll_live(app, ui); }
}

