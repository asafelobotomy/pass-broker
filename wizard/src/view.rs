//! Turning broker answers into what the wizard shows.

use crate::api::{args, s};
use crate::{bg, strings, toast, wiz, App, AppWindow, Shared};
use crate::{AuditRow, BotRow, CheckRow, ConnRow, StepItem};
use serde_json::Value;
use slint::{ComponentHandle, ModelRc, VecModel};
use std::sync::atomic::Ordering;
use crate::state::STEPS;
use crate::TITLES;

pub fn render_steps(app: &App, ui: &AppWindow) {
    let st = app.state.lock().unwrap();
    let items: Vec<StepItem> = (0..STEPS)
        .map(|i| {
            let ui_state = st.ui_state(i);
            let subtitle = match ui_state {
                2 => format!("Locked · {}", st.steps[i].at),
                3 => "Unlocked for editing".to_string(),
                1 => "To do".to_string(),
                _ => format!("Finish step {} first", i),
            };
            StepItem { title: TITLES[i].into(), subtitle: subtitle.into(), state: ui_state }
        })
        .collect();
    wiz(ui).set_steps(ModelRc::new(VecModel::from(items)));
    wiz(ui).set_setup_done(st.setup_done());
    wiz(ui).set_mcp_url(st.address(&app.ts_host.lock().unwrap()).into());
    let access_ok = match wiz(ui).get_tunnel_mode() {
        0 => app.ts_ready.load(Ordering::SeqCst),
        1 => !wiz(ui).get_own_host().trim().is_empty(),
        _ => true,
    };
    wiz(ui).set_access_ok(access_ok);
    wiz(ui).set_requirements_ok(app.requirements_ok.load(Ordering::SeqCst));
    wiz(ui).set_token_stored(app.token_stored.load(Ordering::SeqCst));
    wiz(ui).set_assistants_ok(app.has_assistant.load(Ordering::SeqCst));
}

pub fn load_settings_into_ui(app: &App, ui: &AppWindow) {
    let st = app.state.lock().unwrap();
    let s = &st.settings;
    wiz(ui).set_vault_name(s.vault.clone().into());
    wiz(ui).set_token_name(s.token_name.clone().into());
    wiz(ui).set_token_expiry(s.token_expiry);
    wiz(ui).set_tunnel_mode(s.tunnel_mode);
    wiz(ui).set_own_host(s.own_host.clone().into());
    wiz(ui).set_port(s.port);
    wiz(ui).set_grant_minutes(s.grant_minutes);
    wiz(ui).set_clear_sessions(s.clear_sessions);
    wiz(ui).set_idle_minutes(s.idle_minutes);
}

pub fn save_settings_from_ui(app: &App, ui: &AppWindow) {
    let mut st = app.state.lock().unwrap();
    let s = &mut st.settings;
    s.vault = wiz(ui).get_vault_name().trim().to_string();
    s.token_name = wiz(ui).get_token_name().trim().to_string();
    s.token_expiry = wiz(ui).get_token_expiry();
    s.tunnel_mode = wiz(ui).get_tunnel_mode();
    s.own_host = wiz(ui).get_own_host().trim().trim_start_matches("https://").trim_end_matches('/').to_string();
    s.port = wiz(ui).get_port();
    s.grant_minutes = wiz(ui).get_grant_minutes();
    s.clear_sessions = wiz(ui).get_clear_sessions();
    s.idle_minutes = wiz(ui).get_idle_minutes();
    st.save();
}

pub fn apply_connections(app: &App, ui: &AppWindow, v: &Value) {
    let conns: Vec<ConnRow> = v["connections"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|c| ConnRow {
            id: s(&c["id"]).into(),
            name: s(&c["name"]).into(),
            app: s(&c["app"]).into(),
            created: s(&c["created"]).into(),
            last_used: if c["last_used"].is_null() { "never".into() } else { s(&c["last_used"]).into() },
            active: c["active"].as_bool().unwrap_or(false),
        })
        .collect();
    let clients: Vec<String> = v["clients"].as_array().into_iter().flatten().map(s).collect();
    if let Some(list) = v["bots"].as_array() {
        let bots: Vec<BotRow> = list
            .iter()
            .map(|b| BotRow {
                name: s(&b["name"]).into(),
                enabled: b["enabled"].as_bool().unwrap_or(true),
                first_seen: s(&b["first_seen"]).into(),
                last_seen: s(&b["last_seen"]).into(),
                last_action: s(&b["last_action"]).into(),
                via: b["connections"].as_array().map(|c| c.iter().map(s).collect::<Vec<_>>().join(", ")).unwrap_or_default().into(),
            })
            .collect();
        wiz(ui).set_bots(ModelRc::new(VecModel::from(bots)));
    }
    app.has_assistant.store(conns.iter().any(|c| c.active) || !clients.is_empty(), Ordering::SeqCst);
    wiz(ui).set_connections(ModelRc::new(VecModel::from(conns)));
    wiz(ui).set_clients(strings(clients.into_iter()));
}

pub fn refresh_status(app: &Shared, ui: &AppWindow) {
    bg(app, ui, "Checking this PC…", |app| app.cli.call(&args(["status"]), None), |ui, app, r| match r {
        Ok(v) => {
            let checks: Vec<CheckRow> = v["checks"]
                .as_array()
                .into_iter()
                .flatten()
                .map(|c| CheckRow {
                    label: s(&c["label"]).into(),
                    detail: s(&c["detail"]).into(),
                    ok: c["ok"].as_bool().unwrap_or(false),
                    required: c["required"].as_bool().unwrap_or(true),
                    fix: if s(&c["key"]) == "browser" { "browser".into() } else { "".into() },
                })
                .filter(|c| !matches!(c.label.as_str(), "Proton Pass token saved" | "Assistant connected"))
                .collect();
            app.requirements_ok.store(checks.iter().all(|c| c.ok || !c.required), Ordering::SeqCst);
            app.token_stored.store(v["token_stored"].as_bool().unwrap_or(false), Ordering::SeqCst);
            app.ts_ready.store(v["tailscale"]["running"].as_bool().unwrap_or(false), Ordering::SeqCst);
            *app.ts_host.lock().unwrap() = s(&v["tailscale"]["host"]);
            wiz(ui).set_checks(ModelRc::new(VecModel::from(checks)));
            wiz(ui).set_keyring(s(&v["keyring"]).into());
            let label = s(&v["session"]["label"]);
            wiz(ui).set_session_label(if s(&v["session"]["kind"]) == "none" { "".into() } else { label.into() });
            wiz(ui).set_ts_ready(app.ts_ready.load(Ordering::SeqCst));
            wiz(ui).set_ts_detail(s(&v["tailscale"]["detail"]).into());
            apply_connections(app, ui, &v);
            render_steps(app, ui);
        }
        Err(e) => toast(ui, format!("Couldn't check status: {e}"), true),
    });
}

/// Connections, bots and the audit log, off the UI thread. One at a time: the timer and the
/// page callbacks both ask, and a second request while one runs is dropped.
pub fn poll_live(app: &Shared, ui: &AppWindow) {
    if app.polling.swap(true, Ordering::SeqCst) {
        return;
    }
    let (app, weak) = (app.clone(), ui.as_weak());
    std::thread::spawn(move || {
        let conns = app.cli.call(&args(["connections"]), None);
        let audit = app.cli.call(&args(["audit", "--limit", "150"]), None);
        let app2 = app.clone();
        let _ = weak.upgrade_in_event_loop(move |ui| {
            app2.polling.store(false, Ordering::SeqCst);
            if let Ok(v) = conns {
                apply_connections(&app2, &ui, &v);
                render_steps(&app2, &ui);
            }
            if let Ok(v) = audit {
                let rows: Vec<AuditRow> = v["entries"].as_array().into_iter().flatten().rev().map(audit_row).collect();
                wiz(&ui).set_audit(ModelRc::new(VecModel::from(rows)));
            }
        });
    });
}

pub fn audit_row(e: &Value) -> AuditRow {
    let event = s(&e["event"]);
    let result = match event.as_str() {
        "approval" => if e["allowed"].as_bool() == Some(true) { "allowed" } else { "denied" }.to_string(),
        "refused_origin" => "refused".into(),
        "oauth_bad_code" => "wrong code".into(),
        "oauth_denied" => "denied".into(),
        "bot_refused" => "refused".into(),
        "bot_new" => "new bot".into(),
        "fill_login" => s(&e["step"]),
        "create_login" => "account made".into(),
        "fill_signup" => "signed up".into(),
        "email_alias" => "email address made".into(),
        "mail_rule_asked" => format!("asked {}", s(&e["item"])),
        "mail_rule_done" => "bot-mail rule set up".into(),
        "mail_admin_granted" => "now mail admin".into(),
        "mail_send" => format!("to {}", s(&e["item"])),
        "mail_move" | "mail_flag" | "mail_label" => format!("{} message(s)", s(&e["count"])),
        "list_logins" => format!("{} logins", s(&e["count"])),
        _ => String::new(),
    };
    let ts = s(&e["ts"]).replace('T', " ");
    AuditRow {
        ts: ts.get(..16).unwrap_or(&ts).into(),
        who: {
            let c = s(&e["client"]);
            let b = s(&e["bot"]);
            let base = if c.is_empty() { s(&e["name"]) } else { c };
            if b.is_empty() { base } else { format!("{b} · {base}") }
        }.into(),
        event: event.replace('_', " ").into(),
        item: s(&e["item"]).into(),
        host: { let h = s(&e["host"]); if h.is_empty() { s(&e["app"]) } else { h } }.into(),
        result: result.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::audit_row;
    use serde_json::json;

    #[test]
    fn audit_rows_read_the_log_fields() {
        let row = audit_row(&json!({"ts": "2026-11-05T14:12:35.123+00:00", "event": "approval", "client": "grok/mailbot",
                                    "item": "Shop", "host": "shop.example", "allowed": true}));
        assert_eq!(row.ts, "2026-11-05 14:12");
        assert_eq!((row.who.as_str(), row.event.as_str(), row.result.as_str()), ("grok/mailbot", "approval", "allowed"));
        assert_eq!(audit_row(&json!({"event": "approval", "allowed": false})).result, "denied");
        let made = audit_row(&json!({"event": "create_login", "client": "grok/maker", "item": "shop.example (maker)"}));
        assert_eq!((made.event.as_str(), made.result.as_str()), ("create login", "account made"));
        let oauth = audit_row(&json!({"event": "oauth_denied", "name": "Grok", "app": "cursor.com"}));
        assert_eq!((oauth.who.as_str(), oauth.host.as_str()), ("Grok", "cursor.com"));
    }
}
