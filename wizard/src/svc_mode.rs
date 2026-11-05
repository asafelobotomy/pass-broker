//! Background mode: the broker runs as a sandboxed systemd user service instead of a wizard child.
//!
//! Start writes the unit from the current settings (so unlock output folders are
//! always writable) and restarts it; the state comes from systemd, the log from
//! the service's journal. The service, not the wizard, turns Funnel on and off.

use crate::api::{args, s};
use crate::{bg, strings, toast, wiz, AppWindow, Shared};
use serde_json::Value;
use slint::{ComponentHandle, Model, SharedString, VecModel};
use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

const MAX_LOG_LINES: usize = 400;

pub fn running(app: &Shared) -> bool {
    app.broker.lock().unwrap().is_some() || app.service_active.load(Ordering::SeqCst)
}

pub fn wire(app: &Shared, ui: &AppWindow) {
    wiz(ui).set_service_mode(app.state.lock().unwrap().settings.service_mode);
    wiz(ui).on_set_service_mode({
        let (a, w) = (app.clone(), ui.as_weak());
        move |on| {
            let Some(ui) = w.upgrade() else { return };
            if running(&a) {
                wiz(&ui).set_service_mode(!on);
                toast(&ui, "Stop the broker before switching how it runs.", true);
                return;
            }
            {
                let mut st = a.state.lock().unwrap();
                st.settings.service_mode = on;
                st.save();
            }
            if !on {
                bg(&a, &ui, "Removing the background service…", |app| app.cli.call(&args(["service-uninstall"]), None), |ui, _, r| match r {
                    Ok(_) => toast(ui, "The background service is removed; the broker now runs only while the wizard is open.", false),
                    Err(e) => toast(ui, e, true),
                });
            } else {
                toast(&ui, "Press Start to install and start the background service.", false);
            }
        }
    });
}

fn public_host(app: &Shared) -> String {
    let settings = app.state.lock().unwrap().settings.clone();
    match settings.tunnel_mode {
        0 => app.ts_host.lock().unwrap().clone(),
        1 => settings.own_host,
        _ => String::new(),
    }
}

fn mcp_url(app: &Shared) -> String {
    let public = public_host(app);
    let port = app.state.lock().unwrap().settings.port;
    if public.is_empty() { format!("http://127.0.0.1:{port}/mcp") } else { format!("https://{public}/mcp") }
}

pub fn start(app: &Shared, ui: &AppWindow) {
    let settings = app.state.lock().unwrap().settings.clone();
    let public = public_host(app);
    let mut cmd: Vec<String> = vec![
        "service-install".into(), "--port".into(), settings.port.to_string(), "--vault".into(), settings.vault.clone(),
        "--grant-minutes".into(), settings.grant_minutes.to_string(),
    ];
    if !public.is_empty() {
        cmd.extend(["--public-host".into(), public.clone()]);
    }
    if !settings.browser_window {
        cmd.push("--headless".into());
    }
    if settings.clear_sessions {
        cmd.extend(["--idle-minutes".into(), settings.idle_minutes.to_string()]);
    } else {
        cmd.push("--keep-sessions".into());
    }
    let url = mcp_url(app);
    wiz(ui).set_broker_state("starting".into());
    bg(app, ui, "Starting the background service…", move |app| {
        app.cli.call(&cmd, None)?;
        app.cli.call(&args(["service-control", "restart"]), None)
    }, move |ui, app, r| match r {
        Ok(_) => {
            wiz(ui).set_broker_url(url.into());
            follow_journal(app, ui);
            poll(app, ui);
        }
        Err(e) => {
            wiz(ui).set_broker_state("stopped".into());
            toast(ui, format!("Couldn't start the service: {e}"), true);
        }
    });
}

pub fn stop(app: &Shared, ui: &AppWindow) {
    wiz(ui).set_broker_state("stopping".into());
    bg(app, ui, "Stopping the background service…", |app| app.cli.call(&args(["service-control", "stop"]), None), |ui, app, r| {
        if let Err(e) = r {
            toast(ui, e, true);
        }
        poll(app, ui);
    });
}

/// Ask systemd for the service's state and reflect it in the wizard.
/// One status check at a time (a hung `systemctl` mustn't pile up threads), and the last state
/// seen, so "failed" is announced once rather than every few seconds.
static POLLING: AtomicBool = AtomicBool::new(false);
static FOLLOWING: AtomicBool = AtomicBool::new(false);
static LAST_STATE: Mutex<String> = Mutex::new(String::new());

/// Ask systemd for the service's state and reflect it in the wizard.
pub fn poll(app: &Shared, ui: &AppWindow) {
    if !app.state.lock().unwrap().settings.service_mode || POLLING.swap(true, Ordering::SeqCst) {
        return;
    }
    let (app, weak) = (app.clone(), ui.as_weak());
    std::thread::spawn(move || {
        let r = app.cli.call(&args(["service-status"]), None);
        POLLING.store(false, Ordering::SeqCst);
        let app2 = app.clone();
        let _ = weak.upgrade_in_event_loop(move |ui| {
            let state = r.as_ref().map(|v: &Value| s(&v["state"])).unwrap_or_else(|_| "unknown".into());
            let active = state == "active" || state == "activating";
            app2.service_active.store(active, Ordering::SeqCst);
            let shown = match state.as_str() {
                "active" => "running",
                "activating" | "reloading" => "starting",
                "deactivating" => "stopping",
                _ => "stopped",
            };
            let previous = std::mem::replace(&mut *LAST_STATE.lock().unwrap(), state.clone());
            if state == "failed" && previous != "failed" {
                toast(&ui, "The background service failed; see the log in the Control center.", true);
            }
            wiz(&ui).set_broker_state(shown.into());
            if active && !FOLLOWING.load(Ordering::SeqCst) {
                // reopened while the service runs (or it restarted): show its address and follow this run's log
                wiz(&ui).set_broker_url(mcp_url(&app2).into());
                follow_journal(&app2, &ui);
            } else if !active && state != "unknown" {
                stop_following(&app2);
            }
            crate::view::render_steps(&app2, &ui);
        });
    });
}

/// Stop following the service's log, and reap the follower.
pub fn stop_following(app: &Shared) {
    FOLLOWING.store(false, Ordering::SeqCst);
    if let Some(mut old) = app.journal.lock().unwrap().take() {
        let _ = old.kill();
        let _ = old.wait();
    }
}

fn follow_journal(app: &Shared, ui: &AppWindow) {
    stop_following(app);
    FOLLOWING.store(true, Ordering::SeqCst);
    let lines = Rc::new(VecModel::<SharedString>::default());
    wiz(ui).set_log_lines(slint::ModelRc::from(lines.clone()));
    let (app, w) = (app.clone(), ui.as_weak());
    // systemctl and journalctl run off the UI thread.
    std::thread::spawn(move || {
        // Only this run of the service, not earlier (perhaps failed) starts.
        let invocation = Command::new("systemctl")
            .args(["--user", "show", "passbroker.service", "-p", "InvocationID", "--value"])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .unwrap_or_default();
        let mut filter = vec!["--user".to_string(), "-f".into(), "-n".into(), "200".into(), "-o".into(), "cat".into()];
        if invocation.chars().all(|c| c.is_ascii_hexdigit()) && !invocation.is_empty() {
            filter.extend([format!("_SYSTEMD_INVOCATION_ID={invocation}"), "+".into(), format!("USER_INVOCATION_ID={invocation}")]);
        } else {
            filter.extend(["-u".into(), "passbroker.service".into()]);
        }
        let spawned = Command::new("journalctl").args(&filter).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn();
        let Ok(mut child) = spawned else {
            let _ = w.upgrade_in_event_loop(|ui| {
                wiz(&ui).set_log_lines(strings(std::iter::once("journalctl isn't available; see `journalctl --user -u passbroker`".to_string())));
            });
            return;
        };
        let out = child.stdout.take();
        *app.journal.lock().unwrap() = Some(child);
        let Some(out) = out else { return };
        for line in BufReader::new(out).lines().map_while(Result::ok) {
            let _ = w.upgrade_in_event_loop(move |ui| {
                let model = wiz(&ui).get_log_lines();
                if let Some(vm) = model.as_any().downcast_ref::<VecModel<SharedString>>() {
                    if vm.row_count() >= MAX_LOG_LINES {
                        vm.remove(0);
                    }
                    vm.push(line.into());
                }
            });
        }
    });
}
