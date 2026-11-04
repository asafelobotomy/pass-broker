//! Starting and stopping `passbroker serve` (and Tailscale Funnel with it).

use crate::api::{args, s};
use crate::{bg, open_url, strings, toast, wiz, App, AppWindow, Shared};
use slint::{ComponentHandle, Model, ModelRc, SharedString, VecModel};
use std::sync::atomic::Ordering;
use crate::view::render_steps;
use std::io::{BufRead, BufReader};
use std::rc::Rc;
use std::time::{Duration, Instant};

const MAX_LOG_LINES: usize = 400;


pub fn start_broker(app: &Shared, ui: &AppWindow) {
    if app.broker.lock().unwrap().is_some() {
        return;
    }
    if !app.state.lock().unwrap().setup_done() {
        toast(ui, "Lock steps 1–4 first.", true);
        return;
    }
    wiz(ui).set_broker_state("starting".into());
    wiz(ui).set_log_lines(strings(std::iter::empty()));
    wiz(ui).set_probe_result("".into());
    let settings = app.state.lock().unwrap().settings.clone();
    let weak = ui.as_weak();
    bg(app, ui, "Starting the broker…", move |app| -> Result<(String, Vec<String>), String> {
        let mut public = String::new();
        match settings.tunnel_mode {
            0 => {
                let w = weak.clone();
                let done = app.cli.stream(&["funnel-start".into(), "--port".into(), settings.port.to_string()], move |ev| {
                    if ev["event"] == "url" {
                        let url = s(&ev["url"]);
                        open_url(&url);
                        let _ = w.upgrade_in_event_loop(move |ui| toast(&ui, format!("Enable Funnel for your tailnet in the page that just opened: {url}"), false));
                    }
                })?;
                app.funnel_on.store(true, Ordering::SeqCst);
                public = s(&done["host"]);
            }
            1 => public = settings.own_host.clone(),
            _ => {}
        }
        let mut cmd: Vec<String> = vec![
            "serve-command".into(), "--port".into(), settings.port.to_string(), "--vault".into(), settings.vault.clone(),
            "--grant-minutes".into(), settings.grant_minutes.to_string(),
        ];
        if !public.is_empty() { cmd.extend(["--public-host".into(), public.clone()]); }
        if !settings.show_browser { cmd.push("--headless".into()); }
        if settings.clear_sessions { cmd.extend(["--idle-minutes".into(), settings.idle_minutes.to_string()]); } else { cmd.push("--keep-sessions".into()); }
        let argv: Vec<String> = app.cli.call(&cmd, None)?["argv"].as_array().ok_or("bad serve command")?.iter().map(s).collect();
        let url = if public.is_empty() { format!("http://127.0.0.1:{}/mcp", settings.port) } else { format!("https://{public}/mcp") };
        Ok((url, argv))
    }, |ui, app, r| {
        let (url, argv) = match r {
            Ok(x) => x,
            Err(e) => {
                wiz(ui).set_broker_state("stopped".into());
                toast(ui, format!("Couldn't start: {e}"), true);
                if app.funnel_on.swap(false, Ordering::SeqCst) { let _ = app.cli.call(&args(["funnel-stop"]), None); }
                return;
            }
        };
        let mut child = match app.cli.spawn(&argv) {
            Ok(c) => c,
            Err(e) => { wiz(ui).set_broker_state("stopped".into()); toast(ui, format!("Couldn't start the broker: {e}"), true); return; }
        };
        let lines = Rc::new(VecModel::<SharedString>::default());
        wiz(ui).set_log_lines(ModelRc::from(lines.clone()));
        let started = Instant::now();
        for pipe in [child.stdout.take().map(|p| Box::new(p) as Box<dyn std::io::Read + Send>), child.stderr.take().map(|p| Box::new(p) as Box<dyn std::io::Read + Send>)].into_iter().flatten() {
            let (w, app2, url2) = (ui.as_weak(), app.clone(), url.clone());
            std::thread::spawn(move || {
                for line in BufReader::new(pipe).lines().map_while(Result::ok) {
                    let (app3, url3) = (app2.clone(), url2.clone());
                    let _ = w.upgrade_in_event_loop(move |ui| {
                        let model = wiz(&ui).get_log_lines();
                        if let Some(vm) = model.as_any().downcast_ref::<VecModel<SharedString>>() {
                            if vm.row_count() >= MAX_LOG_LINES { vm.remove(0); }
                            vm.push(line.clone().into());
                        }
                        if line.contains("Application startup complete") || line.contains("Uvicorn running") {
                            wiz(&ui).set_broker_state("running".into());
                            wiz(&ui).set_broker_url(url3.into());
                            render_steps(&app3, &ui);
                        }
                    });
                }
            });
        }
        *app.broker.lock().unwrap() = Some(child);
        let _ = started;
        // notice if the broker exits on its own
        let (w, app2) = (ui.as_weak(), app.clone());
        std::thread::spawn(move || loop {
            std::thread::sleep(Duration::from_millis(700));
            let mut guard = app2.broker.lock().unwrap();
            let exited = match guard.as_mut() { Some(c) => c.try_wait().ok().flatten().is_some(), None => true };
            if exited {
                let was_running = guard.take().is_some();
                drop(guard);
                if was_running && app2.funnel_on.swap(false, Ordering::SeqCst) { let _ = app2.cli.call(&args(["funnel-stop"]), None); }
                let _ = w.upgrade_in_event_loop(move |ui| {
                    if was_running {
                        wiz(&ui).set_broker_state("stopped".into());
                        toast(&ui, "The broker stopped. See the log in the Control center.", true);
                    }
                });
                return;
            }
        });
    });
}

pub fn stop_broker_blocking_app(app: &App) {
    let child = app.broker.lock().unwrap().take();
    if let Some(mut c) = child {
        unsafe { libc::kill(c.id() as i32, libc::SIGTERM); }
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if c.try_wait().ok().flatten().is_some() { break; }
            std::thread::sleep(Duration::from_millis(100));
        }
        let _ = c.kill();
        let _ = c.wait();
    }
    if app.funnel_on.swap(false, Ordering::SeqCst) {
        let _ = app.cli.call(&args(["funnel-stop"]), None);
    }
}
