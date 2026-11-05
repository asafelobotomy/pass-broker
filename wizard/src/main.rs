//! Pass Broker setup wizard and control center.

mod access_cb;
mod api;
mod approvals;
mod broker_proc;
mod extras_cb;
mod live_cb;
mod prefs;
mod preview;
mod setup_cb;
mod single;
mod state;
mod svc_mode;
mod tray;
mod unlock_cb;
mod view;

use api::Cli;
use slint::{ComponentHandle, ModelRc, SharedString, Timer, TimerMode, VecModel};
use state::{WizardState, STEPS};
use std::process::Child;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

slint::include_modules!();

pub const EXPIRATIONS: [&str; 6] = ["1d", "1w", "1m", "3m", "6m", "1y"];
pub const CONTROL_CENTER: i32 = STEPS as i32;

pub const TITLES: [&str; STEPS] = ["Requirements", "Proton Pass token", "Check the vault", "Remote access", "Unlocking & devices", "Connect assistants"];
const UNLOCK_WARNINGS: [&str; STEPS] = [
    "You can re-check and install requirements. Nothing else changes.",
    "You'll be able to replace or remove the Proton Pass token the broker uses to read your vault. If you replace it, the vault check (step 3) has to be done again.",
    "You'll be able to change which vault the broker reads and check it again.",
    "You'll be able to change how Grok reaches the broker and the safety settings. If the address changes, connected apps must connect again, and step 6 has to be done again.",
    "You'll be able to change file-unlock actions, encryption keys, home-device actions and email-code settings. Removing one stops assistants using it immediately.",
    "You'll be able to add or remove local assistants. Revoking connected apps and switching bots off is always possible, even while locked.",
];

pub struct App {
    pub cli: Cli,
    pub state: Mutex<WizardState>,
    pub broker: Mutex<Option<Child>>,
    pub funnel_on: AtomicBool,
    /// Set by any stop: a start still in progress must not go on to launch the broker.
    pub start_cancelled: AtomicBool,
    pub clipboard: Mutex<Option<arboard::Clipboard>>,
    pub busy: AtomicUsize,
    // last known facts from `api status`
    pub requirements_ok: AtomicBool,
    pub token_stored: AtomicBool,
    pub ts_ready: AtomicBool,
    pub ts_host: Mutex<String>,
    pub has_assistant: AtomicBool,
    pub polling: AtomicBool,
    pub service_active: AtomicBool,
    pub journal: Mutex<Option<Child>>,
}

pub type Shared = Arc<App>;

pub fn wiz(ui: &AppWindow) -> Wiz<'_> {
    ui.global::<Wiz>()
}

fn main() -> Result<(), slint::PlatformError> {
    let Ok(_instance_lock) = single::claim() else { return Ok(()) };
    let ui = AppWindow::new()?;
    let app: Shared = Arc::new(App {
        cli: Cli::find(),
        state: Mutex::new(WizardState::load()),
        broker: Mutex::new(None),
        funnel_on: AtomicBool::new(false),
        start_cancelled: AtomicBool::new(false),
        clipboard: Mutex::new(arboard::Clipboard::new().ok()),
        busy: AtomicUsize::new(0),
        requirements_ok: AtomicBool::new(false),
        token_stored: AtomicBool::new(false),
        ts_ready: AtomicBool::new(false),
        ts_host: Mutex::new(String::new()),
        has_assistant: AtomicBool::new(false),
        polling: AtomicBool::new(false),
        service_active: AtomicBool::new(false),
        journal: Mutex::new(None),
    });

    wiz(&ui).set_app_version(env!("CARGO_PKG_VERSION").into());
    wiz(&ui).set_expirations(strings(EXPIRATIONS.iter().map(|x| x.to_string())));
    wiz(&ui).set_unlock_warnings(strings(UNLOCK_WARNINGS.iter().map(|x| x.to_string())));
    view::load_settings_into_ui(&app, &ui);
    view::render_steps(&app, &ui);
    {
        let st = app.state.lock().unwrap();
        wiz(&ui).set_vault_summary(st.vault_summary.clone().into());
        wiz(&ui).set_vault_ok(st.vault_ok);
        // open on the first step that isn't locked yet
        let first = (0..STEPS).find(|&i| !st.steps[i].locked).unwrap_or(STEPS);
        wiz(&ui).set_current(first as i32);
    }
    view::refresh_status(&app, &ui);
    setup_cb::wire_setup(&app, &ui);
    live_cb::wire_live(&app, &ui);
    unlock_cb::wire_unlock(&app, &ui);
    // load data for whichever page the wizard opens on
    match wiz(&ui).get_current() {
        4 => unlock_cb::refresh(&app, &ui),
        p if p >= 5 => view::poll_live(&app, &ui),
        _ => {}
    }
    extras_cb::wire_extras(&app, &ui);
    svc_mode::wire(&app, &ui);
    preview::wire(&app, &ui);
    svc_mode::poll(&app, &ui);
    access_cb::wire_access(&app, &ui);
    approvals::wire(&ui);
    prefs::wire(&app, &ui);
    let minimized = std::env::args().any(|a| a == "--minimized");
    let show_window = prefs::at_launch(&app, &ui, minimized);
    // a Funnel left on by a crash or reboot would expose whatever later listens on our port;
    // only then may the broker start (it may turn Funnel on itself)
    let port = app.state.lock().unwrap().settings.port.to_string();
    {
        let (app, weak) = (app.clone(), ui.as_weak());
        std::thread::spawn(move || {
            let _ = app.cli.call(&["funnel-cleanup".into(), "--port".into(), port], None);
            let _ = weak.upgrade_in_event_loop(move |ui| prefs::start_broker_if_wanted(&app, &ui));
        });
    }

    // poll connections and activity while they're on screen
    let timer = Timer::default();
    {
        let (app, weak) = (app.clone(), ui.as_weak());
        timer.start(TimerMode::Repeated, Duration::from_secs(3), move || {
            let Some(ui) = weak.upgrade() else { return };
            let page = wiz(&ui).get_current();
            svc_mode::poll(&app, &ui);
            if page >= 5 && !app.polling.swap(true, Ordering::SeqCst) {
                view::poll_live(&app, &ui);
            }
        });
    }

    // the hidden browser's live view, while the Control center is on screen
    let preview_timer = Timer::default();
    {
        let (app, weak) = (app.clone(), ui.as_weak());
        preview_timer.start(TimerMode::Repeated, Duration::from_secs(1), move || {
            if let Some(ui) = weak.upgrade() {
                preview::tick(&app, &ui);
            }
        });
    }

    // waiting approvals, shown as an Allow / Deny dialog
    let approvals_timer = Timer::default();
    {
        let weak = ui.as_weak();
        approvals_timer.start(TimerMode::Repeated, Duration::from_millis(500), move || {
            if let Some(ui) = weak.upgrade() {
                approvals::tick(&ui);
            }
        });
    }

    ui.window().on_close_requested({
        let app = app.clone();
        move || {
            // With the tray icon, closing only hides the window; the broker keeps running.
            if !prefs::close_to_tray(&app) {
                // The window goes at once; the broker (up to 10 s to stop cleanly) stops behind it.
                let app = app.clone();
                std::thread::spawn(move || {
                    broker_proc::stop_broker_blocking_app(&app);
                    let _ = slint::invoke_from_event_loop(|| { let _ = slint::quit_event_loop(); });
                });
            }
            slint::CloseRequestResponse::HideWindow
        }
    });
    if show_window {
        ui.show()?;
    }
    let r = slint::run_event_loop_until_quit();
    tray::stop();
    broker_proc::stop_broker_blocking_app(&app);
    svc_mode::stop_following(&app);
    r
}

// ---- helpers ------------------------------------------------------------------------------

pub fn strings(items: impl Iterator<Item = String>) -> ModelRc<SharedString> {
    ModelRc::new(VecModel::from(items.map(SharedString::from).collect::<Vec<_>>()))
}

pub fn toast(ui: &AppWindow, msg: impl Into<String>, error: bool) {
    wiz(ui).set_toast(msg.into().into());
    wiz(ui).set_toast_error(error);
}

/// Run `work` off the UI thread with a busy indicator, then `done` back on it.
pub fn bg<R: Send + 'static>(
    app: &Shared,
    ui: &AppWindow,
    label: &str,
    work: impl FnOnce(&App) -> R + Send + 'static,
    done: impl FnOnce(&AppWindow, &Shared, R) + Send + 'static,
) {
    app.busy.fetch_add(1, Ordering::SeqCst);
    wiz(ui).set_busy(true);
    wiz(ui).set_busy_text(label.into());
    let (app, weak) = (app.clone(), ui.as_weak());
    std::thread::spawn(move || {
        let result = work(&app);
        let app2 = app.clone();
        let _ = weak.upgrade_in_event_loop(move |ui| {
            if app2.busy.fetch_sub(1, Ordering::SeqCst) == 1 {
                wiz(&ui).set_busy(false);
            }
            done(&ui, &app2, result);
        });
    });
}

pub fn open_url(url: &str) {
    if url.starts_with("https://") {
        let _ = std::process::Command::new("xdg-open").arg(url).spawn();
    }
}

