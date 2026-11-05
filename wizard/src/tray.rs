//! The system-tray icon (StatusNotifierItem over D-Bus, which KDE and most desktops show).
//!
//! Left-click shows the window; the menu has Show and Quit. Quit stops a broker the app
//! started (a background service keeps running) and closes the app.

use crate::{App, AppWindow, Shared};
use ksni::blocking::{Handle, TrayMethods};
use ksni::menu::StandardItem;
use ksni::{MenuItem, Tray};
use slint::ComponentHandle;
use std::sync::Mutex;

static TRAY: Mutex<Option<Handle<PassTray>>> = Mutex::new(None);

struct PassTray {
    ui: slint::Weak<AppWindow>,
    app: Shared,
}

fn show(ui: &slint::Weak<AppWindow>) {
    let _ = ui.upgrade_in_event_loop(|ui| {
        if let Err(e) = ui.show() {
            eprintln!("tray: couldn't show the window: {e}");
        }
        // A window first shown after starting in the tray isn't put on screen (Wayland)
        // until it draws; ask for a frame.
        ui.window().request_redraw();
    });
}

fn quit(app: &App) {
    crate::broker_proc::stop_broker_blocking_app(app);
    let _ = slint::invoke_from_event_loop(|| {
        let _ = slint::quit_event_loop();
    });
}

impl Tray for PassTray {
    fn id(&self) -> String {
        "pass-broker".into()
    }
    fn title(&self) -> String {
        "Pass Broker".into()
    }
    fn icon_name(&self) -> String {
        "security-high".into()
    }
    fn tool_tip(&self) -> ksni::ToolTip {
        ksni::ToolTip { title: "Pass Broker".into(), description: "Sign-ins without sharing secrets".into(), ..Default::default() }
    }
    fn activate(&mut self, _x: i32, _y: i32) {
        show(&self.ui);
    }
    fn menu(&self) -> Vec<MenuItem<Self>> {
        vec![
            StandardItem { label: "Show Pass Broker".into(), activate: Box::new(|t: &mut Self| show(&t.ui)), ..Default::default() }.into(),
            MenuItem::Separator,
            StandardItem { label: "Quit".into(), icon_name: "application-exit".into(), activate: Box::new(|t: &mut Self| quit(&t.app)), ..Default::default() }.into(),
        ]
    }
}

/// Show the tray icon (if it isn't already); an error means the desktop has no tray.
pub fn start(app: &Shared, ui: &AppWindow) -> Result<(), String> {
    let mut slot = TRAY.lock().unwrap();
    if slot.as_ref().is_some_and(|h| !h.is_closed()) {
        return Ok(());
    }
    let tray = PassTray { ui: ui.as_weak(), app: app.clone() };
    *slot = Some(tray.spawn().map_err(|e| format!("the desktop has no system tray ({e})"))?);
    Ok(())
}

pub fn stop() {
    if let Some(h) = TRAY.lock().unwrap().take() {
        h.shutdown().wait();
    }
}

pub fn active() -> bool {
    TRAY.lock().unwrap().as_ref().is_some_and(|h| !h.is_closed())
}
