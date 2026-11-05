//! The Settings dialog: launch at login, start the broker on launch, tray icon,
//! keep running in the tray, and theme. Saved in wizard.json under `prefs`.

use crate::state::AppPrefs;
use crate::{toast, tray, wiz, AppWindow, Shared};
use slint::ComponentHandle;
use std::fs;
use std::path::PathBuf;

/// The XDG autostart entry desktops read at login.
fn autostart_path() -> PathBuf {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(".config"));
    base.join("autostart").join("pass-broker.desktop")
}

fn set_autostart(prefs: &AppPrefs) -> Result<(), String> {
    let path = autostart_path();
    if !prefs.launch_at_login {
        return match fs::remove_file(&path) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(format!("couldn't remove {}: {e}", path.display())),
            _ => Ok(()),
        };
    }
    // From an AppImage, the AppImage file: the folder it's mounted on changes every run.
    let exe = match std::env::var_os("APPIMAGE").map(PathBuf::from).filter(|p| p.is_file()) {
        Some(appimage) => appimage,
        None => std::env::current_exe().map_err(|e| format!("couldn't find this program: {e}"))?,
    };
    let exe = exe.to_string_lossy();
    if exe.contains(['"', '\\', '`', '$', '\n']) {
        return Err("this program's path has characters an autostart entry can't hold".into());
    }
    let exe = exe.replace('%', "%%"); // % starts a field code (%f, %u...) in desktop entries
    // In the tray at login rather than a window popping up, when there is a tray.
    let args = if prefs.tray { " --minimized" } else { "" };
    let entry = format!(
        "[Desktop Entry]\nType=Application\nName=Pass Broker\nComment=Sign-ins without sharing secrets\n\
         Exec=\"{exe}\"{args}\nIcon=security-high\nTerminal=false\nX-GNOME-Autostart-enabled=true\n"
    );
    fs::create_dir_all(path.parent().unwrap()).map_err(|e| e.to_string())?;
    fs::write(&path, entry).map_err(|e| format!("couldn't write {}: {e}", path.display()))
}

fn apply_tray(app: &Shared, ui: &AppWindow, on: bool) -> Result<(), String> {
    if on { tray::start(app, ui) } else { tray::stop(); Ok(()) }
}

pub fn wire(app: &Shared, ui: &AppWindow) {
    wiz(ui).on_open_settings({
        let (a, w) = (app.clone(), ui.as_weak());
        move || {
            let Some(ui) = w.upgrade() else { return };
            let p = a.state.lock().unwrap().prefs.clone();
            let g = wiz(&ui);
            g.set_pref_login(p.launch_at_login);
            g.set_pref_start_broker(p.start_broker);
            g.set_pref_tray(p.tray);
            g.set_pref_close_to_tray(p.close_to_tray);
            g.set_pref_theme(p.theme);
            g.set_settings_note("".into());
            g.set_settings_open(true);
        }
    });
    wiz(ui).on_save_settings({
        let (a, w) = (app.clone(), ui.as_weak());
        move || {
            let Some(ui) = w.upgrade() else { return };
            let g = wiz(&ui);
            let prefs = AppPrefs {
                launch_at_login: g.get_pref_login(),
                start_broker: g.get_pref_start_broker(),
                tray: g.get_pref_tray(),
                close_to_tray: g.get_pref_tray() && g.get_pref_close_to_tray(),
                theme: g.get_pref_theme(),
            };
            let mut problems = Vec::new();
            if let Err(e) = set_autostart(&prefs) {
                problems.push(e);
            }
            if let Err(e) = apply_tray(&a, &ui, prefs.tray) {
                problems.push(e);
            }
            ui.invoke_apply_theme(prefs.theme);
            {
                let mut st = a.state.lock().unwrap();
                st.prefs = prefs;
                if let Err(e) = st.try_save() {
                    problems.push(format!("couldn't save the settings ({e})"));
                }
            }
            if problems.is_empty() {
                g.set_settings_open(false);
                toast(&ui, "Settings saved.", false);
            } else {
                g.set_settings_note(format!("Saved, but: {}", problems.join("; ")).into());
            }
        }
    });
}

/// At launch: theme, tray, and starting the broker. Returns whether to show the window
/// (not when started `--minimized` at login and the tray icon is there to open it).
pub fn at_launch(app: &Shared, ui: &AppWindow, minimized: bool) -> bool {
    let prefs = app.state.lock().unwrap().prefs.clone();
    ui.invoke_apply_theme(prefs.theme);
    let tray_ok = prefs.tray && match tray::start(app, ui) {
        Ok(()) => true,
        Err(e) => {
            toast(ui, format!("No tray icon: {e}"), true);
            false
        }
    };
    !(minimized && tray_ok)
}

/// Start the broker if the Settings say so (called once the stale-Funnel cleanup is done).
pub fn start_broker_if_wanted(app: &Shared, ui: &AppWindow) {
    let st = app.state.lock().unwrap();
    // The background service starts at login by itself.
    let wanted = st.prefs.start_broker && st.setup_done() && !st.settings.service_mode;
    drop(st);
    if wanted {
        crate::broker_proc::start_broker(app, ui);
    }
}

/// Closing the window: keep running in the tray, or quit.
pub fn close_to_tray(app: &Shared) -> bool {
    app.state.lock().unwrap().prefs.close_to_tray && tray::active()
}
