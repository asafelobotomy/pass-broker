//! Wizard progress and settings, kept in ~/.config/passbroker/wizard.json.
//!
//! A step is `completed` once its condition was met and `locked` once you
//! confirmed it. Unlocking keeps `completed` (so later steps stay reachable)
//! until something it depends on changes.

use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;

pub const STEPS: usize = 6;
pub const REQUIREMENTS: usize = 0;
pub const TOKEN: usize = 1;
pub const VAULT: usize = 2;
pub const ACCESS: usize = 3;
pub const UNLOCK: usize = 4;
pub const ASSISTANTS: usize = 5;
/// Bumped when steps are added, so saved progress can be moved to the right step.
const VERSION: u32 = 2;

#[derive(Serialize, Deserialize, Clone, Default, Debug)]
pub struct StepState {
    pub completed: bool,
    pub locked: bool,
    pub at: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(default)]
pub struct Settings {
    pub vault: String,
    pub token_name: String,
    pub token_expiry: i32,
    pub tunnel_mode: i32, // 0 Tailscale Funnel, 1 own hostname, 2 this PC only
    pub own_host: String,
    pub port: i32,
    pub grant_minutes: i32,
    pub show_browser: bool,
    pub clear_sessions: bool,
    pub idle_minutes: i32,
    /// Run the broker as a sandboxed systemd user service instead of a wizard child.
    pub service_mode: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            vault: "Agent".into(),
            token_name: "passbroker".into(),
            token_expiry: 2,
            tunnel_mode: 0,
            own_host: String::new(),
            port: 8787,
            grant_minutes: 2,
            show_browser: true,
            clear_sessions: true,
            idle_minutes: 15,
            service_mode: false,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Default, Debug)]
#[serde(default)]
pub struct WizardState {
    pub version: u32,
    pub steps: Vec<StepState>,
    pub settings: Settings,
    /// The address assistants were connected to when step 4 was locked.
    pub locked_address: String,
    pub vault_summary: String,
    pub vault_ok: bool,
    /// Filled from the broker while step 5 is open; not saved.
    #[serde(skip)]
    pub unlock_preset_keys: Vec<String>,
    #[serde(skip)]
    pub unlock_item_titles: Vec<String>,
}

fn path() -> PathBuf {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(".config"));
    base.join("passbroker").join("wizard.json")
}

impl WizardState {
    pub fn load() -> Self {
        let p = path();
        let text = fs::read_to_string(&p).unwrap_or_default();
        if !text.trim().is_empty() && serde_json::from_str::<serde_json::Value>(&text).is_err() {
            // Keep a damaged file for inspection rather than silently starting over on top of it.
            let _ = fs::rename(&p, p.with_extension(format!("corrupt-{}", now().replace([' ', ':'], "-"))));
        }
        Self::parse(&text)
    }

    pub fn parse(text: &str) -> Self {
        let mut s: WizardState = serde_json::from_str(text).unwrap_or_default();
        if s.version < 2 && s.steps.len() == 5 {
            // Version 1 had no "File unlocking" step: it now sits before "Connect assistants".
            s.steps.insert(UNLOCK, StepState::default());
        }
        s.version = s.version.max(VERSION);
        if s.steps.len() < STEPS {
            s.steps.resize(STEPS, StepState::default());
        }
        s
    }

    pub fn save(&self) {
        let p = path();
        if let Some(dir) = p.parent() {
            use std::os::unix::fs::DirBuilderExt;
            let _ = fs::DirBuilder::new().recursive(true).mode(0o700).create(dir);
        }
        let tmp = p.with_extension("tmp");
        let ok = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)
            .and_then(|mut f| f.write_all(serde_json::to_string_pretty(self).unwrap_or_default().as_bytes()));
        if ok.is_ok() {
            let _ = fs::rename(&tmp, &p);
        }
    }

    /// 0 = not reachable yet, 1 = to do, 2 = done and locked, 3 = unlocked for editing.
    pub fn ui_state(&self, i: usize) -> i32 {
        let s = &self.steps[i];
        if s.locked {
            2
        } else if s.completed {
            3
        } else if i == 0 || self.steps[i - 1].completed {
            1
        } else {
            0
        }
    }

    pub fn reachable(&self, i: usize) -> bool {
        self.ui_state(i) != 0
    }

    pub fn setup_done(&self) -> bool {
        (0..ASSISTANTS).all(|i| self.steps[i].locked)
    }

    pub fn lock(&mut self, i: usize) {
        self.steps[i] = StepState { completed: true, locked: true, at: now() };
    }

    pub fn unlock(&mut self, i: usize) {
        self.steps[i].locked = false;
    }

    /// Something step `i` relied on changed: it has to be done (and locked) again.
    pub fn invalidate(&mut self, i: usize) {
        self.steps[i] = StepState::default();
    }

    pub fn address(&self, ts_host: &str) -> String {
        match self.settings.tunnel_mode {
            0 if !ts_host.is_empty() => format!("https://{ts_host}/mcp"),
            0 => "https://<this-pc>.ts.net/mcp".into(),
            1 if !self.settings.own_host.is_empty() => format!("https://{}/mcp", self.settings.own_host),
            1 => "https://<your hostname>/mcp".into(),
            _ => format!("http://127.0.0.1:{}/mcp", self.settings.port),
        }
    }
}

pub fn now() -> String {
    unsafe {
        let t = libc::time(std::ptr::null_mut());
        let mut tm: libc::tm = std::mem::zeroed();
        libc::localtime_r(&t, &mut tm);
        format!("{}-{:02}-{:02} {:02}:{:02}", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_1_progress_moves_assistants_to_step_6() {
        let v1 = r#"{"steps": [
            {"completed": true, "locked": true, "at": "a"}, {"completed": true, "locked": true, "at": "b"},
            {"completed": true, "locked": true, "at": "c"}, {"completed": true, "locked": true, "at": "d"},
            {"completed": true, "locked": true, "at": "e"}]}"#;
        let s = WizardState::parse(v1);
        assert_eq!(s.version, 2);
        assert_eq!(s.steps.len(), STEPS);
        assert!(s.steps[ACCESS].locked && s.steps[ASSISTANTS].locked && s.steps[ASSISTANTS].at == "e");
        assert!(!s.steps[UNLOCK].completed);
        assert!(!s.setup_done(), "the new step has to be locked before the Control center opens");
        assert_eq!(s.ui_state(UNLOCK), 1);
    }

    #[test]
    fn current_progress_is_left_alone() {
        let mut s = WizardState::parse("{}");
        s.lock(REQUIREMENTS);
        let again = WizardState::parse(&serde_json::to_string(&s).unwrap());
        assert_eq!(again.steps.len(), STEPS);
        assert!(again.steps[REQUIREMENTS].locked && again.ui_state(TOKEN) == 1 && again.ui_state(VAULT) == 0);
    }
}
