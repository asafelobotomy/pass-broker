//! What the two ways of running the broker share: as a child of this app (broker_proc.rs) or
//! as the systemd user service (svc_mode.rs). The same options, address and log view.

use crate::state::Settings;
use crate::{wiz, AppWindow};
use slint::{Model, SharedString, VecModel};

/// How many log lines the Control center keeps.
pub const MAX_LOG_LINES: usize = 400;

/// `serve-command` or `service-install`, with the broker's options from the settings.
pub fn serve_args(command: &str, settings: &Settings, public: &str) -> Vec<String> {
    let mut cmd: Vec<String> = vec![
        command.into(), "--port".into(), settings.port.to_string(), "--vault".into(), settings.vault.clone(),
        "--grant-minutes".into(), settings.grant_minutes.to_string(),
    ];
    if !public.is_empty() {
        cmd.extend(["--public-host".into(), public.into()]);
    }
    if !settings.browser_window {
        cmd.push("--headless".into());
    }
    if settings.clear_sessions {
        cmd.extend(["--idle-minutes".into(), settings.idle_minutes.to_string()]);
    } else {
        cmd.push("--keep-sessions".into());
    }
    cmd
}

/// Where assistants connect: the public host over HTTPS, or this PC only.
pub fn mcp_url(port: i32, public: &str) -> String {
    if public.is_empty() { format!("http://127.0.0.1:{port}/mcp") } else { format!("https://{public}/mcp") }
}

/// Add a line to the Control center's log, dropping the oldest past MAX_LOG_LINES.
pub fn push_log(ui: &AppWindow, line: &str) {
    let model = wiz(ui).get_log_lines();
    if let Some(vm) = model.as_any().downcast_ref::<VecModel<SharedString>>() {
        if vm.row_count() >= MAX_LOG_LINES {
            vm.remove(0);
        }
        vm.push(line.into());
    }
}

/// `HH:MM`, `minutes` after `now` (as `state::now()` gives it: `YYYY-MM-DD HH:MM`), past midnight too.
pub fn clock_plus(now: &str, minutes: i64) -> String {
    let time = now.split_once(' ').map(|(_, t)| t).unwrap_or("00:00");
    let (h, m) = time.split_once(':').unwrap_or(("0", "0"));
    let total = h.parse::<i64>().unwrap_or(0) * 60 + m.parse::<i64>().unwrap_or(0) + minutes;
    format!("{:02}:{:02}", total.rem_euclid(1440) / 60, total.rem_euclid(60))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serve_args_follow_the_settings() {
        let s = Settings::default();
        assert_eq!(serve_args("serve-command", &s, ""), [
            "serve-command", "--port", "8787", "--vault", "Agent", "--grant-minutes", "2", "--headless", "--idle-minutes", "15",
        ]);
        let mut s = Settings { browser_window: true, clear_sessions: false, ..Settings::default() };
        s.port = 9000;
        let args = serve_args("service-install", &s, "pc.tail.ts.net");
        assert_eq!(args[0], "service-install");
        assert!(args.windows(2).any(|w| w == ["--public-host", "pc.tail.ts.net"]));
        assert!(args.contains(&"--keep-sessions".to_string()) && !args.contains(&"--headless".to_string()));
        assert!(!args.contains(&"--idle-minutes".to_string()));
    }

    #[test]
    fn mcp_url_is_public_only_with_a_host() {
        assert_eq!(mcp_url(8787, ""), "http://127.0.0.1:8787/mcp");
        assert_eq!(mcp_url(8787, "pc.tail.ts.net"), "https://pc.tail.ts.net/mcp");
    }

    #[test]
    fn clock_plus_wraps_past_midnight() {
        assert_eq!(clock_plus("2026-11-05 14:55", 10), "15:05");
        assert_eq!(clock_plus("2026-11-05 23:55", 10), "00:05");
        assert_eq!(clock_plus("garbled", 10), "00:10");
    }
}
