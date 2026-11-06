//! Step 5 "Bot reports": what bots filed with report_issue (issues.py), to mark fixed or dismissed
//! and copy as Markdown for whoever fixes them.

use crate::api::{args, s};
use crate::{bg, toast, wiz, AppWindow, ReportRow, Shared};
use serde_json::{json, Value};
use slint::{ComponentHandle, ModelRc, VecModel};

/// The rows from `api config`'s "issues", newest first.
pub fn fill(ui: &AppWindow, issues: &Value) {
    let rows: Vec<ReportRow> = issues.as_array().into_iter().flatten().map(row).collect();
    let open = rows.iter().filter(|r| r.open).count() as i32;
    wiz(ui).set_reports(ModelRc::new(VecModel::from(rows)));
    wiz(ui).set_reports_open(open);
}

fn row(i: &Value) -> ReportRow {
    let seen = i["seen"].as_i64().unwrap_or(1);
    let mut line = format!("{} · {} · from {} · {}", s(&i["kind"]), s(&i["severity"]), s(&i["bot"]), s(&i["at"]));
    if seen > 1 {
        line += &format!(" · seen {seen} times");
    }
    if !s(&i["tool"]).is_empty() {
        line += &format!(" · tool {}", s(&i["tool"]));
    }
    if !s(&i["last_error"]["error"]).is_empty() {
        line += &format!(" · last error: {}", s(&i["last_error"]["error"]));
    }
    let status = s(&i["status"]);
    ReportRow {
        id: s(&i["id"]).into(),
        title: s(&i["title"]).into(),
        line: line.into(),
        detail: s(&i["details"]).into(),
        open: status == "open",
        status: status.into(),
        forwarded: s(&i["forwarded"]).into(),
    }
}

/// The bot reports going with the bug report: the one being forwarded, all open ones, or none.
fn chosen(ui: &AppWindow) -> Value {
    let g = wiz(ui);
    let ids = g.get_bug_ids().to_string();
    if !ids.is_empty() {
        json!(ids.split(',').collect::<Vec<_>>())
    } else if g.get_bug_include_open() {
        json!("open")
    } else {
        json!([])
    }
}

fn preview(a: &Shared, ui: &AppWindow) {
    let g = wiz(ui);
    let body = json!({"action": "preview", "title": g.get_bug_title().to_string(), "description": g.get_bug_desc().to_string(),
                      "system": g.get_bug_system(), "issues": chosen(ui)}).to_string();
    bg(a, ui, "Building the report…", move |app| app.cli.call(&args(["bug-report"]), Some(&body)), |ui, _, r| match r {
        Ok(v) => {
            let g = wiz(ui);
            g.set_bug_title(s(&v["title"]).into());
            g.set_bug_body(s(&v["body"]).into());
            g.set_bug_gh(v["gh"].as_bool().unwrap_or(false));
        }
        Err(e) => wiz(ui).set_extras_note(e.into()),
    });
}

fn clear(ui: &AppWindow) {
    let g = wiz(ui);
    g.set_bug_title("".into());
    g.set_bug_desc("".into());
    g.set_bug_body("".into());
    g.set_bug_ids("".into());
    g.set_bug_include_open(false);
}

pub fn wire(app: &Shared, ui: &AppWindow) {
    wiz(ui).on_bug_preview({
        let (a, w) = (app.clone(), ui.as_weak());
        move || {
            if let Some(ui) = w.upgrade() {
                preview(&a, &ui);
            }
        }
    });
    wiz(ui).on_report_forward({
        let (a, w) = (app.clone(), ui.as_weak());
        move |id| {
            let Some(ui) = w.upgrade() else { return };
            wiz(&ui).set_bug_ids(id);
            wiz(&ui).set_bug_title("".into());
            preview(&a, &ui);
        }
    });
    wiz(ui).on_bug_cancel({
        let w = ui.as_weak();
        move || {
            if let Some(ui) = w.upgrade() {
                clear(&ui);
            }
        }
    });
    // Open on GitHub: the link carries title and body (or the body goes by clipboard when too long).
    wiz(ui).on_bug_open({
        let (a, w) = (app.clone(), ui.as_weak());
        move || {
            let Some(ui) = w.upgrade() else { return };
            let g = wiz(&ui);
            let (title, text) = (g.get_bug_title().to_string(), g.get_bug_body().to_string());
            let link = json!({"action": "link", "title": title, "body": text}).to_string();
            let opened = json!({"action": "opened", "issues": chosen(&ui)}).to_string();
            bg(&a, &ui, "Opening GitHub…", move |app| {
                let v = app.cli.call(&args(["bug-report"]), Some(&link))?;
                app.cli.call(&args(["bug-report"]), Some(&opened))?;
                Ok(v)
            }, move |ui, app, r: Result<Value, String>| match r {
                Ok(v) => {
                    if v["clipboard"].as_bool().unwrap_or(false) {
                        crate::live_cb::copy_text(app, ui, text.clone(), false);
                        toast(ui, "The report is long: it's on your clipboard, paste it into the issue.", false);
                    }
                    crate::open_url(&s(&v["url"]));
                    wiz(ui).set_extras_note("Opened on GitHub: check it there and press Submit new issue.".into());
                    clear(ui);
                    crate::extras_cb::refresh(app, ui);
                }
                Err(e) => wiz(ui).set_extras_note(e.into()),
            });
        }
    });
    wiz(ui).on_bug_send({
        let (a, w) = (app.clone(), ui.as_weak());
        move || {
            let Some(ui) = w.upgrade() else { return };
            let g = wiz(&ui);
            let body = json!({"action": "send", "title": g.get_bug_title().to_string(), "body": g.get_bug_body().to_string(),
                              "issues": chosen(&ui)}).to_string();
            bg(&a, &ui, "Sending to GitHub…", move |app| app.cli.call(&args(["bug-report"]), Some(&body)), |ui, app, r| match r {
                Ok(v) => {
                    wiz(ui).set_extras_note(format!("Sent: {}", s(&v["url"])).into());
                    clear(ui);
                    crate::extras_cb::refresh(app, ui);
                }
                Err(e) => wiz(ui).set_extras_note(e.into()),
            });
        }
    });
    wiz(ui).on_report_set({
        let (a, w) = (app.clone(), ui.as_weak());
        move |id, status| {
            let Some(ui) = w.upgrade() else { return };
            let cmd = vec!["issue-set".to_string(), id.to_string(), "--status".into(), status.to_string()];
            bg(&a, &ui, "Saving…", move |app| app.cli.call(&cmd, None), |ui, app, r| {
                if let Err(e) = r {
                    wiz(ui).set_extras_note(e.into());
                }
                crate::extras_cb::refresh(app, ui);
            });
        }
    });
    wiz(ui).on_reports_copy({
        let (a, w) = (app.clone(), ui.as_weak());
        move || {
            let Some(ui) = w.upgrade() else { return };
            let cmd = vec!["issues".to_string(), "--status".into(), "open".into(), "--markdown".into()];
            bg(&a, &ui, "Copying…", move |app| app.cli.call(&cmd, None), |ui, app, r| match r {
                Ok(v) => crate::live_cb::copy_text(app, ui, s(&v["markdown"]), false),
                Err(e) => wiz(ui).set_extras_note(e.into()),
            });
        }
    });
}

#[cfg(test)]
mod tests {
    use super::row;
    use serde_json::json;

    #[test]
    fn rows_say_what_and_who() {
        let r = row(&json!({"id": "ab12", "title": "fill_login fails", "kind": "bug", "severity": "high", "bot": "shopper",
                            "at": "2026-11-06 10:00", "seen": 3, "tool": "fill_login", "status": "open",
                            "last_error": {"error": "no sign-in field"}}));
        assert!(r.open && r.line.contains("seen 3 times") && r.line.contains("last error: no sign-in field"));
        assert!(!row(&json!({"status": "fixed"})).open);
    }
}
