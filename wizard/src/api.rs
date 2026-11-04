//! Talks to the Python broker through `passbroker api …` (one JSON object per
//! line). The wizard never handles the Proton Pass token except to pipe a
//! pasted one straight into `api store-token`.

use serde_json::Value;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};

#[derive(Clone)]
pub struct Cli {
    pub program: PathBuf,
}

impl Cli {
    /// $PASSBROKER_CLI, then `passbroker` on PATH, then a project .venv next to this binary.
    pub fn find() -> Cli {
        if let Some(p) = std::env::var_os("PASSBROKER_CLI") {
            return Cli { program: p.into() };
        }
        if let Some(paths) = std::env::var_os("PATH") {
            // relative PATH entries would run whatever `passbroker` sits in the current folder
            for dir in std::env::split_paths(&paths).filter(|d| d.is_absolute()) {
                let candidate = dir.join("passbroker");
                if candidate.is_file() {
                    return Cli { program: candidate };
                }
            }
        }
        if let Ok(exe) = std::env::current_exe() {
            for dir in exe.ancestors() {
                for rel in [".venv/bin/passbroker", "../.venv/bin/passbroker"] {
                    let candidate = dir.join(rel);
                    if candidate.is_file() {
                        return Cli { program: candidate };
                    }
                }
            }
        }
        Cli { program: "passbroker".into() }
    }

    fn command(&self, args: &[String]) -> Command {
        let mut c = Command::new(&self.program);
        c.arg("api").args(args).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
        c
    }

    /// Run one command; Ok(json) when it reports ok, Err(message) otherwise.
    pub fn call(&self, args: &[String], stdin: Option<&str>) -> Result<Value, String> {
        let mut cmd = self.command(args);
        if stdin.is_some() {
            cmd.stdin(Stdio::piped());
        }
        let mut child = cmd.spawn().map_err(|e| format!("couldn't run {}: {e}", self.program.display()))?;
        if let (Some(input), Some(mut pipe)) = (stdin, child.stdin.take()) {
            let _ = pipe.write_all(input.as_bytes());
            let _ = pipe.write_all(b"\n");
        }
        let out = child.wait_with_output().map_err(|e| e.to_string())?;
        let text = String::from_utf8_lossy(&out.stdout);
        let last = text.lines().rev().find(|l| l.trim_start().starts_with('{'));
        let value: Value = match last.and_then(|l| serde_json::from_str(l).ok()) {
            Some(v) => v,
            None => {
                let err = String::from_utf8_lossy(&out.stderr);
                return Err(err.lines().last().unwrap_or("no response from passbroker").to_string());
            }
        };
        if value["ok"].as_bool() == Some(true) {
            Ok(value)
        } else {
            Err(value["error"].as_str().unwrap_or("failed").to_string())
        }
    }

    /// Run a streaming command, handing each event to `on_event`; returns the final `done` event.
    pub fn stream(&self, args: &[String], mut on_event: impl FnMut(&Value)) -> Result<Value, String> {
        // stderr isn't read here, so don't pipe it: a full pipe would stall the command
        let mut child = self.command(args).stderr(Stdio::null()).spawn().map_err(|e| e.to_string())?;
        let stdout = child.stdout.take().ok_or("no output")?;
        let mut done = None;
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            let Ok(v) = serde_json::from_str::<Value>(&line) else { continue };
            if v["event"] == "done" {
                done = Some(v);
            } else {
                on_event(&v);
            }
        }
        let _ = child.wait();
        match done {
            Some(v) if v["ok"].as_bool() == Some(true) => Ok(v),
            Some(v) => Err(v["error"].as_str().unwrap_or("failed").to_string()),
            None => Err("passbroker stopped without finishing".into()),
        }
    }

    /// Start `passbroker serve …` with merged output.
    pub fn spawn(&self, argv: &[String]) -> std::io::Result<Child> {
        let (prog, rest) = argv.split_first().ok_or_else(|| std::io::Error::other("empty command"))?;
        // serve-command returns the interpreter path; keep using it as given.
        let mut cmd = Command::new(Path::new(prog));
        cmd.args(rest).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
        // If the wizard dies without stopping it, the kernel sends the broker SIGTERM,
        // and the broker turns Funnel off on the way out.
        unsafe {
            cmd.pre_exec(|| {
                libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM);
                Ok(())
            });
        }
        cmd.spawn()
    }
}

pub fn s(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

pub fn args<const N: usize>(a: [&str; N]) -> Vec<String> {
    a.iter().map(|x| x.to_string()).collect()
}
