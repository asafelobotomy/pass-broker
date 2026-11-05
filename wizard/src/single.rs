//! One Pass Broker app at a time.
//!
//! Two copies would each start, stop and clean up the broker and Funnel on their own (one
//! opening would turn off the other's Funnel). The lock is `$XDG_RUNTIME_DIR/passbroker-app.lock`,
//! outside `passbroker/`, which systemd removes whenever the background service stops.
//! A second launch brings the open window forward through its tray icon if it has one, or
//! says it's already open, and exits.

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};

fn lock_path() -> PathBuf {
    std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
        .join("passbroker-app.lock")
}

/// The held lock, to keep for the life of the app (None if it can't be made: run unlocked),
/// or Err if another copy is running.
pub fn claim() -> Result<Option<File>, ()> {
    let path = lock_path();
    let Ok(mut file) = OpenOptions::new().read(true).write(true).create(true).truncate(false).mode(0o600).open(&path) else {
        return Ok(None); // can't make the lock: don't stand in the way
    };
    // SAFETY: flock on a file descriptor we own; no memory is involved.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
        let _ = file.set_len(0);
        let _ = file.rewind();
        let _ = write!(file, "{}", std::process::id());
        return Ok(Some(file));
    }
    let mut pid = String::new();
    let _ = file.read_to_string(&mut pid);
    hand_over(pid.trim());
    Err(())
}

/// Show the running copy's window via its tray icon, or tell the user it's open.
fn hand_over(pid: &str) {
    let shown = pid.chars().all(|c| c.is_ascii_digit())
        && !pid.is_empty()
        && Command::new("busctl")
            .args(["--user", "call", &format!("org.kde.StatusNotifierItem-{pid}-1"), "/StatusNotifierItem"])
            .args(["org.kde.StatusNotifierItem", "Activate", "ii", "0", "0"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
    if !shown {
        let _ = Command::new("notify-send")
            .args(["--app-name=Pass Broker", "Pass Broker is already open", "Use the window that's already open (or its tray icon)."])
            .status();
    }
}
