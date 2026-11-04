"""Running the broker as a sandboxed systemd user service (optional).

`passbroker service install [serve options]` writes
~/.config/systemd/user/passbroker.service. Compared with running it from the
wizard, the service starts at login, restarts on failure, keeps running when
the wizard is closed, and always turns Tailscale Funnel off when it stops,
even after a crash. It runs sandboxed: no privilege gain, a private /tmp, the
system read-only, and writes allowed only to the broker's own folders and the
output folders of your unlock actions. Reinstall after changing those actions
(the wizard does this every time it starts the service).
"""

from __future__ import annotations

import json
import os
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

UNIT = "passbroker.service"


def unit_path() -> Path:
    base = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
    return base / "systemd" / "user" / UNIT


def _writable_dirs(config: Path, data: Path, state: Path) -> list[Path]:
    dirs = [config, data, state]
    try:
        actions = json.loads((config / "unlockers.json").read_text() or "{}").get("actions", [])
    except (FileNotFoundError, json.JSONDecodeError):
        actions = []
    for a in actions:
        out = a.get("output_dir")
        if isinstance(out, str) and out:
            path = Path(os.path.expanduser(out)).resolve()
            path.mkdir(parents=True, exist_ok=True, mode=0o700)
            dirs.append(path)
    return dirs


def render(serve_args: list[str], config: Path, data: Path, state: Path, port: int, funnel: bool) -> str:
    """The unit file text. `serve_args` are the options after `passbroker serve`."""
    if any(a in serve_args for a in ("--mock", "--insecure-auto-approve", "--allow-http-localhost", "--no-pairing-window", "--notify-file")):
        raise ValueError("test-only switches can't go into a service")
    exec_start = shlex.join([sys.executable, "-m", "passbroker.cli", "serve", *serve_args])
    tailscale = shutil.which("tailscale") or "/usr/bin/tailscale"
    rw = " ".join(shlex.quote(str(d)) for d in _writable_dirs(config, data, state))
    funnel_lines = (
        f"ExecStartPre={shlex.join([tailscale, 'funnel', '--bg', '--https=443', f'http://127.0.0.1:{port}'])}\n"
        f"ExecStopPost=-{shlex.join([tailscale, 'funnel', '--https=443', 'off'])}\n"
        if funnel else ""
    )
    return f"""# Written by `passbroker service install`; reinstall rather than editing by hand.
[Unit]
Description=Pass Broker (AI assistants use Proton Pass secrets without seeing them)
After=graphical-session.target network-online.target

[Service]
Type=simple
{funnel_lines}ExecStart={exec_start}
Restart=on-failure
RestartSec=5
UMask=0077
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ReadWritePaths={rw}
# $XDG_RUNTIME_DIR/passbroker: the Control center's live browser view (memory only, removed on stop).
RuntimeDirectory=passbroker
RuntimeDirectoryMode=0700
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
RestrictRealtime=yes
LockPersonality=yes
SystemCallArchitectures=native

[Install]
WantedBy=default.target
"""


def _systemctl(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["systemctl", "--user", *args], capture_output=True, text=True, timeout=60)


def install(serve_args: list[str], config: Path, data: Path, state: Path, port: int, funnel: bool, enable: bool = True) -> Path:
    path = unit_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(render(serve_args, config, data, state, port, funnel))
    os.replace(tmp, path)
    _systemctl("daemon-reload")
    if enable:
        _systemctl("enable", UNIT)
    return path


def uninstall() -> None:
    _systemctl("disable", "--now", UNIT)
    unit_path().unlink(missing_ok=True)
    _systemctl("daemon-reload")


def status() -> dict[str, object]:
    installed = unit_path().exists()
    active = _systemctl("is-active", UNIT).stdout.strip() if installed else "not installed"
    return {"installed": installed, "state": active}


def control(action: str) -> None:
    if action not in ("start", "stop", "restart"):
        raise ValueError(action)
    proc = _systemctl(action, UNIT)
    if proc.returncode != 0:
        raise RuntimeError((proc.stderr or proc.stdout).strip()[-300:] or f"systemctl {action} failed")
