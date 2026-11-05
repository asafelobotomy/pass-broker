"""Human approval on your desktop, outside anything the model can click."""

from __future__ import annotations

import json
import os
import secrets
import subprocess
import threading
import time
from pathlib import Path
from typing import Protocol


class Approver(Protocol):
    def ask(self, title: str, body: str) -> bool: ...


def approvals_dir() -> Path | None:
    run = os.environ.get("XDG_RUNTIME_DIR")
    return Path(run) / "passbroker" / "approvals" if run else None


class DesktopApprover:
    """Allow and Deny in a desktop notification and in the Pass Broker app. Silence means deny.

    Each request is written to `approvals/<id>.json` in $XDG_RUNTIME_DIR (memory,
    readable only by you), where the app shows it with its own Allow and Deny
    buttons and answers by writing `<id>.answer`. Whichever answers first wins and
    the other is withdrawn. Like the notification's buttons, the folder is open to
    programs running as you; they could already read your keyring.

    The text is built only from the item title (your own vault data), the client
    name and the host the broker read from the browser itself, cleaned of
    invisible characters; nothing the page writes goes into it.
    """

    def __init__(self, timeout_s: int = 60, folder: Path | None = None) -> None:
        self._timeout = timeout_s
        self._folder = folder if folder is not None else approvals_dir()
        if self._folder is not None:
            self._folder.mkdir(parents=True, exist_ok=True, mode=0o700)
            os.chmod(self._folder, 0o700)
            for stale in self._folder.iterdir():
                stale.unlink(missing_ok=True)

    def ask(self, title: str, body: str) -> bool:
        rid = secrets.token_hex(8)
        request = answer = None
        if self._folder is not None:
            request, answer = self._folder / f"{rid}.json", self._folder / f"{rid}.answer"
            data = {"id": rid, "title": title, "body": body, "expires": time.time() + self._timeout}
            _write_private(request, json.dumps(data).encode())
        note = _Notification(title, body, self._timeout)
        try:
            deadline = time.monotonic() + self._timeout
            while time.monotonic() < deadline:
                if answer is not None and answer.exists():
                    return answer.read_text().strip() == "allow"
                if note.answer is not None:
                    return note.answer == "allow"
                time.sleep(0.1)
            return False
        finally:
            note.withdraw()
            for f in (request, answer):
                if f is not None:
                    f.unlink(missing_ok=True)


def _write_private(path: Path, data: bytes) -> None:
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, data)
    finally:
        os.close(fd)
    os.replace(tmp, path)


class _Notification:
    """notify-send in the background: its first line is the notification's id, the second the button pressed."""

    def __init__(self, title: str, body: str, timeout_s: int) -> None:
        self.answer: str | None = None
        self._id: str | None = None
        try:
            self._proc: subprocess.Popen[str] | None = subprocess.Popen(
                ["notify-send", "--app-name=Pass Broker", "--urgency=critical", f"--expire-time={timeout_s * 1000}",
                 "--action=allow=Allow", "--action=deny=Deny", "--print-id", "--wait", title, body],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL, text=True,
            )
        except FileNotFoundError:
            self._proc = None
            return
        threading.Thread(target=self._read, daemon=True).start()

    def _read(self) -> None:
        assert self._proc is not None and self._proc.stdout is not None
        lines = (line.strip() for line in self._proc.stdout)
        self._id = next(lines, None)
        reply = next(lines, "")
        if reply in ("allow", "deny"):
            self.answer = reply

    def withdraw(self) -> None:
        if self._proc is None or self._proc.poll() is not None:
            return
        if self._id and self._id.isdigit():
            subprocess.run(["busctl", "--user", "call", "org.freedesktop.Notifications", "/org/freedesktop/Notifications",
                            "org.freedesktop.Notifications", "CloseNotification", "u", self._id], capture_output=True, timeout=5)
        self._proc.terminate()


class StaticApprover:
    """For tests: always answers the same way and records what it was asked."""

    def __init__(self, answer: bool) -> None:
        self.answer = answer
        self.asked: list[tuple[str, str]] = []

    def ask(self, title: str, body: str) -> bool:
        self.asked.append((title, body))
        return self.answer


class GrantCache:
    """Remembers an Allow for one (client, item, host, action) for a short time."""

    def __init__(self, ttl_s: float) -> None:
        self._ttl = ttl_s
        self._grants: dict[tuple[str, str, str, str], float] = {}
        self._lock = threading.Lock()

    def check(self, key: tuple[str, str, str, str]) -> bool:
        with self._lock:
            exp = self._grants.get(key)
            if exp is None or exp < time.monotonic():
                self._grants.pop(key, None)
                return False
            return True

    def grant(self, key: tuple[str, str, str, str]) -> None:
        if self._ttl > 0:
            with self._lock:
                self._grants[key] = time.monotonic() + self._ttl

    def revoke_all(self) -> None:
        with self._lock:
            self._grants.clear()
