"""Human approval on your desktop, outside anything the model can click."""

from __future__ import annotations

import subprocess
import threading
import time
from typing import Protocol


class Approver(Protocol):
    def ask(self, title: str, body: str) -> bool: ...


class DesktopApprover:
    """A KDE/libnotify notification with Allow and Deny. Silence means deny.

    The text is built only from the item title (your own vault data), the
    client name and the host the broker read from the browser itself; nothing
    the model or the page writes goes into it.
    """

    def __init__(self, timeout_s: int = 60) -> None:
        self._timeout = timeout_s

    def ask(self, title: str, body: str) -> bool:
        try:
            proc = subprocess.run(
                [
                    "notify-send",
                    "--app-name=Pass Broker",
                    "--urgency=critical",
                    f"--expire-time={self._timeout * 1000}",
                    "--action=allow=Allow",
                    "--action=deny=Deny",
                    "--wait",
                    title,
                    body,
                ],
                capture_output=True,
                text=True,
                timeout=self._timeout + 5,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False
        return proc.stdout.strip() == "allow"


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
