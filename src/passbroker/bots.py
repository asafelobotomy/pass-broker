"""Self-reported bot names, with an on/off switch for each.

Every tool call carries the name of the bot making it (Grok Bot runs several
bots on one shared connector). The name is a label the bot gives itself, not
proof: a misbehaving or prompt-injected bot can claim any name. It still lets
approvals, grants and the audit log tell honest bots apart, and lets you turn
one off by name without revoking the connection every bot shares.

Each bot also has an access list: which logins, unlock actions, devices and
keys it may use, and whether it may use email codes. A new bot starts with
nothing (it can only browse in its own session) until you grant it more.
"""

from __future__ import annotations

import contextlib
import fcntl
import json
import os
import re
import threading
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

NAME_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,31}")
KINDS = ("logins", "unlock", "devices", "keys")


def empty_access() -> dict[str, Any]:
    return {"logins": [], "unlock": [], "devices": [], "keys": [], "email_codes": False}


class BotError(Exception):
    """Safe to show to the model."""


def clean_bot(name: str | None) -> str:
    bot = (name or "").strip().lower()
    if not NAME_RE.fullmatch(bot):
        raise BotError("give your own bot name in `bot`: 1-32 letters, digits, dot, dash or underscore")
    return bot


class Bots:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = threading.Lock()

    @contextlib.contextmanager
    def _edit(self) -> Iterator[dict[str, Any]]:
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(self.path.with_suffix(".lock"), os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            data = self._read()
            yield data
            tmp = self.path.with_suffix(".tmp")
            wfd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(wfd, "w") as f:
                json.dump(data, f, indent=2)
            os.replace(tmp, self.path)
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    def _read(self) -> dict[str, Any]:
        try:
            return json.loads(self.path.read_text() or "{}")
        except FileNotFoundError:
            return {}

    def list(self) -> list[dict[str, Any]]:
        return [{"name": n, **v} for n, v in sorted(self._read().items())]

    def check(self, connection: str, bot: str | None, action: str, site: str = "") -> tuple[str, bool]:
        """Validate and record a call. Returns (bot, first time seen); raises if switched off."""
        name = clean_bot(bot)
        now = time.strftime("%Y-%m-%d %H:%M")
        with self._lock, self._edit() as data:
            entry = data.get(name)
            new = entry is None
            if new:
                entry = data[name] = {"enabled": True, "first_seen": now, "connections": [], "access": empty_access()}
            if not entry.get("enabled", True):
                raise BotError(f"bot '{name}' is switched off in Pass Broker; ask the user to turn it back on")
            entry["last_seen"] = now
            entry["last_action"] = action + (f" on {site}" if site else "")
            if connection not in entry.setdefault("connections", []):
                entry["connections"].append(connection)
        return name, new

    def set_enabled(self, bot: str, enabled: bool) -> None:
        name = clean_bot(bot)
        with self._lock, self._edit() as data:
            entry = data.setdefault(name, {"first_seen": time.strftime("%Y-%m-%d %H:%M"), "connections": []})
            entry["enabled"] = enabled

    def forget(self, bot: str) -> bool:
        name = clean_bot(bot)
        with self._lock, self._edit() as data:
            return data.pop(name, None) is not None

    def access(self, bot: str) -> dict[str, Any]:
        entry = self._read().get(clean_bot(bot), {})
        return {**empty_access(), **entry.get("access", {})}

    def allowed(self, bot: str, kind: str, name: str = "") -> bool:
        acc = self.access(bot)
        if kind == "email_codes":
            return bool(acc["email_codes"])
        return name in acc.get(kind, [])

    def set_access(self, bot: str, access: dict[str, Any]) -> None:
        name = clean_bot(bot)
        clean = empty_access()
        for kind in KINDS:
            clean[kind] = sorted({str(x)[:120] for x in access.get(kind, []) if str(x).strip()})
        clean["email_codes"] = bool(access.get("email_codes", False))
        with self._lock, self._edit() as data:
            entry = data.setdefault(name, {"enabled": True, "first_seen": time.strftime("%Y-%m-%d %H:%M"), "connections": []})
            entry["access"] = clean
