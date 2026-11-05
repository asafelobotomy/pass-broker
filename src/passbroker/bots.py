"""Self-reported bot names, with an on/off switch for each.

Every tool call carries the name of the bot making it (Grok Bot runs several
bots on one shared connector). The name is a label the bot gives itself, not
proof: a misbehaving or prompt-injected bot can claim any name. It still lets
approvals, grants and the audit log tell honest bots apart, and lets you turn
one off by name without revoking the connection every bot shares.

Each bot also has an access list: which logins, unlock actions, devices and
keys it may use, and whether it may use email codes. A new bot starts with
nothing (it can only browse in its own session) until you grant it more.
It also says whether the bot may make its own accounts (accounts.py), whether it may see personal details on pages (masked by
default, see pii.py) and, optionally, the only sites it may open.
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
HOST_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?)+")
MAX_SITES = 100


def empty_access() -> dict[str, Any]:
    return {
        "logins": [], "unlock": [], "devices": [], "keys": [], "email_codes": False, "create_logins": False,
        "personal_details": False, "sites_limited": False, "sites": [], "blocked_pages": [],
    }


def clean_page(text: str) -> str | None:
    """`https://www.Amazon.co.uk/gp/Account?x=1` -> `www.amazon.co.uk/gp/account`; None if invalid.

    A host, then optionally a path prefix in which `*` matches anything.
    """
    rest = str(text).strip().split("://", 1)[-1].split("?", 1)[0].split("#", 1)[0]
    host_part, slash, path = rest.partition("/")
    host = clean_site(host_part)
    if host is None or not re.fullmatch(r"[\w./~*%+:@!$&'()=,;-]*", path):
        return None
    path = path.lower().rstrip("/") if path.strip("/*") else ""
    return host + ("/" + path if path else "")


def _list(value: Any) -> list[Any]:
    return re.split(r"[\s,]+", value) if isinstance(value, str) else list(value or [])


def clean_site(text: str) -> str | None:
    """`https://www.Example.com/path` -> `www.example.com`; None if it isn't a hostname."""
    host = str(text).strip().lower().split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0].strip(".")
    host = host.removeprefix("*.")
    return host if HOST_RE.fullmatch(host) and len(host) <= 253 else None


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
            conns = entry.setdefault("connections", [])
            if conns and connection not in conns:
                # Grants go by bot name, so the name stays with the connection that first used it:
                # otherwise any other connection could claim to be this bot and get its logins.
                raise BotError(f"the bot name '{name}' belongs to another connection; pick another name, "
                               "or ask the user to forget that bot in Pass Broker")
            if not entry.get("enabled", True):
                raise BotError(f"bot '{name}' is switched off in Pass Broker; ask the user to turn it back on")
            entry["last_seen"] = now
            entry["last_action"] = action + (f" on {site}" if site else "")
            if not conns:
                conns.append(connection)
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
            # A lone string is one name, not a list of letters.
            items = access.get(kind) or []
            items = [items] if isinstance(items, str) else list(items)
            clean[kind] = sorted({str(x)[:120] for x in items if str(x).strip()})
        clean["email_codes"] = bool(access.get("email_codes", False))
        clean["create_logins"] = bool(access.get("create_logins", False))
        clean["personal_details"] = bool(access.get("personal_details", False))
        clean["sites_limited"] = bool(access.get("sites_limited", False))
        sites, pages = _list(access.get("sites")), _list(access.get("blocked_pages"))
        bad = [s for s in sites if str(s).strip() and clean_site(s) is None]
        bad += [s for s in pages if str(s).strip() and clean_page(s) is None]
        if bad:
            raise BotError(f"not a website address: {str(bad[0])[:60]}")
        clean["sites"] = sorted({h for s in sites if (h := clean_site(s))})[:MAX_SITES]
        clean["blocked_pages"] = sorted({h for s in pages if (h := clean_page(s))})[:MAX_SITES]
        with self._lock, self._edit() as data:
            entry = data.setdefault(name, {"enabled": True, "first_seen": time.strftime("%Y-%m-%d %H:%M"), "connections": []})
            entry["access"] = clean

    def record_created(self, bot: str, title: str, site: str) -> None:
        """A bot made a login: it may use it, and the account is listed under the bot."""
        name = clean_bot(bot)
        with self._lock, self._edit() as data:
            entry = data.setdefault(name, {"enabled": True, "first_seen": time.strftime("%Y-%m-%d %H:%M"), "connections": []})
            acc = entry.setdefault("access", empty_access())
            acc["logins"] = sorted({*acc.get("logins", []), title})
            entry.setdefault("created", []).append({"title": title, "site": site, "at": time.strftime("%Y-%m-%d %H:%M")})

    def created_today(self, bot: str) -> int:
        today = time.strftime("%Y-%m-%d")
        made = self._read().get(clean_bot(bot), {}).get("created", [])
        return sum(1 for c in made if str(c.get("at", "")).startswith(today))
