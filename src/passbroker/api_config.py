"""`passbroker api` commands for configuration: pairing, bot access, keys, devices, email codes."""

from __future__ import annotations

import json
import os
import sys
from typing import Any

from . import ops


def c_pair(a) -> dict[str, Any]:
    path = ops.dirs()[0] / "pairing"
    if a.close:
        path.unlink(missing_ok=True)
        return {"open": False}
    path.touch(mode=0o600)
    os.utime(path)
    return {"open": True, "minutes": 10}


def c_bot_access(a) -> dict[str, Any]:
    """Set one bot's access from JSON on stdin: logins, unlock, devices, keys, email_codes,
    personal_details, sites_limited, sites and blocked_pages."""
    data = json.loads(sys.stdin.readline() or "{}")
    if not isinstance(data, dict):
        raise ops.OpError("access must be a JSON object")
    from .bots import BotError

    try:
        ops.bots_store().set_access(a.name, data)
    except BotError as e:
        raise ops.OpError(str(e)) from None
    return {"access": ops.bots_store().access(a.name)}


def _store(kind: str):
    from .devices import DeviceStore
    from .keys import KeyStore

    return {"keys": KeyStore, "devices": DeviceStore}[kind](ops.dirs()[0] / f"{kind}.json")


def c_config(a) -> dict[str, Any]:
    from dataclasses import asdict as _asdict

    from .mailcode import MailSettings

    mail = MailSettings.load(ops.dirs()[0] / "mail.json")
    return {"keys": [_asdict(k) for k in _store("keys").load()], "devices": [_asdict(d) for d in _store("devices").load()], "mail": _asdict(mail)}


def c_config_add(a) -> dict[str, Any]:
    """Add or replace one key or device action, as JSON on stdin."""
    from .devices import Device
    from .keys import Key

    data = json.loads(sys.stdin.readline() or "{}")
    if not isinstance(data, dict):
        raise ops.OpError("expected a JSON object")
    cls = {"keys": Key, "devices": Device}[a.kind]
    fields = set(cls.__dataclass_fields__) - {"extra"}
    pinned = _store(a.kind).add(cls(**{k: v for k, v in data.items() if k in fields}))
    return {"pinned": pinned or ""}


def c_config_remove(a) -> dict[str, Any]:
    if not _store(a.kind).remove(a.name):
        raise ops.OpError(f"nothing named '{a.name}'")
    return {}


def c_mail_set(a) -> dict[str, Any]:
    from .mailcode import MailSettings

    data = json.loads(sys.stdin.readline() or "{}")
    fields = set(MailSettings.__dataclass_fields__)
    path = ops.dirs()[0] / "mail.json"
    old = MailSettings.load(path)
    new = MailSettings(**{k: v for k, v in data.items() if k in fields and k != "cert_pem"})
    if (new.host, new.port) == (old.host, old.port) and not data.get("repin"):
        new.cert_pem = old.cert_pem  # keep the pin unless Bridge moved or you asked to re-pin
    try:
        return {"pinned": new.save(path)}
    except ValueError as e:
        raise ops.OpError(str(e)) from None


def add_parsers(add) -> None:
    add("pair", c_pair, (("--close",), {"action": "store_true"}))
    add("bot-access", c_bot_access, (("name",), {}))
    add("config", c_config)
    add("config-add", c_config_add, (("kind",), {"choices": ["keys", "devices"]}))
    add("config-remove", c_config_remove, (("kind",), {"choices": ["keys", "devices"]}), (("name",), {}))
    add("mail-set", c_mail_set)
