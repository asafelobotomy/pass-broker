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
    from .oauth import PAIRING_WINDOW

    path.touch(mode=0o600)
    os.utime(path)
    return {"open": True, "minutes": PAIRING_WINDOW // 60}


def c_bot_access(a) -> dict[str, Any]:
    """Set one bot's access from JSON on stdin: logins, unlock, devices, keys, email_codes,
    create_logins, personal_details, sites_limited, sites and blocked_pages."""
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

    from . import accounts, botmail, mailadmin
    from .mailcode import MailSettings

    mail = MailSettings.load(ops.dirs()[0] / "mail.json")
    bots = ops.bots_store().list()
    made = [{"bot": b["name"], **c} for b in bots for c in b.get("created", [])]
    emails = [{"bot": b["name"], **b["email"]} for b in bots if b.get("email")]
    admin = mailadmin.load_state(ops.dirs()[0] / "mailadmin.json")
    return {"mail_admin": {k: admin[k] for k in ("admin", "since", "trusted")}, "keys": [_asdict(k) for k in _store("keys").load()], "devices": [_asdict(d) for d in _store("devices").load()], "mail": _asdict(mail),
            "accounts": {**_asdict(accounts.load()), "created": sorted(made, key=lambda c: c.get("at", ""), reverse=True), "emails": emails,
                         "rule_text": botmail.RULE}}


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


def c_mail_bots_folder(a) -> dict[str, Any]:
    """Make the Bots folder through Bridge; returns the Proton Mail rule that fills it."""
    from . import botmail

    return botmail.setup(a.vault, ops.dirs()[0] / "mail.json", a.pass_cli)


def c_accounts_rule(a) -> dict[str, Any]:
    """You added the bot-mail rule yourself (done), or want a mail bot asked again (reset)."""
    import time
    from dataclasses import asdict as _asdict

    from . import accounts

    done = a.state == "done"
    return _asdict(accounts.change({"rule": "done" if done else "", "rule_by": "you" if done else "",
                                    "rule_at": time.strftime("%Y-%m-%d %H:%M") if done else ""}))


def c_mail_admin(a) -> dict[str, Any]:
    """Remove the mail admin (--remove) or set your trusted recipients (--trusted, comma separated)."""
    from . import jsonfile, mailadmin
    from .mailbox import MailboxError, addresses

    path = ops.dirs()[0] / "mailadmin.json"
    trusted = None
    if a.trusted is not None:
        try:
            trusted = sorted({x.lower() for x in addresses(a.trusted)})[:50] if a.trusted.strip() else []
        except MailboxError as e:
            raise ops.OpError(str(e)) from None

    def apply(data: Any) -> dict[str, Any]:
        state = mailadmin.load_state(None) | (data if isinstance(data, dict) else {})
        if a.remove:
            state.update(admin="", since="")
        if trusted is not None:
            state["trusted"] = trusted
        return state

    # Under the file's lock: the broker counts sends and changes in the same file.
    state = jsonfile.update(path, apply, {}) if a.remove or trusted is not None else mailadmin.load_state(path)
    return {"admin": state["admin"], "since": state["since"], "trusted": state["trusted"]}


def c_accounts_setup(a) -> dict[str, Any]:
    """Make the Bot Accounts vault and give the broker's agent editor access there (as you)."""
    from . import accounts

    try:
        return accounts.setup(a.vault, a.agent, a.main_vault, a.pass_cli)
    finally:
        if not a.stay_signed_in and ops.session_kind(a.pass_cli)[0] == "user":
            ops.logout(a.pass_cli)


def c_accounts_off(a) -> dict[str, Any]:
    """Stop bots making accounts. The vault, its logins and the agent's access stay (remove them in Proton Pass)."""
    from dataclasses import asdict as _asdict

    from . import accounts

    return _asdict(accounts.change({"enabled": False}))


def add_parsers(add) -> None:
    from .defaults import VAULT

    add("accounts-setup", c_accounts_setup, (("--vault",), {"default": "Bot Accounts"}), (("--agent",), {"default": "passbroker"}),
        (("--main-vault",), {"default": VAULT}), (("--stay-signed-in",), {"action": "store_true"}))
    add("accounts-off", c_accounts_off)
    add("accounts-rule", c_accounts_rule, (("state",), {"choices": ["done", "reset"]}))
    add("pair", c_pair, (("--close",), {"action": "store_true"}))
    add("bot-access", c_bot_access, (("name",), {}))
    add("config", c_config)
    add("config-add", c_config_add, (("kind",), {"choices": ["keys", "devices"]}))
    add("config-remove", c_config_remove, (("kind",), {"choices": ["keys", "devices"]}), (("name",), {}))
    add("mail-set", c_mail_set)
    add("mail-admin", c_mail_admin, (("--remove",), {"action": "store_true"}), (("--trusted",), {"default": None}))
    add("mail-bots-folder", c_mail_bots_folder, (("--vault",), {"default": VAULT}))
