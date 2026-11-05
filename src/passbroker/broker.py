"""The broker: the only code that ever holds a secret and a page at once.

The core lives here (permissions, approvals, reading secrets); signing in,
unlocking files, encrypting text, device actions and email codes live in
mixins next door so each stays readable.
"""

from __future__ import annotations

import asyncio
import re
from collections.abc import Callable
from typing import Any

from .accounts import AccountSettings, AccountsMixin
from .approvals import Approver, GrantCache
from .audit import AuditLog
from .bots import Bots
from .browser import Browser
from .devices import DevicesMixin, DeviceStore
from .files import FilesMixin
from .fills import FillsMixin
from .keys import KeyStore
from .mailcode import MailMixin, MailSettings
from .policy import PolicyMixin
from .redact import Redactor, clean
from .signup import SignupMixin
from .unlock import Unlockers
from .vault import Backend, Login, VaultError


class BrokerError(Exception):
    """A refusal or failure. Messages are safe to show to the model."""


def plain(text: str, limit: int = 120) -> str:
    """Text from a bot or a file name, made safe for a notification: one line, no
    markup, and no invisible or text-reversing characters that could make the
    request read differently from what it is."""
    return re.sub(r"[\x00-\x1f\x7f<>&]", " ", clean(text or "")).strip()[:limit]


class Broker(FillsMixin, AccountsMixin, SignupMixin, FilesMixin, DevicesMixin, MailMixin, PolicyMixin):
    def __init__(
        self,
        backend: Backend,
        browser: Browser,
        approver: Approver,
        grants: GrantCache,
        audit: AuditLog,
        redactor: Redactor,
        allow_http_localhost: bool = False,
        allow_subdomains: bool = False,
        show_usernames: bool = False,
        unlockers: Unlockers | None = None,
        bots: Bots | None = None,
        keys: KeyStore | None = None,
        devices: DeviceStore | None = None,
        mail: MailSettings | None = None,
        account_settings: Callable[[], AccountSettings] | None = None,
    ) -> None:
        self.backend = backend
        self.browser = browser
        self.approver = approver
        self.grants = grants
        self.audit = audit
        self.redactor = redactor
        self.allow_http_localhost = allow_http_localhost
        self.allow_subdomains = allow_subdomains
        self.show_usernames = show_usernames
        self.unlockers = unlockers
        self.bots = bots
        self.keys = keys
        self.devices = devices
        self.mail = mail
        self.account_settings = account_settings  # re-read on use: set up without a restart
        self._fresh: dict[tuple[str, str], float] = {}
        self._alias_lock = asyncio.Lock()  # one email alias per bot, even when two calls race
        if browser is not None:
            browser.page_refusal = self.page_refusal

    # ---- who may do what --------------------------------------------------------------

    def _permit(self, client: str, kind: str, name: str = "") -> None:
        """Refuse unless this bot was granted `name` (a login, action, device or key)."""
        conn, _, bot = client.partition("/")
        if not bot or self.bots is None:
            return  # local callers without bot names (tests, scripts)
        if not self.bots.allowed(bot, kind, name):
            what = {"logins": f"the login '{name}'", "unlock": f"the unlock action '{name}'", "devices": f"the device action '{name}'",
                    "keys": f"the key '{name}'", "email_codes": "email codes"}[kind]
            self.audit.record("not_permitted", client=client, kind=kind, name=name)
            raise BrokerError(f"bot '{bot}' isn't allowed to use {what}; ask the user to grant it in Pass Broker")

    def _visible(self, client: str, logins: list[Login]) -> list[Login]:
        conn, _, bot = client.partition("/")
        if not bot or self.bots is None:
            return logins
        granted = set(self.bots.access(bot)["logins"])
        return [l for l in logins if l.title in granted]

    async def list_logins(self, client: str, query: str = "") -> list[dict[str, Any]]:
        logins = self._visible(client, await asyncio.to_thread(self.backend.list_logins))
        q = query.lower().strip()
        if q:
            logins = [l for l in logins if q in l.title.lower() or any(q in u.lower() for u in l.urls)]
        self.audit.record("list_logins", client=client, query=query, count=len(logins))
        # Usernames are masked: the model only needs to tell logins apart.
        return [l.public(mask=not self.show_usernames) for l in logins]

    async def end_session(self, client: str) -> dict[str, Any]:
        ended = await self.browser.end_session(client, "ended by the bot")
        self.audit.record("end_session", client=client, ended=ended)
        return {"status": "signed out of everything" if ended else "no session was open"}

    # ---- approvals and secrets ------------------------------------------------------

    async def _approve(
        self, client: str, login: Login, scope: str, action: str, what: str = "", details: str = "", reason: str = ""
    ) -> None:
        key = (client, login.handle, scope, action)
        if self.grants.check(key):
            self.audit.record("approved_cached", client=client, item=login.title, host=scope, action=action)
            return
        verb = {
            "login": f"sign in to {scope}",
            "totp": f"enter a 2FA code for {scope}",
            "email_code": f"enter an emailed code for {scope}",
        }.get(action, what)
        conn, _, bot = client.partition("/")
        asker = f"{bot} (via {conn})" if bot else client
        why = plain(reason)
        ok = await asyncio.to_thread(
            self.approver.ask,
            plain(f"{asker} wants to {verb}", 160),
            (details or f"Site: {scope}\n")
            + f"Item: {plain(login.title, 80)}\n"
            + (f"Bot's reason: {why}\n" if why else "")
            + (f"Bot name is self-reported by {conn}'s bots.\n" if bot else "")
            + "Allow only if you asked for this.",
        )
        self.audit.record("approval", client=client, item=login.title, host=scope, action=action, allowed=ok, reason=why)
        if not ok:
            raise BrokerError("refused: you denied this on your desktop, or nobody answered in time")
        self.grants.grant(key)

    async def _secret(self, client: str, login: Login, field: str, purpose: str) -> str:
        reason = f"pass-broker for {client}: {field} for {login.title[:60]} ({purpose[:80]})"
        try:
            return await asyncio.to_thread(self.backend.secret, login.handle, field, reason)  # type: ignore[arg-type]
        except VaultError as e:
            raise BrokerError(str(e)) from None

    async def _item(self, title: str, owner: str) -> Login:
        """The one vault item called `title` (for unlock actions, keys, devices, mail)."""
        matches = [l for l in await asyncio.to_thread(self.backend.list_logins) if l.title == title]
        if len(matches) != 1:
            raise BrokerError(f"the vault item for '{owner}' {'is missing' if not matches else 'has a duplicate title'}; ask the user to fix it")
        return matches[0]

    def _login(self, client: str, handle: str) -> Login:
        try:
            login = self.backend.get(handle)
        except VaultError as e:
            raise BrokerError(str(e)) from None
        self._permit(client, "logins", login.title)
        if not login.urls:
            raise BrokerError(f"'{login.title}' has no saved website, so it can't be filled anywhere")
        return login
