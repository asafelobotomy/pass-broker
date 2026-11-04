"""The broker's browser on your PC: one Chromium, a separate session per bot.

By default nothing is kept on disk, and a bot's session is signed out of
everything after it sits idle (or when the bot calls end_session), because an
approved sign-in would otherwise stay usable without asking again. Password
saving and autofill are off. Every request is checked against a guard that
refuses this PC, your LAN and your tailnet.
"""

from __future__ import annotations

import asyncio
import re
import socket
import time
from collections.abc import Callable
from pathlib import Path
from urllib.parse import urlsplit

from playwright.async_api import Browser as PWBrowser
from playwright.async_api import Route, WebSocketRoute, async_playwright

from .browser_js import OTP_SELECTORS, USERNAME_SELECTORS  # noqa: F401  (re-exported for the broker)
from .netguard import BLOCKED_SUFFIXES, _private
from .redact import Redactor
from .session import BrowserError, Session  # noqa: F401

CHROMIUM_ARGS = [
    "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",  # no LAN addresses via WebRTC
    "--disable-save-password-bubble",
    "--password-store=basic",
    "--disable-features=PasswordManagerOnboarding,AutofillServerCommunication,AutofillEnableAccountWalletStorage",
]
VIEWPORT = {"width": 1280, "height": 900}
MAX_SESSIONS = 12


class Browser:
    def __init__(
        self,
        profile_dir: Path,
        redactor: Redactor,
        headless: bool = False,
        keep_sessions: bool = False,
        idle_minutes: float = 15,
        allow_private: bool = False,
    ) -> None:
        self._profile = profile_dir
        self._redactor = redactor
        self._headless = headless
        self._keep = keep_sessions
        self._idle_s = idle_minutes * 60
        self._allow_private = allow_private
        self._pw = None
        self._browser: PWBrowser | None = None
        self._sessions: dict[str, Session] = {}
        self._dns: dict[str, tuple[float, bool]] = {}
        self._idle_task: asyncio.Task | None = None
        self._create = asyncio.Lock()
        self.on_signed_out: Callable[[str, str], None] = lambda key, reason: None

    async def start(self) -> None:
        # Playwright talks to Chromium over a pipe: no DevTools port is opened
        # that other local programs could attach to.
        self._pw = await async_playwright().start()
        if not self._keep:
            self._browser = await self._pw.chromium.launch(headless=self._headless, args=CHROMIUM_ARGS)
        if self._idle_s > 0 and not self._keep:
            self._idle_task = asyncio.create_task(self._idle_watch())

    async def session(self, key: str) -> Session:
        """The session for one bot (`connection/bot`), created on first use."""
        async with self._create:
            s = self._sessions.get(key)
            if s is not None and not s.ctx.pages and s.used:
                s = None  # its window was closed
            if s is None:
                if len(self._sessions) >= MAX_SESSIONS:
                    raise BrowserError("too many bots have browser sessions open; end some with end_session")
                s = await self._new_session(key)
                self._sessions[key] = s
            return s

    async def _new_session(self, key: str) -> Session:
        assert self._pw is not None
        if self._keep:
            folder = self._profile / re.sub(r"[^\w.-]", "_", key)
            folder.mkdir(parents=True, exist_ok=True, mode=0o700)
            ctx = await self._pw.chromium.launch_persistent_context(
                str(folder), headless=self._headless, accept_downloads=False, viewport=VIEWPORT, args=CHROMIUM_ARGS,
                service_workers="block",
            )
        else:
            assert self._browser is not None
            ctx = await self._browser.new_context(accept_downloads=False, viewport=VIEWPORT, service_workers="block")
        await ctx.route("**/*", self._guard)
        await ctx.route_web_socket("**/*", self._ws_guard)
        s = Session(key, ctx, self._redactor, self.blocked)
        await s.open()
        return s

    async def end_session(self, key: str, reason: str = "ended") -> bool:
        """Sign one bot out of everything by closing its session."""
        s = self._sessions.pop(key, None)
        if s is None:
            return False
        async with s.lock:
            await s.ctx.close()
        self.on_signed_out(key, reason)
        return True

    async def reset_sessions(self) -> None:
        for key in list(self._sessions):
            await self.end_session(key, "reset")
        self._dns.clear()

    async def blocked(self, host: str) -> bool:
        if self._allow_private:
            return False
        host = host.lower().rstrip(".")
        if not host or host == "localhost" or host.endswith(BLOCKED_SUFFIXES):
            return True
        now = time.monotonic()
        cached = self._dns.get(host)
        if cached and cached[0] > now:
            return cached[1]
        try:
            infos = await asyncio.get_running_loop().getaddrinfo(host, None, type=socket.SOCK_STREAM)
            blocked = any(_private(i[4][0]) for i in infos)
        except (OSError, ValueError):
            blocked = False  # unresolvable: Chromium will fail it anyway
        self._dns[host] = (now + 60, blocked)
        return blocked

    async def _guard(self, route: Route) -> None:
        """Block every request (pages, frames, scripts, XHR) to this PC, LAN or tailnet."""
        parts = urlsplit(route.request.url)
        if parts.scheme in ("http", "https", "ws", "wss") and await self.blocked(parts.hostname or ""):
            await route.abort("blockedbyclient")
            return
        await route.continue_()

    async def _ws_guard(self, ws: WebSocketRoute) -> None:
        """WebSockets bypass route(); check them too (they have no CORS to protect local services)."""
        if await self.blocked(urlsplit(ws.url).hostname or ""):
            await ws.close(code=1008, reason="blocked by Pass Broker")
            return
        ws.connect_to_server()

    async def _idle_watch(self) -> None:
        while True:
            await asyncio.sleep(min(30, max(1, self._idle_s / 4)))
            now = time.monotonic()
            for key, s in list(self._sessions.items()):
                if s.used and now - s.last_use > self._idle_s and not s.lock.locked():
                    await self.end_session(key, "idle")

    async def stop(self) -> None:
        if self._idle_task:
            self._idle_task.cancel()
        for s in list(self._sessions.values()):
            await s.ctx.close()
        self._sessions.clear()
        if self._browser:
            await self._browser.close()
        if self._pw:
            await self._pw.stop()
