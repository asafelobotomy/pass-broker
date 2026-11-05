"""The broker's browser on your PC: one Chromium, a separate session per bot.

By default nothing is kept on disk, and a bot's session is signed out of
everything after it sits idle (or when the bot calls end_session), because an
approved sign-in would otherwise stay usable without asking again. Password
saving and autofill are off. Every request is checked against a guard that
refuses this PC, your LAN and your tailnet.

Without a window (`headless`), Chromium runs in its new headless mode: the
same browser as the windowed one, so sites treat it the same, but nothing
appears on your desktop. The wizard's Control center shows it instead
(see preview.py).
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
import shutil
import socket
import time
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from playwright.async_api import Browser as PWBrowser
from playwright.async_api import Route, WebSocketRoute, async_playwright

from . import confine
from .browser_js import OTP_SELECTORS, USERNAME_SELECTORS  # noqa: F401  (re-exported for the broker)
from .netguard import BLOCKED_SUFFIXES, _private
from .netproxy import GuardProxy
from .redact import Redactor
from .session import BrowserError, Session  # noqa: F401

CHROMIUM_ARGS = [
    "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",  # no LAN addresses via WebRTC
    # Nothing a page asks for is granted: camera, microphone, location, notifications, clipboard,
    # USB/serial/HID/Bluetooth device pickers... are refused without a prompt.
    "--deny-permission-prompts",
    "--disable-notifications",
    "--disable-file-system",  # no FileSystem API storage
    "--disable-speech-api",
    "--disable-print-preview",
    "--no-pings",
    "--disable-save-password-bubble",
    "--password-store=basic",
    "--disable-features=PasswordManagerOnboarding,AutofillServerCommunication,AutofillEnableAccountWalletStorage",
]
VIEWPORT = {"width": 1280, "height": 900}
# Variables that make Playwright, or the Node driver under it, log every call
# (fill values included) to stderr or a file outside the scrubbed logs, open a
# debugger, or load extra code. Only where the browsers live is kept.
DEBUG_ENV = ("DEBUG", "DEBUG_FILE", "NODE_DEBUG", "NODE_OPTIONS", "PWDEBUG")
DEBUG_PREFIXES = ("PW_", "PWDEBUG", "PWTEST_", "PLAYWRIGHT_")
KEEP_ENV = ("PLAYWRIGHT_BROWSERS_PATH",)
log = logging.getLogger(__name__)


def drop_debug_env() -> list[str]:
    """Remove debugging variables before Playwright starts; returns what was removed."""
    gone = [k for k in os.environ if k not in KEEP_ENV and (k in DEBUG_ENV or k.startswith(DEBUG_PREFIXES))]
    for k in gone:
        del os.environ[k]
    return sorted(gone)
MAX_SESSIONS = 12
ALLOW_UNSANDBOXED = "PASSBROKER_ALLOW_UNSANDBOXED"


async def _no_refusal(key: str, url: str, top: bool = True) -> str | None:
    return None


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
        self._confine: Path | None = None  # the bubblewrap launcher, when used
        self.isolation = ""  # "confined", "sandboxed" or "none", once started
        self._pw = None
        self._browser: PWBrowser | None = None
        self._sessions: dict[str, Session] = {}
        self._dns: dict[str, tuple[float, bool]] = {}
        self._idle_task: asyncio.Task | None = None
        self._create = asyncio.Lock()
        self.on_signed_out: Callable[[str, str], None] = lambda key, reason: None
        # Set by the broker: why this session (`connection/bot`) may not show a URL, or None.
        # The flag says whether it's the tab's own page (True) or a frame inside it.
        self.page_refusal: Callable[[str, str, bool], Awaitable[str | None]] = _no_refusal
        # Every browser connection goes through this, which is where private addresses are
        # refused for good (redirects included); _guard below only gives earlier, clearer errors.
        self.proxy = GuardProxy(self.refuse_address)

    def refuse_address(self, host: str, ip: str) -> bool:
        """May the browser not connect to `host`, resolved to `ip`?"""
        if self._allow_private:
            return False
        return host == "localhost" or host.endswith(BLOCKED_SUFFIXES) or _private(ip)

    async def start(self) -> None:
        # Playwright talks to Chromium over a pipe: no DevTools port is opened
        # that other local programs could attach to.
        gone = drop_debug_env()
        if gone:
            log.warning("ignored debugging variables that could log secrets: %s", ", ".join(gone))
        await self.proxy.start()
        self._pw = await async_playwright().start()
        # A window needs the desktop's display socket, which the box leaves out on purpose.
        if self._headless and confine.available():
            self._confine = confine.wrapper(self._pw.chromium.executable_path, confine.private_folder())
        if not self._keep:
            self._browser = await self._sandboxed(lambda opts: self._pw.chromium.launch(**opts))
        if self._idle_s > 0 and not self._keep:
            self._idle_task = asyncio.create_task(self._idle_watch())

    async def _sandboxed(self, launch: Callable[[dict[str, object]], Awaitable[Any]]) -> Any:
        """Launch isolated as far as this system allows, never less than Chromium's own sandbox.

        1. In a bubblewrap box (confine.py) with Chromium's sandbox: a taken-over browser still
           can't touch your files or desktop session.
        2. Chromium's sandbox alone (Playwright turns it off by default): each page's renderer is
           walled off from your files and processes.
        Without either the broker refuses to start, unless PASSBROKER_ALLOW_UNSANDBOXED=1.
        """
        tries: list[tuple[str, dict[str, object]]] = []
        if self._confine is not None:
            tries.append(("confined", {"executable_path": str(self._confine), "chromium_sandbox": True}))
        tries.append(("sandboxed", {"chromium_sandbox": True}))
        problem = ""
        for level, extra in tries:
            opts = {**self._launch_opts(), **extra}
            if "executable_path" in extra:
                opts.pop("channel", None)  # the box runs that same full Chromium
            try:
                launched = await launch(opts)
                self.isolation = level
                return launched
            except Exception as e:
                problem = str(e).splitlines()[0][:160]
                log.warning("browser isolation %r unavailable here: %s", level, problem)
        if os.environ.get(ALLOW_UNSANDBOXED) == "1":
            log.warning("running the browser WITHOUT its sandbox (%s=1)", ALLOW_UNSANDBOXED)
            self.isolation = "none"
            return await launch(self._launch_opts())
        raise BrowserError(f"Chromium's sandbox can't start on this system ({problem}). It needs unprivileged user "
                           f"namespaces; see the README. To run without it anyway (not recommended): {ALLOW_UNSANDBOXED}=1")

    def _launch_opts(self) -> dict[str, object]:
        # channel="chromium" picks full Chromium's new headless mode over the
        # stripped-down headless shell, which more sites detect and block.
        opts: dict[str, object] = {"headless": self._headless, "args": CHROMIUM_ARGS, "proxy": self.proxy.settings}
        if self._headless:
            opts["channel"] = "chromium"
        return opts

    def sessions(self) -> list[tuple[str, Session]]:
        return list(self._sessions.items())

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
            pw = self._pw
            ctx = await self._sandboxed(lambda opts: pw.chromium.launch_persistent_context(
                str(folder), accept_downloads=False, viewport=VIEWPORT, service_workers="block", **opts,
            ))
        else:
            assert self._browser is not None
            ctx = await self._browser.new_context(accept_downloads=False, viewport=VIEWPORT, service_workers="block")
        await ctx.route("**/*", lambda route: self._guard(route, key))
        await ctx.route_web_socket("**/*", self._ws_guard)
        s = Session(key, ctx, self._redactor, self.blocked, lambda url: self.page_refusal(key, url, True))
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

    async def _guard(self, route: Route, key: str) -> None:
        """Block every request (pages, frames, scripts, XHR) to this PC, LAN or tailnet,
        page loads (the top frame, popups included) outside the bot's site list, and
        any page or frame it may not see."""
        req = route.request
        parts = urlsplit(req.url)
        if parts.scheme in ("http", "https", "ws", "wss") and await self.blocked(parts.hostname or ""):
            await route.abort("blockedbyclient")
            return
        if req.is_navigation_request():
            why = await self.page_refusal(key, req.url, req.frame.parent_frame is None)
            if why:
                if (s := self._sessions.get(key)) is not None:
                    s.refused = why  # so the bot's click or key press can say why nothing happened
                # "aborted" cancels the load as if it never happened: the tab stays on the page it was on.
                await route.abort("aborted")
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
        """Close everything, step by step: Chromium may already be gone (killed with the
        service, or crashed), and that mustn't stop the rest of the shutdown."""
        if self._idle_task:
            self._idle_task.cancel()
        closers = [s.ctx.close for s in self._sessions.values()]
        self._sessions.clear()
        if self._browser:
            closers.append(self._browser.close)
        if self._pw:
            closers.append(self._pw.stop)
        closers.append(self.proxy.stop)
        if self._confine is not None:
            shutil.rmtree(self._confine.parent, ignore_errors=True)
        for close in closers:
            try:
                await close()
            except Exception as e:
                log.info("browser already closed: %s", type(e).__name__)
