"""One bot's browser session: its own cookies, tab and lock.

Each bot (connection/bot name) gets a separate browser context, so one bot
can't use a site another bot signed in to. The model drives it only through
these redacted primitives; there is deliberately no "evaluate JavaScript" tool.
"""

from __future__ import annotations

import asyncio
import secrets
import time
from collections.abc import Awaitable, Callable
from typing import Any
from urllib.parse import urlsplit

from playwright.async_api import BrowserContext, Frame, Locator, Page
from playwright.async_api import TimeoutError as PWTimeout

from .browser_js import SENSITIVE_CSS, SNAPSHOT_JS, VISIBLE_TEXT_JS
from .netproxy import BLOCKED_HEADER
from .pii import PERSONAL_FIELDS, SCREEN_TEXT
from .redact import Redactor

IS_SENSITIVE_JS = """el => {
  const t = (el.getAttribute('type') || '').toLowerCase();
  const ac = el.getAttribute('autocomplete') || '';
  return el.hasAttribute('data-pb-secret') || t === 'password' || el.maxLength === 1 ||
         /(one-time-code|current-password|new-password|^cc-)/i.test(ac);
}"""


class BrowserError(Exception):
    pass


class Session:
    def __init__(
        self,
        key: str,
        ctx: BrowserContext,
        redactor: Redactor,
        blocked: Callable[[str], Awaitable[bool]],
        refusal: Callable[[str], Awaitable[str | None]] | None = None,
    ) -> None:
        self.key = key
        self._refusal = refusal
        self.ctx = ctx
        self._redactor = redactor
        self._blocked = blocked
        self._page: Page | None = None
        self.last_use = time.monotonic()
        self.used = False
        self.lock = asyncio.Lock()
        self.refused: str | None = None  # set by the browser when it cancels a page this bot may not see
        ctx.on("page", self._on_page)

    def _on_page(self, page: Page) -> None:
        self._page = page

    async def open(self) -> None:
        self._page = self.ctx.pages[0] if self.ctx.pages else await self.ctx.new_page()

    def touch(self) -> None:
        self.last_use = time.monotonic()
        self.used = True

    @property
    def page(self) -> Page:
        if self._page is None or self._page.is_closed():
            live = [p for p in self.ctx.pages if not p.is_closed()]
            if not live:
                raise BrowserError("no open tab")
            self._page = live[-1]
        return self._page

    def frames(self) -> list[Frame]:
        return [f for f in self.page.frames if not f.is_detached()]

    # ---- model-facing primitives -------------------------------------------------

    async def navigate(self, url: str) -> dict[str, Any]:
        if not url.lower().startswith(("https://", "http://")):
            raise BrowserError("only http and https URLs can be opened")
        self.touch()
        host = urlsplit(url).hostname or ""
        if await self._blocked(host):
            raise BrowserError(f"blocked: {host or 'that address'} is on this PC, your LAN or your tailnet")
        why = self._refusal and await self._refusal(url)
        if why:
            raise BrowserError(f"not allowed: {why}; ask the user to change it in Pass Broker")
        try:
            resp = await self.page.goto(url, wait_until="domcontentloaded", timeout=30000)
        except PWTimeout:
            raise BrowserError("page took too long to load") from None
        except Exception as e:
            if "ERR_ABORTED" in str(e):
                raise BrowserError("the page didn't load: it may have redirected to a site or page this bot may not open") from None
            if "ERR_TUNNEL_CONNECTION_FAILED" in str(e) or "ERR_PROXY_CONNECTION_FAILED" in str(e):
                raise BrowserError("blocked: that page is (or redirects to) this PC, your LAN or your tailnet, or it can't be reached") from None
            if "ERR_BLOCKED_BY_CLIENT" in str(e):
                raise BrowserError("blocked: that page redirected to this PC, your LAN or your tailnet") from None
            raise
        if resp is not None and resp.headers.get(BLOCKED_HEADER.lower()):
            raise BrowserError("blocked: that page is (or redirects to) this PC, your LAN or your tailnet")
        # The site list and blocked pages go by the full address, which a redirect can change
        # unseen: check where the tab ended up before returning anything from it.
        await self.check_tab()
        return {"url": self.page.url, "status": resp.status if resp else None, "title": await self.page.title()}

    def _outcome(self, result: dict[str, Any]) -> dict[str, Any]:
        if self.refused:
            result["blocked"] = f"{self.refused}, so it didn't open; the tab stayed where it was"
            self.refused = None
        return result

    async def check_tab(self) -> None:
        """Leave a page the bot may not see. Sites that change pages without loading one
        (single-page apps) slip past the request guard; this catches them on the next look."""
        if not self._refusal:
            return
        why = await self._refusal(self.page.url)
        if not why:
            return
        try:
            await self.page.go_back(wait_until="domcontentloaded", timeout=8000)
        except Exception:
            pass
        if await self._refusal(self.page.url):
            await self.page.goto("about:blank")
        raise BrowserError(f"not allowed: {why}; went back to the previous page")

    async def snapshot(self) -> dict[str, Any]:
        self.touch()
        await self.check_tab()
        frames = []
        for idx, frame in enumerate(self.frames()):
            try:
                data = await frame.evaluate(SNAPSHOT_JS, f"f{idx}:")
            except Exception:
                continue
            if idx and not data["elements"] and not data["text"]:
                continue
            frames.append(data)
        return self._redactor.scrub_obj({"url": self.page.url, "frames": frames})

    def _ref(self, ref: str) -> Locator:
        try:
            idx = int(ref.split(":", 1)[0].removeprefix("f"))
            frame = self.frames()[idx]
        except (ValueError, IndexError):
            raise BrowserError("unknown ref; take a new snapshot") from None
        return frame.locator(f'[data-pb-ref="{ref}"]')

    async def click(self, ref: str) -> dict[str, Any]:
        self.touch()
        loc = self._ref(ref)
        if not await loc.count():
            raise BrowserError("element is gone; take a new snapshot")
        self.refused = None
        await loc.first.click(timeout=10000)
        await self.settle()
        await self.check_tab()
        return self._outcome({"url": self.page.url, "title": await self.page.title()})

    async def type_text(self, ref: str, text: str, submit: bool = False) -> dict[str, Any]:
        """The model's own text only: never into password or code fields, never a known secret."""
        self.touch()
        loc = self._ref(ref)
        if not await loc.count():
            raise BrowserError("element is gone; take a new snapshot")
        if await loc.first.evaluate(IS_SENSITIVE_JS):
            raise BrowserError("refused: that's a password or code field; use fill_login, fill_totp or fill_email_code")
        if self._redactor.contains_secret(text):
            raise BrowserError("refused: that text contains a secret the broker holds")
        self.refused = None
        await loc.first.fill(text, timeout=10000)
        if submit:
            await loc.first.press("Enter")
            await self.settle()
            await self.check_tab()
        return self._outcome({"url": self.page.url})

    async def press(self, key: str) -> dict[str, Any]:
        self.touch()
        self.refused = None
        await self.page.keyboard.press(key)
        await self.settle()
        await self.check_tab()
        return self._outcome({"url": self.page.url})

    async def screenshot(self, hide_personal: bool = True) -> bytes:
        self.touch()
        await self.check_tab()
        return await self.masked_capture(hide_personal=hide_personal)

    async def masked_capture(self, jpeg_quality: int | None = None, hide_personal: bool = False) -> bytes:
        """The tab with secret fields blacked out, refused while a secret shows as text.

        Doesn't count as use, so the live view never keeps an idle session signed in.
        """
        for frame in self.frames():
            try:
                text = await frame.evaluate(VISIBLE_TEXT_JS)
            except Exception:
                continue
            if self._redactor.contains_secret(text):
                raise BrowserError("screenshot withheld: the page is showing a secret value as text")
        masks = [f.locator(SENSITIVE_CSS) for f in self.frames()]
        if hide_personal:
            for f in self.frames():
                masks += [f.locator(PERSONAL_FIELDS), f.get_by_text(SCREEN_TEXT)]
        fmt: dict[str, Any] = {"type": "jpeg", "quality": jpeg_quality} if jpeg_quality else {}
        return await self.page.screenshot(mask=masks, mask_color="#000000", animations="disabled", caret="hide", **fmt)

    # ---- broker-only primitives --------------------------------------------------

    async def settle(self, page: Page | None = None) -> None:
        page = page or self.page
        try:
            await page.wait_for_load_state("domcontentloaded", timeout=8000)
        except PWTimeout:
            pass
        await page.wait_for_timeout(800)

    async def find(self, selectors: list[str]) -> tuple[Frame, Locator] | None:
        for frame in self.frames():
            for sel in selectors:
                loc = frame.locator(sel)
                if await loc.count():
                    return frame, loc.first
        return None

    async def find_many(self, selector: str, minimum: int) -> tuple[Frame, Locator] | None:
        """All matches in the first frame that has at least `minimum` of them."""
        for frame in self.frames():
            loc = frame.locator(selector)
            if await loc.count() >= minimum:
                return frame, loc
        return None

    async def fill_pinned(self, frame: Frame, loc: Locator, value: str, verify: Callable[[Frame], None]) -> Locator:
        """Fill a secret into exactly the document that passed the origin check.

        The field is tagged with a random nonce, the frame's origin is checked
        again, and the fill targets the nonce. If the frame navigates anywhere
        in between, the new document has no such element and nothing is filled.
        """
        nonce = secrets.token_hex(12)
        verify(frame)
        await loc.evaluate("(el, n) => { el.setAttribute('data-pb-secret', ''); el.setAttribute('data-pb-nonce', n); }", nonce)
        verify(frame)
        pinned = frame.locator(f'[data-pb-nonce="{nonce}"]')
        try:
            await pinned.fill(value, timeout=3000)
        except PWTimeout:
            raise BrowserError("the page changed while signing in; nothing was filled") from None
        verify(frame)
        return pinned

    async def fill_boxes(self, frame: Frame, loc: Locator, value: str, verify: Callable[[Frame], None]) -> Locator:
        """For one-digit-per-box code fields: every box is tagged and pinned."""
        nonce = secrets.token_hex(12)
        verify(frame)
        count = await loc.count()
        for i in range(count):
            await loc.nth(i).evaluate("(el, n) => { el.setAttribute('data-pb-secret', ''); el.setAttribute('data-pb-nonce', n); }", f"{nonce}-{i}")
        verify(frame)
        for i, ch in enumerate(value[:count]):
            box = frame.locator(f'[data-pb-nonce="{nonce}-{i}"]')
            try:
                await box.fill(ch, timeout=3000)
            except PWTimeout:
                raise BrowserError("the page changed while entering the code; stopped") from None
            verify(frame)
        return frame.locator(f'[data-pb-nonce="{nonce}-{min(len(value), count) - 1}"]')

    async def submit(self, frame: Frame, loc: Locator, verify: Callable[[Frame], None]) -> None:
        verify(frame)
        page = frame.page
        try:
            async with page.expect_navigation(timeout=8000):
                await loc.press("Enter", timeout=3000)
        except PWTimeout:
            pass
        await self.settle(page)

    async def clear_secrets(self, page: Page | None = None) -> None:
        for frame in [f for f in (page or self.page).frames if not f.is_detached()]:
            loc = frame.locator("[data-pb-secret]")
            try:
                for i in range(await loc.count()):
                    await loc.nth(i).fill("", timeout=2000)
            except Exception:
                continue
