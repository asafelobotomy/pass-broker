"""Signing in: filling usernames, passwords and codes into the right page only."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING, Any

from playwright.async_api import Frame, Locator

from .browser_js import OTP_SELECTORS, USERNAME_SELECTORS
from .origin import host_of, origin_allowed
from .session import Session
from .vault import Login

if TYPE_CHECKING:
    from .broker import Broker

PASSWORD_SELECTORS = ["input[type=password]:visible"]
MASK_JS = "el => el.setAttribute('data-pb-masked', '')"


def _error(msg: str) -> Exception:
    from .broker import BrokerError

    return BrokerError(msg)


class FillsMixin:
    def _allowed(self: "Broker", url: str, login: Login) -> bool:
        return origin_allowed(url, login.urls, self.allow_http_localhost, self.allow_subdomains)

    def _verifier(self: "Broker", client: str, login: Login) -> Callable[[Frame], None]:
        """Checks the frame, every frame above it and its own page's top URL, right now."""

        def verify(frame: Frame) -> None:
            if frame.is_detached():
                raise _error("the page changed while signing in; nothing more was filled")
            chain, f = [], frame
            while f is not None:
                chain.append(f.url)
                f = f.parent_frame
            chain.append(frame.page.url)
            for url in chain:
                if not self._allowed(url, login):
                    self.audit.record("refused_origin", client=client, item=login.title, url=host_of(url) or url[:80])
                    raise _error(
                        f"refused: {host_of(url) or 'this page'} is not a site saved for '{login.title}' "
                        f"(saved: {', '.join(host_of(u) for u in login.urls) or 'none'})"
                    )

        return verify

    async def _username_value(self: "Broker", client: str, login: Login, host: str) -> str | None:
        if login.username:
            return login.username
        try:
            return await self._secret(client, login, "username", f"sign in on {host}")
        except Exception:
            return None

    async def _fill_username(self: "Broker", s: Session, frame: Frame, field: Locator, value: str, verify: Callable[[Frame], None]) -> None:
        verify(frame)
        await field.evaluate(MASK_JS)  # snapshots show it masked, like list_logins does
        await field.fill(value)

    async def fill_login(self: "Broker", client: str, handle: str, reason: str = "") -> dict[str, Any]:
        login = self._login(client, handle)
        verify = self._verifier(client, login)
        s = await self.browser.session(client)
        s.touch()
        page = s.page
        async with s.lock:
            await s.check_tab()  # nothing is filled into a page the bot may not see
            try:
                found = await s.find(PASSWORD_SELECTORS)
                if found is None:
                    # Two-step sign-in: username first, password on the next page.
                    user = await s.find(USERNAME_SELECTORS)
                    if user is None:
                        raise _error("no sign-in field on this page; open the site's login page first")
                    frame, field = user
                    page = frame.page
                    verify(frame)
                    host = host_of(frame.url)
                    await self._approve(client, login, host, "login", reason=reason)
                    username = await self._username_value(client, login, host)
                    if not username:
                        raise _error(f"'{login.title}' has no username saved")
                    await self._fill_username(s, frame, field, username, verify)
                    await s.submit(frame, field, verify)
                    found = await s.find(PASSWORD_SELECTORS)
                    if found is None:
                        self.audit.record("fill_login", client=client, item=login.title, host=host, step="username_only")
                        return {"status": "username_submitted", "note": "no password field appeared; call fill_login again when it does", "url": page.url}
                frame, field = found
                page = frame.page
                verify(frame)
                host = host_of(frame.url)
                await self._approve(client, login, host, "login", reason=reason)
                user_field = await _find_in(frame, USERNAME_SELECTORS)
                if user_field is not None and not await user_field.input_value():
                    username = await self._username_value(client, login, host)
                    if username:
                        await self._fill_username(s, frame, user_field, username, verify)
                password = await self._secret(client, login, "password", f"sign in on {host}")
                pinned = await s.fill_pinned(frame, field, password, verify)
                del password
                await s.submit(frame, pinned, verify)
            finally:
                await s.clear_secrets(page)
            self.audit.record("fill_login", client=client, item=login.title, host=host_of(page.url), step="submitted")
            return {"status": "submitted", "url": page.url, "title": await page.title()}

    async def _fill_code(
        self: "Broker", client: str, login: Login, action: str, get_code: Callable[[str], Awaitable[str]], reason: str = ""
    ) -> dict[str, Any]:
        """Find the code field, approve, get the code (TOTP or email) and fill it pinned."""
        verify = self._verifier(client, login)
        s = await self.browser.session(client)
        s.touch()
        page = s.page
        async with s.lock:
            await s.check_tab()  # nothing is filled into a page the bot may not see
            try:
                split = await s.find_many("input[maxlength='1']:visible", minimum=4)
                found = None if split else await s.find(OTP_SELECTORS)
                if found is None and split is None:
                    raise _error("no code field on this page")
                frame, field = split or found  # type: ignore[misc]
                page = frame.page
                verify(frame)
                host = host_of(frame.url)
                await self._approve(client, login, host, action, reason=reason)
                code = await get_code(host)
                self.redactor.add(code)
                last = await (s.fill_boxes if split else s.fill_pinned)(frame, field, code, verify)
                del code
                await s.submit(frame, last, verify)
            finally:
                await s.clear_secrets(page)
            self.audit.record(f"fill_{action}", client=client, item=login.title, host=host_of(page.url))
            return {"status": "submitted", "url": page.url, "title": await page.title()}

    async def fill_totp(self: "Broker", client: str, handle: str, reason: str = "") -> dict[str, Any]:
        login = self._login(client, handle)
        if login.has_totp is False:
            raise _error(f"'{login.title}' has no 2FA secret saved")

        async def totp(host: str) -> str:
            return await self._secret(client, login, "totp", f"2FA code on {host}")

        return await self._fill_code(client, login, "totp", totp, reason)


async def _find_in(frame: Frame, selectors: list[str]) -> Locator | None:
    for sel in selectors:
        loc = frame.locator(sel)
        if await loc.count():
            return loc.first
    return None
