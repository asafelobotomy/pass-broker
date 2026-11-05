"""Filling a sign-up form with a login the broker made (accounts.py), without the bot seeing it.

A sign-up form asks for some of: a username, an email (often twice), a password (usually twice).
Each visible field is sorted into email or username by its type, autocomplete hint, name, id,
label and placeholder, and only empty ones are filled, so whatever the bot typed itself (a name,
a birthday) stays. Every value is filled pinned to the page that passed the origin check, like a
sign-in. Forms that ask for the email first and the password on a later page work too: the first
call fills what's there and moves on, and the next call finishes.
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Any

from playwright.async_api import Frame

from .origin import host_of

if TYPE_CHECKING:
    from .broker import Broker
    from .session import Session
    from .vault import Login

# Tags each visible text-like input data-pb-kind=email|username; returns how many of each.
KIND_JS = r"""els => {
  const skip = new Set(['password', 'hidden', 'checkbox', 'radio', 'submit', 'button', 'reset', 'file', 'image',
                        'tel', 'number', 'date', 'datetime-local', 'month', 'week', 'time', 'color', 'range', 'search']);
  const n = {email: 0, username: 0};
  for (const el of els) {
    el.removeAttribute('data-pb-kind');
    if (el.tagName !== 'INPUT' || skip.has((el.type || '').toLowerCase()) || el.disabled || el.readOnly) continue;
    const ac = (el.getAttribute('autocomplete') || '').toLowerCase();
    const labels = Array.from(el.labels || []).map(l => l.textContent).join(' ');
    const words = [el.name, el.id, el.getAttribute('aria-label'), el.placeholder, labels].join(' ').toLowerCase();
    let kind = '';
    if (el.type === 'email' || /\bemail\b/.test(ac) || /e-?mail/.test(words)) kind = 'email';
    else if (/\busername\b/.test(ac) || /user|login|handle|nick|screen.?name|account.?name|member.?name/.test(words)) kind = 'username';
    if (kind) { el.setAttribute('data-pb-kind', kind); n[kind]++; }
  }
  return n;
}"""
PASSWORDS = "input[type=password]:visible"
MAX_PASSWORDS = 3  # password, confirm (and a rare third)
MAX_EMAILS = 2  # email, confirm


def _error(msg: str) -> Exception:
    from .broker import BrokerError

    return BrokerError(msg)


class SignupMixin:
    _fresh: dict[tuple[str, str], float]

    async def _account_values(self: "Broker", client: str, login: "Login", host: str) -> tuple[str, str]:
        """(username, email) the login was made with: as recorded when this bot made it, else
        the saved username (an address counts as the email)."""
        bot = client.partition("/")[2]
        made = self.bots.created(bot, login.title) if self.bots is not None and bot else None
        if made is not None:
            return str(made.get("username", "")), str(made.get("email", ""))
        saved = await self._username_value(client, login, host) or ""
        return ("", saved) if "@" in saved else (saved, "")

    async def _account_fields(
        self: "Broker", s: "Session", frame: Frame, username: str, email: str, verify
    ) -> tuple[list[str], list[str], Any]:
        """Fill the empty email and username fields. Returns (filled, left empty, last field)."""
        from .fills import MASK_JS

        counts = await frame.locator("input:visible").evaluate_all(KIND_JS)
        emails, users = frame.locator("[data-pb-kind=email]"), frame.locator("[data-pb-kind=username]")
        filled, left, last = [], [], None
        # A form with no email field takes the address as its username, as sign-ins do.
        plan = [("email", emails, min(counts["email"], MAX_EMAILS), email),
                ("username", users, min(counts["username"], 1), username or ("" if counts["email"] else email))]
        for kind, loc, n, value in plan:
            for i in range(n):
                field = loc.nth(i)
                if await field.input_value():
                    continue  # the bot (or the site) filled it already
                if not value:
                    left.append(kind)
                    continue
                await field.evaluate(MASK_JS)
                last = await s.fill_pinned(frame, field, value, verify)
                filled.append(kind if i == 0 else f"{kind} (confirm)")
        return filled, left, last

    async def fill_signup(self: "Broker", client: str, handle: str, reason: str = "") -> dict[str, Any]:
        """The empty email and username fields, then every password field; then submit."""
        login = self._login(client, handle)
        verify = self._verifier(client, login)
        s = await self.browser.session(client)
        s.touch()
        page = s.page
        async with s.lock:
            await s.check_tab()
            try:
                found = await s.find_many(PASSWORDS, minimum=1)
                frame = found[0] if found else await self._account_frame(s)
                if frame is None:
                    raise _error("no sign-up field on this page; open the sign-up form first")
                page = frame.page
                verify(frame)
                host = host_of(frame.url)
                if self._fresh.get((client, login.handle), 0) <= time.monotonic():  # covered by approving create_login
                    await self._approve(client, login, host, "signup", f"fill in a sign-up form on {host}", reason=reason)
                username, email = await self._account_values(client, login, host)
                filled, left, last = await self._account_fields(s, frame, username, email, verify)
                if found is None:  # email (or username) first, the password on the next page
                    if last is None:
                        raise _error("no empty sign-up field on this page to fill")
                    await s.submit(frame, last, verify)
                    self.audit.record("fill_signup", client=client, item=login.title, host=host, step="details_only")
                    return {"status": "details_submitted", "filled": filled, "left_empty": left, "url": page.url,
                            "note": "no password field yet; when it appears, call fill_signup again"}
                fields = found[1]
                password = await self._secret(client, login, "password", f"sign up on {host}")
                for i in range(min(await fields.count(), MAX_PASSWORDS)):
                    last = await s.fill_pinned(frame, fields.nth(i), password, verify)
                    filled.append("password" if i == 0 else "password (confirm)")
                del password
                await s.submit(frame, last, verify)
            finally:
                await s.clear_secrets(page)
            self.audit.record("fill_signup", client=client, item=login.title, host=host_of(page.url))
            result = {"status": "submitted", "filled": filled, "left_empty": left, "url": page.url, "title": await page.title()}
            if left:
                result["note"] = ("this login has no " + " or ".join(sorted(set(left))) + " to fill those fields with; "
                                  "if the site needs one, make the login again with create_login giving it")
            return result

    async def _account_frame(self: "Broker", s: "Session") -> Frame | None:
        """The first frame with an email or username field, for forms that ask for those first."""
        for frame in s.frames():
            counts = await frame.locator("input:visible").evaluate_all(KIND_JS)
            if counts["email"] or counts["username"]:
                return frame
        return None
