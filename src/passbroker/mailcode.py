"""Sign-in codes sent by email, read on your PC through Proton Mail Bridge.

The broker logs in to Bridge's local IMAP server with credentials from a vault
item, finds the newest message from the site's domain received in the last few
minutes, takes the code out of it and types it into the page. Bots never see
the code or the mail; they only learn whether it was submitted. Messages are
read with BODY.PEEK, so they stay unread.
"""

from __future__ import annotations

import email
import html
import imaplib
import ipaddress
import json
import os
import re
import ssl
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass
from email.utils import parseaddr, parsedate_to_datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .origin import host_of

if TYPE_CHECKING:
    from .broker import Broker

CODE_NEAR_WORD = re.compile(
    r"(?:code|verification|verify|one[- ]time|otp|passcode|pin|security)[^A-Za-z0-9]{0,40}(?:is[^A-Za-z0-9]{0,5})?\b([0-9]{4,8}|[A-Z0-9]{6,8})\b",
    re.I,
)
SIX_DIGITS = re.compile(r"(?<![0-9])([0-9]{6})(?![0-9])")


@dataclass
class MailSettings:
    item: str = ""  # vault item: username = Bridge username, password = Bridge password
    host: str = "127.0.0.1"
    port: int = 1143
    folder: str = "INBOX"
    max_age_minutes: int = 10
    cert_pem: str = ""  # Bridge's own certificate, pinned when the settings are saved

    def is_local(self) -> bool:
        if re.fullmatch(r"[0-9.:]+", self.host):
            return ipaddress.ip_address(self.host).is_loopback
        return self.host == "localhost"

    @staticmethod
    def load(path: Path) -> "MailSettings":
        try:
            return MailSettings(**json.loads(path.read_text() or "{}"))
        except FileNotFoundError:
            return MailSettings()

    def save(self, path: Path) -> str:
        """Save, pinning Bridge's self-signed certificate on first save. Returns its fingerprint."""
        if not isinstance(self.item, str) or not isinstance(self.port, int) or not 1 <= self.max_age_minutes <= 60:
            raise ValueError("invalid email-code settings")
        from .tlspin import fetch_imap_starttls_cert, fingerprint

        if self.item and self.is_local() and not self.cert_pem:
            try:
                self.cert_pem = fetch_imap_starttls_cert(self.host, self.port)
            except OSError as e:
                raise ValueError(f"couldn't reach Proton Mail Bridge to record its certificate ({type(e).__name__}); start Bridge and save again") from None
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(asdict(self), f, indent=2)
        return fingerprint(self.cert_pem) if self.cert_pem else ""


def site_domains(urls: tuple[str, ...] | list[str]) -> set[str]:
    """Crude registrable domains of a login's sites: account.proton.me -> proton.me."""
    out = set()
    for u in urls:
        host = host_of(u)
        parts = host.split(".")
        if host and not re.fullmatch(r"[0-9.]+", host):
            out.add(".".join(parts[-3:]) if len(parts) > 2 and len(parts[-2]) <= 3 else ".".join(parts[-2:]))
    return out


def _text_of(msg: email.message.Message) -> str:
    plain, rich = [], []
    for part in msg.walk() if msg.is_multipart() else [msg]:
        ctype = part.get_content_type()
        if ctype not in ("text/plain", "text/html"):
            continue
        payload = part.get_payload(decode=True) or b""
        text = payload.decode(part.get_content_charset() or "utf-8", errors="replace")
        (plain if ctype == "text/plain" else rich).append(text)
    if plain:
        return "\n".join(plain)
    return html.unescape(re.sub(r"<[^>]+>", " ", "\n".join(rich)))


def extract_code(subject: str, body: str) -> str | None:
    for text in (subject, body):
        m = CODE_NEAR_WORD.search(text)
        if m and any(ch.isdigit() for ch in m.group(1)):
            return m.group(1)
    for text in (subject, body):
        m = SIX_DIGITS.search(text)
        if m:
            return m.group(1)
    return None


def fetch_code(settings: MailSettings, user: str, password: str, domains: set[str], now: float | None = None) -> str | None:
    """Newest code from a sender in `domains` within the age limit, or None."""
    now = now or time.time()
    if settings.cert_pem:
        from .tlspin import pinned_context

        ctx = pinned_context(settings.cert_pem)  # Bridge's own self-signed certificate, and only that
    elif settings.is_local():
        raise ssl.SSLError("Bridge's certificate isn't pinned yet; save the email-code settings again while Bridge runs")
    else:
        ctx = ssl.create_default_context()
    imap = imaplib.IMAP4(settings.host, settings.port, timeout=20)
    try:
        imap.starttls(ssl_context=ctx)
        imap.login(user, password)
        imap.select(settings.folder, readonly=True)
        since = time.strftime("%d-%b-%Y", time.gmtime(now - 86400))
        _, data = imap.search(None, "SINCE", since)
        ids = (data[0] or b"").split()[-30:]
        for msg_id in reversed(ids):
            _, parts = imap.fetch(msg_id, "(BODY.PEEK[])")
            raw = next((p[1] for p in parts if isinstance(p, tuple)), b"")
            msg = email.message_from_bytes(raw)
            sender = parseaddr(msg.get("From", ""))[1].lower()
            sender_domain = sender.rpartition("@")[2]
            if not any(sender_domain == d or sender_domain.endswith("." + d) for d in domains):
                continue
            try:
                sent = parsedate_to_datetime(msg.get("Date")).timestamp()
            except (TypeError, ValueError):
                continue
            if now - sent > settings.max_age_minutes * 60:
                return None  # newest matching message is too old
            return extract_code(str(msg.get("Subject", "")), _text_of(msg))
        return None
    finally:
        try:
            imap.logout()
        except Exception:
            pass


class MailMixin:
    mail_fetch: Callable[..., str | None] = staticmethod(fetch_code)

    async def fill_email_code(self: "Broker", client: str, handle: str, reason: str = "") -> dict[str, Any]:
        import asyncio

        from .broker import BrokerError

        if self.mail is None or not self.mail.item:
            raise BrokerError("email codes aren't set up; ask the user to add Proton Mail Bridge in Pass Broker")
        self._permit(client, "email_codes")
        login = self._login(client, handle)
        domains = site_domains(login.urls)

        async def from_mail(host: str) -> str:
            bridge = await self._item(self.mail.item, "email codes")
            user = bridge.username or await self._secret(client, bridge, "username", "read a sign-in email")
            password = await self._secret(client, bridge, "password", f"read a sign-in email from {', '.join(sorted(domains))}")
            try:
                code = await asyncio.to_thread(self.mail_fetch, self.mail, user, password, domains)
            except ssl.SSLError as e:
                raise BrokerError(str(e) if "pinned" in str(e) else "Bridge's certificate changed or couldn't be checked; save the email-code settings again") from None
            except (OSError, imaplib.IMAP4.error) as e:
                raise BrokerError(f"couldn't read mail through Proton Mail Bridge ({type(e).__name__}); is Bridge running?") from None
            finally:
                del password
            if not code:
                raise BrokerError(f"no code email from {', '.join(sorted(domains))} in the last {self.mail.max_age_minutes} minutes; wait a moment and try again")
            return code

        return await self._fill_code(client, login, "email_code", from_mail, reason)
