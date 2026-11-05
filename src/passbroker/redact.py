"""Scrubs every secret the broker has ever handled from anything it sends out."""

from __future__ import annotations

import base64
import html
import json
import re
import threading
from typing import Any
from urllib.parse import quote, quote_plus

MASK = "[REDACTED]"

# Characters that render as nothing (or reorder text) but that a model still
# reads: zero-width and joiner characters, bidi controls, soft hyphen, Unicode
# tag characters (U+E0000-E007F, "ASCII smuggling"), variation selectors used
# to smuggle bytes, and C0 controls other than tab and newlines. Pages use them
# to hide instructions from you, or to split a secret so exact matching misses it.
INVISIBLE = re.compile(
    "[\x00-\x08\x0b\x0c\x0e-\x1f\x7f\u00ad\u034f\u061c\u115f\u1160\u17b4\u17b5\u180b-\u180f"
    "\u200b-\u200f\u202a-\u202e\u2060-\u206f\u3164\ufe00-\ufe0f\ufeff\uffa0\ufff0-\ufffb"
    "\U0001d173-\U0001d17a\U000e0000-\U000e0fff]"
)
# What may sit between the digits of a code on a page: "123 456", "123-456", "1 2 3 4 5 6".
CODE_GAP = "[\\s\\-.\u00b7\u2010-\u2015\u2212]{0,3}"


def _url_pattern(secret: str) -> re.Pattern[str]:
    """The secret with any of its characters percent-encoded, in either hex case (and spaces as +):
    browsers encode only some characters, and pages re-encode them their own way."""
    def hexes(byte: int) -> str:
        return "%" + "".join(f"[{c.lower()}{c.upper()}]" if c.isalpha() else c for c in f"{byte:02X}")

    parts = []
    for ch in secret:
        alts = [re.escape(ch), "".join(hexes(b) for b in ch.encode())] + (["\\+"] if ch == " " else [])
        parts.append("(?:" + "|".join(alts) + ")")
    return re.compile("".join(parts))


def _base64_cores(raw: bytes) -> list[str]:
    """Parts of the secret's base64 that stay the same wherever it sits in longer data (as in
    `Basic base64(user:password)`): at each of the 3 alignments, the characters that depend only
    on the secret's own bytes."""
    cores = []
    for k in range(3):
        start = -(-8 * k // 6)  # characters touched by the k bytes before the secret
        end = (k + len(raw)) * 8 // 6  # the last character that's complete without what follows
        for enc in (base64.b64encode, base64.urlsafe_b64encode):
            core = enc(b"\0" * k + raw).decode()[start:end]
            if len(core) >= 8:
                cores.append(core)
    return cores


def clean(text: str) -> str:
    """`text` without invisible characters."""
    return INVISIBLE.sub("", text)


class Redactor:
    """Holds every secret value seen this process and masks them in outgoing text.

    Variants (URL-encoded in either case, JSON-escaped, HTML-escaped, base64)
    are masked too, so a page that echoes a password in a query string or
    attribute is still caught. Codes are also caught with spaces or dashes
    between their digits. Outgoing text loses its invisible characters first,
    so they can't be slipped between a secret's characters to hide it.
    """

    def __init__(self) -> None:
        self._needles: set[str] = set()
        self._codes: list[re.Pattern[str]] = []
        self._lock = threading.Lock()

    def add(self, secret: str | None) -> None:
        if not secret:
            return
        raw = secret.encode()
        encoded = quote(secret, safe="")
        variants = {
            secret,
            clean(secret),
            encoded,
            re.sub(r"%[0-9A-F]{2}", lambda m: m.group(0).lower(), encoded),
            *_base64_cores(raw),
            quote_plus(secret),
            quote(secret, safe="*-._").replace("%20", "+"),  # how browsers encode form fields
            json.dumps(secret)[1:-1],
            html.escape(secret),
        }
        patterns = []
        if secret.isdecimal() and 4 <= len(secret) <= 10:
            patterns.append(re.compile("(?<![0-9])" + CODE_GAP.join(secret) + "(?![0-9])"))
        if len(secret) >= 3:
            patterns.append(_url_pattern(secret))
        with self._lock:
            self._needles.update(v for v in variants if len(v) >= 3)
            known = {c.pattern for c in self._codes}
            self._codes.extend(c for c in patterns if c.pattern not in known)

    def contains_secret(self, text: str) -> bool:
        text = clean(text)
        with self._lock:
            needles, codes = list(self._needles), list(self._codes)
        return any(n in text for n in needles) or any(c.search(text) for c in codes)

    def scrub(self, text: str) -> str:
        text = clean(text)
        with self._lock:
            needles, codes = sorted(self._needles, key=len, reverse=True), list(self._codes)
        for n in needles:
            if n in text:
                text = text.replace(n, MASK)
        for c in codes:
            text = c.sub(MASK, text)
        return text

    def scrub_obj(self, obj: Any) -> Any:
        if isinstance(obj, str):
            return self.scrub(obj)
        if isinstance(obj, dict):
            return {self.scrub_obj(k): self.scrub_obj(v) for k, v in obj.items()}
        if isinstance(obj, (list, tuple)):
            return type(obj)(self.scrub_obj(v) for v in obj)
        return obj
