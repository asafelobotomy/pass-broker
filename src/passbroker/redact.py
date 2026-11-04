"""Scrubs every secret the broker has ever handled from anything it sends out."""

from __future__ import annotations

import html
import json
import threading
from typing import Any
from urllib.parse import quote, quote_plus

MASK = "[REDACTED]"


class Redactor:
    """Holds every secret value seen this process and masks them in outgoing text.

    Variants (URL-encoded, JSON-escaped, HTML-escaped) are masked too, so a page
    that echoes a password in a query string or attribute is still caught.
    """

    def __init__(self) -> None:
        self._needles: set[str] = set()
        self._lock = threading.Lock()

    def add(self, secret: str | None) -> None:
        if not secret:
            return
        variants = {
            secret,
            quote(secret, safe=""),
            quote_plus(secret),
            quote(secret, safe="*-._").replace("%20", "+"),  # how browsers encode form fields
            json.dumps(secret)[1:-1],
            html.escape(secret),
        }
        with self._lock:
            self._needles.update(v for v in variants if len(v) >= 3)

    def contains_secret(self, text: str) -> bool:
        with self._lock:
            needles = list(self._needles)
        return any(n in text for n in needles)

    def scrub(self, text: str) -> str:
        with self._lock:
            needles = sorted(self._needles, key=len, reverse=True)
        for n in needles:
            if n in text:
                text = text.replace(n, MASK)
        return text

    def scrub_obj(self, obj: Any) -> Any:
        if isinstance(obj, str):
            return self.scrub(obj)
        if isinstance(obj, dict):
            return {self.scrub_obj(k): self.scrub_obj(v) for k, v in obj.items()}
        if isinstance(obj, (list, tuple)):
            return type(obj)(self.scrub_obj(v) for v in obj)
        return obj
