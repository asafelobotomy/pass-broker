"""Masking personal details on pages before a bot sees them.

Once a bot is signed in, account pages show your email, phone, card and bank
numbers. Whatever a bot reads stays in the assistant's chat history, and
chat histories have leaked (shared Grok chats were indexed by search engines
in 2025). Unless a bot is allowed to see personal details (in its Access…
settings), these are replaced with placeholders in everything it reads, and
blacked out in its screenshots.

This is pattern matching, so it's a safety net, not a guarantee: names and
street addresses, for example, aren't recognised in page text.
"""

from __future__ import annotations

import re
from typing import Any

EMAIL = re.compile(r"(?<![\w.+-])[A-Za-z0-9._%+-]+(?:@|%40)[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}\b")
CARD = re.compile(r"(?<![\w-])\d(?:[ -]?\d){12,18}(?![\w-])")
IBAN = re.compile(r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]){11,30}\b")
SSN = re.compile(r"(?<![\w-])\d{3}-\d{2}-\d{4}(?![\w-])")
PHONE = re.compile(
    r"(?<![\w+])(?:\+|00)\d(?:[ .()-]{0,2}\d){7,14}(?!\w)"  # international: +44 7700 900123
    r"|(?<![\w+])\(?0\d{2,4}\)?[ .-]?\d{3,4}[ .-]?\d{3,4}(?!\w)"  # national, leading 0: 07700 900123
    r"|(?<![\w+])\(?\d{3}\)?[ .-]\d{3}[ .-]\d{4}(?!\w)"  # North American: (555) 010-0199
)

# For screenshots: elements whose text looks like any of the above, and form
# fields meant for personal details, are blacked out.
SCREEN_TEXT = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+\.[A-Za-z]{2,}|\+?\(?\d[\d ().-]{7,}\d")
PERSONAL_FIELDS = ", ".join(
    [
        "input[type=email]",
        "input[type=tel]",
        '[autocomplete*="email"]',
        '[autocomplete*="tel"]',
        '[autocomplete*="cc-"]',
        '[autocomplete*="address"]',
        '[autocomplete*="postal-code"]',
        '[autocomplete*="bday"]',
        '[autocomplete*="name"]',
    ]
)


def _luhn(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        n = int(ch)
        if i % 2:
            n = n * 2 - 9 if n > 4 else n * 2
        total += n
    return total % 10 == 0


def _iban_ok(text: str) -> bool:
    s = text.replace(" ", "")
    if not 15 <= len(s) <= 34:
        return False
    moved = s[4:] + s[:4]
    return int("".join(str(int(c, 36)) for c in moved)) % 97 == 1


def _card(m: re.Match[str]) -> str:
    digits = re.sub(r"\D", "", m.group(0))
    return "[card number]" if _luhn(digits) else m.group(0)


def _iban(m: re.Match[str]) -> str:
    return "[bank account]" if _iban_ok(m.group(0)) else m.group(0)


def mask_text(text: str) -> str:
    text = CARD.sub(_card, text)
    text = IBAN.sub(_iban, text)
    text = SSN.sub("[ID number]", text)
    text = PHONE.sub("[phone]", text)
    return EMAIL.sub("[email]", text)


def mask_obj(obj: Any) -> Any:
    if isinstance(obj, str):
        return mask_text(obj)
    if isinstance(obj, dict):
        return {k: mask_obj(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return type(obj)(mask_obj(v) for v in obj)
    return obj
