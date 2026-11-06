"""Pieces the mailbox modules share (mailbox.py, mailorganise.py)."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

SYSTEM = ("INBOX", "Archive", "Sent", "Drafts", "Spam", "Trash", "All Mail", "Starred")
NAME_RE = re.compile(r"[\w .&()'+,-]{1,60}")  # a folder or label name you'd type in Proton Mail
MAX_TEXT = 20_000


class MailboxError(Exception):
    """Safe to show to the bot: it asked for something that isn't there or isn't allowed."""


@dataclass(frozen=True)
class Creds:
    user: str
    password: str


def quote(name: str) -> str:
    return '"' + name.replace("\\", "\\\\").replace('"', '\\"') + '"'


def split_id(msg_id: str) -> tuple[str, str]:
    folder, _, uid = str(msg_id).rpartition("#")
    if not folder or not uid.isdigit():
        raise MailboxError(f"not a message id: {str(msg_id)[:80]} (use the ids mail_search gives)")
    return folder, uid


def by_folder(ids: list[str]) -> dict[str, list[str]]:
    """Message ids grouped by folder, each folder's UIDs in order, so one command covers a folder."""
    out: dict[str, list[str]] = {}
    for msg_id in ids:
        folder, uid = split_id(msg_id)
        if uid not in out.setdefault(folder, []):
            out[folder].append(uid)
    return out


def check(typ: str, data: Any, what: str) -> Any:
    if typ != "OK":
        detail = b" ".join(d for d in (data or []) if isinstance(d, bytes)).decode(errors="replace")[:200]
        raise MailboxError(f"{what} failed: {detail or typ}")
    return data
