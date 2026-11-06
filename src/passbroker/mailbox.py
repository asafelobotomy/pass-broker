"""Your mailbox through Proton Mail Bridge: the operations the mail admin's tools use (mailadmin.py).

Plain IMAP and SMTP against Bridge on this PC, over STARTTLS pinned to Bridge's own certificate.
Nothing here decides who may do what: mailadmin.py checks the bot, asks you and keeps the log.

A message is named `folder#uid`. Proton keeps a message in one folder plus any number of labels;
Bridge shows folders under `Folders/`, labels under `Labels/`, and the system folders (INBOX,
Archive, Sent, Drafts, Spam, Trash, All Mail, Starred) by name. Changing mail is in
mailorganise.py.

One connection serves the admin's calls (Pool): opening one costs a TLS handshake and a login, and
the list of folders (often a hundred or more) is kept for FOLDERS_S. imaplib isn't thread-safe,
so calls take turns on it; a connection that dropped is replaced once, transparently.
"""

from __future__ import annotations

import email
import email.policy
import html
import imaplib
import re
import threading
import time
from collections import Counter
from collections.abc import Callable
from email.message import EmailMessage, Message
from email.utils import (
    formatdate,
    getaddresses,
    make_msgid,
    parseaddr,
    parsedate_to_datetime,
)
from typing import Any

from .mailbase import MAX_TEXT, SYSTEM, Creds, MailboxError, check, quote, split_id
from .mailcode import MailSettings
from .mailorganise import OrganiseMixin

__all__ = ["Creds", "Mailbox", "MailboxError", "Pool", "addresses", "compose", "text_of"]
MAX_RESULTS = 50
FOLDERS_S = 30  # the folder list is read again after this (you may add folders in Proton Mail)
IDLE_S = 120  # an unused connection is closed after this
CHECK_S = 20  # a connection unused this long is checked (NOOP) before use


class Mailbox(OrganiseMixin):
    """One logged-in connection to Bridge."""

    def __init__(self, settings: MailSettings, creds: Creds) -> None:
        from .tlspin import pinned_context

        if not settings.cert_pem:
            raise MailboxError("Bridge's certificate isn't pinned yet; ask the user to save the email-code settings again")
        self.settings, self.creds = settings, creds
        self.ctx = pinned_context(settings.cert_pem)
        self.imap: imaplib.IMAP4 | None = None
        self._names: tuple[float, list[str]] | None = None

    def open(self) -> Mailbox:
        imap = imaplib.IMAP4(self.settings.host, self.settings.port, timeout=30)
        imap.starttls(ssl_context=self.ctx)
        imap.login(self.creds.user, self.creds.password)
        self.imap = imap
        return self

    def close(self) -> None:
        try:
            if self.imap is not None:
                self.imap.logout()
        except Exception:
            pass
        self.imap = None

    def __enter__(self) -> Mailbox:
        return self.open()

    def __exit__(self, *exc: Any) -> None:
        self.close()

    @property
    def i(self) -> imaplib.IMAP4:
        assert self.imap is not None
        return self.imap

    # ---- folders and finding messages -------------------------------------------------------

    def folder_names(self) -> list[str]:
        if self._names is not None and self._names[0] > time.monotonic():
            return self._names[1]
        names = []
        for raw in check(*self.i.list(), "listing folders"):
            m = re.search(rb'\) (?:"[^"]*"|NIL) (.+)$', raw if isinstance(raw, bytes) else b"")
            if m:
                names.append(m.group(1).decode(errors="replace").strip().strip('"'))
        self._names = (time.monotonic() + FOLDERS_S, names)
        return names

    def _forget_folders(self) -> None:
        self._names = None

    def folders(self, counts: bool = True) -> list[dict[str, Any]]:
        out = []
        for name in self.folder_names():
            kind = "label" if name.startswith("Labels/") else "system" if name in SYSTEM else "folder"
            entry: dict[str, Any] = {"name": name, "kind": kind}
            if counts:
                typ, data = self.i.status(quote(name), "(MESSAGES UNSEEN)")
                found = dict(re.findall(rb"(MESSAGES|UNSEEN) (\d+)", data[0] or b"")) if typ == "OK" and data else {}
                entry |= {"messages": int(found.get(b"MESSAGES", 0)), "unread": int(found.get(b"UNSEEN", 0))}
            out.append(entry)
        return out

    def _select(self, folder: str, write: bool = False) -> None:
        if folder not in self.folder_names():
            self._forget_folders()  # made in Proton Mail a moment ago?
            if folder not in self.folder_names():
                raise MailboxError(f"no folder called {folder[:80]} (mail_folders lists them)")
        check(*self.i.select(quote(folder), readonly=not write), f"opening {folder}")

    def existing(self, uids: list[str]) -> list[str]:
        """Which of these UIDs are in the open folder."""
        if not uids:
            return []
        _, data = self.i.uid("SEARCH", None, "UID", ",".join(uids))
        there = set((data[0] or b"").decode().split())
        return [u for u in uids if u in there]

    def _headers(self, uids: list[str], fields: str) -> list[tuple[str, str, Message]]:
        """(uid, flags and size, headers) for many messages in one FETCH."""
        if not uids:
            return []
        _, parts = self.i.uid("FETCH", ",".join(uids), f"(UID FLAGS RFC822.SIZE BODY.PEEK[HEADER.FIELDS ({fields})])")
        out = []
        for part in parts:
            if isinstance(part, tuple) and (m := re.search(rb"UID (\d+)", part[0])):
                out.append((m.group(1).decode(), part[0].decode(errors="replace"),
                            email.message_from_bytes(part[1], policy=email.policy.default)))
        return out

    def message_ids(self, uids: list[str]) -> dict[str, str]:
        return {uid: str(h.get("Message-ID", "")).strip() for uid, _, h in self._headers(uids, "MESSAGE-ID")}

    def uids_of(self, mids: list[str]) -> list[str]:
        """UIDs in the open folder of messages with these Message-IDs."""
        found: list[str] = []
        for mid in dict.fromkeys(m for m in mids if m):
            _, data = self.i.uid("SEARCH", None, "HEADER", "Message-ID", quote(mid))
            found += [u for u in (data[0] or b"").decode().split() if u not in found]
        return found

    # ---- looking ----------------------------------------------------------------------------

    def _criteria(self, sender: str, to: str, subject: str, text: str, days: int, unread: bool, starred: bool) -> list[str]:
        crit = ["SINCE", time.strftime("%d-%b-%Y", time.gmtime(time.time() - max(1, min(days, 3650)) * 86400))]
        for key, value in (("FROM", sender), ("TO", to), ("SUBJECT", subject), ("TEXT", text)):
            if value:
                crit += [key, quote(str(value)[:100])]
        return crit + (["UNSEEN"] if unread else []) + (["FLAGGED"] if starred else [])

    def matching(self, folder: str = "INBOX", sender: str = "", to: str = "", subject: str = "", text: str = "",
                 days: int = 30, unread: bool = False, starred: bool = False) -> list[str]:
        """Every matching UID in `folder`, oldest first."""
        self._select(folder)
        _, data = self.i.uid("SEARCH", None, *self._criteria(sender, to, subject, text, days, unread, starred))
        return [u.decode() for u in (data[0] or b"").split()]

    def search(self, folder: str = "INBOX", limit: int = 20, page: int = 1, **query: Any) -> dict[str, Any]:
        uids = self.matching(folder, **query)
        limit, page = max(1, min(int(limit), MAX_RESULTS)), max(1, int(page))
        newest = list(reversed(uids))[(page - 1) * limit: page * limit]
        rows = {uid: self._row(folder, uid, flags, h) for uid, flags, h in self._headers(newest, "FROM TO CC SUBJECT DATE")}
        return {"messages": [rows[u] for u in newest if u in rows], "total": len(uids), "page": page,
                "more": page * limit < len(uids)}

    @staticmethod
    def _row(folder: str, uid: str, flags: str, head: Message) -> dict[str, Any]:
        size = re.search(r"RFC822\.SIZE (\d+)", flags)
        return {"id": f"{folder}#{uid}", "from": str(head.get("From", "")), "to": str(head.get("To", "")),
                "cc": str(head.get("Cc", "")), "subject": str(head.get("Subject", "")), "date": str(head.get("Date", "")),
                "unread": "\\Seen" not in flags, "starred": "\\Flagged" in flags, "size": int(size.group(1)) if size else None}

    def senders(self, folder: str = "INBOX", days: int = 30, limit: int = 20) -> list[dict[str, Any]]:
        """Who sends the most mail to `folder`: the first thing to look at when tidying."""
        uids = self.matching(folder, days=days)[-2000:]
        counts: Counter[str] = Counter()
        unread: Counter[str] = Counter()
        for i in range(0, len(uids), 200):
            for _, flags, head in self._headers(uids[i:i + 200], "FROM"):
                who = parseaddr(str(head.get("From", "")))[1].lower() or "(unknown)"
                counts[who] += 1
                unread[who] += "\\Seen" not in flags
        return [{"sender": s, "messages": n, "unread": unread[s]} for s, n in counts.most_common(max(1, min(limit, 100)))]

    def thread(self, msg_id: str) -> list[dict[str, Any]]:
        """The conversation a message belongs to, from All Mail, oldest first."""
        msg = self.fetch(msg_id)
        ids = re.findall(r"<[^<>\s]+>", " ".join(str(msg.get(h, "")) for h in ("References", "In-Reply-To", "Message-ID")))
        ids = list(dict.fromkeys(ids))[-20:]
        where = "All Mail" if "All Mail" in self.folder_names() else split_id(msg_id)[0]
        self._select(where)
        uids: list[str] = []
        for mid in ids:
            for header in ("Message-ID", "References"):
                _, data = self.i.uid("SEARCH", None, "HEADER", header, quote(mid))
                uids += [u for u in (data[0] or b"").decode().split() if u not in uids]
        rows = [self._row(where, uid, flags, h) for uid, flags, h in self._headers(uids[:50], "FROM TO CC SUBJECT DATE")]
        return sorted(rows, key=lambda r: _when(r["date"]))

    def fetch(self, msg_id: str) -> Message:
        folder, uid = split_id(msg_id)
        self._select(folder)
        _, parts = self.i.uid("FETCH", uid, "(BODY.PEEK[])")
        raw = next((p[1] for p in parts if isinstance(p, tuple)), None)
        if raw is None:
            raise MailboxError(f"no message {msg_id}")
        return email.message_from_bytes(raw, policy=email.policy.default)

    def read(self, msg_id: str, mark_read: bool = False) -> dict[str, Any]:
        msg = self.fetch(msg_id)
        if mark_read:
            self.flag_many([msg_id], "read", True)
        attachments = [{"name": p.get_filename() or "(unnamed)", "type": p.get_content_type(),
                        "size": len(p.get_payload(decode=True) or b"")} for p in msg.walk() if p.get_filename()]
        body = text_of(msg)
        extra = {k: str(msg[h]) for k, h in (("reply_to", "Reply-To"), ("list_unsubscribe", "List-Unsubscribe"),
                                             ("list_id", "List-Id")) if msg.get(h)}
        return {"id": msg_id, "from": str(msg.get("From", "")), "to": str(msg.get("To", "")), "cc": str(msg.get("Cc", "")),
                "subject": str(msg.get("Subject", "")), "date": str(msg.get("Date", "")), **extra,
                "text": body[:MAX_TEXT], "truncated": len(body) > MAX_TEXT, "attachments": attachments}

    def attachment_text(self, msg_id: str, name: str) -> str:
        for part in self.fetch(msg_id).walk():
            if part.get_filename() == name:
                if not part.get_content_type().startswith("text/"):
                    raise MailboxError(f"{name} is {part.get_content_type()}; only text attachments can be read")
                data = part.get_payload(decode=True) or b""
                return data.decode(part.get_content_charset() or "utf-8", errors="replace")[:MAX_TEXT]
        raise MailboxError(f"no attachment called {name[:80]}")


class Pool:
    """The one connection the admin's calls share, a call at a time (imaplib isn't thread-safe)."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._mb: Mailbox | None = None
        self._key: tuple[Any, ...] | None = None
        self._used = 0.0

    def run(self, settings: MailSettings, creds: Creds, work: Callable[[Mailbox], Any]) -> Any:
        key = (settings.host, settings.port, settings.cert_pem, creds)
        with self._lock:
            for attempt in (1, 2):
                mb = self._ready(key, settings, creds)
                try:
                    result = work(mb)
                except MailboxError:
                    self._used = time.monotonic()  # the bot's mistake; the connection is fine
                    raise
                except (imaplib.IMAP4.abort, OSError):
                    self._drop()
                    if attempt == 2:
                        raise
                    continue  # Bridge restarted or the connection timed out: once more, fresh
                except BaseException:
                    self._drop()
                    raise
                self._used = time.monotonic()
                return result
        raise AssertionError("unreachable")

    def _ready(self, key: tuple[Any, ...], settings: MailSettings, creds: Creds) -> Mailbox:
        idle = time.monotonic() - self._used
        if self._mb is not None and (self._key != key or idle > IDLE_S):
            self._drop()
        if self._mb is not None and idle > CHECK_S:
            try:
                self._mb.i.noop()
            except Exception:
                self._drop()
        if self._mb is None:
            self._mb, self._key = Mailbox(settings, creds).open(), key
        return self._mb

    def _drop(self) -> None:
        if self._mb is not None:
            self._mb.close()
        self._mb = self._key = None

    def close(self) -> None:
        with self._lock:
            self._drop()


def _when(date: str) -> float:
    """A Date header as a timestamp; one with no time zone ("-0000") counts as UTC, not local time."""
    from datetime import UTC

    try:
        when = parsedate_to_datetime(date)
    except (TypeError, ValueError):
        return 0.0
    return (when if when.tzinfo else when.replace(tzinfo=UTC)).timestamp()


def text_of(msg: Message) -> str:
    """The message as text: its plain part, or its HTML without styles, scripts and tags."""
    plain, rich = [], []
    for part in msg.walk() if msg.is_multipart() else [msg]:
        ctype = part.get_content_type()
        if ctype not in ("text/plain", "text/html") or part.get_filename():
            continue
        data = part.get_payload(decode=True) or b""
        text = data.decode(part.get_content_charset() or "utf-8", errors="replace")
        (plain if ctype == "text/plain" else rich).append(text)
    if plain:
        return "\n".join(plain).strip()
    raw = re.sub(r"(?is)<(style|script|head)\b.*?</\1>", " ", "\n".join(rich))
    raw = re.sub(r"(?i)<br\s*/?>|</p>|</div>|</tr>|</h\d>", "\n", raw)
    return re.sub(r"[ \t]+", " ", re.sub(r"\n\s*\n+", "\n\n", html.unescape(re.sub(r"<[^>]+>", " ", raw)))).strip()


def addresses(*values: str) -> list[str]:
    out = []
    for _, addr in getaddresses([v for v in values if v]):
        if not re.fullmatch(r"[^@\s<>]+@[^@\s<>]+\.[^@\s<>]+", addr):
            raise MailboxError(f"not an email address: {addr[:80] or '(empty)'}")
        out.append(addr)
    return out


def compose(sender: str, to: list[str], cc: list[str], subject: str, body: str, reply_to: Message | None = None,
            forward: Message | None = None) -> EmailMessage:
    msg = EmailMessage()
    msg["From"], msg["To"], msg["Subject"] = sender, ", ".join(to), subject
    if cc:
        msg["Cc"] = ", ".join(cc)
    msg["Date"], msg["Message-ID"] = formatdate(localtime=True), make_msgid(domain=sender.rpartition("@")[2] or None)
    if reply_to is not None:
        orig = str(reply_to.get("Message-ID", "")).strip()
        if orig:
            msg["In-Reply-To"] = orig
            msg["References"] = (str(reply_to.get("References", "")) + " " + orig).strip()
        body += "\n\n" + _quoted(reply_to)
    msg.set_content(body)
    if forward is not None:
        msg.add_attachment(forward, filename="forwarded.eml")  # the whole email, attachments and all
    return msg


def _quoted(msg: Message) -> str:
    when = str(msg.get("Date", ""))
    try:
        when = parsedate_to_datetime(when).strftime("%Y-%m-%d %H:%M")
    except (TypeError, ValueError):
        pass
    who = parseaddr(str(msg.get("From", "")))[1]
    return f"On {when}, {who} wrote:\n" + "\n".join("> " + line for line in text_of(msg)[:MAX_TEXT].splitlines())
