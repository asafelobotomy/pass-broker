"""Your mailbox through Proton Mail Bridge: the operations the mail admin's tools use (mailadmin.py).

Plain IMAP and SMTP against Bridge on this PC, over STARTTLS pinned to Bridge's own certificate.
Nothing here decides who may do what: mailadmin.py checks the bot, asks you and keeps the log.

A message is named `folder#uid`. Proton keeps a message in one folder plus any number of labels;
Bridge shows folders under `Folders/`, labels under `Labels/`, and the system folders (INBOX,
Archive, Sent, Drafts, Spam, Trash, All Mail, Starred) by name. Moving copies nothing: a message
leaves its folder. Labelling copies it into `Labels/<name>`; unlabelling removes it from there.
Nothing is ever erased for good: "delete" means move to Trash, and Trash is never emptied.
"""

from __future__ import annotations

import email
import email.policy
import html
import imaplib
import re
import smtplib
import time
from dataclasses import dataclass
from email.message import EmailMessage, Message
from email.utils import (
    formatdate,
    getaddresses,
    make_msgid,
    parseaddr,
    parsedate_to_datetime,
)
from typing import Any

from .mailcode import MailSettings

SYSTEM = ("INBOX", "Archive", "Sent", "Drafts", "Spam", "Trash", "All Mail", "Starred")
SMTP_PORT = 1025  # Bridge's SMTP, next to its IMAP on 1143
MAX_TEXT = 20_000
MAX_RESULTS = 50
NAME_RE = re.compile(r"[\w .&()'+,-]{1,60}")  # a folder or label name you'd type in Proton Mail


class MailboxError(Exception):
    """Safe to show to the bot."""


@dataclass
class Creds:
    user: str
    password: str


def _quote(name: str) -> str:
    return '"' + name.replace("\\", "\\\\").replace('"', '\\"') + '"'


def split_id(msg_id: str) -> tuple[str, str]:
    folder, _, uid = str(msg_id).rpartition("#")
    if not folder or not uid.isdigit():
        raise MailboxError(f"not a message id: {str(msg_id)[:80]} (use the ids mail_search gives)")
    return folder, uid


def _check(typ: str, data: Any, what: str) -> Any:
    if typ != "OK":
        detail = b" ".join(d for d in (data or []) if isinstance(d, bytes)).decode(errors="replace")[:200]
        raise MailboxError(f"{what} failed: {detail or typ}")
    return data


class Mailbox:
    """One connection to Bridge, for one tool call: `with Mailbox(settings, creds) as mb:`."""

    def __init__(self, settings: MailSettings, creds: Creds) -> None:
        from .tlspin import pinned_context

        if not settings.cert_pem:
            raise MailboxError("Bridge's certificate isn't pinned yet; ask the user to save the email-code settings again")
        self.settings, self.creds = settings, creds
        self.ctx = pinned_context(settings.cert_pem)
        self.imap: imaplib.IMAP4 | None = None

    def __enter__(self) -> "Mailbox":
        imap = imaplib.IMAP4(self.settings.host, self.settings.port, timeout=30)
        imap.starttls(ssl_context=self.ctx)
        imap.login(self.creds.user, self.creds.password)
        self.imap = imap
        return self

    def __exit__(self, *exc: Any) -> None:
        try:
            self.imap.logout()  # type: ignore[union-attr]
        except Exception:
            pass

    @property
    def i(self) -> imaplib.IMAP4:
        assert self.imap is not None
        return self.imap

    # ---- looking ----------------------------------------------------------------------------

    def folder_names(self) -> list[str]:
        names = []
        for raw in _check(*self.i.list(), "listing folders"):
            m = re.search(rb'\) (?:"[^"]*"|NIL) (.+)$', raw if isinstance(raw, bytes) else b"")
            if m:
                names.append(m.group(1).decode(errors="replace").strip().strip('"'))
        return names

    def folders(self) -> list[dict[str, Any]]:
        out = []
        for name in self.folder_names():
            typ, data = self.i.status(_quote(name), "(MESSAGES UNSEEN)")
            counts = dict(re.findall(rb"(MESSAGES|UNSEEN) (\d+)", data[0] or b"")) if typ == "OK" and data else {}
            kind = "label" if name.startswith("Labels/") else "system" if name in SYSTEM else "folder"
            out.append({"name": name, "kind": kind, "messages": int(counts.get(b"MESSAGES", 0)), "unread": int(counts.get(b"UNSEEN", 0))})
        return out

    def _select(self, folder: str, write: bool = False) -> None:
        if folder not in self.folder_names():
            raise MailboxError(f"no folder called {folder[:80]} (mail_folders lists them)")
        _check(*self.i.select(_quote(folder), readonly=not write), f"opening {folder}")

    def search(self, folder: str = "INBOX", sender: str = "", to: str = "", subject: str = "", text: str = "",
               days: int = 30, unread: bool = False, starred: bool = False, limit: int = 20) -> list[dict[str, Any]]:
        self._select(folder)
        crit: list[str] = ["SINCE", time.strftime("%d-%b-%Y", time.gmtime(time.time() - max(1, min(days, 3650)) * 86400))]
        for key, value in (("FROM", sender), ("TO", to), ("SUBJECT", subject), ("TEXT", text)):
            if value:
                crit += [key, _quote(str(value)[:100])]
        crit += (["UNSEEN"] if unread else []) + (["FLAGGED"] if starred else [])
        _, data = self.i.uid("SEARCH", None, *crit)
        uids = (data[0] or b"").split()[-max(1, min(limit, MAX_RESULTS)):]
        return list(reversed([self._summary(folder, u.decode()) for u in uids]))

    def _summary(self, folder: str, uid: str) -> dict[str, Any]:
        _, parts = self.i.uid("FETCH", uid, "(FLAGS RFC822.SIZE BODY.PEEK[HEADER.FIELDS (FROM TO CC SUBJECT DATE)])")
        meta = next((p for p in parts if isinstance(p, tuple)), None)
        if meta is None:
            raise MailboxError(f"no message {folder}#{uid}")
        head = email.message_from_bytes(meta[1], policy=email.policy.default)
        flags = meta[0].decode(errors="replace")
        size = re.search(r"RFC822\.SIZE (\d+)", flags)
        return {"id": f"{folder}#{uid}", "from": str(head.get("From", "")), "to": str(head.get("To", "")),
                "cc": str(head.get("Cc", "")), "subject": str(head.get("Subject", "")), "date": str(head.get("Date", "")),
                "unread": "\\Seen" not in flags, "starred": "\\Flagged" in flags, "size": int(size.group(1)) if size else None}

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
            self.flag(msg_id, "read", True)
        attachments = [{"name": p.get_filename() or "(unnamed)", "type": p.get_content_type(),
                        "size": len(p.get_payload(decode=True) or b"")} for p in msg.walk() if p.get_filename()]
        body = text_of(msg)
        return {"id": msg_id, "from": str(msg.get("From", "")), "to": str(msg.get("To", "")), "cc": str(msg.get("Cc", "")),
                "subject": str(msg.get("Subject", "")), "date": str(msg.get("Date", "")),
                "text": body[:MAX_TEXT], "truncated": len(body) > MAX_TEXT, "attachments": attachments}

    def attachment_text(self, msg_id: str, name: str) -> str:
        for part in self.fetch(msg_id).walk():
            if part.get_filename() == name:
                if not part.get_content_type().startswith("text/"):
                    raise MailboxError(f"{name} is {part.get_content_type()}; only text attachments can be read")
                data = part.get_payload(decode=True) or b""
                return data.decode(part.get_content_charset() or "utf-8", errors="replace")[:MAX_TEXT]
        raise MailboxError(f"no attachment called {name[:80]}")

    # ---- organising -------------------------------------------------------------------------

    def move(self, msg_id: str, to: str) -> str:
        folder, uid = split_id(msg_id)
        if to.startswith("Labels/") or to in ("All Mail", "Starred"):
            raise MailboxError(f"{to} isn't a folder you can move to; use mail_label for labels and mail_flag to star")
        if to not in self.folder_names():
            raise MailboxError(f"no folder called {to[:80]} (mail_folders lists them; mail_folder_create makes one)")
        self._select(folder, write=True)
        _check(*self.i.uid("MOVE", uid, _quote(to)), f"moving to {to}")
        return to

    def flag(self, msg_id: str, flag: str, on: bool) -> None:
        imap_flag = {"read": "\\Seen", "starred": "\\Flagged"}.get(flag)
        if imap_flag is None:
            raise MailboxError("flag: read or starred")
        folder, uid = split_id(msg_id)
        self._select(folder, write=True)
        _check(*self.i.uid("STORE", uid, "+FLAGS.SILENT" if on else "-FLAGS.SILENT", f"({imap_flag})"), "flagging")

    def label(self, msg_id: str, name: str, on: bool) -> None:
        target = name if name.startswith("Labels/") else f"Labels/{name}"
        if target not in self.folder_names():
            raise MailboxError(f"no label called {name[:60]} (mail_folder_create with kind=label makes one)")
        folder, uid = split_id(msg_id)
        if on:
            self._select(folder, write=True)
            _check(*self.i.uid("COPY", uid, _quote(target)), "labelling")
            return
        # Unlabel: find the same message under the label, by its Message-ID, and take it out there.
        mid = str(self.fetch(msg_id).get("Message-ID", "")).strip()
        self._select(target, write=True)
        _, data = self.i.uid("SEARCH", None, "HEADER", "Message-ID", _quote(mid)) if mid else ("OK", [b""])
        found = (data[0] or b"").split()
        if not found:
            raise MailboxError("that message doesn't have the label")
        _check(*self.i.uid("STORE", found[0].decode(), "+FLAGS.SILENT", "(\\Deleted)"), "unlabelling")
        self.i.expunge()  # in a label, this removes the label; the message itself stays

    def create(self, name: str, kind: str = "folder") -> str:
        if not NAME_RE.fullmatch(name) or name.strip() != name:
            raise MailboxError("name: up to 60 letters, digits, spaces and . & ( ) ' + , - _")
        full = ("Labels/" if kind == "label" else "Folders/") + name
        if full in self.folder_names():
            return full
        _check(*self.i.create(_quote(full)), f"making {full}")
        return full

    def rename(self, old: str, new: str) -> str:
        if old in SYSTEM or not old.startswith(("Folders/", "Labels/")):
            raise MailboxError("only your own folders and labels can be renamed")
        if not NAME_RE.fullmatch(new):
            raise MailboxError("name: up to 60 letters, digits, spaces and . & ( ) ' + , - _")
        full = old.split("/", 1)[0] + "/" + new
        _check(*self.i.rename(_quote(old), _quote(full)), "renaming")
        return full

    def delete_folder(self, name: str) -> None:
        """The folder or label goes; Proton keeps its messages (a folder's move to the inbox)."""
        if name in SYSTEM or not name.startswith(("Folders/", "Labels/")):
            raise MailboxError("only your own folders and labels can be deleted")
        _check(*self.i.delete(_quote(name)), "deleting")

    # ---- writing ----------------------------------------------------------------------------

    def save_draft(self, msg: EmailMessage) -> None:
        _check(*self.i.append("Drafts", "(\\Draft \\Seen)", imaplib.Time2Internaldate(time.time()), msg.as_bytes()), "saving the draft")

    def send(self, msg: EmailMessage) -> None:
        with smtplib.SMTP(self.settings.host, SMTP_PORT, timeout=30) as smtp:
            smtp.starttls(context=self.ctx)
            smtp.login(self.creds.user, self.creds.password)
            smtp.send_message(msg)


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
