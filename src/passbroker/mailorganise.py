"""Changing the mailbox: moving, flags, labels, folders, drafts and sending (part of mailbox.Mailbox).

Each command covers a whole folder's worth of messages at once (UID sets), and messages that
aren't there are reported, not silently counted. Moves remember each message's Message-ID and
where it came from, so mail_undo can put them back. Nothing here erases mail: "delete" is a move
to Trash, and unlabelling takes a message out of the label only.
"""

from __future__ import annotations

import imaplib
import smtplib
import time
from email.message import EmailMessage
from typing import TYPE_CHECKING, Any

from .mailbase import NAME_RE, SYSTEM, MailboxError, by_folder, check, quote

if TYPE_CHECKING:
    from .mailbox import Mailbox

SMTP_PORT = 1025  # Bridge's SMTP, next to its IMAP on 1143


class OrganiseMixin:
    def _moveable(self: "Mailbox", to: str) -> None:
        if to.startswith("Labels/") or to in ("All Mail", "Starred", "Drafts", "Sent"):
            raise MailboxError(f"{to} isn't a folder you can move to; use mail_label for labels and mail_flag to star")
        if to not in self.folder_names():
            raise MailboxError(f"no folder called {to[:80]} (mail_folders lists them; mail_folder_create makes one)")

    def move_many(self: "Mailbox", ids: list[str], to: str) -> dict[str, Any]:
        self._moveable(to)
        moved, missing, undo = 0, [], []
        for folder, uids in by_folder(ids).items():
            if folder == to:
                continue
            self._select(folder, write=True)
            found = self.existing(uids)
            missing += [f"{folder}#{u}" for u in uids if u not in found]
            if not found:
                continue
            mids = self.message_ids(found)
            check(*self.i.uid("MOVE", ",".join(found), quote(to)), f"moving to {to}")
            moved += len(found)
            undo += [{"mid": mids[u], "from": folder, "to": to} for u in found if mids.get(u)]
        return {"moved": moved, "not_found": missing, "undo": undo}

    def flag_many(self: "Mailbox", ids: list[str], flag: str, on: bool) -> dict[str, Any]:
        imap_flag = {"read": "\\Seen", "starred": "\\Flagged"}.get(flag)
        if imap_flag is None:
            raise MailboxError("flag: read or starred")
        done, missing = 0, []
        for folder, uids in by_folder(ids).items():
            self._select(folder, write=True)
            found = self.existing(uids)
            missing += [f"{folder}#{u}" for u in uids if u not in found]
            if found:
                check(*self.i.uid("STORE", ",".join(found), "+FLAGS.SILENT" if on else "-FLAGS.SILENT", f"({imap_flag})"), "flagging")
                done += len(found)
        return {"changed": done, "not_found": missing}

    def label_many(self: "Mailbox", ids: list[str], name: str, on: bool) -> dict[str, Any]:
        target = name if name.startswith("Labels/") else f"Labels/{name}"
        if target not in self.folder_names():
            raise MailboxError(f"no label called {name[:60]} (mail_folder_create with kind=label makes one)")
        done, missing, mids = 0, [], []
        for folder, uids in by_folder(ids).items():
            self._select(folder, write=on)  # Bridge refuses COPY from a folder opened read-only
            found = self.existing(uids)
            missing += [f"{folder}#{u}" for u in uids if u not in found]
            if not found:
                continue
            if on:
                check(*self.i.uid("COPY", ",".join(found), quote(target)), "labelling")
                done += len(found)
            else:
                mids += [m for m in self.message_ids(found).values() if m]
        if mids:  # unlabel: the same messages, found under the label by Message-ID, taken out there
            self._select(target, write=True)
            under = self.uids_of(mids)
            if under:
                check(*self.i.uid("STORE", ",".join(under), "+FLAGS.SILENT", "(\\Deleted)"), "unlabelling")
                self._expunge(under)
                done += len(under)
        return {"changed": done, "not_found": missing}

    def _expunge(self: "Mailbox", uids: list[str]) -> None:
        """Only these: a plain EXPUNGE would also take anything else marked deleted in the folder."""
        if "UIDPLUS" in self.i.capabilities:
            self.i.uid("EXPUNGE", ",".join(uids))
        else:
            self.i.expunge()

    def undo_moves(self: "Mailbox", entries: list[dict[str, str]]) -> int:
        back = 0
        by_dest: dict[str, list[dict[str, str]]] = {}
        for e in entries:
            by_dest.setdefault(e["to"], []).append(e)
        for dest, group in by_dest.items():
            if dest not in self.folder_names():
                continue
            self._select(dest, write=True)
            for origin in {e["from"] for e in group}:
                if origin not in self.folder_names():
                    continue
                uids = self.uids_of([e["mid"] for e in group if e["from"] == origin])
                if uids:
                    check(*self.i.uid("MOVE", ",".join(uids), quote(origin)), "moving back")
                    back += len(uids)
        return back

    def create(self: "Mailbox", name: str, kind: str = "folder") -> str:
        if not NAME_RE.fullmatch(name) or name.strip() != name:
            raise MailboxError("name: up to 60 letters, digits, spaces and . & ( ) ' + , - _")
        full = ("Labels/" if kind == "label" else "Folders/") + name
        other = ("Folders/" if kind == "label" else "Labels/") + name
        if full not in self.folder_names():
            if other in self.folder_names():  # Proton Mail refuses a folder and a label of one name
                raise MailboxError(f"there's already a {'folder' if kind == 'label' else 'label'} called {name[:60]}; "
                                   "Proton Mail needs folders and labels to have different names")
            check(*self.i.create(quote(full)), f"making {full}")
            self._forget_folders()
        return full

    def rename(self: "Mailbox", old: str, new: str) -> str:
        if old in SYSTEM or not old.startswith(("Folders/", "Labels/")):
            raise MailboxError("only your own folders and labels can be renamed")
        if not NAME_RE.fullmatch(new):
            raise MailboxError("name: up to 60 letters, digits, spaces and . & ( ) ' + , - _")
        full = old.split("/", 1)[0] + "/" + new
        check(*self.i.rename(quote(old), quote(full)), "renaming")
        self._forget_folders()
        return full

    def delete_folder(self: "Mailbox", name: str) -> None:
        """The folder or label goes; Proton keeps its messages (a folder's move to the inbox)."""
        if name in SYSTEM or not name.startswith(("Folders/", "Labels/")):
            raise MailboxError("only your own folders and labels can be deleted")
        check(*self.i.delete(quote(name)), "deleting")
        self._forget_folders()

    def save_draft(self: "Mailbox", msg: EmailMessage) -> None:
        check(*self.i.append("Drafts", "(\\Draft \\Seen)", imaplib.Time2Internaldate(time.time()), msg.as_bytes()), "saving the draft")

    def send(self: "Mailbox", msg: EmailMessage) -> None:
        from . import mailorganise

        with smtplib.SMTP(self.settings.host, mailorganise.SMTP_PORT, timeout=30) as smtp:
            smtp.starttls(context=self.ctx)
            smtp.login(self.creds.user, self.creds.password)
            smtp.send_message(msg)
