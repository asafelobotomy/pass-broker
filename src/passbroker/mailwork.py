"""The mail admin's looking and organising tools (mailadmin.py has the admin, sending and limits).

Changes go a folder at a time in one command each, and say which messages weren't there. Moves
are remembered (UNDO_KEEP batches, while the broker runs), so mail_undo can put the last ones
back, including a whole mail_apply over a search.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from .mailadmin import CHANGES_PER_DAY, UNTRUSTED

if TYPE_CHECKING:
    from .broker import Broker

UNDO_KEEP = 20
APPLY_MAX = 500  # messages one mail_apply may change
QUERY = ("sender", "to", "subject", "text", "days", "unread", "starred")


class MailWorkMixin:
    _mail_undo: list[list[dict[str, str]]]

    # ---- looking ----------------------------------------------------------------------------

    async def mail_folders(self: "Broker", client: str, counts: bool = True) -> list[dict[str, Any]]:
        self._admin(client)
        return await self._in_mailbox(client, "folders", lambda mb: mb.folders(counts))

    async def mail_search(self: "Broker", client: str, **query: Any) -> dict[str, Any]:
        self._admin(client)
        found = await self._in_mailbox(client, "search", lambda mb: mb.search(**query), item=query.get("folder", "INBOX"))
        return {**found, "untrusted": "senders and subjects are " + UNTRUSTED}

    async def mail_senders(self: "Broker", client: str, folder: str = "INBOX", days: int = 30, limit: int = 20) -> dict[str, Any]:
        self._admin(client)
        top = await self._in_mailbox(client, "senders", lambda mb: mb.senders(folder, days, limit), item=folder)
        return {"senders": top, "folder": folder, "days": days}

    async def mail_read(self: "Broker", client: str, message_id: str, mark_read: bool = False) -> dict[str, Any]:
        self._admin(client)
        msg = await self._in_mailbox(client, "read", lambda mb: mb.read(message_id, mark_read), item=message_id)
        return {**msg, "untrusted": "this email is " + UNTRUSTED}

    async def mail_thread(self: "Broker", client: str, message_id: str) -> dict[str, Any]:
        self._admin(client)
        rows = await self._in_mailbox(client, "thread", lambda mb: mb.thread(message_id), item=message_id)
        return {"messages": rows, "untrusted": "senders and subjects are " + UNTRUSTED}

    async def mail_attachment(self: "Broker", client: str, message_id: str, name: str) -> dict[str, Any]:
        self._admin(client)
        text = await self._in_mailbox(client, "attachment", lambda mb: mb.attachment_text(message_id, name), item=message_id)
        return {"name": name, "text": text, "untrusted": "this attachment is " + UNTRUSTED}

    # ---- organising -------------------------------------------------------------------------

    def _remember(self: "Broker", undo: list[dict[str, str]]) -> None:
        if undo:
            self._mail_undo = (self._mail_undo + [undo])[-UNDO_KEEP:]

    async def _changing(self: "Broker", client: str, n: int, action: str, work, **log: Any) -> Any:
        """Count `n` changes first; give back what didn't happen (missing messages, a failure)."""
        self._count("changed", n, CHANGES_PER_DAY)
        try:
            result = await self._in_mailbox(client, action, work, **log)
        except BaseException:
            self._count("changed", -n, CHANGES_PER_DAY)
            raise
        done = result.get("moved", result.get("changed", n))
        if done < n:
            self._count("changed", done - n, CHANGES_PER_DAY)
        return result

    async def mail_move(self: "Broker", client: str, message_ids: list[str], to: str) -> dict[str, Any]:
        self._admin(client)
        ids = self._ids(message_ids)
        result = await self._changing(client, len(ids), "move", lambda mb: mb.move_many(ids, to), item=to, count=len(ids))
        self._remember(result.pop("undo"))
        return {"status": "moved", "count": result["moved"], "to": to, "not_found": result["not_found"]}

    async def mail_flag(self: "Broker", client: str, message_ids: list[str], flag: str, on: bool = True) -> dict[str, Any]:
        self._admin(client)
        ids = self._ids(message_ids)
        result = await self._changing(client, len(ids), "flag", lambda mb: mb.flag_many(ids, flag, on), item=flag, count=len(ids))
        return {"status": "done", "count": result["changed"], "not_found": result["not_found"]}

    async def mail_label(self: "Broker", client: str, message_ids: list[str], label: str, on: bool = True) -> dict[str, Any]:
        self._admin(client)
        ids = self._ids(message_ids)
        result = await self._changing(client, len(ids), "label", lambda mb: mb.label_many(ids, label, on), item=label, count=len(ids))
        return {"status": "labelled" if on else "unlabelled", "count": result["changed"], "not_found": result["not_found"]}

    async def mail_apply(self: "Broker", client: str, action: str, target: str = "", on: bool = True,
                         folder: str = "INBOX", **query: Any) -> dict[str, Any]:
        """Move, flag or label everything a search matches (at most APPLY_MAX), in one go."""
        from .broker import BrokerError

        self._admin(client)
        if action not in ("move", "flag", "label") or (action != "flag" and not target):
            raise BrokerError("action: move (target = a folder), flag (target = read or starred) or label (target = a label)")
        query = {k: v for k, v in query.items() if k in QUERY}
        uids = await self._in_mailbox(client, None, lambda mb: mb.matching(folder, **query))
        if not uids:
            return {"status": "nothing matched", "count": 0}
        if len(uids) > APPLY_MAX:
            raise BrokerError(f"{len(uids)} messages match; narrow the search to at most {APPLY_MAX}")
        ids = [f"{folder}#{u}" for u in uids]
        work = {"move": lambda mb: mb.move_many(ids, target), "flag": lambda mb: mb.flag_many(ids, target or "read", on),
                "label": lambda mb: mb.label_many(ids, target, on)}[action]
        result = await self._changing(client, len(ids), f"apply_{action}", work, item=target or folder, count=len(ids))
        self._remember(result.pop("undo", []))
        return {"status": "done", "action": action, "count": result.get("moved", result.get("changed", 0)),
                "matched": len(ids), **({"undo": "mail_undo puts them back"} if action == "move" else {})}

    async def mail_undo(self: "Broker", client: str) -> dict[str, Any]:
        """Put back the last batch of moved messages."""
        self._admin(client)
        if not self._mail_undo:
            return {"status": "nothing to undo"}
        batch = self._mail_undo.pop()
        try:
            back = await self._in_mailbox(client, "undo", lambda mb: mb.undo_moves(batch), count=len(batch))
        except BaseException:
            self._mail_undo.append(batch)
            raise
        return {"status": "moved back", "count": back, "left_to_undo": len(self._mail_undo)}

    async def mail_folder_create(self: "Broker", client: str, name: str, kind: str = "folder") -> dict[str, Any]:
        self._admin(client)
        full = await self._in_mailbox(client, "folder_create", lambda mb: mb.create(name, kind), item=name)
        return {"status": "ready", "name": full}

    async def mail_folder_rename(self: "Broker", client: str, name: str, new_name: str) -> dict[str, Any]:
        self._admin(client)
        full = await self._in_mailbox(client, "folder_rename", lambda mb: mb.rename(name, new_name), item=name)
        return {"status": "renamed", "name": full}

    async def mail_folder_delete(self: "Broker", client: str, name: str, reason: str = "") -> dict[str, Any]:
        import secrets

        from .vault import Login

        self._admin(client)
        placeholder = Login(f"mailfolder:{secrets.token_hex(4)}", f"mail folder {name[:60]}", (), None, False)
        await self._approve(client, placeholder, "your mailbox", "mail_folder_delete", f"delete the mail folder {name[:60]}",
                            f"Folder or label: {name[:80]}\nProton keeps its messages (a folder's go back to the inbox).\n", reason)
        self._admin(client)  # still the admin after the wait
        await self._in_mailbox(client, "folder_delete", lambda mb: mb.delete_folder(name), item=name)
        return {"status": "deleted", "name": name}
