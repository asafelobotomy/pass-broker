"""The mail admin's tools at speed and under pressure: one shared connection, batches, pages,
apply and undo, and the races between the broker, the wizard and your Allow."""

import asyncio
import email.utils
import json
import socket

import pytest

from passbroker import mailadmin, mailorganise
from passbroker.approvals import StaticApprover
from passbroker.broker import BrokerError

from .test_mailadmin import _mail, admin, mail_setup

pytestmark = pytest.mark.needs("openssl")


@pytest.fixture
def mail(tmp_path, monkeypatch):
    yield from mail_setup(tmp_path, monkeypatch)


async def test_one_login_serves_many_calls_and_survives_a_drop(mail):
    broker, server, _, _ = mail
    me = await admin(broker)
    for _ in range(4):
        await broker.mail_folders(me, counts=False)
        await broker.mail_search(me)
    assert len(server.logins) == 1
    broker._mail_pool._mb.imap.sock.shutdown(socket.SHUT_RDWR)  # Bridge restarted, or the connection timed out
    assert (await broker.mail_search(me))["total"] == 2  # retried once on a fresh connection
    assert len(server.logins) == 2


async def test_bridge_login_is_read_once_when_calls_arrive_together(mail):
    broker, _, _, _ = mail
    me = await admin(broker)
    reads = []
    real = broker.backend.secret
    broker.backend.secret = lambda h, f, why: reads.append(f) or real(h, f, why)
    broker._mail_creds = None
    await asyncio.gather(*(broker.mail_folders(me, counts=False) for _ in range(6)))
    assert reads == ["password"]


async def test_pages_senders_and_thread(mail):
    broker, server, _, _ = mail
    me = await admin(broker)
    for n in range(5):
        server.add("INBOX", _mail("Shop <news@shop.example>", f"Deal {n}", "cheap"))
    first = await broker.mail_search(me, limit=3)
    assert (first["total"], first["more"], len(first["messages"])) == (7, True, 3)
    last = await broker.mail_search(me, limit=3, page=3)
    assert (len(last["messages"]), last["more"]) == (1, False)
    assert {m["id"] for m in first["messages"]}.isdisjoint(m["id"] for m in last["messages"])
    top = (await broker.mail_senders(me))["senders"]
    assert top[0] == {"sender": "news@shop.example", "messages": 6, "unread": 6}
    server.folders["All Mail"] = []
    for raw in server.raws("INBOX")[:1]:
        server.add("All Mail", raw)
    reply = _mail("Me <me@proton.me>", "Re: Dinner", "Yes!", to="ann@friend.example").replace(
        b"Subject:", b"In-Reply-To: <dinner@friend.example>\r\nReferences: <dinner@friend.example>\r\nSubject:")
    server.add("All Mail", reply)
    server.add("All Mail", _mail("X <x@other.example>", "Unrelated", "no"))
    broker._mail_pool._mb._forget_folders()  # Bridge always has All Mail; this one was made just now
    dinner = (await broker.mail_search(me, subject="Dinner"))["messages"][0]["id"]
    thread = (await broker.mail_thread(me, dinner))["messages"]
    assert [m["subject"] for m in thread] == ["Dinner", "Re: Dinner"]


async def test_apply_to_a_search_then_undo(mail):
    broker, server, _, _ = mail
    me = await admin(broker)
    for n in range(3):
        server.add("INBOX", _mail("Shop <news@shop.example>", f"Deal {n}", "cheap"))
    done = await broker.mail_apply(me, "move", "Archive", sender="news@shop.example")
    assert (done["count"], done["matched"]) == (4, 4) and len(server.folders["Archive"]) == 4
    assert len(server.folders["INBOX"]) == 1  # only the dinner email stayed
    back = await broker.mail_undo(me)
    assert back["count"] == 4 and len(server.folders["INBOX"]) == 5 and server.folders["Archive"] == []
    assert (await broker.mail_undo(me))["status"] == "nothing to undo"
    starred = await broker.mail_apply(me, "flag", "starred", sender="news@shop.example")
    assert starred["count"] == 4 and sum("\\Flagged" in m["flags"] for m in server.folders["INBOX"]) == 4
    with pytest.raises(BrokerError, match="action"):
        await broker.mail_apply(me, "delete")


async def test_missing_messages_are_reported_and_not_counted(mail):
    broker, server, _, _ = mail
    me = await admin(broker)
    dinner = (await broker.mail_search(me, subject="Dinner"))["messages"][0]["id"]
    got = await broker.mail_move(me, [dinner, "INBOX#999"], "Archive")
    assert (got["count"], got["not_found"]) == (1, ["INBOX#999"])
    assert mailadmin.load_state(broker.mail_admin_path)["today"]["changed"] == 1  # the missing one was given back


async def test_unlabelling_takes_out_only_that_message(mail):
    broker, server, _, _ = mail
    me = await admin(broker)
    dinner, sale = [m["id"] for m in reversed((await broker.mail_search(me))["messages"])]
    await broker.mail_label(me, [dinner, sale], "Family")
    server.folders["Labels/Family"][1]["flags"].add("\\Deleted")  # marked deleted by something else, not to be swept up
    await broker.mail_label(me, [dinner], "Family", on=False)
    assert len(server.folders["Labels/Family"]) == 1


async def test_a_failed_send_is_not_counted(mail, monkeypatch):
    broker, server, _, _ = mail
    me = await admin(broker)
    monkeypatch.setattr(mailorganise, "SMTP_PORT", 1)  # nothing listens there
    with pytest.raises(BrokerError, match="sending failed"):
        await broker.mail_send(me, ["ann@friend.example"], subject="x", body="y")
    assert mailadmin.load_state(broker.mail_admin_path)["today"].get("sent", 0) == 0 and server.sent == []


async def test_removing_the_admin_while_a_send_waits_stops_it(mail):
    broker, server, _, _ = mail
    me = await admin(broker)

    class RemovesFirst(StaticApprover):
        def ask(self, title, body):
            (broker.mail_admin_path).write_text(json.dumps({"admin": "", "since": ""}))  # you, in the wizard
            return super().ask(title, body)

    broker.approver = RemovesFirst(True)
    with pytest.raises(BrokerError, match="only the mail admin"):
        await broker.mail_send(me, ["ann@friend.example"], subject="x", body="y")
    assert server.sent == []


async def test_counting_never_brings_back_a_removed_admin(mail):
    from passbroker import cli, ops

    broker, _, _, _ = mail
    me = await admin(broker)
    dinner = (await broker.mail_search(me, subject="Dinner"))["messages"][0]["id"]
    import unittest.mock

    with unittest.mock.patch.object(ops, "dirs", lambda: (broker.mail_admin_path.parent,) * 3):
        cli.main(["api", "mail-admin", "--remove"])
    broker._count("changed", 1, 500)  # a count landing just after: it must not write the old admin back
    assert mailadmin.load_state(broker.mail_admin_path)["admin"] == ""
    with pytest.raises(BrokerError, match="only the mail admin"):
        await broker.mail_move(me, [dinner], "Archive")


def test_dates_sort_threads():
    from passbroker.mailbox import _when

    assert _when(email.utils.formatdate(0)) == 0 and _when("not a date") == 0.0
