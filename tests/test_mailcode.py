"""Reading an emailed code from a fake Proton Mail Bridge: STARTTLS, the pinned certificate,
the sender's domain, the age limit and the newest message."""

import email.utils
import imaplib
import ssl
import time

import pytest

from passbroker.mailcode import MailSettings, fetch_code

from .fakebridge import FakeBridge
from .test_pinning import _self_signed

pytestmark = pytest.mark.needs("openssl")  # for the test certificates
NOW = time.time()


def _mail(sender: str, subject: str, body: str, age_s: float, to: str = "me@proton.me") -> bytes:
    return (f"From: {sender}\r\nTo: {to}\r\nSubject: {subject}\r\n"
            f"Date: {email.utils.formatdate(NOW - age_s)}\r\nContent-Type: text/plain\r\n\r\n{body}\r\n").encode()


MESSAGES = [
    _mail("Shop <no-reply@shop.example>", "Old code", "Your code is 111111", 3600),
    _mail("Shop <no-reply@mail.shop.example>", "Sign-in code", "Use 482913 to sign in.", 120),
    _mail("Other <hi@other.example>", "Your code", "Your code is 999999", 10),  # newest, wrong sender
]


@pytest.fixture
def bridge(tmp_path):
    key, cert = _self_signed(tmp_path, "bridge")
    b = FakeBridge(key, cert, MESSAGES)
    yield b, cert.read_text()
    b.close()


def test_newest_code_from_the_sites_domain(bridge):
    server, pem = bridge
    settings = MailSettings(item="Bridge", port=server.port, cert_pem=pem)
    assert fetch_code(settings, "me@proton.me", "bridge-pass", {"shop.example"}, now=NOW) == "482913"
    assert server.logins == ["me@proton.me"]  # only after STARTTLS: the server refuses plain logins


def test_too_old_or_other_senders_give_nothing(bridge):
    server, pem = bridge
    settings = MailSettings(item="Bridge", port=server.port, cert_pem=pem, max_age_minutes=1)
    assert fetch_code(settings, "me@proton.me", "bridge-pass", {"shop.example"}, now=NOW) is None  # 2 minutes old
    assert fetch_code(settings, "me@proton.me", "bridge-pass", {"nowhere.example"}, now=NOW) is None


def test_wrong_password_is_an_error(bridge):
    server, pem = bridge
    with pytest.raises(imaplib.IMAP4.error):
        fetch_code(MailSettings(item="Bridge", port=server.port, cert_pem=pem), "me@proton.me", "wrong", {"shop.example"}, now=NOW)


def test_a_different_certificate_is_refused(bridge, tmp_path):
    server, _ = bridge
    _, other = _self_signed(tmp_path, "impostor")
    with pytest.raises(ssl.SSLError):
        fetch_code(MailSettings(item="Bridge", port=server.port, cert_pem=other.read_text()), "me@proton.me", "bridge-pass",
                   {"shop.example"}, now=NOW)
    assert server.logins == []  # the password never went to it


def test_a_bots_alias_gets_only_codes_sent_to_it(tmp_path):
    """The same site emails a code to you and one to the bot's alias: each account gets its own."""
    key, cert = _self_signed(tmp_path, "bridge")
    server = FakeBridge(key, cert, messages=[
        _mail("Shop <no-reply@shop.example>", "Code", "Bot code 246810", 300, to="Maker <maker.x1@passmail.net>"),
        _mail("Shop <no-reply@shop.example>", "Code", "Your code 135791", 60),
    ])
    try:
        settings = MailSettings(item="Bridge", port=server.port, cert_pem=cert.read_text())
        fetch = lambda to: fetch_code(settings, "me@proton.me", "bridge-pass", {"shop.example"}, now=NOW, to=to)
        assert fetch("") == "135791"  # your own sign-in: the newest from the site
        assert fetch("MAKER.x1@passmail.net") == "246810"
        assert fetch("other.y2@passmail.net") is None
    finally:
        server.close()


def test_a_bcc_to_the_alias_counts_by_its_envelope(tmp_path):
    """As Proton forwards it: To names someone else, the envelope header names the alias."""
    key, cert = _self_signed(tmp_path, "bridge")
    raw = _mail("Shop <no-reply@shop.example>", "Code", "Bot code 246810", 30, to="list@shop.example")
    raw = raw.replace(b"Subject:", b"X-SimpleLogin-Envelope-To: maker.x1@passmail.net\r\nDelivered-To: me@proton.me\r\nSubject:")
    server = FakeBridge(key, cert, messages=[raw])
    try:
        settings = MailSettings(item="Bridge", port=server.port, cert_pem=cert.read_text())
        assert fetch_code(settings, "me@proton.me", "bridge-pass", {"shop.example"}, now=NOW, to="maker.x1@passmail.net") == "246810"
    finally:
        server.close()


def test_codes_are_found_in_any_folder_but_trash_and_spam(tmp_path):
    """Your filters file the bot's alias mail into a folder; spam and trash are never read."""
    key, cert = _self_signed(tmp_path, "bridge")
    server = FakeBridge(key, cert, messages={
        "INBOX": [_mail("Other <hi@other.example>", "Hi", "nothing here", 30)],
        "Folders/Aliases": [_mail("Shop <no-reply@shop.example>", "Code", "Your code is 482913", 60, to="maker.x1@passmail.net")],
        "Spam": [_mail("Shop <no-reply@shop.example>", "Code", "Your code is 999999", 5, to="maker.x1@passmail.net")],
        "Trash": [_mail("Shop <no-reply@shop.example>", "Code", "Your code is 888888", 5, to="maker.x1@passmail.net")],
    })
    try:
        settings = MailSettings(item="Bridge", port=server.port, cert_pem=cert.read_text())
        assert fetch_code(settings, "me@proton.me", "bridge-pass", {"shop.example"}, now=NOW, to="maker.x1@passmail.net") == "482913"
        assert fetch_code(settings, "me@proton.me", "bridge-pass", {"shop.example"}, now=NOW) == "482913"
        only = MailSettings(item="Bridge", port=server.port, cert_pem=cert.read_text(), folder="INBOX/none")
        assert fetch_code(only, "me@proton.me", "bridge-pass", {"shop.example"}, now=NOW) is None  # a folder you set: only that
    finally:
        server.close()


def test_all_mail_is_enough_when_bridge_has_it(tmp_path):
    key, cert = _self_signed(tmp_path, "bridge")
    code = _mail("Shop <no-reply@shop.example>", "Code", "Your code is 482913", 60)
    server = FakeBridge(key, cert, messages={"INBOX": [], "All Mail": [code], "Folders/Shop": []})
    try:
        settings = MailSettings(item="Bridge", port=server.port, cert_pem=cert.read_text())
        assert fetch_code(settings, "me@proton.me", "bridge-pass", {"shop.example"}, now=NOW) == "482913"
    finally:
        server.close()


def test_the_bots_folder_is_made_once(tmp_path):
    from passbroker import botmail

    key, cert = _self_signed(tmp_path, "bridge")
    server = FakeBridge(key, cert, messages={"INBOX": []})
    try:
        settings = MailSettings(item="Bridge", port=server.port, cert_pem=cert.read_text())
        assert botmail.make_folder(settings, "me@proton.me", "bridge-pass") is True
        assert "Folders/Bots" in server.folders
        assert botmail.make_folder(settings, "me@proton.me", "bridge-pass") is False  # already there
        with pytest.raises(imaplib.IMAP4.error):
            botmail.make_folder(settings, "me@proton.me", "wrong")
    finally:
        server.close()


def test_the_rule_files_every_bot_alias():
    from passbroker import accounts, botmail

    assert accounts._prefix("anybot").startswith(botmail.PREFIX)
    assert f'"{botmail.PREFIX}*"' in botmail.RULE and f'fileinto "{botmail.FOLDER}"' in botmail.RULE
    assert "X-SimpleLogin-Envelope-To" in botmail.RULE  # a Bcc to the alias is filed too


def test_making_the_folder_needs_email_codes_set_up(tmp_path):
    from passbroker import botmail
    from passbroker.ops import OpError

    with pytest.raises(OpError, match="set up email codes first"):
        botmail.setup("Agent", tmp_path / "mail.json")
