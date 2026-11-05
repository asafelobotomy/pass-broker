"""Reading an emailed code from a fake Proton Mail Bridge: STARTTLS, the pinned certificate,
the sender's domain, the age limit and the newest message."""

import email.utils
import imaplib
import socket
import ssl
import threading
import time

import pytest

from passbroker.mailcode import MailSettings, fetch_code

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


class FakeBridge:
    """Just enough IMAP4rev1 for imaplib: CAPABILITY, STARTTLS, LOGIN, EXAMINE, SEARCH, FETCH."""

    def __init__(self, key, cert, messages=MESSAGES, password="bridge-pass"):
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ctx.load_cert_chain(cert, key)
        self.folders = messages if isinstance(messages, dict) else {"INBOX": messages}  # folder -> messages
        self.messages, self.password = self.folders.get("INBOX", []), password
        self.sock = socket.create_server(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.logins: list[str] = []
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._session, args=(conn,), daemon=True).start()

    def _session(self, conn):
        f = conn.makefile("rwb")
        send = lambda s: (f.write(s if isinstance(s, bytes) else s.encode()), f.flush())
        send("* OK fake Bridge ready\r\n")
        tls = False
        try:
            while line := f.readline():
                tag, cmd, *rest = line.decode().rstrip("\r\n").split(" ", 2)
                arg = rest[0] if rest else ""
                cmd = cmd.upper()
                if cmd == "CAPABILITY":
                    send(f"* CAPABILITY IMAP4rev1 {'AUTH=PLAIN MOVE' if tls else 'STARTTLS LOGINDISABLED'}\r\n{tag} OK done\r\n")
                elif cmd == "STARTTLS":
                    send(f"{tag} OK begin TLS\r\n")
                    conn = self.ctx.wrap_socket(conn, server_side=True)
                    f, tls = conn.makefile("rwb"), True
                    send = lambda s, f=f: (f.write(s if isinstance(s, bytes) else s.encode()), f.flush())
                elif cmd == "LOGIN":
                    user, pw = arg.split(" ", 1)
                    self.logins.append(user)
                    ok = tls and pw.strip('"') == self.password
                    send(f"{tag} OK logged in\r\n" if ok else f"{tag} NO wrong password\r\n")
                elif cmd == "LIST":
                    pattern = arg.split(" ", 1)[-1].strip('"') if arg else "*"
                    names = [n for n in self.folders if pattern in ("*", "%") or n == pattern]
                    send("".join(f'* LIST (\\HasNoChildren) "/" "{name}"\r\n' for name in names) + f"{tag} OK done\r\n")
                elif cmd == "CREATE":
                    self.folders.setdefault(arg.strip('"'), [])
                    send(f"{tag} OK created\r\n")
                elif cmd == "UID":  # UIDs are positions; a moved message leaves a None behind
                    sub, _, rest = arg.partition(" ")
                    live = [(i + 1, m) for i, m in enumerate(self.messages) if m is not None]
                    if sub.upper() == "SEARCH":
                        send(f"* SEARCH {' '.join(str(u) for u, _ in live)}\r\n{tag} OK done\r\n")
                    elif sub.upper() == "FETCH":
                        want = {int(x) for x in rest.split(" ", 1)[0].split(",")}
                        out = b""
                        for u, m in live:
                            if u in want:
                                head = m.split(b"\r\n\r\n", 1)[0] + b"\r\n\r\n"
                                out += f"* {u} FETCH (UID {u} BODY[HEADER] {{{len(head)}}}\r\n".encode() + head + b")\r\n"
                        send(out + f"{tag} OK done\r\n".encode())
                    elif sub.upper() == "MOVE":
                        ids, dest = rest.split(" ", 1)
                        for x in ids.split(","):
                            self.folders.setdefault(dest.strip('"'), []).append(self.messages[int(x) - 1])
                            self.messages[int(x) - 1] = None
                        send(f"{tag} OK moved\r\n")
                elif cmd in ("EXAMINE", "SELECT"):
                    name = arg.strip().strip('"')
                    if name not in self.folders:
                        send(f"{tag} NO no such folder\r\n")
                        continue
                    self.messages = self.folders[name]
                    mode = "READ-ONLY" if cmd == "EXAMINE" else "READ-WRITE"
                    send(f"* {len(self.messages)} EXISTS\r\n{tag} OK [{mode}] done\r\n")
                elif cmd == "SEARCH":
                    send(f"* SEARCH {' '.join(str(i + 1) for i in range(len(self.messages)))}\r\n{tag} OK done\r\n")
                elif cmd == "FETCH":
                    n = int(arg.split(" ", 1)[0])
                    raw = self.messages[n - 1]
                    send(f"* {n} FETCH (BODY[] {{{len(raw)}}}\r\n".encode() + raw + b")\r\n" + f"{tag} OK done\r\n".encode())
                elif cmd == "LOGOUT":
                    send(f"* BYE\r\n{tag} OK bye\r\n")
                    return
                else:
                    send(f"{tag} BAD unknown\r\n")
        except (OSError, ValueError):
            return
        finally:
            conn.close()

    def close(self):
        self.sock.close()


@pytest.fixture
def bridge(tmp_path):
    key, cert = _self_signed(tmp_path, "bridge")
    b = FakeBridge(key, cert)
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
