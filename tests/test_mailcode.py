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


def _mail(sender: str, subject: str, body: str, age_s: float) -> bytes:
    return (f"From: {sender}\r\nTo: me@proton.me\r\nSubject: {subject}\r\n"
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
        self.messages, self.password = messages, password
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
                    send(f"* CAPABILITY IMAP4rev1 {'AUTH=PLAIN' if tls else 'STARTTLS LOGINDISABLED'}\r\n{tag} OK done\r\n")
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
                elif cmd == "EXAMINE":
                    send(f"* {len(self.messages)} EXISTS\r\n{tag} OK [READ-ONLY] done\r\n")
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
