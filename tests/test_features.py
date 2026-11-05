"""Per-bot access, the typing guard, WebSockets, email codes, keys and device actions."""

import asyncio
import json
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from passbroker import devices as devices_mod
from passbroker.approvals import GrantCache, StaticApprover
from passbroker.audit import AuditLog
from passbroker.bots import Bots
from passbroker.broker import Broker, BrokerError
from passbroker.browser import Browser, BrowserError
from passbroker.devices import Device, DeviceError, DeviceStore
from passbroker.keys import Key, KeyStore
from passbroker.mailcode import MailSettings, extract_code, site_domains
from passbroker.redact import Redactor
from passbroker.vault import MockBackend

from .site import PASSWORD, TOTP, Site

KEY_PASS = "Ledger-Passphrase-42"
ROUTER_PASS = "Router-Admin-99"
MAILBOT = "conn1/mailbot"


@pytest.fixture
def site():
    with Site() as s:
        yield s


@pytest.fixture
async def setup(tmp_path, site):
    items = site.vault() + [
        {"title": "Ledger key", "urls": [], "password": KEY_PASS},
        {"title": "Router", "urls": [], "password": ROUTER_PASS},
        {"title": "Mail bridge", "urls": [], "username": "me@proton.me", "password": "bridge-pw-1234"},
    ]
    (tmp_path / "vault.json").write_text(json.dumps(items))
    r = Redactor()
    browser = Browser(tmp_path / "p", r, headless=True, allow_private=True)
    await browser.start()
    bots = Bots(tmp_path / "bots.json")
    keys = KeyStore(tmp_path / "keys.json")
    devs = DeviceStore(tmp_path / "devices.json")
    backend = MockBackend(tmp_path / "vault.json", r)
    approver = StaticApprover(True)
    broker = Broker(backend, browser, approver, GrantCache(0), AuditLog(tmp_path / "audit.jsonl", r), r,
                    allow_http_localhost=True, bots=bots, keys=keys, devices=devs, mail=MailSettings(item="Mail bridge"))
    handles = {l.title: l.handle for l in backend.list_logins()}
    yield broker, bots, handles, approver
    await browser.stop()
    audit = (tmp_path / "audit.jsonl").read_text() if (tmp_path / "audit.jsonl").exists() else ""
    for secret in (PASSWORD, TOTP, KEY_PASS, ROUTER_PASS, "bridge-pw-1234"):
        assert secret not in audit


async def test_bots_only_see_and_use_what_they_are_granted(setup, site):
    broker, bots, handles, _ = setup
    bots.check("conn1", "mailbot", "list")
    assert await broker.list_logins(MAILBOT) == []
    with pytest.raises(BrokerError, match="isn't allowed to use the login 'Test Site'"):
        await broker.fill_login(MAILBOT, handles["Test Site"])
    bots.set_access("mailbot", {"logins": ["Test Site"]})
    assert [l["title"] for l in await broker.list_logins(MAILBOT)] == ["Test Site"]
    s = await broker.browser.session(MAILBOT)
    await s.navigate(site.url("/login"))
    assert (await broker.fill_login(MAILBOT, handles["Test Site"], reason="check the invoices"))["status"] == "submitted"
    title, body = broker.approver.asked[-1]
    assert "Bot's reason: check the invoices" in body


async def test_typing_guard(setup, site):
    broker, *_ = setup
    s = await broker.browser.session("grok")
    await s.navigate(site.url("/login"))
    snap = await s.snapshot()
    pw = next(e for e in snap["frames"][0]["elements"] if e.get("type") == "password")
    user = next(e for e in snap["frames"][0]["elements"] if e.get("name") == "Username")
    with pytest.raises(BrowserError, match="password or code field"):
        await s.type_text(pw["ref"], "guess")
    broker.redactor.add(PASSWORD)
    with pytest.raises(BrowserError, match="contains a secret"):
        await s.type_text(user["ref"], f"x{PASSWORD}x")
    await s.type_text(user["ref"], "alice")


async def test_websockets_to_private_addresses_are_blocked(tmp_path):
    hits = []
    server = await asyncio.start_server(lambda r, w: hits.append(1) or w.close(), "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    b = Browser(tmp_path / "q", Redactor(), headless=True)
    await b.start()
    try:
        s = await b.session("t")
        await s.page.set_content(f"<script>new WebSocket('ws://127.0.0.1:{port}/x')</script>")
        await s.page.wait_for_timeout(1500)
        assert hits == []
    finally:
        await b.stop()
        server.close()


async def test_email_code_is_read_and_filled_without_the_bot_seeing_it(setup, site):
    broker, bots, handles, _ = setup
    seen = {}

    def fake_fetch(settings, user, password, domains, to=""):
        seen.update(user=user, password=password, domains=domains, to=to)
        return TOTP

    broker.mail_fetch = fake_fetch
    bots.set_access("mailbot", {"logins": ["Test Site"]})
    s = await broker.browser.session(MAILBOT)
    await s.navigate(site.url("/otp"))
    with pytest.raises(BrokerError, match="email codes"):
        await broker.fill_email_code(MAILBOT, handles["Test Site"])
    bots.set_access("mailbot", {"logins": ["Test Site"], "email_codes": True})
    result = await broker.fill_email_code(MAILBOT, handles["Test Site"])
    assert TOTP not in json.dumps(result) and site.posts[-1] == ("/otp", {"otp": [TOTP]})
    assert seen == {"user": "me@proton.me", "password": "bridge-pw-1234", "domains": {"localhost"}, "to": ""}  # not a bot-made account


def test_code_extraction():
    assert extract_code("Your GitHub launch code", "Your verification code is 482913.") == "482913"
    assert extract_code("Sign in to Proton", "Use code: AB12CD to continue") == "AB12CD"
    assert extract_code("Hello", "Order 12345678 shipped") is None
    assert extract_code("Your code", "Enter 552211 to sign in") == "552211"
    assert site_domains(["https://account.proton.me", "https://www.github.com/login", "https://shop.example.co.uk"]) == {"proton.me", "github.com", "example.co.uk"}


@pytest.mark.needs("gpg")
async def test_encrypt_then_decrypt_with_a_vault_key(setup):
    broker, bots, _, approver = setup
    broker.keys.add(Key(name="ledger", item="Ledger key", note="the finance ledger"))
    with pytest.raises(BrokerError, match="isn't allowed to use the key"):
        await broker.encrypt_text(MAILBOT, "ledger", "x")
    bots.set_access("mailbot", {"keys": ["ledger"]})
    assert await broker.list_keys(MAILBOT) == [{"key": "ledger", "note": "the finance ledger"}]
    sealed = (await broker.encrypt_text(MAILBOT, "ledger", "balance: 1,204.50"))["ciphertext"]
    assert sealed.startswith("-----BEGIN PGP MESSAGE-----") and KEY_PASS not in sealed and approver.asked == []
    assert (await broker.decrypt_text(MAILBOT, "ledger", sealed, reason="monthly report"))["text"] == "balance: 1,204.50"
    assert "decrypt text with the key 'ledger'" in approver.asked[-1][0]
    with pytest.raises(BrokerError):
        await broker.decrypt_text(MAILBOT, "ledger", "not ciphertext")


def test_device_actions_never_target_this_pc():
    for host in ("localhost", "127.0.0.1", socket.gethostname()):
        with pytest.raises(DeviceError, match="not on this PC"):
            devices_mod.validate(Device(name="x", kind="ssh", host=host, command="true"))
    with pytest.raises(DeviceError, match="not on this PC"):
        devices_mod.validate(Device(name="x", kind="http", url="http://127.0.0.1:8080/", item="Router", auth="basic", plain_http_ok=True))
    with pytest.raises(DeviceError):
        devices_mod.validate(Device(name="x", kind="wol", mac="nonsense"))
    devices_mod.validate(Device(name="nas", kind="wol", mac="aa:bb:cc:dd:ee:ff"))


def test_ssh_host_cannot_be_an_ssh_option(monkeypatch):
    """`-oProxyCommand=...` as a host would make ssh run a command on this PC."""
    for host in ("-oProxyCommand=touch /tmp/x", "-p22", "user@nas", "nas;id", ""):
        with pytest.raises(DeviceError, match="host name"):
            devices_mod.validate(Device(name="x", kind="ssh", host=host, command="true"))
    with pytest.raises(DeviceError, match="ssh user"):
        devices_mod.validate(Device(name="x", kind="ssh", host="nas.example.org", user="-oX", command="true"))
    seen = {}
    monkeypatch.setattr(devices_mod.subprocess, "run", lambda argv, **k: seen.setdefault("argv", argv) and type("P", (), {"returncode": 0, "stdout": b"", "stderr": b""})())
    devices_mod.run(Device(name="x", kind="ssh", host="nas.example.org", user="admin", command="uptime"), None)
    argv = seen["argv"]
    assert argv[argv.index("--") + 1 :] == ["nas.example.org", "uptime"]  # the host comes after --


async def test_http_device_action_returns_only_done(setup, monkeypatch):
    broker, bots, _, _ = setup
    got = []

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_POST(self):
            got.append(self.rfile.read(int(self.headers["content-length"])).decode())
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"router says hi")

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    monkeypatch.setattr(devices_mod, "_this_pc", lambda host: False)  # stand in for a router on the LAN
    try:
        broker.devices.add(Device(name="wake-nas", kind="http", plain_http_ok=True, url=f"http://127.0.0.1:{httpd.server_address[1]}/wake",
                                  auth="body", body='{"password": "{secret}", "target": "nas"}', item="Router"))
        bots.set_access("mailbot", {"devices": ["wake-nas"]})
        result = await broker.run_device_action(MAILBOT, "wake-nas", reason="nightly backup")
        assert result == {"result": "done"}
        assert json.loads(got[0]) == {"password": ROUTER_PASS, "target": "nas"}
    finally:
        httpd.shutdown()


def test_password_over_plain_http_needs_consent_and_methods_are_standard():
    d = Device(name="x", kind="http", url="http://router.example.org/api", item="Router", auth="bearer")
    with pytest.raises(DeviceError, match="unencrypted"):
        devices_mod.validate(d)
    d.plain_http_ok = True
    devices_mod.validate(d)
    devices_mod.validate(Device(name="x", kind="http", url="http://router.example.org/api"))  # no password: fine
    with pytest.raises(DeviceError, match="method"):
        devices_mod.validate(Device(name="x", kind="http", url="https://router.example.org/", method="TRACE"))
