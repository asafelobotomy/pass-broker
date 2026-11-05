"""The broker against a real headless Chromium and the local test site."""

import json

import pytest

from passbroker.approvals import GrantCache, StaticApprover
from passbroker.audit import AuditLog
from passbroker.broker import Broker, BrokerError
from passbroker.browser import Browser, BrowserError
from passbroker.redact import Redactor
from passbroker.vault import MockBackend

from .site import PASSWORD, TOTP, Site


@pytest.fixture
def site():
    with Site() as s:
        yield s


@pytest.fixture
async def make(tmp_path, site):
    made = []

    async def _make(approve=True, grant_s=600, approver=None):
        vault = tmp_path / "vault.json"
        vault.write_text(json.dumps(site.vault()))
        r = Redactor()
        browser = Browser(tmp_path / f"profile{len(made)}", r, headless=True, allow_private=True)
        await browser.start()
        approver = approver or StaticApprover(approve)
        broker = Broker(MockBackend(vault, r), browser, approver, GrantCache(grant_s), AuditLog(tmp_path / "audit.jsonl", r), r, allow_http_localhost=True)
        logins = {l["title"]: l["handle"] for l in await broker.list_logins("test")}
        made.append(browser)
        return broker, logins, approver

    yield _make
    for b in made:
        await b.stop()
    audit = (tmp_path / "audit.jsonl").read_text() if (tmp_path / "audit.jsonl").exists() else ""
    assert PASSWORD not in audit and TOTP not in audit


def no_secrets(obj):
    text = json.dumps(obj)
    assert PASSWORD not in text and TOTP not in text and "nowhere-Secret-77" not in text
    return obj


async def test_list_logins_has_no_secrets(make):
    broker, logins, _ = await make()
    no_secrets(await broker.list_logins("test"))
    assert set(logins) == {"Test Site", "No Website"}


async def test_fill_login_submits_and_reveals_nothing(make, site):
    broker, logins, approver = await make()
    await (await broker.browser.session("grok")).navigate(site.url("/login"))
    result = no_secrets(await broker.fill_login("grok", logins["Test Site"]))
    assert result["status"] == "submitted" and result["url"].endswith("/welcome")
    assert site.posts[-1] == ("/session", {"login": ["alice"], "password": [PASSWORD]})
    [(title, body)] = approver.asked
    assert title == "grok wants to sign in to localhost" and "Test Site" in body


async def test_two_step_login(make, site):
    broker, logins, _ = await make()
    await (await broker.browser.session("grok")).navigate(site.url("/step1"))
    result = no_secrets(await broker.fill_login("grok", logins["Test Site"]))
    assert result["url"].endswith("/welcome")
    assert [p for p, _ in site.posts] == ["/step1", "/session"]


async def test_wrong_origin_refused_before_asking(make, site):
    broker, logins, approver = await make()
    await (await broker.browser.session("grok")).navigate(site.url("/login", host="127.0.0.1"))
    with pytest.raises(BrokerError, match="not a site saved"):
        await broker.fill_login("grok", logins["Test Site"])
    assert approver.asked == [] and site.posts == []


async def test_cross_origin_iframe_refused(make, site):
    broker, logins, approver = await make()
    await (await broker.browser.session("grok")).navigate(site.url("/framed"))
    await (await broker.browser.session("grok")).page.wait_for_timeout(500)
    with pytest.raises(BrokerError, match="127.0.0.1"):
        await broker.fill_login("grok", logins["Test Site"])
    assert approver.asked == [] and site.posts == []


async def test_denied_approval_fills_nothing(make, site):
    broker, logins, _ = await make(approve=False)
    await (await broker.browser.session("grok")).navigate(site.url("/login"))
    with pytest.raises(BrokerError, match="denied"):
        await broker.fill_login("grok", logins["Test Site"])
    assert site.posts == []
    snap = no_secrets(await (await broker.browser.session("grok")).snapshot())
    pw = next(e for e in snap["frames"][0]["elements"] if e.get("type") == "password")
    assert pw == {**pw, "sensitive": True, "filled": False}


async def test_item_without_website_cannot_fill(make, site):
    broker, logins, _ = await make()
    await (await broker.browser.session("grok")).navigate(site.url("/login"))
    with pytest.raises(BrokerError, match="no saved website"):
        await broker.fill_login("grok", logins["No Website"])


async def test_unknown_handle(make, site):
    broker, _, _ = await make()
    await (await broker.browser.session("grok")).navigate(site.url("/login"))
    with pytest.raises(BrokerError, match="unknown handle"):
        await broker.fill_login("grok", "h_madeup")


async def test_grant_is_reused_then_expires_per_client(make, site):
    broker, logins, approver = await make()
    for _ in range(2):
        await (await broker.browser.session("grok")).navigate(site.url("/login"))
        await broker.fill_login("grok", logins["Test Site"])
    assert len(approver.asked) == 1
    await (await broker.browser.session("claude")).navigate(site.url("/login"))
    await broker.fill_login("claude", logins["Test Site"])  # a different client asks again
    assert len(approver.asked) == 2


async def test_totp_field(make, site):
    broker, logins, _ = await make()
    await (await broker.browser.session("grok")).navigate(site.url("/otp"))
    result = no_secrets(await broker.fill_totp("grok", logins["Test Site"]))
    assert result["url"].endswith("/welcome") and site.posts[-1] == ("/otp", {"otp": [TOTP]})


async def test_totp_split_boxes(make, site):
    broker, logins, _ = await make()
    await (await broker.browser.session("grok")).navigate(site.url("/split"))
    result = no_secrets(await broker.fill_totp("grok", logins["Test Site"]))
    assert result["url"].endswith("/welcome") and site.posts[-1] == ("/otp", {"otp": [TOTP]})


async def test_leaky_page_is_scrubbed_and_screenshot_withheld(make, site):
    broker, logins, _ = await make()
    b = await broker.browser.session("grok")
    await b.navigate(site.url("/leaky"))
    no_secrets(await broker.fill_login("grok", logins["Test Site"]))
    # The page copied the password into its text and a plain input before we cleared the field.
    assert PASSWORD in await b.page.inner_text("#echo")
    snap = no_secrets(await b.snapshot())
    assert "[REDACTED]" in json.dumps(snap)
    with pytest.raises(BrowserError, match="withheld"):
        await b.screenshot()


async def test_password_cleared_when_page_stays(make, site):
    broker, logins, _ = await make()
    b = await broker.browser.session("grok")
    await b.navigate(site.url("/stay"))
    await broker.fill_login("grok", logins["Test Site"])
    assert await b.page.input_value("#pw") == ""
    await b.page.click("#show")  # even with the field turned into plain text
    no_secrets(await b.snapshot())
    png = await b.screenshot()
    assert png.startswith(b"\x89PNG")


async def test_snapshot_refs_drive_the_page(make, site):
    broker, _, _ = await make()
    b = await broker.browser.session("grok")
    await b.navigate(site.url("/login"))
    snap = await b.snapshot()
    user = next(e for e in snap["frames"][0]["elements"] if e.get("name") == "Username")
    await b.type_text(user["ref"], "typed-by-model")
    assert await b.page.input_value("#login_field") == "typed-by-model"


async def test_navigate_refuses_other_schemes(make):
    broker, _, _ = await make()
    for url in ["file:///etc/passwd", "javascript:alert(1)", "chrome://settings", "view-source:https://x"]:
        with pytest.raises(BrowserError):
            await (await broker.browser.session("grok")).navigate(url)


class NavigatingApprover(StaticApprover):
    """Allows only once the page has gone to `to`: the move always happens during the approval."""

    page = loop = to = None

    def ask(self, title, body):
        import asyncio

        async def go():
            await self.page.evaluate("to => { location.href = to; }", self.to)
            await self.page.wait_for_url("**/evil", timeout=10000)

        asyncio.run_coroutine_threadsafe(go(), self.loop).result(timeout=15)
        return super().ask(title, body)


async def test_page_navigating_away_during_approval_gets_nothing(make, site):
    import asyncio

    approver = NavigatingApprover(True)
    broker, logins, _ = await make(approver=approver)
    s = await broker.browser.session("grok")
    approver.page, approver.loop, approver.to = s.page, asyncio.get_running_loop(), site.url("/evil", host="127.0.0.1")
    await s.navigate(site.url("/login"))
    with pytest.raises(BrokerError, match="127.0.0.1|changed"):
        await broker.fill_login("grok", logins["Test Site"])
    assert len(approver.asked) == 1 and s.page.url.endswith("/evil")  # it was asked, and the page did move
    assert not any(path == "/steal" for path, _ in site.posts)
    assert not any(PASSWORD in str(form) for _, form in site.posts)


async def test_split_boxes_all_hidden_and_cleared(make, site):
    broker, logins, _ = await make()
    b = await broker.browser.session("grok")
    await b.navigate(site.url("/split-stay"))
    await broker.fill_totp("grok", logins["Test Site"])
    snap = no_secrets(await b.snapshot())
    boxes = [e for e in snap["frames"][0]["elements"] if (e.get("name") or "").startswith("digit")]
    assert len(boxes) == 6 and all(e.get("sensitive") and "value" not in e for e in boxes)
    assert [await b.page.locator(".d").nth(i).input_value() for i in range(6)] == [""] * 6


async def test_usernames_masked_for_the_model(make):
    broker, _, _ = await make()
    [site_login] = [l for l in await broker.list_logins("grok") if l["title"] == "Test Site"]
    assert site_login["username"] == "a***"


async def test_private_addresses_blocked(tmp_path, site):
    r = Redactor()
    b = Browser(tmp_path / "p", r, headless=True)
    await b.start()
    try:
        for url in [site.url("/login"), site.url("/login", host="127.0.0.1"), "http://192.168.1.1/", "http://100.100.100.100/", "http://router.local/", "http://box.tail1234.ts.net/"]:
            with pytest.raises(BrowserError, match="blocked"):
                await (await b.session("t")).navigate(url)
    finally:
        await b.stop()


async def test_sessions_are_fresh_after_reset(make, site):
    broker, logins, _ = await make()
    b = await broker.browser.session("grok")
    await b.navigate(site.url("/login"))
    await b.page.context.add_cookies([{"name": "sid", "value": "abc", "url": site.url("/")}])
    other = await broker.browser.session("conn1/other")
    assert await other.page.context.cookies() == []  # each bot has its own cookies
    await broker.browser.end_session("grok")
    fresh = await broker.browser.session("grok")
    assert fresh is not b and await fresh.page.context.cookies() == []


async def test_each_bot_needs_its_own_allow(make, site):
    broker, logins, approver = await make()
    for client in ("conn1/mailbot", "conn1/mailbot", "conn1/planner"):
        await (await broker.browser.session(client)).navigate(site.url("/login"))
        await broker.fill_login(client, logins["Test Site"])
    titles = [t for t, _ in approver.asked]
    assert titles == ["mailbot (via conn1) wants to sign in to localhost", "planner (via conn1) wants to sign in to localhost"]
    assert "self-reported" in approver.asked[0][1]
