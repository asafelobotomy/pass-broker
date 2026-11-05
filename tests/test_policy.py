"""Per-bot limits: personal details masked, and only listed sites opened."""

import json

import pytest

from passbroker.approvals import GrantCache, StaticApprover
from passbroker.audit import AuditLog
from passbroker.bots import BotError, Bots
from passbroker.broker import Broker
from passbroker.browser import Browser, BrowserError
from passbroker.pii import mask_text
from passbroker.redact import Redactor
from passbroker.vault import MockBackend

from .test_broker import site  # noqa: F401  (fixture)


@pytest.fixture
async def setup(tmp_path, site):  # noqa: F811
    vault = tmp_path / "vault.json"
    vault.write_text(json.dumps(site.vault()))
    r = Redactor()
    browser = Browser(tmp_path / "profile", r, headless=True, allow_private=True)
    await browser.start()
    bots = Bots(tmp_path / "bots.json")
    broker = Broker(MockBackend(vault, r), browser, StaticApprover(True), GrantCache(600), AuditLog(tmp_path / "audit.jsonl", r), r,
                    allow_http_localhost=True, bots=bots)
    yield broker, bots
    await browser.stop()


@pytest.mark.parametrize(
    ("text", "masked"),
    [
        ("mail alice.smith@proton.me now", "mail [email] now"),
        ("?u=bob%40ex.com", "?u=[email]"),
        ("card 4111 1111 1111 1111", "card [card number]"),
        ("IBAN GB82 WEST 1234 5698 7654 32", "IBAN [bank account]"),
        ("ssn 123-45-6789", "ssn [ID number]"),
        ("+44 7700 900123 / 07700 900123 / (555) 010-0199", "[phone] / [phone] / [phone]"),
    ],
)
def test_personal_details_masked(text, masked):
    assert mask_text(text) == masked


@pytest.mark.parametrize("text", ["order 1234567890123", "on 2026-11-04 at 14:30", "$1,299.00", "v1.18.1", "a***@proton.me", "ref 98765"])
def test_ordinary_numbers_left_alone(text):
    assert mask_text(text) == text


async def test_bot_sees_no_personal_details_unless_allowed(setup, site):  # noqa: F811
    broker, bots = setup
    bots.check("conn", "mailbot", "test")
    assert broker.hides_personal("conn/mailbot")
    s = await broker.browser.session("conn/mailbot")
    await s.navigate(site.url("/account"))
    from passbroker.pii import mask_obj

    snap = json.dumps(mask_obj(await s.snapshot()))
    for leak in ("alice@example.com", "bob@example.org", "7700 900123", "4111 1111"):
        assert leak not in snap
    assert "[email]" in snap and "Order 1234567" in snap
    shown = await s.screenshot(hide_personal=True)
    plain = await s.screenshot(hide_personal=False)
    assert shown != plain  # details blacked out
    bots.set_access("mailbot", {"personal_details": True})
    assert not broker.hides_personal("conn/mailbot")


async def test_site_list_limits_pages_and_links(setup, site):  # noqa: F811
    broker, bots = setup
    bots.check("conn", "shopbot", "test")
    s = await broker.browser.session("conn/shopbot")
    await s.navigate(site.url("/account"))  # no list yet: anywhere public

    bots.set_access("shopbot", {"sites_limited": True, "sites": ["http://127.0.0.1/"]})
    await s.navigate(site.url("/account", host="127.0.0.1"))
    with pytest.raises(BrowserError, match="site list"):
        await s.navigate(site.url("/welcome"))
    await s.page.click("#away")  # a link off the list doesn't load
    await s.page.wait_for_timeout(300)
    assert "localhost" not in s.page.url
    audit = (broker.audit._path).read_text()
    assert '"site_refused"' in audit and '"localhost"' in audit

    # the sites of granted logins are allowed too
    bots.set_access("shopbot", {"sites_limited": True, "sites": [], "logins": ["Test Site"]})
    await s.navigate(site.url("/welcome"))
    with pytest.raises(BotError, match="website address"):
        bots.set_access("shopbot", {"sites": ["not a site!"]})


async def test_blocked_pages_never_show(setup, site):  # noqa: F811
    broker, bots = setup
    bots.check("conn", "shopbot", "test")
    bots.set_access("shopbot", {"blocked_pages": ["http://127.0.0.1/Account/Payments"], "logins": ["Test Site"]})
    assert bots.access("shopbot")["blocked_pages"] == ["127.0.0.1/account/payments"]
    s = await broker.browser.session("conn/shopbot")
    with pytest.raises(BrowserError, match="blocked for this bot"):
        await s.navigate(site.url("/account/payments", host="127.0.0.1"))

    await s.navigate(site.url("/shop", host="127.0.0.1"))
    ref = next(e["ref"] for f in (await s.snapshot())["frames"] for e in f["elements"] if e.get("name") == "Payments")
    result = await s.click(ref)
    assert result["url"].endswith("/shop")  # the link's page never loaded
    assert "blocked for this bot" in result["blocked"]  # and the bot is told why

    await s.page.click("#spa")  # the address changes without a page load
    with pytest.raises(BrowserError, match="went back"):
        await s.snapshot()
    assert not s.page.url.endswith("/payments")
    await s.page.click("#spa")
    with pytest.raises(BrowserError, match="blocked"):
        await broker.fill_login("conn/shopbot", (await broker.list_logins("conn/shopbot"))[0]["handle"])
    audit = broker.audit._path.read_text()
    assert '"page_refused"' in audit
