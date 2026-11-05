"""Bots making their own accounts: approved, generated in the vault, filled unseen, granted to the maker."""

import json

import pytest

from passbroker import accounts
from passbroker.accounts import AccountSettings
from passbroker.approvals import GrantCache, StaticApprover
from passbroker.audit import AuditLog
from passbroker.bots import Bots
from passbroker.broker import Broker, BrokerError
from passbroker.browser import Browser
from passbroker.redact import Redactor
from passbroker.vault import MockBackend, PasswordRules, ProtonPassBackend

from .conftest import fake_tool
from .site import Site

BOT = "conn/maker"


@pytest.fixture
def site():
    with Site() as s:
        yield s


@pytest.fixture
async def setup(tmp_path, site):
    vault = tmp_path / "vault.json"
    vault.write_text(json.dumps(site.vault()))
    r = Redactor()
    browser = Browser(tmp_path / "profile", r, headless=True, allow_private=True)
    await browser.start()
    bots = Bots(tmp_path / "bots.json")
    bots.check("conn", "maker", "test")
    bots.set_access("maker", {"create_logins": True})
    settings = AccountSettings(vault="Bot Accounts", enabled=True)
    approver = StaticApprover(True)
    backend = MockBackend(vault, r)
    broker = Broker(backend, browser, approver, GrantCache(0), AuditLog(tmp_path / "audit.jsonl", r), r,
                    allow_http_localhost=True, bots=bots, account_settings=lambda: settings)
    yield broker, backend, bots, settings, approver
    await browser.stop()


async def test_make_an_account_and_sign_up_without_seeing_it(setup, site, tmp_path):
    broker, backend, bots, _, approver = setup
    await (await broker.browser.session(BOT)).navigate(site.url("/signup"))
    made = await broker.create_login(BOT, email_alias=True, reason="sign up for the newsletter")
    password = backend._items[backend._index.ref[made["handle"]]]["password"]
    assert made["title"] == "localhost (maker)" and password not in json.dumps(made)
    [(title, body)] = approver.asked
    assert "make an account on localhost" in title and "Bot Accounts" in body and "never sees it" in body
    assert "localhost (maker)" in bots.access("maker")["logins"] and bots.created_today("maker") == 1

    s = await broker.browser.session(BOT)
    await s.page.fill("input[name=name]", "Maker Bot")  # the bot's own field
    result = await broker.fill_signup(BOT, made["handle"])
    assert password not in json.dumps(result) and result["url"].endswith("/welcome")
    path, form = site.posts[-1]
    assert path == "/signup" and form["password"] == [password] and form["confirm"] == [password]
    assert form["email"] == [made["email"]] and made["email"].startswith("maker.") and form["name"] == ["Maker Bot"]
    assert bots.email("maker") == made["email"]  # the bot's address from now on
    assert len(approver.asked) == 1  # approving the account covered its own sign-up form
    assert password not in (tmp_path / "audit.jsonl").read_text()
    assert [l["title"] for l in await broker.list_logins(BOT)] == ["localhost (maker)"]  # and only its own


async def test_refused_unless_set_up_and_allowed(setup, site):
    broker, _, bots, settings, approver = setup
    await (await broker.browser.session(BOT)).navigate(site.url("/signup"))
    settings.enabled = False
    with pytest.raises(BrokerError, match="isn't set up"):
        await broker.create_login(BOT, username="maker1")
    settings.enabled = True
    bots.set_access("maker", {"create_logins": False})
    with pytest.raises(BrokerError, match="isn't allowed to make accounts"):
        await broker.create_login(BOT, username="maker1")
    assert approver.asked == []


async def test_new_login_works_only_on_its_own_site(setup, site):
    broker, _, _, _, _ = setup
    s = await broker.browser.session(BOT)
    await s.navigate(site.url("/signup"))
    made = await broker.create_login(BOT, username="maker1")
    await s.navigate(site.url("/signup", host="127.0.0.1"))
    with pytest.raises(BrokerError, match="not a site saved"):
        await broker.fill_signup(BOT, made["handle"])


async def test_limits(setup, site):
    broker, _, bots, _, approver = setup
    await (await broker.browser.session(BOT)).navigate(site.url("/signup"))
    with pytest.raises(BrokerError, match="give a username"):
        await broker.create_login(BOT)
    with pytest.raises(BrokerError, match="length"):
        await broker.create_login(BOT, username="maker1", length=6)
    broker.redactor.add("hunter2-Secret")
    with pytest.raises(BrokerError, match="username"):
        await broker.create_login(BOT, username="hunter2-Secret")
    for i in range(accounts.PER_BOT_PER_DAY):
        bots.record_created("maker", f"x{i}", "example.com")
    with pytest.raises(BrokerError, match="at most"):
        await broker.create_login(BOT, username="maker1")
    assert approver.asked == []


async def test_denied_creates_nothing(setup, site):
    broker, backend, bots, _, approver = setup
    approver.answer = False
    await (await broker.browser.session(BOT)).navigate(site.url("/signup"))
    before = len(backend._items)
    with pytest.raises(BrokerError, match="refused"):
        await broker.create_login(BOT, username="maker1")
    assert len(backend._items) == before and bots.created_today("maker") == 0


async def test_every_account_field_is_filled_and_only_those(setup, site):
    broker, backend, _, _, _ = setup
    s = await broker.browser.session(BOT)
    await s.navigate(site.url("/signup-full"))
    made = await broker.create_login(BOT, username="maker1", email_alias=True)
    for name, value in (("first_name", "Maker"), ("phone", "0123"), ("display", "Mr Maker")):
        await s.page.fill(f"input[name={name}]", value)  # the bot's own fields
    await s.page.check("input[name=terms]")
    result = await broker.fill_signup(BOT, made["handle"])
    password = backend._items[backend._index.ref[made["handle"]]]["password"]
    assert password not in json.dumps(result) and result["left_empty"] == []
    assert sorted(result["filled"]) == ["email", "email (confirm)", "password", "password (confirm)", "username"]
    path, form = site.posts[-1]
    assert path == "/signup-full" and form["user_name"] == ["maker1"]
    assert form["email"] == form["email_confirm"] == [made["email"]] and form["pw"] == form["pw2"] == [password]
    assert (form["first_name"], form["phone"], form["display"], form["terms"]) == (["Maker"], ["0123"], ["Mr Maker"], ["yes"])


async def test_email_first_then_password_on_the_next_page(setup, site):
    broker, backend, _, _, approver = setup
    s = await broker.browser.session(BOT)
    await s.navigate(site.url("/join"))
    made = await broker.create_login(BOT, email_alias=True)
    first = await broker.fill_signup(BOT, made["handle"])
    assert first["status"] == "details_submitted" and first["filled"] == ["email"] and s.page.url.endswith("/join2")
    assert site.posts[-1] == ("/join", {"address": [made["email"]]})
    done = await broker.fill_signup(BOT, made["handle"])
    password = backend._items[backend._index.ref[made["handle"]]]["password"]
    assert done["status"] == "submitted" and site.posts[-1] == ("/join2", {"new": [password], "again": [password]})
    assert len(approver.asked) == 1  # both pages covered by approving the account


async def test_a_username_field_with_no_username_is_reported(setup, site):
    broker, _, _, _, _ = setup
    await (await broker.browser.session(BOT)).navigate(site.url("/signup-full"))
    made = await broker.create_login(BOT, email_alias=True)
    result = await broker.fill_signup(BOT, made["handle"])
    assert result["left_empty"] == ["username"] and "create_login" in result["note"]
    assert site.posts[-1][1].get("user_name") is None  # left empty, not filled with the address


async def test_one_email_alias_per_bot_for_good(setup, site):
    broker, backend, bots, _, approver = setup
    made_aliases = []
    real = backend.create_alias
    backend.create_alias = lambda *a: made_aliases.append(real(*a)) or made_aliases[-1]
    got = await broker.email_address(BOT, reason="newsletter")
    assert got["email"] == bots.email("maker") and len(approver.asked) == 1
    assert "every account it makes" in approver.asked[0][1]
    assert (await broker.email_address(BOT))["email"] == got["email"] and len(approver.asked) == 1  # asked once only
    s = await broker.browser.session(BOT)
    for page in ("/signup", "/signup-full"):
        await s.navigate(site.url(page))
        made = await broker.create_login(BOT, username="maker1", email_alias=True)  # asking for a new one changes nothing
        assert made["email"] == got["email"]
        assert f"the bot's own alias {got['email']}" in approver.asked[-1][1]
    assert made_aliases == [got["email"]]
    assert [c.get("email") for c in bots.list()[0]["created"]] == [got["email"]] * 2


async def test_two_requests_at_once_still_make_one_alias(setup, site):
    import asyncio

    broker, backend, bots, _, _ = setup
    calls = []
    real = backend.create_alias
    backend.create_alias = lambda *a: calls.append(1) or real(*a)
    a, b = await asyncio.gather(broker.email_address(BOT), broker.email_address(BOT))
    assert a["email"] == b["email"] == bots.email("maker") and len(calls) == 1


async def test_email_codes_for_a_bot_account_come_only_to_its_alias(setup, site):
    from passbroker.mailcode import MailSettings

    broker, _, bots, _, _ = setup
    s = await broker.browser.session(BOT)
    await s.navigate(site.url("/signup"))
    made = await broker.create_login(BOT, email_alias=True)
    bots.set_access("maker", {"create_logins": True, "email_codes": True, "logins": [made["title"]]})
    broker.mail_path, broker.mail = None, MailSettings(item="Test Site")  # any item stands in for Bridge's
    seen = {}
    broker.mail_fetch = lambda settings, user, password, domains, to="": seen.update(to=to) or "482913"
    await s.navigate(site.url("/otp"))
    await broker.fill_email_code(BOT, made["handle"])
    assert seen == {"to": made["email"]}


async def test_email_address_needs_permission(setup):
    broker, _, bots, settings, approver = setup
    bots.set_access("maker", {"create_logins": False})
    with pytest.raises(BrokerError, match="isn't allowed to have an email address"):
        await broker.email_address(BOT)
    assert approver.asked == [] and bots.email("maker") == ""


def test_titles_never_collide():
    assert accounts._title("example.com", "maker", {"example.com (maker)", "example.com (maker) 2"}) == "example.com (maker) 3"
    assert accounts._prefix("mail-bot") == "mailbot" and accounts._prefix("..") == "bot"


def test_proton_backend_never_handles_the_password(tmp_path):
    """pass-cli generates it: it's in no argument, and the new item is found in the second vault."""
    log = tmp_path / "calls"
    cli = fake_tool(tmp_path, "pass-cli", f"""echo "$@" >> {log}
case "$*" in
  *"item list"*"Bot Accounts"*) echo '{{"items": [{{"id": "n1", "title": "example.com (maker)", "content": {{"urls": ["https://example.com"], "username": "maker1", "totp_uri": ""}}}}]}}' ;;
  *"item list"*) echo '{{"items": []}}' ;;
  *"alias create"*) echo '{{"email": "example.ab12@passmail.net"}}' ;;
esac
""")
    backend = ProtonPassBackend("Agent", lambda: "x", Redactor(), pass_cli=cli, session_dir=tmp_path / "s")
    backend.extra_vault = lambda: "Bot Accounts"
    assert backend.create_alias("Bot Accounts", "example", "why") == "example.ab12@passmail.net"
    login = backend.create_login("Bot Accounts", "example.com (maker)", "https://example.com", "maker1", "", PasswordRules(24, False), "why")
    assert login.title == "example.com (maker)" and [l.title for l in backend.list_logins()] == ["example.com (maker)"]
    create = next(line for line in log.read_text().splitlines() if line.startswith("item create"))
    assert "--generate-password=24,uppercase " in create + " " and "--password" not in create.replace("--generate-password", "")
    assert "--vault-name Bot Accounts" in create


def test_setup_keeps_the_agent_vault_read_only(tmp_path):
    from passbroker.ops import OpError

    cli = fake_tool(tmp_path, "pass-cli", "exit 1\n")
    with pytest.raises(OpError, match="vault of its own"):
        accounts.setup("agent", "passbroker", "Agent", cli)
    with pytest.raises(OpError, match="sign in to pass-cli as yourself"):
        accounts.setup("Bot Accounts", "passbroker", "Agent", cli)


def test_setup_finds_the_brokers_own_agent_among_namesakes(tmp_path, monkeypatch):
    """Three agents called passbroker (old renewals): only the one the broker holds gets editor."""
    log, granted = tmp_path / "calls", tmp_path / "granted"
    granted.write_text("")
    cli = fake_tool(tmp_path, "pass-cli", f"""echo "$@" >> {log}
[ "$1" = info ] && {{ echo "Email: me@example.com"; exit 0; }}
[ "$1 $2" = "vault list" ] && {{ echo '{{"vaults": [{{"name": "Agent"}}]}}'; exit 0; }}
[ "$1 $2" = "agent list" ] && {{ printf -- '- [old1]: passbroker (expires: x)\\n- [mid2]: passbroker (expires: x)\\n- [other]: Bebe (Grok) (expires: x)\\n- [new3]: passbroker (expires: x)\\n'; exit 0; }}
case "$*" in
  *list-access*old1*) echo "- [s0] Personal | Type=Vault | Role=Viewer" ;;
  *list-access*) id=$(echo "$*" | sed 's/.*token-id //'); echo "- [s1] Agent | Type=Vault | Role=Viewer"; grep -q "$id" {granted} && echo "- [g-$id] Bot Accounts | Type=Vault | Role=Editor" ;;
  *"access grant"*) echo "$*" | sed 's/.*token-id \\([a-z0-9]*\\).*/\\1/' >> {granted} ;;
  *"access revoke"*) id=$(echo "$*" | sed 's/.*token-id \\([a-z0-9]*\\).*/\\1/'); grep -v "$id" {granted} > {granted}.n; mv {granted}.n {granted} ;;
esac
exit 0
""")
    monkeypatch.setattr(accounts, "settings_path", lambda: tmp_path / "accounts.json")
    brokers = "mid2"  # the token in the keyring belongs to this one, not the newest
    sees = lambda vault, cli: brokers in granted.read_text().split()
    assert accounts.setup("Bot Accounts", "passbroker", "Agent", cli, sees=sees) == {"vault": "Bot Accounts", "enabled": True}
    calls = log.read_text()
    assert "vault create --name Bot Accounts" in calls
    assert granted.read_text().split() == ["mid2"]  # new3 tried first, then taken back
    assert "revoke --personal-access-token-id new3 --share-id g-new3" in calls
    assert "token-id old1 --vault-name" not in calls  # no Agent access: not the broker's
    assert "--vault-name Agent" not in calls and "agent access grant" not in calls
    assert accounts.load(tmp_path / "accounts.json").enabled


def test_setup_gives_up_cleanly_when_no_agent_matches(tmp_path, monkeypatch):
    from passbroker.ops import OpError

    cli = fake_tool(tmp_path, "pass-cli", """[ "$1" = info ] && { echo "Email: me@example.com"; exit 0; }
[ "$1 $2" = "agent list" ] && { echo '- [a]: passbroker (expires: x)'; exit 0; }
echo '{"vaults": [{"name": "Bot Accounts"}]}'; exit 0
""")
    monkeypatch.setattr(accounts, "settings_path", lambda: tmp_path / "accounts.json")
    with pytest.raises(OpError, match="none of your agents"):
        accounts.setup("Bot Accounts", "passbroker", "Agent", cli, sees=lambda v, c: False)
    assert not (tmp_path / "accounts.json").exists()


def test_trashed_items_are_never_listed(tmp_path):
    """A login you moved to the trash is out of every bot's reach."""
    log = tmp_path / "calls"
    cli = fake_tool(tmp_path, "pass-cli", f"""echo "$@" >> {log}
case "$*" in
  *"item list"*) echo '{{"items": [{{"id": "a1", "state": "Active", "title": "kept", "content": {{"urls": ["https://a.example"], "username": "u", "totp_uri": ""}}}}, {{"id": "t1", "state": "Trashed", "title": "binned", "content": {{"urls": ["https://b.example"], "username": "u", "totp_uri": ""}}}}]}}' ;;
esac
""")
    backend = ProtonPassBackend("Agent", lambda: "x", Redactor(), pass_cli=cli, session_dir=tmp_path / "s")
    assert [l.title for l in backend.list_logins()] == ["kept"]
    assert "--filter-state active" in log.read_text()
