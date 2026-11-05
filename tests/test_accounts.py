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
    assert form["email"][0].startswith("localhost.") and form["name"] == ["Maker Bot"]
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


def test_titles_never_collide():
    assert accounts._title("example.com", "maker", {"example.com (maker)", "example.com (maker) 2"}) == "example.com (maker) 3"
    assert accounts._prefix("www.shop.example.co.uk") == "shop" and accounts._prefix("accounts.google.com") == "google"


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
