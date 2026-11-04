import json

import pytest

from passbroker.origin import origin_allowed
from passbroker.redact import MASK, Redactor
from passbroker.vault import ProtonPassBackend, VaultError


@pytest.mark.parametrize(
    "page,saved,ok",
    [
        ("https://github.com/login", ["https://github.com"], True),
        ("https://www.github.com/login", ["github.com"], True),
        ("https://gist.github.com/", ["https://github.com"], False),
        ("https://evil.atlassian.net/", ["https://atlassian.net"], False),
        ("https://github.com.evil.io/login", ["https://github.com"], False),
        ("https://evilgithub.com/", ["https://github.com"], False),
        ("https://example.com/", ["https://accounts.example.com"], False),
        ("http://github.com/login", ["https://github.com"], False),
        ("https://xn--gthub-n4a.com/", ["https://github.com"], False),
        ("about:blank", ["https://github.com"], False),
        ("http://localhost:8000/", ["http://localhost:8000"], False),
        ("https://github.com:8443/", ["https://github.com"], False),
        ("https://github.com:8443/", ["https://github.com:8443"], True),
        ("https://github.com:8443/", ["https://github.com:9443"], False),
    ],
)
def test_origin(page, saved, ok):
    assert origin_allowed(page, saved) is ok


def test_origin_subdomains_opt_in():
    assert origin_allowed("https://gist.github.com/", ["https://github.com"], allow_subdomains=True)
    assert not origin_allowed("https://github.com.evil.io/", ["https://github.com"], allow_subdomains=True)


def test_mask_username():
    from passbroker.vault import mask_username

    assert mask_username("alice@proton.me") == "a***@proton.me" and mask_username("bob") == "b***" and mask_username(None) is None


def test_origin_localhost_only_when_allowed():
    assert origin_allowed("http://localhost:8000/x", ["http://localhost:8000"], allow_http_localhost=True)
    assert not origin_allowed("http://127.0.0.1:8000/x", ["http://localhost:8000"], allow_http_localhost=True)


def test_redactor_variants():
    r = Redactor()
    r.add("p@ss w/rd&<1>")
    for text in ["p@ss w/rd&<1>", "p%40ss%20w%2Frd%26%3C1%3E", "p%40ss+w%2Frd%26%3C1%3E", "p@ss w/rd&amp;&lt;1&gt;"]:
        out = r.scrub(f"before {text} after")
        assert MASK in out and text not in out
    assert r.scrub_obj({"a": ["x p@ss w/rd&<1> y"]}) == {"a": [f"x {MASK} y"]}


def _fake_cli(tmp_path, script: str) -> str:
    path = tmp_path / "pass-cli"
    path.write_text("#!/bin/sh\n" + script)
    path.chmod(0o755)
    return str(path)


def test_pass_cli_token_never_in_argv_and_secrets_registered(tmp_path):
    log = tmp_path / "calls"
    items = {"items": [{"id": "it1", "title": "GitHub", "content": {"urls": ["https://github.com"], "username": "alice", "password": "pw-from-list", "totp_uri": "otpauth://totp/x?secret=ABC"}}]}
    (tmp_path / "items.json").write_text(json.dumps(items))
    cli = _fake_cli(
        tmp_path,
        f"""echo "$@ | token=${{PROTON_PASS_PERSONAL_ACCESS_TOKEN:-none}} | reason=$PROTON_PASS_AGENT_REASON" >> {log}
case "$1 $2" in
  "item list") cat {tmp_path}/items.json ;;
  "item view") echo "pw-from-view" ;;
  "login ") exit 0 ;;
esac
""",
    )
    r = Redactor()
    b = ProtonPassBackend("Agent", lambda: "pst_TOKEN::KEY", r, pass_cli=cli)
    [login] = b.list_logins()
    assert login.urls == ("https://github.com",) and login.username == "alice" and login.has_totp
    assert "pw-from-list" not in json.dumps(login.public())
    assert r.scrub("pw-from-list") == MASK  # listing output is registered before anything can echo it
    assert b.secret(login.handle, "password", "test reason") == "pw-from-view"
    calls = log.read_text()
    assert "item view --vault-name Agent --item-id it1 --field password" in calls and "reason=test reason" in calls
    assert "pst_TOKEN" not in calls  # no login was needed, so the token was never handed out


def test_pass_cli_relogin_uses_env_not_argv(tmp_path):
    log = tmp_path / "calls"
    flag = tmp_path / "logged_in"
    cli = _fake_cli(
        tmp_path,
        f"""echo "argv=$@" >> {log}
if [ "$1" = login ]; then [ "$PROTON_PASS_PERSONAL_ACCESS_TOKEN" = "pst_T::K" ] && touch {flag} && exit 0; exit 1; fi
[ -f {flag} ] || {{ echo "not logged in" >&2; exit 1; }}
echo '{{"items": []}}'
""",
    )
    b = ProtonPassBackend("Agent", lambda: "pst_T::K", Redactor(), pass_cli=cli)
    assert b.list_logins() == []
    assert "pst_T" not in log.read_text()


def test_pass_cli_errors_are_scrubbed(tmp_path):
    cli = _fake_cli(tmp_path, 'echo "error near pst_T::K" >&2; exit 1\n')
    b = ProtonPassBackend("Agent", lambda: "pst_T::K", Redactor(), pass_cli=cli)
    with pytest.raises(VaultError) as e:
        b.list_logins()
    assert "pst_T::K" not in str(e.value)


def test_unknown_handle():
    b = ProtonPassBackend("Agent", lambda: "x", Redactor(), pass_cli="/bin/false")
    with pytest.raises(VaultError):
        b.secret("h_guess", "password", "r")


def test_listing_without_secrets_reads_each_item_view(tmp_path):
    """Agent sessions can't use --show-secrets: the listing has titles and ids only."""
    log = tmp_path / "calls"
    (tmp_path / "items.json").write_text(json.dumps({"items": [{"id": "it9", "title": "Forge"}]}))
    cli = _fake_cli(
        tmp_path,
        f"""echo "$@" >> {log}
case "$1 $2" in
  "item list") cat {tmp_path}/items.json ;;
  "item view") echo '{{"item": {{"id": "it9", "content": {{"title": "Forge", "content": {{"Login": {{"email": "carol@forge.example", "username": "", "password": "pw-in-view", "urls": ["https://forge.example", "https://login.forge.example"], "totp_uri": "otpauth://totp/x?secret=SEED"}}}}}}}}}}' ;;
  "item totp") echo '{{"TOTP": "246810"}}' ;;
esac
""",
    )
    b = ProtonPassBackend("Agent", lambda: "x", Redactor(), pass_cli=cli)
    [login] = b.list_logins()
    assert login.urls == ("https://forge.example", "https://login.forge.example")
    assert login.username == "carol@forge.example" and login.has_totp is True
    assert "pw-in-view" not in json.dumps(login.public()) and "SEED" not in json.dumps(login.public())
    assert b.secret(login.handle, "totp", "r") == "246810"
    calls = log.read_text()
    assert "item totp --vault-name Agent --item-id it9 --output json" in calls
    assert calls.count("item view") == 1  # one view per item, not one per field


@pytest.mark.parametrize(
    "out,code",
    [('{"TOTP 1": "123456"}', "123456"), ('[{"field": "totp", "code": "0042137"}]', "0042137"), ("TOTP: 654321\n", "654321"), ("no code", None)],
)
def test_totp_code_parsing(out, code):
    from passbroker.vault import _totp_code

    assert _totp_code(out) == code


def test_bots_registry(tmp_path):
    from passbroker.bots import BotError, Bots

    bots = Bots(tmp_path / "bots.json")
    assert bots.check("conn1", "Mailbot", "sign in", "github.com") == ("mailbot", True)
    assert bots.check("conn1", "mailbot", "list logins") == ("mailbot", False)
    bots.set_enabled("mailbot", False)
    with pytest.raises(BotError, match="switched off"):
        bots.check("conn1", "mailbot", "sign in")
    assert bots.check("conn1", "planner", "list logins")[0] == "planner"
    [h, o] = bots.list()
    assert h["name"] == "mailbot" and h["enabled"] is False and h["last_action"] == "list logins" and o["enabled"]
    for bad in ["", None, "a b", "x" * 40, "../etc"]:
        with pytest.raises(BotError):
            bots.check("conn1", bad, "x")
    assert bots.forget("mailbot") and [b["name"] for b in bots.list()] == ["planner"]
