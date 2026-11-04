import json
import os

import pytest

from passbroker import ops

from .conftest import fake_tool

TOKEN = "pst_AbC123def456::KeYkEy789"


def test_store_token_validates(memkeyring):
    with pytest.raises(ops.OpError):
        ops.store_token("not-a-token")
    ops.store_token(f"  {TOKEN}\n")
    assert ops.token_stored() and ops.load_token() == TOKEN
    ops.delete_token()
    assert not ops.token_stored()


def test_create_agent_token_goes_straight_to_keyring(tmp_path, memkeyring):
    log = tmp_path / "calls"
    cli = fake_tool(
        tmp_path,
        "pass-cli",
        f"""echo "$@" >> {log}
case "$1 $2" in
  "info ") echo "- Email: me@example.com" ;;
  "agent create") echo '{{"token": "{TOKEN}", "instruction": "export PROTON_PASS_PERSONAL_ACCESS_TOKEN=..."}}' ;;
esac
""",
    )
    backend = ops.create_agent_token("passbroker", "1m", "Agent", cli)
    assert TOKEN not in backend
    assert ops.load_token() == TOKEN
    calls = log.read_text()
    assert "agent create passbroker --expiration 1m --vault Agent" in calls


def test_create_agent_token_errors_never_contain_token(tmp_path, memkeyring):
    cli = fake_tool(tmp_path, "pass-cli", f'[ "$1" = info ] && {{ echo "- Email: me@example.com"; exit 0; }}\necho "vault Nope not found near {TOKEN}" >&2; exit 1\n')
    with pytest.raises(ops.OpError) as e:
        ops.create_agent_token("passbroker", "1m", "Nope", cli)
    assert TOKEN not in str(e.value) and "pst_[REDACTED]" in str(e.value)
    assert not ops.token_stored()


@pytest.mark.parametrize("name,exp", [("bad name", "1m"), ("ok", "2w"), ("a;rm -rf", "1m")])
def test_create_agent_token_rejects_bad_input(name, exp, memkeyring):
    with pytest.raises(ops.OpError):
        ops.create_agent_token(name, exp, "Agent", "/bin/false")


def test_clients_round_trip(xdg):
    token = ops.add_client("grok")
    assert token.startswith("pbc_") and ops.list_clients() == ["grok"]
    stored = ops.clients_path().read_text()
    assert token not in stored
    assert oct(os.stat(ops.clients_path()).st_mode & 0o777) == "0o600"
    ops.remove_client("grok")
    assert ops.list_clients() == []
    with pytest.raises(ops.OpError):
        ops.remove_client("grok")
    with pytest.raises(ops.OpError):
        ops.add_client("../evil")


def test_tailscale_state(tmp_path, monkeypatch):
    status = {"BackendState": "Running", "Self": {"DNSName": "desk.tail1234.ts.net."}}
    fake_tool(tmp_path, "tailscale", f"echo '{json.dumps(status)}'\n")
    monkeypatch.setenv("PATH", f"{tmp_path / 'bin'}:{os.environ['PATH']}")
    ts = ops.tailscale_state()
    assert ts.running and ts.host == "desk.tail1234.ts.net"


def test_tailscale_stopped(tmp_path, monkeypatch):
    fake_tool(tmp_path, "tailscale", 'echo \'{"BackendState": "NeedsLogin", "Self": {}}\'\n')
    monkeypatch.setenv("PATH", f"{tmp_path / 'bin'}:{os.environ['PATH']}")
    ts = ops.tailscale_state()
    assert ts.installed and not ts.running and "tailscale up" in ts.detail


def test_funnel_commands_and_hints():
    assert ops.funnel_start_command(8787) == ["tailscale", "funnel", "--bg", "--https=443", "http://127.0.0.1:8787"]
    assert "operator" in ops.funnel_hint("Access denied: serve config denied")
    assert "enable" in ops.funnel_hint("Funnel is not enabled on your tailnet. To enable, visit: https://login.tailscale.com/f/funnel?node=x")
    assert ops.funnel_hint("all good") is None


def test_serve_command():
    cmd = ops.serve_command(8787, "Agent", ["desk.tail1234.ts.net"], 5, True, "/usr/bin/pass-cli")
    assert cmd[-1] == "--headless" and cmd[cmd.index("--pass-cli") + 1] == "/usr/bin/pass-cli"
    assert cmd[cmd.index("--public-host"):cmd.index("--public-host") + 2] == ["--public-host", "desk.tail1234.ts.net"]


def test_find_url():
    assert ops.find_url("Open https://account.proton.me/login?x=1. Then wait") == "https://account.proton.me/login?x=1"


def test_create_refused_while_signed_in_as_agent(tmp_path, memkeyring):
    log = tmp_path / "calls"
    cli = fake_tool(tmp_path, "pass-cli", f'echo "$@" >> {log}\n[ "$1" = info ] && {{ echo "- Personal Access Token: [Agent] helper (Grok)"; exit 0; }}\nexit 1\n')
    with pytest.raises(ops.OpError, match=r"helper \(Grok\).*sign in as yourself"):
        ops.create_agent_token("passbroker", "1m", "Agent", cli)
    assert "agent create" not in log.read_text()
    assert ops.session_kind(cli) == ("token", "[Agent] helper (Grok)")


def test_create_refused_when_signed_out(tmp_path, memkeyring):
    cli = fake_tool(tmp_path, "pass-cli", 'echo "Error: This operation requires an authenticated client" >&2; exit 1\n')
    with pytest.raises(ops.OpError, match="isn't signed in"):
        ops.create_agent_token("passbroker", "1m", "Agent", cli)


def test_broker_uses_its_own_session_dir(tmp_path):
    from passbroker.redact import Redactor
    from passbroker.vault import ProtonPassBackend

    log = tmp_path / "calls"
    cli = fake_tool(tmp_path, "pass-cli", f'echo "dir=$PROTON_PASS_SESSION_DIR" >> {log}\necho \'{{"items": []}}\'\n')
    session = tmp_path / "broker-session"
    ProtonPassBackend("Agent", lambda: "x", Redactor(), pass_cli=cli, session_dir=session).list_logins()
    assert f"dir={session}" in log.read_text() and session.is_dir()
