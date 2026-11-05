"""The JSON each `passbroker api` command prints: the wizard reads these exact fields.

Every command prints one JSON object with `ok`; on failure `ok` is false, `error` says why
(never a token) and the exit code is 1. Commands that need Proton, Tailscale or systemd are
covered by their own tests; these run offline against a fake pass-cli.
"""

import io
import json
import sys

import pytest

from passbroker import cli

from .conftest import fake_tool


@pytest.fixture
def api(xdg, tmp_path, monkeypatch, memkeyring, capsys):
    monkeypatch.setenv("HOME", str(tmp_path))
    pass_cli = fake_tool(tmp_path, "pass-cli", '[ "$1" = --version ] && echo "Proton Pass CLI 2.7.0"\n'
                         '[ "$1" = info ] && { echo "Email: me@example.com"; exit 0; }\nexit 0\n')

    def call(*args: str, stdin: str = "", ok: bool = True) -> dict:
        monkeypatch.setattr(sys, "stdin", io.StringIO(stdin))
        capsys.readouterr()
        try:
            cli.main(["api", "--pass-cli", pass_cli, *args])
            code = 0
        except SystemExit as e:
            code = e.code
        out = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
        assert out["ok"] is ok and code == (0 if ok else 1), out
        if not ok:
            assert isinstance(out["error"], str) and out["error"]
        return out

    return call


def has(obj: dict, *keys: str) -> None:
    missing = [k for k in keys if k not in obj]
    assert not missing, f"missing {missing} in {sorted(obj)}"


def test_status_and_session(api):
    out = api("status")
    has(out, "pass_cli", "checks", "token_stored", "keyring", "session", "clients", "connections", "tailscale")
    for check in out["checks"]:
        has(check, "key", "label", "ok", "detail", "required")
    has(out["session"], "kind", "label")
    has(out["tailscale"], "running", "host", "detail")
    assert api("session") == {"ok": True, "kind": "user", "label": "me@example.com"}


def test_clients_and_connections(api):
    made = api("add-client", "local")
    assert made["name"] == "local" and made["token"].startswith("pbc_")
    out = api("connections")
    has(out, "connections", "clients", "bots")
    assert out["clients"] == ["local"]
    assert "pbc_" not in json.dumps(out)  # only the hash is kept
    api("remove-client", "local")
    assert api("connections")["clients"] == []
    api("add-client", "not a name!", ok=False)


def test_bots_and_access(api, tmp_path):
    from passbroker import ops

    ops.bots_store().check("conn", "mailbot", "list logins")
    [bot] = api("bots")["bots"]
    has(bot, "name", "enabled", "first_seen", "last_seen", "last_action", "access", "connections")
    access = api("bot-access", "mailbot", stdin=json.dumps({"logins": ["Site"], "create_logins": True}))["access"]
    has(access, "logins", "unlock", "devices", "keys", "email_codes", "create_logins", "personal_details",
        "sites_limited", "sites", "blocked_pages")
    assert access["logins"] == ["Site"] and access["create_logins"] is True
    api("bot-access", "mailbot", stdin='{"sites": ["not a site!"]}', ok=False)
    api("bot-enable", "mailbot", "--off")
    assert api("bots")["bots"][0]["enabled"] is False
    api("bot-forget", "mailbot")
    assert api("bots")["bots"] == []


def test_unlockers(api, tmp_path):
    folder, output = tmp_path / "locked", tmp_path / "unlocked"
    folder.mkdir()
    output.mkdir()
    out = api("unlockers")
    has(out, "presets", "actions")
    for p in out["presets"]:
        has(p, "key", "label", "tool", "extensions", "description", "installed")
    action = {"name": "docs", "preset": "gpg-decrypt", "item": "Docs key", "folders": [str(folder)], "output_dir": str(output)}
    api("unlocker-add", stdin=json.dumps(action))
    [saved] = api("unlockers")["actions"]
    has(saved, "name", "preset", "item", "folders", "output_dir", "return_output")
    api("unlocker-remove", "docs")
    api("unlocker-remove", "docs", ok=False)


def test_config_keys_devices_mail_accounts(api):
    api("config-add", "keys", stdin='{"name": "ledger", "item": "Ledger key", "note": "finance"}')
    api("config-add", "devices", stdin='{"name": "wake-nas", "kind": "wol", "mac": "aa:bb:cc:dd:ee:ff"}')
    out = api("config")
    has(out, "keys", "devices", "mail", "accounts")
    has(out["keys"][0], "name", "item", "note")
    has(out["devices"][0], "name", "kind", "host", "mac", "url", "method", "item", "return_output")
    has(out["mail"], "item", "host", "port", "max_age_minutes")
    has(out["accounts"], "vault", "enabled", "created")
    assert out["accounts"]["enabled"] is False
    assert api("config-add", "devices", stdin='{"name": "x", "kind": "telnet"}', ok=False)["error"]
    api("config-remove", "keys", "ledger")
    api("config-remove", "keys", "ledger", ok=False)
    assert api("accounts-off")["enabled"] is False


def test_pairing_audit_and_serve_command(api):
    assert api("pair") == {"ok": True, "open": True, "minutes": 10}
    assert api("pair", "--close") == {"ok": True, "open": False}
    assert api("audit", "--limit", "5") == {"ok": True, "entries": []}
    has(api("audit-verify"), "ok")
    argv = api("serve-command", "--port", "8899", "--grant-minutes", "3", "--headless")["argv"]
    assert argv[argv.index("--port") + 1] == "8899" and "--headless" in argv
    assert argv[argv.index("--grant-minutes") + 1] == "3.0"
    assert api("revoke-all") == {"ok": True, "revoked": 0}
