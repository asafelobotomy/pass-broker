"""The whole pipeline as Grok would see it: HTTP, bearer auth, MCP tools.

Every byte the client receives, plus the server's log and audit file, is
checked for the password and the 2FA code.
"""

import base64
import json
import os
import socket
import subprocess
import sys
import time

import httpx2
import pytest
from mcp import Client
from mcp.client.streamable_http import streamable_http_client
from mcp.shared._httpx_utils import create_mcp_http_client

from .site import PASSWORD, TOTP, Site

SECRETS = [PASSWORD, TOTP, "nowhere-Secret-77"]


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def server(tmp_path):
    env = {**os.environ, "PASSBROKER_TEST_MODE": "1", **{k: str(tmp_path / k) for k in ("XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME")}}
    cli = [sys.executable, "-m", "passbroker.cli"]
    token = subprocess.run([*cli, "add-client", "grok"], env=env, capture_output=True, text=True, check=True).stdout.strip().splitlines()[-1]
    with Site() as site:
        vault = tmp_path / "vault.json"
        vault.write_text(json.dumps(site.vault()))
        port = _free_port()
        log = open(tmp_path / "server.log", "w+")  # noqa: SIM115 (kept open across the yield)
        proc = subprocess.Popen(
            [*cli, "serve", "--mock", str(vault), "--allow-http-localhost", "--insecure-auto-approve", "--headless", "--port", str(port),
             "--notify-file", str(tmp_path / "notes.jsonl")],
            env=env, stdout=log, stderr=subprocess.STDOUT,
        )
        for _ in range(100):
            try:
                socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
                break
            except OSError:
                time.sleep(0.2)
        subprocess.run([*cli, "api", "bot-access", "tester"], input='{"logins": ["Test Site"]}\n', text=True, env=env, check=True, capture_output=True)
        try:
            yield {"url": f"http://127.0.0.1:{port}/mcp", "token": token, "site": site, "tmp": tmp_path}
        finally:
            proc.terminate()
            proc.wait(10)
            log.seek(0)
            text = log.read()
            for s in SECRETS:
                assert s not in text, "secret in server log"
            audit_path = tmp_path / "XDG_STATE_HOME/passbroker/audit.jsonl"
            audit = audit_path.read_text() if audit_path.exists() else ""
            for s in SECRETS:
                assert s not in audit, "secret in audit log"


async def test_rejects_missing_wrong_and_forged_tokens(server):
    async with httpx2.AsyncClient() as http:
        body = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
        for headers in ({}, {"authorization": "Bearer pbc_wrong"}, {"x-pb-client": "grok"}, {"authorization": server["token"]}):
            r = await http.post(server["url"], json=body, headers=headers)
            assert r.status_code == 401


async def test_full_sign_in_reveals_nothing(server):
    site = server["site"]
    http = create_mcp_http_client(headers={"authorization": f"Bearer {server['token']}"})
    seen: list[str] = []

    async with http, Client(streamable_http_client(server["url"], http_client=http)) as client:

        async def call(name, args=None, bot="tester"):
            args = dict(args or {})
            if bot is not None:
                args["bot"] = bot
            result = await client.call_tool(name, args)
            dumped = result.model_dump_json()
            seen.append(dumped)
            return result, dumped

        tools = {t.name for t in (await client.list_tools()).tools}
        assert tools == {"list_logins", "open_url", "snapshot", "click", "type_text", "press_key", "screenshot", "fill_login", "fill_totp", "list_unlockers", "list_locked_files", "unlock_file",
                         "fill_email_code", "end_session", "list_keys", "encrypt_text", "decrypt_text", "list_device_actions", "run_device_action",
                         "create_login", "fill_signup", "email_address", "mail_tasks", "mail_rule_done", "request_mail_admin", "mail_folders", "mail_search", "mail_senders", "mail_thread",
                         "mail_apply", "mail_undo", "report_issue", "my_reports",
                         "mail_read", "mail_attachment", "mail_move", "mail_flag", "mail_label", "mail_folder_create",
                         "mail_folder_rename", "mail_folder_delete", "mail_draft", "mail_send"}

        result, dumped = await call("list_logins", bot=None)
        assert result.is_error  # `bot` is a required argument
        result, dumped = await call("list_logins", bot="Not A Name!")
        assert result.is_error and "bot name" in dumped
        _, dumped = await call("list_logins")
        logins = json.loads(dumped)["structured_content"]["result"]
        handle = next(l["handle"] for l in logins if l["title"] == "Test Site")

        await call("open_url", {"url": site.url("/login", host="127.0.0.1")})
        result, dumped = await call("fill_login", {"handle": handle})
        assert result.is_error and "not a site saved" in dumped

        await call("open_url", {"url": site.url("/leaky")})
        await call("fill_login", {"handle": handle})
        _, dumped = await call("snapshot")
        assert "[REDACTED]" in dumped
        result, dumped = await call("screenshot")
        assert result.is_error and "withheld" in dumped

        await call("open_url", {"url": site.url("/login")})
        result, _ = await call("fill_login", {"handle": handle})
        assert not result.is_error
        assert site.posts[-1] == ("/session", {"login": ["alice"], "password": [PASSWORD]})

        await call("open_url", {"url": site.url("/otp")})
        result, _ = await call("fill_totp", {"handle": handle})
        assert not result.is_error and site.posts[-1] == ("/otp", {"otp": [TOTP]})

        result, _ = await call("screenshot")
        png = base64.b64decode(next(c for c in result.content if c.type == "image").data)
        assert png.startswith(b"\x89PNG")

        # switch the bot off from outside, as the wizard would
        env = {**os.environ, **{k: str(server["tmp"] / k) for k in ("XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME")}}
        subprocess.run([sys.executable, "-m", "passbroker.cli", "api", "bot-enable", "tester", "--off"], env=env, check=True, capture_output=True)
        result, dumped = await call("list_logins")
        assert result.is_error and "switched off" in dumped
        result, dumped = await call("list_logins", bot="mailbot")
        assert not result.is_error and "Test Site" not in dumped  # a new bot sees nothing until granted

    everything = "\n".join(seen)
    for s in SECRETS:
        assert s not in everything, "secret reached the client"

    audit = (server["tmp"] / "XDG_STATE_HOME/passbroker/audit.jsonl").read_text()
    assert '"client": "grok"' in audit and '"bot": "tester"' in audit and "refused_origin" in audit and "bot_refused" in audit
    notes = (server["tmp"] / "notes.jsonl").read_text()
    assert "Bot: tester" not in notes and "Bot: mailbot" in notes  # tester was granted access before its first call


async def test_local_tokens_refused_through_funnel_whatever_the_host(server):
    """A request through Funnel claiming `Host: 127.0.0.1:port` must still be treated as from the internet."""
    body = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
    headers = {"authorization": f"Bearer {server['token']}", "tailscale-funnel-request": "?1",
               "accept": "application/json, text/event-stream", "content-type": "application/json"}
    async with httpx2.AsyncClient() as http:
        r = await http.post(server["url"], json=body, headers=headers)
    assert r.status_code == 401 and b"can't be used from the internet" in r.content


async def test_a_bot_reports_a_failure_and_you_see_it(server):
    """Through the real server: a failed call, then report_issue; the report carries the failure."""
    http = create_mcp_http_client(headers={"authorization": f"Bearer {server['token']}"})
    async with http, Client(streamable_http_client(server["url"], http_client=http)) as client:
        failed = await client.call_tool("fill_login", {"bot": "tester", "handle": "h_madeup"})
        assert failed.is_error
        filed = json.loads((await client.call_tool("report_issue", {"bot": "tester", "title": "fill_login says unknown handle",
                                                                     "details": f"tried {PASSWORD}", "tool": "fill_login"})).content[0].text)
        assert filed["status"] == "filed"
        mine = (await client.call_tool("my_reports", {"bot": "tester"})).model_dump_json()
        assert filed["id"] in mine
    env = {**os.environ, **{k: str(server["tmp"] / k) for k in ("XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME")}}
    out = subprocess.run([sys.executable, "-m", "passbroker.cli", "api", "issues"], env=env, capture_output=True, text=True, check=True).stdout
    [report] = json.loads(out)["issues"]
    assert report["last_error"]["action"] == "sign in" and "unknown handle" in report["last_error"]["error"]
    assert PASSWORD not in out  # a secret the broker knows is scrubbed from what the bot wrote
