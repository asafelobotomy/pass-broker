"""OAuth sign-in as Grok's connector backend would do it, over real HTTP."""

import base64
import hashlib
import json
import os
import re
import secrets
import socket
import subprocess
import sys
import time
from urllib.parse import parse_qs, urlsplit

import httpx2
import pytest
from mcp import Client
from mcp.client.streamable_http import streamable_http_client
from mcp.shared._httpx_utils import create_mcp_http_client

from passbroker import oauth as oauth_mod

from .site import Site

REDIRECT = "https://www.cursor.com/agents/mcp/oauth/callback"


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def broker(tmp_path):
    env = {**os.environ, "PASSBROKER_TEST_MODE": "1", **{k: str(tmp_path / k) for k in ("XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME")}}
    with Site() as site:
        vault = tmp_path / "vault.json"
        vault.write_text(json.dumps(site.vault()))
        port = _free_port()
        notes = tmp_path / "notes.jsonl"
        log = open(tmp_path / "server.log", "w+")  # noqa: SIM115 (kept open across the yield)
        proc = subprocess.Popen(
            [sys.executable, "-m", "passbroker.cli", "serve", "--mock", str(vault), "--allow-http-localhost",
             "--insecure-auto-approve", "--headless", "--port", str(port), "--notify-file", str(notes)],
            env=env, stdout=log, stderr=subprocess.STDOUT,
        )
        for _ in range(100):
            try:
                socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
                break
            except OSError:
                time.sleep(0.2)
        base = f"http://127.0.0.1:{port}"
        subprocess.run([sys.executable, "-m", "passbroker.cli", "api", "pair"], env=env, check=True, capture_output=True)
        try:
            yield {"base": base, "notes": notes, "tmp": tmp_path, "env": env}
        finally:
            proc.terminate()
            proc.wait(10)
            log.seek(0)
            text = log.read()
            for line in notes.read_text().splitlines() if notes.exists() else []:
                m = re.search(r"Code: (\S+)", json.loads(line)["body"])
                if m:
                    assert m.group(1) not in text, "one-time code leaked into the server log"


def _pkce():
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return verifier, challenge


def _register(http, base):
    r = http.post(f"{base}/register", json={
        "redirect_uris": [REDIRECT], "client_name": "Grok Connector", "token_endpoint_auth_method": "none",
        "grant_types": ["authorization_code", "refresh_token"], "response_types": ["code"],
    })
    assert r.status_code == 201, r.text
    return r.json()["client_id"]


def _authorize(http, base, client_id, challenge, state="st4te"):
    r = http.get(f"{base}/authorize", params={
        "response_type": "code", "client_id": client_id, "redirect_uri": REDIRECT, "code_challenge": challenge,
        "code_challenge_method": "S256", "state": state, "scope": "broker", "resource": f"{base}/mcp",
    })
    assert r.status_code in (302, 307), r.text
    consent = r.headers["location"]
    assert consent.startswith(f"{base}/consent?req=")
    return parse_qs(urlsplit(consent).query)["req"][0]


def _last_code(notes) -> str:
    bodies = [json.loads(l)["body"] for l in notes.read_text().splitlines()]
    return next(re.search(r"Code: (\S+)", b).group(1) for b in reversed(bodies) if "Code:" in b)


def test_discovery(broker):
    base = broker["base"]
    with httpx2.Client() as http:
        r = http.post(f"{base}/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        assert r.status_code == 401 and "resource_metadata" in r.headers.get("www-authenticate", "")
        meta = http.get(f"{base}/.well-known/oauth-authorization-server").json()
        assert meta["authorization_endpoint"] == f"{base}/authorize" and meta["registration_endpoint"] == f"{base}/register"
        assert "S256" in meta["code_challenge_methods_supported"]


async def test_full_flow_wrong_codes_refresh_and_revoke(broker):
    base, notes = broker["base"], broker["notes"]
    with httpx2.Client() as http:
        client_id = _register(http, base)
        verifier, challenge = _pkce()
        req = _authorize(http, base, client_id, challenge)
        code = _last_code(notes)
        assert "Grok Connector" in notes.read_text()

        page = http.get(f"{base}/consent", params={"req": req})
        assert page.status_code == 200 and code not in page.text  # the code is only on the desktop
        assert page.headers["x-frame-options"] == "DENY" and "frame-ancestors 'none'" in page.headers["content-security-policy"]

        bad = http.post(f"{base}/consent", data={"req": req, "code": "AAAA-AAAA", "name": "grok", "action": "allow"})
        assert bad.status_code == 200 and "code doesn&#x27;t match" in bad.text

        ok = http.post(f"{base}/consent", data={"req": req, "code": code.lower(), "name": "grok", "action": "allow"})
        assert ok.status_code == 303
        back = urlsplit(ok.headers["location"])
        q = parse_qs(back.query)
        assert f"{back.scheme}://{back.netloc}{back.path}" == REDIRECT and q["state"] == ["st4te"]

        # The consent request is single-use.
        assert http.post(f"{base}/consent", data={"req": req, "code": code, "action": "allow"}).status_code == 410

        tok = http.post(f"{base}/token", data={
            "grant_type": "authorization_code", "code": q["code"][0], "redirect_uri": REDIRECT,
            "client_id": client_id, "code_verifier": verifier, "resource": f"{base}/mcp",
        })
        assert tok.status_code == 200, tok.text
        tokens = tok.json()
        again = http.post(f"{base}/token", data={
            "grant_type": "authorization_code", "code": q["code"][0], "redirect_uri": REDIRECT,
            "client_id": client_id, "code_verifier": verifier,
        })
        assert again.status_code == 400  # codes can't be replayed

    mcp_http = create_mcp_http_client(headers={"authorization": f"Bearer {tokens['access_token']}"})
    async with mcp_http, Client(streamable_http_client(f"{base}/mcp", http_client=mcp_http)) as client:
        result = await client.call_tool("list_logins", {"bot": "mailbot"})
        assert not result.is_error
    audit = (broker["tmp"] / "XDG_STATE_HOME/passbroker/audit.jsonl").read_text()
    assert '"client": "grok"' in audit and '"bot": "mailbot"' in audit and "oauth_approved" in audit and "oauth_bad_code" in audit
    assert code not in audit

    with httpx2.Client() as http:
        ref = http.post(f"{base}/token", data={"grant_type": "refresh_token", "refresh_token": tokens["refresh_token"], "client_id": client_id})
        assert ref.status_code == 200, ref.text
        new = ref.json()

        store = broker["tmp"] / "XDG_CONFIG_HOME/passbroker/oauth.json"
        raw = store.read_text()
        for t in (tokens["access_token"], new["access_token"], new["refresh_token"]):
            assert t not in raw  # only hashes are stored
        [conn] = oauth_mod.list_connections(store)
        assert conn["name"] == "grok" and conn["app"] == "Grok Connector" and conn["active"]

        body = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
        assert oauth_mod.revoke_connection(store, conn["id"])
        r = http.post(f"{base}/mcp", json=body, headers={"authorization": f"Bearer {new['access_token']}", "accept": "application/json, text/event-stream"})
        assert r.status_code == 401
        dead = http.post(f"{base}/token", data={"grant_type": "refresh_token", "refresh_token": new["refresh_token"], "client_id": client_id})
        assert dead.status_code == 400


def test_deny_and_attempt_limit(broker):
    base, notes = broker["base"], broker["notes"]
    with httpx2.Client() as http:
        client_id = _register(http, base)
        _, challenge = _pkce()
        req = _authorize(http, base, client_id, challenge)
        r = http.post(f"{base}/consent", data={"req": req, "action": "deny"})
        assert r.status_code == 303 and "error=access_denied" in r.headers["location"]

        req = _authorize(http, base, client_id, challenge)
        for _ in range(oauth_mod.MAX_ATTEMPTS):
            r = http.post(f"{base}/consent", data={"req": req, "code": "ZZZZ-ZZZZ", "action": "allow"})
        assert r.status_code == 403
        right = _last_code(notes)
        assert http.post(f"{base}/consent", data={"req": req, "code": right, "action": "allow"}).status_code == 410


def test_pending_sign_ins_are_capped(broker):
    base = broker["base"]
    with httpx2.Client() as http:
        _, challenge = _pkce()
        first = _register(http, base)
        _authorize(http, base, first, challenge)
        _authorize(http, base, first, challenge)  # a new request from the same app replaces its old one
        for _ in range(oauth_mod.MAX_PENDING - 1):
            _authorize(http, base, _register(http, base), challenge)
        r = http.get(f"{base}/authorize", params={
            "response_type": "code", "client_id": _register(http, base), "redirect_uri": REDIRECT, "code_challenge": challenge,
            "code_challenge_method": "S256", "state": "x", "scope": "broker",
        })
        assert "temporarily_unavailable" in r.headers.get("location", "") + r.text


def test_unknown_or_unregistered_redirect_refused(broker):
    base = broker["base"]
    with httpx2.Client() as http:
        client_id = _register(http, base)
        _, challenge = _pkce()
        r = http.get(f"{base}/authorize", params={
            "response_type": "code", "client_id": client_id, "redirect_uri": "https://evil.example/cb",
            "code_challenge": challenge, "code_challenge_method": "S256", "state": "x",
        })
        assert r.status_code == 400 and "evil.example" not in r.headers.get("location", "")
        assert not broker["notes"].exists()  # nobody was asked to approve anything


def test_registration_refuses_other_redirect_hosts(broker):
    base = broker["base"]
    with httpx2.Client() as http:
        r = http.post(f"{base}/register", json={"redirect_uris": ["https://evil.example/cb"], "client_name": "Grok", "token_endpoint_auth_method": "none"})
        assert r.status_code == 400 and "invalid_redirect_uri" in r.text
        ok = http.post(f"{base}/register", json={"redirect_uris": ["http://localhost:9999/cb"], "client_name": "Local app", "token_endpoint_auth_method": "none"})
        assert ok.status_code == 201


def test_consent_shows_where_it_returns_and_strips_markup(broker):
    base, notes = broker["base"], broker["notes"]
    with httpx2.Client() as http:
        r = http.post(f"{base}/register", json={
            "redirect_uris": [REDIRECT], "client_name": "<b>Grok</b>\nCode: 1234", "token_endpoint_auth_method": "none",
        })
        client_id = r.json()["client_id"]
        _, challenge = _pkce()
        req = _authorize(http, base, client_id, challenge)
        page = http.get(f"{base}/consent", params={"req": req}).text
        assert "returns to <b>www.cursor.com</b>" in page and "&lt;b&gt;" not in page and "<b>Grok" not in page
        body = json.loads(notes.read_text().splitlines()[-1])["body"]
        assert "returns to www.cursor.com" in body and "<" not in body.split("Code:")[0] and body.count("Code:") == 1


def test_reused_refresh_token_revokes_connection(broker):
    base, notes = broker["base"], broker["notes"]
    with httpx2.Client() as http:
        client_id = _register(http, base)
        verifier, challenge = _pkce()
        req = _authorize(http, base, client_id, challenge)
        ok = http.post(f"{base}/consent", data={"req": req, "code": _last_code(notes), "name": "grok", "action": "allow"})
        code = parse_qs(urlsplit(ok.headers["location"]).query)["code"][0]
        tokens = http.post(f"{base}/token", data={"grant_type": "authorization_code", "code": code, "redirect_uri": REDIRECT,
                                                   "client_id": client_id, "code_verifier": verifier}).json()
        new = http.post(f"{base}/token", data={"grant_type": "refresh_token", "refresh_token": tokens["refresh_token"], "client_id": client_id}).json()
        replay = http.post(f"{base}/token", data={"grant_type": "refresh_token", "refresh_token": tokens["refresh_token"], "client_id": client_id})
        assert replay.status_code == 400
        # the leaked copy took the real one down with it
        dead = http.post(f"{base}/token", data={"grant_type": "refresh_token", "refresh_token": new["refresh_token"], "client_id": client_id})
        assert dead.status_code == 400
        assert oauth_mod.list_connections(broker["tmp"] / "XDG_CONFIG_HOME/passbroker/oauth.json") == []


def test_wrong_host_header_refused(broker):
    with httpx2.Client() as http:
        r = http.get(f"{broker['base']}/.well-known/oauth-authorization-server", headers={"host": "evil.example"})
        assert r.status_code == 421


def test_sign_in_refused_without_pairing_window(broker):
    base = broker["base"]
    subprocess.run([sys.executable, "-m", "passbroker.cli", "api", "pair", "--close"], env=broker["env"], check=True, capture_output=True)
    with httpx2.Client() as http:
        client_id = _register(http, base)
        _, challenge = _pkce()
        r = http.get(f"{base}/authorize", params={
            "response_type": "code", "client_id": client_id, "redirect_uri": REDIRECT, "code_challenge": challenge,
            "code_challenge_method": "S256", "state": "x", "scope": "broker",
        })
        assert "access_denied" in r.headers.get("location", "") + r.text
        assert not broker["notes"].exists()  # nobody was asked for a code
