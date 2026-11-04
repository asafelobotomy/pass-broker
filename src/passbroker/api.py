"""`passbroker api …`: a JSON interface for the wizard (and scripts).

Every command prints one JSON object, `{"ok": true, ...}` or
`{"ok": false, "error": "..."}`. Streaming commands (login, funnel-start,
install-browser) print one JSON object per line instead, ending with an
`{"event": "done", ...}` line. Nothing here ever prints the Proton Pass token;
`add-client` prints the new local assistant token once, by design.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from dataclasses import asdict
from pathlib import Path
from typing import Any

from . import ops


def detect_pass_cli() -> str:
    found = shutil.which("pass-cli")
    if found:
        return found
    for candidate in (Path.home() / ".local/bin/pass-cli", Path("/usr/local/bin/pass-cli")):
        if candidate.exists():
            return str(candidate)
    return "pass-cli"


def emit(obj: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()


def _stream(cmd: list[str], url_filter: str | None = None) -> int:
    """Run a command, relaying its output as log events (and any URL it prints)."""
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, text=True, bufsize=1)
    assert proc.stdout is not None
    for line in proc.stdout:
        line = ops._scrub_tokens(line.rstrip())
        if not line:
            continue
        emit({"event": "log", "line": line})
        url = ops.find_url(line)
        if url and (url_filter is None or url_filter in url):
            emit({"event": "url", "url": url})
    return proc.wait()


# ---- commands -----------------------------------------------------------------------


def c_status(a) -> dict[str, Any]:
    cli = a.pass_cli
    kind, label = ops.session_kind(cli) if ops.pass_cli_version(cli) else ("none", "")
    _, backend = ops.keyring_backend()
    return {
        "pass_cli": cli,
        "checks": [asdict(c) for c in ops.environment_checks(cli)],
        "token_stored": ops.token_stored(),
        "keyring": backend,
        "session": {"kind": kind, "label": label},
        "clients": ops.list_clients(),
        "connections": ops.list_connections(),
        "tailscale": asdict(ops.tailscale_state()),
    }


def c_session(a) -> dict[str, Any]:
    kind, label = ops.session_kind(a.pass_cli)
    return {"kind": kind, "label": label}


def c_logout(a) -> dict[str, Any]:
    ops.logout(a.pass_cli)
    return {}


def c_login(a) -> None:
    """Web sign-in as yourself, streamed: a `url` event, then `done`."""
    kind, label = ops.session_kind(a.pass_cli)
    if kind == "user":
        emit({"event": "done", "ok": True, "already": True, "label": label})
        return
    if kind == "token":
        if not a.sign_out_agent:
            emit({"event": "done", "ok": False, "error": f"pass-cli is signed in as an agent or token ({label})", "agent": label})
            return
        ops.logout(a.pass_cli)
    code = _stream([a.pass_cli, "login"])
    emit({"event": "done", "ok": code == 0, **({} if code == 0 else {"error": f"sign-in didn't finish (exit code {code})"})})


def c_create_token(a) -> dict[str, Any]:
    backend = ops.create_agent_token(a.name, a.expiration, a.vault, a.pass_cli)
    if not a.stay_signed_in:
        ops.logout(a.pass_cli)
    return {"keyring": backend}


def c_store_token(a) -> dict[str, Any]:
    return {"keyring": ops.store_token(sys.stdin.readline())}


def c_delete_token(a) -> dict[str, Any]:
    ops.delete_token()
    return {}


def c_check_vault(a) -> dict[str, Any]:
    ops.harden_process()
    return ops.check_vault(a.vault, a.pass_cli)


def c_add_client(a) -> dict[str, Any]:
    return {"name": a.name, "token": ops.add_client(a.name)}


def c_remove_client(a) -> dict[str, Any]:
    ops.remove_client(a.name)
    return {}


def c_connections(a) -> dict[str, Any]:
    return {"connections": ops.list_connections(), "clients": ops.list_clients(), "bots": ops.bots_store().list()}


def c_bots(a) -> dict[str, Any]:
    return {"bots": ops.bots_store().list()}


def c_bot_enable(a) -> dict[str, Any]:
    ops.bots_store().set_enabled(a.name, not a.off)
    return {}


def c_bot_forget(a) -> dict[str, Any]:
    ops.bots_store().forget(a.name)
    return {}


def _unlockers():
    from .unlock import Unlockers

    return Unlockers(ops.dirs()[0] / "unlockers.json")


def c_unlockers(a) -> dict[str, Any]:
    from dataclasses import asdict as _asdict

    from .unlock import available_presets

    return {"presets": available_presets(), "actions": [_asdict(x) for x in _unlockers().load()]}


def c_unlocker_add(a) -> dict[str, Any]:
    """One action as JSON on stdin: name, preset, item, folders, output_dir, return_output."""
    from .unlock import Action

    data = json.loads(sys.stdin.readline() or "{}")
    allowed = {"name", "preset", "item", "folders", "output_dir", "return_output"}
    _unlockers().add(Action(**{k: v for k, v in data.items() if k in allowed}))
    return {}


def c_unlocker_remove(a) -> dict[str, Any]:
    if not _unlockers().remove(a.name):
        raise ops.OpError(f"no action named '{a.name}'")
    return {}


def c_revoke(a) -> dict[str, Any]:
    ops.revoke_connection(a.id)
    return {}


def c_revoke_all(a) -> dict[str, Any]:
    n = 0
    for c in ops.list_connections():
        ops.revoke_connection(c["id"])
        n += 1
    return {"revoked": n}


def c_probe(a) -> dict[str, Any]:
    reachable, detail = ops.probe_public(a.host)
    return {"reachable": reachable, "detail": detail}


def c_audit(a) -> dict[str, Any]:
    return {"entries": ops.read_audit(a.limit)}


def c_audit_verify(a) -> dict[str, Any]:
    from .audit import verify

    return verify(ops.dirs()[2] / "audit.jsonl")


def c_tailscale(a) -> dict[str, Any]:
    return asdict(ops.tailscale_state())


def c_funnel_start(a) -> None:
    ts = ops.tailscale_state()
    if not ts.running or not ts.host:
        emit({"event": "done", "ok": False, "error": f"Tailscale isn't ready: {ts.detail}"})
        return
    cmd = ops.funnel_start_command(a.port)
    emit({"event": "log", "line": "$ " + " ".join(cmd)})
    lines: list[str] = []
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, text=True, bufsize=1)
    assert proc.stdout is not None
    for line in proc.stdout:
        line = line.rstrip()
        if not line:
            continue
        lines.append(line)
        emit({"event": "log", "line": line})
        url = ops.find_url(line)
        if url and "login.tailscale.com" in url:
            emit({"event": "url", "url": url})
    code = proc.wait()
    if code == 0:
        emit({"event": "done", "ok": True, "host": ts.host})
    else:
        emit({"event": "done", "ok": False, "error": ops.funnel_hint("\n".join(lines)) or f"tailscale funnel failed (exit code {code})"})


def c_funnel_stop(a) -> dict[str, Any]:
    cmd = ops.funnel_stop_command()
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise ops.OpError("turning Funnel off failed: " + (proc.stderr.strip() or proc.stdout.strip())[:200])
    return {}


def c_funnel_cleanup(a) -> dict[str, Any]:
    """Turn off a Funnel left pointing at the broker's port (after a crash or reboot)."""
    from .tailscale import funnel_points_at

    if not shutil.which("tailscale") or not funnel_points_at(a.port):
        return {"cleaned": False}
    c_funnel_stop(a)
    return {"cleaned": True}


def c_install_browser(a) -> None:
    code = _stream(ops.install_browser_command())
    emit({"event": "done", "ok": code == 0})


def c_serve_command(a) -> dict[str, Any]:
    return {"argv": ops.serve_command(a.port, a.vault, a.public_host, a.grant_minutes, a.headless, a.pass_cli, a.keep_sessions, a.idle_minutes)}


def c_clear_browser(a) -> dict[str, Any]:
    ops.clear_browser()
    return {}


STREAMING = {c_login, c_funnel_start, c_install_browser}


def add_parser(sub: argparse._SubParsersAction) -> None:
    api = sub.add_parser("api", help="JSON interface used by the setup wizard")
    api.add_argument("--pass-cli", default=None, help="path to pass-cli (default: found automatically)")
    cmds = api.add_subparsers(dest="api_cmd", required=True)

    def add(name: str, fn, *arguments: tuple[tuple, dict]):
        s = cmds.add_parser(name)
        for args_, kwargs in arguments:
            s.add_argument(*args_, **kwargs)
        s.set_defaults(api_func=fn)

    vault = (("--vault",), {"default": "Agent"})
    add("status", c_status)
    add("session", c_session)
    add("logout", c_logout)
    add("login", c_login, (("--sign-out-agent",), {"action": "store_true"}))
    add("create-token", c_create_token, (("--name",), {"default": "passbroker"}), (("--expiration",), {"default": "1m"}), vault,
        (("--stay-signed-in",), {"action": "store_true"}))
    add("store-token", c_store_token)
    add("delete-token", c_delete_token)
    add("check-vault", c_check_vault, vault)
    add("add-client", c_add_client, (("name",), {}))
    add("remove-client", c_remove_client, (("name",), {}))
    add("connections", c_connections)
    add("revoke", c_revoke, (("id",), {}))
    add("bots", c_bots)
    add("unlockers", c_unlockers)
    add("unlocker-add", c_unlocker_add)
    add("unlocker-remove", c_unlocker_remove, (("name",), {}))
    add("bot-enable", c_bot_enable, (("name",), {}), (("--off",), {"action": "store_true"}))
    add("bot-forget", c_bot_forget, (("name",), {}))
    add("revoke-all", c_revoke_all)
    add("probe", c_probe, (("host",), {}))
    add("audit", c_audit, (("--limit",), {"type": int, "default": 200}))
    add("audit-verify", c_audit_verify)
    add("tailscale", c_tailscale)
    add("funnel-start", c_funnel_start, (("--port",), {"type": int, "default": 8787}))
    add("funnel-stop", c_funnel_stop)
    add("funnel-cleanup", c_funnel_cleanup, (("--port",), {"type": int, "default": 8787}))
    add("install-browser", c_install_browser)
    add("serve-command", c_serve_command, (("--port",), {"type": int, "default": 8787}), vault,
        (("--public-host",), {"action": "append", "default": []}), (("--grant-minutes",), {"type": float, "default": 10}),
        (("--headless",), {"action": "store_true"}), (("--keep-sessions",), {"action": "store_true"}),
        (("--idle-minutes",), {"type": float, "default": 15}))
    add("clear-browser", c_clear_browser)
    from . import api_config, api_service

    api_service.add_parsers(add, vault)
    api_config.add_parsers(add)
    api.set_defaults(func=run)


def run(a: argparse.Namespace) -> None:
    a.pass_cli = a.pass_cli or detect_pass_cli()
    fn = a.api_func
    try:
        if fn in STREAMING:
            fn(a)
        else:
            emit({"ok": True, **(fn(a) or {})})
    except Exception as e:  # ops errors never contain the token
        msg = ops._scrub_tokens(str(e) or type(e).__name__)
        if fn in STREAMING:
            emit({"event": "done", "ok": False, "error": msg})
        else:
            emit({"ok": False, "error": msg})
        sys.exit(1)
