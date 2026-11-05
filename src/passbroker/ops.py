"""Setup and housekeeping steps shared by the command line and the GUI.

Nothing here returns the Proton Pass token. The one value handed back is a new
client token from `add_client`, which the person must copy into their assistant.
"""

from __future__ import annotations

import contextlib
import ctypes
import json
import os
import re
import resource
import secrets
import shutil
import subprocess
import sys
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import confine, jsonfile
from .tailscale import (  # noqa: F401  (re-exported for api and tests)
    FUNNEL_OPERATOR_FIX,
    TailscaleState,
    funnel_hint,
    funnel_start_command,
    funnel_stop_command,
    tailscale_state,
)

KEYRING_SERVICE = "passbroker"
KEYRING_PAT = "proton-pass-pat"
PASS_CLI_INSTALL = "curl -fsSL https://proton.me/download/pass-cli/install.sh | bash"
EXPIRATIONS = ["1d", "1w", "1m", "3m", "6m", "1y"]
_TOKEN_RE = re.compile(r"pst_[^\s'\"`,}]+")


class OpError(Exception):
    """A setup step failed. Messages never contain the token."""


def dirs() -> tuple[Path, Path, Path]:
    home = Path.home()
    config = Path(os.environ.get("XDG_CONFIG_HOME", home / ".config")) / "passbroker"
    data = Path(os.environ.get("XDG_DATA_HOME", home / ".local/share")) / "passbroker"
    state = Path(os.environ.get("XDG_STATE_HOME", home / ".local/state")) / "passbroker"
    for d in (config, data, state):
        d.mkdir(parents=True, exist_ok=True, mode=0o700)
    return config, data, state


def harden_process() -> None:
    """No core dumps, and other processes of yours can't ptrace or read /proc/<pid>/mem."""
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    with contextlib.suppress(Exception):
        PR_SET_DUMPABLE = 4
        ctypes.CDLL(None, use_errno=True).prctl(PR_SET_DUMPABLE, 0, 0, 0, 0)


def _scrub_tokens(text: str) -> str:
    return _TOKEN_RE.sub("pst_[REDACTED]", text)


def _run(cmd: list[str], env: dict[str, str] | None = None, timeout: float = 60) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env, stdin=subprocess.DEVNULL)
    except FileNotFoundError:
        raise OpError(f"{cmd[0]} is not installed or not on PATH") from None
    except subprocess.TimeoutExpired:
        raise OpError(f"{cmd[0]} timed out") from None


# ---- the Proton Pass token ------------------------------------------------------


def store_token(token: str) -> str:
    """Save a token to the system keyring. Returns the keyring backend's name."""
    import keyring

    token = token.strip()
    if not token.startswith("pst_"):
        raise OpError("that doesn't look like a Proton Pass access token (they start with pst_)")
    keyring.set_password(KEYRING_SERVICE, KEYRING_PAT, token)
    return keyring.get_keyring().__class__.__name__


def load_token() -> str:
    import keyring

    token = keyring.get_password(KEYRING_SERVICE, KEYRING_PAT)
    if not token:
        raise RuntimeError("no access token saved; run: passbroker set-token")
    return token


def token_stored() -> bool:
    import keyring

    with contextlib.suppress(Exception):
        return bool(keyring.get_password(KEYRING_SERVICE, KEYRING_PAT))
    return False


def delete_token() -> None:
    import keyring

    with contextlib.suppress(Exception):
        keyring.delete_password(KEYRING_SERVICE, KEYRING_PAT)


def keyring_backend() -> tuple[bool, str]:
    import keyring

    try:
        kr = keyring.get_keyring()
    except Exception as e:
        return False, str(e)
    name = kr.__class__.__name__
    ok = getattr(kr, "priority", 1) > 0 and "fail" not in name.lower() and "null" not in name.lower()
    return ok, name


# ---- clients ----------------------------------------------------------------------


def clients_path() -> Path:
    return dirs()[0] / "clients.json"


def list_clients() -> list[str]:
    from .server import load_clients

    return list(load_clients(clients_path()))


def _write_clients(clients: dict[str, str]) -> None:
    # Atomic: the running broker reads this on every request.
    jsonfile.write(clients_path(), clients)


def add_client(name: str) -> str:
    """Create (or replace) a client and return its bearer token. Only its hash is kept."""
    from .server import hash_token, load_clients

    if not re.fullmatch(r"[A-Za-z0-9._-]{1,32}", name):
        raise OpError("assistant name: letters, digits, dot, dash and underscore only")
    clients = load_clients(clients_path())
    if name.lower() in {c["name"].lower() for c in list_connections()}:
        raise OpError(f"a connected app is already called {name}; pick another name")
    token = "pbc_" + secrets.token_urlsafe(32)
    clients[name] = hash_token(token)
    _write_clients(clients)
    return token


def bots_store():
    from .bots import Bots

    return Bots(dirs()[0] / "bots.json")


def connections_path() -> Path:
    return dirs()[0] / "oauth.json"


def list_connections() -> list[dict[str, Any]]:
    """Apps connected through OAuth (e.g. Grok): names and dates, no tokens."""
    from .oauth import list_connections as _list

    return _list(connections_path())


def revoke_connection(grant_id: str) -> None:
    from .oauth import revoke_connection as _revoke

    if not _revoke(connections_path(), grant_id):
        raise OpError("that connection was already removed")


def remove_client(name: str) -> None:
    from .server import load_clients

    clients = load_clients(clients_path())
    if clients.pop(name, None) is None:
        raise OpError(f"no assistant named '{name}'")
    _write_clients(clients)


# ---- environment ----------------------------------------------------------------


@dataclass
class Check:
    key: str
    label: str
    ok: bool
    detail: str
    required: bool = True


def browser_installed() -> bool:
    from playwright.sync_api import sync_playwright

    with contextlib.suppress(Exception), sync_playwright() as p:
        return Path(p.chromium.executable_path).exists()
    return False


def install_browser_command() -> list[str]:
    return [sys.executable, "-I", "-m", "playwright", "install", "chromium"]


def environment_checks(pass_cli: str = "pass-cli", browser_check: Callable[[], bool] = browser_installed) -> list[Check]:
    version = pass_cli_version(pass_cli)
    kr_ok, kr_name = keyring_backend()
    has_browser = browser_check()
    ts = tailscale_state()
    return [
        Check("pass-cli", "Proton Pass CLI", bool(version), version or "not installed"),
        Check("browser", "Browser for sign-ins", has_browser, "Chromium installed" if has_browser else "not installed"),
        Check("keyring", "System keyring", kr_ok, kr_name if kr_ok else f"no usable keyring ({kr_name})"),
        Check("notify", "Desktop approvals", bool(shutil.which("notify-send")), "notify-send found" if shutil.which("notify-send") else "notify-send missing (install libnotify)"),
        Check("token", "Proton Pass token saved", token_stored(), "in keyring" if token_stored() else "not yet"),
        Check(
            "clients",
            "Assistant connected",
            bool(list_clients() or list_connections()),
            ", ".join(list_clients() + [c["name"] for c in list_connections() if c["active"]]) or "none yet (Grok connects itself on step 6)",
            required=False,
        ),
        Check("tailscale", "Tailscale (for Funnel)", ts.running, ts.detail, required=False),
        Check("sandbox", "Browser sandbox", *confine.sandbox_status()),
        Check("confine", "Browser confinement", *confine.confinement_status(), required=False),
    ]


def serve_command(
    port: int,
    vault: str,
    public_hosts: list[str],
    grant_minutes: float,
    headless: bool,
    pass_cli: str = "pass-cli",
    keep_sessions: bool = False,
    idle_minutes: float = 15,
) -> list[str]:
    cmd = [sys.executable, "-I", "-m", "passbroker.cli", "serve", "--port", str(port), "--vault", vault, "--grant-minutes", str(grant_minutes), "--pass-cli", pass_cli]
    cmd += ["--keep-sessions"] if keep_sessions else ["--idle-minutes", str(idle_minutes)]
    if public_hosts and any(h.endswith(".ts.net") for h in public_hosts):
        cmd.append("--manage-funnel")
    for host in public_hosts:
        cmd += ["--public-host", host]
    if headless:
        cmd.append("--headless")
    return cmd


def probe_public(host: str, timeout: float = 10) -> tuple[bool, str]:
    """From outside: the broker should answer 401 without a token."""
    import httpx2

    url = f"https://{host}/mcp"
    try:
        r = httpx2.post(url, json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"}, timeout=timeout)
    except Exception as e:
        return False, f"couldn't reach {url}: {type(e).__name__}"
    if r.status_code == 401:
        return True, f"{url} is reachable and refuses requests without a token"
    return False, f"{url} answered {r.status_code}; expected 401"


def clear_browser() -> None:
    """Delete the kept browser profile: signs out of every site the broker used."""
    profile = dirs()[1] / "profile"
    if profile.is_dir() and profile.name == "profile":
        shutil.rmtree(profile)


def read_audit(limit: int = 500) -> list[dict[str, Any]]:
    path = dirs()[2] / "audit.jsonl"
    if not path.exists():
        return []
    rows = []
    for line in path.read_text().splitlines()[-limit:]:
        with contextlib.suppress(json.JSONDecodeError):
            rows.append(json.loads(line))
    return rows


# The pass-cli steps live in passcli.py; imported last, as that module imports from this one.
from .passcli import (  # noqa: E402, F401
    broker_session_dir,
    check_vault,
    create_agent_token,
    find_url,
    logout,
    pass_cli_info,
    pass_cli_version,
    session_kind,
    start_user_login,
)
