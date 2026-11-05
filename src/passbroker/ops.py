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


# ---- pass-cli -------------------------------------------------------------------


def pass_cli_version(pass_cli: str = "pass-cli") -> str | None:
    with contextlib.suppress(OpError):
        proc = _run([pass_cli, "--version"], timeout=15)
        if proc.returncode == 0:
            return proc.stdout.strip() or proc.stderr.strip()
    return None


def pass_cli_info(pass_cli: str = "pass-cli") -> tuple[bool, str]:
    """(signed in?, what pass-cli says about the session)."""
    proc = _run([pass_cli, "info"], timeout=30)
    text = _scrub_tokens((proc.stdout or proc.stderr).strip())
    return proc.returncode == 0, text


def start_user_login(pass_cli: str = "pass-cli") -> subprocess.Popen[str]:
    """Start `pass-cli login` (web login). The caller reads stdout for the URL."""
    try:
        return subprocess.Popen(
            [pass_cli, "login"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, text=True, bufsize=1
        )
    except FileNotFoundError:
        raise OpError(f"{pass_cli} is not installed or not on PATH") from None


def find_url(line: str) -> str | None:
    m = re.search(r"https://\S+", line)
    return m.group(0).rstrip(".,)'\"") if m else None


def logout(pass_cli: str = "pass-cli") -> None:
    _run([pass_cli, "logout"], timeout=30)


def create_agent_token(name: str, expiration: str, vault: str, pass_cli: str = "pass-cli") -> str:
    """Create a Proton Pass agent token with viewer access to one vault and keyring it.

    An agent is an access token whose every read is logged with a reason
    (`pass-cli agent monitor`). Needs pass-cli signed in as you. The token goes
    straight from pass-cli's output into the keyring and is never returned or
    shown. Returns the keyring backend's name.
    """
    if expiration not in EXPIRATIONS:
        raise OpError(f"expiration must be one of {', '.join(EXPIRATIONS)}")
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", name):
        raise OpError("token name: letters, digits, dot, dash and underscore only")
    kind, label = session_kind(pass_cli)
    if kind == "token":
        raise OpError(
            f"pass-cli is signed in with an access token or agent ({label}), not your own account. "
            "Only your account can create agents: sign out of that session and sign in as yourself first."
        )
    if kind == "none":
        raise OpError("pass-cli isn't signed in. Sign in to Proton as yourself first (step 1).")
    proc = _run([pass_cli, "agent", "create", name, "--expiration", expiration, "--vault", vault])
    if proc.returncode != 0:
        raise OpError("creating the agent token failed: " + _scrub_tokens(proc.stderr.strip() or proc.stdout.strip())[:300])
    found = _TOKEN_RE.findall(proc.stdout + "\n" + proc.stderr)
    if not found:
        raise OpError("pass-cli created the agent but its output didn't contain a token; check `pass-cli agent list`, renew it and paste the token instead")
    backend = store_token(found[0])
    del found
    return backend


def broker_session_dir() -> Path:
    return dirs()[1] / "pass-session"


def session_kind(pass_cli: str = "pass-cli") -> tuple[str, str]:
    """Your own pass-cli session (not the broker's): ("none" | "user" | "token", label)."""
    signed_in, text = pass_cli_info(pass_cli)
    if not signed_in:
        return "none", ""
    m = re.search(r"Personal Access Token:\s*(.+)", text)
    if m:
        return "token", m.group(1).strip()[:80]
    m = re.search(r"(?:Email|User(?:name)?|Account):\s*(.+)", text, re.I)
    return "user", (m.group(1).strip()[:80] if m else "your account")


def check_vault(vault: str, pass_cli: str = "pass-cli") -> dict[str, Any]:
    """Log in with the stored token and list what assistants will see. Reads no passwords.

    Also returns the JSON key names (never values) pass-cli's listing used, to
    diagnose logins whose websites weren't found.
    """
    from .redact import Redactor
    from .vault import ProtonPassBackend

    backend = ProtonPassBackend(vault, load_token, Redactor(), pass_cli=pass_cli, session_dir=broker_session_dir())
    logins = [login.public() for login in backend.list_logins()]
    return {"logins": logins, "keys": sorted(getattr(backend, "seen_keys", set()))}


# ---- clients ----------------------------------------------------------------------


def clients_path() -> Path:
    return dirs()[0] / "clients.json"


def list_clients() -> list[str]:
    from .server import load_clients

    return list(load_clients(clients_path()))


def _write_clients(clients: dict[str, str]) -> None:
    fd = os.open(clients_path(), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(clients, f, indent=2)


def add_client(name: str) -> str:
    """Create (or replace) a client and return its bearer token. Only its hash is kept."""
    from .server import hash_token, load_clients

    if not re.fullmatch(r"[A-Za-z0-9._-]{1,32}", name):
        raise OpError("assistant name: letters, digits, dot, dash and underscore only")
    clients = load_clients(clients_path())
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
