"""pass-cli as you: signing in, making the broker's agent token, and checking the vault.

Moved out of ops.py (which re-exports it all), so neither file nears the 400-line limit.
"""

from __future__ import annotations

import contextlib
import re
import subprocess
from pathlib import Path
from typing import Any

from .ops import (
    _TOKEN_RE,
    EXPIRATIONS,
    OpError,
    _run,
    _scrub_tokens,
    dirs,
    load_token,
    store_token,
)


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


def broker_session_dir(name: str = "pass-session") -> Path:
    return dirs()[1] / name


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
    from . import accounts
    from .redact import Redactor
    from .vault import ProtonPassBackend

    # Its own session: the running broker may be logging in on its session at the same moment.
    backend = ProtonPassBackend(vault, load_token, Redactor(), pass_cli=pass_cli, session_dir=broker_session_dir("pass-session-check"))
    backend.extra_vault = lambda: (s.vault if (s := accounts.load()).enabled else None)  # bot-made accounts
    logins = [login.public() for login in backend.list_logins()]
    return {"logins": logins, "keys": sorted(getattr(backend, "seen_keys", set())), "accounts_error": backend.extra_error}
