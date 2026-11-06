"""Report a bug to Pass Broker's developers: your description, your system, and bots' reports.

Built here, shown to you in full, and sent only when you press a button: either opened as a
pre-filled new issue on GitHub (you sign in and submit it yourself; nothing needs a token), or
created for you with the GitHub CLI if `gh` is signed in. Before you see it, personal details
(emails, phone and card numbers), your home folder, user name, computer name, tailnet names,
IP addresses and Pass Broker tokens are blanked. Bots' reports are quoted as untrusted text.
"""

from __future__ import annotations

import os
import platform
import re
import shutil
import socket
import subprocess
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

REPO = "asafelobotomy/pass-broker"
MAX_URL = 7000  # GitHub refuses longer new-issue links; the body then goes by clipboard
LABEL = "bug"


def clean(text: str) -> str:
    """What a public issue mustn't carry about you or this machine."""
    from .pii import mask_text

    home, user, host = str(Path.home()), os.environ.get("USER", ""), socket.gethostname()
    text = text.replace(home, "~")
    text = re.sub(r"\bpbc_[A-Za-z0-9_-]{8,}", "pbc_…", text)
    text = re.sub(r"\b(?:[a-z0-9-]+\.)+ts\.net\b", "<tailnet>", text, flags=re.I)
    text = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", lambda m: m.group(0) if m.group(0).startswith("127.") else "<ip>", text)
    for word, mark in ((host, "<computer>"), (user, "<user>")):
        if len(word) >= 3:
            text = re.sub(rf"(?<![\w-]){re.escape(word)}(?![\w-])", mark, text)
    return mask_text(text)


def system_info() -> str:
    from importlib.metadata import version

    try:
        distro = platform.freedesktop_os_release().get("PRETTY_NAME", "Linux")
    except OSError:
        distro = platform.system()
    lines = [f"- Pass Broker {version('passbroker')}" + (" (AppImage)" if os.environ.get("APPIMAGE") else ""),
             f"- {distro}, kernel {platform.release()}, Python {platform.python_version()}",
             f"- Desktop: {os.environ.get('XDG_CURRENT_DESKTOP', '?')} ({os.environ.get('XDG_SESSION_TYPE', '?')})"]
    try:
        out = subprocess.run(["pass-cli", "--version"], capture_output=True, text=True, timeout=10).stdout.strip()
        lines.append(f"- pass-cli: {out.splitlines()[0] if out else 'not found'}")
    except (OSError, subprocess.SubprocessError):
        lines.append("- pass-cli: not found")
    try:
        socket.create_connection(("127.0.0.1", 1143), timeout=0.5).close()
        lines.append("- Proton Mail Bridge: running")
    except OSError:
        lines.append("- Proton Mail Bridge: not running")
    return "\n".join(lines)


def build(title: str, description: str, reports: list[dict[str, Any]], system: bool) -> dict[str, Any]:
    from .issues import markdown

    title = clean(" ".join(str(title or "").split()))[:120] or (reports[0]["title"] if len(reports) == 1 else "")
    parts = []
    if description.strip():
        parts += ["## What happened", "", clean(description.strip()), ""]
    if system:
        parts += ["## System", "", clean(system_info()), ""]
    if reports:
        quoted = markdown(reports).replace("\n## ", "\n### ").replace("# Pass Broker: reports from bots", "## Reports from bots")
        parts += [clean(quoted)]
    parts += ["", "_Sent with Pass Broker's Report a bug._"]
    body = "\n".join(parts).strip() + "\n"
    return {"title": clean(title)[:120], "body": body, **link(title, body), "gh": gh_ready()}


def link(title: str, body: str) -> dict[str, Any]:
    """The new-issue link; past MAX_URL the body goes by clipboard instead (`clipboard`)."""
    base = f"https://github.com/{REPO}/issues/new?"
    url = base + urlencode({"title": title, "labels": LABEL, "body": body})
    if len(url) <= MAX_URL:
        return {"url": url, "clipboard": False}
    note = "The full report is on your clipboard: paste it here, replacing this line."
    return {"url": base + urlencode({"title": title, "labels": LABEL, "body": note}), "clipboard": True}


def gh_ready() -> bool:
    if shutil.which("gh") is None:
        return False
    try:
        return subprocess.run(["gh", "auth", "status"], capture_output=True, timeout=15).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def send(title: str, body: str) -> str:
    """Create the issue with the GitHub CLI, as whoever `gh` is signed in as. Returns its link."""
    if not title.strip() or not body.strip():
        raise ValueError("give the report a title and some text")
    if not gh_ready():
        raise ValueError("the GitHub CLI (gh) isn't installed or signed in; use Open on GitHub instead")
    base = ["gh", "issue", "create", "--repo", REPO, "--title", title[:120], "--body-file", "-"]
    for args in (base + ["--label", LABEL], base):  # the label may not exist; then without it
        proc = subprocess.run(args, input=body, capture_output=True, text=True, timeout=60)
        if proc.returncode == 0:
            found = re.search(r"https://github\.com/\S+/issues/\d+", proc.stdout)
            return found.group(0) if found else proc.stdout.strip()
        if "label" not in proc.stderr.lower():
            break
    raise ValueError("GitHub refused the report: " + clean(proc.stderr.strip())[:300])
