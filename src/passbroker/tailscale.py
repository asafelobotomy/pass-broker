"""Tailscale Funnel: publishes the broker at https://<machine>.<tailnet>.ts.net.

It has to be Funnel, not Serve: Grok's connectors call from Cursor's servers,
which aren't on your tailnet.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass

FUNNEL_OPERATOR_FIX = "run0 tailscale set --operator=$USER"


@dataclass
class TailscaleState:
    installed: bool
    running: bool
    host: str | None
    detail: str


def tailscale_state() -> TailscaleState:
    if not shutil.which("tailscale"):
        return TailscaleState(False, False, None, "tailscale not installed (pacman -S tailscale)")
    try:
        proc = subprocess.run(["tailscale", "status", "--json"], capture_output=True, text=True, timeout=15, stdin=subprocess.DEVNULL)
    except (OSError, subprocess.TimeoutExpired):
        return TailscaleState(True, False, None, "tailscale didn't answer")
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return TailscaleState(True, False, None, "tailscaled isn't running (run0 systemctl enable --now tailscaled)")
    state = data.get("BackendState", "")
    host = ((data.get("Self") or {}).get("DNSName") or "").rstrip(".") or None
    if state != "Running":
        return TailscaleState(True, False, host, f"not connected ({state or 'unknown'}); run: tailscale up")
    return TailscaleState(True, True, host, host or "connected")


def funnel_start_command(port: int) -> list[str]:
    return ["tailscale", "funnel", "--bg", "--https=443", f"http://127.0.0.1:{port}"]


def funnel_stop_command() -> list[str]:
    return ["tailscale", "funnel", "--https=443", "off"]


def funnel_points_at(port: int) -> bool:
    """True when a Funnel is on and forwards to the broker's local port."""
    try:
        proc = subprocess.run(["tailscale", "funnel", "status", "--json"], capture_output=True, text=True, timeout=15)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return f"127.0.0.1:{port}" in proc.stdout and "AllowFunnel" in proc.stdout


def funnel_hint(output: str) -> str | None:
    """Turn the usual first-run Funnel errors into something actionable."""
    low = output.lower()
    if "access denied" in low or "operator" in low or "permission" in low:
        return f"Tailscale needs you as its operator once. Run: {FUNNEL_OPERATOR_FIX}"
    if "funnel" in low and ("not enabled" in low or "enable" in low) and "https://" in low:
        return "Funnel isn't enabled for this tailnet yet. Open the link shown to enable it, then press Start again."
    if "https" in low and "cert" in low:
        return "Turn on HTTPS certificates for your tailnet in the Tailscale admin console (DNS page), then try again."
    return None


