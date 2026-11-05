"""Device actions (optional): things you let bots trigger on your home server and devices.

You define each action in the wizard (stored in ~/.config/passbroker/devices.json):
  - wol:  send a Wake-on-LAN packet to a MAC address (no secret needed)
  - ssh:  run one fixed command on a home server over SSH, with the vault
          password on the command's stdin (your SSH keys do the login)
  - http: call a device's web API (a router, say) with the vault password as
          basic auth, a bearer token, or a {secret} placeholder in the body
The command, address and secret are fixed by you; a bot can only name the
action. Actions never target this PC. Bots get "done" or "failed" back, plus
output only if you allow it for that action.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import re
import socket
import subprocess
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from . import jsonfile
from .vault import Login

if TYPE_CHECKING:
    from .broker import Broker

NAME_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,31}")
MAC_RE = re.compile(r"([0-9a-f]{2}[:-]){5}[0-9a-f]{2}", re.I)
MAX_OUTPUT = 4000


class DeviceError(Exception):
    """Safe to show to the assistant."""


@dataclass
class Device:
    name: str
    kind: str  # wol | ssh | http
    description: str = ""
    host: str = ""  # ssh host, or the broadcast address for wol
    port: int = 0
    user: str = ""
    command: str = ""  # ssh: the remote command
    mac: str = ""  # wol
    url: str = ""  # http
    method: str = "POST"
    auth: str = "none"  # http: none | basic | bearer | body
    username: str = ""  # http basic auth user
    body: str = ""  # http: request body, may contain {secret}
    content_type: str = "application/json"
    insecure_tls: bool = False  # self-signed: pin its certificate (recorded when the action is added)
    plain_http_ok: bool = False  # you accept sending the password unencrypted to an http:// URL
    tls_cert_pem: str = ""  # the pinned certificate
    item: str = ""  # vault item whose password is used; empty = none
    return_output: bool = False
    extra: dict[str, Any] = field(default_factory=dict)

    def public(self) -> dict[str, Any]:
        return {"action": self.name, "kind": self.kind, "description": self.description, "returns_output": self.return_output}


# A host as ssh would take it from you: a name (or ~/.ssh/config alias) or an IP address, never
# anything ssh could read as an option (-oProxyCommand=... would run a command on this PC).
SSH_HOST_RE = re.compile(r"[A-Za-z0-9_](?:[A-Za-z0-9_.-]{0,251}[A-Za-z0-9_])?")
SSH_USER_RE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,31}")


def _ssh_host_ok(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return bool(SSH_HOST_RE.fullmatch(host or ""))


def _this_pc(host: str) -> bool:
    """True when `host` is this machine (by name, loopback, or one of its addresses)."""
    host = host.strip("[]").lower()
    if host in {"localhost", socket.gethostname().lower(), socket.getfqdn().lower()}:
        return True
    try:
        targets = {i[4][0] for i in socket.getaddrinfo(host, None)}
        mine = {i[4][0] for i in socket.getaddrinfo(socket.gethostname(), None)}
    except OSError:
        return False
    return any(ipaddress.ip_address(t.split("%")[0]).is_loopback for t in targets) or bool(targets & mine)


def validate(d: Device) -> None:
    if not (isinstance(d.name, str) and NAME_RE.fullmatch(d.name)):
        raise DeviceError("action name: 1-32 lowercase letters, digits, dot, dash or underscore")
    if d.kind not in ("wol", "ssh", "http"):
        raise DeviceError("kind must be wol, ssh or http")
    if not isinstance(d.return_output, bool) or not isinstance(d.insecure_tls, bool):
        raise DeviceError("switches must be true or false")
    if d.insecure_tls and not d.url.startswith("https://"):
        raise DeviceError("pinning a self-signed certificate needs an https:// URL")
    if d.kind == "wol":
        if not MAC_RE.fullmatch(d.mac or ""):
            raise DeviceError("enter the device's MAC address, like aa:bb:cc:dd:ee:ff")
        return
    if d.kind == "ssh":
        if not d.command or not _ssh_host_ok(d.host):
            raise DeviceError("ssh needs a host name or address (as in your ~/.ssh/config; no user@, spaces or leading -) and a command")
        if d.user and not SSH_USER_RE.fullmatch(d.user):
            raise DeviceError("ssh user: letters, digits, dot, dash and underscore, not starting with -")
        target = d.host
    else:
        from urllib.parse import urlsplit

        parts = urlsplit(d.url)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise DeviceError("http needs a full http(s) URL")
        if d.auth not in ("none", "basic", "bearer", "body"):
            raise DeviceError("auth must be none, basic, bearer or body")
        if d.auth == "body" and "{secret}" not in d.body:
            raise DeviceError("put {secret} in the body where the password goes")
        if parts.scheme == "http" and d.auth != "none" and not d.plain_http_ok:
            raise DeviceError("this would send the password unencrypted to an http:// address: use https, "
                              "or turn on sending it over plain http")
        if d.method.upper() not in ("GET", "POST", "PUT", "PATCH", "DELETE"):
            raise DeviceError("method must be GET, POST, PUT, PATCH or DELETE")
        target = parts.hostname
    if _this_pc(target):
        raise DeviceError("device actions run on your home server and devices, not on this PC")
    if d.kind == "http" and d.auth != "none" and not d.item:
        raise DeviceError("pick the vault item that holds the password")


class DeviceStore:
    def __init__(self, path: Path) -> None:
        self.path = path

    def load(self) -> list[Device]:
        data = jsonfile.read(self.path, {})
        return [jsonfile.build(Device, d) for d in data.get("actions", [])]

    def _save(self, devices: list[Device]) -> None:
        jsonfile.write(self.path, {"actions": [asdict(d) for d in devices]})

    def add(self, d: Device) -> str:
        """Save the action; for a self-signed device, record (pin) its certificate now. Returns its fingerprint."""
        validate(d)
        pinned = ""
        if d.kind == "http" and d.insecure_tls:
            from urllib.parse import urlsplit

            from .tlspin import fetch_https_cert, fingerprint

            parts = urlsplit(d.url)
            if not d.tls_cert_pem:
                # Re-saving the same device keeps the certificate recorded the first time: fetching
                # it again would silently trust whatever answers now (someone in between, say).
                same = next((x for x in self.load() if x.name == d.name and x.tls_cert_pem and urlsplit(x.url).netloc == parts.netloc), None)
                d.tls_cert_pem = same.tls_cert_pem if same else ""
            if not d.tls_cert_pem:
                try:
                    d.tls_cert_pem = fetch_https_cert(parts.hostname or "", parts.port or 443)
                except OSError as e:
                    raise DeviceError(f"couldn't reach the device to record its certificate ({type(e).__name__}); is it on?") from None
            pinned = fingerprint(d.tls_cert_pem)
        self._save([x for x in self.load() if x.name != d.name] + [d])
        return pinned

    def remove(self, name: str) -> bool:
        items = self.load()
        kept = [x for x in items if x.name != name]
        self._save(kept)
        return len(kept) != len(items)

    def get(self, name: str) -> Device:
        for d in self.load():
            if d.name == name:
                return d
        raise DeviceError(f"no device action named '{name}'; call list_device_actions")


def wake(mac: str, broadcast: str = "255.255.255.255", port: int = 9) -> None:
    raw = bytes.fromhex(re.sub(r"[:-]", "", mac))
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        s.sendto(b"\xff" * 6 + raw * 16, (broadcast or "255.255.255.255", port or 9))


def run(d: Device, secret: str | None) -> dict[str, Any]:
    validate(d)  # re-check: the file may have been edited, or DNS changed
    if d.kind == "wol":
        wake(d.mac, d.host, d.port)
        return {"ok": True}
    if d.kind == "ssh":
        argv = ["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=10"]
        argv += (["-p", str(d.port)] if d.port else []) + (["-l", d.user] if d.user else []) + ["--", d.host, d.command]
        try:
            proc = subprocess.run(argv, input=((secret or "") + "\n").encode(), capture_output=True, timeout=120)
        except subprocess.TimeoutExpired:
            return {"ok": False, "error": "timed out"}
        out = (proc.stdout + proc.stderr).decode("utf-8", errors="replace")
        return {"ok": proc.returncode == 0, "exit_code": proc.returncode, "output": out[-MAX_OUTPUT:]}
    import httpx2

    headers = {"content-type": d.content_type} if d.body else {}
    auth = None
    body = d.body
    if d.auth == "basic":
        auth = (d.username, secret or "")
    elif d.auth == "bearer":
        headers["authorization"] = f"Bearer {secret}"
    elif d.auth == "body":
        escaped = json.dumps(secret or "")[1:-1] if "json" in d.content_type else secret or ""
        body = body.replace("{secret}", escaped)
    try:
        verify: Any = True
        if d.insecure_tls:
            if not d.tls_cert_pem:
                return {"ok": False, "error": "no pinned certificate; ask the user to add this action again"}
            from .tlspin import pinned_context

            verify = pinned_context(d.tls_cert_pem)
        r = httpx2.request(d.method, d.url, content=body.encode() if body else None, headers=headers, auth=auth,
                           verify=verify, timeout=20, follow_redirects=False)
    except Exception as e:
        return {"ok": False, "error": f"couldn't reach the device ({type(e).__name__})"}
    return {"ok": 200 <= r.status_code < 300, "status": r.status_code, "output": r.text[:MAX_OUTPUT]}


class DevicesMixin:
    async def list_device_actions(self: "Broker", client: str) -> list[dict[str, Any]]:
        devices = self.devices.load() if self.devices else []
        names = set(self._granted(client, "devices", [d.name for d in devices]))
        return [d.public() for d in devices if d.name in names]

    async def run_device_action(self: "Broker", client: str, action: str, reason: str = "") -> dict[str, Any]:
        from .broker import BrokerError, plain

        if self.devices is None:
            raise BrokerError("device actions aren't set up on this broker")
        self._permit(client, "devices", action)
        try:
            d = self.devices.get(action)
        except DeviceError as e:
            raise BrokerError(str(e)) from None
        login = await self._item(d.item, d.name) if d.item else Login(f"device:{d.name}", f"(no secret) {d.name}", (), None, False)
        where = d.mac if d.kind == "wol" else (d.host if d.kind == "ssh" else d.url)
        details = (
            f"Device action: {d.name} ({d.kind}) → {plain(where, 100)}\n"
            + (f"Does: {plain(d.description, 100)}\n" if d.description else "")
            + ("Its output WILL be shown to the assistant.\n" if d.return_output else "The assistant only sees done or failed.\n")
        )
        await self._approve(client, login, f"device:{d.name}", "device", f"run the device action '{d.name}'", details, reason)
        secret = await self._secret(client, login, "password", f"device action {d.name}") if d.item else None
        try:
            result = await asyncio.to_thread(run, d, secret)
        except DeviceError as e:
            raise BrokerError(str(e)) from None
        finally:
            del secret
        self.audit.record("device_action", client=client, action=d.name, ok=result["ok"])
        reply: dict[str, Any] = {"result": "done" if result["ok"] else "failed"}
        if not result["ok"] and result.get("error"):
            reply["error"] = result["error"]
        if d.return_output:
            reply["output"] = result.get("output", "")
        return reply
