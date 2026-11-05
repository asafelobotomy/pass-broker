"""OAuth sign-in for remote assistants, approved by a code shown only on your desktop.

Grok's connector backend can't send a fixed header without the Bot reading it,
so remote apps connect with OAuth instead:

1. The app registers itself (dynamic client registration) and opens /authorize.
2. The broker shows a desktop notification with a one-time code, and sends the
   browser to a consent page that asks for that code.
3. Only someone who can see this PC's screen can type the code, so someone
   else starting a sign-in gets nowhere, even if you click carelessly.
4. The app gets an access token (1 hour) and a refresh token (30 days,
   replaced on every use). The broker stores only their hashes.

Local assistants keep using the fixed `pbc_` tokens from `passbroker add-client`;
`load_access_token` accepts both.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
import subprocess
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    AuthorizeError,
    RefreshToken,
    RegistrationError,
    TokenError,
)
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken

from .consent_page import ConsentMixin
from .oauth_store import Store, list_connections, revoke_connection  # noqa: F401

SCOPE = "broker"
ACCESS_TTL = 3600
REFRESH_TTL = 30 * 24 * 3600
CONSENT_TTL = 300
CODE_TTL = 120
MAX_PENDING = 3
MAX_ATTEMPTS = 5
MAX_CLIENTS = 50
NOTIFY_PER_HOUR = 20
PAIRING_WINDOW = 600
CLIENT_GRACE = 600  # don't evict a registration younger than this
CODE_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"
# Where sign-in codes may be sent: Cursor's connector backend (Grok Bot), plus
# loopback addresses for apps on this PC. Anything else can't register, so a
# look-alike "Grok" registered by someone else can't receive your connection.
DEFAULT_REDIRECT_HOSTS = ("www.cursor.com", "cursor.com")
LOOPBACK = {"localhost", "127.0.0.1", "::1"}


def clean_name(name: str | None) -> str:
    """App names come from whoever registered: no markup, no control characters."""
    text = re.sub(r"[^\w .()\-]", "", name or "").strip()
    return text[:40] or "an app"


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _one_time_code() -> str:
    raw = "".join(secrets.choice(CODE_ALPHABET) for _ in range(8))
    return f"{raw[:4]}-{raw[4:]}"


def desktop_notify(title: str, body: str) -> None:
    """Non-blocking notification; the code is shown here and nowhere else."""
    try:
        subprocess.Popen(
            ["notify-send", "--app-name=Pass Broker", "--urgency=critical", "--expire-time=300000", title, body],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except FileNotFoundError:
        pass


@dataclass
class Pending:
    id: str
    client: OAuthClientInformationFull
    params: AuthorizationParams
    code: str
    expires: float
    attempts: int = 0


class BrokerOAuth(ConsentMixin):
    """OAuthAuthorizationServerProvider for the MCP SDK, plus the consent page."""

    def __init__(
        self,
        issuer: str,
        resource: str,
        store_path: Path,
        static_clients: Callable[[], dict[str, str]],
        notify: Callable[[str, str], None] = desktop_notify,
        audit: Callable[..., None] | None = None,
        redirect_hosts: tuple[str, ...] | list[str] = DEFAULT_REDIRECT_HOSTS,
        pairing_path: Path | None = None,
    ) -> None:
        # Sign-ins only start while you have "Connect an app" open in the wizard,
        # so a link someone else sends you can't start one.
        self.pairing_path = pairing_path
        self.redirect_hosts = {h.lower() for h in redirect_hosts}
        self._notified: list[float] = []
        self.issuer = issuer.rstrip("/")
        self.resource = resource
        self.store = Store(store_path)
        self.store.load()
        self.static_clients = static_clients
        self.notify = notify
        self.audit = audit or (lambda *a, **k: None)
        self.pending: dict[str, Pending] = {}
        self.codes: dict[str, tuple[AuthorizationCode, str]] = {}  # code -> (code, connection name)
        self._lock = threading.Lock()

    # ---- who is asking ------------------------------------------------------------

    def name_for(self, bearer: str | None) -> str:
        """The assistant name behind an Authorization header, for the audit log."""
        if not bearer or not bearer.lower().startswith("bearer "):
            return "unknown"
        token = bearer[7:].strip()
        digest = _hash(token)
        for name, h in self.static_clients().items():
            if hmac.compare_digest(digest, h):
                return name
        with self._lock:
            self.store.load()
            for g in self.store.grants.values():
                if any(hmac.compare_digest(digest, a["hash"]) for a in g.get("access", [])):
                    return g["name"]
        return "unknown"

    def taken_names(self) -> set[str]:
        """Names in use by a connection, a sign-in about to become one, or a local assistant (lower-cased)."""
        with self._lock:
            self.store.load()
            names = {str(g.get("name", "")).lower() for g in self.store.grants.values()}
            names |= {name.lower() for _, name in self.codes.values()}
        return names | {n.lower() for n in self.static_clients()}

    # ---- client registration --------------------------------------------------------

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        with self._lock:
            self.store.load()
            data = self.store.clients.get(client_id)
        return OAuthClientInformationFull.model_validate(data) if data else None

    def _redirect_ok(self, uri: str) -> bool:
        parts = urlsplit(uri)
        host = (parts.hostname or "").lower()
        if parts.scheme == "https":
            return host in self.redirect_hosts or host in LOOPBACK
        return parts.scheme == "http" and host in LOOPBACK

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        uris = [str(u) for u in (client_info.redirect_uris or [])]
        bad = [u for u in uris if not self._redirect_ok(u)]
        if not uris or bad:
            self.audit("oauth_register_refused", app=clean_name(client_info.client_name), redirect=(urlsplit(bad[0]).hostname if bad else ""))
            raise RegistrationError(
                "invalid_redirect_uri",
                "this broker only sends sign-in codes to: " + ", ".join(sorted(self.redirect_hosts)) + " (or this PC)",
            )
        now = time.time()
        with self._lock, self.store.transaction():
            if len(self.store.clients) >= MAX_CLIENTS:
                # Drop registrations that never connected, oldest first, sparing fresh ones.
                used = {g["client_id"] for g in self.store.grants.values()}
                idle = sorted(
                    (c for c, d in self.store.clients.items() if c not in used and now - d.get("client_id_issued_at", 0) > CLIENT_GRACE),
                    key=lambda c: self.store.clients[c].get("client_id_issued_at", 0),
                )
                if not idle:
                    raise RegistrationError("invalid_client_metadata", "too many registrations; try again later")
                for cid in idle[: len(self.store.clients) - MAX_CLIENTS + 1]:
                    del self.store.clients[cid]
            self.store.clients[client_info.client_id] = json.loads(client_info.model_dump_json(exclude_none=True))
        self.audit("oauth_register", app=clean_name(client_info.client_name))

    # ---- authorization ------------------------------------------------------------

    def _app_name(self, client: OAuthClientInformationFull) -> str:
        return clean_name(client.client_name)

    @staticmethod
    def _returns_to(params: AuthorizationParams) -> str:
        return (urlsplit(str(params.redirect_uri)).hostname or "?").lower()

    def pairing_open(self) -> bool:
        if self.pairing_path is None:
            return True
        try:
            return time.time() - self.pairing_path.stat().st_mtime < PAIRING_WINDOW
        except FileNotFoundError:
            return False

    async def authorize(self, client: OAuthClientInformationFull, params: AuthorizationParams) -> str:
        now = time.time()
        if not self.pairing_open():
            self.audit("oauth_not_pairing", app=self._app_name(client))
            raise AuthorizeError("access_denied", "open Pass Broker and press Connect an app first, then try again within 10 minutes")
        with self._lock:
            self.pending = {k: p for k, p in self.pending.items() if p.expires > now and p.client.client_id != client.client_id}
            self._notified = [t for t in self._notified if t > now - 3600]
            if len(self.pending) >= MAX_PENDING or len(self._notified) >= NOTIFY_PER_HOUR:
                raise AuthorizeError("temporarily_unavailable", "too many sign-ins waiting; try again in a few minutes")
            self._notified.append(now)
            p = Pending(secrets.token_urlsafe(24), client, params, _one_time_code(), now + CONSENT_TTL)
            self.pending[p.id] = p
        self.notify(
            "Pass Broker: an app wants to connect",
            f"App: {self._app_name(client)} (returns to {self._returns_to(params)})\nCode: {p.code}\n\n"
            "Type this code only on a sign-in page you opened yourself. If you didn't start this, ignore it.",
        )
        self.audit("oauth_consent_shown", app=self._app_name(client))
        return f"{self.issuer}/consent?req={p.id}"

    async def load_authorization_code(self, client: OAuthClientInformationFull, authorization_code: str) -> AuthorizationCode | None:
        with self._lock:
            entry = self.codes.get(authorization_code)
        if not entry or entry[0].client_id != client.client_id or entry[0].expires_at < time.time():
            return None
        return entry[0]

    def _issue(self, grant_id: str, scopes: list[str]) -> OAuthToken:
        access, refresh = "pba_" + secrets.token_urlsafe(32), "pbr_" + secrets.token_urlsafe(32)
        now = time.time()
        g = self.store.grants[grant_id]
        g["access"] = [a for a in g.get("access", []) if a["exp"] > now] + [{"hash": _hash(access), "exp": now + ACCESS_TTL}]
        if g.get("refresh_hash"):
            g["old_refresh"] = (g.get("old_refresh", []) + [g["refresh_hash"]])[-20:]
        g["refresh_hash"] = _hash(refresh)
        g["refresh_exp"] = now + REFRESH_TTL
        g["scopes"] = scopes
        return OAuthToken(access_token=access, expires_in=ACCESS_TTL, scope=" ".join(scopes), refresh_token=refresh)

    async def exchange_authorization_code(self, client: OAuthClientInformationFull, authorization_code: AuthorizationCode) -> OAuthToken:
        with self._lock:
            entry = self.codes.pop(authorization_code.code, None)
            if entry is None:
                raise TokenError("invalid_grant", "authorization code already used")
            name = entry[1]
            with self.store.transaction():
                # Backstop for two sign-ins naming themselves the same at once.
                taken = {str(g.get("name", "")).lower() for g in self.store.grants.values()} | {n.lower() for n in self.static_clients()}
                base, n = name, 2
                while name.lower() in taken:
                    name, n = f"{base[:29]}-{n}", n + 1
                grant_id = "g_" + secrets.token_urlsafe(9)
                self.store.grants[grant_id] = {
                    "name": name,
                    "app": clean_name(client.client_name),
                    "client_id": client.client_id,
                    "created": time.strftime("%Y-%m-%d %H:%M"),
                }
                token = self._issue(grant_id, authorization_code.scopes)
        self.audit("oauth_connected", name=name, app=(client.client_name or "")[:60])
        if self.pairing_path is not None:
            self.pairing_path.unlink(missing_ok=True)  # one connection per "Connect an app"
        return token

    def _grant_by_refresh(self, refresh: str) -> tuple[str, dict[str, Any]] | None:
        digest = _hash(refresh)
        for gid, g in self.store.grants.items():
            if hmac.compare_digest(digest, g.get("refresh_hash", "")) and g.get("refresh_exp", 0) > time.time():
                return gid, g
        return None

    async def load_refresh_token(self, client: OAuthClientInformationFull, refresh_token: str) -> RefreshToken | None:
        with self._lock, self.store.transaction():
            found = self._grant_by_refresh(refresh_token)
            if not found:
                # An old refresh token coming back means a copy leaked: cut the connection.
                gid = self._reused_refresh(refresh_token)
                if gid is not None:
                    g = self.store.grants.pop(gid)
                    self.audit("oauth_refresh_reuse_revoked", name=g["name"])
        if not found or found[1]["client_id"] != client.client_id:
            return None
        g = found[1]
        return RefreshToken(token=refresh_token, client_id=client.client_id, scopes=g.get("scopes", [SCOPE]), expires_at=int(g["refresh_exp"]), resource=self.resource)

    def _reused_refresh(self, refresh: str) -> str | None:
        digest = _hash(refresh)
        for gid, g in self.store.grants.items():
            if any(hmac.compare_digest(digest, h) for h in g.get("old_refresh", [])):
                return gid
        return None

    async def exchange_refresh_token(self, client: OAuthClientInformationFull, refresh_token: RefreshToken, scopes: list[str]) -> OAuthToken:
        with self._lock, self.store.transaction():
            found = self._grant_by_refresh(refresh_token.token)
            if not found:
                raise TokenError("invalid_grant", "refresh token is not valid")
            gid, g = found
            granted = g.get("scopes", [SCOPE])
            if scopes and not set(scopes) <= set(granted):
                raise TokenError("invalid_scope", "can't widen scopes on refresh")
            return self._issue(gid, scopes or granted)

    async def load_access_token(self, token: str) -> AccessToken | None:
        digest = _hash(token)
        for name, h in self.static_clients().items():
            if hmac.compare_digest(digest, h):
                return AccessToken(token=token, client_id=f"local:{name}", scopes=[SCOPE], resource=self.resource)
        now = time.time()
        with self._lock:
            self.store.load()
            for gid, g in self.store.grants.items():
                for a in g.get("access", []):
                    if a["exp"] > now and hmac.compare_digest(digest, a["hash"]):
                        if not g.get("last_used") or g["last_used"] < time.strftime("%Y-%m-%d %H:%M", time.localtime(now - 300)):
                            with self.store.transaction():
                                if gid in self.store.grants:
                                    self.store.grants[gid]["last_used"] = time.strftime("%Y-%m-%d %H:%M")
                        return AccessToken(token=token, client_id=g["client_id"], scopes=g.get("scopes", [SCOPE]), expires_at=int(a["exp"]), resource=self.resource)
        return None

    async def revoke_token(self, token: AccessToken | RefreshToken) -> None:
        digest = _hash(token.token)
        with self._lock, self.store.transaction():
            for gid, g in list(self.store.grants.items()):
                if hmac.compare_digest(digest, g.get("refresh_hash", "")) or any(hmac.compare_digest(digest, a["hash"]) for a in g.get("access", [])):
                    del self.store.grants[gid]
                    self.audit("oauth_revoked", name=g["name"])
                    return
