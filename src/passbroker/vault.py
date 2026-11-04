"""Vault backends: Proton Pass via pass-cli, and a JSON mock for tests.

The model only ever sees `Login` metadata and an opaque handle. Handles are
random per process, so the model cannot construct a reference to an item it
was not shown, and nothing it says can name a vault or field directly.
"""

from __future__ import annotations

import json
import os
import re
import secrets
import subprocess
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal, Protocol

from .redact import Redactor

Field = Literal["username", "password", "totp"]


class VaultError(Exception):
    """A vault failure. Messages are safe to show: they never carry values."""


@dataclass(frozen=True)
class Login:
    handle: str
    title: str
    urls: tuple[str, ...]
    username: str | None
    has_totp: bool | None  # None: the vault listing didn't say

    def public(self, mask: bool = False) -> dict[str, Any]:
        return {
            "handle": self.handle,
            "title": self.title,
            "urls": list(self.urls),
            "username": mask_username(self.username) if mask else self.username,
            "has_totp": self.has_totp,
            "fillable": bool(self.urls),
        }


def mask_username(name: str | None) -> str | None:
    """a***@gmail.com / a***: enough to tell logins apart, not enough to reuse."""
    if not name:
        return name
    local, at, domain = name.partition("@")
    return f"{local[:1]}***{at}{domain}"


class Backend(Protocol):
    def list_logins(self) -> list[Login]: ...
    def get(self, handle: str) -> Login: ...
    def secret(self, handle: str, field: Field, reason: str) -> str: ...


def _new_handle() -> str:
    return "h_" + secrets.token_urlsafe(9)


@dataclass
class _Index:
    by_handle: dict[str, Login] = field(default_factory=dict)
    ref: dict[str, str] = field(default_factory=dict)  # handle -> backend item key
    handle_for: dict[str, str] = field(default_factory=dict)  # item key -> handle

    def put(self, key: str, make: Callable[[str], Login]) -> Login:
        handle = self.handle_for.get(key) or _new_handle()
        login = make(handle)
        self.by_handle[handle] = login
        self.ref[handle] = key
        self.handle_for[key] = handle
        return login

    def get(self, handle: str) -> Login:
        try:
            return self.by_handle[handle]
        except KeyError:
            raise VaultError("unknown handle; call list_logins first") from None


class MockBackend:
    """Reads logins from a JSON list: title, urls, username, password, totp."""

    def __init__(self, path: Path, redactor: Redactor) -> None:
        self._items = {str(i): item for i, item in enumerate(json.loads(path.read_text()))}
        self._redactor = redactor
        self._index = _Index()
        for item in self._items.values():
            redactor.add(item.get("password"))
            redactor.add(item.get("totp"))

    def list_logins(self) -> list[Login]:
        return [
            self._index.put(
                key,
                lambda h, it=item: Login(
                    handle=h,
                    title=it["title"],
                    urls=tuple(it.get("urls", [])),
                    username=it.get("username"),
                    has_totp=bool(it.get("totp")),
                ),
            )
            for key, item in self._items.items()
        ]

    def get(self, handle: str) -> Login:
        return self._index.get(handle)

    def secret(self, handle: str, field: Field, reason: str) -> str:
        self._index.get(handle)
        value = self._items[self._index.ref[handle]].get(field)
        if not value:
            raise VaultError(f"item has no {field}")
        self._redactor.add(value)
        return value


# Key names seen in pass-cli JSON vary between versions and are not documented,
# so metadata is pulled out by searching for likely keys at any depth.
_URL_KEYS = {"urls", "url", "website", "websites"}
_USER_KEYS = {"username", "email", "item_email", "item_username", "itememail", "itemusername"}
_SECRET_KEYS = {"password", "totp", "totp_uri", "totpuri"}


def _walk(obj: Any):
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield k.lower(), v
            yield from _walk(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _walk(v)


def _strings(v: Any) -> list[str]:
    if isinstance(v, str):
        return [v] if v else []
    if isinstance(v, list):
        return [s for s in v if isinstance(s, str) and s]
    return []


class ProtonPassBackend:
    """Talks to Proton Pass through pass-cli, logged in with a personal access token.

    The token goes to pass-cli through its environment (never argv), and only
    for `login`. Every read carries PROTON_PASS_AGENT_REASON so Proton's audit
    log records why the broker asked.
    """

    def __init__(
        self,
        vault: str,
        load_token: Callable[[], str],
        redactor: Redactor,
        pass_cli: str = "pass-cli",
        timeout: float = 30,
        session_dir: Path | None = None,
    ) -> None:
        self._vault = vault
        # The broker keeps its own pass-cli session, so signing in as yourself
        # (or as another agent) in a terminal never replaces it, and vice versa.
        self._session_dir = session_dir
        if session_dir is not None:
            session_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._load_token = load_token
        self._redactor = redactor
        self._cli = pass_cli
        self._timeout = timeout
        self._index = _Index()

    def _env(self, extra: dict[str, str]) -> dict[str, str]:
        keep = ("PATH", "HOME", "LANG", "LC_ALL", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME", "XDG_RUNTIME_DIR")
        env = {k: os.environ[k] for k in keep if k in os.environ}
        env["PROTON_PASS_NO_UPDATE_CHECK"] = "1"
        if self._session_dir is not None:
            env["PROTON_PASS_SESSION_DIR"] = str(self._session_dir)
        env.update(extra)
        return env

    def _exec(self, args: list[str], extra_env: dict[str, str]) -> subprocess.CompletedProcess[str]:
        try:
            return subprocess.run(
                [self._cli, *args],
                env=self._env(extra_env),
                capture_output=True,
                text=True,
                timeout=self._timeout,
                stdin=subprocess.DEVNULL,
            )
        except FileNotFoundError:
            raise VaultError("pass-cli is not installed or not on PATH") from None
        except subprocess.TimeoutExpired:
            raise VaultError("pass-cli timed out") from None

    def _login(self) -> None:
        token = self._load_token()
        self._redactor.add(token)
        proc = self._exec(["login"], {"PROTON_PASS_PERSONAL_ACCESS_TOKEN": token})
        if proc.returncode != 0:
            raise VaultError("pass-cli login with the access token failed: " + self._redactor.scrub(proc.stderr.strip())[:300])

    def _run(self, args: list[str], reason: str) -> str:
        env = {"PROTON_PASS_AGENT_REASON": reason[:300]}
        proc = self._exec(args, env)
        if proc.returncode != 0:
            # Token sessions last two hours; log in again once and retry.
            self._login()
            proc = self._exec(args, env)
        if proc.returncode != 0:
            raise VaultError("pass-cli failed: " + self._redactor.scrub(proc.stderr.strip())[:300])
        return proc.stdout

    def _item_args(self, handle: str) -> list[str]:
        self._index.get(handle)
        return ["--vault-name", self._vault, "--item-id", self._index.ref[handle]]

    def _extract(self, item: Any) -> tuple[list[str], str | None, bool | None]:
        """Websites, username and whether 2FA is set, from listing or item-view JSON.

        Secret values met on the way (password, TOTP seed) go to the redactor
        only. In pass-cli 2.7.0 an item view looks like
        item.content.content.Login.{urls, username, email, password, totp_uri}.
        """
        urls: list[str] = []
        users: dict[str, str] = {}
        has_totp: bool | None = None
        for k, v in _walk(item):
            self.seen_keys.add(k)
            if k in _URL_KEYS:
                urls += _strings(v)
            elif k in _USER_KEYS and _strings(v):
                users.setdefault(k, _strings(v)[0])
            elif k in _SECRET_KEYS:
                for s in _strings(v):
                    self._redactor.add(s)
                if k.startswith("totp"):
                    has_totp = bool(_strings(v)) or bool(has_totp)
        username = next((users[k] for k in ("username", "item_username", "itemusername", "email", "item_email", "itememail") if k in users), None)
        return urls, username, has_totp

    def list_logins(self) -> list[Login]:
        # Agent sessions can't use --show-secrets, so the listing carries only
        # titles and ids; each item's own view then supplies its websites.
        out = self._run(
            ["item", "list", "--vault-name", self._vault, "--filter-type", "login", "--output", "json"],
            "pass-broker: list login titles and websites",
        )
        try:
            data = json.loads(out)
        except json.JSONDecodeError:
            raise VaultError("pass-cli returned output that isn't JSON") from None
        items = data.get("items", data) if isinstance(data, dict) else data
        self.seen_keys: set[str] = set()
        logins = []
        for item in items if isinstance(items, list) else []:
            key = item.get("id") or item.get("item_id") or item.get("itemId")
            if not key:
                continue
            key = str(key)
            title = str(item.get("title") or next((v for k, v in _walk(item) if k in ("title", "name") and isinstance(v, str)), "untitled"))
            urls, username, has_totp = self._extract(item)
            if not urls or username is None or has_totp is None:
                try:
                    view = json.loads(
                        self._run(
                            ["item", "view", "--vault-name", self._vault, "--item-id", key, "--output", "json"],
                            f"pass-broker: read the website and username saved for {title[:60]}",
                        )
                    )
                except (VaultError, json.JSONDecodeError):
                    view = None
                if view is not None:
                    v_urls, v_user, v_totp = self._extract(view)
                    urls = urls or v_urls
                    username = username if username is not None else v_user
                    has_totp = has_totp if has_totp is not None else v_totp
            logins.append(
                self._index.put(
                    key,
                    lambda h, t=title, u=tuple(dict.fromkeys(urls)), n=username, tp=has_totp: Login(h, t, u, n, tp),
                )
            )
        return logins

    def get(self, handle: str) -> Login:
        return self._index.get(handle)

    def secret(self, handle: str, field: Field, reason: str) -> str:
        args = self._item_args(handle)
        if field == "totp":
            value = _totp_code(self._run(["item", "totp", *args, "--output", "json"], reason))
        else:
            value = self._run(["item", "view", *args, "--field", field], reason).rstrip("\r\n")
        if not value:
            raise VaultError(f"item has no {field}")
        self._redactor.add(value)
        return value


def _totp_code(out: str) -> str | None:
    """The first 6-8 digit code in `item totp` output, JSON or plain."""
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        data = None
    if data is not None:
        for _, v in _walk({"": data}):
            if isinstance(v, (str, int)) and re.fullmatch(r"\d{6,8}", str(v)):
                return str(v)
    m = re.search(r"\b\d{6,8}\b", out)
    return m.group(0) if m else None
