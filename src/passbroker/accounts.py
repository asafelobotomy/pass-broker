"""Bot-made accounts: a bot signs up on a site with a login the broker creates, never seeing it.

The bot opens a site's sign-up page and calls create_login. You approve on your desktop; Proton
Pass then generates the password and saves a new login, bound to that site, in a vault of its
own (**Bot Accounts** by default). The bot gets only a handle. fill_signup fills the username or
email and every password field (password and confirm) and submits, like a sign-in. The new login
is granted to the bot that made it, so it can sign in with it later, still with your approval.

Why a separate vault: creating items needs the token's `editor` role. Your Agent vault stays
read-only (`viewer`) to the broker, so a compromised broker still can't change or delete the
logins you put there; it can only touch the accounts bots made.
"""

from __future__ import annotations

import asyncio
import re
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

from . import jsonfile
from .browser_js import USERNAME_SELECTORS
from .origin import host_of, origin_allowed
from .vault import Login, PasswordRules, VaultError

if TYPE_CHECKING:
    from .broker import Broker

USERNAME_RE = re.compile(r"[\w.@+-]{1,64}")
VAULT_RE = re.compile(r"[\w .-]{1,40}")
PER_BOT_PER_DAY = 10
FRESH_S = 600  # approving the new account also covers its sign-up form, for this long


@dataclass
class AccountSettings:
    vault: str = "Bot Accounts"
    enabled: bool = False


def settings_path() -> Path:
    from .ops import dirs

    return dirs()[0] / "accounts.json"


def load(path: Path | None = None) -> AccountSettings:
    try:
        return jsonfile.build(AccountSettings, jsonfile.read(path or settings_path(), {}) or {})
    except (ValueError, TypeError):
        return AccountSettings()


AGENT_LINE = re.compile(r"^- \[([^\]]+)\]: (.+?) \(expires", re.M)
GRANT_LINE = re.compile(r"^- \[([^\]]+)\] (.+?) \| Type=Vault \| Role=(\w+)", re.M)


def broker_sees(vault: str, pass_cli: str = "pass-cli") -> bool:
    """Whether the token Pass Broker holds can list `vault`, from a fresh session of its own."""
    import shutil
    import tempfile

    from .ops import dirs, load_token
    from .redact import Redactor
    from .vault import ProtonPassBackend

    folder = Path(tempfile.mkdtemp(prefix="pass-session-setup-", dir=dirs()[1]))
    try:
        backend = ProtonPassBackend(vault, load_token, Redactor(), pass_cli=pass_cli, session_dir=folder)
        backend._login()
        return backend._exec(["item", "list", "--vault-name", vault, "--output", "json"], {}).returncode == 0
    except VaultError:
        return False
    finally:
        shutil.rmtree(folder, ignore_errors=True)


def setup(vault: str, agent: str, main_vault: str, pass_cli: str = "pass-cli", sees=broker_sees) -> dict[str, Any]:
    """Make the vault (if needed) and give the broker's own agent `editor` there. Run as yourself.

    Several agents can share a name (renewing in the wizard makes another), and granting by name
    picks the oldest, which may not be the token the broker holds. So each agent of that name with
    access to your Agent vault is tried, newest first, until the broker's token can see the new
    vault; a grant that didn't help is taken back at once."""
    from .ops import OpError, _run, _scrub_tokens, session_kind

    vault = vault.strip()
    if not VAULT_RE.fullmatch(vault):
        raise OpError("vault name: up to 40 letters, digits, spaces, dot, dash or underscore")
    if vault.lower() == main_vault.strip().lower():
        raise OpError(f"use a vault of its own, not {main_vault}: the broker keeps read-only access to that one")
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", agent):
        raise OpError("agent name: letters, digits, dot, dash and underscore only")
    kind, _ = session_kind(pass_cli)
    if kind != "user":
        raise OpError("sign in to pass-cli as yourself first (step 1): only your account can change what the broker may do")

    def run(args: list[str], what: str) -> str:
        proc = _run([pass_cli, *args])
        if proc.returncode != 0:
            raise OpError(f"{what} failed: " + _scrub_tokens(proc.stderr.strip() or proc.stdout.strip())[:300])
        return proc.stdout

    listed = run(["vault", "list", "--output", "json"], "listing your vaults")
    if not re.search(r'"name"\s*:\s*"' + re.escape(vault) + '"', listed):
        run(["vault", "create", "--name", vault], f"creating the {vault} vault")
    if not sees(vault, pass_cli):
        _grant_the_brokers_agent(run, sees, agent, vault, main_vault, pass_cli)
    jsonfile.write(settings_path(), asdict(AccountSettings(vault=vault, enabled=True)))
    return {"vault": vault, "enabled": True}


def _grant_the_brokers_agent(run, sees, agent: str, vault: str, main_vault: str, pass_cli: str) -> None:
    from .ops import OpError

    ids = [i for i, name in AGENT_LINE.findall(run(["agent", "list"], "listing your agents")) if name.strip() == agent]
    if not ids:
        raise OpError(f"you have no agent called {agent}; create the token in step 2 first")
    pat = ["personal-access-token", "access"]
    for pid in reversed(ids):  # newest last in pass-cli's list
        grants = GRANT_LINE.findall(run([*pat, "list-access", "--personal-access-token-id", pid], "reading an agent's access"))
        if not any(v.strip() == main_vault for _, v, _ in grants):
            continue  # not one the broker uses
        run([*pat, "grant", "--personal-access-token-id", pid, "--vault-name", vault, "--role", "editor"], "giving the broker access")
        if sees(vault, pass_cli):
            return
        after = GRANT_LINE.findall(run([*pat, "list-access", "--personal-access-token-id", pid], "reading an agent's access"))
        for share, v, _ in after:
            if v.strip() == vault:
                run([*pat, "revoke", "--personal-access-token-id", pid, "--share-id", share], "taking back a grant that didn't help")
    raise OpError(f"none of your agents called {agent} is the token Pass Broker holds; renew the token in step 2, then try again")


def _title(site: str, bot: str, taken: set[str]) -> str:
    base = f"{site} ({bot})"
    n, title = 1, base
    while title in taken:
        n += 1
        title = f"{base} {n}"
    return title


class AccountsMixin:
    _fresh: dict[tuple[str, str], float]

    def _accounts(self: "Broker") -> AccountSettings:
        return self.account_settings() if self.account_settings else AccountSettings()

    async def create_login(
        self: "Broker", client: str, username: str = "", email_alias: bool = False,
        length: int = 20, symbols: bool = True, reason: str = "",
    ) -> dict[str, Any]:
        from .broker import BrokerError, plain

        settings = self._accounts()
        if not settings.enabled:
            raise BrokerError("making accounts isn't set up on this broker; ask the user to set up Bot Accounts in Pass Broker")
        conn, _, bot = client.partition("/")
        if self.bots is not None and bot and not self.bots.access(bot).get("create_logins"):
            self.audit.record("not_permitted", client=client, kind="create_logins")
            raise BrokerError(f"bot '{bot}' isn't allowed to make accounts; ask the user to allow it in Pass Broker")
        if self.bots is not None and bot and self.bots.created_today(bot) >= PER_BOT_PER_DAY:
            raise BrokerError(f"a bot may make at most {PER_BOT_PER_DAY} accounts a day; try again tomorrow")
        username = (username or "").strip()
        if username and (not USERNAME_RE.fullmatch(username) or self.redactor.contains_secret(username)):
            raise BrokerError("username: up to 64 letters, digits, dot, dash, underscore, plus or @")
        if not (username or email_alias):
            raise BrokerError("give a username, or set email_alias to sign up with a new email alias")
        if not (isinstance(length, int) and 12 <= length <= 64):
            raise BrokerError("password length: 12 to 64")

        s = await self.browser.session(client)
        url = s.page.url
        site = host_of(url)
        origin = "{0.scheme}://{0.netloc}".format(urlsplit(url))
        if not site or not origin_allowed(url, [origin], self.allow_http_localhost, False):
            raise BrokerError("open the site's sign-up page (https) first; the new login is saved for that site")
        if await self.page_refusal(client, url):
            raise BrokerError("this page is blocked for your bot")
        existing = await asyncio.to_thread(self.backend.list_logins)
        title = _title(site, bot or conn, {l.title for l in existing})
        email_note = "a new email alias (hide-my-email), forwarding to you" if email_alias else ""
        details = (
            f"Site: {site}\n"
            f"Saved in your vault '{plain(settings.vault, 40)}' as '{plain(title, 80)}'\n"
            + (f"Username: {plain(username, 64)}\n" if username else "")
            + (f"Email: {email_note}\n" if email_alias else "")
            + f"Password: made by Proton Pass ({length} characters); the bot never sees it.\n"
            + "The bot may then fill in the sign-up form and later sign in with it, with your approval.\n"
        )
        placeholder = Login(f"new:{title}", title, (origin,), None, False)
        await self._approve(client, placeholder, site, "create_login", f"make an account on {site}", details, reason)
        why = f"pass-broker for {client}: new account on {site}"
        try:
            email = await asyncio.to_thread(self.backend.create_alias, settings.vault, _prefix(site), why) if email_alias else ""
            login = await asyncio.to_thread(
                self.backend.create_login, settings.vault, title, origin, username, email,
                PasswordRules(length, symbols), why,
            )
        except VaultError as e:
            raise BrokerError(str(e)) from None
        if self.bots is not None and bot:
            await asyncio.to_thread(self.bots.record_created, bot, title, site)
        self._login_sites = None  # the bot's site list now includes this site
        self._fresh[(client, login.handle)] = time.monotonic() + FRESH_S
        self.audit.record("create_login", client=client, item=title, host=site, alias=email_alias)
        return {"status": "created", "handle": login.handle, "title": title, "site": site,
                "next": "fill in the rest of the form yourself, then call fill_signup with this handle"}

    async def fill_signup(self: "Broker", client: str, handle: str, reason: str = "") -> dict[str, Any]:
        """The username or email if its field is empty, then every password field; then submit."""
        from .broker import BrokerError
        from .fills import MASK_JS, PASSWORD_SELECTORS, _find_in

        login = self._login(client, handle)
        verify = self._verifier(client, login)
        s = await self.browser.session(client)
        s.touch()
        page = s.page
        async with s.lock:
            await s.check_tab()
            try:
                found = await s.find_many(PASSWORD_SELECTORS[0], minimum=1)
                if found is None:
                    raise BrokerError("no password field on this page; open the sign-up form first")
                frame, fields = found
                page = frame.page
                verify(frame)
                host = host_of(frame.url)
                fresh = self._fresh.pop((client, login.handle), 0) > time.monotonic()
                if not fresh:
                    await self._approve(client, login, host, "signup", f"fill in a sign-up form on {host}", reason=reason)
                user_field = await _find_in(frame, USERNAME_SELECTORS)
                if user_field is not None and not await user_field.input_value():
                    username = await self._username_value(client, login, host)
                    if username:
                        await user_field.evaluate(MASK_JS)
                        await s.fill_pinned(frame, user_field, username, verify)
                password = await self._secret(client, login, "password", f"sign up on {host}")
                last = None
                for i in range(min(await fields.count(), 3)):  # password, confirm (and a rare third)
                    last = await s.fill_pinned(frame, fields.nth(i), password, verify)
                del password
                await s.submit(frame, last, verify)  # type: ignore[arg-type]
            finally:
                await s.clear_secrets(page)
            self.audit.record("fill_signup", client=client, item=login.title, host=host_of(page.url))
            return {"status": "submitted", "url": page.url, "title": await page.title()}


def _prefix(site: str) -> str:
    """`www.example.co.uk` -> `example`: the alias says which site it's for."""
    labels = [x for x in site.split(".") if x not in ("www", "m", "app", "accounts", "signup")]
    return re.sub(r"[^a-z0-9]", "", (labels[0] if labels else "site").lower())[:20] or "site"
