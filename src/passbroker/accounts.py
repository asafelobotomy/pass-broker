"""Bot-made accounts: a bot signs up on a site with a login the broker creates, never seeing it.

The bot opens a site's sign-up page and calls create_login. You approve on your desktop; Proton
Pass then generates the password and saves a new login, bound to that site, in a vault of its
own (**Bot Accounts** by default). The bot gets only a handle; signup.py fills the form. The new
login is granted to the bot that made it, so it can sign in with it later, still with your approval.

Each bot has one email address: the first hide-my-email alias it gets (with your approval) is
kept as its own, saved with every account it makes, and never replaced by another.

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
    # The Proton Mail rule that files bot mail into Bots (botmail.py): '', 'asked' (a mail bot
    # was given the job), or 'done'; who it went to or who did it, and when.
    rule: str = ""
    rule_by: str = ""
    rule_at: str = ""


def settings_path() -> Path:
    from .ops import dirs

    return dirs()[0] / "accounts.json"


def load(path: Path | None = None) -> AccountSettings:
    try:
        return jsonfile.build(AccountSettings, jsonfile.read(path or settings_path(), {}) or {})
    except (ValueError, TypeError):
        return AccountSettings()


def change(fields: dict[str, Any], path: Path | None = None) -> AccountSettings:
    """Set some fields under the file's lock, keeping whatever else the broker or wizard wrote."""
    def apply(data: Any) -> dict[str, Any]:
        try:
            current = jsonfile.build(AccountSettings, data if isinstance(data, dict) else {})
        except (ValueError, TypeError):
            current = AccountSettings()
        return {**asdict(current), **fields}

    return jsonfile.build(AccountSettings, jsonfile.update(path or settings_path(), apply, {}))


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
    change({"vault": vault, "enabled": True})
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
    _alias_lock: asyncio.Lock

    def _accounts(self: "Broker") -> AccountSettings:
        return self.account_settings() if self.account_settings else AccountSettings()

    def _may_make(self: "Broker", client: str, what: str = "make accounts") -> tuple[AccountSettings, str, str]:
        from .broker import BrokerError

        settings = self._accounts()
        if not settings.enabled:
            raise BrokerError("making accounts isn't set up on this broker; ask the user to set up Bot Accounts in Pass Broker")
        conn, _, bot = client.partition("/")
        if self.bots is not None and bot and not self.bots.access(bot).get("create_logins"):
            self.audit.record("not_permitted", client=client, kind="create_logins")
            raise BrokerError(f"bot '{bot}' isn't allowed to {what}; ask the user to allow it in Pass Broker")
        return settings, conn, bot

    def _bot_email(self: "Broker", bot: str) -> str:
        return self.bots.email(bot) if self.bots is not None and bot else ""

    async def _new_alias(self: "Broker", client: str, settings: AccountSettings, bot: str) -> str:
        """Make the bot's alias and keep it as the bot's address (once: callers hold _alias_lock)."""
        from .broker import BrokerError

        try:
            email = await asyncio.to_thread(self.backend.create_alias, settings.vault, _prefix(bot or "bot"),
                                            f"pass-broker for {client}: the bot's own email alias")
        except VaultError as e:
            raise BrokerError(str(e)) from None
        if self.bots is not None and bot:
            await asyncio.to_thread(self.bots.set_email, bot, email)
        self.audit.record("email_alias", client=client)
        return email

    async def email_address(self: "Broker", client: str, reason: str = "") -> dict[str, Any]:
        """The bot's own email alias, made (with the user's approval) the first time it's asked for."""
        from .broker import plain

        settings, conn, bot = self._may_make(client, "have an email address")
        async with self._alias_lock:
            email = self._bot_email(bot)
            if not email:
                details = (f"A new hide-my-email alias, saved in your vault '{plain(settings.vault, 40)}'. Mail to it "
                           "forwards to you; you can turn it off in Proton Pass at any time.\n"
                           "It becomes this bot's address: every account it makes uses it, and it may give it out.\n")
                placeholder = Login(f"new:alias:{client}", f"email alias for {bot or conn}", (), None, False)
                await self._approve(client, placeholder, "email", "email_alias", "get its own email address", details, reason)
                email = await self._new_alias(client, settings, bot)
        return {"email": email, "note": "your own address: every account you make uses it, and codes sent to it can be "
                                        "entered with fill_email_code", **self.mail_rule_guidance(bot or conn)}

    async def create_login(
        self: "Broker", client: str, username: str = "", email_alias: bool = False,
        length: int = 20, symbols: bool = True, reason: str = "",
    ) -> dict[str, Any]:
        from .broker import BrokerError, plain

        settings, conn, bot = self._may_make(client)
        if self.bots is not None and bot and self.bots.created_today(bot) >= PER_BOT_PER_DAY:
            raise BrokerError(f"a bot may make at most {PER_BOT_PER_DAY} accounts a day; try again tomorrow")
        username = (username or "").strip()
        if username and (not USERNAME_RE.fullmatch(username) or self.redactor.contains_secret(username)):
            raise BrokerError("username: up to 64 letters, digits, dot, dash, underscore, plus or @")
        if not (isinstance(length, int) and 12 <= length <= 64):
            raise BrokerError("password length: 12 to 64")
        email = self._bot_email(bot)  # once a bot has its address, every account it makes uses it
        if not (username or email or email_alias):
            raise BrokerError("give a username, or set email_alias to sign up with your own email alias")

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
        make_alias = email_alias and not email
        email_line = (f"Email: the bot's own alias {plain(email, 80)}\n" if email else
                      "Email: a new email alias (hide-my-email), forwarding to you; it becomes this bot's address for "
                      "every account it makes\n" if make_alias else "")
        details = (
            f"Site: {site}\n"
            f"Saved in your vault '{plain(settings.vault, 40)}' as '{plain(title, 80)}'\n"
            + (f"Username: {plain(username, 64)}\n" if username else "")
            + email_line
            + f"Password: made by Proton Pass ({length} characters); the bot never sees it.\n"
            + "The bot may then fill in the sign-up form and later sign in with it, with your approval.\n"
        )
        placeholder = Login(f"new:{title}", title, (origin,), None, False)
        await self._approve(client, placeholder, site, "create_login", f"make an account on {site}", details, reason)
        if make_alias:
            async with self._alias_lock:
                email = self._bot_email(bot) or await self._new_alias(client, settings, bot)
        try:
            login = await asyncio.to_thread(
                self.backend.create_login, settings.vault, title, origin, username, email,
                PasswordRules(length, symbols), f"pass-broker for {client}: new account on {site}",
            )
        except VaultError as e:
            raise BrokerError(str(e)) from None
        if self.bots is not None and bot:
            await asyncio.to_thread(self.bots.record_created, bot, title, site, username, email)
        self._login_sites = None  # the bot's site list now includes this site
        self._fresh[(client, login.handle)] = time.monotonic() + FRESH_S
        self.audit.record("create_login", client=client, item=title, host=site, alias=bool(email))
        return {"status": "created", "handle": login.handle, "title": title, "site": site,
                **({"username": username} if username else {}), **({"email": email} if email else {}),
                **(self.mail_rule_guidance(bot or conn) if make_alias else {}),
                "next": "fill in the other fields yourself (not the username, email or passwords), then call fill_signup with this handle"}


def _prefix(name: str) -> str:
    """`mail-bot` -> `bot-mailbot`: the alias says which bot it's for, and the `bot-` start lets one
    Proton Mail rule file every bot's mail together (botmail.py)."""
    from .botmail import PREFIX

    return PREFIX + (re.sub(r"[^a-z0-9]", "", name.lower())[:20] or "bot")
