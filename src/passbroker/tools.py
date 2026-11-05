"""The MCP tools assistants call. Every one names the calling bot.

Bot names are checked against the on/off switches and recorded (off the event
loop); browser tools run in that bot's own session; results and errors are
scrubbed of every secret the broker has seen.
"""

from __future__ import annotations

import asyncio
import contextlib
import time
from typing import Any

from mcp.server.mcpserver import Context, Image, MCPServer
from mcp.server.mcpserver.exceptions import ToolError

from .bots import BotError, Bots
from .broker import Broker, BrokerError
from .oauth import BrokerOAuth
from .origin import host_of
from .pii import mask_obj
from .redact import Redactor
from .session import BrowserError

BOT = "Your own bot name, e.g. mailbot. Required on every call; the user sees it and can switch bots off."
REASON = "A short reason (the task), shown to the user when they approve."
NEW_BOT_NOTICES_PER_HOUR = 10
MAX_BOTS_PER_CONNECTION = 20
CALLS_PER_10_MIN = 300


def for_bot(redactor: Redactor, result: Any, hide_personal: bool) -> Any:
    """What a bot may see of a page-derived result. Secrets are scrubbed before personal details
    are masked: masking could rewrite part of a secret (a password ending in something
    phone-shaped) so that the scrubber no longer recognises it."""
    result = redactor.scrub_obj(result)
    return mask_obj(result) if hide_personal else result


def register_tools(mcp: MCPServer, broker: Broker, redactor: Redactor, oauth: BrokerOAuth, bots: Bots) -> None:
    notices: list[float] = []
    calls: dict[str, list[float]] = {}
    sites: dict[str, str] = {}

    def safe(result: Any) -> Any:
        return redactor.scrub_obj(result)

    @contextlib.contextmanager
    def errors():
        try:
            yield
        except (BrokerError, BrowserError) as e:
            raise ToolError(redactor.scrub(str(e))) from None
        except ToolError:
            raise
        except Exception as e:
            raise ToolError(redactor.scrub(f"{type(e).__name__}: {e}")[:500]) from None

    async def who(ctx: Context, bot: str, action: str, site: str = "") -> str:
        """`connection/bot` for sessions, approvals and the log; refuses switched-off bots."""
        conn = oauth.name_for((ctx.headers or {}).get("authorization"))
        now = time.monotonic()
        recent = calls[conn] = [t for t in calls.get(conn, []) if t > now - 600] + [now]
        if len(recent) > CALLS_PER_10_MIN:
            raise ToolError("too many calls; slow down and try again in a few minutes")
        known = [b["name"] for b in await asyncio.to_thread(bots.list) if conn in b.get("connections", [])]
        try:
            name, new = await asyncio.to_thread(bots.check, conn, bot, action, site)
        except BotError as e:
            broker.audit.record("bot_refused", client=conn, bot=(bot or "")[:32], action=action)
            raise ToolError(str(e)) from None
        if new:
            if len(known) >= MAX_BOTS_PER_CONNECTION:
                await asyncio.to_thread(bots.set_enabled, name, False)
                raise ToolError("this connection has too many bot names; ask the user to forget unused ones")
            broker.audit.record("bot_new", client=conn, bot=name)
            notices[:] = [t for t in notices if t > now - 3600]
            if len(notices) < NEW_BOT_NOTICES_PER_HOUR:
                notices.append(now)
                oauth.notify("Pass Broker: a new bot", f"Bot: {name} (self-reported)\nConnection: {conn}\nIt can't use any logins until you grant them in Pass Broker.")
        return f"{conn}/{name}"

    async def page_site(client: str) -> str:
        return sites.get(client.lower(), "")

    async def browse(ctx: Context, bot: str, action: str, site: str = ""):
        client = await who(ctx, bot, action, site or await page_site(f"{oauth.name_for((ctx.headers or {}).get('authorization'))}/{bot}"))
        return client, await broker.browser.session(client)

    def remember(client: str, result: dict[str, Any]) -> dict[str, Any]:
        """Every page-derived result passes here: note the site, and mask personal details.

        Secrets are scrubbed first: masking could rewrite part of a secret (a password ending in
        something phone-shaped) so that the scrubber no longer finds it whole."""
        sites[client] = host_of(result.get("url", "")) if result.get("url") else sites.get(client.lower(), "")
        return for_bot(redactor, result, broker.hides_personal(client))

    # ---- sign-ins ---------------------------------------------------------------------

    @mcp.tool(description="List the saved logins your bot may use: title, sites, masked username and a handle. Never returns passwords. " + BOT)
    async def list_logins(ctx: Context, bot: str, query: str = "") -> list[dict[str, Any]]:
        with errors():
            return safe(await broker.list_logins(await who(ctx, bot, "list logins"), query))

    @mcp.tool(description="Open an http(s) URL in your bot's own browser session. " + BOT)
    async def open_url(ctx: Context, bot: str, url: str) -> dict[str, Any]:
        with errors():
            client, s = await browse(ctx, bot, "open page", host_of(url))
            async with s.lock:
                return safe(remember(client, await s.navigate(url)))

    @mcp.tool(description="Read the current page: text plus interactive elements with refs. Secret fields show only as sensitive. " + BOT)
    async def snapshot(ctx: Context, bot: str) -> dict[str, Any]:
        with errors():
            client, s = await browse(ctx, bot, "read page")
            async with s.lock:
                return safe(remember(client, await s.snapshot()))

    @mcp.tool(description="Click an element by ref from the latest snapshot. " + BOT)
    async def click(ctx: Context, bot: str, ref: str) -> dict[str, Any]:
        with errors():
            client, s = await browse(ctx, bot, "click")
            async with s.lock:
                return safe(remember(client, await s.click(ref)))

    @mcp.tool(description="Type your own text into a field by ref; optionally press Enter. Refuses password and code fields: use the fill tools. " + BOT)
    async def type_text(ctx: Context, bot: str, ref: str, text: str, submit: bool = False) -> dict[str, Any]:
        with errors():
            client, s = await browse(ctx, bot, "type")
            async with s.lock:
                return safe(remember(client, await s.type_text(ref, text, submit)))

    @mcp.tool(description="Press a key such as Enter, Tab or Escape. " + BOT)
    async def press_key(ctx: Context, bot: str, key: str) -> dict[str, Any]:
        with errors():
            client, s = await browse(ctx, bot, "press key")
            async with s.lock:
                return safe(remember(client, await s.press(key)))

    @mcp.tool(description="Screenshot of your bot's current tab, with secret fields (and, unless allowed, personal details) blacked out. " + BOT)
    async def screenshot(ctx: Context, bot: str) -> Image:
        with errors():
            client, s = await browse(ctx, bot, "screenshot")
            async with s.lock:
                return Image(data=await s.screenshot(hide_personal=broker.hides_personal(client)), format="png")

    @mcp.tool(description="Sign in on the current page with a saved login. The user approves on their desktop; you never see the password. " + BOT + " " + REASON)
    async def fill_login(ctx: Context, bot: str, handle: str, reason: str = "") -> dict[str, Any]:
        with errors():
            client = await who(ctx, bot, "sign in", await page_site(f"{oauth.name_for((ctx.headers or {}).get('authorization'))}/{bot}"))
            return safe(remember(client, await broker.fill_login(client, handle, reason)))

    @mcp.tool(description="Enter the current authenticator (TOTP) code for a saved login on the current page. You never see the code. " + BOT + " " + REASON)
    async def fill_totp(ctx: Context, bot: str, handle: str, reason: str = "") -> dict[str, Any]:
        with errors():
            client = await who(ctx, bot, "2FA code")
            return safe(remember(client, await broker.fill_totp(client, handle, reason)))

    @mcp.tool(description="Enter a sign-in code the site just emailed to the user, read from their mail on their PC. You never see the code or the email. " + BOT + " " + REASON)
    async def fill_email_code(ctx: Context, bot: str, handle: str, reason: str = "") -> dict[str, Any]:
        with errors():
            client = await who(ctx, bot, "email code")
            return safe(remember(client, await broker.fill_email_code(client, handle, reason)))

    @mcp.tool(description="Your bot's own email address: a hide-my-email alias that forwards to the user. The first time, the user "
              "approves making it; after that it is yours for good, every account you make uses it, and fill_email_code reads codes "
              "sent to it. Use it wherever a site or form wants your email. " + BOT + " " + REASON)
    async def email_address(ctx: Context, bot: str, reason: str = "") -> dict[str, Any]:
        with errors():
            client = await who(ctx, bot, "email address")
            return safe(await broker.email_address(client, reason))

    @mcp.tool(description="For a bot that manages the user's mail with its own access (the user marks it so in Pass Broker): "
              "anything to set up in their mail for the other bots, such as one rule filing all bots' mail into a folder. "
              "Do it with your own mail access, then report it done. " + BOT)
    async def mail_tasks(ctx: Context, bot: str) -> dict[str, Any]:
        with errors():
            return safe(await broker.mail_tasks(await who(ctx, bot, "mail tasks")))

    @mcp.tool(description="Report that you set up the bot-mail rule from mail_tasks in the user's mail. " + BOT)
    async def mail_rule_done(ctx: Context, bot: str) -> dict[str, Any]:
        with errors():
            return safe(await broker.mail_rule_done(await who(ctx, bot, "mail rule done")))

    @mcp.tool(description="Make a new account login for the site of the current page (open its sign-up page first). The user approves; "
              "Proton Pass generates the password and saves it in the user's vault. You get a handle, never the password. If the form "
              "asks for a username, give one. Your email address (see email_address) is saved with every account you make; "
              "email_alias=true makes it now if you have none. length 12-64; symbols=false for sites that refuse them. " + BOT + " " + REASON)
    async def create_login(ctx: Context, bot: str, username: str = "", email_alias: bool = False, length: int = 20,
                           symbols: bool = True, reason: str = "") -> dict[str, Any]:
        with errors():
            client = await who(ctx, bot, "make account", await page_site(f"{oauth.name_for((ctx.headers or {}).get('authorization'))}/{bot}"))
            return safe(await broker.create_login(client, username, email_alias, length, symbols, reason))

    @mcp.tool(description="Fill a sign-up form with a login from create_login: every empty username, email and confirm-email field, "
              "and every password and confirm-password field, then submit. Fill the other fields (name, birthday) and tick any boxes "
              "first. If the form asks for the email first and the password on a later page, call it again there. "
              "You never see the password. " + BOT + " " + REASON)
    async def fill_signup(ctx: Context, bot: str, handle: str, reason: str = "") -> dict[str, Any]:
        with errors():
            client = await who(ctx, bot, "sign up", await page_site(f"{oauth.name_for((ctx.headers or {}).get('authorization'))}/{bot}"))
            return safe(remember(client, await broker.fill_signup(client, handle, reason)))

    @mcp.tool(description="Sign your bot's browser out of everything. Call it when your task is done. " + BOT)
    async def end_session(ctx: Context, bot: str) -> dict[str, Any]:
        with errors():
            client = await who(ctx, bot, "end session")
            sites.pop(client, None)
            return await broker.end_session(client)

    # ---- files, keys, devices -----------------------------------------------------------

    @mcp.tool(description="List the file-unlock actions your bot may use (archives, encrypted files, databases). " + BOT)
    async def list_unlockers(ctx: Context, bot: str) -> list[dict[str, Any]]:
        with errors():
            return safe(await broker.list_unlockers(await who(ctx, bot, "list unlockers")))

    @mcp.tool(description="List the files one unlock action may open. " + BOT)
    async def list_locked_files(ctx: Context, bot: str, action: str) -> list[str]:
        with errors():
            return safe(await broker.list_locked_files(await who(ctx, bot, "list files", action), action))

    @mcp.tool(description="Unlock one file with an action's saved passphrase. The user approves; you never see the passphrase. " + BOT + " " + REASON)
    async def unlock_file(ctx: Context, bot: str, action: str, file: str, reason: str = "") -> dict[str, Any]:
        with errors():
            return safe(await broker.unlock_file(await who(ctx, bot, "unlock", action), action, file, reason))

    @mcp.tool(description="List the encryption keys your bot may use. The passphrases stay in the user's vault. " + BOT)
    async def list_keys(ctx: Context, bot: str) -> list[dict[str, str]]:
        with errors():
            return safe(await broker.list_keys(await who(ctx, bot, "list keys")))

    @mcp.tool(description="Encrypt text with a named key; returns armored ciphertext to store instead of the plain text. " + BOT)
    async def encrypt_text(ctx: Context, bot: str, key: str, text: str) -> dict[str, Any]:
        with errors():
            return await broker.encrypt_text(await who(ctx, bot, "encrypt", key), key, text)

    @mcp.tool(description="Decrypt ciphertext from encrypt_text with the same key. The user approves. " + BOT + " " + REASON)
    async def decrypt_text(ctx: Context, bot: str, key: str, ciphertext: str, reason: str = "") -> dict[str, Any]:
        with errors():
            return safe(await broker.decrypt_text(await who(ctx, bot, "decrypt", key), key, ciphertext, reason))

    @mcp.tool(description="List the home-device actions your bot may run (wake a machine, router or server tasks). " + BOT)
    async def list_device_actions(ctx: Context, bot: str) -> list[dict[str, Any]]:
        with errors():
            return safe(await broker.list_device_actions(await who(ctx, bot, "list devices")))

    @mcp.tool(description="Run one home-device action. The user approves; you get done or failed (and output only if allowed). " + BOT + " " + REASON)
    async def run_device_action(ctx: Context, bot: str, action: str, reason: str = "") -> dict[str, Any]:
        with errors():
            return safe(await broker.run_device_action(await who(ctx, bot, "device", action), action, reason))
