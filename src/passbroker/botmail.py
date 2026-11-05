"""All the bots' mail in one folder of your Proton Mail.

Every bot's email alias is named `bot-<name>.<random>@...` (accounts.py), so one fixed rule in
Proton Mail can tell bot mail from yours, including bots that join later: it files anything sent
to a `bot-` address into the **Bots** folder. The broker never touches your mail settings itself.
When a bot gets its alias and the rule isn't in place yet, the job goes to a bot that manages your
mail with access of its own (you mark it so in Access): the requesting bot if it does, otherwise
the first such bot, which finds it with mail_tasks and reports with mail_rule_done. With no such
bot, the requesting bot is asked to tell you, and Pass Broker's Bot accounts tab offers the same:
make the folder (through Bridge), copy the rule, open Proton Mail's filters page.
Email codes are read from any folder, so they work either way.
"""

from __future__ import annotations

import imaplib
import ssl
import time
from typing import TYPE_CHECKING, Any

from .mailcode import MailSettings

if TYPE_CHECKING:
    from .broker import Broker

PREFIX = "bot-"
FOLDER = "Bots"
# Matches the alias in To/Cc, and in the header Proton's forwarding adds, which names the alias
# even when the site sent a Bcc.
RULE = f"""require ["fileinto"];

# Pass Broker: mail to your bots' aliases ({PREFIX}...) goes to the {FOLDER} folder.
if anyof (address :localpart :matches ["to", "cc"] "{PREFIX}*",
          header :matches "X-SimpleLogin-Envelope-To" "{PREFIX}*") {{
    fileinto "{FOLDER}";
}}
"""


def _connect(settings: MailSettings) -> imaplib.IMAP4:
    from .tlspin import pinned_context

    if not settings.cert_pem:
        raise ssl.SSLError("Bridge's certificate isn't pinned yet; save the email-code settings first")
    imap = imaplib.IMAP4(settings.host, settings.port, timeout=20)
    imap.starttls(ssl_context=pinned_context(settings.cert_pem))
    return imap


FILTERS_URL = "https://account.proton.me/mail/filters"
HOW = (f"In Proton Mail: make a folder called {FOLDER}, then Settings > Filters > Add sieve filter, "
       "paste the rule and save.")
FOLDER_PATH = f"Folders/{FOLDER}"


class BotMailMixin:
    def _mail_managers(self: "Broker") -> list[str]:
        """Bots you marked as managing your mail (with access of their own), switched on."""
        if self.bots is None:
            return []
        return [b["name"] for b in self.bots.list() if b.get("enabled", True) and b.get("access", {}).get("manages_mail")]

    def _set_rule(self: "Broker", state: str, by: str) -> None:
        from dataclasses import asdict

        from . import jsonfile

        s = self._accounts()
        s.rule, s.rule_by, s.rule_at = state, by, time.strftime("%Y-%m-%d %H:%M")
        if self.accounts_path is not None:
            jsonfile.write(self.accounts_path, asdict(s))

    def mail_rule_guidance(self: "Broker", bot: str) -> dict[str, Any]:
        """What a bot that just got (or asked for) its alias should know about the bot-mail rule."""
        acc = self._accounts()
        if acc.rule == "done":
            return {}
        managers = self._mail_managers()
        task = {"folder": FOLDER, "rule": RULE, "how": HOW}
        if bot in managers:
            self._set_rule("asked", bot)
            return {"mail_rule": {**task, "to_do": "you manage the user's mail: set this up now (once, for every bot), "
                                                   "then call mail_rule_done"}}
        if managers:
            helper = acc.rule_by if acc.rule == "asked" and acc.rule_by in managers else managers[0]
            if acc.rule != "asked" or acc.rule_by != helper:
                self._set_rule("asked", helper)
                self.audit.record("mail_rule_asked", client=bot, item=helper)
            return {"mail_rule": {"note": f"the bot '{helper}' manages the user's mail and has the job of filing all bots' mail "
                                          f"into a {FOLDER} folder; nothing for you to do"}}
        return {"mail_rule": {**task, "tell_your_user": "no bot manages the user's mail, so please tell your user: to keep all "
                                                        "bots' mail in one folder, add this rule in Proton Mail, or use Set up "
                                                        "bot mail in Pass Broker's Bot accounts tab"}}

    async def mail_tasks(self: "Broker", client: str) -> dict[str, Any]:
        """For a bot that manages your mail: what to set up, if anything."""
        from .broker import BrokerError

        bot = client.partition("/")[2]
        if bot not in self._mail_managers():
            raise BrokerError("only a bot the user marked as managing their mail has mail tasks")
        if self._accounts().rule == "done":
            return {"tasks": []}
        return {"tasks": [{"task": "file all bots' mail into one folder", "folder": FOLDER, "rule": RULE, "how": HOW,
                           "then": "call mail_rule_done"}]}

    async def mail_rule_done(self: "Broker", client: str) -> dict[str, Any]:
        from .broker import BrokerError

        bot = client.partition("/")[2]
        if bot not in self._mail_managers():
            raise BrokerError("only a bot the user marked as managing their mail can report this")
        self._set_rule("done", bot)
        self.audit.record("mail_rule_done", client=client)
        return {"status": "noted: all bots' mail now goes to the " + FOLDER + " folder"}



def _ensure_folder(imap: imaplib.IMAP4) -> bool:
    typ, listed = imap.list('""', f'"{FOLDER_PATH}"')
    if typ == "OK" and any(item for item in listed if item):
        return False
    typ, data = imap.create(f'"{FOLDER_PATH}"')
    if typ != "OK":
        raise imaplib.IMAP4.error(b" ".join(d for d in data if isinstance(d, bytes)).decode(errors="replace")[:200])
    return True


def make_folder(settings: MailSettings, user: str, password: str) -> bool:
    """Make Folders/Bots in your mailbox through Bridge. True if it was made, False if it existed."""
    imap = _connect(settings)
    try:
        imap.login(user, password)
        return _ensure_folder(imap)
    finally:
        try:
            imap.logout()
        except Exception:
            pass


def setup(vault: str, mail_path, pass_cli: str = "pass-cli", make=make_folder) -> dict[str, Any]:
    """Read Bridge's login from the vault with the broker's token, then make the folder."""
    from . import accounts
    from .ops import OpError, broker_session_dir, load_token
    from .redact import Redactor
    from .vault import ProtonPassBackend, VaultError

    settings = MailSettings.load(mail_path)
    if not settings.item:
        raise OpError("set up email codes first: the folder is made through Proton Mail Bridge")
    backend = ProtonPassBackend(vault, load_token, Redactor(), pass_cli=pass_cli, session_dir=broker_session_dir("pass-session-check"))
    backend.extra_vault = lambda: (s.vault if (s := accounts.load()).enabled else None)
    try:
        items = [login for login in backend.list_logins() if login.title == settings.item]
        if len(items) != 1:
            raise OpError(f"the vault item '{settings.item}' for Bridge {'is missing' if not items else 'has a duplicate title'}")
        bridge = items[0]
        user = bridge.username or backend.secret(bridge.handle, "username", "pass-broker: make the Bots mail folder")
        password = backend.secret(bridge.handle, "password", "pass-broker: make the Bots mail folder")
    except VaultError as e:
        raise OpError(str(e)) from None
    try:
        made = make(settings, user, password)
    except ssl.SSLError as e:
        raise OpError(f"Bridge's certificate didn't match ({e}); record it again under Email codes") from None
    except (OSError, imaplib.IMAP4.error) as e:
        raise OpError(f"couldn't make the folder through Proton Mail Bridge ({type(e).__name__}); is Bridge running?") from None
    finally:
        del password
    return {"folder": FOLDER, "made": made, "rule": RULE}
