"""Who sets up the rule that files every bot's mail into one folder: a bot that manages your mail,
another bot that does, or (with none) you, told by the bot that asked."""

import json

import pytest

from passbroker import accounts, botmail
from passbroker.accounts import AccountSettings
from passbroker.approvals import GrantCache, StaticApprover
from passbroker.audit import AuditLog
from passbroker.bots import Bots
from passbroker.broker import Broker, BrokerError
from passbroker.redact import Redactor
from passbroker.vault import MockBackend


@pytest.fixture
def make(tmp_path):
    def _make(*managers: str):
        vault = tmp_path / "vault.json"
        vault.write_text("[]")
        r = Redactor()
        bots = Bots(tmp_path / "bots.json")
        for name in ("shopper", "mailbot", "planner"):
            bots.check("conn", name, "test")
            bots.set_access(name, {"create_logins": True, "manages_mail": name in managers})
        settings = AccountSettings(vault="Bot Accounts", enabled=True)
        broker = Broker(MockBackend(vault, r), None, StaticApprover(True), GrantCache(600), AuditLog(tmp_path / "audit.jsonl", r), r,
                        bots=bots, account_settings=lambda: settings)
        broker.accounts_path = tmp_path / "accounts.json"
        return broker, settings, bots

    return _make


async def test_with_no_mail_bot_the_asking_bot_tells_its_user(make):
    broker, settings, _ = make()
    got = await broker.email_address("conn/shopper")
    rule = got["mail_rule"]
    assert "tell_your_user" in rule and rule["rule"] == botmail.RULE and rule["folder"] == "Bots"
    assert settings.rule == ""  # nobody has the job; the wizard offers it to you


async def test_a_bot_that_manages_mail_does_it_itself(make):
    broker, settings, _ = make("mailbot")
    got = await broker.email_address("conn/mailbot")
    assert "to_do" in got["mail_rule"] and (settings.rule, settings.rule_by) == ("asked", "mailbot")
    [task] = (await broker.mail_tasks("conn/mailbot"))["tasks"]
    assert task["rule"] == botmail.RULE
    await broker.mail_rule_done("conn/mailbot")
    assert (settings.rule, settings.rule_by) == ("done", "mailbot")
    assert (await broker.mail_tasks("conn/mailbot"))["tasks"] == []
    assert "mail_rule" not in await broker.email_address("conn/mailbot")  # done: nobody hears of it again


async def test_the_job_goes_to_the_bot_that_manages_mail(make, tmp_path):
    broker, settings, _ = make("mailbot")
    got = await broker.email_address("conn/shopper")
    assert "mailbot" in got["mail_rule"]["note"] and "rule" not in got["mail_rule"]  # the shopper has nothing to do
    assert (settings.rule, settings.rule_by) == ("asked", "mailbot")
    assert json.loads((tmp_path / "accounts.json").read_text())["rule_by"] == "mailbot"  # saved
    await broker.email_address("conn/planner")  # asked once, not again for every bot
    events = [json.loads(line)["event"] for line in (tmp_path / "audit.jsonl").read_text().splitlines()]
    assert events.count("mail_rule_asked") == 1
    assert (await broker.mail_tasks("conn/mailbot"))["tasks"]


async def test_only_mail_bots_get_mail_tasks(make):
    broker, settings, bots = make("mailbot")
    for call in (broker.mail_tasks, broker.mail_rule_done):
        with pytest.raises(BrokerError, match="managing their mail"):
            await call("conn/shopper")
    bots.set_enabled("mailbot", False)  # switched off: no longer counted
    assert "tell_your_user" in (await broker.email_address("conn/shopper"))["mail_rule"]
    assert settings.rule != "done"


def test_you_can_mark_it_done_or_ask_again(tmp_path, monkeypatch, capsys):
    from passbroker import cli

    monkeypatch.setattr(accounts, "settings_path", lambda: tmp_path / "accounts.json")
    cli.main(["api", "accounts-rule", "done"])
    assert json.loads(capsys.readouterr().out)["rule_by"] == "you" and accounts.load(tmp_path / "accounts.json").rule == "done"
    cli.main(["api", "accounts-rule", "reset"])
    capsys.readouterr()
    assert accounts.load(tmp_path / "accounts.json").rule == ""
