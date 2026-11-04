"""File unlocking with real gpg, openssl and 7z."""

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from passbroker.approvals import GrantCache, StaticApprover
from passbroker.audit import AuditLog
from passbroker.broker import Broker, BrokerError
from passbroker.redact import Redactor
from passbroker.unlock import Action, UnlockError, Unlockers, resolve_input, validate
from passbroker.vault import MockBackend

PASS = "Correct-Horse-77"


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    (tmp_path / "Secure").mkdir()
    (tmp_path / "Secure" / "plain.txt").write_text("the secret plans\n")
    return tmp_path


def _make(home, tool, *args):
    subprocess.run(args, input=PASS + "\n", text=True, capture_output=True, check=True, cwd=home / "Secure")


@pytest.fixture
def broker(home):
    r = Redactor()
    vault = home / "vault.json"
    vault.write_text(json.dumps([{"title": "Secure files", "urls": [], "password": PASS}, {"title": "Site", "urls": ["https://x.example"], "password": "other"}]))
    unl = Unlockers(home / "unlockers.json")
    b = Broker(MockBackend(vault, r), None, StaticApprover(True), GrantCache(0), AuditLog(home / "audit.jsonl", r), r, unlockers=unl)
    return b, unl, r


def _action(home, preset, **kw):
    return Action(name=preset, preset=preset, item="Secure files", folders=[str(home / "Secure")], output_dir=str(home / "Unlocked"), **kw)


@pytest.mark.skipif(not shutil.which("gpg"), reason="gpg not installed")
async def test_gpg_decrypt_stays_on_pc_by_default(home, broker):
    b, unl, _ = broker
    _make(home, "gpg", "gpg", "--batch", "--pinentry-mode", "loopback", "--passphrase-fd", "0", "--symmetric", "-o", "plans.txt.gpg", "plain.txt")
    unl.add(_action(home, "gpg-decrypt"))
    assert await b.list_locked_files("conn1/mailbot", "gpg-decrypt") == ["plans.txt.gpg"]
    res = await b.unlock_file("conn1/mailbot", "gpg-decrypt", "plans.txt.gpg")
    assert res["ok"] and "content" not in res
    assert Path(res["result_path"]).read_text() == "the secret plans\n" and oct(os.stat(res["result_path"]).st_mode & 0o777) == "0o600"
    title, body = b.approver.asked[0]
    assert title == "mailbot (via conn1) wants to unlock plans.txt.gpg" and "stays on this PC" in body
    assert PASS not in json.dumps(res) and PASS not in (home / "audit.jsonl").read_text()


@pytest.mark.skipif(not shutil.which("openssl"), reason="openssl not installed")
async def test_openssl_returns_content_when_allowed_and_cleans_up_failures(home, broker):
    b, unl, _ = broker
    _make(home, "openssl", "openssl", "enc", "-aes-256-cbc", "-pbkdf2", "-salt", "-in", "plain.txt", "-out", "notes.enc", "-pass", "stdin")
    unl.add(_action(home, "openssl-decrypt", return_output=True))
    res = await b.unlock_file("conn1/mailbot", "openssl-decrypt", "notes.enc")
    assert res["content"] == "the secret plans\n" and "WILL be shown" in b.approver.asked[0][1]
    (home / "Secure" / "junk.enc").write_bytes(b"not really encrypted at all......")
    bad = await b.unlock_file("conn1/mailbot", "openssl-decrypt", "junk.enc")
    assert not bad["ok"] and "result_path" not in bad and not (home / "Unlocked" / "junk").exists()


@pytest.mark.skipif(not shutil.which("7z"), reason="7z not installed")
async def test_7z_extract_and_list(home, broker):
    b, unl, _ = broker
    subprocess.run(["7z", "a", f"-p{PASS}", "-mhe=on", "box.7z", "plain.txt"], cwd=home / "Secure", capture_output=True, check=True)
    unl.add(_action(home, "7z-extract"))
    unl.add(_action(home, "7z-list"))
    res = await b.unlock_file("conn1/mailbot", "7z-extract", "box.7z")
    assert res["ok"] and res["files"] == ["plain.txt"]
    listing = await b.unlock_file("conn1/mailbot", "7z-list", "box.7z")
    assert "plain.txt" in listing["content"] and PASS not in json.dumps(listing)


def test_files_outside_the_folder_are_refused(home):
    a = _action(home, "gpg-decrypt")
    (home / "elsewhere.gpg").write_text("x")
    os.symlink(home / "elsewhere.gpg", home / "Secure" / "link.gpg")
    for bad in ["../elsewhere.gpg", str(home / "elsewhere.gpg"), "link.gpg", "plain.txt", "missing.gpg"]:
        with pytest.raises(UnlockError):
            resolve_input(a, bad)


def test_actions_are_validated(home):
    ok = _action(home, "gpg-decrypt")
    validate(ok)
    for bad in [
        Action(name="Bad Name", preset="gpg-decrypt", item="x", folders=[str(home / "Secure")], output_dir=str(home / "o")),
        Action(name="a", preset="rm-rf", item="x", folders=[str(home / "Secure")], output_dir=str(home / "o")),
        Action(name="a", preset="gpg-decrypt", item="x", folders=[str(home)], output_dir=str(home / "o")),
        Action(name="a", preset="gpg-decrypt", item="x", folders=["/etc"], output_dir=str(home / "o")),
        Action(name="a", preset="gpg-decrypt", item="x", folders=[str(home / "Secure")], output_dir="/tmp"),
    ]:
        with pytest.raises(UnlockError):
            validate(bad)


async def test_denied_unlock_reads_no_secret(home, broker):
    b, unl, _ = broker
    b.approver = StaticApprover(False)
    (home / "Secure" / "x.gpg").write_text("x")
    unl.add(_action(home, "gpg-decrypt"))
    with pytest.raises(BrokerError, match="denied"):
        await b.unlock_file("conn1/mailbot", "gpg-decrypt", "x.gpg")
    with pytest.raises(BrokerError, match="no unlock action"):
        await b.unlock_file("conn1/mailbot", "nope", "x.gpg")


@pytest.mark.skipif(not shutil.which("7z"), reason="7z not installed")
async def test_archive_with_a_link_is_refused(home, broker):
    b, unl, _ = broker
    (home / "target.txt").write_text("outside")
    work = home / "build"
    work.mkdir()
    os.symlink(home / "target.txt", work / "evil-link")
    subprocess.run(["7z", "a", f"-p{PASS}", "-snl", str(home / "Secure" / "links.7z"), "evil-link"], cwd=work, capture_output=True, check=True)
    unl.add(_action(home, "7z-extract"))
    with pytest.raises(BrokerError, match="links"):
        await b.unlock_file("conn1/mailbot", "7z-extract", "links.7z")
    assert not any((home / "Unlocked").rglob("evil-link"))


@pytest.mark.skipif(not shutil.which("openssl"), reason="openssl not installed")
async def test_planted_link_in_output_folder_is_not_followed(home, broker):
    b, unl, _ = broker
    _make(home, "openssl", "openssl", "enc", "-aes-256-cbc", "-pbkdf2", "-salt", "-in", "plain.txt", "-out", "job.enc", "-pass", "stdin")
    (home / "Unlocked").mkdir()
    victim = home / "victim.desktop"
    os.symlink(victim, home / "Unlocked" / "job")
    unl.add(_action(home, "openssl-decrypt"))
    res = await b.unlock_file("conn1/mailbot", "openssl-decrypt", "job.enc")
    assert res["ok"] and not victim.exists() and Path(res["result_path"]).read_text() == "the secret plans\n"


def test_output_folder_rules(home):
    for out in [str(home / "Secure"), str(home / "Secure" / "out"), str(home / ".config" / "x"), str(home / ".ssh")]:
        with pytest.raises(UnlockError):
            validate(Action(name="a", preset="gpg-decrypt", item="x", folders=[str(home / "Secure")], output_dir=out))
    with pytest.raises(UnlockError, match="true or false"):
        validate(Action(name="a", preset="gpg-decrypt", item="x", folders=[str(home / "Secure")], output_dir=str(home / "o"), return_output="false"))
