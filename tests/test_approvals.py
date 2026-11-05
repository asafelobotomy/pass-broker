"""Approvals answered in the Pass Broker app (the notification is stubbed out)."""

import json
import threading
import time

import pytest

from passbroker import approvals
from passbroker.approvals import DesktopApprover


@pytest.fixture(autouse=True)
def no_notifications(monkeypatch):
    def popen(*a, **k):
        raise FileNotFoundError("notify-send")

    monkeypatch.setattr(approvals.subprocess, "Popen", popen)


def answer_when_asked(folder, reply):
    def run():
        for _ in range(100):
            reqs = list(folder.glob("*.json"))
            if reqs:
                req = json.loads(reqs[0].read_text())
                assert req["title"] == "bot wants to sign in" and req["expires"] > time.time()
                assert reqs[0].stat().st_mode & 0o077 == 0
                (folder / f"{req['id']}.answer").write_text(reply)
                return
            time.sleep(0.05)

    t = threading.Thread(target=run)
    t.start()
    return t


@pytest.mark.parametrize(("reply", "allowed"), [("allow", True), ("deny", False), ("yes please", False)])
def test_answer_from_the_app(tmp_path, reply, allowed):
    folder = tmp_path / "approvals"
    approver = DesktopApprover(timeout_s=5, folder=folder)
    t = answer_when_asked(folder, reply)
    assert approver.ask("bot wants to sign in", "Site: example.com") is allowed
    t.join()
    assert not list(folder.iterdir())  # request and answer are cleaned up


def test_silence_means_deny_and_stale_requests_are_cleared(tmp_path):
    folder = tmp_path / "approvals"
    folder.mkdir()
    (folder / "old.json").write_text("{}")
    approver = DesktopApprover(timeout_s=1, folder=folder)
    assert not (folder / "old.json").exists()
    assert approver.ask("bot wants to sign in", "Site: example.com") is False
    assert not list(folder.iterdir())
