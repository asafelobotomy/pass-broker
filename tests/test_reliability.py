"""Settings files that survive concurrent writers, newer versions and hand edits."""

import json

from passbroker import jsonfile, service
from passbroker.bots import Bots
from passbroker.devices import DeviceStore
from passbroker.keys import KeyStore
from passbroker.mailcode import MailSettings


def test_unknown_keys_are_ignored_not_fatal(tmp_path):
    (tmp_path / "devices.json").write_text(json.dumps({"actions": [{"name": "nas", "kind": "wol", "mac": "aa:bb:cc:dd:ee:ff", "from_a_newer_version": 1}]}))
    (tmp_path / "keys.json").write_text(json.dumps({"keys": [{"name": "ledger", "item": "Ledger", "colour": "blue"}]}))
    (tmp_path / "mail.json").write_text(json.dumps({"item": "Bridge", "theme": "dark"}))
    assert DeviceStore(tmp_path / "devices.json").load()[0].name == "nas"
    assert KeyStore(tmp_path / "keys.json").load()[0].name == "ledger"
    assert MailSettings.load(tmp_path / "mail.json").item == "Bridge"


def test_writes_are_atomic_private_and_leave_nothing_behind(tmp_path):
    path = tmp_path / "clients.json"
    for n in range(20):
        jsonfile.write(path, {"n": n})
        assert json.loads(path.read_text()) == {"n": n}  # never half a file
    assert path.stat().st_mode & 0o077 == 0
    assert sorted(p.name for p in tmp_path.iterdir()) == ["clients.json"]


def test_a_lone_string_grant_is_one_name(tmp_path):
    bots = Bots(tmp_path / "bots.json")
    bots.set_access("mailbot", {"logins": "GitHub", "unlock": ["tax"]})
    access = bots.access("mailbot")
    assert access["logins"] == ["GitHub"] and access["unlock"] == ["tax"]


def test_service_starts_even_if_funnel_cant(tmp_path):
    config, data, state = (tmp_path / n for n in ("config", "data", "state"))
    config.mkdir()
    text = service.render(["--port", "8787"], config, data, state, 8787, funnel=True)
    assert "ExecStartPre=-" in text  # a failing Funnel doesn't stop the broker starting
    assert "network-online.target" not in text
