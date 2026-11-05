import os
import shutil

import keyring
import pytest
from keyring.backend import KeyringBackend


class MemoryKeyring(KeyringBackend):
    priority = 1

    def __init__(self):
        super().__init__()
        self.store: dict[tuple[str, str], str] = {}

    def get_password(self, service, username):
        return self.store.get((service, username))

    def set_password(self, service, username, password):
        self.store[(service, username)] = password

    def delete_password(self, service, username):
        self.store.pop((service, username), None)


@pytest.fixture
def memkeyring():
    previous = keyring.get_keyring()
    kr = MemoryKeyring()
    keyring.set_keyring(kr)
    yield kr
    keyring.set_keyring(previous)


@pytest.fixture
def xdg(tmp_path, monkeypatch):
    for k in ("XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME"):
        monkeypatch.setenv(k, str(tmp_path / k))
    return tmp_path


def fake_tool(tmp_path, name: str, script: str) -> str:
    bindir = tmp_path / "bin"
    bindir.mkdir(exist_ok=True)
    path = bindir / name
    path.write_text("#!/bin/sh\n" + script)
    path.chmod(0o755)
    return str(path)


def pytest_runtest_setup(item):
    """`@pytest.mark.needs("gpg")`: skip without the tool, except in CI, where it must be there
    (a missing tool there is a broken setup that would otherwise pass unnoticed)."""
    for mark in item.iter_markers("needs"):
        missing = [t for t in mark.args if not shutil.which(t)]
        if missing and os.environ.get("CI"):
            pytest.fail(f"{', '.join(missing)} not installed, and CI should have it")
        if missing:
            pytest.skip(f"{', '.join(missing)} not installed")
