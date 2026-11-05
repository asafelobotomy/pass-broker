"""The generated systemd user service (nothing is installed by these tests)."""

import json
from pathlib import Path

import pytest

from passbroker import service


def test_unit_is_sandboxed_and_manages_funnel(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    config, data, state = (tmp_path / n for n in ("config", "data", "state"))
    config.mkdir()
    (config / "unlockers.json").write_text(json.dumps({"actions": [{"output_dir": str(tmp_path / "Unlocked")}]}))
    text = service.render(["--port", "8787", "--public-host", "pc.example.ts.net", "--manage-funnel"], config, data, state, 8787, funnel=True)
    for line in ("NoNewPrivileges=yes", "PrivateTmp=yes", "ProtectSystem=strict", "UMask=0077", "Restart=on-failure", "KillMode=mixed",
                 "RuntimeDirectory=passbroker", "RuntimeDirectoryMode=0700"):
        assert line in text
    assert "funnel --bg --https=443 http://127.0.0.1:8787" in text and "funnel --https=443 off" in text
    rw = next(line for line in text.splitlines() if line.startswith("ReadWritePaths="))
    assert str(tmp_path / "Unlocked") in rw and str(config) in rw and str(tmp_path) + " " not in rw + " "
    assert (tmp_path / "Unlocked").is_dir()


def test_no_funnel_lines_without_funnel(tmp_path):
    text = service.render(["--port", "8787"], tmp_path, tmp_path, tmp_path, 8787, funnel=False)
    assert "tailscale" not in text and "ExecStartPre" not in text


@pytest.mark.parametrize("flag", ["--insecure-auto-approve", "--mock", "--allow-http-localhost"])
def test_test_switches_never_go_into_a_service(tmp_path, flag):
    with pytest.raises(ValueError, match="test-only"):
        service.render(["--port", "8787", flag], tmp_path, tmp_path, tmp_path, 8787, funnel=False)


def test_unit_carries_custom_folders_and_installs_where_systemd_looks(tmp_path, monkeypatch):
    config, data, state = (tmp_path / n for n in ("config", "data", "state"))
    config.mkdir()
    monkeypatch.setenv("XDG_CONFIG_HOME", str(config))
    monkeypatch.setenv("XDG_STATE_HOME", str(state))
    monkeypatch.delenv("XDG_DATA_HOME", raising=False)
    text = service.render(["--port", "8787"], config, data, state, 8787, funnel=False)
    assert f'Environment="XDG_CONFIG_HOME={config}"' in text and f'Environment="XDG_STATE_HOME={state}"' in text
    assert "XDG_DATA_HOME" not in text
    # systemd's user manager reads ~/.config/systemd/user, whatever the wizard's own XDG_CONFIG_HOME is
    monkeypatch.setattr(service.subprocess, "run", lambda *a, **k: type("R", (), {"stdout": "PATH=/usr/bin\n"})())
    assert service.unit_path() == Path.home() / ".config" / "systemd" / "user" / service.UNIT
    monkeypatch.setenv("XDG_STATE_HOME", '/tmp/bad"quote')
    with pytest.raises(ValueError):
        service.render(["--port", "8787"], config, data, state, 8787, funnel=False)


def test_service_from_an_appimage_starts_the_appimage_file(tmp_path, monkeypatch):
    config, data, state = (tmp_path / n for n in ("config", "data", "state"))
    config.mkdir()
    appimage = tmp_path / "Pass_Broker-x86_64.AppImage"
    appimage.write_bytes(b"")
    monkeypatch.setenv("APPIMAGE", str(appimage))
    text = service.render(["--port", "8787"], config, data, state, 8787, funnel=False)
    assert f"ExecStart={appimage} passbroker serve --port 8787" in text
    assert 'Environment="APPIMAGE_EXTRACT_AND_RUN=1"' in text
    monkeypatch.delenv("APPIMAGE")
    assert " -I -m passbroker.cli serve" in service.render(["--port", "8787"], config, data, state, 8787, funnel=False)
