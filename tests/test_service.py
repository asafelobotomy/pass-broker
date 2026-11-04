"""The generated systemd user service (nothing is installed by these tests)."""

import json

import pytest

from passbroker import service


def test_unit_is_sandboxed_and_manages_funnel(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    config, data, state = (tmp_path / n for n in ("config", "data", "state"))
    config.mkdir()
    (config / "unlockers.json").write_text(json.dumps({"actions": [{"output_dir": str(tmp_path / "Unlocked")}]}))
    text = service.render(["--port", "8787", "--public-host", "pc.example.ts.net", "--manage-funnel"], config, data, state, 8787, funnel=True)
    for line in ("NoNewPrivileges=yes", "PrivateTmp=yes", "ProtectSystem=strict", "UMask=0077", "Restart=on-failure",
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
