"""The Control center's live view of the hidden browser."""

import json
import os

from passbroker.preview import INDEX, WATCHING, Preview, frame_name

from .site import PASSWORD, TOTP
from .test_broker import make, site  # noqa: F401  (fixtures)


def index(folder):
    return json.loads((folder / INDEX).read_text())


async def test_frames_only_while_watched(make, site, tmp_path):  # noqa: F811
    broker, _, _ = await make()
    folder = tmp_path / "preview"
    p = Preview(broker.browser, broker.redactor, folder)
    await p.start()
    s = await broker.browser.session("conn/grok")
    await s.navigate(site.url("/login"))
    used = s.last_use

    await p.tick()
    assert not (folder / INDEX).exists() and not list(folder.glob("*.jpg"))

    (folder / WATCHING).touch()
    await p.tick()
    entry = index(folder)["sessions"][0]
    assert entry["bot"] == "grok" and entry["url"].endswith("/login") and not entry["withheld"]
    assert (folder / frame_name("conn/grok")).read_bytes().startswith(b"\xff\xd8")  # JPEG
    assert s.last_use == used  # watching doesn't keep an idle session signed in
    assert (folder / frame_name("conn/grok")).stat().st_mode & 0o077 == 0

    await broker.browser.end_session("conn/grok")
    await p.tick()
    assert index(folder)["sessions"] == [] and not list(folder.glob("*.jpg"))

    await p.stop()
    assert not list(folder.iterdir())


async def test_no_frame_while_a_secret_shows(make, site, tmp_path):  # noqa: F811
    broker, logins, _ = await make()
    folder = tmp_path / "preview"
    p = Preview(broker.browser, broker.redactor, folder)
    await p.start()
    (folder / WATCHING).touch()
    s = await broker.browser.session("conn/grok")
    await s.navigate(site.url("/leaky"))
    await broker.fill_login("conn/grok", logins["Test Site"])
    await p.tick()
    assert index(folder)["sessions"][0]["withheld"]
    assert not list(folder.glob("*.jpg"))
    text = (folder / INDEX).read_text()
    assert PASSWORD not in text and TOTP not in text
    await p.stop()


def test_sigterm_runs_cleanup(tmp_path):
    """systemd and the wizard stop the broker with SIGTERM; the live-view folder must be emptied."""
    import signal
    import socket
    import subprocess
    import sys
    import time

    run = tmp_path / "run"
    run.mkdir(mode=0o700)
    (tmp_path / "vault.json").write_text("[]")
    env = {**os.environ, "XDG_RUNTIME_DIR": str(run), "XDG_CONFIG_HOME": str(tmp_path / "c"), "XDG_DATA_HOME": str(tmp_path / "d"),
           "XDG_STATE_HOME": str(tmp_path / "s"), "PASSBROKER_TEST_MODE": "1"}

    def start() -> tuple[subprocess.Popen, bool]:
        # A free port can be taken by something else before the broker binds it: then it exits,
        # and we try another. Waits until it listens or exits, not a fixed time.
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        proc = subprocess.Popen(
            [sys.executable, "-m", "passbroker.cli", "serve", "--mock", str(tmp_path / "vault.json"), "--headless", "--port", str(port),
             "--allow-http-localhost", "--insecure-auto-approve"],
            env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline and proc.poll() is None:
            with socket.socket() as sock:
                if sock.connect_ex(("127.0.0.1", port)) == 0:
                    return proc, True
            time.sleep(0.2)
        proc.kill()
        return proc, False

    for _ in range(3):
        proc, listening = start()
        if listening:
            break
    assert listening, "the broker never started listening"
    folder = run / "passbroker" / "preview"
    try:
        (folder / WATCHING).touch()
        (folder / "left-over.jpg").write_bytes(b"x")
        proc.send_signal(signal.SIGTERM)
        assert proc.wait(timeout=20) == 0
    finally:
        proc.kill()
    assert not list(folder.iterdir())
