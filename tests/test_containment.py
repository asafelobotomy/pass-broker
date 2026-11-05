"""The browser can't be used to reach this PC: not its settings, files, other programs or keys."""

import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from passbroker import confine
from passbroker.browser import Browser, BrowserError
from passbroker.redact import Redactor
from passbroker.session import _not_a_web_page, key_allowed

PAGE = b"""<!doctype html><title>start</title>
<a id=chrome href="chrome://settings">settings</a> <a id=flags href="chrome://flags">flags</a>
<a id=file href="file:///etc/hostname">file</a> <a id=ext href="steam://run/1">app</a>
<a id=vs href="view-source:https://example.com/">source</a>
<input id=up type=file> <button id=al onclick="document.title = String(confirm('ok?'))">confirm</button>"""


@pytest.fixture
def page_url():
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(PAGE)))
            self.end_headers()
            self.wfile.write(PAGE)

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}/"
    srv.shutdown()


@pytest.fixture
async def session(tmp_path):
    b = Browser(tmp_path / "p", Redactor(), headless=True, allow_private=True)
    await b.start()
    yield await b.session("conn/bot"), b
    await b.stop()


@pytest.mark.parametrize("key", ["Enter", "Tab", "a", "Shift+A", "ArrowDown", "Backspace", "+", "7"])
def test_plain_keys_are_allowed(key):
    assert key_allowed(key)


@pytest.mark.parametrize("key", ["Control+V", "Control+Shift+I", "Alt+F4", "Meta+L", "F12", "Control+L", "Shift+Control+T"])
def test_shortcuts_are_refused(key):
    assert not key_allowed(key)


@pytest.mark.parametrize("url", ["chrome://settings", "file:///etc/passwd", "view-source:https://x.org/", "devtools://x", "steam://run/1"])
def test_only_web_pages(url):
    assert _not_a_web_page(url)
    assert not _not_a_web_page("https://example.com/") and not _not_a_web_page("about:blank")


async def test_pages_cant_leave_the_web_or_reach_this_pc(session, page_url):
    s, browser = session
    assert browser.isolation in ("confined", "sandboxed")  # never "none" unless explicitly allowed
    for link in ("#chrome", "#flags", "#file", "#ext", "#vs"):
        await s.navigate(page_url)
        await s.page.click(link, timeout=5000)
        await s.page.wait_for_timeout(300)
        await s.check_tab()
        assert s.page.url.startswith("http://127.0.0.1"), link
    await s.navigate(page_url)
    await s.page.evaluate("location.href = 'chrome://settings'")
    await s.page.wait_for_timeout(300)
    assert s.page.url.startswith("http://127.0.0.1")
    with pytest.raises(BrowserError):
        await s.navigate("file:///etc/passwd")


async def test_pickers_and_dialogs_dont_reach_the_desktop(session, page_url):
    s, _ = session
    await s.navigate(page_url)
    await s.page.click("#up", timeout=5000)  # a file picker: swallowed, nothing opens
    await s.page.click("#al", timeout=5000)  # a confirm(): dismissed at once
    await s.page.wait_for_timeout(300)
    assert await s.page.title() == "false"
    with pytest.raises(BrowserError, match="shortcuts"):
        await s.press("Control+V")  # would paste your clipboard into the page


@pytest.mark.skipif(not confine.available(), reason="bubblewrap not installed")
def test_the_box_hides_your_files_and_session(tmp_path, monkeypatch):
    """A stand-in "chrome" reports what it can see from inside the box."""
    install = tmp_path / "chromium" / "chrome-linux64"
    install.mkdir(parents=True)
    secret = tmp_path / "secret.txt"  # stands in for anything of yours outside the box
    secret.write_text("private")
    profile = tmp_path / "profile"
    profile.mkdir()
    fake = install / "chrome"
    fake.write_text(f"""#!/bin/sh
echo "home: $(ls -A "$HOME" | tr '\\n' ' ')"
echo "secret: $(cat {secret} 2>/dev/null || echo unreadable)"
echo "usr: $(test -r /usr/bin/env && echo readable)"
echo "profile: $(touch "$1/written" 2>/dev/null && echo writable || echo read-only)"
echo "etc: $(touch /etc/x 2>/dev/null && echo writable || echo read-only)"
echo "bus: ${{DBUS_SESSION_BUS_ADDRESS:-none}} display: ${{WAYLAND_DISPLAY:-none}}"
""")
    fake.chmod(0o755)
    monkeypatch.setenv("DBUS_SESSION_BUS_ADDRESS", "unix:path=/run/user/1000/bus")
    launcher = confine.wrapper(str(fake), tmp_path / "launcher")
    profile_arg = f"--user-data-dir={profile}"
    out = subprocess.run([str(launcher), str(profile), profile_arg], capture_output=True, text=True, timeout=30).stdout
    assert "secret: unreadable" in out
    assert out.splitlines()[0].strip() == "home:"  # an empty home: no ~/.ssh, keyring or Pass Broker settings
    assert "usr: readable" in out and "profile: writable" in out and "etc: read-only" in out
    assert "bus: none display: none" in out
