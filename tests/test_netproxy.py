"""HTTP redirects: the browser must never follow one into a private address or off a bot's list."""

import asyncio
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from passbroker.browser import Browser, BrowserError
from passbroker.redact import Redactor


@pytest.fixture
def redirector():
    """`/r` redirects from http://localhost:PORT to http://127.0.0.1:PORT/private."""
    hits: list[tuple[str, str]] = []

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            hits.append((self.headers["Host"].split(":")[0], self.path))
            if self.path == "/r":
                self.send_response(302)
                self.send_header("Location", f"http://127.0.0.1:{port}/private")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            body = b"<title>PRIVATE</title>router admin"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield port, hits
    srv.shutdown()


@pytest.fixture
async def browser(tmp_path):
    b = Browser(tmp_path / "p", Redactor(), headless=True)

    # "localhost" plays a public website, "127.0.0.1" your router.
    async def blocked(host):
        return host == "127.0.0.1"

    b.blocked = blocked
    b.proxy.refuse = lambda host, ip: host == "127.0.0.1"
    await b.start()
    yield b
    await b.stop()


async def test_redirect_into_a_private_address_is_refused(browser, redirector):
    port, hits = redirector
    s = await browser.session("conn/bot")
    with pytest.raises(BrowserError, match="blocked"):
        await s.navigate(f"http://localhost:{port}/r")
    assert ("localhost", "/r") in hits  # the public site was reached and redirected...
    assert ("127.0.0.1", "/private") not in hits  # ...but the request never reached the "router"
    assert "PRIVATE" not in await s.page.title()


async def test_redirect_off_a_bots_list_is_left_before_it_is_read(browser, redirector):
    port, hits = redirector
    browser.proxy.refuse = lambda host, ip: False  # reachable, but not on this bot's list

    async def refusal(key, url, top=True):
        return "127.0.0.1 isn't on this bot's site list" if "127.0.0.1" in url else None

    browser.page_refusal = refusal
    s = await browser.session("conn/bot")
    with pytest.raises(BrowserError, match="site list"):
        await s.navigate(f"http://localhost:{port}/r")
    assert "127.0.0.1" not in s.page.url


async def test_proxy_needs_its_password(browser):
    reader, writer = await asyncio.open_connection("127.0.0.1", browser.proxy.port)
    writer.write(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
    await writer.drain()
    reply = await asyncio.wait_for(reader.readline(), 5)
    writer.close()
    assert b"407" in reply
