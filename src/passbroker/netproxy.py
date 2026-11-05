"""The proxy every connection of the broker's browser goes through.

Playwright's request routing never sees the target of an HTTP redirect, so a page could
answer `302 Location: http://192.168.1.1/` and walk the browser into your router. Here,
at the connection level, nothing is missed: pages, every redirect hop, frames, scripts and
WebSockets all arrive as CONNECT (https, wss) or plain-http requests. The proxy resolves the
host itself, refuses this PC, LANs and tailnets, and connects to the very address it checked,
so DNS can't answer differently in between. A host that doesn't resolve is refused too.

Only the broker's Chromium can use it: it listens on 127.0.0.1 and requires a random password.
"""

from __future__ import annotations

import asyncio
import base64
import hmac
import logging
import secrets
import socket
from collections.abc import Callable
from urllib.parse import urlsplit

log = logging.getLogger(__name__)

MAX_HEAD = 32 * 1024
TIMEOUT = 20
# Marks the proxy's own refusal of a plain-http page, so the session can report it as blocked.
BLOCKED_HEADER = "X-Pass-Broker-Blocked"
HOP_HEADERS = {"proxy-authorization", "proxy-connection", "connection", "keep-alive", "te", "trailer", "upgrade"}


def _split_hostport(target: str, default_port: int) -> tuple[str, int]:
    host, sep, port = target.rpartition(":")
    if not sep or "]" in port:  # no port, or a bare IPv6 address
        return target.strip("[]"), default_port
    return host.strip("[]"), int(port)


async def _pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        while data := await reader.read(65536):
            writer.write(data)
            await writer.drain()
    except (ConnectionError, OSError):
        pass
    finally:
        try:
            writer.write_eof()
        except (OSError, RuntimeError):
            pass


async def _first_connection(ips: list[str], port: int) -> tuple[asyncio.StreamReader, asyncio.StreamWriter] | None:
    """Connect to the first of `ips` that answers, starting each attempt 250 ms after the last."""
    attempts: list[asyncio.Task] = []
    winner: asyncio.Task | None = None
    waiting = list(ips)
    try:
        async with asyncio.timeout(TIMEOUT):
            while waiting or any(not a.done() for a in attempts):
                if waiting:
                    attempts.append(asyncio.create_task(asyncio.open_connection(waiting.pop(0), port)))
                running = [a for a in attempts if not a.done()]
                if running:
                    await asyncio.wait(running, timeout=0.25 if waiting else None, return_when=asyncio.FIRST_COMPLETED)
                winner = next((a for a in attempts if a.done() and not a.cancelled() and a.exception() is None), None)
                if winner is not None:
                    return winner.result()
    except TimeoutError:
        pass
    finally:
        for a in attempts:
            if a is winner:
                continue
            if not a.done():
                a.cancel()
            elif not a.cancelled() and a.exception() is None:
                a.result()[1].close()  # a second address that also connected
    return None


class GuardProxy:
    def __init__(self, refuse: Callable[[str, str], bool]) -> None:
        """`refuse(host, ip)`: True if the browser must not reach `host` at address `ip`."""
        self.refuse = refuse
        self.username = "passbroker"
        self.password = secrets.token_urlsafe(24)
        self._expected = "Basic " + base64.b64encode(f"{self.username}:{self.password}".encode()).decode()
        self._server: asyncio.Server | None = None
        self.port = 0

    async def start(self) -> None:
        self._server = await asyncio.start_server(self._client, "127.0.0.1", 0)
        self.port = self._server.sockets[0].getsockname()[1]

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            self._server = None

    @property
    def settings(self) -> dict[str, str]:
        """What Playwright's `proxy=` takes. An empty bypass list: loopback goes through us too."""
        return {"server": f"http://127.0.0.1:{self.port}", "bypass": "", "username": self.username, "password": self.password}

    async def _open(self, host: str, port: int) -> tuple[asyncio.StreamReader, asyncio.StreamWriter] | None:
        host = host.lower().rstrip(".")
        try:
            infos = await asyncio.get_running_loop().getaddrinfo(host, port, type=socket.SOCK_STREAM)
        except (OSError, UnicodeError):
            return None  # fail closed: the browser can't reach what we can't check
        if not infos or any(self.refuse(host, str(i[4][0])) for i in infos):
            log.info("refused a browser connection to %s", host)
            return None
        # Every address was checked above. Race them as browsers do ("happy eyeballs"): one
        # family is often slow or unreachable, so start each a moment after the last.
        return await _first_connection(list(dict.fromkeys(str(i[4][0]) for i in infos)), port)

    async def _client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            while True:  # more than one request only while authenticating
                try:
                    head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), TIMEOUT)
                except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, TimeoutError, ConnectionError):
                    return
                if len(head) > MAX_HEAD:
                    return
                lines = head.decode("latin-1").split("\r\n")
                try:
                    method, target, version = lines[0].split(" ", 2)
                except ValueError:
                    return
                headers = [(k.strip(), v.strip()) for k, _, v in (line.partition(":") for line in lines[1:] if line)]
                auth = next((v for k, v in headers if k.lower() == "proxy-authorization"), "")
                if not hmac.compare_digest(auth.encode(), self._expected.encode()):
                    writer.write(b'HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm="pass-broker"\r\n'
                                 b"Content-Length: 0\r\n\r\n")
                    await writer.drain()
                    continue
                if method.upper() == "CONNECT":
                    await self._tunnel(target, reader, writer)
                else:
                    await self._forward(method, target, version, headers, reader, writer)
                return
        finally:
            writer.close()

    async def _tunnel(self, target: str, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            host, port = _split_hostport(target, 443)
        except ValueError:
            return
        upstream = await self._open(host, port)
        if upstream is None:
            writer.write(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            await writer.drain()
            return
        up_reader, up_writer = upstream
        writer.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
        await writer.drain()
        try:
            await asyncio.gather(_pipe(reader, up_writer), _pipe(up_reader, writer))
        finally:
            up_writer.close()

    async def _forward(self, method: str, target: str, version: str, headers: list[tuple[str, str]],
                       reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        parts = urlsplit(target)
        if parts.scheme != "http" or not parts.hostname:
            writer.write(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            await writer.drain()
            return
        upstream = await self._open(parts.hostname, parts.port or 80)
        if upstream is None:
            body = b"Blocked by Pass Broker: this PC, your LAN or your tailnet."
            writer.write(b"HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nConnection: close\r\n" + BLOCKED_HEADER.encode() + b": 1\r\n"
                         + f"Content-Length: {len(body)}\r\n\r\n".encode() + body)
            await writer.drain()
            return
        up_reader, up_writer = upstream
        path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
        kept = [f"{k}: {v}" for k, v in headers if k.lower() not in HOP_HEADERS]
        # One request per connection, both ways: the browser's next request may be for another
        # host, which must be checked, so it must come in on a new connection.
        up_writer.write(f"{method} {path} {version}\r\n".encode("latin-1") + "\r\n".join([*kept, "Connection: close"]).encode("latin-1")
                        + b"\r\n\r\n")
        body = asyncio.create_task(_pipe(reader, up_writer))  # the request body, if any
        try:
            head = await asyncio.wait_for(up_reader.readuntil(b"\r\n\r\n"), TIMEOUT * 3)
            status, *rest = head.decode("latin-1").split("\r\n")
            fields = [line for line in rest if line and line.split(":", 1)[0].strip().lower() not in HOP_HEADERS]
            writer.write("\r\n".join([status, *fields, "Connection: close", "", ""]).encode("latin-1"))
            await writer.drain()
            while data := await up_reader.read(65536):
                writer.write(data)
                await writer.drain()
        except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, TimeoutError, ConnectionError, OSError):
            pass
        finally:
            body.cancel()
            up_writer.close()
