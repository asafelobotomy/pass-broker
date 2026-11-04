"""A live view of each bot's browser tab, shown in the wizard's Control center.

The browser runs without a window by default, so it never takes over your
desktop. While the Control center is open, the wizard touches a `watching`
file in the preview folder, and the broker then writes a frame of every bot's
tab about once a second, plus `sessions.json` describing them.

Frames are masked exactly like the screenshots bots get: secret fields are
blacked out, and no frame at all is written while a secret shows as text.
They live only in $XDG_RUNTIME_DIR (memory, never your disk), only you can
read them, and they are deleted when nobody is watching, when a session
ends and when the broker stops.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import logging
import os
import time
from pathlib import Path
from typing import Any

from .redact import Redactor
from .session import BrowserError

log = logging.getLogger(__name__)

INTERVAL = 1.0
WATCH_TTL = 10.0
QUALITY = 70
INDEX = "sessions.json"
WATCHING = "watching"


def preview_dir() -> Path | None:
    run = os.environ.get("XDG_RUNTIME_DIR")
    return Path(run) / "passbroker" / "preview" if run else None


def frame_name(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()[:16] + ".jpg"


def _write(path: Path, data: bytes) -> None:
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, data)
    finally:
        os.close(fd)
    os.replace(tmp, path)


class Preview:
    def __init__(self, browser: Any, redactor: Redactor, folder: Path | None) -> None:
        self._browser = browser
        self._redactor = redactor
        self._folder = folder
        self._task: asyncio.Task | None = None
        self._last: dict[str, dict[str, Any]] = {}

    async def start(self) -> None:
        if self._folder is None:
            return
        self._folder.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self._folder, 0o700)
        self._clear(keep_watching=True)
        self._task = asyncio.create_task(self._run())

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
        if self._folder is not None:
            self._clear(keep_watching=False)

    def watching(self) -> bool:
        if self._folder is None:
            return False
        try:
            return time.time() - (self._folder / WATCHING).stat().st_mtime < WATCH_TTL
        except FileNotFoundError:
            return False

    def _clear(self, keep_watching: bool) -> None:
        assert self._folder is not None
        self._last.clear()
        for f in self._folder.iterdir():
            if keep_watching and f.name == WATCHING:
                continue
            f.unlink(missing_ok=True)

    async def _run(self) -> None:
        while True:
            await asyncio.sleep(INTERVAL)
            try:
                await self.tick()
            except Exception as e:  # a closing tab or browser must not end the live view
                log.debug("preview: %s", e)

    async def tick(self) -> None:
        assert self._folder is not None
        if not self.watching():
            if self._last or (self._folder / INDEX).exists():
                self._clear(keep_watching=True)
            return
        entries: dict[str, dict[str, Any]] = {}
        for key, s in self._browser.sessions():
            if s.lock.locked():  # a bot is acting: show its last frame rather than slow it down
                if key in self._last:
                    entries[key] = {**self._last[key], "busy": True}
                continue
            async with s.lock:
                try:
                    entries[key] = await self._capture(key, s)
                except Exception as e:  # tab closing, or the session just ended
                    log.debug("preview of %s: %s", key, e)
        for f in self._folder.glob("*.jpg"):
            if f.name not in {e["file"] for e in entries.values() if not e["withheld"]}:
                f.unlink(missing_ok=True)
        self._last = entries
        index = {"updated": time.time(), "sessions": list(entries.values())}
        _write(self._folder / INDEX, json.dumps(index).encode())

    async def _capture(self, key: str, s: Any) -> dict[str, Any]:
        assert self._folder is not None
        name = frame_name(key)
        bot = key.split("/", 1)[-1]
        entry: dict[str, Any] = {"key": key, "bot": bot, "file": name, "url": "", "title": "", "withheld": False, "busy": False}
        page = s.page
        try:
            entry["url"] = self._redactor.scrub(page.url)
            entry["title"] = self._redactor.scrub(await page.title())
            _write(self._folder / name, await s.masked_capture(jpeg_quality=QUALITY))
        except BrowserError:
            entry["withheld"] = True
            (self._folder / name).unlink(missing_ok=True)
        return entry
