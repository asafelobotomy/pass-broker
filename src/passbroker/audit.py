"""Append-only local audit log: scrubbed, rotated and hash-chained.

Every line carries `prev`, the SHA-256 of the line before it (across rotated
files), so an edited, inserted or deleted line breaks the chain and
`passbroker api audit-verify` reports where. A program running as you could
still rewrite the whole chain consistently; the chain catches casual or
partial tampering, not a determined attacker with your login.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from pathlib import Path
from typing import Any

from .redact import Redactor

MAX_BYTES = 5 * 1024 * 1024
KEEP = 3
GENESIS = "0" * 64


def _rotated(path: Path, n: int) -> Path:
    return path.with_name(f"{path.stem}.{n}{path.suffix}")


def _last_hash(path: Path) -> str | None:
    """Hash of the last line of `path`, or None if it has no lines."""
    try:
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            f.seek(max(0, size - 65536))
            lines = f.read().splitlines(keepends=True)
    except FileNotFoundError:
        return None
    return hashlib.sha256(lines[-1]).hexdigest() if lines else None


class AuditLog:
    def __init__(self, path: Path, redactor: Redactor, max_bytes: int = MAX_BYTES, keep: int = KEEP) -> None:
        self._path = path
        self._redactor = redactor
        self._max = max_bytes
        self._keep = keep
        self._lock = threading.Lock()
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._prev = _last_hash(path) or _last_hash(_rotated(path, 1)) or GENESIS

    def _rotate(self) -> None:
        for n in range(self._keep, 0, -1):
            src = self._path if n == 1 else _rotated(self._path, n - 1)
            if src.exists():
                os.replace(src, _rotated(self._path, n))

    def record(self, event: str, **fields: Any) -> None:
        client = fields.get("client")
        if isinstance(client, str) and "/" in client:
            fields["client"], fields["bot"] = client.split("/", 1)
        with self._lock:
            entry = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "event": event, **fields, "prev": self._prev}
            line = (self._redactor.scrub(json.dumps(entry, default=str)) + "\n").encode()
            try:
                if self._path.stat().st_size + len(line) > self._max:
                    self._rotate()
            except FileNotFoundError:
                pass
            fd = os.open(self._path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
            try:
                os.write(fd, line)
            finally:
                os.close(fd)
            self._prev = hashlib.sha256(line).hexdigest()


def verify(path: Path, keep: int = KEEP) -> dict[str, Any]:
    """Check the chain across rotated files, oldest first.

    The very first line can't be checked against anything (older history may
    have been rotated away), so the chain is anchored there.
    """
    files = [_rotated(path, n) for n in range(keep, 0, -1)] + [path]
    prev: str | None = None
    count = 0
    for f in files:
        if not f.exists():
            continue
        with open(f, "rb") as fh:
            for n, line in enumerate(fh.read().splitlines(keepends=True), 1):
                try:
                    claimed = json.loads(line).get("prev")
                except json.JSONDecodeError:
                    return {"ok": False, "entries": count, "broken_at": f"{f.name}:{n}", "why": "not valid JSON"}
                if prev is not None and claimed != prev:
                    return {"ok": False, "entries": count, "broken_at": f"{f.name}:{n}", "why": "doesn't follow the line before it"}
                prev = hashlib.sha256(line).hexdigest()
                count += 1
    return {"ok": True, "entries": count, "head": prev}
