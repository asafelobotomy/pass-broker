"""Registered apps and connections on disk: hashes only, locked across processes.

The wizard edits the same file to revoke a connection, so every change is a
locked read-modify-write and readers notice changes by mtime.
"""

from __future__ import annotations

import contextlib
import fcntl
import json
import os
import threading
import time
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class Store:
    """Registered apps and connections, persisted with hashes only.

    The GUI edits the same file to revoke a connection, so it is re-read
    whenever it changes on disk.
    """

    path: Path
    clients: dict[str, dict[str, Any]] = field(default_factory=dict)
    grants: dict[str, dict[str, Any]] = field(default_factory=dict)
    _mtime: float = 0.0
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def load(self) -> None:
        try:
            mtime = self.path.stat().st_mtime
        except FileNotFoundError:
            return
        if mtime == self._mtime:
            return
        data = json.loads(self.path.read_text() or "{}")
        self.clients = data.get("clients", {})
        self.grants = data.get("grants", {})
        self._mtime = mtime

    @contextlib.contextmanager
    def transaction(self) -> Iterator["Store"]:
        """Lock the file across processes, load the latest copy, then save on success."""
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(self.path.with_suffix(".lock"), os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            self._mtime = 0.0
            self.load()
            yield self
            self.save()
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        tmp = self.path.with_suffix(".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump({"clients": self.clients, "grants": self.grants}, f, indent=2)
        os.replace(tmp, self.path)
        self._mtime = self.path.stat().st_mtime


def list_connections(path: Path) -> list[dict[str, Any]]:
    store = Store(path)
    store.load()
    now = time.time()
    return [
        {
            "id": gid,
            "name": g["name"],
            "app": g.get("app", ""),
            "created": g["created"],
            "last_used": g.get("last_used"),
            "active": g.get("refresh_exp", 0) > now,
        }
        for gid, g in store.grants.items()
    ]


def revoke_connection(path: Path, grant_id: str) -> bool:
    store = Store(path)
    with store.transaction():
        return store.grants.pop(grant_id, None) is not None
