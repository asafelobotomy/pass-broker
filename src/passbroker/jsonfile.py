"""Small, safe settings files: written atomically and privately, read tolerantly.

The running broker re-reads clients.json, unlockers.json, keys.json and devices.json while the
wizard writes them. Writing in place would let it read half a file; a fixed `.tmp` name would let
two writers trample each other. So each write goes to its own temporary file beside the target,
readable only by you, and is renamed over it in one step. Reading ignores keys this version
doesn't know (a newer version wrote them, or a hand edit), rather than refusing to start.
Files both sides change (the mail admin's, the bot-accounts settings) go through update(), which
holds a lock for the whole read-change-write.
"""

from __future__ import annotations

import contextlib
import dataclasses
import fcntl
import json
import logging
import os
import tempfile
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any, TypeVar

log = logging.getLogger(__name__)
T = TypeVar("T")


def write(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")  # 0600
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(data, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


@contextlib.contextmanager
def _locked(path: Path) -> Iterator[None]:
    """Hold `path`'s lock file: one read-change-write at a time, across processes."""
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(path.with_name(f".{path.name}.lock"), os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def update(path: Path, change: Callable[[Any], Any], default: Any = None) -> Any:
    """Read, change and write `path` under its lock, so the broker and the wizard writing the same
    file at once can't undo each other. `change` gets the current data and returns the new data."""
    with _locked(path):
        try:
            data = read(path, default)
        except ValueError:
            data = default
        new = change(data)
        write(path, new)
        return new


def read(path: Path, default: Any = None) -> Any:
    try:
        text = path.read_text()
    except FileNotFoundError:
        return default
    return json.loads(text) if text.strip() else default


def build(cls: type[T], data: dict[str, Any]) -> T:
    """`cls(**data)` without the keys `cls` doesn't have."""
    names = {f.name for f in dataclasses.fields(cls)}  # type: ignore[arg-type]
    extra = sorted(set(data) - names)
    if extra:
        log.info("ignoring unknown %s settings: %s", cls.__name__, ", ".join(extra))
    return cls(**{k: v for k, v in data.items() if k in names})
