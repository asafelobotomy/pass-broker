"""Append-only local audit log. Every line is scrubbed before it is written."""

from __future__ import annotations

import json
import os
import threading
import time
from pathlib import Path
from typing import Any

from .redact import Redactor


class AuditLog:
    def __init__(self, path: Path, redactor: Redactor) -> None:
        self._path = path
        self._redactor = redactor
        self._lock = threading.Lock()
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)

    def record(self, event: str, **fields: Any) -> None:
        client = fields.get("client")
        if isinstance(client, str) and "/" in client:
            fields["client"], fields["bot"] = client.split("/", 1)
        entry = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "event": event, **fields}
        line = self._redactor.scrub(json.dumps(entry, default=str)) + "\n"
        with self._lock:
            fd = os.open(self._path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
            try:
                os.write(fd, line.encode())
            finally:
                os.close(fd)
