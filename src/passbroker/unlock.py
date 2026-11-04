"""Unlocking files with vault secrets that have no website (archive and file passphrases).

You define *actions* (in the wizard, stored in ~/.config/passbroker/unlockers.json).
Each binds one vault item to one built-in tool, the folders whose files it may
open, and where results go. An assistant can only pick an action and a file
inside those folders: it never chooses the command, the item or the output
path, and every unlock needs your desktop Allow.

The secret reaches the tool on stdin (never argv, which other programs can
read), output is scrubbed and size-limited, and decrypted results go to the
action's output folder. They're returned to the assistant only when the action
says so.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

MAX_OUTPUT = 20_000
MAX_EXTRACT = 2 * 1024**3  # refuse archives that unpack to more than this
TIMEOUT_S = 300
ARCHIVE_TYPES = {".7z": "7z", ".zip": "zip"}
# Output folders may not be (or contain) places where a written file becomes code or config.
SENSITIVE_DIRS = (".ssh", ".gnupg", ".config", ".local/bin", ".local/share/applications", ".bashrc.d", ".mozilla", ".pki")
NAME_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,31}")


class UnlockError(Exception):
    """Safe to show to the assistant."""


@dataclass(frozen=True)
class Preset:
    key: str
    label: str
    tool: str
    argv: tuple[str, ...]  # {in} = input file, {out} = output file or folder
    produces: str  # "file", "dir" or "text"
    extensions: tuple[str, ...]
    description: str


PRESETS: dict[str, Preset] = {
    p.key: p
    for p in (
        Preset(
            "gpg-decrypt", "Decrypt a GPG file", "gpg",
            # A fresh, empty home: no secret keys, agent cache or gpg.conf of yours can take part.
            ("gpg", "--homedir", "{home}", "--no-options", "--batch", "--yes", "--no-symkey-cache", "--pinentry-mode", "loopback",
             "--passphrase-fd", "0", "--output", "{out}", "--decrypt", "{in}"),
            "file", (".gpg", ".asc", ".pgp"), "Passphrase-encrypted .gpg/.asc files (symmetric).",
        ),
        Preset(
            "openssl-decrypt", "Decrypt an OpenSSL file", "openssl",
            ("openssl", "enc", "-d", "-aes-256-cbc", "-pbkdf2", "-in", "{in}", "-out", "{out}", "-pass", "stdin"),
            "file", (".enc", ".aes"), "Files made with: openssl enc -aes-256-cbc -pbkdf2.",
        ),
        Preset(
            "7z-extract", "Extract a 7-Zip/ZIP archive", "7z",
            ("7z", "x", "-y", "-snl-", "-t{type}", "-o{out}", "{in}"),
            "dir", (".7z", ".zip"), "Password-protected archives, extracted to a new folder.",
        ),
        Preset(
            "7z-list", "List a 7-Zip/ZIP archive", "7z",
            ("7z", "l", "-ba", "-t{type}", "{in}"),
            "text", (".7z", ".zip"), "Shows what's inside an archive without extracting it.",
        ),
        Preset(
            "keepassxc-list", "List a KeePassXC database", "keepassxc-cli",
            ("keepassxc-cli", "ls", "--recursive", "--flatten", "{in}"),
            "text", (".kdbx",), "Entry titles only; never passwords.",
        ),
    )
}


@dataclass
class Action:
    name: str
    preset: str
    item: str  # vault item title whose password is the passphrase
    folders: list[str]
    output_dir: str = ""
    return_output: bool = False
    extra: dict[str, Any] = field(default_factory=dict)

    def public(self) -> dict[str, Any]:
        p = PRESETS.get(self.preset)
        return {
            "action": self.name,
            "does": p.label if p else self.preset,
            "folders": self.folders,
            "file_types": list(p.extensions) if p else [],
            "returns_content_to_you": self.return_output or (p is not None and p.produces == "text"),
        }


def available_presets() -> list[dict[str, Any]]:
    return [{**asdict(p), "installed": shutil.which(p.tool) is not None} for p in PRESETS.values()]


def _expand(path: str) -> Path:
    return Path(os.path.expanduser(path)).resolve()


def _inside(path: Path, root: Path) -> bool:
    return path == root or root in path.parents


class Unlockers:
    def __init__(self, path: Path) -> None:
        self.path = path

    def load(self) -> list[Action]:
        try:
            data = json.loads(self.path.read_text() or "{}")
        except FileNotFoundError:
            return []
        return [Action(**a) for a in data.get("actions", [])]

    def save(self, actions: list[Action]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        tmp = self.path.with_suffix(".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump({"actions": [asdict(a) for a in actions]}, f, indent=2)
        os.replace(tmp, self.path)

    def add(self, action: Action) -> None:
        validate(action)
        actions = [a for a in self.load() if a.name != action.name]
        self.save(actions + [action])

    def remove(self, name: str) -> bool:
        actions = self.load()
        kept = [a for a in actions if a.name != name]
        self.save(kept)
        return len(kept) != len(actions)

    def get(self, name: str) -> Action:
        for a in self.load():
            if a.name == name:
                return a
        raise UnlockError(f"no unlock action named '{name}'; call list_unlockers")


def validate(a: Action) -> None:
    if not (isinstance(a.name, str) and isinstance(a.preset, str) and isinstance(a.item, str) and isinstance(a.output_dir, str)):
        raise UnlockError("name, tool, item and output folder must be text")
    if not isinstance(a.return_output, bool):
        raise UnlockError("'show result to the assistant' must be true or false")
    if not (isinstance(a.folders, list) and all(isinstance(f, str) for f in a.folders)):
        raise UnlockError("folders must be a list of paths")
    if not NAME_RE.fullmatch(a.name):
        raise UnlockError("action name: 1-32 lowercase letters, digits, dot, dash or underscore")
    p = PRESETS.get(a.preset)
    if p is None:
        raise UnlockError(f"unknown tool '{a.preset}'")
    if not a.item.strip():
        raise UnlockError("pick the vault item that holds the passphrase")
    if not a.folders:
        raise UnlockError("add at least one folder the action may open files from")
    home = Path.home().resolve()
    for f in a.folders:
        d = _expand(f)
        if not d.is_dir():
            raise UnlockError(f"folder not found: {f}")
        if d == home or d == Path("/") or not _inside(d, home):
            raise UnlockError(f"pick a specific folder inside your home folder, not {d}")
    if p.produces != "text":
        out = _expand(a.output_dir or "")
        if not a.output_dir or not _inside(out, home) or out == home:
            raise UnlockError("pick an output folder inside your home folder")
        for f in a.folders:
            d = _expand(f)
            if _inside(out, d) or _inside(d, out):
                raise UnlockError("the output folder can't be inside (or contain) a folder files are opened from")
        for name in SENSITIVE_DIRS:
            if _inside(out, home / name):
                raise UnlockError(f"the output folder can't be inside ~/{name}")


def resolve_input(a: Action, file: str) -> Path:
    """The real path of `file`, which must be a regular file inside one of the action's folders."""
    p = PRESETS[a.preset]
    roots = [_expand(f) for f in a.folders]
    candidates = [Path(file)] if os.path.isabs(os.path.expanduser(file)) else [r / file for r in roots]
    for c in candidates:
        real = _expand(str(c))
        if any(_inside(real, r) for r in roots) and real.is_file():
            if p.extensions and real.suffix.lower() not in p.extensions:
                raise UnlockError(f"{real.name} isn't a {'/'.join(p.extensions)} file")
            return real
    raise UnlockError("that file isn't in this action's folders (links leading elsewhere don't count)")


def list_files(a: Action, limit: int = 200) -> list[str]:
    p = PRESETS[a.preset]
    out: list[str] = []
    for f in a.folders:
        root = _expand(f)
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames.sort()
            for name in sorted(filenames):
                path = Path(dirpath) / name
                if (not p.extensions or path.suffix.lower() in p.extensions) and _inside(path.resolve(), root) and path.is_file():
                    out.append(str(path.relative_to(root)))
                    if len(out) >= limit:
                        return out
    return out


def _decode(data: bytes) -> str:
    return data.decode("utf-8", errors="replace")


def _check_archive(src: Path, kind: str, env: dict[str, str], secret: str) -> None:
    """Refuse archives with links, absolute or `..` paths, or that unpack too large."""
    proc = subprocess.run(["7z", "l", "-slt", f"-t{kind}", str(src)], input=(secret + "\n").encode(), capture_output=True, timeout=120, env=env)
    if proc.returncode != 0:
        return  # wrong passphrase etc.: the extraction itself will fail cleanly
    total = 0
    for block in _decode(proc.stdout).split("\n\n"):
        fields = dict(line.split(" = ", 1) for line in block.splitlines() if " = " in line)
        path = fields.get("Path", "")
        if not path or "Attributes" not in fields and "Size" not in fields:
            continue
        if path.startswith("/") or ".." in Path(path).parts or fields.get("Symbolic Link") or fields.get("Hard Link"):
            raise UnlockError("the archive contains links or paths that point outside it; refused")
        attrs = fields.get("Attributes", "")
        if re.search(r"(^|\s)l[rwxsStT-]{9}", attrs) or "LINK" in attrs.upper() or fields.get("Link"):
            raise UnlockError("the archive contains links; refused")
        total += int(fields.get("Size") or 0)
        if total > MAX_EXTRACT:
            raise UnlockError("the archive unpacks to more than 2 GB; refused")


def run(a: Action, src: Path, secret: str) -> dict[str, Any]:
    """Run the action's tool with the secret on stdin. Returns raw results for the caller to scrub."""
    p = PRESETS[a.preset]
    if shutil.which(p.tool) is None:
        raise UnlockError(f"{p.tool} isn't installed on the PC")
    keep = ("PATH", "HOME", "LANG", "LC_ALL", "XDG_RUNTIME_DIR")
    env = {k: os.environ[k] for k in keep if k in os.environ}
    kind = ARCHIVE_TYPES.get(src.suffix.lower(), "")
    work = None
    if p.produces != "text":
        out_dir = _expand(a.output_dir)
        out_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        # A fresh private folder per run: no planted links, no collisions between runs.
        work = Path(tempfile.mkdtemp(prefix=re.sub(r"[^\w.-]", "_", src.stem)[:60] + "-", dir=out_dir))
    target = (work / re.sub(r"[^\w.-]", "_", src.stem if src.suffix.lower() in p.extensions else src.name)[:80]) if p.produces == "file" else work
    home = tempfile.mkdtemp(prefix="pb-gpg-") if "{home}" in p.argv else ""
    argv = [x.replace("{in}", str(src)).replace("{out}", str(target or "")).replace("{home}", home).replace("{type}", kind) for x in p.argv]
    try:
        if a.preset == "7z-extract":
            _check_archive(src, kind, env, secret)
        proc = subprocess.run(argv, input=(secret + "\n").encode(), capture_output=True, timeout=TIMEOUT_S, env=env)
    except subprocess.TimeoutExpired:
        if work:
            shutil.rmtree(work, ignore_errors=True)
        raise UnlockError("the tool took too long and was stopped") from None
    except UnlockError:
        if work:
            shutil.rmtree(work, ignore_errors=True)
        raise
    finally:
        if home:
            shutil.rmtree(home, ignore_errors=True)
    result: dict[str, Any] = {"exit_code": proc.returncode, "ok": proc.returncode == 0}
    if p.produces == "text":
        result["content"] = _decode(proc.stdout[:MAX_OUTPUT])
        return result
    result["log"] = _decode(proc.stdout + b"\n" + proc.stderr).strip()[-2000:]
    assert work is not None and target is not None
    if not result["ok"]:
        # wrong passphrase or damaged file: don't leave half-written output behind
        shutil.rmtree(work, ignore_errors=True)
        return result
    if p.produces == "dir":
        real = work.resolve()
        bad = [f for f in work.rglob("*") if f.is_symlink() or not _inside(f.resolve(), real)]
        if bad:
            shutil.rmtree(work, ignore_errors=True)
            raise UnlockError("the archive tried to write outside its folder; nothing was kept")
        result["files"] = [_decode(str(f.relative_to(work)).encode("utf-8", "surrogateescape")) for f in sorted(work.rglob("*")) if f.is_file()][:200]
        result["result_path"] = str(work)
    else:
        os.chmod(target, 0o600)
        result["result_path"] = str(target)
        if a.return_output:
            fd = os.open(target, os.O_RDONLY | os.O_NOFOLLOW)
            with os.fdopen(fd, "rb") as fh:
                data = fh.read(MAX_OUTPUT)
            try:
                result["content"] = data.decode()
            except UnicodeDecodeError:
                result["content_note"] = "the result isn't text, so it wasn't returned"
    return result
