"""Encrypting and decrypting text with a passphrase that stays in your vault.

A *key* is a name you give a vault item (its password is the passphrase), set
up in the wizard and stored in ~/.config/passbroker/keys.json. Bots send text
to encrypt (no approval needed: it reveals nothing) or ciphertext to decrypt
(needs your Allow), so files like a security log or a ledger can live
encrypted on the bots' computer with no key beside them.

gpg does the work in a fresh, empty home folder, so none of your own GPG keys,
agent cache or config take part; the passphrase goes in on a separate pipe.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path

from . import jsonfile

MAX_TEXT = 1_000_000
NAME_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,31}")
ARMOR_HEAD = "-----BEGIN PGP MESSAGE-----"


class KeyError_(Exception):
    """Safe to show to the assistant."""


@dataclass
class Key:
    name: str
    item: str  # vault item whose password is the passphrase
    note: str = ""


class KeyStore:
    def __init__(self, path: Path) -> None:
        self.path = path

    def load(self) -> list[Key]:
        data = jsonfile.read(self.path, {})
        return [jsonfile.build(Key, k) for k in data.get("keys", [])]

    def _save(self, keys: list[Key]) -> None:
        jsonfile.write(self.path, {"keys": [asdict(k) for k in keys]})

    def add(self, key: Key) -> None:
        if not (isinstance(key.name, str) and NAME_RE.fullmatch(key.name)):
            raise KeyError_("key name: 1-32 lowercase letters, digits, dot, dash or underscore")
        if not (isinstance(key.item, str) and key.item.strip()):
            raise KeyError_("pick the vault item that holds the passphrase")
        if not isinstance(key.note, str):
            raise KeyError_("the note must be text")
        self._save([k for k in self.load() if k.name != key.name] + [key])

    def remove(self, name: str) -> bool:
        keys = self.load()
        kept = [k for k in keys if k.name != name]
        self._save(kept)
        return len(kept) != len(keys)

    def get(self, name: str) -> Key:
        for k in self.load():
            if k.name == name:
                return k
        raise KeyError_(f"no key named '{name}'; call list_keys")


def _gpg(args: list[str], data: bytes, passphrase: str) -> bytes:
    if shutil.which("gpg") is None:
        raise KeyError_("gpg isn't installed on the PC")
    home = tempfile.mkdtemp(prefix="pb-gpg-")
    r, w = os.pipe()
    try:
        os.write(w, passphrase.encode() + b"\n")
        os.close(w)
        w = -1
        proc = subprocess.run(
            ["gpg", "--homedir", home, "--no-options", "--batch", "--yes", "--quiet", "--no-symkey-cache",
             "--pinentry-mode", "loopback", "--passphrase-fd", str(r), *args],
            input=data, capture_output=True, timeout=120, pass_fds=(r,),
            env={k: os.environ[k] for k in ("PATH", "LANG", "LC_ALL") if k in os.environ},
        )
    except subprocess.TimeoutExpired:
        raise KeyError_("gpg took too long") from None
    finally:
        os.close(r)
        if w != -1:
            os.close(w)
        shutil.rmtree(home, ignore_errors=True)
    if proc.returncode != 0:
        raise KeyError_("that didn't work: wrong key, or the text isn't something this key encrypted")
    return proc.stdout


def encrypt(passphrase: str, text: str) -> str:
    data = text.encode()
    if len(data) > MAX_TEXT:
        raise KeyError_("text is over 1 MB")
    out = _gpg(["--symmetric", "--armor", "--cipher-algo", "AES256", "--output", "-"], data, passphrase)
    return out.decode()


def decrypt(passphrase: str, ciphertext: str) -> str:
    text = ciphertext.strip()
    if not text.startswith(ARMOR_HEAD) or len(text) > MAX_TEXT * 2:
        raise KeyError_("send the armored text encrypt_text returned (it starts with " + ARMOR_HEAD + ")")
    out = _gpg(["--decrypt", "--output", "-"], text.encode(), passphrase)
    if len(out) > MAX_TEXT:
        raise KeyError_("the decrypted text is over 1 MB")
    return out.decode("utf-8", errors="replace")
