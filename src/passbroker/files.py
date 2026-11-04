"""Unlocking files on this PC, and encrypting or decrypting text, with vault passphrases."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any

from .keys import KeyError_, decrypt, encrypt
from .unlock import PRESETS, UnlockError, Unlockers, list_files, resolve_input
from .unlock import run as run_unlock
from .vault import Login

if TYPE_CHECKING:
    from .broker import Broker


def _error(msg: str) -> Exception:
    from .broker import BrokerError

    return BrokerError(msg)


class FilesMixin:
    # ---- unlocking files ----------------------------------------------------------

    def _unlockers(self: "Broker") -> Unlockers:
        if self.unlockers is None:
            raise _error("file unlocking isn't set up on this broker")
        return self.unlockers

    def _granted(self: "Broker", client: str, kind: str, names: list[str]) -> list[str]:
        conn, _, bot = client.partition("/")
        if not bot or self.bots is None:
            return names
        allowed = set(self.bots.access(bot)[kind])
        return [n for n in names if n in allowed]

    async def list_unlockers(self: "Broker", client: str) -> list[dict[str, Any]]:
        actions = self._unlockers().load()
        names = set(self._granted(client, "unlock", [a.name for a in actions]))
        self.audit.record("list_unlockers", client=client)
        return [a.public() for a in actions if a.name in names]

    async def list_locked_files(self: "Broker", client: str, action: str) -> list[str]:
        self._permit(client, "unlock", action)
        try:
            a = self._unlockers().get(action)
            files = await asyncio.to_thread(list_files, a)
        except UnlockError as e:
            raise _error(str(e)) from None
        self.audit.record("list_locked_files", client=client, action=action, count=len(files))
        return files

    async def unlock_file(self: "Broker", client: str, action: str, file: str, reason: str = "") -> dict[str, Any]:
        from .broker import plain

        self._permit(client, "unlock", action)
        try:
            a = self._unlockers().get(action)
            src = resolve_input(a, file)
        except UnlockError as e:
            raise _error(str(e)) from None
        login = await self._item(a.item, a.name)
        preset = PRESETS[a.preset]
        shown = a.return_output or preset.produces == "text"
        details = (
            ("The result WILL be shown to the assistant.\n" if shown else "The result stays on this PC.\n")
            + f"Action: {a.name} ({preset.label})\nFile: {plain(src.name, 80)} in {plain(str(src.parent), 120)}\n"
            + (f"Result saved in: {plain(a.output_dir, 120)}\n" if preset.produces != "text" else "")
        )
        await self._approve(client, login, f"file:{src}", f"unlock:{a.name}", f"unlock {plain(src.name, 60)}", details, reason)
        secret = await self._secret(client, login, "password", f"unlock {src.name}")
        try:
            result = await asyncio.to_thread(run_unlock, a, src, secret)
        except UnlockError as e:
            raise _error(str(e)) from None
        finally:
            del secret
        self.audit.record("unlock", client=client, item=login.title, action=a.name, file=src.name, ok=result["ok"])
        if not result["ok"]:
            result["error"] = "the tool failed: wrong passphrase, or the file isn't what this action expects"
        return result

    # ---- encrypting and decrypting text ---------------------------------------------

    def _key_login(self: "Broker", client: str, name: str) -> tuple[str, Any]:
        if self.keys is None:
            raise _error("keys aren't set up on this broker")
        self._permit(client, "keys", name)
        try:
            return name, self.keys.get(name)
        except KeyError_ as e:
            raise _error(str(e)) from None

    async def list_keys(self: "Broker", client: str) -> list[dict[str, str]]:
        keys = self.keys.load() if self.keys else []
        names = set(self._granted(client, "keys", [k.name for k in keys]))
        return [{"key": k.name, "note": k.note} for k in keys if k.name in names]

    async def encrypt_text(self: "Broker", client: str, key: str, text: str) -> dict[str, Any]:
        _, k = self._key_login(client, key)
        login: Login = await self._item(k.item, f"key {key}")
        secret = await self._secret(client, login, "password", f"encrypt with key {key}")
        try:
            out = await asyncio.to_thread(encrypt, secret, text)
        except KeyError_ as e:
            raise _error(str(e)) from None
        finally:
            del secret
        self.audit.record("encrypt", client=client, key=key, size=len(text))
        return {"ciphertext": out}

    async def decrypt_text(self: "Broker", client: str, key: str, ciphertext: str, reason: str = "") -> dict[str, Any]:
        _, k = self._key_login(client, key)
        login: Login = await self._item(k.item, f"key {key}")
        details = f"Key: {key}\nThe decrypted text WILL be shown to the assistant.\n"
        await self._approve(client, login, f"key:{key}", "decrypt", f"decrypt text with the key '{key}'", details, reason)
        secret = await self._secret(client, login, "password", f"decrypt with key {key}")
        try:
            out = await asyncio.to_thread(decrypt, secret, ciphertext)
        except KeyError_ as e:
            raise _error(str(e)) from None
        finally:
            del secret
        self.audit.record("decrypt", client=client, key=key, size=len(out))
        return {"text": out}
