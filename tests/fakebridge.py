"""Just enough of Proton Mail Bridge for the tests: IMAP (STARTTLS, folders, UIDs, flags, moves,
labels as copies, APPEND) and SMTP (STARTTLS, AUTH PLAIN), each on its own local port."""

from __future__ import annotations

import base64
import re
import socket
import ssl
import threading


def _tokens(s: str) -> list[str]:
    """IMAP arguments: "quoted", (grouped) and atoms; quotes and escapes taken off."""
    out, i = [], 0
    while i < len(s):
        c = s[i]
        if c == " ":
            i += 1
        elif c == '"':
            j, buf = i + 1, []
            while s[j] != '"':
                if s[j] == "\\":
                    j += 1
                buf.append(s[j])
                j += 1
            out.append("".join(buf))
            i = j + 1
        elif c == "(":
            depth, j = 0, i
            while True:
                depth += {"(": 1, ")": -1}.get(s[j], 0)
                j += 1
                if depth == 0:
                    break
            out.append(s[i:j])
            i = j
        else:
            j = s.find(" ", i)
            j = len(s) if j < 0 else j
            out.append(s[i:j])
            i = j
    return out


class FakeBridge:
    def __init__(self, key, cert, messages=(), password="bridge-pass"):
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ctx.load_cert_chain(cert, key)
        given = messages if isinstance(messages, dict) else {"INBOX": list(messages)}
        self.folders: dict[str, list[dict]] = {}
        self.next_uid = 1
        for name in ("INBOX", *given):
            self.folders.setdefault(name, [])
        for name, raws in given.items():
            for raw in raws:
                self.add(name, raw)
        self.password = password
        self.logins: list[str] = []
        self.sent: list[tuple[str, list[str], bytes]] = []
        self.sock = socket.create_server(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.smtp_sock = socket.create_server(("127.0.0.1", 0))
        self.smtp_port = self.smtp_sock.getsockname()[1]
        self.lock = threading.Lock()
        threading.Thread(target=self._serve, args=(self.sock, self._imap), daemon=True).start()
        threading.Thread(target=self._serve, args=(self.smtp_sock, self._smtp), daemon=True).start()

    def add(self, folder: str, raw: bytes, flags=()) -> dict:
        msg = {"uid": self.next_uid, "raw": raw, "flags": set(flags)}
        self.next_uid += 1
        self.folders.setdefault(folder, []).append(msg)
        return msg

    def raws(self, folder: str) -> list[bytes]:
        return [m["raw"] for m in self.folders.get(folder, [])]

    def close(self):
        self.sock.close()
        self.smtp_sock.close()

    def _serve(self, sock, handler):
        while True:
            try:
                conn, _ = sock.accept()
            except OSError:
                return
            threading.Thread(target=handler, args=(conn,), daemon=True).start()

    # ---- IMAP -----------------------------------------------------------------------------

    def _imap(self, conn):
        io = {"f": conn.makefile("rwb"), "conn": conn, "tls": False, "box": None}

        def send(s):
            io["f"].write(s if isinstance(s, bytes) else s.encode())
            io["f"].flush()

        send("* OK fake Bridge ready\r\n")
        try:
            while line := io["f"].readline():
                text = line.decode().rstrip("\r\n")
                if m := re.search(r"\{(\d+)\}$", text):  # a literal follows (APPEND)
                    send("+ go\r\n")
                    literal = io["f"].read(int(m.group(1)))
                    io["f"].readline()
                    text = text[: m.start()] + "LITERAL"
                else:
                    literal = None
                tag, cmd, *rest = text.split(" ", 2)
                args = _tokens(rest[0]) if rest else []
                with self.lock:
                    reply = self._command(io, tag, cmd.upper(), args, literal, send)
                if reply == "BYE":
                    return
        except (OSError, ValueError, IndexError):
            return
        finally:
            io["conn"].close()

    def _command(self, io, tag, cmd, args, literal, send):
        ok = f"{tag} OK done\r\n"
        if cmd == "CAPABILITY":
            send(f"* CAPABILITY IMAP4rev1 {'AUTH=PLAIN MOVE' if io['tls'] else 'STARTTLS LOGINDISABLED'}\r\n" + ok)
        elif cmd == "STARTTLS":
            send(f"{tag} OK begin TLS\r\n")
            io["conn"] = self.ctx.wrap_socket(io["conn"], server_side=True)
            io["f"], io["tls"] = io["conn"].makefile("rwb"), True
        elif cmd == "LOGIN":
            self.logins.append(args[0])
            send(ok if io["tls"] and args[1] == self.password else f"{tag} NO wrong password\r\n")
        elif cmd == "LOGOUT":
            send(f"* BYE\r\n{tag} OK bye\r\n")
            return "BYE"
        elif cmd == "LIST":
            pattern = args[1] if len(args) > 1 else "*"
            names = [n for n in self.folders if pattern in ("*", "%") or n == pattern]
            send("".join(f'* LIST (\\HasNoChildren) "/" "{n}"\r\n' for n in names) + ok)
        elif cmd == "STATUS":
            box = self.folders.get(args[0])
            if box is None:
                return send(f"{tag} NO no such folder\r\n")
            unseen = sum(1 for m in box if "\\Seen" not in m["flags"])
            send(f'* STATUS "{args[0]}" (MESSAGES {len(box)} UNSEEN {unseen})\r\n' + ok)
        elif cmd in ("EXAMINE", "SELECT"):
            if args[0] not in self.folders:
                return send(f"{tag} NO no such folder\r\n")
            io["box"] = args[0]
            mode = "READ-ONLY" if cmd == "EXAMINE" else "READ-WRITE"
            send(f"* {len(self.folders[args[0]])} EXISTS\r\n{tag} OK [{mode}] done\r\n")
        elif cmd == "CREATE":
            self.folders.setdefault(args[0], [])
            send(ok)
        elif cmd == "RENAME":
            self.folders[args[1]] = self.folders.pop(args[0])
            send(ok)
        elif cmd == "DELETE":
            msgs = self.folders.pop(args[0], [])
            if args[0].startswith("Folders/"):
                self.folders["INBOX"] += msgs  # Proton keeps a deleted folder's mail
            send(ok)
        elif cmd == "APPEND":
            flags = args[1].strip("()").split() if len(args) > 2 else []
            self.add(args[0], literal, flags)
            send(ok)
        elif cmd == "EXPUNGE":
            box = self.folders[io["box"]]
            box[:] = [m for m in box if "\\Deleted" not in m["flags"]]
            send(ok)
        elif cmd in ("SEARCH", "FETCH"):  # by position, as fetch_code uses them
            box = self.folders[io["box"]]
            if cmd == "SEARCH":
                send(f"* SEARCH {' '.join(str(i + 1) for i in range(len(box)))}\r\n" + ok)
            else:
                n = int(args[0])
                send(self._fetched(n, box[n - 1], args[1]) + ok.encode())
        elif cmd == "UID":
            self._uid(io, tag, args[0].upper(), args[1:], send)
        else:
            send(f"{tag} BAD unknown\r\n")

    def _fetched(self, n, m, what) -> bytes:
        data = m["raw"] if "HEADER" not in what.upper() else m["raw"].split(b"\r\n\r\n", 1)[0] + b"\r\n\r\n"
        flags = " ".join(sorted(m["flags"]))
        head = f"* {n} FETCH (UID {m['uid']} FLAGS ({flags}) RFC822.SIZE {len(m['raw'])} BODY[] {{{len(data)}}}\r\n"
        return head.encode() + data + b")\r\n"

    def _uid(self, io, tag, sub, args, send):
        box = self.folders[io["box"]]
        ok = f"{tag} OK done\r\n"
        find = lambda ids: [m for m in box if str(m["uid"]) in ids.split(",")]  # noqa: E731
        if sub == "SEARCH":
            hits = list(box)
            words = [a.upper() for a in args]
            if "UNSEEN" in words:
                hits = [m for m in hits if "\\Seen" not in m["flags"]]
            if "FLAGGED" in words:
                hits = [m for m in hits if "\\Flagged" in m["flags"]]
            for key in ("FROM", "SUBJECT", "TO"):
                if key in words:
                    value = args[words.index(key) + 1].lower().encode()
                    hits = [m for m in hits if re.search(rb"(?im)^" + key.encode() + rb":.*" + re.escape(value), m["raw"])]
            if "HEADER" in words:
                value = args[words.index("HEADER") + 2].encode()
                hits = [m for m in hits if value in m["raw"]]
            send(f"* SEARCH {' '.join(str(m['uid']) for m in hits)}\r\n" + ok)
        elif sub == "FETCH":
            send(b"".join(self._fetched(box.index(m) + 1, m, args[1]) for m in find(args[0])) + ok.encode())
        elif sub in ("MOVE", "COPY"):
            for m in find(args[0]):
                self.add(args[1], m["raw"], m["flags"])
                if sub == "MOVE":
                    box.remove(m)
            send(ok)
        elif sub == "STORE":
            change = set(args[2].strip("()").split())
            for m in find(args[0]):
                m["flags"] = m["flags"] | change if args[1].startswith("+") else m["flags"] - change
            send(ok)
        else:
            send(f"{tag} BAD unknown\r\n")

    # ---- SMTP -----------------------------------------------------------------------------

    def _smtp(self, conn):
        f = conn.makefile("rwb")
        send = lambda s: (f.write(s.encode()), f.flush())  # noqa: E731
        send("220 fake Bridge SMTP\r\n")
        tls, authed, sender, rcpts = False, False, "", []
        try:
            while line := f.readline():
                cmd = line.decode().rstrip("\r\n")
                verb = cmd.split(" ", 1)[0].upper()
                if verb in ("EHLO", "HELO"):
                    send("250-fake\r\n" + ("250 AUTH PLAIN\r\n" if tls else "250 STARTTLS\r\n"))
                elif verb == "STARTTLS":
                    send("220 go\r\n")
                    conn = self.ctx.wrap_socket(conn, server_side=True)
                    f, tls = conn.makefile("rwb"), True
                    send = lambda s, f=f: (f.write(s.encode()), f.flush())  # noqa: E731
                elif verb == "AUTH":
                    _, user, pw = base64.b64decode(cmd.split()[2]).split(b"\0")
                    authed = tls and pw.decode() == self.password
                    send("235 ok\r\n" if authed else "535 no\r\n")
                elif verb == "MAIL":
                    sender = cmd.split(":", 1)[1].strip().strip("<>").split(">")[0]
                    send("250 ok\r\n" if authed else "530 auth first\r\n")
                elif verb == "RCPT":
                    rcpts.append(cmd.split(":", 1)[1].strip().strip("<>").split(">")[0])
                    send("250 ok\r\n")
                elif verb == "DATA":
                    send("354 go\r\n")
                    data = b""
                    while (chunk := f.readline()) != b".\r\n":
                        data += chunk
                    with self.lock:
                        self.sent.append((sender, rcpts, data))
                        self.add("Sent", data, {"\\Seen"})
                    rcpts = []
                    send("250 queued\r\n")
                elif verb == "QUIT":
                    send("221 bye\r\n")
                    return
                else:
                    send("250 ok\r\n")
        except (OSError, ValueError):
            return
        finally:
            conn.close()
