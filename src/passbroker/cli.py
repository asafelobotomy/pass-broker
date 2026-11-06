"""passbroker command line: store the token, manage clients, run the server."""

from __future__ import annotations

import argparse
import asyncio
import getpass
import json
import logging
import os
import signal
import subprocess
import sys
from pathlib import Path

from . import defaults, ops
from .ops import dirs as _dirs
from .ops import harden_process
from .ops import load_token as _load_token


def cmd_set_token(args: argparse.Namespace) -> None:
    token = sys.stdin.readline() if args.stdin else getpass.getpass("Proton Pass access token (input hidden): ")
    print(f"Saved in your system keyring ({ops.store_token(token)}).")


def cmd_add_client(args: argparse.Namespace) -> None:
    token = ops.add_client(args.name)
    print(f"Client '{args.name}' added. Its bearer token is shown once; put it in that client's connector settings:\n")
    print(token)


def cmd_remove_client(args: argparse.Namespace) -> None:
    ops.remove_client(args.name)
    print(f"Client '{args.name}' removed; its token stops working on the next request.")


def cmd_list_clients(args: argparse.Namespace) -> None:
    for name in ops.list_clients():
        print(name)


def cmd_check(args: argparse.Namespace) -> None:
    """Log in with the stored token and print what assistants would see."""
    harden_process()
    result = ops.check_vault(args.vault, args.pass_cli)
    logins = result["logins"]
    for info in logins:
        flag = "" if info["fillable"] else "   (no website saved: can't be filled)"
        print(f"{info['title']}  {', '.join(info['urls'])}  user={info['username']}  2fa={ {True: 'yes', False: 'no', None: 'unknown'}[info['has_totp']] }{flag}")
    print(f"\n{len(logins)} logins in vault '{args.vault}'. No passwords were read.")
    if any(not l["urls"] for l in logins):
        print("Some logins have no website. Key names in pass-cli's listing (no values): " + ", ".join(result["keys"]))


def _file_notifier(path: Path):
    """Tests only: write sign-in notifications to a file instead of the desktop."""

    def notify(title: str, body: str) -> None:
        with open(path, "a") as f:
            f.write(json.dumps({"title": title, "body": body}) + "\n")

    return notify


TEST_SWITCHES = ("mock", "allow_http_localhost", "insecure_auto_approve", "no_pairing_window", "notify_file")


def check_test_switches(args: argparse.Namespace) -> None:
    """Switches the test suite needs are refused unless PASSBROKER_TEST_MODE=1 is set.

    Without this, any program running as you could restart the broker with
    approvals off or the private-network guard disabled.
    """
    used = [f"--{name.replace('_', '-')}" for name in TEST_SWITCHES if getattr(args, name)]
    if not used:
        return
    if os.environ.get("PASSBROKER_TEST_MODE") != "1":
        sys.exit(f"passbroker: {', '.join(used)} are for the test suite only (set PASSBROKER_TEST_MODE=1 to use them)")
    print(f"WARNING: TEST MODE ({', '.join(used)}): approvals, the network guard or the pairing window may be off. Never use this for real.", file=sys.stderr)


def cmd_serve(args: argparse.Namespace) -> None:
    import uvicorn

    from . import accounts
    from .approvals import DesktopApprover, GrantCache, StaticApprover
    from .audit import AuditLog
    from .bots import Bots
    from .broker import Broker
    from .browser import Browser
    from .devices import DeviceStore
    from .keys import KeyStore
    from .mailcode import MailSettings
    from .oauth import DEFAULT_REDIRECT_HOSTS, BrokerOAuth
    from .preview import Preview, preview_dir
    from .redact import Redactor
    from .server import ScrubLogs, build_app, build_server, load_clients
    from .unlock import Unlockers
    from .vault import MockBackend, ProtonPassBackend

    check_test_switches(args)
    harden_process()
    config, data, state = _dirs()
    redactor = Redactor()
    scrub = ScrubLogs(redactor)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    for handler in logging.getLogger().handlers:
        handler.addFilter(scrub)

    if args.mock:
        backend = MockBackend(Path(args.mock), redactor)
    else:
        backend = ProtonPassBackend(args.vault, _load_token, redactor, pass_cli=args.pass_cli, session_dir=ops.broker_session_dir())
        backend.extra_vault = lambda: (s.vault if (s := accounts.load(config / "accounts.json")).enabled else None)
    approver = StaticApprover(True) if args.insecure_auto_approve else DesktopApprover(args.approval_timeout)
    browser = Browser(
        data / "profile",
        redactor,
        headless=args.headless,
        keep_sessions=args.keep_sessions,
        idle_minutes=args.idle_minutes,
        allow_private=args.allow_http_localhost,
    )
    bots = Bots(config / "bots.json")
    broker = Broker(
        backend,
        browser,
        approver,
        GrantCache(args.grant_minutes * 60),
        AuditLog(state / "audit.jsonl", redactor),
        redactor,
        allow_http_localhost=args.allow_http_localhost,
        allow_subdomains=args.allow_subdomains,
        show_usernames=args.show_usernames,
        unlockers=Unlockers(config / "unlockers.json"),
        bots=bots,
        account_settings=lambda: accounts.load(config / "accounts.json"),
        keys=KeyStore(config / "keys.json"),
        devices=DeviceStore(config / "devices.json"),
        mail=MailSettings.load(config / "mail.json"),
    )
    broker.mail_path = config / "mail.json"
    broker.accounts_path = config / "accounts.json"
    broker.mail_admin_path = config / "mailadmin.json"
    preview = Preview(browser, redactor, preview_dir())
    browser.on_signed_out = lambda key, reason: broker.audit.record("signed_out", client=key, reason=reason)
    clients_path = config / "clients.json"
    public = args.public_host[0] if args.public_host else None
    issuer = f"https://{public}" if public else f"http://127.0.0.1:{args.port}"
    oauth = BrokerOAuth(
        issuer,
        issuer + "/mcp",
        config / "oauth.json",
        lambda: load_clients(clients_path),
        audit=broker.audit.record,
        redirect_hosts=args.oauth_redirect_host or list(DEFAULT_REDIRECT_HOSTS),
        pairing_path=None if args.no_pairing_window else config / "pairing",
        **({"notify": _file_notifier(Path(args.notify_file))} if args.notify_file else {}),
    )
    mcp = build_server(broker, redactor, oauth, bots)
    app = build_app(mcp, args.public_host, args.port)
    print(f"Pass Broker serving {issuer}/mcp", file=sys.stderr)

    async def main() -> None:
        try:
            # Inside the try: if the browser can't start, Funnel must still be turned off below.
            await browser.start()
            await preview.start()
            # log_config=None: uvicorn logs through the root handlers, which scrub every record.
            server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=args.port, log_config=None, access_log=False))
            await server.serve()
        finally:
            # Each step runs even if one before it fails.
            for stop in (preview.stop, browser.stop):
                try:
                    await stop()
                except Exception as e:
                    logging.getLogger("passbroker").warning("shutdown: %s", type(e).__name__)
            if args.manage_funnel:
                # Funnel would otherwise stay on (and survive reboots) with nothing behind it.
                subprocess.run(ops.funnel_stop_command(), capture_output=True, timeout=20)

    # uvicorn shuts down on SIGTERM (systemd, the wizard's Stop) and then raises the
    # signal again. With the default handler that kills the process before the
    # `finally` above runs, skipping the browser sign-out, the live-view cleanup and
    # turning Funnel off. Exiting normally instead lets all of it run.
    signal.signal(signal.SIGTERM, _exit_on_term)
    asyncio.run(main())


def _exit_on_term(signum: int, frame: object) -> None:
    raise SystemExit(0)


def main(argv: list[str] | None = None) -> None:
    from importlib.metadata import version

    p = argparse.ArgumentParser(prog="passbroker", description="Let AI assistants sign in with Proton Pass without seeing secrets.")
    p.add_argument("--version", action="version", version=f"passbroker {version('passbroker')}")
    sub = p.add_subparsers(required=True)

    s = sub.add_parser("set-token", help="store your Proton Pass access token in the system keyring")
    s.add_argument("--stdin", action="store_true", help="read the token from stdin instead of a hidden prompt")
    s.set_defaults(func=cmd_set_token)

    s = sub.add_parser("add-client", help="create a bearer token for an assistant (e.g. grok)")
    s.add_argument("name")
    s.set_defaults(func=cmd_add_client)

    s = sub.add_parser("remove-client", help="revoke an assistant's bearer token")
    s.add_argument("name")
    s.set_defaults(func=cmd_remove_client)

    s = sub.add_parser("list-clients", help="list assistant names")
    s.set_defaults(func=cmd_list_clients)

    s = sub.add_parser("check", help="log in with the stored token and list what assistants will see")
    s.add_argument("--vault", default=defaults.VAULT)
    s.add_argument("--pass-cli", default="pass-cli")
    s.set_defaults(func=cmd_check)

    s = sub.add_parser("serve", help="run the broker on 127.0.0.1")
    s.add_argument("--vault", default=defaults.VAULT, help=f"Proton Pass vault the token can read (default: {defaults.VAULT})")
    s.add_argument("--port", type=int, default=defaults.PORT)
    s.add_argument("--public-host", action="append", default=[], help="tunnel hostname allowed in the Host header, e.g. pass.example.com")
    s.add_argument("--grant-minutes", type=float, default=defaults.GRANT_MINUTES, help="how long one Allow lasts for the same item and site (0 = ask every time)")
    s.add_argument("--approval-timeout", type=int, default=60)
    s.add_argument("--headless", action="store_true", help="run the browser without a window; the wizard's Control center shows it instead")
    s.add_argument("--pass-cli", default="pass-cli")
    s.add_argument("--keep-sessions", action="store_true", help="keep sites signed in between runs (default: fresh browser each run)")
    s.add_argument("--idle-minutes", type=float, default=defaults.IDLE_MINUTES, help="sign the browser out of everything after this long unused (0 = never)")
    s.add_argument("--allow-subdomains", action="store_true", help="let a saved site match its subdomains too")
    s.add_argument("--show-usernames", action="store_true", help="show assistants full usernames instead of masked ones")
    s.add_argument("--oauth-redirect-host", action="append", default=[], help="host allowed to receive sign-in codes (default: Cursor's)")
    s.add_argument("--manage-funnel", action="store_true", help="turn Tailscale Funnel off when the broker stops")
    s.add_argument("--no-pairing-window", action="store_true", help=argparse.SUPPRESS)
    s.add_argument("--mock", metavar="FILE", help=argparse.SUPPRESS)
    s.add_argument("--allow-http-localhost", action="store_true", help=argparse.SUPPRESS)
    s.add_argument("--insecure-auto-approve", action="store_true", help=argparse.SUPPRESS)
    s.add_argument("--notify-file", help=argparse.SUPPRESS)
    s.set_defaults(func=cmd_serve)

    from . import api

    api.add_parser(sub)

    from .vault import VaultError

    args = p.parse_args(argv)
    try:
        args.func(args)
    except (VaultError, ops.OpError, RuntimeError) as e:
        sys.exit(f"passbroker: {e}")


if __name__ == "__main__":
    main()
