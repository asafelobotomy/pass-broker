"""`passbroker api service-*`: install and control the optional systemd user service."""

from __future__ import annotations

from typing import Any

from . import ops, service


def c_service_install(a) -> dict[str, Any]:
    argv = ops.serve_command(a.port, a.vault, a.public_host, a.grant_minutes, a.headless, a.pass_cli, a.keep_sessions, a.idle_minutes)
    serve_args = argv[argv.index("serve") + 1 :]
    config, data, state = ops.dirs()
    funnel = any(h.endswith(".ts.net") for h in a.public_host)
    path = service.install(serve_args, config, data, state, a.port, funnel)
    return {"unit": str(path), **service.status()}


def c_service_uninstall(a) -> dict[str, Any]:
    service.uninstall()
    return service.status()


def c_service_status(a) -> dict[str, Any]:
    return service.status()


def c_service_control(a) -> dict[str, Any]:
    try:
        service.control(a.action)
    except RuntimeError as e:
        raise ops.OpError(str(e)) from None
    return service.status()


def add_parsers(add) -> None:
    from .defaults import SERVE_OPTIONS

    add("service-install", c_service_install, *SERVE_OPTIONS)
    add("service-uninstall", c_service_uninstall)
    add("service-status", c_service_status)
    add("service-control", c_service_control, (("action",), {"choices": ["start", "stop", "restart"]}))
