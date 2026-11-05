"""Defaults the command line, the wizard's API and the service share (the wizard's own
copies are in wizard/src/state.rs; tests/test_defaults.py keeps the two in step)."""

VAULT = "Agent"  # the vault the broker's token may read
PORT = 8787
GRANT_MINUTES = 2  # how long one Allow lasts for the same item and site
IDLE_MINUTES = 15  # sign the browser out after this long unused

# `passbroker api` options shared by serve-command and service-install.
SERVE_OPTIONS = (
    (("--port",), {"type": int, "default": PORT}),
    (("--vault",), {"default": VAULT}),
    (("--public-host",), {"action": "append", "default": []}),
    (("--grant-minutes",), {"type": float, "default": GRANT_MINUTES}),
    (("--headless",), {"action": "store_true"}),
    (("--keep-sessions",), {"action": "store_true"}),
    (("--idle-minutes",), {"type": float, "default": IDLE_MINUTES}),
)
