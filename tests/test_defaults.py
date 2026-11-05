"""The command line, the wizard's API and the wizard itself start from the same defaults."""

import re
from pathlib import Path

from passbroker import cli, defaults

ROOT = Path(__file__).resolve().parent.parent


def _wizard(field: str) -> str:
    text = (ROOT / "wizard/src/state.rs").read_text()
    defaults_block = text[text.index("impl Default for Settings"):]
    m = re.search(rf"\b{field}: ([^,]+),", defaults_block)
    assert m, field
    return m.group(1).strip().removesuffix(".into()").strip('"')


def test_the_wizard_starts_where_the_broker_does():
    assert float(_wizard("grant_minutes")) == defaults.GRANT_MINUTES
    assert float(_wizard("idle_minutes")) == defaults.IDLE_MINUTES
    assert int(_wizard("port")) == defaults.PORT
    assert _wizard("vault") == defaults.VAULT


def test_every_command_uses_the_shared_defaults(capsys, monkeypatch):
    import json

    monkeypatch.setattr("sys.argv", ["passbroker"])
    for args in (["api", "serve-command"],):  # service-install takes the same SERVE_OPTIONS
        cli.main(args)
        argv = json.loads(capsys.readouterr().out)["argv"]
        assert float(argv[argv.index("--grant-minutes") + 1]) == defaults.GRANT_MINUTES
        assert float(argv[argv.index("--idle-minutes") + 1]) == defaults.IDLE_MINUTES
        assert argv[argv.index("--port") + 1] == str(defaults.PORT)
