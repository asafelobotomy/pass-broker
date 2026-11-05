"""The command line, the wizard's API and the wizard itself start from the same defaults."""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _python_defaults(name: str) -> set[float]:
    found = set()
    for f in ("cli.py", "api.py", "api_service.py"):
        text = (ROOT / "src/passbroker" / f).read_text()
        found |= {float(v) for v in re.findall(rf'"--{name}"\)?,\s*(?:\{{"type": float, "default": |type=float, default=)([\d.]+)', text)}
    return found


def _wizard_default(field: str) -> float:
    m = re.search(rf"\b{field}: (\d+),", (ROOT / "wizard/src/state.rs").read_text())
    assert m, field
    return float(m.group(1))


def test_one_allow_lasts_as_long_everywhere():
    assert _python_defaults("grant-minutes") == {_wizard_default("grant_minutes")}


def test_idle_sign_out_is_the_same_everywhere():
    assert _python_defaults("idle-minutes") == {_wizard_default("idle_minutes")}
