"""The broker, the wizard and both lock files carry one version, so any commit can be tagged."""

import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _locked(path: Path, name: str) -> str:
    return next(p["version"] for p in tomllib.loads(path.read_text())["package"] if p["name"] == name)


def test_one_version_everywhere():
    py = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["version"]
    rs = tomllib.loads((ROOT / "wizard/Cargo.toml").read_text())["package"]["version"]
    assert re.fullmatch(r"\d+\.\d+\.\d+", py)
    assert {
        "pyproject.toml": py,
        "wizard/Cargo.toml": rs,
        "uv.lock": _locked(ROOT / "uv.lock", "passbroker"),
        "wizard/Cargo.lock": _locked(ROOT / "wizard/Cargo.lock", "passbroker-wizard"),
    } == dict.fromkeys(["pyproject.toml", "wizard/Cargo.toml", "uv.lock", "wizard/Cargo.lock"], py), \
        "run packaging/bump.sh X.Y.Z to set them all"
