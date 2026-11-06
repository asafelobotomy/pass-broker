"""Releasing on a version bump: notes from the CHANGELOG, and the workflows wired together."""

import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "packaging"))
import release_notes  # noqa: E402

CHANGELOG = """# Changelog

## Unreleased

- next thing

## 0.4.0

- **Big feature**
- A fix

## 0.3.1

- older
"""


def test_notes_are_that_versions_section_then_how_to_install():
    notes = release_notes.notes("0.4.0", CHANGELOG)
    assert notes.startswith("- **Big feature**\n- A fix\n")
    assert "older" not in notes and "next thing" not in notes
    assert "sha256sum -c" in notes and "Made with Slint" in notes


def test_a_version_without_a_section_is_refused():
    for version in ("0.5.0", "0.4"):
        with pytest.raises(SystemExit):
            release_notes.notes(version, CHANGELOG)
    with pytest.raises(SystemExit):
        release_notes.notes("0.4.0", "## 0.4.0\n\n## 0.3.1\n- x\n")  # empty


def test_the_changelog_has_a_section_for_the_current_or_next_version():
    text = (ROOT / "CHANGELOG.md").read_text()
    version = next(line.split('"')[1] for line in (ROOT / "pyproject.toml").read_text().splitlines() if line.startswith("version ="))
    assert f"## {version}\n" in text or "## Unreleased\n" in text


def _workflow(name: str) -> str:
    return (ROOT / ".github/workflows" / name).read_text()


def test_a_bump_on_main_tags_and_calls_the_release_build():
    tag = _workflow("release-tag.yml")
    assert "branches: [main]" in tag and "paths: [pyproject.toml]" in tag
    assert "uses: ./.github/workflows/appimage.yml" in tag and "tag: ${{ needs.tag.outputs.tag }}" in tag
    assert tag.count("contents: write") == 2  # the tag job pushes; the called workflow publishes
    for must in ("already tagged", "older than the newest release", "release_notes.py", 'git push origin "v$v"', "GITHUB_OUTPUT"):
        assert must in tag


def test_the_release_build_takes_the_tag_checks_and_publishes():
    app = _workflow("appimage.yml")
    assert "workflow_call:" in app and 'tags: ["v*"]' in app
    assert "ref: ${{ inputs.tag || '' }}" in app
    assert "packaging/appimage/verify.sh" in app and "packaging/release_notes.py" in app
    publish = app[app.index("  release:"):]
    assert "if: inputs.tag || github.ref_type == 'tag'" in publish
    assert "--draft" not in publish.replace("--draft=false", "") and "--notes-file release-notes.md" in publish and "--latest" in publish


def test_verify_refuses_a_wrong_version(tmp_path):
    fake = tmp_path / "Pass_Broker-x86_64.AppImage"
    fake.write_text("#!/bin/sh\necho passbroker 0.0.1\n")
    fake.chmod(0o755)
    subprocess.run(["sha256sum", fake.name], cwd=tmp_path, check=True, stdout=(tmp_path / f"{fake.name}.sha256").open("w"))
    out = subprocess.run([str(ROOT / "packaging/appimage/verify.sh"), "0.4.0", str(tmp_path)], capture_output=True, text=True)
    assert out.returncode != 0 and "not 'passbroker 0.4.0'" in out.stdout
