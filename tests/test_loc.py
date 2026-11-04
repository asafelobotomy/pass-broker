"""Every source file stays at or under 400 lines."""

from pathlib import Path

LIMIT = 400
ROOT = Path(__file__).resolve().parent.parent
PATTERNS = ["src/**/*.py", "tests/**/*.py", "wizard/src/**/*.rs", "wizard/ui/**/*.slint", "wizard/build.rs"]


def test_no_file_over_limit():
    files = {p for pattern in PATTERNS for p in ROOT.glob(pattern)}
    assert files, "no source files found"
    over = {str(p.relative_to(ROOT)): n for p in sorted(files) if (n := len(p.read_text().splitlines())) > LIMIT}
    assert not over, f"files over {LIMIT} lines: {over}"
