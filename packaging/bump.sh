#!/usr/bin/env bash
# Set the version everywhere it's recorded, so a release tag matches the source:
#
#     packaging/bump.sh 0.3.0
#
# Updates pyproject.toml and wizard/Cargo.toml, then their lock files (only Pass Broker's own
# entry; no dependency changes), and turns CHANGELOG.md's "## Unreleased" into "## X.Y.Z"
# (those become the release notes). Then commit and push to main: the release-tag workflow
# sees the new version, tags vX.Y.Z, builds the AppImage and publishes the release.
set -euo pipefail

NEW="${1:-}"
if ! [[ "$NEW" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "usage: $0 X.Y.Z" >&2
    exit 2
fi
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
OLD="$(sed -n 's/^version = "\(.*\)"/\1/p' pyproject.toml | head -1)"
if git rev-parse -q --verify "refs/tags/v$NEW" >/dev/null; then
    echo "v$NEW is already tagged" >&2
    exit 1
fi

# The release notes come from CHANGELOG.md: the version needs a section with something in it.
if grep -q "^## $NEW\b" CHANGELOG.md; then
    :
elif grep -q "^## Unreleased" CHANGELOG.md; then
    sed -i "0,/^## Unreleased[[:space:]]*$/s//## $NEW/" CHANGELOG.md
else
    echo "CHANGELOG.md needs a '## Unreleased' (or '## $NEW') section saying what changed" >&2
    exit 1
fi
python3 packaging/release_notes.py "$NEW" >/dev/null

# The first `version =` in each manifest is the package's own.
sed -i "0,/^version = \".*\"/s//version = \"$NEW\"/" pyproject.toml wizard/Cargo.toml
uv lock -q
(cd wizard && cargo update -q --offline -p passbroker-wizard)

for f in pyproject.toml wizard/Cargo.toml uv.lock wizard/Cargo.lock; do
    git diff --quiet -- "$f" && { echo "$f didn't change" >&2; exit 1; }
done
echo "$OLD -> $NEW in pyproject.toml, wizard/Cargo.toml, uv.lock, wizard/Cargo.lock and CHANGELOG.md"
echo "Now commit and push to main; the release follows by itself."
