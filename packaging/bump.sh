#!/usr/bin/env bash
# Set the version everywhere it's recorded, so a release tag matches the source:
#
#     packaging/bump.sh 0.3.0
#
# Updates pyproject.toml and wizard/Cargo.toml, then their lock files (only Pass Broker's own
# entry; no dependency changes). Then commit, tag vX.Y.Z and push the tag: the AppImage
# workflow checks the tag matches and drafts the release.
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

# The first `version =` in each manifest is the package's own.
sed -i "0,/^version = \".*\"/s//version = \"$NEW\"/" pyproject.toml wizard/Cargo.toml
uv lock -q
(cd wizard && cargo update -q --offline -p passbroker-wizard)

for f in pyproject.toml wizard/Cargo.toml uv.lock wizard/Cargo.lock; do
    git diff --quiet -- "$f" && { echo "$f didn't change" >&2; exit 1; }
done
echo "$OLD -> $NEW in pyproject.toml, wizard/Cargo.toml, uv.lock and wizard/Cargo.lock"
