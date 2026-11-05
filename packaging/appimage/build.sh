#!/usr/bin/env bash
# Build Pass_Broker-x86_64.AppImage: the wizard, a relocatable Python with the broker and
# its locked dependencies, and the AppImage runtime.
#
# Not bundled (the wizard's Requirements step checks them, and installs Chromium on first
# run into ~/.cache/ms-playwright): Proton Pass CLI, Chromium, Tailscale, notify-send,
# gpg, openssl, 7z.
#
# Built from the committed source only (git archive HEAD), so stray local files never get in,
# and reproducibly: a fixed Python, timestamps from the last commit, hash-checked .pyc files and
# no build paths in the wizard. Commit first; BUILD_DIRTY=1 builds the working tree as it is.
#
# Needs: git, cargo, uv, mksquashfs (4.4+), curl, sha256sum.
# Output: dist/Pass_Broker-x86_64.AppImage and dist/THIRD_PARTY_LICENSES
set -euo pipefail
export LC_ALL=C TZ=UTC

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PYVER="${PYVER:-3.12.14}"  # exact: a different patch release would change the build
PYMINOR="${PYVER%.*}"
# The AppImage runtime (https://github.com/AppImage/type2-runtime), pinned and checked.
RUNTIME_TAG="20251108"
RUNTIME_SHA256="2fca8b443c92510f1483a883f60061ad09b46b978b2631c807cd873a47ec260d"
RUNTIME_URL="https://github.com/AppImage/type2-runtime/releases/download/$RUNTIME_TAG/runtime-x86_64"

BUILD="$ROOT/build/appimage"
APPDIR="$BUILD/AppDir"
OUT="$ROOT/dist/Pass_Broker-x86_64.AppImage"
SRC="$BUILD/src"
rm -rf "$APPDIR" "$SRC"
mkdir -p "$APPDIR/usr/bin" "$ROOT/dist" "$BUILD" "$SRC"

echo "==> source"
if [ "${BUILD_DIRTY:-0}" = 1 ]; then
    git -C "$ROOT" ls-files -z --cached --others --exclude-standard | (cd "$ROOT" && xargs -0 tar -c) | tar -x -C "$SRC"
    SOURCE_DATE_EPOCH="$(date +%s)"
else
    if [ -n "$(git -C "$ROOT" status --porcelain)" ]; then
        echo "note: uncommitted changes are left out (BUILD_DIRTY=1 includes them)" >&2
    fi
    git -C "$ROOT" archive HEAD | tar -x -C "$SRC"
    SOURCE_DATE_EPOCH="$(git -C "$ROOT" log -1 --format=%ct)"
fi
export SOURCE_DATE_EPOCH

echo "==> wizard"
# Reuses the checkout's target folder as a cache; the paths baked into the binary are remapped.
export CARGO_TARGET_DIR="$ROOT/wizard/target/appimage"
export RUSTFLAGS="${RUSTFLAGS:-} --remap-path-prefix=$SRC=/src --remap-path-prefix=$CARGO_TARGET_DIR=/target --remap-path-prefix=${CARGO_HOME:-$HOME/.cargo}=/cargo"
(cd "$SRC/wizard" && cargo build --release --locked)
install -m755 "$CARGO_TARGET_DIR/release/passbroker-wizard" "$APPDIR/usr/bin/"

echo "==> Python $PYVER (python-build-standalone, via uv)"
uv python install "$PYVER" >/dev/null
PYBIN="$(readlink -f "$(uv python find --managed-python "$PYVER")")"
PYROOT="$(dirname "$(dirname "$PYBIN")")"
cp -a "$PYROOT" "$APPDIR/usr/python"
PY="$APPDIR/usr/python/bin/python3"
PYLIB="$APPDIR/usr/python/lib/python$PYMINOR"
# uv marks its Pythons as externally managed; this copy is ours to install into.
rm -f "$PYLIB/EXTERNALLY-MANAGED"
# What a broker never needs: tests, Tk, IDLE, headers, docs.
rm -rf "$PYLIB/test" "$PYLIB/idlelib" "$PYLIB/tkinter" "$PYLIB/turtledemo" "$PYLIB/lib2to3" \
       "$APPDIR/usr/python/include" "$APPDIR/usr/python/share" \
       "$APPDIR"/usr/python/lib/libtcl* "$APPDIR"/usr/python/lib/libtk* "$APPDIR"/usr/python/lib/tcl* "$APPDIR"/usr/python/lib/tk* \
       "$PYLIB"/lib-dynload/_tkinter*

echo "==> broker and its locked dependencies"
(cd "$SRC" && uv export --frozen --no-dev --no-emit-project --no-hashes -q) > "$BUILD/requirements.txt"
uv pip install --python "$PY" --no-cache -q -r "$BUILD/requirements.txt"
uv pip install --python "$PY" --no-cache -q --no-deps "$SRC"
# Installing is done here, at build time; the AppImage never needs pip.
rm -rf "$PYLIB"/site-packages/pip "$PYLIB"/site-packages/pip-*

echo "==> no build paths or install times in the result"
# The broker always runs as `python -m`, so the console scripts (whose first line names this
# build folder) and the build-only helpers go.
find "$APPDIR/usr/python/bin" -mindepth 1 ! -name 'python3.*[0-9]' ! -name python3 ! -name python -delete
# uv's install records: where it was installed from (a path in your home) and when.
for info in "$PYLIB"/site-packages/*.dist-info; do
    rm -f "$info/direct_url.json" "$info/uv_cache.json"
    [ -f "$info/RECORD" ] && sed -i -e '/\/direct_url\.json,/d' -e '/\/uv_cache\.json,/d' "$info/RECORD"
done
# uv points the interpreter's build settings at where it installed it; put back the neutral
# prefix python-build-standalone ships with (they're only used to compile C extensions).
sed -i "s|$PYROOT|/install|g" "$PYLIB"/_sysconfigdata_*.py
find "$APPDIR/usr/python" -name "__pycache__" -prune -exec rm -rf {} +
# Hash-checked .pyc files don't record when the sources were installed, and name each source by
# its path inside the AppImage, not in this build folder.
"$PY" -I -B -m compileall -f -q -j0 --invalidation-mode unchecked-hash -s "$APPDIR" -p / "$PYLIB" >/dev/null || true

echo "==> licences"
DOC="$APPDIR/usr/share/doc/pass-broker"
mkdir -p "$DOC"
install -m644 "$SRC/LICENSE" "$DOC/LICENSE"
(cd "$SRC/wizard" && "$PY" -I -B "$SRC/packaging/licenses.py" . "$PYLIB/site-packages" "$DOC/THIRD_PARTY_LICENSES")
cp "$DOC/THIRD_PARTY_LICENSES" "$ROOT/dist/THIRD_PARTY_LICENSES"

cat > "$APPDIR/usr/bin/passbroker" <<'EOF'
#!/bin/sh
exec "$(dirname "$(readlink -f "$0")")/../python/bin/python3" -I -m passbroker.cli "$@"
EOF
chmod 755 "$APPDIR/usr/bin/passbroker"

# Python run without -B above would have left .pyc files naming this build folder.
if grep -rl --binary-files=binary -e "$APPDIR" -e "$PYROOT" -e "$SRC" -e "$HOME/" "$APPDIR" | grep . ; then
    echo "build paths left in the files above" >&2; exit 1
fi

echo "==> AppDir metadata"
install -m755 "$SRC/packaging/appimage/AppRun" "$APPDIR/AppRun"
install -m644 "$SRC/packaging/appimage/pass-broker.desktop" "$APPDIR/pass-broker.desktop"
install -m644 "$SRC/wizard/ui/icon.svg" "$APPDIR/pass-broker.svg"
ln -sf pass-broker.svg "$APPDIR/.DirIcon"

echo "==> AppImage runtime $RUNTIME_TAG"
RUNTIME="$BUILD/runtime-x86_64-$RUNTIME_TAG"
if [ ! -f "$RUNTIME" ]; then
    curl -fsSL --proto '=https' --tlsv1.2 -o "$RUNTIME.part" "$RUNTIME_URL"
    mv "$RUNTIME.part" "$RUNTIME"
fi
echo "$RUNTIME_SHA256  $RUNTIME" | sha256sum -c --quiet - || { rm -f "$RUNTIME"; echo "runtime checksum mismatch" >&2; exit 1; }

echo "==> squashfs and AppImage"
# Every file gets the last commit's time (mksquashfs 4.4+ reads SOURCE_DATE_EPOCH and orders
# its output the same way every run).
rm -f "$BUILD/app.squashfs"
mksquashfs "$APPDIR" "$BUILD/app.squashfs" -root-owned -noappend -comp zstd -Xcompression-level 19 -quiet -no-progress
cat "$RUNTIME" "$BUILD/app.squashfs" > "$OUT.part"
chmod 755 "$OUT.part"
mv "$OUT.part" "$OUT"
echo "Built $OUT ($(du -h "$OUT" | cut -f1))"
