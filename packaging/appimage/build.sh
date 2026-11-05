#!/usr/bin/env bash
# Build Pass_Broker-x86_64.AppImage: the wizard, a relocatable Python with the broker and
# its locked dependencies, and the AppImage runtime.
#
# Not bundled (the wizard's Requirements step checks them, and installs Chromium on first
# run into ~/.cache/ms-playwright): Proton Pass CLI, Chromium, Tailscale, notify-send,
# gpg, openssl, 7z.
#
# Needs: cargo, uv, mksquashfs, curl, sha256sum. Output: dist/Pass_Broker-x86_64.AppImage
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
HERE="$ROOT/packaging/appimage"
PYVER="${PYVER:-3.12}"
# The AppImage runtime (https://github.com/AppImage/type2-runtime), pinned and checked.
RUNTIME_TAG="20251108"
RUNTIME_SHA256="2fca8b443c92510f1483a883f60061ad09b46b978b2631c807cd873a47ec260d"
RUNTIME_URL="https://github.com/AppImage/type2-runtime/releases/download/$RUNTIME_TAG/runtime-x86_64"

BUILD="$ROOT/build/appimage"
APPDIR="$BUILD/AppDir"
OUT="$ROOT/dist/Pass_Broker-x86_64.AppImage"
rm -rf "$APPDIR"
mkdir -p "$APPDIR/usr/bin" "$ROOT/dist" "$BUILD"

echo "==> wizard"
(cd "$ROOT/wizard" && cargo build --release --locked)
install -m755 "$ROOT/wizard/target/release/passbroker-wizard" "$APPDIR/usr/bin/"

echo "==> Python $PYVER (python-build-standalone, via uv)"
uv python install "$PYVER" >/dev/null
PYBIN="$(readlink -f "$(uv python find --managed-python "$PYVER")")"
PYROOT="$(dirname "$(dirname "$PYBIN")")"
cp -a "$PYROOT" "$APPDIR/usr/python"
PY="$APPDIR/usr/python/bin/python3"
PYLIB="$APPDIR/usr/python/lib/python$PYVER"
# uv marks its Pythons as externally managed; this copy is ours to install into.
rm -f "$PYLIB/EXTERNALLY-MANAGED"
# What a broker never needs: tests, Tk, IDLE, headers, docs.
rm -rf "$PYLIB/test" "$PYLIB/idlelib" "$PYLIB/tkinter" "$PYLIB/turtledemo" "$PYLIB/lib2to3" \
       "$APPDIR/usr/python/include" "$APPDIR/usr/python/share" \
       "$APPDIR"/usr/python/lib/libtcl* "$APPDIR"/usr/python/lib/libtk* "$APPDIR"/usr/python/lib/tcl* "$APPDIR"/usr/python/lib/tk* \
       "$PYLIB"/lib-dynload/_tkinter*

echo "==> broker and its locked dependencies"
(cd "$ROOT" && uv export --frozen --no-dev --no-emit-project --no-hashes -q) > "$BUILD/requirements.txt"
uv pip install --python "$PY" --no-cache -q -r "$BUILD/requirements.txt"
uv pip install --python "$PY" --no-cache -q --no-deps "$ROOT"
# Installing is done here, at build time; the AppImage never needs pip.
rm -rf "$PYLIB"/site-packages/pip "$PYLIB"/site-packages/pip-* "$APPDIR"/usr/python/bin/pip*
find "$APPDIR/usr/python" -name "__pycache__" -prune -exec rm -rf {} +
"$PY" -I -m compileall -q -j0 "$PYLIB" >/dev/null || true

cat > "$APPDIR/usr/bin/passbroker" <<'EOF'
#!/bin/sh
exec "$(dirname "$(readlink -f "$0")")/../python/bin/python3" -I -m passbroker.cli "$@"
EOF
chmod 755 "$APPDIR/usr/bin/passbroker"

echo "==> AppDir metadata"
install -m755 "$HERE/AppRun" "$APPDIR/AppRun"
install -m644 "$HERE/pass-broker.desktop" "$APPDIR/pass-broker.desktop"
install -m644 "$ROOT/wizard/ui/icon.svg" "$APPDIR/pass-broker.svg"
ln -sf pass-broker.svg "$APPDIR/.DirIcon"

echo "==> AppImage runtime $RUNTIME_TAG"
RUNTIME="$BUILD/runtime-x86_64-$RUNTIME_TAG"
if [ ! -f "$RUNTIME" ]; then
    curl -fsSL --proto '=https' --tlsv1.2 -o "$RUNTIME.part" "$RUNTIME_URL"
    mv "$RUNTIME.part" "$RUNTIME"
fi
echo "$RUNTIME_SHA256  $RUNTIME" | sha256sum -c --quiet - || { rm -f "$RUNTIME"; echo "runtime checksum mismatch" >&2; exit 1; }

echo "==> squashfs and AppImage"
mksquashfs "$APPDIR" "$BUILD/app.squashfs" -root-owned -noappend -comp zstd -Xcompression-level 19 -quiet
cat "$RUNTIME" "$BUILD/app.squashfs" > "$OUT.part"
chmod 755 "$OUT.part"
mv "$OUT.part" "$OUT"
echo "Built $OUT ($(du -h "$OUT" | cut -f1))"
