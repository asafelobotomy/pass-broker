#!/usr/bin/env bash
# Check a built AppImage before it's released, the checks once done by hand:
#
#     packaging/appimage/verify.sh X.Y.Z [dist]
#
# - it reports version X.Y.Z;
# - nothing in it needs a glibc newer than 2.35 (Ubuntu 22.04, the oldest we support);
# - the THIRD_PARTY_LICENSES beside it is the one inside;
# - its checksum file matches.
set -euo pipefail

WANT="${1:?usage: verify.sh X.Y.Z [dist]}"
DIST="$(cd "${2:-dist}" && pwd)"
APP="$DIST/Pass_Broker-x86_64.AppImage"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

(cd "$DIST" && sha256sum -c --quiet Pass_Broker-x86_64.AppImage.sha256)

got="$(APPIMAGE_EXTRACT_AND_RUN=1 "$APP" passbroker --version)"
[ "$got" = "passbroker $WANT" ] || { echo "::error::the AppImage says '$got', not 'passbroker $WANT'"; exit 1; }

(cd "$WORK" && "$APP" --appimage-extract >/dev/null)
root="$WORK/squashfs-root"

newest="$(find "$root" -type f -exec sh -c 'head -c4 "$1" | grep -q "ELF" && objdump -T "$1" 2>/dev/null' _ {} \; \
          | grep -o 'GLIBC_[0-9.]*' | sort -uV | tail -1)"
echo "newest glibc needed: ${newest:-none}"
if [ -n "$newest" ] && [ "$(printf '%s\n%s\n' "$newest" GLIBC_2.35 | sort -V | tail -1)" != GLIBC_2.35 ]; then
    echo "::error::it needs $newest; it must run with GLIBC_2.35"
    exit 1
fi

cmp -s "$DIST/THIRD_PARTY_LICENSES" "$root/usr/share/doc/pass-broker/THIRD_PARTY_LICENSES" \
    || { echo "::error::THIRD_PARTY_LICENSES differs from the one inside the AppImage"; exit 1; }
echo "verified: version $WANT, glibc <= 2.35, licences match, checksum ok"
