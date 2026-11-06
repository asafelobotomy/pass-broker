"""Release notes for vX.Y.Z: that version's CHANGELOG section, then how to install and the
Slint credit. Used by the release workflow; fails if the version has no section.

    python packaging/release_notes.py 0.4.0 > notes.md
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

INSTALL = """
---

**Pass_Broker-x86_64.AppImage** runs on any desktop Linux with glibc 2.35 or newer (Ubuntu 22.04, Debian 13, Fedora 36 and later).

```bash
sha256sum -c Pass_Broker-x86_64.AppImage.sha256
chmod +x Pass_Broker-x86_64.AppImage
./Pass_Broker-x86_64.AppImage
```

If you use **Run in the background** or **Open Pass Broker when I log in**, replace the old AppImage file in the same place, then Stop and Start the broker once.

`THIRD_PARTY_LICENSES` lists every library inside, with its licence.

The wizard's interface is built with [Slint](https://slint.dev), used under its royalty-free licence.

[![Made with Slint](https://raw.githubusercontent.com/slint-ui/slint/master/logo/MadeWithSlint-logo-whitebg.png)](https://slint.dev)
"""


def section(changelog: str, version: str) -> str:
    """The text under `## <version>`, up to the next `## `."""
    m = re.search(rf"^## {re.escape(version)}[ \t]*\n(.*?)(?=^## |\Z)", changelog, re.M | re.S)
    if not m or not m.group(1).strip():
        raise SystemExit(f"CHANGELOG.md has no '## {version}' section with something in it")
    return m.group(1).strip()


def notes(version: str, changelog: str | None = None) -> str:
    text = changelog if changelog is not None else (ROOT / "CHANGELOG.md").read_text()
    return section(text, version) + "\n" + INSTALL


if __name__ == "__main__":
    if len(sys.argv) != 2 or not re.fullmatch(r"\d+\.\d+\.\d+", sys.argv[1]):
        raise SystemExit("usage: release_notes.py X.Y.Z")
    sys.stdout.write(notes(sys.argv[1]))
