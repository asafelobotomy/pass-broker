"""Write THIRD_PARTY_LICENSES: every library the AppImage ships, with its licence text.

    python3 -I packaging/licenses.py WIZARD_DIR SITE_PACKAGES OUT

Rust: the wizard's normal (linked) dependencies for x86_64 Linux, from `cargo metadata`, with
the licence files each crate ships. Python: every distribution installed in SITE_PACKAGES,
with the licence files in its .dist-info. Build-only tools aren't shipped, so aren't listed.
"""

from __future__ import annotations

import json
import subprocess
import sys
from importlib.metadata import distributions
from pathlib import Path

TARGET = "x86_64-unknown-linux-gnu"
NAMES = ("LICENSE", "LICENCE", "COPYING", "COPYRIGHT", "NOTICE", "UNLICENSE")


def _licence_files(folder: Path) -> list[Path]:
    found = [p for p in folder.iterdir() if p.is_file() and p.name.upper().startswith(NAMES)]
    for sub in ("LICENSES", "licenses", "license_files"):
        if (folder / sub).is_dir():
            found += [p for p in (folder / sub).rglob("*") if p.is_file()]
    return sorted(set(found))


def rust(wizard: Path) -> list[tuple[str, str, list[Path]]]:
    meta = json.loads(subprocess.run(
        ["cargo", "metadata", "--format-version", "1", "--locked", "--filter-platform", TARGET],
        cwd=wizard, check=True, capture_output=True, text=True).stdout)
    packages = {p["id"]: p for p in meta["packages"]}
    nodes = {n["id"]: n for n in meta["resolve"]["nodes"]}
    root = meta["resolve"]["root"]
    seen, todo = set(), [root]
    while todo:  # follow only dependencies that end up linked in (not build or dev ones)
        node = nodes[todo.pop()]
        for dep in node["deps"]:
            if any(k["kind"] is None for k in dep["dep_kinds"]) and dep["pkg"] not in seen:
                seen.add(dep["pkg"])
                todo.append(dep["pkg"])
    out = []
    for pid in sorted(seen, key=lambda i: (packages[i]["name"], packages[i]["version"])):
        p = packages[pid]
        out.append((f"{p['name']} {p['version']}", p.get("license") or "see files",
                    _licence_files(Path(p["manifest_path"]).parent)))
    return out


def python(site: Path) -> list[tuple[str, str, list[Path]]]:
    out = []
    for d in sorted(distributions(path=[str(site)]), key=lambda d: d.metadata["Name"].lower()):
        name = d.metadata["Name"]
        if name.lower() == "passbroker":
            continue
        licence = d.metadata.get("License-Expression") or d.metadata.get("License") or ""
        if not licence or len(licence) > 80:  # some put the whole text in License
            classifiers = [c.split(" :: ")[-1] for c in d.metadata.get_all("Classifier") or [] if c.startswith("License ::")]
            licence = ", ".join(classifiers) or "see files"
        info = Path(str(d._path))  # type: ignore[attr-defined]  # the .dist-info folder
        out.append((f"{name} {d.version}", licence, _licence_files(info)))
    return out


def write(out: Path, sections: dict[str, list[tuple[str, str, list[Path]]]]) -> None:
    lines = ["Pass Broker is MIT-licensed (see LICENSE). It includes the libraries below, each under",
             "its own licence. Slint is used under the Slint Royalty-free Desktop, Mobile, and Web",
             "Applications License 2.0 (attribution: Settings > About).", ""]
    for title, items in sections.items():
        lines += ["=" * 78, title, "=" * 78, ""]
        for name, licence, files in items:
            lines += ["-" * 78, f"{name}  ({licence})", "-" * 78]
            for f in files:
                text = f.read_text(errors="replace").strip()
                lines += [f"[{f.name}]", text, ""]
            if not files:
                lines += ["(no licence file shipped with the package; licence as stated above)", ""]
    out.write_text("\n".join(lines) + "\n")


def main() -> None:
    wizard, site, out = (Path(a) for a in sys.argv[1:4])
    write(out, {"Wizard (Rust crates)": rust(wizard), "Broker (Python packages)": python(site)})
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
