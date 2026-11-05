"""Running the broker's Chromium inside a bubblewrap box.

Chromium's own sandbox walls each page's renderer off. This is the layer around the browser
process itself, for the case where a browser bug lets a page take it over: inside the box the
system is read-only, the home folder is empty, and the only writable places are the browser's
own profile folder and a private /tmp. So a compromised browser still can't read or change your
files, SSH keys, keyring, Proton Pass session or the broker's own settings, and can't reach your
desktop session (no D-Bus or display socket). It shares only the network, which the filtering
proxy (netproxy.py) controls.

Used when bubblewrap is installed and the browser runs without a window. A window needs the
display socket, so **Own window** runs the browser unconfined (Chromium's sandbox still applies).
"""

from __future__ import annotations

import os
import shlex
import shutil
import stat
import tempfile
from pathlib import Path

HOST_DIRS = ("/bin", "/lib", "/lib64", "/sbin")  # often symlinks into /usr


def available() -> bool:
    return shutil.which("bwrap") is not None


def _layout() -> list[str]:
    """The read-only system, rebuilding /bin, /lib... as the host has them (dirs or links into /usr)."""
    args = ["--ro-bind", "/usr", "/usr", "--ro-bind", "/etc", "/etc"]
    for d in HOST_DIRS:
        if os.path.islink(d):
            args += ["--symlink", os.readlink(d), d]
        elif os.path.isdir(d):
            args += ["--ro-bind", d, d]
    for optional in ("/opt", "/var/cache/fontconfig"):
        args += ["--ro-bind-try", optional, optional]
    return args


def wrapper(chrome: str, folder: Path) -> Path:
    """Write a launcher that runs `chrome` inside the box; Playwright starts it in Chromium's place."""
    chrome = os.path.realpath(chrome)
    install = str(Path(chrome).parent.parent)  # the whole browser install (chrome-linux64/..)
    home = os.path.expanduser("~")
    fixed = [
        "bwrap", "--die-with-parent", "--new-session",
        "--unshare-pid", "--unshare-ipc", "--unshare-uts", "--unshare-cgroup-try",
        *_layout(),
        "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/dev/shm",
        "--tmpfs", "/tmp", "--tmpfs", "/var/tmp", "--tmpfs", "/run",
        "--tmpfs", home, "--ro-bind", install, install,
        "--setenv", "HOME", home,
        "--unsetenv", "DBUS_SESSION_BUS_ADDRESS", "--unsetenv", "WAYLAND_DISPLAY", "--unsetenv", "DISPLAY",
        "--unsetenv", "XAUTHORITY", "--unsetenv", "SSH_AUTH_SOCK",
    ]
    common = " ".join(shlex.quote(a) for a in fixed)
    script = f"""#!/bin/sh
# Written by Pass Broker: Chromium in a bubblewrap box (see passbroker/confine.py).
UDD=
for a; do case $a in --user-data-dir=*) UDD=${{a#--user-data-dir=}};; esac; done
if [ -n "$UDD" ]; then
    exec {common} --bind "$UDD" "$UDD" -- {shlex.quote(chrome)} "$@"
fi
exec {common} -- {shlex.quote(chrome)} "$@"
"""
    folder.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = folder / "chrome"
    path.write_text(script)
    path.chmod(stat.S_IRWXU)
    return path


def private_folder() -> Path:
    return Path(tempfile.mkdtemp(prefix="passbroker-browser-"))


def sandbox_status() -> tuple[bool, str]:
    """Whether Chromium's sandbox can start: it needs unprivileged user namespaces."""
    def read(path: str) -> str | None:
        try:
            return Path(path).read_text().strip()
        except OSError:
            return None

    if read("/proc/sys/kernel/unprivileged_userns_clone") == "0":
        return False, "user namespaces are switched off (sysctl kernel.unprivileged_userns_clone=1 turns them on)"
    if read("/proc/sys/user/max_user_namespaces") == "0":
        return False, "user namespaces are switched off (sysctl user.max_user_namespaces)"
    if read("/proc/sys/kernel/apparmor_restrict_unprivileged_userns") == "1":
        return False, "AppArmor blocks it (Ubuntu): sysctl kernel.apparmor_restrict_unprivileged_userns=0, or see the README"
    return True, "available"


def confinement_status() -> tuple[bool, str]:
    if available():
        return True, "bubblewrap found: the browser runs boxed off from your files"
    return False, "install bubblewrap for an extra layer around the browser"
