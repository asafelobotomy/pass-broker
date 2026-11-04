"""The Control center's live view of the hidden browser."""

import json

from passbroker.preview import INDEX, WATCHING, Preview, frame_name

from .site import PASSWORD, TOTP
from .test_broker import make, site  # noqa: F401  (fixtures)


def index(folder):
    return json.loads((folder / INDEX).read_text())


async def test_frames_only_while_watched(make, site, tmp_path):  # noqa: F811
    broker, _, _ = await make()
    folder = tmp_path / "preview"
    p = Preview(broker.browser, broker.redactor, folder)
    await p.start()
    s = await broker.browser.session("conn/grok")
    await s.navigate(site.url("/login"))
    used = s.last_use

    await p.tick()
    assert not (folder / INDEX).exists() and not list(folder.glob("*.jpg"))

    (folder / WATCHING).touch()
    await p.tick()
    entry = index(folder)["sessions"][0]
    assert entry["bot"] == "grok" and entry["url"].endswith("/login") and not entry["withheld"]
    assert (folder / frame_name("conn/grok")).read_bytes().startswith(b"\xff\xd8")  # JPEG
    assert s.last_use == used  # watching doesn't keep an idle session signed in
    assert (folder / frame_name("conn/grok")).stat().st_mode & 0o077 == 0

    await broker.browser.end_session("conn/grok")
    await p.tick()
    assert index(folder)["sessions"] == [] and not list(folder.glob("*.jpg"))

    await p.stop()
    assert not list(folder.iterdir())


async def test_no_frame_while_a_secret_shows(make, site, tmp_path):  # noqa: F811
    broker, logins, _ = await make()
    folder = tmp_path / "preview"
    p = Preview(broker.browser, broker.redactor, folder)
    await p.start()
    (folder / WATCHING).touch()
    s = await broker.browser.session("conn/grok")
    await s.navigate(site.url("/leaky"))
    await broker.fill_login("conn/grok", logins["Test Site"])
    await p.tick()
    assert index(folder)["sessions"][0]["withheld"]
    assert not list(folder.glob("*.jpg"))
    text = (folder / INDEX).read_text()
    assert PASSWORD not in text and TOTP not in text
    await p.stop()
