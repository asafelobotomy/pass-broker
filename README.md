# Pass Broker

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

## What protects what

| Layer | Stops |
|---|---|
| Proton Pass agent token limited to one **Agent** vault, `viewer` role, short expiry | a compromised broker reaching your real vault |
| Token stored in your system keyring, passed to `pass-cli` by environment, never argv | the token showing up in process lists or files |
| Opaque, per-run handles | the model naming items or fields it wasn't shown |
| Origin binding (page **and** frame must be HTTPS on a saved host) | prompt injection that fills your password on `evil.com` or in a cross-site iframe |
| Desktop approval per client, item, site and action (Allow lasts 10 min by default) | the assistant signing in anywhere you didn't ask for |
| Fill and submit in one step, then the field is cleared | the Secure Form problem where a filled password showed up in a page snapshot |
| Pinned fills: the field is tagged with a random nonce, and the origin of the frame, every frame above it and the page is re-checked before and after each step | a page that navigates elsewhere while you're approving, which would otherwise receive the password |
| Exact host matching (subdomains only with `--allow-subdomains`), default ports enforced | `evil.atlassian.net` matching a saved `atlassian.net` |
| Fresh browser each run, a separate session per bot, signed out after 15 idle minutes or on `end_session` (`--keep-sessions` to opt out); password saving and autofill off | an approved sign-in staying usable, with no further approval, long after you allowed it |
| The browser refuses this PC, private/LAN, CGNAT/tailnet and `.local`/`.ts.net` addresses for pages, every subresource and WebSockets. Service workers are blocked and WebRTC doesn't reveal LAN addresses | the model using the browser to reach your router, Syncthing, debug ports or other tailnet machines |
| One-digit-per-box code fields treated as secret everywhere | 2FA digits showing up in snapshots and screenshots |
| Usernames masked for the model (`a***@proton.me`) | your email landing in the assistant's chat history |
| No JavaScript tool; snapshots never read sensitive fields; every output scrubbed of every secret seen (plain, URL-, JSON- and HTML-encoded) | a page that echoes your password, or a "show password" button |
| Screenshots black out secret fields, and are refused if a secret is visible as text | pixels leaking a password |
| OAuth for remote apps: approving a connection means typing a one-time code that appears **only on your desktop**. 5 tries, 5-minute expiry, one waiting per app, at most 3 in all and 20 notifications an hour | someone else starting a sign-in and you clicking Allow by mistake |
| Only Cursor's callback host (`--oauth-redirect-host` to change) or this PC can register to receive codes; the consent page and notification name where the code goes; app names are stripped to plain text | a look-alike "Grok" app phishing a connection to itself |
| A refresh token used twice revokes the whole connection; rate limits on every sign-in endpoint; a Host check on every route; `pbc_` tokens refused through Funnel; a 10-minute pairing window | stolen refresh tokens, notification floods, DNS rebinding, phished connections |
| Funnel is turned off when the broker stops, the broker stops if the wizard dies, and a stale Funnel is cleared when the wizard starts | the broker's port staying public with nothing (or something else) behind it |
| Access tokens last 1 hour; refresh tokens last 30 days and are replaced on every use; only hashes are stored; Revoke in the app cuts a connection off at once | a leaked token staying useful |
| Fixed `pbc_` tokens for local assistants only; Host/Origin checks; binds to 127.0.0.1 | anyone else on the internet or your LAN using the broker |
| No core dumps, process not ptrace-able | other programs of yours reading the broker's memory |
| Audit log (`~/.local/state/passbroker/audit.jsonl`) plus Proton's agent audit reasons | not knowing who used what, when |

### What it can't stop

- **Bots on one Grok account aren't separated.** They share one connection and one browser (see
  step 6).
- **DNS can change between the broker's check and Chromium's own lookup.** The private-address guard
  resolves names itself and caches them for a minute, so a host that rebinds to a private address in
  that window could slip through.

- **After you sign in, the assistant can use the account.** Hiding the password doesn't hide
  what's inside. Only put logins in the Agent vault that you'd let the assistant act in.
- **Session cookies** live in the broker's browser profile on your PC
  (`~/.local/share/passbroker/profile`). Anyone with your user account can use them.
- **A site you trust that is itself compromised** (XSS on the real domain) gets your password,
  just as it would if you typed it.
- A page drawing your password into a `<canvas>` or an image can't be detected by text scrubbing.
- Pages run their own JavaScript in the same world the broker reads from. A hostile page on the
  *right* domain can lie about its fields; scrubbing is the backstop for that.
- pass-cli 2.7.0's JSON field names aren't documented. `passbroker check` (below) confirms sites and
  usernames were read, and prints the listing's key names (never values) if any website is missing.

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

A Chromium window opens. Leave it visible so you can watch what the assistant does.
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
  codes with **Access…** in the wizard (or `passbroker api bot-access NAME` with JSON on stdin).
  Bots only see what they're granted.
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

Every source file is kept to at most 400 lines; `tests/test_loc.py` enforces it. The wizard has its
own tests:

```bash
cargo test --manifest-path wizard/Cargo.toml
```
