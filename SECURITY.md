# Security

Pass Broker exists to keep secrets away from AI assistants, so security reports
are very welcome.

## Reporting a vulnerability

Please report privately through GitHub: **Security → Report a vulnerability** on
this repository (private vulnerability reporting). Don't open a public issue for
anything that could help someone extract a secret, bypass an approval or reach
the broker without authorisation. You'll get an answer within a week.

In scope: anything that lets an assistant, a web page, a file being unlocked,
another bot, or someone on the internet see a password, passphrase, code or
token; act without your approval; reach this PC's or your LAN's services through
the broker; or tamper with its records unnoticed.

## Supported versions

Fixes go into the latest release only, so please update before reporting. Check yours in
**Settings › About** or with `passbroker --version`.

## Threat model

The broker assumes the AI model may be careless or prompt-injected, the web
pages and files it handles may be hostile, other bots on the same assistant
account may misbehave, and anyone on the internet can reach the public address.
It does **not** defend against malware already running as your user: such a
program can read your keyring and the broker's files directly.

## What protects what

| Layer | Stops |
|---|---|
| Proton Pass agent token limited to one **Agent** vault, `viewer` role, short expiry; if you turn on bot accounts, `editor` on their own separate vault and nowhere else | a compromised broker reaching your real vault, or changing or deleting the logins you put in the Agent vault |
| Bot-made accounts: off until you set them up, then per bot; each needs your Allow (site, vault, username or alias shown), at most 10 a day per bot; Proton Pass generates the password (never on a command line), the login is bound to the sign-up page's host and granted only to the bot that made it | a bot filling your vault with accounts, or learning or reusing a password it had made |
| Token stored in your system keyring, passed to `pass-cli` by environment, never argv | the token showing up in process lists or files |
| Opaque, per-run handles | the model naming items or fields it wasn't shown |
| Origin binding (page **and** frame must be HTTPS on a saved host) | prompt injection that fills your password on `evil.com` or in a cross-site iframe |
| Desktop approval per bot, item, site and action, showing the bot's stated reason (one Allow lasts 2 minutes by default), in a notification and in the app; pending requests live in memory (`$XDG_RUNTIME_DIR`), readable only by you | the assistant signing in anywhere you didn't ask for |
| Fill and submit in one step, then the field is cleared | the Secure Form problem where a filled password showed up in a page snapshot |
| Pinned fills: the field is tagged with a random nonce, and the origin of the frame, every frame above it and the page is re-checked before and after each step | a page that navigates elsewhere while you're approving, which would otherwise receive the password |
| Exact host matching (subdomains only with `--allow-subdomains`), default ports enforced | `evil.atlassian.net` matching a saved `atlassian.net` |
| Fresh browser each run, a separate session per bot, signed out after 15 idle minutes or on `end_session` (`--keep-sessions` to opt out); password saving and autofill off | an approved sign-in staying usable, with no further approval, long after you allowed it |
| Every browser connection goes through a filtering proxy inside the broker (password-protected, on 127.0.0.1). It resolves each host itself, refuses this PC, private/LAN, CGNAT/tailnet and `.local`/`.ts.net` addresses (and hosts that don't resolve), and connects to exactly the address it checked: pages, every redirect hop, frames, scripts and WebSockets. Service workers are blocked and WebRTC sends nothing outside the proxy | the model using the browser to reach your router, Syncthing, debug ports or other tailnet machines, including through a redirect or DNS rebinding |
| One-digit-per-box code fields treated as secret everywhere | 2FA digits showing up in snapshots and screenshots |
| Usernames masked for the model (`a***@proton.me`), in snapshots and screenshots, and filled through the same pinned-field check as passwords | your email landing in the assistant's chat history, or in a frame that changed origin mid-fill |
| Personal details on pages (emails, phone, card and bank numbers) masked in what a bot reads and blacked out in its screenshots, unless you allow that bot | your details piling up in chat histories, which have leaked (indexed shared chats) |
| Optional per-bot site list: page loads, clicks, popups and redirects outside the listed sites and the bot's login sites are refused and logged | a tricked bot sending page data to an attacker's URL through the broker's browser |
| Optional per-bot blocked pages: never loaded (the tab stays put), left at once if a site switches to one without loading, and never filled | a bot reading or acting on pages you keep for yourself (payment methods, security settings) on sites it may otherwise use |
| No JavaScript tool; snapshots never read sensitive fields; every output scrubbed of every secret seen (plain, wholly or partly URL-encoded in either case, JSON-, HTML- and base64-encoded at any offset, as inside `Basic` auth, and codes split up as `482 913`), before personal details are masked | a page that echoes your password, or a "show password" button |
| Invisible characters (zero-width, text-direction controls, Unicode tag characters) removed from everything the bot gets and from approval notifications | instructions hidden in page text for the model ("ASCII smuggling"), a secret split by invisible characters to dodge scrubbing, a bot's reason that reads differently from what it says |
| Playwright and Node debugging variables (`DEBUG`, `PWDEBUG`, `NODE_OPTIONS`, `PW_*`…) removed before the browser starts | every fill, password included, being logged to stderr or a file outside the scrubbed logs |
| Tokens copied from the wizard are marked for clipboard managers to skip, and cleared after 60 seconds | a token kept in Klipper's saved clipboard history |
| The browser runs hidden; the Control center's live view is masked like bot screenshots, kept in memory and made only while watched | screen recorders or screenshot tools capturing the browser |
| Screenshots black out secret fields, and are refused if a secret is visible as text | pixels leaking a password |
| Chromium runs with its own sandbox (Playwright turns it off by default) and won't start without it unless you set `PASSBROKER_ALLOW_UNSANDBOXED=1`; with bubblewrap installed, the browser runs in a box where the system is read-only, the home folder is empty and there's no D-Bus or display socket (only its profile folder is writable) | a malicious page exploiting the renderer or the browser and reaching your files, SSH keys, keyring, Proton Pass session or desktop |
| The tab may only show http(s) pages (checked after every load); every permission prompt is denied (camera, microphone, location, notifications, clipboard, USB/serial/HID/Bluetooth); dialogs are dismissed and file pickers swallowed; bots may press only plain keys, never Control, Alt or Meta shortcuts | a page or bot opening `chrome://settings` or flags, `file://`, another program's link, your clipboard (Ctrl+V), or your files through a picker |
| OAuth for remote apps: approving a connection means typing a one-time code that appears **only on your desktop**. 5 tries, 5-minute expiry, one waiting per app, at most 3 in all and 20 notifications an hour | someone else starting a sign-in and you clicking Allow by mistake |
| Only Cursor's callback host (`--oauth-redirect-host` to change) or this PC can register to receive codes; the consent page and notification name where the code goes; app names are stripped to plain text | a look-alike "Grok" app phishing a connection to itself |
| A refresh token used twice revokes the whole connection; rate limits on every sign-in endpoint; a Host check on every route; `pbc_` tokens refused through Funnel (recognised by Tailscale's own `Tailscale-Funnel-Request` header, whatever Host the request claims); unique connection names; a 10-minute pairing window | stolen refresh tokens, notification floods, DNS rebinding, phished connections |
| Funnel is turned off when the broker stops, the broker stops if the wizard dies, and a stale Funnel is cleared when the wizard starts | the broker's port staying public with nothing (or something else) behind it |
| Access tokens last 1 hour; refresh tokens last 30 days and are replaced on every use; only hashes are stored; Revoke in the app cuts a connection off at once | a leaked token staying useful |
| Fixed `pbc_` tokens for local assistants only; Host/Origin checks; binds to 127.0.0.1 | anyone else on the internet or your LAN using the broker |
| No core dumps, process not ptrace-able | other programs of yours reading the broker's memory |
| Audit log (`~/.local/state/passbroker/audit.jsonl`), rotated at 5 MB and hash-chained so `passbroker api audit-verify` finds edited or deleted lines; plus Proton's agent audit reasons | not knowing who used what, when; casual tampering with the record |
| Each bot gets only the logins, unlock actions, devices and keys you grant it; a new bot gets nothing; switch any bot off | one bot (honestly named) using another's logins |
| Self-signed devices and Proton Mail Bridge are reached only with the exact certificate recorded when you set them up (pinned; its dates don't matter), never with checks switched off. Re-saving a device keeps the recorded certificate. Sending a device password to an `http://` address needs an explicit switch | someone on your network intercepting the router or Bridge connection, or reading a password sent unencrypted |
| Test-only `serve` switches (auto-approve, no network guard, no pairing window, mock vault) refuse to work without `PASSBROKER_TEST_MODE=1` and can't go into the service | another program restarting the broker with approvals off |
| Optional systemd service: no privilege gain, private `/tmp`, the system read-only, writes only to the broker's folders and unlock output folders; Funnel off whenever it stops | a compromised broker or browser writing elsewhere; Funnel left on after a crash |
| Unlock tools get the passphrase on stdin; `gpg` runs in an empty home; every unlock writes into a fresh private folder; archives with links or `..` paths, or over 2 GB, are refused | the passphrase in process lists; your own GPG keys being used; output redirected through planted links |

## What it can't stop

- **Bot names are self-reported.** Bots on one Grok account share one connection. Each gets its own
  access list, approvals and browser session, but a bot that lies about its name gets that name's
  grants. A name belongs to the connection that first used it, so another connection can't claim
  it. Revoke is the real off switch.
- **After you sign in, the assistant can use the account.** Hiding the password doesn't hide
  what's inside. Only put logins in the Agent vault that you'd let the assistant act in.
- **Personal-detail masking is pattern matching.** Names, street addresses and unusual formats
  get through, and so does anything shown only as an image.
- **The site list covers the broker's browser only.** An assistant that can browse by itself (Grok
  can) has its own way out; the list stops the broker's browser being that way.
- **A bot can act in the accounts it makes.** It never sees their passwords, but once signed in it
  can do anything the account can. Approve only accounts you'd want it to have.
- **Decrypted text and returned unlock output go to the assistant** (and so to its provider) by
  design, when you approve it.
- **Programs running as you** can answer an approval (as they could press a notification's button), read the agent token in your keyring, the broker's pass-cli
  session, kept browser sessions (`--keep-sessions`), and could rewrite the audit chain consistently.
- **Redirects and the site list.** A redirect can't reach a private address (the proxy refuses the
  connection), but the site list and blocked pages go by the page's full address, which the proxy
  can't see inside https. After every load the broker checks where the tab ended up and goes back
  before the bot can read it, so a site's own open redirect can still send one request elsewhere.
- **A site you trust that is itself compromised** (XSS on the real domain) gets your password,
  just as it would if you typed it.
- A page drawing your password into a `<canvas>` or an image can't be detected by text scrubbing,
  and pages run their own JavaScript in the same world the broker reads from: a hostile page on the
  *right* domain can lie about its fields. Scrubbing is the backstop.
- **Pinning trusts the first certificate it sees.** Set up devices and Bridge on a network you trust.
