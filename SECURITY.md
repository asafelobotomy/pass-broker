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

## Threat model

The broker assumes the AI model may be careless or prompt-injected, the web
pages and files it handles may be hostile, other bots on the same assistant
account may misbehave, and anyone on the internet can reach the public address.
It does **not** defend against malware already running as your user: such a
program can read your keyring and the broker's files directly.

## What protects what

| Layer | Stops |
|---|---|
| Proton Pass agent token limited to one **Agent** vault, `viewer` role, short expiry | a compromised broker reaching your real vault |
| Token stored in your system keyring, passed to `pass-cli` by environment, never argv | the token showing up in process lists or files |
| Opaque, per-run handles | the model naming items or fields it wasn't shown |
| Origin binding (page **and** frame must be HTTPS on a saved host) | prompt injection that fills your password on `evil.com` or in a cross-site iframe |
| Desktop approval per bot, item, site and action, showing the bot's stated reason (one Allow lasts 2 minutes by default) | the assistant signing in anywhere you didn't ask for |
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
| Audit log (`~/.local/state/passbroker/audit.jsonl`), rotated at 5 MB and hash-chained so `passbroker api audit-verify` finds edited or deleted lines; plus Proton's agent audit reasons | not knowing who used what, when; casual tampering with the record |
| Each bot gets only the logins, unlock actions, devices and keys you grant it; a new bot gets nothing; switch any bot off | one bot (honestly named) using another's logins |
| Self-signed devices and Proton Mail Bridge are reached only with the certificate recorded when you set them up (pinned), never with checks switched off | someone on your network intercepting the router or Bridge connection |
| Test-only `serve` switches (auto-approve, no network guard, no pairing window, mock vault) refuse to work without `PASSBROKER_TEST_MODE=1` and can't go into the service | another program restarting the broker with approvals off |
| Optional systemd service: no privilege gain, private `/tmp`, the system read-only, writes only to the broker's folders and unlock output folders; Funnel off whenever it stops | a compromised broker or browser writing elsewhere; Funnel left on after a crash |
| Unlock tools get the passphrase on stdin; `gpg` runs in an empty home; every unlock writes into a fresh private folder; archives with links or `..` paths, or over 2 GB, are refused | the passphrase in process lists; your own GPG keys being used; output redirected through planted links |

## What it can't stop

- **Bot names are self-reported.** Bots on one Grok account share one connection. Each gets its own
  access list, approvals and browser session, but a bot that lies about its name gets that name's
  grants. Revoke is the real off switch.
- **After you sign in, the assistant can use the account.** Hiding the password doesn't hide
  what's inside. Only put logins in the Agent vault that you'd let the assistant act in.
- **Decrypted text and returned unlock output go to the assistant** (and so to its provider) by
  design, when you approve it.
- **Programs running as you** can read the agent token in your keyring, the broker's pass-cli
  session, kept browser sessions (`--keep-sessions`), and could rewrite the audit chain consistently.
- **DNS can change between the broker's check and Chromium's own lookup.** The private-address guard
  resolves names itself and caches them for a minute, so a host that rebinds to a private address in
  that window could slip through.
- **A site you trust that is itself compromised** (XSS on the real domain) gets your password,
  just as it would if you typed it.
- A page drawing your password into a `<canvas>` or an image can't be detected by text scrubbing,
  and pages run their own JavaScript in the same world the broker reads from: a hostile page on the
  *right* domain can lie about its fields. Scrubbing is the backstop.
- **Pinning trusts the first certificate it sees.** Set up devices and Bridge on a network you trust.
