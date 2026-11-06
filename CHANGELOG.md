# Changelog

Each release on [GitHub](https://github.com/asafelobotomy/pass-broker/releases) has the AppImage
and fuller notes. Versions follow [semantic versioning](https://semver.org): before 1.0, a new
minor version (0.x.0) can change how things work, and a patch (0.x.y) only fixes.

## Unreleased

- **Each bot has one email address**: the first alias a bot gets (new `email_address` tool, or
  `create_login` with `email_alias`) stays its own, is saved with every account it makes and is
  listed in the wizard. Email codes for those accounts come only from mail sent to that alias.
- **All bot mail in one folder**: bot aliases are named `bot-<name>…`, so one Proton Mail rule
  files every bot's mail into a **Bots** folder. A bot you mark as managing your mail is given the
  job (new `mail_tasks` and `mail_rule_done` tools); with none, the bot tells you, and the wizard's
  **Set up bot mail** makes the folder, copies the rule and opens Proton Mail's filters.
- **A mail admin**: one bot you approve can look through, read, organise (move, archive, star,
  label, spam, trash, folders), draft and send your mail through Bridge. Each send asks you unless
  every recipient is trusted; nothing is erased for good; daily limits; Bridge's password stays with
  the broker. Remove it, or set trusted recipients, in the Email codes tab. Its tools share one
  Bridge connection and work a folder at a time; `mail_senders`, `mail_thread`, `mail_apply` (act
  on a whole search) and `mail_undo` help it tidy, and search comes a page at a time.
- Settings both the broker and the wizard write (the mail admin's, bot accounts) are changed under
  a lock, so neither can undo the other's change.
- **Bots report problems**: `report_issue` files a bug, error, problem or feature request with
  the bot's last failed call and the broker's version attached; repeats are merged; `my_reports`
  shows a bot what happened to them. Review, close and copy them as Markdown in the new **Bot
  reports** tab, or with `passbroker api issues` and `issue-set`.
- **Report a bug**: send your own report, and any bots' reports, to Pass Broker's GitHub issues
  from the Bot reports tab. You see (and can edit) exactly what goes, after personal details, home
  folder, user and computer names, IPs and tokens are blanked; open it on GitHub to submit, or send
  it with the GitHub CLI.
- Fixed (found by a live smoke test): labelling mail failed on a real Bridge (the folder was opened
  read-only); making a label with a folder's name (or the other way round) now says Proton Mail
  needs different names; two live-view refreshes at once could collide on one temporary file.
- **Releases on a version bump**: pushing a new version to main (`packaging/bump.sh`) tags it and
  publishes the release by itself, with the version's CHANGELOG section as notes, after checking
  the AppImage (version, glibc 2.35, licence list).
- Email codes are found in any folder, not only the inbox (filters may file them away).
- `fill_signup` fills every account field: username, email and confirm-email, password and
  confirm-password, leaving the bot's own fields alone, and handles forms that ask for the email
  first and the password on a later page. It says what it filled and what it couldn't.
- Fixed: a form with both a username and an email field could get the email in the username
  field and nothing in the email field.
- Fixed: logins you had moved to the trash in Proton Pass were still listed, and bots could use
  them.

## 0.3.1

- `passbroker --version`; SECURITY.md says which versions get fixes.
- One desktop file and icon name (`pass-broker`), checked in CI; the README installs the
  browser with the broker's own command, so it matches the installed Playwright.
- The audit view names account events (made, signed up).
- Tests for the JSON every offline `passbroker api` command returns (the wizard depends on it),
  for reading email codes from a fake Proton Mail Bridge, and for the wizard's serve command,
  autostart entry, clock and audit rows.
- Tests that relied on timing now wait for what they check; tools the tests need (gpg,
  openssl, 7z, bubblewrap) fail in CI instead of being skipped.
- Tidier code: one set of serve defaults, one serve-command builder and log view in the
  wizard, the pass-cli steps in their own module, and dead code removed. Only one live-view
  refresh runs at a time.
- Unmaintained Rust crates are tracked by advisory ID; any new one fails CI.

## 0.3.0

- **Bots can make their own accounts**, without seeing the passwords. You approve each one;
  Proton Pass generates the password and saves the login in a vault of its own (**Bot
  Accounts**), and the bot fills in the sign-up form. The Agent vault stays read-only to the
  broker.
- One Allow lasts 2 minutes everywhere (the command line said 10).
- Settings › About; `THIRD_PARTY_LICENSES` lists every included library with its licence.
- CI checks dependencies for known vulnerabilities and licences.
- Releases are built without caches from a tag that must match the source version
  (`packaging/bump.sh`); builds are repeatable.
- Fixed: AppImages recorded folder paths from the machine that built them.

## 0.2.4

Reliability fixes: settings files written atomically and read tolerantly; email settings apply
without a restart (and **Record Bridge's certificate again**); Stop during a start cancels it;
no freezes when closing; the background service log follows restarts; a damaged settings file is
kept as a backup; the service starts even if Funnel can't; failed service installs say so.

## 0.2.3

- The browser runs in a bubblewrap box (read-only system, empty home, no desktop session).
- Chromium's own sandbox is required.
- The tab shows only web pages; bots may press only plain keys; every permission prompt is
  refused, dialogs dismissed and file pickers swallowed.

## 0.2.2

- Fixed: part of a password could reach a bot when masking personal details ran first.
- More disguised secrets caught (partial URL encoding, base64 at any position).
- Blocked pages can't be reached by encoding tricks; usernames are blacked out in screenshots;
  in-app approval buttons wait a second after each new request.

## 0.2.1

- Fixed: redirects could reach your LAN. Every browser connection now goes through a filtering
  proxy that checks each host, redirect hop and WebSocket.
- Bot names belong to the connection that first used them; connection names are unique.
- Local tokens are refused through Funnel; opening the app no longer turns off the background
  service's Funnel; only one copy of the app runs; Emergency stop stops the service too.

## 0.2.0

First AppImage release.

- The browser runs hidden, shown live and masked in the Control center.
- Personal details masked for bots unless allowed; per-bot site lists and blocked pages.
- Approvals in the app as well as in notifications; a Settings dialog (login, tray, theme).
- Run in the background as a sandboxed systemd user service.

## 0.1.0

The broker, the wizard and the security model: OAuth for Grok over Tailscale Funnel, `pbc_`
tokens for local assistants, desktop approvals, origin-bound fills, redaction, file unlocking,
encrypted text, home-device actions and email codes.
