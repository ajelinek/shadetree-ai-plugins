# Known platform issues

## Full Disk Access (TCC)

`chat.db`, `CallHistory.storedata`, and the AddressBook are protected by macOS's
TCC (Transparency, Consent, and Control) system. Reading them needs **Full Disk
Access**, and the app that must hold it is **Shadetree iPhone Bridge**, bundled
with this plugin at `bridge/Shadetree iPhone Bridge.app`. It is not Claude.app.

### Why not Claude.app

TCC checks Full Disk Access against the *responsible* process, not the process
that opens the file. Claude Desktop starts MCP servers through
`Claude.app/Contents/Helpers/disclaimer`, which makes the server's first binary
its own responsible process, cut off from Claude.app's grants. Before 0.2.0
that binary was `uv`, so TCC checked a version-specific path like
`/opt/homebrew/Cellar/uv/0.11.14/bin/uv`. Granting FDA to Claude.app did nothing,
and granting it to uv broke on the next `brew upgrade uv` and handed FDA to
every uv-run script. (Verified from tccd's `AUTHREQ_ATTRIBUTION` log lines:
`log show --predicate 'subsystem == "com.apple.TCC"'`.)

### The bridge

`.mcp.json` launches the bridge (source: `bridge/iphone_bridge.c`), which:

- re-spawns itself with responsibility disclaimed if something else is
  responsible (a terminal or IDE), so TCC always checks the bridge, whatever
  launched it, and users get one instruction;
- spawns `uv run --project <plugin root> --locked python -m
  shadetree_ai_plugins_iphone` and stays alive as its parent (spawn, not exec:
  after an exec TCC would check uv again);
- ignores all arguments and strips `DYLD_*`, `PYTHON*`, `UV_*`, `VIRTUAL_ENV`,
  and `CONDA_*` from the environment, so other local programs can't use the
  FDA-holding bridge to run their own code. A program running as the same user
  can still edit the plugin's files, so this narrows misuse rather than ruling
  it out, the same as granting FDA to a terminal.

`/bin/sh` wraps the launch only to re-apply the executable bit in case an
installer drops it; it `exec`s the bridge, so it never becomes responsible
itself.

### Diagnosing

Both doctors report `chat_db_access` / `call_history_db_access` /
`address_book_access` as `readable`, `denied` (TCC or file permissions),
`missing`, or `error`, plus `full_disk_access`:

- `checked_against`: the binary TCC actually checks (looked up with
  `responsibility_get_pid_responsible_for_pid`);
- `grant_to`: its enclosing `.app`, which is what to add in System Settings;
- `via_bridge`: whether that's the bridge.

When anything is `denied`, `iphone_setup` opens System Settings -> Privacy &
Security -> Full Disk Access and reveals `grant_to` in Finder. The user drags it
in, turns it on, then quits and reopens Claude.

### When a grant stops working

The bridge is ad-hoc signed, so TCC ties the grant to this exact binary. A
plugin release that rebuilds the bridge (rare, noted in CHANGELOG) needs the
grant redone: remove the old entry and add the new app. Plugin updates that
don't touch the bridge keep the same binary. Whether a grant survives the
plugin moving to a new install directory is still being verified; if a doctor
says `denied` right after an update, re-add the app from its new location
(`grant_to`).

## Transient "database is locked" errors

`chat.db` is under SQLite's WAL mode and Messages.app can be mid-checkpoint when a
read happens. `_open_readonly_db` retries briefly (two short backoff delays) on an
`OperationalError` whose message mentions "locked" or "busy" before giving up — this
is not a permissions problem and normally clears in well under a second.

## AddressBook access

Contact name resolution reads
`~/Library/Application Support/AddressBook/Sources/*/AddressBook-v22.abcddb` — also
a plain SQLite file, also covered by Full Disk Access. If it's unreadable or
missing, this plugin degrades gracefully: handles are shown as raw phone
numbers/emails instead of names, and `imessage_doctor` reports
`address_book_found: false` as a warning, not a failure — name resolution is a
nice-to-have, not a hard requirement to use these tools.

## Automation permission (TCC) for sending

`imessage_send` never touches chat.db — it shells out to `osascript`, which tells
Messages.app to deliver the text via AppleScript's `tell application "Messages" to
send`. macOS gates this separately from Full Disk Access: the first `imessage_send`
call in a session (or after an OS update) triggers an **Automation** permission
prompt for the responsible process, which is the bridge ("Shadetree iPhone
Bridge wants to control Messages"). If the user dismissed or never saw that prompt,
`osascript` exits nonzero and `send_via_applescript()` raises with the fix pointer:

System Settings -> Privacy & Security -> Automation -> Shadetree iPhone Bridge ->
enable Messages.

A denied/missing grant here does not affect `imessage_doctor` or any read tool —
Full Disk Access and Automation are independent TCC checks.

## iCloud multi-device sync

`chat.db` only contains what has synced to **this** Mac. If "Messages in iCloud" is
off (or a different Mac was primary), a Mac that's new to your account, or one where
Messages.app hasn't been open continuously, may only have a partial — or very
shallow — local history. It does **not** inherit another Mac's full history just by
being signed into the same Apple ID; it accumulates going forward from whenever
Messages.app was running on this device. Relatedly, what's visible in Messages.app
itself isn't guaranteed to match chat.db exactly — older history can be offloaded to
iCloud-only storage even while it still displays in the app.

`imessage_doctor` heuristically flags this: if the earliest message in chat.db is
less than 90 days old, it emits a warning suggesting the user check whether
"Messages in iCloud" is enabled and fully synced (initial sync of a large history
can reportedly take 1-2 days). This is a heuristic, not a certainty — a genuinely
new iMessage user would also trip it harmlessly.

To fix: enable "Messages in iCloud" on all devices signed into the account
(Messages -> Settings -> iMessage on Mac; Settings -> [name] -> iCloud ->
"Messages in iCloud" on iPhone), and give it time to finish an initial sync before
re-running `imessage_doctor`.

## Watching for new messages

This plugin is deliberately on-demand only: open, query, close, return data, done —
no background watcher, no polling for inbound messages. If you need Claude to react
to new messages as they arrive rather than being asked to check, there are two real
options, neither built into this plugin:

1. **Claude Code's "Channels" feature** (research preview as of this writing) is the
   mechanism Anthropic's own official iMessage channel plugin
   ([anthropics/claude-plugins-official/external_plugins/imessage](https://github.com/anthropics/claude-plugins-official/tree/main/external_plugins/imessage))
   uses: an MCP server declares the `claude/channel` capability, polls chat.db
   internally (that plugin polls once a second for `ROWID > watermark`), and pushes
   a `notifications/claude/channel` event into the live Claude Code session when
   something new shows up — no separate cron/launchd job needed, but it requires
   the MCP server process itself to stay running, is gated behind Anthropic's
   channel allowlist or the `--dangerously-load-development-channels` flag, and is
   wired through the low-level MCP SDK rather than FastMCP's high-level tool API.
   See [the Channels reference](https://code.claude.com/docs/en/channels-reference)
   for the full contract.
2. **An external scheduler** (a local `/loop`-style recurring session, or a plain
   macOS `launchd` job) that wakes periodically, calls `imessage_recent` with a
   `since` watermark it persists itself, and only invokes Claude when there's
   something new. Simpler to build with what this plugin already exposes, at the
   cost of being coarser-grained than a live push.

## Why no calling/write capability beyond `imessage_send`

Everything here is on-demand: open, query, close, return data, exit (or, for
`imessage_send`, hand off to `osascript` once). A future scheduled job calling
`imessage_recent` on an interval is a natural next step for anyone wiring up option
2 above, but the watermark should live in whatever calling system consumes this
plugin's output, not be invented here.
