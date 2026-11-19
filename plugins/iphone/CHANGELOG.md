# Changelog

## 0.2.0 -- 2026-11-19

- Fix Full Disk Access never working in Claude Desktop. Desktop starts MCP
  servers through a helper that makes the server's first binary (`uv`) the
  process macOS checks, so FDA on Claude.app was ignored. `.mcp.json` now
  launches a bundled launcher, `bin/Shadetree iPhone Bridge.app`, which always
  makes itself the process macOS checks. Grant Full Disk Access to it once.
- Add `iphone_setup`: opens System Settings at Full Disk Access and shows the
  bridge in Finder to drag in.
- `imessage_doctor` / `calls_doctor` now report `*_access` (`readable`,
  `denied`, `missing`, `error`) and `full_disk_access` (the binary macOS
  checks and what to grant), instead of a bare "unable to open database file".
- The Automation prompt for `imessage_send` now names Shadetree iPhone Bridge.

## 0.1.2 -- 2026-11-01

- Bundle shared helpers and the startup hook as real files rather than
  checkout-relative symlinks. Git marketplace installs that copy only this
  plugin no longer lose `shadetree_ai_plugins_common` or `check_uv.py`.

## 0.1.1 -- 2026-10-21

- `imessage_send`: fix sends failing with "Can't get chat id ... (-1728)" when
  a 1:1 chat exists in `chat.db` but not among Messages.app's loaded chats
  (deleted in the app, or not synced to this Mac). The send now falls back to
  the chat's handle as a participant.
- The fallback follows the chat's own service (`RCS` -> RCS, then SMS;
  `SMS` -> SMS; `iMessage` -> iMessage, then SMS). Messages.app accepts an
  iMessage send to a non-iMessage number and only fails at delivery, so
  iMessage is never tried for an RCS/SMS chat.

## 0.1.0

Initial release.
