# iphone

Read (and send) local iMessage history, read local Mac/iPhone call history
(cellular + FaceTime), and resolve Contacts — all via one bundled local FastMCP
server. Everything stays on this Mac: reads open the relevant database
read-only, query, close, and return structured data; the only thing that ever
leaves the machine is a sent iMessage, delivered through Messages.app via
AppleScript (never over the network directly from this plugin).

macOS only. Needs Full Disk Access for the bundled **Shadetree iPhone Bridge**
app (to read `chat.db`, `CallHistory.storedata`, and the local AddressBook) and,
for sending, a separate Automation permission for Messages.app. See
`skills/imessage/references/platform-issues.md`.

## Prerequisites

The machine needs `uv` installed and on `PATH`
(https://docs.astral.sh/uv/getting-started/installation/).

## Install

In Claude Desktop: **Customize → Plugins → (+) → Add marketplace**,
enter `ajelinek/shadetree-ai-plugins`, then install `iphone` from the list.
(Equivalent commands also work in a Desktop or Cowork chat window:
`/plugin marketplace add ajelinek/shadetree-ai-plugins` then
`/plugin install iphone@shadetree-ai-plugins`.)

## One-time setup: Full Disk Access

Ask Claude to "check iMessage doctor". On a new Mac it reports access denied and
runs `iphone_setup`, which opens System Settings at **Privacy & Security -> Full
Disk Access** and shows **Shadetree iPhone Bridge** in Finder. Then:

1. Drag **Shadetree iPhone Bridge** from Finder into the Full Disk Access list.
2. Make sure its switch is on.
3. Quit Claude completely (Cmd+Q) and reopen it.

Grant it to the bridge, not to Claude.app. Claude Desktop runs plugin servers in
a way that ignores Claude.app's Full Disk Access, so a grant there has no effect.
The first `imessage_send` also asks once for permission to control Messages.

## What's inside

- `.claude-plugin/plugin.json` / `.mcp.json` — plugin + MCP server manifest
  (one server, `shadetree_ai_plugins_iphone`, launched through the bridge).
- `bridge/Shadetree iPhone Bridge.app` — prebuilt, committed launcher that holds
  the Full Disk Access grant, next to its source and `bridge/build.sh`. It can't
  live in a top-level `bin/`: claude.ai-hosted marketplaces reject that. Rebuild
  only when it has to change, because a rebuilt
  ad-hoc-signed bridge makes users grant Full Disk Access again.
- `fastmcp.json` — local dev only (`fastmcp run fastmcp.json`), not used by the
  installed plugin.
- `skills/imessage/SKILL.md` — usage guidance for the `imessage_*` tools
  (read/send iMessage, trusted contacts).
- `skills/icallhistory/SKILL.md` — usage guidance for the `calls_*` tools
  (read-only call history).
- `src/shadetree_ai_plugins_iphone/server.py` — the FastMCP server: `imessage_*` tools,
  `calls_*` tools, and a shared `contacts` tool.
- `src/shadetree_ai_plugins_iphone/contacts.py` / `dates.py` — shared AddressBook
  resolution and date-argument parsing used by both tool families.
- `src/shadetree_ai_plugins_common` — bundled copy of the repo's shared helpers (logging,
  `~/.shadetree-ai-plugins/iphone/` state dir for trusted contacts).
- `tests/test_server.py` — in-memory tests against synthetic chat.db /
  CallHistory.storedata / AddressBook fixtures (`uv run pytest` from repo
  root — no real macOS databases required).

## Tools

| Server | Tools |
|---|---|
| `imessage_*` | `imessage_doctor`, `imessage_chats`, `imessage_recent`, `imessage_messages`, `imessage_search`, `imessage_resolve_chat`, `imessage_send` (preview-then-confirm), `imessage_get_attachment`, `imessage_trusted_list`/`_add`/`_remove`/`_suggest` |
| `calls_*` | `calls_doctor`, `calls_list` |
| shared | `contacts`, `iphone_setup` (Full Disk Access walkthrough) |

See the two SKILL.md files for full usage guidance, safety rules around
`imessage_send`, and known platform caveats.
