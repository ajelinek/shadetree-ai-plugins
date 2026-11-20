# Handoff: port the email-domain-reputation overhaul into the plugin

**Date:** 2026-11-19
**Goal:** bring the upgraded skill from `skills-stash` into
`plugin-stash/plugins/email-domain-reputation` as v0.2.0. The upgrade turns the
skill from an inbound "is this sender legit" check into a **client domain
health audit**: an IT provider supporting a client wants to know what needs
fixing technically to keep that client's outbound mail reputation and
deliverability healthy.

## Where things are

| What | Path | State |
|---|---|---|
| Source of the port (the new code) | `/Users/ajelinek/code/skills/skills-stash/email-domain-reputation/` | Uncommitted in the `skills-stash` repo: 6 files modified, 15 new. 197 tests pass. |
| Target | `/Users/ajelinek/code/skills/plugin-stash/plugins/email-domain-reputation/` | v0.1.0, last commit `e4d5b07`. None of the new work is here yet. |
| Leave alone | `/Users/ajelinek/code/skills/plugin-stash-website-health/plugins/email-domain-reputation/` | A third copy that another session was committing to. Don't touch it. |

**Never read `skills-stash/email-domain-reputation/.env`.** It holds a real
AbstractAPI key. That directory's `.claude/settings.json` denies `Read(./.env)`.

Read `plugin-stash/CLAUDE.md` and `docs/plugin-authoring.md` first. They
cover the release steps, vendoring, lockfile, CI, and the `skills-stash`
migration plan (each repo gets its own commit, plus a cleanup step on the
`skills-stash` side).

## The source is a different architecture, so port it rather than copy it

| Concern | skills-stash (source) | plugin (target), and what to do |
|---|---|---|
| DNS | Shells out to the system `dig` (`_dns.py`). It parses rcode and the `ad` flag, and validates names before running anything (the fix for an injection bug). | Uses **dnspython** with the machine's resolver, because clients include Windows and have no `dig`. Rewrite `_dns.query()` on dnspython. Map NXDOMAIN, NoAnswer, NoNameservers/SERVFAIL, REFUSED and Timeout to the same `status` strings. Get `ad` from `response.flags & dns.flags.AD`. Use `dns.resolver.Resolver(configure=False)` with `nameservers=[...]` for an explicit resolver. With no subprocess, argv injection can't happen, but **keep the name validation** anyway, since untrusted SPF/PTR/header names still flow into queries. |
| Secrets | Env var or `.env` | OS keychain through `shadetree_ai_plugins_common.secrets` (`NAMESPACE="email-domain-reputation"`, key `abstractapi-api-key`). Keep the plugin's approach. |
| Reputation API | GET with `api_key` in the query string | The plugin's `reputation.py` is better: POST with a Bearer token, normalized-only output, explicit failure handling. **Keep the plugin's version.** Only add the `http.client.HTTPException` → `network_error` catch if it's missing. |
| Interface | CLI scripts printing JSON | FastMCP tools in `server.py`, tested in-memory with `fastmcp.Client` (`tests/test_server.py`). |
| Judgment | Trust/Caution/Block (inbound) plus a Critical→Info health rubric | The plugin skill deliberately uses **evidence-led assessments instead of Trust/Block claims** (see CHANGELOG 0.1.0). Adapt the new rubric to that tone. Severity tiers for client health findings fit fine. |
| HTTP (RDAP, MTA-STS) | stdlib `urllib` | stdlib is fine. `httpx` also comes with fastmcp if it's preferred. MTA-STS must **not follow redirects** (RFC 8461). |
| Python | stdlib, any 3.x | `>=3.12`, deps `fastmcp`, `keyring`, `dnspython`. If deps change, regenerate the standalone `uv.lock`. |

The plugin already fixed some things on its own in 0.1.0: duplicate SPF
records, null MX, unknown DNS errors, invalid DMARC percentages and tags, and
per-selector DKIM errors. **Diff before porting** so those fixes aren't lost,
and keep its stricter `normalize_email`/`normalize_domain`/`validate_selectors`.

## What to port (source files and what they hold)

Each source module's docstring documents its full output contract. Treat the
docstrings as the spec.

| Source | Contents |
|---|---|
| `scripts/_domain.py` | `normalize_domain`, `is_valid_domain`, `org_domain` (an approximate public-suffix list with multi-part suffixes), `org_domain_is_approximate` (true for ccTLDs), and `aligned(a, b, mode)` for DMARC relaxed/strict alignment. |
| `scripts/_dns.py` | `query()` → `{status, answers, ad}`, `records`/`txt_records` (raise on failure, `[]` on absence), `txt_strings` (multi-string TXT plus `\DDD` unescape, ASCII digits only), name/rtype/resolver validation. |
| `scripts/_common.py` | `add_error`, `mechanism_target`. |
| `scripts/check_dns_auth.py` | See the field list below. |
| `scripts/check_blocklists.py` | Domain lists (Spamhaus DBL, SURBL, URIBL); IP lists (Spamhaus ZEN, Barracuda, SpamCop, PSBL); IPv6 via ZEN only. Sentinel decoding: Spamhaus `127.255.255.25x` and `127.0.1.255`, URIBL/SURBL `127.0.0.1` mean refused. Bitmask decoding. Per-zone **canaries** (`resolver_canaries`): when a canary fails, empty answers become `unreliable_resolver` with `listed: null`, never a false "not listed". IPs are auto-discovered from the domain's own SPF `ip4`/`ip6`/`a`/`mx` terms (provider includes are not expanded), with PTR / forward-confirmed reverse DNS and a generic-PTR heuristic. |
| `scripts/check_registration.py` | RDAP via `https://rdap.org/domain/<org domain>`. Returns registrar, created/expires, `days_until_expiry`, statuses and the `on_hold`/`pending_delete`/`transfer_locked` flags (null when there's no status list), nameservers, and the DNSSEC delegation. |
| `scripts/check_headers.py` | Parses a raw message's headers and **never emits the body, Subject or unsubscribe URLs**. Covers Authentication-Results (including Microsoft's `compauth`), ARC, DKIM-Signature `d=`/`s=`, relaxed alignment, the Received chain → `sending_ip` heuristic, List-Unsubscribe one-click, `list_id_present`/`list_id_domain`, and X-Forefront/BCL/SCL. |
| `scripts/audit.py` | The orchestrator. Headers run first, and their aligned DKIM selectors and sending IP feed the DNS and blocklist checks. Then DNS, blocklists, registration and reputation run concurrently. Returns `sections`, `section_errors`, `skipped`, and `cross_checks` (`header_from_matches_target`, `header_dkim_selectors_in_dns`, `header_sending_ip_in_spf` (walks SPF left to right; `+all` aware; null when unverifiable), `header_alignment_per_dmarc_policy` (honors strict `adkim`/`aspf`), `dmarc_rua_present`, `registration_nameservers_match_dns`, `provider_spf_include_present`), plus `org_domain_approximate`. |
| `tests/` | 197 tests, with fixtures in `tests/fixtures/headers/*.eml`, which use `.example` domains and documentation IPs. `test_check_dns_auth.py` includes real 1024- and 2048-bit DKIM keys. Most tests mock at `_dns.query`, so swap them to mock the new dnspython-backed query. |
| `SKILL.md` | The new workflow: the health audit is primary, then the test-message step, the resolver caveat, what only the client can provide (Postmaster Tools, SNDS, the list of third-party senders), the report format, and limitations. |
| `references/interpretation-rules.md` | Rule zero (unknowns are scoped per field and are never a pass or a fail), the Critical→Info health rubric, the overall grade, the Gmail/Yahoo/Microsoft bulk-sender checklist, and inbound triage tiers. |
| `references/remediation-records.md` | Per-provider fixes (Google, Microsoft 365 including the new `mx.microsoft` / `dkim.mail.microsoft` formats, Zoho, Proton, Fastmail, generic), the DMARC rollout, MTA-STS/TLS-RPT/BIMI, SPF lookup overflow, PTR, and delisting. Fact-checked against vendor docs on 2026-11-19. |

### `check_dns_auth.py` fields (the biggest port)

- **MX:** `null_mx`, `provider`, `security_gateway`.
- **SPF:**
  - recursive `include`/`redirect` evaluation: `dns_lookup_count` (RFC 7208 §4.6.4), `lookup_limit_exceeded`, `void_lookup_count`/`void_limit_exceeded`, `lookup_count_is_minimum`
  - findings: `permerrors` (including an `mx` mechanism with more than 10 MX records), `plus_all`, `has_ptr`
  - the record's own terms: `direct_ips`, `direct_ip_terms` (with qualifiers), `effective_all_mechanism`/`effective_strict` (follows `redirect`)
  - the provider include: `expected_provider_include`, `provider_include_present`
- **DMARC:**
  - tags: `adkim`/`aspf`/`ruf`/`fo`, `policy_valid`, `has_rua`, `effective_policy`
  - inheritance: `inherited_from` (org-domain fallback)
  - external reports: `rua_external_authorization` (checks `<domain>._report._dmarc.<dest>`)
  - RFC 9989 (DMARCbis): `testing` (`t=y`, which makes `enforced` false), `np`, `psd`; `pct` is legacy
  - a failed lookup sets `found`/`has_rua`/`enforced`/`policy_valid`/`effective_policy` to **null**
- **DKIM:**
  - selector list: about 30 selectors plus `--selector` input
  - per selector: `cname_target`, `cname_without_key`, `revoked`, `key_type`, `key_bits` (DER parse of SPKI or RSAPublicKey), `testing`
  - failures: `selectors_failed`
- **New sections:**
  - `mta_sts`: TXT record plus the policy fetch; `policy_valid`/`policy_errors`, `mx_covered`
  - `tls_rpt`
  - `bimi`
  - `dnssec.ad_flag`
- **Unknown, not absent:** `found` is null when a lookup failed, and digit parsing is ASCII-only, because a crafted `\178` value in a DNS record crashes `int()`.

## Proposed MCP tool surface (confirm with the user)

- Keep `check_setup`, `investigate_email` and `audit_domain`, extending them with the new DNS fields.
- Add **`audit_client_domain(target, raw_headers: str | None = None, selectors=None, sending_ips=None)`**. It returns the `audit.py` structure. Reputation is **optional** here: health auditing is mostly keyless. Use the API only when the target is an address and a key is configured, and report it in `skipped`/`section_errors` otherwise. This deliberately departs from `investigate_email`'s rule that no DNS-only result is given when the API fails. Confirm that with the user.
- Headers arrive as **pasted text** (Claude Desktop users paste the original message). Cap the size (e.g. 256 KB) and accept headers-only input. Optionally also accept a local file path.
- Optional smaller tools: `check_blocklists(target, ips=None)`, `check_registration(target)`, `analyze_headers(raw_headers)`.
- Mark every tool read-only (`READ_ONLY` annotations), and update the server `instructions` string.

## Open decisions for the user (ask at the start)

1. **Should the health audit require the API key?** I recommend no (above).
2. **One combined audit tool or several tools?** I recommend `audit_client_domain` plus the existing tools.
3. **What happens to the `skills-stash` copy after the port:** commit it as the reference, or remove it per the migration plan's cleanup step?
4. **Version:** 0.2.0 (new tools, backward compatible) is suggested.

## Suggested execution (this worked well last time)

Split the work across `@coder` agents with **disjoint file ownership** and
fixed field names in each brief:

1. A dnspython `_dns` layer plus `_domain`/`_common` helpers, so the shared helpers land first.
2. In parallel: `dns_auth.py` (merged with the plugin's existing module), `blocklists.py`, `registration.py`, `headers.py`, each with tests.
3. `audit.py`-equivalent orchestration plus the `server.py` tools and `test_server.py`.
4. Docs: the skill's `SKILL.md` and `references/`, adapted to tool calls instead of CLI and to the evidence-led tone. Also the README and CHANGELOG.
5. `@reviewer` pass, then fixes, then a re-review. Last time the first review found 15 real issues and the re-review found 6.
6. `@validator`: `uv sync --all-packages --locked`, `uv run ruff check .`,
   `uv run pytest plugins/email-domain-reputation/tests`,
   `claude plugin validate ./plugins/email-domain-reputation`, `claude plugin validate .`.
7. Release steps from CLAUDE.md: bump `plugin.json` and `pyproject.toml`, add a CHANGELOG entry, regenerate `uv.lock` if deps changed, commit. **Only commit or push when the user asks.**

Live smoke targets that worked:
- `microsoft.com`: covers a Microsoft 365 rotated selector and 1024-bit key, and enforced DMARC.
- `dbltest.com`: Spamhaus DBL's official test listing (`127.0.1.2`).
- `127.0.0.2`: the IP-list test entry.

## Known caveats to carry over

- Some values in `remediation-records.md` are unverified and marked "check provider docs": Zoho's regional SPF includes, and whether Microsoft is currently hard-rejecting non-compliant bulk mail (Microsoft's own announcement contradicts itself).
- DKIM discovery without a test message is guesswork against a selector list. The headers step settles it.
- `org_domain` is approximate for ccTLDs (`org_domain_approximate`).
- Spamhaus, URIBL and SURBL fail silently through public resolvers. The canaries handle this, and the result must stay "unknown", never "clean".
- AbstractAPI scores the address as a sign-up/fraud risk, not as sender reputation. Treat breach hits as an account-security item (MFA, password reset).
