# Changelog

## 1.0.0 — 2026-11-19

- The skill is now primarily a client email domain health audit for IT
  providers, graded with Critical→Info findings and per-provider DNS fixes
  (`references/remediation-records.md`). Inbound sender triage stays as an
  evidence-led secondary workflow.
- New `audit_client_domain` tool: one call covers mail DNS, DNS blocklists,
  RDAP registration, AbstractAPI reputation and, when the user pastes a test
  message's original headers (256 KB cap, headers only is fine), the
  receiver's verdict. It also returns cross-checks that combine sections. It
  needs the API key and a client address. Reputation runs first, so a
  missing key or a failed API call sends nothing else and returns no partial
  audit.
- `audit_domain` and `investigate_email` now return the extended DNS
  results:
  - SPF: recursive include/redirect evaluation, with the RFC 7208
    lookup-limit and void-limit counts.
  - DMARC: inheritance from the organizational domain, external `rua`
    authorization, and the RFC 9989 tags `t`, `np` and `psd`.
  - DKIM: a list of 29 common selectors, with key type and key size.
  - MX: provider and security-gateway detection, including Microsoft's
    `mx.microsoft` hosts.
  - New sections: MTA-STS (policy fetched without following redirects, then
    validated), TLS-RPT, BIMI, and the DNSSEC AD flag.
- Blocklist checks:
  - Domain lists: Spamhaus DBL, SURBL and URIBL. IP lists: ZEN, Barracuda,
    SpamCop and PSBL.
  - Each list zone has a resolver canary, so a resolver that is being
    refused reports the result as unknown, never as clean.
  - Sending IPs are found automatically from the domain's SPF record, with
    a forward-confirmed PTR (FCrDNS) check for each one.
- Header analysis covers Authentication-Results (including `compauth`), ARC,
  DKIM signature alignment, the Received chain, List-Unsubscribe one-click
  and Microsoft BCL/SCL. It never returns the body, Subject or unsubscribe
  URLs.
- Untrusted input and hostile records are bounded: SPF stops expanding at
  the lookup limit, a pasted message contributes at most 20 DKIM selectors,
  sending-IP discovery is capped, and names are checked before any query.
- New keyless troubleshooting tools: `analyze_headers` (pasted message,
  parsed locally), `check_blocklists` (with an optional `resolver` to
  re-check through a local or ISP resolver) and `check_registration`.
- New `references/troubleshooting.md`: a symptom → evidence → tool map
  (bounces, junk, missing mail, forwarding, spoofing, devices that can't
  send) and Gmail, Microsoft 365 and Yahoo bounce-code tables.
- Reputation requests also report `network_error` when the HTTP layer
  fails mid-request.
- Added the ShadeTree IT icon (`.claude-plugin/icon.png`).

## 0.1.0 — 2026-10-30

- Migrated the reputation and mail-DNS skill to a local FastMCP plugin.
- Added one-address investigations, keyless domain audits, optional known DKIM
  selectors, and cross-platform DNS without a system `dig` requirement.
- Added reusable hidden-prompt OS-keychain credential setup in `packages/common`.
- Switched to POST/Bearer authentication, normalized-only output, explicit API
  failure handling, and evidence-led assessments instead of Trust/Block claims.
- Corrected duplicate-SPF handling, null MX, unknown DNS errors, invalid DMARC
  percentages/tags, and per-selector DKIM error reporting.
