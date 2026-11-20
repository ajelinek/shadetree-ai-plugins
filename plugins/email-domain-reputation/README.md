# Email/domain reputation

Version 1.0.0.

A client email domain health audit for IT providers. Give Claude an address
at a client's domain, and optionally paste a test message's original
source. The plugin checks published mail DNS, DNS blocklists, registration
and expiry, the receiving server's verdict on the test message, and
AbstractAPI's signals for the address. Claude turns that into a graded
report with severity-ranked findings, the evidence behind each one, and
copy-pasteable DNS fixes.

It also triages a single unknown inbound sender, reporting the evidence and
unknowns without claiming a sender or message is verified safe.

## Install and setup

Install `email-domain-reputation` from `ajelinek/shadetree-ai-plugins` in
Claude Desktop's Plugins panel. The machine needs `uv` on PATH; Python and
locked dependencies are managed by uv. No `dig` installation is needed.

From Claude Code:

```
/plugin marketplace add ajelinek/shadetree-ai-plugins
/plugin install email-domain-reputation@shadetree-ai-plugins
```

Ask Claude to run `check_setup` and show its setup command. Run that command
yourself in a local terminal. It prompts for your Email Reputation API key
twice without echoing, then saves and verifies it in the OS keychain.
Get a product-specific key at https://www.abstractapi.com/api/email-reputation-api.

From this checkout, the equivalent command is:

```sh
uv run --project plugins/email-domain-reputation --locked python -m shadetree_ai_plugins_email_domain_reputation credentials set
```

For installed clients, use the absolute project path returned by
`check_setup`, not a checkout path. Replace `set` with `status`, `replace`,
or `delete` to inspect, rotate, or remove the key. Values are never command
arguments. Never paste keys into chat, `.env` files, or MCP calls.

Supported credential stores: macOS Keychain, Windows Credential Locker,
Linux Secret Service/KWallet. An unavailable or locked store is a setup
error; there is no plaintext fallback. The service is
`shadetree-ai-plugins:email-domain-reputation`, credential
`abstractapi-api-key`. The stored key survives plugin updates.

## Tools

All tools are read-only.

| Tool | Key | What it does |
|---|---|---|
| `check_setup()` | no | Reports whether a key is stored and readable, and returns the setup command. Makes no API request. |
| `audit_client_domain(target, raw_headers?, selectors?, sending_ips?)` | yes | The full health audit. `target` is an address at the client's domain. Returns `sections` (`dns`, `blocklists`, `registration`, `headers`, `reputation`), `section_errors`, `skipped`, and `cross_checks`. |
| `audit_domain(target, selectors?)` | no | DNS only: MX, SPF, DMARC, DKIM, MTA-STS, TLS-RPT, BIMI, DNSSEC. No blocklist, registration, or header checks. |
| `investigate_email(email, selectors?)` | yes | Inbound sender triage: AbstractAPI signals plus the domain's DNS checks. |
| `analyze_headers(raw_headers)` | no | Parses a pasted received message locally (no network): the receiver's SPF/DKIM/DMARC/compauth, alignment, sending IP, unsubscribe and spam-filter headers. |
| `check_blocklists(target, sending_ips?, resolver?)` | no | Domain and sending-IP DNSBLs with PTR/FCrDNS and resolver canaries. `resolver` re-checks through a named local or ISP resolver. |
| `check_registration(target)` | no | RDAP registrar, expiry, EPP holds and locks, nameservers, DNSSEC delegation. |

`raw_headers` is the pasted original message source (Gmail **Show
original**, Outlook **View message source**). Headers only is fine, up to
256 KB. The parser never returns the body, the Subject, or unsubscribe
URLs. `selectors` adds known DKIM selector names to the built-in common
list; `sending_ips` adds known outbound server IPs to the blocklist checks.

The key-bearing tools stop on a missing key (`setup_required`) or an API
failure (`reputation_unavailable`). They don't fall back to a partial audit
or retry, since each request can use a credit. Lookup failures inside a
successful audit come back as `null` (unknown), never as "absent" or "not
listed".

## Use

- "Audit the email domain for jane@client.example. Here's a test message
  she sent me: ..." Full audit with the receiver's verdict.
- "Why is client.example's mail going to spam?" Claude asks for an address
  and a test message, then runs the audit.
- "Just check the DNS for client.example." Keyless `audit_domain`.
- "Why did this bounce with 550 5.7.26?" or "Why is this in junk?" Paste the bounce or the received message; Claude decodes it with `analyze_headers` and the troubleshooting guide, no key needed.
- "Is this sender legit? billing@vendor.example" Inbound triage.

## What data goes where

The MCP server runs locally, but the checks are not offline:

- **AbstractAPI** receives the email address (one metered request per
  `audit_client_domain` or `investigate_email` call).
- **The machine's DNS resolver** receives the domain, DKIM selector names,
  SPF-referenced names, and PTR lookups. Blocklist checks send the domain
  and sending IPs as DNS queries to the Spamhaus, SURBL, URIBL, Barracuda,
  SpamCop, and PSBL zones.
- **rdap.org** receives the organizational domain for the registration
  lookup.
- **The domain's MTA-STS host** (`https://mta-sts.<domain>`) is fetched for
  its policy file, without following redirects.
- **Pasted headers** are parsed locally. Their sending IP and DKIM
  selectors feed the DNS and blocklist queries above.

No lookup history, raw provider responses, or breach lists are stored.
Breach counts in the result are PII; Claude shows them but shouldn't save
them anywhere. Chat results remain subject to the client app's retention
policy.

## Limitations

- Spamhaus, URIBL, and SURBL refuse or distort queries from large public
  resolvers. Per-zone canaries detect this, and those lists come back as
  unknown. For reliable results, run from a network with its own or an ISP
  resolver.
- Without a test message, DKIM discovery is a guess against common
  selectors, and the grade reflects published configuration only.
- The organizational domain is approximate for some ccTLDs
  (`org_domain_approximate`).
- AbstractAPI scores the address as a sign-up or fraud risk, not the
  domain's sender reputation. Breach hits are an account-security item.
- The audit can't see Google Postmaster Tools, Microsoft SNDS, sending
  volume, or which third-party services send as the domain. Claude asks the
  client for these.
- No bulk screening, DNS changes, automatic blocking, or audit history.

Implemented for macOS, Windows, and Linux. Automated checks and local
keychain validation were run on macOS; real Windows/Linux and installed
Desktop smoke tests remain necessary before promising those environments
are verified.

## Development

```sh
uv run pytest plugins/email-domain-reputation/tests packages/common/tests
uv run ruff check .
claude plugin validate plugins/email-domain-reputation
```

Tests replace the network and keychain boundaries; they don't spend real
API credits. Also test a dereferenced standalone copy with its own
`uv.lock`, as described in `docs/plugin-authoring.md`.
