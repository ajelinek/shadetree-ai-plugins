# Interpretation rubric

The tools fetch and normalize evidence. None of them computes a verdict or a
severity; that judgment lives here. Read this with the tool JSON in hand.
Part A covers the client domain health audit (the primary workflow). Part B
covers inbound sender triage. Thresholds are reasonable defaults, not a
validated model. Attribute provider risk labels to AbstractAPI.

## Field namespaces

Paths below are shorthand for `audit_client_domain` output:

- `dns.*` = `sections.dns`: `mx`, `spf`, `dmarc`, `dkim`, `mta_sts`,
  `tls_rpt`, `bimi`, `dnssec`, `errors`. `audit_domain` and
  `investigate_email` return the same object as their top-level `dns`.
- `bl.*` = `sections.blocklists`: `domain_listings.<domain>.<list>`, `ips[]`
  (each with `source`, `listings`, `ptr`, `fcrdns`, `ptr_looks_generic`),
  `skipped_ranges`, `skipped_ips`, `resolver_note`, `resolver_canaries`,
  `errors`.
- `reg.*` = `sections.registration.registration`: `registrar`, `created`,
  `expires`, `last_changed`, `domain_age_days`, `days_until_expiry`,
  `statuses`, `on_hold`, `pending_delete`, `transfer_locked`,
  `auto_renew_period`, `nameservers`, `dnssec_delegation_signed`. `reg.source` = `sections.registration.source`.
- `hdr.*` = `sections.headers`: `from`, `receiver_verdict`, `alignment`,
  `dkim_signatures`, `selectors`, `sending_ip`, `sending_ip_source`,
  `authentication_results`, `arc_authentication_results`, `received_chain`,
  `list_unsubscribe`, `list_id_present`, `list_id_domain`, `spam_headers`,
  `warnings`.
- `rep.*` = `sections.reputation.signals`, with `sections.reputation.source`.
  `investigate_email` returns the same object as top-level `signals` and
  `source`.
- `xc.*` = `cross_checks`. `true`/`false` is a result. `null` means the
  check couldn't be evaluated (no headers, a missing section, or a failed
  lookup). Specific semantics:
  - `header_sending_ip_in_spf`: walks the domain's own SPF record left to
    right, first match wins, without expanding lookups. `true` means the
    first `ip4:`/`ip6:` term containing the IP is `+`-qualified, or nothing
    contains it and the record reaches `+all` with every earlier
    `include`/`a`/`mx`/`ptr`/`exists` also `+`. `false` means the first
    containing term is `-`/`~`/`?`, or nothing contains it and the record
    reaches a `-`/`~`/`?` `all`, or ends with no `all` and no `redirect=`
    (or there's no SPF record, or there are multiple SPF records, a
    permerror that never authorizes). `null` means an unexpanded term came before
    the deciding one, only `redirect=` remains, or the IP or SPF is
    unknown. When it's `null`, rely on `hdr.receiver_verdict.spf`.
  - `header_dkim_selectors_in_dns`: `{selector: bool | null}`, looked up
    under the **target** domain. `null` means that selector's lookup
    failed. A signature whose `d=` is a different (sub)domain can show
    `false` even though its key exists under that `d=`, so check
    `hdr.dkim_signatures[].d` before calling it a finding.
  - `header_alignment_per_dmarc_policy`: `{adkim, aspf, spf_aligned,
    dkim_aligned}` against the domain's published modes (strict honored).
    **This, or `hdr.receiver_verdict.dmarc` = `pass`, is the proof of
    alignment.** `hdr.alignment.*` is always relaxed, so it can say
    "aligned" where a strict policy fails. Use it only when this is `null`,
    and say so.
  - `registration_nameservers_match_dns`: `null` if the NS lookup failed.
  - `header_from_matches_target`, `dmarc_rua_present`,
    `provider_spf_include_present`: booleans, or `null` when an input is
    missing.
- `skipped.<section>`: why a section is `null` by design (for example, no
  headers were pasted). Report it as "not checked", which is different
  from unknown.

## Rule zero: unknown is not pass or fail

Each of these means **Unknown, re-check** for the value it covers. It is
never a finding in either direction:

- `found: null` (the lookup for that record failed), or any other field
  that's `null` because its lookup failed (for example `dns.dmarc.has_rua`
  when the org-domain fallback failed).
- A listing with `listed: null`: statuses `query_refused`,
  `unreliable_resolver`, `lookup_failed`, `unexpected_answer`, `skipped`.
- A lookup error ending in `(invalid_query_name)` in `dns.errors.<section>`
  (a malformed name the tool refused to query). A malformed SPF
  include/redirect/a/mx/exists target is different: it's a permerror
  finding (see section 3), not an unknown.
- `dns.spf.provider_include_present: null`: no provider include was found,
  but part of the include tree couldn't be read.
- `fcrdns: null`, `reg.source.ok: false`, or a non-empty
  `section_errors.<section>` (that whole section is unknown).

**Scope the unknown per field.** A non-empty `dns.errors.<section>` does
not make the whole section unknown. Only the fields that failure affects
are unknown, and positive evidence still in the output stands as a finding:
`cname_without_key`, a 1024-bit key, `p=none`, `multiple_records`, a
permerror. Examples:

- One DKIM selector failed (listed in `dns.dkim.selectors_failed`): only
  that selector is unknown. Grade `selectors_found` normally. Don't call
  `dns.dkim.found: false` "no DKIM" while `selectors_failed` is non-empty;
  say "not found under the selectors that resolved", plus an unknown.
- An external report authorization lookup failed: only that
  `rua_external_authorization.<dest>` value is unknown.
- Lookups failed inside the SPF include tree
  (`dns.spf.lookup_count_is_minimum` is `true`): `dns_lookup_count` is a
  lower bound. Say "at least N", and still flag it if N reaches a band.
  Past the 10-lookup limit the tool stops expanding and reports 11
  (`lookup_limit_exceeded: true`, `lookup_count_is_minimum: true`); say
  "at least 11". A `redirect=` it didn't reach has `includes[].status`
  `limit_reached`, so `effective_all_mechanism`/`effective_strict` are
  unknown.
- The MTA-STS policy fetch failed: the policy fields are unknown, but a
  `multiple_records: true` TXT finding still stands.

List unknowns in the report's "Unknowns to re-check" with how to re-check:
run again from a network with its own or an ISP resolver (see
`bl.resolver_canaries`), retry after a rate limit, or check the registry's
WHOIS for ccTLDs without RDAP (`reg.source.error` `not_found_or_no_rdap`).

**Blocklist canaries.** `bl.resolver_canaries.<list>` is `"ok"` when the
resolver returned that list's always-listed test entry. Any other value
(`"refused"`, `"no_answer"`, `"lookup_failed"`) means that zone's answers
through this resolver can't be trusted, and its empty answers come back as
`unreliable_resolver` with `listed: null`. Report those lists as unknown,
never clean.

**Approximate org domain.** When `org_domain_approximate` is `true` (common
for ccTLDs such as `.co.uk` or `.com.au`), `org_domain` was derived without
a full Public Suffix List and may be wrong. Sanity-check it before trusting
DMARC inheritance (`dns.dmarc.inherited_from`), relaxed alignment, or
org-domain RDAP and blocklist results. If it's wrong, treat those as
unknown.

---

# A. Client health audit rubric

## Severity scale

- **Critical:** mail is being rejected or junked now, or will be soon. Fix
  today.
- **High:** a material deliverability or spoofing risk, or a failed
  Gmail/Yahoo/Microsoft requirement. Fix this week.
- **Medium:** weakens reputation or blocks the path to enforcement. Plan
  the fix.
- **Low:** hardening or best practice.
- **Info:** context only.

Each finding names the field that produced it. Apply the modifiers under
each table before assigning the final severity.

## Critical

| Finding | Field(s) |
|---|---|
| Domain on registry or registrar hold | `reg.on_hold` is `true` |
| Domain pending deletion or in redemption | `reg.pending_delete` is `true` |
| Domain expires in under 14 days, or has expired | `reg.days_until_expiry` `< 14` (negative means expired) |
| No MX where the domain hosts mailboxes | `dns.mx.found` is `false` or `dns.mx.null_mx` is `true`, and the client uses the domain for mailboxes |
| SPF authorizes the whole internet | `dns.spf.plus_all` is `true`, or `dns.spf.effective_all_mechanism` is `+all` |
| SPF permanently errors | `dns.spf.permerrors` non-empty, including `lookup_limit_exceeded`, `void_limit_exceeded`, and an `mx` mechanism with more than 10 MX records |
| More than one SPF record | `dns.spf.multiple_records` is `true` |
| More than one DMARC record (DMARC is ignored) | `dns.dmarc.multiple_records` is `true` |
| Domain on a domain blocklist | `bl.domain_listings.*.spamhaus_dbl.listed`, `.surbl.listed`, or `.uribl.listed` is `true` (URIBL **black** or **red**) |
| Sending IP on a reputation blocklist | `bl.ips[].listings.spamhaus_zen` has an SBL, CSS, XBL, or DROP code, or `barracuda`/`spamcop` is `listed: true` |
| A real receiver failed DMARC for the client's mail | `hdr.receiver_verdict.dmarc` is `"fail"` with `xc.header_from_matches_target` `true` |

Modifiers:

- **SPF permerror with aligned DKIM** (`xc.header_alignment_per_dmarc_policy.dkim_aligned`
  `true`): DMARC still passes. Grade it **High**; one forwarding hop or one
  DKIM problem from failing is still urgent.
- **DBL codes `127.0.1.102`–`.106`** ("abused legit"): the client's own
  site or form is being abused. Still Critical, but the fix is cleaning up
  the site, then delisting.
- **XBL** means a compromised host behind that IP. Investigate the
  client's network before requesting delisting.

## High

| Finding | Field(s) |
|---|---|
| No DMARC record, or an invalid policy | `dns.dmarc.found` is `false`, or `found` `true` with `policy_valid` `false` |
| No DKIM key found | `dns.dkim.found` is `false` and `dns.dkim.selectors_failed` is empty (see the DKIM modifier) |
| DKIM CNAME with no key behind it (signing never activated) | any `dns.dkim.selectors_found.*.cname_without_key` is `true` |
| DKIM key revoked on the selector in use | `selectors_found.<s>.revoked` is `true`, where `<s>` is in `hdr.selectors` or is the only selector found |
| No SPF record | `dns.spf.found` is `false` |
| Mail provider's SPF include missing | `dns.spf.provider_include_present` is `false` (compare `dns.spf.expected_provider_include`) |
| No DMARC aggregate reporting | `dns.dmarc.has_rua` is `false` (or `xc.dmarc_rua_present` `false`) |
| External `rua`/`ruf` destination hasn't authorized reports | any `dns.dmarc.rua_external_authorization.<dest>` is `false` |
| Receiver saw no aligned DKIM pass | `xc.header_alignment_per_dmarc_policy.dkim_aligned` is `false` |
| Receiver saw SPF fail or softfail | `hdr.receiver_verdict.spf` is `fail`/`softfail`, or `xc.header_sending_ip_in_spf` is `false` (ignore that when `hdr.sending_ip_source` is `x_originating_ip`/`x_sender_ip`) |
| Microsoft composite auth failed | `hdr.receiver_verdict.compauth` is `fail` |
| Receiver filed the test message as spam | `hdr.spam_headers.x_forefront_antispam_report.SCL` `>= 5`, `x_ms_exchange_organization_scl` `>= 5`, or `x_spam_flag` is `YES` |
| Self-hosted sending IP has no or a non-matching PTR | `bl.ips[].fcrdns` is `false` |
| Self-hosted sending IP looks residential or dynamic | `bl.ips[].ptr_looks_generic` is `true` |
| Self-hosted sending IP in an end-user range | `bl.ips[].listings.spamhaus_zen` has a PBL code (`127.0.0.10`/`.11`) |
| Sending IP on PSBL | `bl.ips[].listings.psbl.listed` is `true` |
| Domain expires within 45 days | `reg.days_until_expiry` `< 45` |

Modifiers:

- **DKIM not found** depends most on the test message. Selector discovery
  without headers is guesswork against a list of common selectors. If
  `xc.header_alignment_per_dmarc_policy.dkim_aligned` is `true`, there's
  **no finding**: DKIM works under a selector that wasn't probed. Rerun
  with `selectors` set to `hdr.selectors` to grade the key. Without
  headers, report "High, unconfirmed: no DKIM under common selectors; send
  a test message to confirm." A `false` in `xc.header_dkim_selectors_in_dns`
  means that selector didn't resolve under the target domain; re-check it
  only if the matching `hdr.dkim_signatures[].d` is the target domain.
- **Provider include missing** only matters if outbound mail actually
  leaves through that provider. A gateway (`dns.mx.security_gateway`) or a
  relay can change the path. `null` means no known include applies.
- **SPF unaligned** (`spf_aligned` `false`) is normal for ESPs that use
  their own bounce domain. If DKIM is aligned, DMARC passes; grade it
  **Low**. It's High only if DKIM is also unaligned.
- **PTR/PBL findings** apply only to IPs the client operates
  (`bl.ips[].source` from SPF `ip4`/`ip6`/`a`/`mx`, or a header IP from the
  client's own server). Ignore them when `hdr.sending_ip_source` is
  `x_originating_ip`/`x_sender_ip` (the end user's device). A Google or
  Microsoft shared IP is the provider's concern.
- **Mailbox signals are not sender reputation.** AbstractAPI scores the
  address as a sign-up or fraud risk. `rep.deliverable: false` on a client
  mailbox is worth a Medium check with the client (is the mailbox real and
  accepting mail?). `rep.address_risk: "high"` on the client's own mailbox
  is an account-security prompt, not a deliverability finding.
- **Breaches** (`rep.total_breaches` `> 0`) are a Low **account-security**
  item: enforce MFA, reset the password, and check mailbox rules and
  forwarding. Raise it to High alongside signs of abuse (XBL, a DBL abuse
  code). Breach data is PII: show it, don't persist it.

## Medium

| Finding | Field(s) |
|---|---|
| DMARC monitoring only | `dns.dmarc.effective_policy` is `"none"`. The fix is the staged rollout. |
| DMARC in test mode | `dns.dmarc.testing` is `true` (RFC 9989 `t=y`); receivers treat it as not enforced |
| DMARC partially applied (legacy `pct`) | `dns.dmarc.pct` `< 100`. Obsolete under RFC 9989 but still honored by many receivers. |
| 1024-bit DKIM key | `selectors_found.*.key_bits` is `1024` (rotate to 2048) |
| DKIM key under 1024 bits | `key_bits` `< 1024`. Grade **High**; many receivers treat it as failing. |
| DKIM in testing mode | `selectors_found.*.testing` is `true` |
| SPF approaching the 10-lookup limit | `dns.spf.dns_lookup_count` 8–10 ("at least N" if `lookup_count_is_minimum`) |
| SPF void lookups present | `dns.spf.void_lookup_count` 1–2 (more is a Critical permerror) |
| SPF uses `ptr` | `dns.spf.has_ptr` is `true` |
| SPF neutral or missing `all` | `dns.spf.effective_all_mechanism` is `?all`, or `null` with `effective_strict` `false`. `effective_strict: null` means the `redirect=` chain didn't resolve: unknown, not missing. |
| Bulk mail without one-click unsubscribe | `hdr.list_unsubscribe.one_click` or `present` is `false`, and the client sends bulk or subscribed mail |
| MTA-STS in testing mode | `dns.mta_sts.policy.mode` is `"testing"` |
| MTA-STS doesn't cover every MX | `dns.mta_sts.mx_covered` is `false`. **High** if `mode` is `"enforce"`. |
| MTA-STS published but broken | `dns.mta_sts.found` `true` with `policy_valid` `false` (name `policy_errors`), or `multiple_records` `true`. `policy_valid: null` from a failed fetch is unknown. |
| Registration nameservers differ from live DNS | `xc.registration_nameservers_match_dns` is `false` |
| Header From doesn't match the audited domain | `xc.header_from_matches_target` is `false`. Header findings don't apply; re-test. |
| Newly registered domain | `reg.domain_age_days` `< 30` (needs gradual volume warm-up) |
| Elevated bulk-complaint level | `hdr.spam_headers.x_microsoft_antispam.bcl` `>= 7` |
| URIBL grey listing | `bl.domain_listings.*.uribl` has a `grey` code (a scoring signal, not a block) |

## Low

| Finding | Field(s) |
|---|---|
| No MTA-STS | `dns.mta_sts.found` is `false` |
| No TLS-RPT | `dns.tls_rpt.found` is `false` |
| SPF `~all` without enforced DMARC | `dns.spf.effective_all_mechanism` is `~all` and `dns.dmarc.enforced` is `false` (not `null`). The fix is DMARC enforcement, not SPF `-all`. |
| DNSSEC not signed | `reg.dnssec_delegation_signed` is `false` |
| Registrar transfer lock off | `reg.transfer_locked` is `false` |
| Mailbox in known breaches (account security) | `rep.total_breaches` `> 0` |
| SPF unaligned while DKIM is aligned | `spf_aligned` `false`, `dkim_aligned` `true` |
| Revoked or legacy key on an unused selector | `revoked` `true` on a selector not in use |

## Info

- **No BIMI** (`dns.bimi.found` `false`). Needs DMARC enforcement
  (`dns.dmarc.enforced` `true`, not testing), and Gmail also needs a VMC or
  CMC. Suggest it only after enforcement.
- **SPF `~all` with enforced DMARC.** Acceptable and common. `-all` is
  optional, not a finding.
- **DMARC inherited** from the org domain (`dns.dmarc.inherited_from`
  set). `sp=` governs this domain.
- **Strict alignment** (`adkim`/`aspf` = `s`). Confirm every third-party
  sender uses the exact domain.
- **`np=` / `psd=`** (`dns.dmarc.np`, `dns.dmarc.psd`). Mention only if
  present or the client asks about subdomain spoofing.
- **Security gateway in MX** (`dns.mx.security_gateway`). Check its SPF
  include and DKIM setting.
- **`rep.is_catchall` `true`.** More inbound spam and backscatter, not an
  outbound problem.
- **`dns.dnssec.ad_flag`.** Meaningful only from a validating resolver.
- **`bl.skipped_ranges`.** SPF CIDR ranges weren't expanded. If the client
  owns them, rerun with specific `sending_ips`.

## Overall health grade

This grades the domain's configuration, not anyone's trustworthiness.

1. Any Critical: **At risk**.
2. Otherwise any High: **Needs work**.
3. Otherwise any Medium or Low: **Healthy with recommendations**.
4. Otherwise: **Healthy**.

If an unknown covers a check that could have produced a Critical or High
(MX, SPF, DMARC, blocklists with `listed: null`, registration unavailable),
add **"(provisional)"** and name the re-check that would settle it. If no
test message was supplied, say the grade reflects published configuration
only.

## Bulk sender checklist

Applies to senders of roughly **5,000+ messages a day** to the provider's
consumer users: Gmail and Yahoo since February 2024, Microsoft
Outlook.com/Hotmail.com/Live.com since May 5, 2025. Report it for every
client; the bulk items matter once volume nears the threshold.

| Requirement | Gmail/Yahoo | Microsoft | Field(s) |
|---|---|---|---|
| SPF passes | all senders (SPF **or** DKIM); bulk: both | bulk: required | `dns.spf.found`, empty `permerrors`, `hdr.receiver_verdict.spf` = `pass` |
| DKIM passes | all senders (SPF **or** DKIM); bulk: both | bulk: required | `dns.dkim.found`, `hdr.receiver_verdict.dkim` = `pass` |
| DMARC published (`p=none` minimum) | bulk | bulk | `dns.dmarc.found`, `policy_valid` |
| DMARC alignment | bulk | bulk | `hdr.receiver_verdict.dmarc` = `pass`, or `xc.header_alignment_per_dmarc_policy` aligned with a pass |
| Forward and reverse DNS for sending IPs | all senders | recommended | `bl.ips[].fcrdns` (self-hosted only) |
| TLS in transit | all senders | recommended | Not checked. Look for `ESMTPS` in Received hops, or Postmaster Tools. |
| Spam rate under 0.3% (target under 0.1%) | all senders | keep complaints low | Client only: Postmaster Tools |
| One-click unsubscribe (RFC 8058), honored within 2 days | bulk | functional unsubscribe expected | `hdr.list_unsubscribe.one_click`, `present` |
| Don't impersonate other From domains | all senders | n/a | `xc.header_from_matches_target` |

Enforcement is moving. Microsoft first said non-compliant bulk mail would
go to Junk, then an April 2025 update described rejection with
`550 5.7.515`; its own messaging conflicts, so **check provider docs**
before telling a client which outcome to expect. Gmail has been rejecting a
growing share of non-compliant mail since November 2025.

---

# B. Inbound sender triage

Use this when the target is someone else's address. Lead with one
evidence-led assessment: **High risk**, **Caution**, **No red flags
found**, or **Insufficient evidence**. Name every signal that drove it,
with its field. These are assessments of the evidence, not a trust or block
decision; never call a sender "verified safe" or recommend automatic
blocking.

`investigate_email` returns `signals` (= `rep.*`) and `dns`. If
`audit_client_domain` was used with the received message, `hdr.*`, `bl.*`,
and `reg.*` are available too. Prefer `reg.domain_age_days` over
`rep.domain_age_days`, and `dns.*`/`hdr.*` over `rep.spf_strict` and
`rep.dmarc_enforced`.

## 1. Completeness first

- `ok: false`: stop. Explain the setup or provider error. No assessment and
  no DNS-only fallback.
- `source.ok: true` is a successful lookup, not full coverage. Missing or
  `null` signals stay unknown (rule zero), often because of the API plan.
- If the evidence supports neither a concern nor a useful clean finding,
  use **Insufficient evidence** and name what's missing.

## 2. High risk

Any one, attributed to its source:

- `rep.address_risk` is `"high"` (AbstractAPI's label).
- `rep.is_disposable` and a domain under 90 days old (a heuristic, not
  proof of fraud; say so).
- Domain listed for abuse: `spamhaus_dbl` codes `127.0.1.2`/`.4`/`.5`/`.6`,
  SURBL `phishing`/`malware`, or URIBL `black`.
- A received message failed DMARC (`hdr.receiver_verdict.dmarc` = `fail`)
  under an enforced policy (`dns.dmarc.enforced` `true`) with no forwarding
  explanation: no passing ARC result and no forwarder or mailing-list hop
  in `hdr.received_chain` (and `hdr.list_id_present` not `true`). With a
  forwarding explanation, use Caution.
- `reg.domain_age_days` `< 14` and the message asks for payment,
  credentials, or a download.
- `rep.is_risky_tld` plus at least one other risk signal from this list or
  the Caution list.

A breach hit or a risky TLD alone is not High risk. A breached mailbox
isn't thereby attacker-controlled.

## 3. Caution

If not High risk, any specific supported concern:

- `rep.address_risk` `"medium"`, or `rep.domain_risk` `"medium"`/`"high"`.
- Disposable address, domain under 90 days, risky TLD, or suspicious
  username (weak heuristics; state the limits).
- Undeliverable mailbox (use `rep.deliverability_detail`; a full mailbox
  is a delivery problem, not fraud), or a catch-all.
- Breach exposure: account hygiene, not evidence the sender is hostile.
  Suggest verifying unusual requests out of band.
- `rep.is_free_email` and `rep.is_role` together (for example
  `billing@` at a free provider).
- Null MX (`dns.mx.null_mx` `true`): the domain advertises no mail service.
- DMARC fail explained by forwarding, DMARC fail under `p=none`,
  `compauth` fail, or no aligned pass in
  `xc.header_alignment_per_dmarc_policy`.
- Malformed SPF names (a `dns.spf.permerrors` entry ending in
  `(invalid_query_name)`, or a `dns.spf.includes[].status` of
  `invalid_query_name`).
- Sending IP or domain listed (ZEN SBL/XBL/CSS, Barracuda, SpamCop, URIBL
  grey, DBL "abused legit"), or `reg.on_hold`/`reg.pending_delete`.

Missing SPF or DMARC alone is a configuration finding, not a reason to
accuse a sender. Missing MX is inconclusive (SMTP can fall back to A/AAAA).
Resolve contradictory evidence explicitly.

## 4. No red flags found

Use this only when nothing above applies and there's meaningful positive
evidence: `rep.address_risk` and `rep.domain_risk` both `"low"` and the
address deliverable. A `rep.quality_score` over 0.7, enforced DMARC, an
old domain, and `hdr.receiver_verdict.dmarc` = `pass` corroborate it. If
the data is mostly null, use **Insufficient evidence** instead.

DMARC pass shows the **domain** is authentic, not that the **request** is.
A compromised real account passes everything. For payment or credential
requests, always recommend verification through a known independent
channel.
