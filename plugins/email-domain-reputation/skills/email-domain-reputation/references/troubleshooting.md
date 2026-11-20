# Troubleshooting delivery problems

Use this when the user reports a specific symptom ("mail to Gmail bounces",
"invoices go to spam", "a customer never got it") rather than asking for a
full audit. Start from the symptom, get the evidence that answers it, then
widen to `audit_client_domain` if the cause looks configuration-wide.

Bounce texts and codes change. The meanings below are a starting point
(compiled 2026-11). Quote the exact text from the bounce or NDR, and confirm
unusual codes against the receiving provider's current documentation before
you tell the client what is wrong.

## Symptom → evidence → tool

| Symptom | Ask for | Call | Read first |
|---|---|---|---|
| A message bounced (NDR / "undeliverable") | The full bounce text, especially the `5xx`/`4xx` line and the reporting server | Decode with the table below, then the matching tool | Code meaning, then the fields named in the row |
| Delivered, but to spam/junk | That message's original source from the **recipient's** mailbox | `analyze_headers` | `receiver_verdict` (dmarc, spf, dkim, compauth), `alignment`, `spam_headers` (BCL/SCL), `list_unsubscribe` |
| Never arrived, no bounce | Sender's sent time, recipient address, and whether the recipient checked spam/quarantine | `audit_domain` on the **recipient** domain (MX exists? null MX?), `check_registration` on it | `dns.mx`, `registration.on_hold` / `pending_delete` / `days_until_expiry` (from `check_registration`) |
| Only one platform's mail fails (newsletter, CRM, invoicing) | A test message from **that** platform | `analyze_headers`, then `audit_domain` with its DKIM selector | `alignment.dkim_aligned`, header `selectors`, `dns.dkim.selectors_found.<s>`, `dns.spf.dns_lookup_count` |
| Fails only when forwarded or sent through a mailing list | The received copy after forwarding | `analyze_headers` | `arc_authentication_results`, `receiver_verdict.dmarc`; DMARC `p=reject` with SPF-only alignment breaks on forwarding, so aligned DKIM fixes it |
| "We're blocklisted" / bounce names Spamhaus, Barracuda, SpamCop | The listed IP or domain from the bounce | `check_blocklists(target, sending_ips=[ip])` | `ips[].listings`, `domain_listings`, `resolver_canaries` (unknown is not clean) |
| Mail and website both stopped at once | Nothing | `check_registration`, then `audit_domain` | `registration.on_hold`, `pending_delete`, `days_until_expiry`, `nameservers` |
| Received mail claims to be from the client but they didn't send it (spoofing) | The received message's source | `analyze_headers` | `receiver_verdict.dmarc`, `from.domain` vs `return_path.domain`; then `dns.dmarc.effective_policy` via `audit_domain` |
| Scanner/copier/app can't send | The device's error text | None of these tools test SMTP submission | Usually SMTP AUTH disabled or a connector issue (`5.7.57`, `5.7.64`); see Microsoft below |

A bounce copied from the sender's mailbox is fine for decoding the code. For
`analyze_headers`, the message must come from the **recipient's** side; a
Sent-folder copy has no receiver results.

## Reading an enhanced status code

`class.subject.detail` (RFC 3463). The first digit matters most:

- **`4.x.x`, temporary.** The sender will retry. Repeated `4.7.x` deferrals
  usually mean rate limiting or reputation, not broken DNS.
- **`5.x.x`, permanent.** It won't be retried. Fix the cause, then resend.

Common generic codes:

| Code | Usual meaning | Likely fix |
|---|---|---|
| `5.1.1` / `5.1.10` | Recipient mailbox doesn't exist | Recipient typo or deleted mailbox. Not a domain-health issue |
| `5.2.2` | Recipient mailbox full | Recipient side |
| `5.4.1` | Recipient address rejected (Microsoft: often the recipient isn't in their directory) | Recipient side, or wrong MX at the recipient |
| `5.7.1` | Generic policy rejection | Read the text: it names the real reason (blocklist, spam, relay denied) |
| `4.7.0` / `4.7.1` | Temporary policy deferral (greylisting, rate, TLS) | Usually clears on retry. Persistent → reputation |

## Gmail

| Code | Meaning | Check |
|---|---|---|
| `550 5.7.26` | Unauthenticated: the message failed DMARC, or passed neither SPF nor DKIM | `analyze_headers` `receiver_verdict`; `dns.spf`, `dns.dkim`, `alignment` |
| `550 5.7.25` | The sending IP has no PTR record | `check_blocklists` `ips[].ptr` / `fcrdns`; set PTR with the IP owner |
| `550 5.7.27` | SPF failure for the sending domain (verify the exact text) | `dns.spf.found`, `effective_all_mechanism`, `cross_checks.header_sending_ip_in_spf` |
| `5.7.32` | The From domain doesn't align with the SPF or DKIM domain (bulk-sender rule; verify the exact text) | `alignment.*`, `cross_checks.header_alignment_per_dmarc_policy` |
| `421 4.7.28` / `550 5.7.28` | An unusual rate of unsolicited mail from this IP or domain | Postmaster Tools spam rate; `check_blocklists`; slow sending down |
| `550 5.7.1` "likely unsolicited" | Content or reputation | Postmaster Tools; `list_unsubscribe.one_click` for bulk mail |

## Microsoft 365 / Outlook.com

| Code / text | Meaning | Check / fix |
|---|---|---|
| `550 5.7.1 ... [S3150]` or "blocked using Blocklist 1" | The IP is on Microsoft's own blocklist | Delist at https://sender.office.com |
| "blocked using Spamhaus" | Spamhaus listing (Microsoft quotes it) | `check_blocklists`; delist per `remediation-records.md` |
| `5.7.606`–`5.7.649` | The sending IP is banned by Microsoft | Delist at https://sender.office.com |
| `550 5.7.509` | DMARC failed and the sending domain's policy is `reject` | `analyze_headers` alignment; fix the failing sender, not the policy |
| `550 5.7.515` | Outlook.com bulk-sender rule: the domain doesn't meet the required authentication level | Needs SPF pass, DKIM pass, and DMARC (at least `p=none`) aligned |
| `550 5.7.23` | Rejected for an SPF violation (`-all` hard fail) | `dns.spf`, `cross_checks.header_sending_ip_in_spf` |
| `5.7.705` / `5.7.708` / `5.7.750` | The **sending** tenant is restricted: suspected compromise, high-risk delivery pool, or unregistered domains | Account-security incident. Check for compromised mailboxes and outbound spam in Defender, then request release |
| `5.7.57` | The client isn't authenticated for SMTP submission | SMTP AUTH disabled for the mailbox or tenant; common for scanners and apps |
| `5.7.64` | TenantAttribution: relay access denied | Inbound connector (certificate or IP) misconfigured for relay |
| `4.7.500`–`4.7.699`, `4.4.x` | Throttling or a temporary routing problem | Usually clears. Persistent → reputation or volume |

## Yahoo / AOL

| Code / text | Meaning | Check |
|---|---|---|
| `421 4.7.0 [TSS04]` | Temporarily deferred: complaints, volume, or reputation | Spam complaints, volume spikes, `check_blocklists` |
| `554 5.7.9` | Rejected for policy reasons, often authentication (DMARC) | `analyze_headers` alignment; `dns.dmarc` |
| `553 5.7.2` / `5.7.1` with "[BL21]" style tags | Blocked by IP or domain reputation | `check_blocklists`; Yahoo's sender support form |

## When to escalate to a full audit

Run `audit_client_domain` when the symptom isn't limited to one recipient or
one message: several providers reject, the code points to authentication
(`5.7.26`, `5.7.509`, `5.7.515`, `554 5.7.9`), or one fix is likely to
reveal another. Report the specific symptom first ("Gmail rejects because
DKIM isn't aligned"), then the wider findings.
