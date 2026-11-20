# Remediation records

Copy-pasteable fixes for the client's administrator. This plugin never
changes DNS; every record here is a recommendation. Replace `example.com` with the client's domain. Pick
the provider section from `dns.mx.provider`. If `dns.mx.security_gateway`
is set, the mailbox provider is usually the next entry in
`dns.mx.providers_detected`. Ask the client if you're unsure. Always tell
the client to copy exact values (DKIM keys and CNAME targets) from their
provider's admin console. The values below are well-known public defaults,
and when a value varies by tenant or region, it is marked **check provider
docs**.

DNS changes can take up to the record's TTL to propagate. Run
`audit_client_domain` (or `audit_domain` for DNS only) again afterward to
confirm. Values here were checked against vendor docs on 2026-11-19.

## SPF basics

The domain gets **one** TXT record at the apex. Combine every sender into
it:

```
example.com.  TXT  "v=spf1 include:<provider include> include:<esp include> ~all"
```

- `~all` (softfail) is the standard choice once DMARC is enforced, and
  `-all` is optional. Never use `+all`.
- There is a limit of **10 DNS-querying terms** in total (`include`, `a`,
  `mx`, `ptr`, `exists`, and `redirect`, counted recursively), and at most
  2 void lookups. `ip4:` and `ip6:` terms are free.
- Only list senders that use the client's domain as the **envelope**
  sender (Return-Path). Most ESPs use their own bounce domain, so they
  need DKIM, not an SPF include on the root domain.

### Fixing SPF lookup overflow (`lookup_limit_exceeded`, or a count of 8–10)

Try these in order:

1. **Remove unused includes.** Ask the client which services still send.
   Old ESPs, a previous mail host, and duplicate includes are common.
   Remove `ptr` (deprecated) and `a`/`mx` when those hosts don't send
   mail.
2. **Move bulk or marketing senders to a subdomain.** For example, have
   the ESP send from `news.example.com` or use its custom-return-path
   (bounce) subdomain feature. The subdomain then has its own SPF record,
   and DKIM aligns under the organizational domain with relaxed
   alignment.
3. **Replace an include with `ip4:`/`ip6:`** only for IPs the client
   controls and that rarely change.
4. **Flattening** (resolving includes into IP lists) works only with a
   service that refreshes it automatically. Hand-flattened records break
   silently when a provider changes IPs.

## Per-provider records

### Google Workspace (`google`)

- **MX:** `example.com. MX 1 smtp.google.com.` This is Google's current
  single-record setup. Older setups list `aspmx.l.google.com` and
  alternates, which also work.
- **SPF:** `v=spf1 include:_spf.google.com ~all`
- **DKIM:** go to Admin console (admin.google.com) → **Apps → Google
  Workspace → Gmail → Authenticate email**. Select the domain, then
  **Generate new record** (choose a 2048-bit key; the default selector
  prefix is `google`). Publish the TXT at `google._domainkey.example.com`,
  wait for DNS, then click **Start authentication**. Signing doesn't begin
  until you click it.

### Microsoft 365 (`microsoft365`)

- **MX:** the tenant-specific host shown in the Microsoft 365 admin
  center (**Settings → Domains**), traditionally
  `example-com.mail.protection.outlook.com`. Domains with DNSSEC/DANE
  enabled, and newly added domains, use a host under `mx.microsoft` (for
  example, `example-com.o-v1.mx.microsoft`), so copy the exact value from the
  admin center (**check provider docs**).
- **SPF:** `v=spf1 include:spf.protection.outlook.com ~all`
- **DKIM:** go to the Microsoft Defender portal → **Email & collaboration
  → Policies & rules → Threat policies → Email authentication settings →
  DKIM** (https://security.microsoft.com/authentication?viewid=DKIM).
  Select the domain. The portal shows two CNAMEs, `selector1._domainkey`
  and `selector2._domainkey`. Publish them **exactly as shown**, because
  the targets are tenant-specific (current format:
  `selector1-example-com._domainkey.<tenant>.n-v1.dkim.mail.microsoft`;
  older tenants use `..._domainkey.<tenant>.onmicrosoft.com`). Then toggle **Sign messages for this
  domain with DKIM signatures** to Enabled. If the CNAMEs exist but
  `cname_without_key` is `true`, signing was never enabled. In PowerShell,
  `Get-DkimSigningConfig` and `Set-DkimSigningConfig -Identity example.com
  -Enabled $true` do the same.

### Zoho Mail (`zoho`)

- **SPF:** `v=spf1 include:zohomail.com ~all` for US-hosted orgs (Zoho
  suggests `include:one.zoho.com` instead if the domain also sends from
  other Zoho apps). Regional data centers may use a regional include (for
  example, EU), so use the exact value Zoho's admin console shows (**check
  provider docs**).
- **DKIM:** go to Zoho Mail Admin Console → **Domains** → the domain →
  **Email Configuration → DKIM**. Add a selector, then publish the TXT
  record shown at `<selector>._domainkey.example.com`, then **Verify** and
  enable it. The selector name is chosen by the admin, so pass it in
  the audit's `selectors`. Menu names may vary, so **check provider docs**.

### Proton Mail (`proton`)

- **SPF:** `v=spf1 include:_spf.protonmail.ch ~all`
- **DKIM:** go to Proton **Settings → All settings → Organization →
  Domain names** → **Review** next to the domain → **DKIM** tab. Publish the three CNAMEs (`protonmail._domainkey`,
  `protonmail2._domainkey`, and `protonmail3._domainkey`) with the
  domain-specific targets shown there.

### Fastmail (`fastmail`)

- **SPF:** `v=spf1 include:spf.messagingengine.com ~all`
- **DKIM:** go to Fastmail **Settings → Domains** → the domain. If
  Fastmail hosts the DNS, the records are automatic. Otherwise publish the
  CNAMEs it lists (`fm1._domainkey`, `fm2._domainkey`, and
  `fm3._domainkey`, pointing to `fm1.example.com.dkim.fmhosted.com`,
  `fm2.example.com.dkim.fmhosted.com`, and `fm3.example.com.dkim.fmhosted.com`).
  Fastmail's own SPF example ends in `?all`; `~all` also works.

### Generic / other / self-hosted (`other`, or `null`)

- **SPF:** list the actual outbound servers (`ip4:` for a self-hosted MTA)
  plus each service's documented include. If outbound mail goes through a
  security gateway (Mimecast, Proofpoint, or Barracuda), use the
  gateway's region-specific include (**check provider docs**).
- **DKIM:** enable it in each platform's admin area. For a self-hosted MTA,
  generate a 2048-bit key (for example, with OpenDKIM or the MTA's
  built-in signer) and publish
  `<selector>._domainkey.example.com TXT "v=DKIM1; k=rsa; p=<base64 key>"`.
- **Third-party senders** (newsletter, CRM, invoicing, helpdesk): in each
  one, find "domain authentication" or "sender authentication" and
  publish the DKIM CNAMEs it gives. This is what makes their mail pass
  DMARC.

### Rotating a 1024-bit key, or removing `t=y`

Generate a new 2048-bit key in the provider console. Microsoft 365 uses
**Rotate DKIM keys** in the same DKIM page. Google requires a new record
followed by Start authentication. Then publish it and remove `t=y` once
signing is verified.

## DMARC: starter record and staged rollout

One TXT record, at `_dmarc.example.com`:

```
Stage 1 (monitor, 2-4 weeks minimum):
_dmarc.example.com.  TXT  "v=DMARC1; p=none; rua=mailto:dmarc@example.com"

Stage 2 (quarantine, once every legitimate sender passes aligned):
_dmarc.example.com.  TXT  "v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com"

Stage 3 (reject):
_dmarc.example.com.  TXT  "v=DMARC1; p=reject; rua=mailto:dmarc@example.com"
```

- Read the aggregate (`rua`) reports at every stage. A DMARC report
  analyzer service makes them readable. Move to the next stage only when
  every legitimate source shows aligned SPF or DKIM passes.
- `pct=` is obsolete in the current DMARC spec (RFC 9989), which replaces
  it with `t=y` (test mode, roughly the old `pct=0`). Many receivers still
  honor `pct=`, but don't rely on partial ramps; leaving it under 100 (or
  `t=y`) means the policy is only partly applied.
- `sp=` sets the policy for subdomains. It defaults to `p=`. Consider
  `sp=reject` early for subdomains that never send mail.
- **External report address:** if `rua` points to another domain (for
  example, a report vendor), that domain must publish an authorization
  record. Reputable vendors do this automatically:

  ```
  example.com._report._dmarc.vendor.example.  TXT  "v=DMARC1"
  ```

  If `rua_external_authorization` is `false` for a vendor, contact the
  vendor or use an address on the client's own domain.
- Remove any duplicate `_dmarc` records. Exactly one is allowed.

## MTA-STS and TLS-RPT

These protect mail **to** the client from TLS downgrade, and the reports
show TLS failures.

1. TLS-RPT (start here; it is harmless):

   ```
   _smtp._tls.example.com.  TXT  "v=TLSRPTv1; rua=mailto:tlsrpt@example.com"
   ```

2. Host the policy file at `https://mta-sts.example.com/.well-known/mta-sts.txt`.
   It needs a valid HTTPS certificate for `mta-sts.example.com`, and the
   file must be served without redirects:

   ```
   version: STSv1
   mode: testing
   mx: smtp.google.com
   max_age: 604800
   ```

   Put one `mx:` line per MX host. Wildcards are allowed, for example
   `mx: *.mail.protection.outlook.com` for Microsoft 365. A wildcard matches
   only one label, so list an `mx.microsoft` host exactly (**verify in
   provider docs**). The `mx:` lines
   must cover every host in `dns.mx.records`.
3. Announce it:

   ```
   _mta-sts.example.com.  TXT  "v=STSv1; id=20261119T000000"
   ```

   Change `id` every time you edit the policy file.
4. After a couple of weeks of clean TLS reports, change to `mode: enforce`,
   raise `max_age` (for example, `1209600` or longer), and bump `id`.

## BIMI (only after DMARC enforcement)

Prerequisites: `p=quarantine` or `p=reject` with `pct=100` and no `t=y`, a logo in
**SVG Tiny Portable/Secure (SVG Tiny PS)** format, and for Gmail, a VMC
(trademarked logo) or CMC certificate.

```
default._bimi.example.com.  TXT  "v=BIMI1; l=https://example.com/bimi/logo.svg; a=https://example.com/bimi/certificate.pem"
```

Leave `a=` empty (`a=;`) when there is no certificate. Some providers
still show the logo without one, but Gmail won't.

## Reverse DNS (PTR) for self-hosted sending IPs

PTR records are set by whoever owns the IP block, which is the hosting,
cloud, or ISP provider, not the domain's DNS host. Ask them to set:

```
<sending IP>  PTR  mail.example.com.
mail.example.com.  A  <sending IP>     # forward record must match (FCrDNS)
```

Use a descriptive mail hostname, not a generic one that embeds the IP.
Residential or dynamic IPs (`ptr_looks_generic`, Spamhaus PBL) shouldn't
send mail directly. Relay through the mail provider or a smarthost
instead.

## Blocklist delisting

Fix the cause first (a compromised account or host, an open relay, a
hacked website, or a purchased list). Otherwise the listing comes back.

- **Spamhaus (ZEN SBL/CSS/XBL/PBL, DBL):** look up and request removal at
  https://check.spamhaus.org/. XBL and PBL have self-service removal. SBL
  and DBL go through a ticket, usually opened by the IP's network owner
  for SBL.
- **Barracuda (BRBL):** https://www.barracudacentral.org/rbl/removal-request
- **SpamCop:** listings **expire automatically**, typically about 24 hours
  after reports stop, so there's no removal form. Check at
  https://www.spamcop.net/bl.shtml.
- **PSBL:** self-service removal at https://psbl.org/.
- **URIBL:** lookup and removal request at https://admin.uribl.com/.
- **SURBL:** lookup and removal at https://surbl.org/surbl-analysis.
- **Microsoft (Outlook.com/Hotmail blocks, `550 5.7.x` mentioning
  S3150 and similar):** https://sender.office.com/ for the delist portal.
  Use SNDS and JMRP for ongoing monitoring.
- **Gmail:** there's no blocklist to request removal from. Fix
  authentication and complaint rate, then use Postmaster Tools and, if
  needed, Google's bulk sender contact form.

## Domain registration

- **Expiring soon:** renew now and enable auto-renew at the registrar.
  Confirm the registrar's billing contact is current.
- **`on_hold` / `pending_delete`:** contact the registrar right away.
  Holds often come from unpaid renewals, failed WHOIS email verification,
  or abuse complaints. Redemption may still be recoverable for a fee.
- **Transfer lock off:** enable "Registrar Lock" (`clientTransferProhibited`)
  in the registrar's control panel.
- **DNSSEC:** enable it at the DNS host, then publish the DS record at the
  registrar. Many registrars do both when they host the DNS.
