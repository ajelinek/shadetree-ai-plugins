"""One-shot email-domain health audit, ported from audit.py.

`run_audit(target, *, raw_headers=None, selectors=None, sending_ips=None,
api_key=None, resolver=None, reputation_result=None)` runs every check module
in-process and combines their outputs into one dict, plus a few cross-section
facts.

reputation_result is an already-fetched reputation.check_reputation result.
When given, it becomes sections.reputation and no API call is made (api_key is
then unused). The audit_client_domain tool uses this to call the API first
and run nothing else when that call fails, so a failed API call sends no
DNS/DNSBL/RDAP/MTA-STS traffic. Standalone run_audit (no reputation_result)
calls the API concurrently with the other sections, as below.

Input validation happens up front, before any network call; invalid input
raises ValueError (`validate_inputs` runs the same checks on their own):
    target       an email address or bare domain (strict normalize_email /
                 normalize_domain)
    raw_headers  pasted message headers or a full message (headers.analyze_headers:
                 non-empty, at most 256 KB, at least one recognizable header)
    selectors    at most 20 DKIM selectors (validate_selectors)
    sending_ips  at most 20 IP address strings; one fewer when the headers
                 supply a sending IP that isn't already listed
    resolver     an IP address, or None for the machine's resolver

Sections (each value is exactly that module's normal output dict, or null
when skipped / failed):
    headers       headers.analyze_headers(raw_headers). Runs first: its aligned
                  DKIM "selectors" are added to the DNS selector list, and its
                  "sending_ip" is added to the blocklist IPs with source
                  "headers". Null without raw_headers.
    dns           dns_auth.build_output (MX/SPF/DMARC/DKIM/MTA-STS/TLS-RPT/BIMI/DNSSEC).
    blocklists    blocklists.build_output (domain + IP DNSBLs, PTR/FCrDNS);
                  sending_ips use source "argument".
    registration  registration.build_output (RDAP).
    reputation    reputation.check_reputation's {signals, source} result (or the
                  given reputation_result). Runs only when the target is an
                  email address and api_key (or reputation_result) is given.
                  WARNING: contains breach data (PII) for the address -- show it,
                  but don't persist it to tickets, logs or files.

dns, blocklists, registration, reputation and the live NS lookup run
concurrently; the output is assembled in a fixed order.

Output:
    {target (normalized), domain, org_domain, org_domain_approximate,
     generated_at (UTC ISO 8601), resolver ("system" or the IP),
     sections: {dns, blocklists, registration, headers, reputation},
     section_errors: {<section>: message},   # unexpected exceptions; a live
                                             # NS failure is "cross_checks"
     skipped: {<section>: reason},           # why a section is null by design:
                                             # headers "no_raw_headers",
                                             # reputation "not_email_target" |
                                             # "no_api_key"
     cross_checks: {...}}
    org_domain_approximate is true when the domain is under a two-letter
    ccTLD, where org_domain (no full Public Suffix List) may be wrong.

An exception inside one section is caught into section_errors.<section>;
the other sections still run. The API key never appears in section_errors.
Per-lookup failures inside a section stay in that section's own "errors" /
"source" fields.

cross_checks -- deterministic facts that need two sections; null means
"can't tell" (an input section is missing or the fact isn't cheaply known).
No severity or verdict here; judgment lives in the bundled skill.
    header_from_matches_target      headers From org domain == target org domain
    header_dkim_selectors_in_dns    {selector: true|false|null} -- each header
                                    selector found in dns.dkim with a public
                                    key (looked up under the target domain;
                                    a signature whose d= is a different
                                    subdomain may show false); null when that
                                    selector's lookup failed
                                    (dns.dkim.selectors_failed)
    header_sending_ip_in_spf        walks the target's own SPF record left to
                                    right, first match wins: true if the first
                                    ip4:/ip6: term containing the header
                                    sending IP has the "+" qualifier, or no
                                    term contains it and the record reaches
                                    "+all" (with any earlier include/a/mx/ptr/
                                    exists also "+"); false if that term is
                                    -/~/?, or the record reaches a -/~/? "all"
                                    or ends with no all/redirect= (or there is
                                    no SPF record, or multiple SPF records --
                                    a permerror that never authorizes); null if the IP or SPF is
                                    unknown, an unexpanded include/a/mx/ptr/
                                    exists precedes the deciding term, or no
                                    term matches and only redirect= remains
    header_alignment_per_dmarc_policy
                                    {adkim, aspf, spf_aligned, dkim_aligned}:
                                    the received message's alignment re-run
                                    with the domain's DMARC modes
                                    (dns.dmarc.adkim/aspf, default "r"); like
                                    headers.alignment *_pass_aligned it needs
                                    a receiver pass. All null without headers,
                                    without DNS, or when DMARC is unknown;
                                    spf_aligned/dkim_aligned null without a
                                    From domain or Authentication-Results
    dmarc_rua_present               dns.dmarc.has_rua (null if DMARC unknown)
    registration_nameservers_match_dns
                                    RDAP nameserver set == live NS set of the
                                    org domain (null if either is missing)
    provider_spf_include_present    copied from dns.spf.provider_include_present
                                    (null when no match was found but a nested
                                    lookup failed or part of the include tree
                                    wasn't expanded)
"""

from __future__ import annotations

import ipaddress
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime

from . import _dns, blocklists, dns_auth, headers, registration, reputation
from ._domain import (
    domain_from_arg,
    normalize_email,
    org_domain,
    org_domain_is_approximate,
    validate_selectors,
)

SECTIONS = ("dns", "blocklists", "registration", "headers", "reputation")
REDACTED = "[redacted]"


# ---------------------------------------------------------------- sections

def live_nameservers(domain, resolver=None):
    return sorted({a["data"].rstrip(".").lower()
                   for a in _dns.records(domain, "NS", resolver=resolver)})


def guard_secret(secret, fn, *args):
    """-> (result, error message or None); `secret` is scrubbed from messages."""
    try:
        return fn(*args), None
    except Exception as exc:  # isolate one section's failure from the rest
        message = f"{type(exc).__name__}: {exc}"
        return None, message.replace(secret, REDACTED) if secret else message


def _validate_ips(sending_ips, header_ip):
    """Strictly validated user IPs as (ip, "argument") pairs, plus the header IP."""
    ips = [(ip, "argument") for ip, _ in blocklists._validate_ips(sending_ips)]
    if header_ip and all(ip != header_ip for ip, _ in ips):
        if len(ips) >= blocklists.MAX_IPS:
            raise ValueError(f"Supply at most {blocklists.MAX_IPS - 1} IP addresses when the "
                             "headers supply a sending IP.")
        ips.append((header_ip, "headers"))
    return ips


# ------------------------------------------------------------ cross checks

def _spf_ip_match(ip, spf):
    if not ip or not spf or spf.get("found") is None:
        return None
    if not spf["found"] or spf.get("multiple_records"):
        return False  # multiple records: permerror, never authorized
    addr = ipaddress.ip_address(ip)
    records = spf.get("records") or []
    mechanisms, modifiers, _ = dns_auth.parse_spf_terms(records[0]) if records else ([], {}, [])
    # SPF evaluates left to right and the first matching mechanism wins, so an
    # unexpanded lookup mechanism (include/a/mx/ptr/exists) before the match
    # could have matched first with a different qualifier.
    lookup_qualifiers = []
    for mech in mechanisms:
        if mech["name"] in ("ip4", "ip6"):
            try:
                hit = addr in ipaddress.ip_network(mech["value"], strict=False)
            except ValueError:
                continue
            if hit:
                return None if lookup_qualifiers else mech["qualifier"] == "+"
        elif mech["name"] == "all":  # evaluation ends here; redirect= is ignored
            if mech["qualifier"] == "+" and all(q == "+" for q in lookup_qualifiers):
                return True  # every earlier match would also pass
            return None if lookup_qualifiers else False
        else:
            lookup_qualifiers.append(mech["qualifier"])
    return None if lookup_qualifiers or "redirect" in modifiers else False


def _alignment_per_policy(header_info, dmarc):
    unknown = {"adkim": None, "aspf": None, "spf_aligned": None, "dkim_aligned": None}
    if header_info is None or not dmarc or dmarc.get("found") is None:
        return unknown
    adkim, aspf = dmarc.get("adkim") or "r", dmarc.get("aspf") or "r"
    from_domain = (header_info.get("from") or {}).get("domain")
    result = {**unknown, "adkim": adkim, "aspf": aspf}
    if from_domain:
        alignment = headers.build_alignment(
            from_domain, (header_info.get("return_path") or {}).get("domain"),
            header_info.get("authentication_results") or [], aspf=aspf, adkim=adkim)
        result["spf_aligned"] = alignment["spf_pass_aligned"]
        result["dkim_aligned"] = alignment["dkim_aligned"]
    return result


def build_cross_checks(target_org, sections, nameservers):
    header_info, dns = sections["headers"], sections["dns"]
    reg = sections["registration"]

    from_org = ((header_info or {}).get("from") or {}).get("org_domain")
    selectors_in_dns = None
    if header_info is not None and dns is not None:
        found = dns["dkim"]["selectors_found"]
        failed = set(dns["dkim"].get("selectors_failed", []))
        selectors_in_dns = {s: None if s in failed else bool(found.get(s, {}).get("has_public_key"))
                            for s in header_info["selectors"]}

    reg_ns = sorted({n.lower().rstrip(".") for n in
                     ((reg or {}).get("registration") or {}).get("nameservers", [])})
    ns_match = sorted(nameservers) == reg_ns if reg_ns and nameservers else None

    dmarc = (dns or {}).get("dmarc") or {}
    spf = (dns or {}).get("spf")
    return {
        "header_from_matches_target": from_org == target_org if from_org else None,
        "header_dkim_selectors_in_dns": selectors_in_dns,
        "header_sending_ip_in_spf": _spf_ip_match((header_info or {}).get("sending_ip"), spf),
        "header_alignment_per_dmarc_policy": _alignment_per_policy(header_info, dmarc),
        "dmarc_rua_present": dmarc.get("has_rua") if dmarc.get("found") is not None else None,
        "registration_nameservers_match_dns": ns_match,
        "provider_spf_include_present": spf.get("provider_include_present") if spf else None,
    }


# ------------------------------------------------------------------ output

def validate_inputs(target, *, raw_headers=None, selectors=None, sending_ips=None,
                    resolver=None) -> dict:
    """Validate every run_audit input without any network call; ValueError if
    invalid. Returns {target, domain, is_email, headers, selectors, ips}."""
    if not isinstance(target, str):
        raise ValueError("Provide an email address or domain name.")
    is_email = "@" in target
    target = normalize_email(target) if is_email else domain_from_arg(target)
    if resolver is not None and not _dns.is_valid_resolver(resolver):
        raise ValueError("resolver must be an IP address.")
    user_selectors = validate_selectors(selectors)
    header_info = headers.analyze_headers(raw_headers) if raw_headers is not None else None
    if sending_ips is not None and not isinstance(sending_ips, (list, tuple)):
        raise ValueError("sending_ips must be a list of IP addresses.")
    return {
        "target": target,
        "domain": domain_from_arg(target),
        "is_email": is_email,
        "headers": header_info,
        "selectors": list(dict.fromkeys(
            [*user_selectors, *(header_info or {}).get("selectors", [])])),
        "ips": _validate_ips(sending_ips, (header_info or {}).get("sending_ip")),
    }


def run_audit(target, *, raw_headers=None, selectors=None, sending_ips=None, api_key=None,
              resolver=None, reputation_result=None) -> dict:
    """Run the full audit (see the module docstring). Raises ValueError for
    invalid input before any network call."""
    inputs = validate_inputs(target, raw_headers=raw_headers, selectors=selectors,
                             sending_ips=sending_ips, resolver=resolver)
    target, domain, header_info = inputs["target"], inputs["domain"], inputs["headers"]
    ips, all_selectors, is_email = inputs["ips"], inputs["selectors"], inputs["is_email"]

    org = org_domain(domain)
    sections = dict.fromkeys(SECTIONS)
    errors = {}
    skipped = {}

    sections["headers"] = header_info
    if header_info is None:
        skipped["headers"] = "no_raw_headers"

    jobs = {
        "dns": (dns_auth.build_output, domain, resolver, all_selectors),
        "blocklists": (blocklists.build_output, domain, ips, resolver),
        "registration": (registration.build_output, domain),
        "nameservers": (live_nameservers, org, resolver),
    }
    if not is_email:
        skipped["reputation"] = "not_email_target"
    elif reputation_result is not None:
        sections["reputation"] = reputation_result
    elif not api_key:
        skipped["reputation"] = "no_api_key"
    else:
        jobs["reputation"] = (reputation.check_reputation, target, api_key)

    with ThreadPoolExecutor(max_workers=len(jobs)) as pool:
        futures = {name: pool.submit(guard_secret, api_key, *job) for name, job in jobs.items()}
        results = {name: future.result() for name, future in futures.items()}

    nameservers = None
    for name in jobs:  # insertion order -> deterministic section_errors order
        value, error = results[name]
        if name == "nameservers":
            nameservers = value
            name = "cross_checks"
        else:
            sections[name] = value
        if error:
            errors[name] = f"live NS lookup: {error}" if name == "cross_checks" else error

    return {
        "target": target,
        "domain": domain,
        "org_domain": org,
        "org_domain_approximate": org_domain_is_approximate(domain),
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "resolver": _dns.effective_resolver(resolver) or "system",
        "sections": sections,
        "section_errors": errors,
        "skipped": skipped,
        "cross_checks": build_cross_checks(org, sections, nameservers),
    }
