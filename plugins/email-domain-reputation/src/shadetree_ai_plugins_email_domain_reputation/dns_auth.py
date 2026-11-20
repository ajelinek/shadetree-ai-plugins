"""Live DNS inspection of a domain's mail-authentication and transport-security records.

`build_output(domain)` (and the validating `audit_dns(target)`) returns one dict:
MX (provider / security-gateway detection and RFC 7505 null MX), SPF
(recursively expanded, with RFC 7208 lookup and void-lookup counting), DMARC
(organizational-domain inheritance and external report authorization), DKIM
(best-effort selector probing with key size), MTA-STS, TLS-RPT, BIMI, and a
best-effort DNSSEC signal. These are public DNS records (plus the public
MTA-STS policy file over HTTPS); no API key is needed.

Lookups go through `_dns.query` (dnspython) using the machine's resolver, or
an explicit resolver IP passed as `resolver=`. Queries run concurrently.

A lookup that FAILS (SERVFAIL, REFUSED, timeout, ...) is reported in
"errors.<section>" and the section's "found" is null (unknown) -- it is never
reported as "record not found". NXDOMAIN / no data is "not found".

DKIM has no discoverable record without the sender's selector, so this probes
a list of common provider-default selectors (plus any given via `selectors`,
e.g. the s= tag of a real DKIM-Signature header). Absence of a hit does NOT
mean DKIM isn't configured.

DNSSEC: "dnssec.ad_flag" is the AD (authenticated data) bit from an SOA
query. It is only meaningful when the resolver validates DNSSEC; a
non-validating resolver always yields false.

Top-level keys: domain, resolver ("system" or the IP), mx, spf, dmarc, dkim,
mta_sts, tls_rpt, bimi, dnssec, errors.

Fields worth knowing (beyond the obvious record/found/policy values):
    mx.null_mx / accepts_mail       null when the MX lookup failed; accepts_mail
                                    is also null when no MX exists (absent MX
                                    is not proof that mail can't be received)
    spf.all_mechanism / strict      the top-level record's own "all" only;
                                    strict is false with multiple SPF records
    spf.effective_all_mechanism / effective_strict
                                    the top-level "all", else the "all" of the
                                    last record in the followed redirect=
                                    chain (strict null if that chain couldn't
                                    be resolved)
    spf.direct_ips                  ["ip4:...", "ip6:..."] terms (any qualifier)
    spf.direct_ip_terms             [{qualifier: "+|-|~|?", value: "<ip[/cidr]>"}]
    spf.lookup_count_is_minimum     true when a nested lookup failed, a macro
                                    wasn't evaluated, or the lookup limit
                                    stopped expansion, so dns_lookup_count is
                                    a lower bound
    spf.dns_lookup_count            exact for records within the limit; once
                                    it exceeds 10, expansion stops (permerror)
                                    and it reports 11
    spf.includes[].status           ok | loop | depth_exceeded | lookup_failed |
                                    no_spf_record | multiple_records |
                                    macro_not_evaluated | invalid_query_name |
                                    limit_reached (a redirect= not followed
                                    because the lookup limit was exceeded;
                                    effective_strict is then null)
    spf.provider_include_present    true on a match; null when no match but a
                                    nested lookup failed, a macro wasn't
                                    evaluated, or the lookup limit stopped
                                    expansion; else false
    spf.permerrors                  incl. an mx mechanism with >10 MX records
                                    and a malformed include/redirect/a/mx/
                                    exists target ("... (invalid_query_name)")
    spf.*                           found and the derived booleans/counts are
                                    null when the SPF lookup itself failed
    dmarc.testing                   RFC 9989 (DMARCbis) t=y test mode
    dmarc.np / dmarc.psd            RFC 9989 non-existent-subdomain policy /
                                    public-suffix-domain flag (raw values)
    dmarc.record_valid              false for multiple records, duplicate or
                                    malformed tags, v other than DMARC1, an
                                    invalid p/sp, or a pct that isn't 0..100
    dmarc.pct                       legacy RFC 7489 tag; 100 when absent, null
                                    when present but invalid
    dmarc.enforced                  false under t=y, a legacy pct<100, an
                                    invalid record, or a none/invalid policy
    dmarc.found / has_rua / enforced / policy_valid / record_valid /
    effective_policy                null when the lookup -- or the needed
                                    org-domain fallback lookup -- failed
                                    (unknown, not absent)
    dmarc.inherited_from            org domain whose record applies, else null
    dmarc.rua_external_authorization {dest: true|false|null (lookup failed)}
    dkim.selectors_found.<s>        cname_target, cname_without_key, revoked,
                                    key_type, key_bits (RSA modulus from the
                                    DER key; 256 for ed25519), testing,
                                    multiple_records
    dkim.selectors_failed           selectors whose lookup failed (unknown, not
                                    absent); errors.dkim is only a summary
    dkim.found                      true when a usable key was found, null when
                                    none was found but some selector lookups
                                    failed, else false
    mta_sts.policy_valid / policy_errors
                                    RFC 8461 3.2 checks on the fetched policy:
                                    Content-Type text/plain, version STSv1,
                                    mode enforce|testing|none, integer max_age
                                    0..31557600, >=1 mx unless mode none
                                    (null / [] when no policy was fetched)
    mta_sts.mx_covered              every MX host matches a policy mx pattern

This module only fetches and normalizes -- judgment lives in the skill's
interpretation rules.
"""

from __future__ import annotations

import base64
import binascii
import http.client
import re
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

from . import _dns
from ._common import add_error, mechanism_target
from ._domain import (
    MAX_USER_SELECTORS,
    aligned,
    bare_domain,
    domain_from_arg,
    is_valid_domain,
    normalize_domain,
    normalize_email,
    org_domain,
    validate_selectors,
)

__all__ = [
    "COMMON_DKIM_SELECTORS", "audit_dns", "build_bimi", "build_dkim", "build_dmarc",
    "build_dnssec", "build_mta_sts", "build_output", "build_tls_rpt", "domain_from_arg",
    "evaluate_spf", "fetch_dkim", "fetch_dmarc", "fetch_mx", "fetch_spf", "is_valid_domain",
    "normalize_domain", "normalize_email", "parse_dmarc", "parse_mx", "parse_spf",
    "parse_spf_terms", "validate_selectors",
]

# Common DKIM selector defaults by provider. Best-effort only -- a provider
# using a non-default or randomized selector won't be found here.
COMMON_DKIM_SELECTORS = (
    "google",       # Google Workspace
    "selector1",    # Microsoft 365
    "selector2",    # Microsoft 365
    "default",      # generic / many ESPs
    "dkim",         # generic
    "k1",           # Mailchimp/Mandrill
    "k2", "k3",     # Mailchimp
    "s1",           # SendGrid
    "s2",           # SendGrid
    "mail",         # generic
    "zoho", "zmail",                                # Zoho
    "protonmail", "protonmail2", "protonmail3",     # Proton
    "fm1", "fm2", "fm3",                            # Fastmail
    "pm",           # Postmark
    "mandrill",     # Mandrill
    "key1", "key2", "sig1", "smtp",                 # generic / iCloud (sig1)
    "mxvault",      # MXVault
    "everlytickey1",                                # Everlytic
    "cm",           # Campaign Monitor
    "amazonses",    # Amazon SES (legacy)
)

# MX host suffix -> provider; each MX host is matched independently.
MX_PROVIDER_PATTERNS = (
    ("google", ("google.com", "googlemail.com")),
    ("microsoft365", ("mail.protection.outlook.com", "outlook.com", "mx.microsoft")),
    ("zoho", ("zoho.com", "zoho.eu", "zoho.in", "zoho.com.au", "zohomail.com")),
    ("proton", ("protonmail.ch", "proton.me")),
    ("fastmail", ("messagingengine.com", "fastmail.com")),
    ("icloud", ("icloud.com",)),
    ("yahoo", ("yahoodns.net",)),
    ("gmx_ionos", ("gmx.net", "gmx.com", "gmx.de", "ionos.com", "ionos.de",
                   "1and1.com", "kundenserver.de", "perfora.net")),
    ("mimecast", ("mimecast.com", "mimecast.co.za")),
    ("proofpoint", ("pphosted.com", "ppe-hosted.com", "proofpoint.com")),
    ("barracuda", ("barracudanetworks.com", "barracuda.com")),
)
SECURITY_GATEWAYS = frozenset({"mimecast", "proofpoint", "barracuda"})

# Provider -> SPF include domains that authorize its outbound servers. Any
# include/redirect in the expanded tree equal to (or a subdomain of) one of
# these counts. The first entry is the one reported as "expected".
PROVIDER_SPF_INCLUDES = {
    "google": ("_spf.google.com",),
    "microsoft365": ("spf.protection.outlook.com",),
    "zoho": ("zoho.com", "zohomail.com", "zoho.eu", "zoho.in", "zoho.com.au", "zohomail.eu"),
    "proton": ("_spf.protonmail.ch",),
    "fastmail": ("spf.messagingengine.com",),
    "icloud": ("icloud.com",),
}

SPF_MECHANISMS = frozenset({"all", "include", "a", "mx", "ptr", "ip4", "ip6", "exists"})
SPF_LOOKUP_TERMS = frozenset({"include", "a", "mx", "ptr", "exists"})  # + redirect
SPF_LOOKUP_LIMIT = 10
SPF_VOID_LIMIT = 2
SPF_MAX_DEPTH = 10
MAX_EXTRA_SELECTORS = 2 * MAX_USER_SELECTORS  # user (20) + header-derived (20)
SPF_MX_LIMIT = 10  # RFC 7208 4.6.4: an mx mechanism resolving to >10 MX names is a permerror
SPF_RECORD_RE = re.compile(r"^v=spf1(?:\s|$)", re.IGNORECASE)
SPF_ALL_RE = re.compile(r"(?:^|\s)([-~?+]?)all(?:\s|$)", re.IGNORECASE)
SPF_TERM_RE = re.compile(r"^([+\-~?]?)([a-z0-9]+)(?:[:/](.*))?$", re.IGNORECASE)
SPF_MODIFIER_RE = re.compile(r"^([a-z][a-z0-9_.\-]*)=(.*)$", re.IGNORECASE)

DMARC_POLICIES = ("none", "quarantine", "reject")
MTA_STS_MODES = ("enforce", "testing", "none")
MTA_STS_MAX_AGE_LIMIT = 31557600  # RFC 8461 3.2
MTA_STS_FETCH_TIMEOUT_SECONDS = 8
MTA_STS_MAX_BYTES = 64 * 1024
MAX_WORKERS = 8


def _parse_tag_list(record: str) -> tuple[dict[str, str], bool]:
    """-> (tags, valid); valid is false for a duplicate tag or a part without '='.
    The first occurrence of a duplicated tag is kept."""
    tags: dict[str, str] = {}
    valid = True
    for part in record.split(";"):
        part = part.strip()
        if not part:
            continue
        key, equals, value = part.partition("=")
        key = key.strip().lower()
        if not equals or key in tags:
            valid = False
            continue
        tags[key] = value.strip()
    return tags, valid


def _tags(record: str) -> dict[str, str]:
    return _parse_tag_list(record)[0]


def _suffix_match(host: str, suffixes) -> bool:
    host = host.lower().rstrip(".")
    return any(host == s or host.endswith("." + s) for s in suffixes)


def _is_ascii_int(value: str) -> bool:
    """True for a plain ASCII digit string. str.isdigit() alone also accepts
    Unicode digits such as "²" (a \\178 TXT escape), which int() rejects."""
    return value.isascii() and value.isdigit()


# --------------------------------------------------------------------- MX

def fetch_mx(domain, resolver=None) -> list[dict]:
    records = []
    for answer in _dns.records(domain, "MX", resolver=resolver):
        parts = answer["data"].split()
        if len(parts) == 2 and _is_ascii_int(parts[0]):
            records.append({"preference": int(parts[0]),
                            "exchange": parts[1].rstrip(".").lower() or "."})
    records.sort(key=lambda r: r["preference"])
    return records


def detect_mx_provider(host: str) -> str:
    for provider, suffixes in MX_PROVIDER_PATTERNS:
        if _suffix_match(host, suffixes):
            return provider
    return "other"


def parse_mx(records: list[dict]) -> dict:
    # RFC 7505 null MX: a "0 ." record means "this domain accepts no mail".
    null_mx = any(r["exchange"] == "." for r in records)
    hosts = [r["exchange"] for r in records if r["exchange"] != "."]
    providers = list(dict.fromkeys(detect_mx_provider(host) for host in hosts))
    gateways = [p for p in providers if p in SECURITY_GATEWAYS]
    return {
        "records": records,
        "found": bool(hosts),
        "null_mx": null_mx,
        "accepts_mail": None if not records else not null_mx,
        "provider": providers[0] if providers else None,
        "providers_detected": providers,
        "security_gateway": gateways[0] if gateways else None,
    }


def _unknown_mx() -> dict:
    return {**parse_mx([]), "found": None, "null_mx": None, "accepts_mail": None}


# -------------------------------------------------------------------- SPF

def _is_spf(txt: str) -> bool:
    return bool(SPF_RECORD_RE.match(txt))


def fetch_spf(domain, resolver=None) -> list[str]:
    return [t for t in _dns.txt_records(domain, resolver=resolver) if _is_spf(t)]


def _spf_all_qualifier(record: str) -> str | None:
    match = SPF_ALL_RE.search(record)
    return (match.group(1) or "+") + "all" if match else None


def parse_spf_terms(record: str):
    """Split an SPF record into mechanisms and modifiers.

    Returns (mechanisms, modifiers, syntax_errors); each mechanism is a dict
    {"qualifier", "name", "value", "term"}.
    """
    mechanisms, modifiers, errors = [], {}, []
    for term in record.split()[1:]:
        modifier = SPF_MODIFIER_RE.match(term)
        if modifier:
            name = modifier.group(1).lower()
            if name in modifiers and name in ("redirect", "exp"):
                errors.append(f"duplicate {name} modifier")
            modifiers[name] = modifier.group(2)
            continue
        match = SPF_TERM_RE.match(term)
        name = match.group(2).lower() if match else None
        if not match or name not in SPF_MECHANISMS:
            errors.append(f"unknown mechanism: {term}")
            continue
        value = match.group(3)
        if name in ("include", "exists", "ip4", "ip6") and not value:
            errors.append(f"{name} without a value: {term}")
            continue
        mechanisms.append({
            "qualifier": match.group(1) or "+", "name": name, "value": value,
            "term": term.lstrip("+-~?"),
        })
    return mechanisms, modifiers, errors


class SpfEvaluator:
    """Expand include:/redirect= recursively and count DNS lookups per
    RFC 7208 4.6.4 (include, a, mx, ptr, exists, redirect = 1 each) and void
    lookups (NXDOMAIN or no answers).

    Evaluation stops (no further DNS queries) once the lookup count exceeds
    SPF_LOOKUP_LIMIT, which is already a permerror, so the reported count is
    then SPF_LOOKUP_LIMIT + 1 (a minimum). Void checks stop once the void count
    exceeds SPF_VOID_LIMIT. Each (name, rtype) is queried at most once; a
    repeated name reuses the answer but still counts its lookups and voids."""

    def __init__(self, resolver=None):
        self.resolver = resolver
        self.lookups = 0
        self.voids = 0
        self.includes = []
        self.permerrors = []
        self.lookup_errors = []
        self.has_ptr = False
        self.include_domains = set()
        self.unexpanded = False  # a macro or the lookup limit left part of the tree unread
        self._answers = {}

    def _count_lookup(self) -> bool:
        """Count one lookup term; False once the limit is exceeded (stop)."""
        if self.lookups > SPF_LOOKUP_LIMIT:
            return False
        self.lookups += 1
        if self.lookups > SPF_LOOKUP_LIMIT:
            self.unexpanded = True
            return False
        return True

    def _valid_target(self, target, term) -> bool:
        """A malformed domain-spec is a permerror (RFC 7208 4.8); macros are
        left unevaluated."""
        if "%" in target or _dns.is_valid_query_name(target):
            return True
        self.permerrors.append(f"{term} target {target!r} is not a valid domain name "
                               "(invalid_query_name)")
        return False

    def walk(self, domain, record, chain):
        mechanisms, modifiers, syntax_errors = parse_spf_terms(record)
        self.permerrors += [f"{domain}: {e}" for e in syntax_errors]
        for mech in mechanisms:
            name = mech["name"]
            if name == "ptr":
                self.has_ptr = True
            if name not in SPF_LOOKUP_TERMS:
                continue
            if not self._count_lookup():
                break
            if name == "ptr":
                continue
            target = mechanism_target(mech, domain)
            if name == "include":
                self._follow(target, domain, "include", chain)
            elif self._valid_target(target, name):
                self._check_void(target, name)
        redirect = modifiers.get("redirect")
        # redirect= is ignored when the record has an "all" mechanism.
        if redirect and not any(m["name"] == "all" for m in mechanisms):
            target = redirect.lower().rstrip(".")
            if self._count_lookup():
                self._follow(target, domain, "redirect", chain)
            else:  # never followed: the effective "all" is unknown
                self.includes.append({"domain": target, "parent": domain, "via": "redirect",
                                      "depth": len(chain), "record": None,
                                      "status": "limit_reached"})

    def _lookup(self, name, rtype):
        key = (name.lower(), rtype)
        if key not in self._answers:
            result = _dns.query(name, rtype, resolver=self.resolver)
            if _dns.is_failure(result["status"]):
                detail = f" ({result['error']})" if result.get("error") else ""
                self.lookup_errors.append(f"{rtype} {name}: {result['status']}{detail}")
                self._answers[key] = None
            else:
                self._answers[key] = [a for a in result["answers"] if a["type"] == rtype]
        return self._answers[key]

    def _check_void(self, target, mechanism):
        if "%" in target:  # macro -- depends on the connecting client
            return
        if self.voids > SPF_VOID_LIMIT:  # already a permerror; stop querying
            return
        rtypes = ("A", "AAAA") if mechanism == "a" else ("MX",) if mechanism == "mx" else ("A",)
        for rtype in rtypes:
            answers = self._lookup(target, rtype)
            if answers and mechanism == "mx" and len(answers) > SPF_MX_LIMIT:
                self.permerrors.append(
                    f"mx:{target} returns {len(answers)} MX records (> {SPF_MX_LIMIT})")
            if answers is None or answers:
                return
        self.voids += 1

    def _follow(self, target, parent, via, chain):
        entry = {"domain": target, "parent": parent, "via": via, "depth": len(chain),
                 "record": None, "status": "ok"}
        self.includes.append(entry)
        self.include_domains.add(target)
        if "%" in target:
            entry["status"] = "macro_not_evaluated"
            self.unexpanded = True
            return
        if not self._valid_target(target, via):
            entry["status"] = "invalid_query_name"
            return
        if target in chain:
            entry["status"] = "loop"
            self.permerrors.append(f"{via} loop: {parent} -> {target}")
            return
        if len(chain) >= SPF_MAX_DEPTH:
            entry["status"] = "depth_exceeded"
            self.permerrors.append(f"{via} depth limit reached at {target}")
            return
        answers = self._lookup(target, "TXT")
        if answers is None:
            entry["status"] = "lookup_failed"
            return
        if not answers:
            self.voids += 1
        spf = [t for t in (_dns.txt_strings(a["data"]) for a in answers) if _is_spf(t)]
        if not spf:
            entry["status"] = "no_spf_record"
            self.permerrors.append(f"{via} {target} has no SPF record")
        elif len(spf) > 1:
            entry["status"] = "multiple_records"
            self.permerrors.append(f"{via} {target} has multiple SPF records")
        else:
            entry["record"] = spf[0]
            self.walk(target, spf[0], chain + (target,))


def parse_spf(records: list[str]) -> dict:
    """Top-level facts about the domain's own SPF record(s); no DNS.
    Multiple SPF records are a permerror, so they are never strict."""
    qualifiers = [q for q in (_spf_all_qualifier(r) for r in records) if q]
    all_mechanism = qualifiers[0].lower() if qualifiers else None
    mechanisms = parse_spf_terms(records[0])[0] if records else []
    return {
        "records": records,
        "found": bool(records),
        "multiple_records": len(records) > 1,
        "all_mechanism": all_mechanism,
        "strict": len(records) == 1 and all_mechanism == "-all",
        "plus_all": all_mechanism == "+all",
        "direct_ips": [m["term"] for m in mechanisms if m["name"] in ("ip4", "ip6")],
        "direct_ip_terms": [{"qualifier": m["qualifier"], "value": m["value"]}
                            for m in mechanisms if m["name"] in ("ip4", "ip6")],
        "has_a_or_mx_mechanism": any(m["name"] in ("a", "mx") for m in mechanisms),
    }


def _effective_all(domain, top_all, includes):
    """(effective_all_mechanism, effective_strict): the top-level "all", else
    the "all" of the last record in the redirect= chain. strict is None when
    the chain couldn't be resolved (lookup failure / macro / lookup limit)."""
    if top_all:
        return top_all, top_all == "-all"
    current, depth, last = domain, 1, None
    while True:
        nxt = next((e for e in includes if e["via"] == "redirect"
                    and e["parent"] == current and e["depth"] == depth), None)
        if nxt is None:
            break
        last, current, depth = nxt, nxt["domain"], depth + 1
    if last is None:
        return None, False
    if last["status"] in ("lookup_failed", "macro_not_evaluated", "limit_reached"):
        return None, None
    effective = _spf_all_qualifier(last["record"]) if last["record"] else None
    effective = effective.lower() if effective else None
    return effective, effective == "-all"


def evaluate_spf(domain, records, provider=None, resolver=None):
    """-> (spf section dict, nested lookup error strings)."""
    result = parse_spf(records)
    evaluator = SpfEvaluator(resolver)
    if records:
        evaluator.walk(domain, records[0], (domain,))
    permerrors = list(evaluator.permerrors)
    if len(records) > 1:
        permerrors.insert(0, "multiple SPF records")
    if evaluator.lookups > SPF_LOOKUP_LIMIT:
        permerrors.append(f"DNS lookup limit exceeded ({evaluator.lookups} > {SPF_LOOKUP_LIMIT})")
    if evaluator.voids > SPF_VOID_LIMIT:
        permerrors.append(f"void lookup limit exceeded ({evaluator.voids} > {SPF_VOID_LIMIT})")
    expected = PROVIDER_SPF_INCLUDES.get(provider)
    effective_all, effective_strict = _effective_all(
        domain, result["all_mechanism"], evaluator.includes)
    if len(records) > 1:
        effective_strict = False
    result.update({
        "effective_all_mechanism": effective_all,
        "effective_strict": effective_strict,
        "has_ptr": evaluator.has_ptr,
        "dns_lookup_count": evaluator.lookups,
        "lookup_count_is_minimum": bool(evaluator.lookup_errors) or evaluator.unexpanded,
        "lookup_limit_exceeded": evaluator.lookups > SPF_LOOKUP_LIMIT,
        "void_lookup_count": evaluator.voids,
        "void_limit_exceeded": evaluator.voids > SPF_VOID_LIMIT,
        "includes": evaluator.includes,
        "permerrors": permerrors,
        "expected_provider_include": expected[0] if expected else None,
        "provider_include_present": _provider_include_present(evaluator, expected, records),
    })
    return result, evaluator.lookup_errors


def _provider_include_present(evaluator, expected, records):
    """True on a match; null (unknown) when there is no match but part of the
    tree couldn't be read (failed lookup, macro, lookup limit); else false."""
    if not expected or not records:
        return None
    if any(_suffix_match(d, expected) for d in evaluator.include_domains):
        return True
    return None if evaluator.lookup_errors or evaluator.unexpanded else False


def _unknown_spf(provider=None) -> dict:
    """SPF state when the top-level lookup failed: unknown (null), not absent."""
    result, _ = evaluate_spf("", [], provider)
    result.update({key: None for key in (
        "found", "multiple_records", "strict", "plus_all", "has_a_or_mx_mechanism",
        "effective_strict", "has_ptr", "dns_lookup_count", "lookup_limit_exceeded",
        "void_lookup_count", "void_limit_exceeded", "provider_include_present")})
    return result


def _build_spf(domain, provider, errors, resolver=None) -> dict:
    try:
        records = fetch_spf(domain, resolver)
    except _dns.DNSLookupError as exc:
        add_error(errors, "spf", str(exc))
        return _unknown_spf(provider)
    spf, lookup_errors = evaluate_spf(domain, records, provider, resolver)
    if lookup_errors:
        add_error(errors, "spf", "nested lookup(s) failed: " + ", ".join(lookup_errors))
    return spf


# ------------------------------------------------------------------ DMARC

def fetch_dmarc(domain, resolver=None) -> list[str]:
    txts = _dns.txt_records(f"_dmarc.{domain}", resolver=resolver)
    return [t for t in txts if t.lower().startswith("v=dmarc1")]


def _split_uris(value) -> list[str]:
    return [uri.strip() for uri in (value or "").split(",") if uri.strip()]


def report_uri_domain(uri: str) -> str | None:
    """Destination domain of a mailto: report URI (size suffix "!10m" removed)."""
    if not uri.lower().startswith("mailto:") or "@" not in uri:
        return None
    return bare_domain(uri.split("!", 1)[0].rsplit("@", 1)[-1])


def parse_dmarc(records: list[str], inherited: bool = False) -> dict:
    if not records:
        return {
            "found": False, "record": None, "policy": None, "subdomain_policy": None,
            "effective_policy": None, "policy_valid": False, "record_valid": False,
            "pct": None, "rua": [], "ruf": [], "has_rua": False, "fo": None,
            "adkim": None, "aspf": None, "testing": False, "np": None, "psd": None,
            "enforced": False, "multiple_records": False,
        }
    record = records[0]
    tags, tags_valid = _parse_tag_list(record)
    policy = tags.get("p")
    policy_norm = policy.lower() if policy else None
    subdomain_policy = tags.get("sp", policy)
    pct_text = tags.get("pct")
    if pct_text is None:
        pct = 100  # legacy RFC 7489 tag; absent means 100
    elif _is_ascii_int(pct_text) and len(pct_text) <= 3 and int(pct_text) <= 100:
        pct = int(pct_text)
    else:
        pct = None
    testing = tags.get("t", "").lower() == "y"  # RFC 9989 test mode
    rua = _split_uris(tags.get("rua"))
    multiple = len(records) > 1
    # Multiple _dmarc TXT records make DMARC invalid (RFC 9989 / RFC 7489).
    record_valid = (not multiple and tags_valid and tags.get("v") == "DMARC1"
                    and policy_norm in DMARC_POLICIES and pct is not None
                    and (subdomain_policy or "").lower() in DMARC_POLICIES)
    # An inherited (organizational-domain) record governs this domain via sp=.
    effective = (subdomain_policy if inherited else policy) or ""
    return {
        "found": True,
        "record": record,
        "policy": policy,
        "subdomain_policy": subdomain_policy,
        "effective_policy": effective or None,
        "policy_valid": policy_norm in DMARC_POLICIES,
        "record_valid": record_valid,
        "pct": pct,
        "rua": rua,
        "ruf": _split_uris(tags.get("ruf")),
        "has_rua": bool(rua),
        "fo": tags.get("fo"),
        "adkim": tags.get("adkim", "r").lower(),
        "aspf": tags.get("aspf", "r").lower(),
        "testing": testing,
        "np": tags.get("np"),
        "psd": tags.get("psd"),
        # Test mode (t=y), a legacy pct<100 and an invalid record aren't enforced.
        "enforced": (record_valid and effective.lower() in ("reject", "quarantine")
                     and pct == 100 and not testing),
        "multiple_records": multiple,
    }


def check_external_report_auth(policy_domain, uris, resolver=None):
    """RFC 7489 7.1: a report destination outside the policy domain's org must
    publish <policy_domain>._report._dmarc.<dest> TXT "v=DMARC1"."""
    results, failures = {}, []
    for uri in uris:
        dest = report_uri_domain(uri)
        if not dest or dest in results or aligned(policy_domain, dest):
            continue
        try:
            txts = _dns.txt_records(f"{policy_domain}._report._dmarc.{dest}", resolver=resolver)
            results[dest] = any(t.lower().startswith("v=dmarc1") for t in txts)
        except _dns.DNSLookupError as exc:
            results[dest] = None
            failures.append(str(exc))
    return results, failures


def _unknown_dmarc() -> dict:
    """DMARC state when a needed lookup failed: unknown (null), not absent."""
    return {**parse_dmarc([]), "found": None, "has_rua": None, "enforced": None,
            "effective_policy": None, "policy_valid": None, "record_valid": None,
            "inherited_from": None, "rua_external_authorization": {}}


def build_dmarc(domain, errors, resolver=None) -> dict:
    try:
        records = fetch_dmarc(domain, resolver)
    except _dns.DNSLookupError as exc:
        add_error(errors, "dmarc", str(exc))
        return _unknown_dmarc()
    inherited_from = None
    org = org_domain(domain)
    if not records and org != domain:
        try:
            records = fetch_dmarc(org, resolver)
            inherited_from = org if records else None
        except _dns.DNSLookupError as exc:
            # No own record and the inherited one is unknown -> DMARC unknown.
            add_error(errors, "dmarc", f"org-domain fallback: {exc}")
            return _unknown_dmarc()
    result = parse_dmarc(records, inherited=bool(inherited_from))
    result["inherited_from"] = inherited_from
    auth, failures = check_external_report_auth(
        inherited_from or domain, result["rua"] + result["ruf"], resolver)
    result["rua_external_authorization"] = auth
    for failure in failures:
        add_error(errors, "dmarc", f"external report authorization: {failure}")
    return result


# ------------------------------------------------------------------- DKIM

def _der_tlv(buf: bytes, pos: int):
    tag, length = buf[pos], buf[pos + 1]
    pos += 2
    if length & 0x80:
        count = length & 0x7F
        if count == 0 or count > 4:
            raise ValueError("unsupported DER length")
        length = int.from_bytes(buf[pos:pos + count], "big")
        pos += count
    end = pos + length
    if end > len(buf):
        raise ValueError("truncated DER")
    return tag, pos, end


def rsa_key_bits(p_value: str) -> int | None:
    """Modulus bit length of a DKIM RSA key: p= is base64 DER, either a
    SubjectPublicKeyInfo or a bare RSAPublicKey. None if it can't be parsed."""
    try:
        der = base64.b64decode("".join(p_value.split()), validate=True)
        tag, start, _ = _der_tlv(der, 0)
        if tag != 0x30:
            return None
        tag, s, e = _der_tlv(der, start)
        buf = der
        if tag == 0x30:  # SubjectPublicKeyInfo: AlgorithmIdentifier, BIT STRING
            tag, s, e = _der_tlv(der, e)
            if tag != 0x03:
                return None
            buf = der[s + 1:e]  # skip the unused-bits byte
            tag, start, _ = _der_tlv(buf, 0)
            if tag != 0x30:
                return None
            tag, s, e = _der_tlv(buf, start)
        if tag != 0x02:
            return None
        return int.from_bytes(buf[s:e], "big").bit_length() or None
    except (ValueError, IndexError, binascii.Error):
        return None


def _is_dkim_key_record(record: str) -> bool:
    tags = _tags(record)
    return "p" in tags and tags.get("v", "DKIM1") == "DKIM1"


def parse_dkim_record(record: str) -> dict:
    tags, valid = _parse_tag_list(record)
    p_value = tags.get("p")
    key_type = tags.get("k", "rsa").lower()
    has_key = bool(p_value) and valid
    key_bits = None
    if has_key and key_type == "rsa":
        key_bits = rsa_key_bits(p_value)
    elif has_key and key_type == "ed25519":
        key_bits = 256
    return {
        "has_public_key": has_key,
        "revoked": p_value == "",
        "key_type": key_type,
        "key_bits": key_bits,
        "testing": "y" in [f.strip().lower() for f in tags.get("t", "").split(":")],
        "multiple_records": False,
    }


def _probe_selector(domain, selector, resolver):
    """-> (entry or None, failure status or None)."""
    result = _dns.query(f"{selector}._domainkey.{domain}", "TXT", resolver=resolver)
    if _dns.is_failure(result["status"]):
        return None, result["status"]
    cnames = [a["data"].rstrip(".").lower() for a in result["answers"] if a["type"] == "CNAME"]
    txts = [_dns.txt_strings(a["data"]) for a in result["answers"] if a["type"] == "TXT"]
    keys = [t for t in txts if _is_dkim_key_record(t)]
    cname_target = cnames[-1] if cnames else None
    if keys:
        entry = {"cname_target": cname_target, "cname_without_key": False,
                 **parse_dkim_record(keys[0])}
        if len(keys) > 1:  # ambiguous: a verifier can't rely on either key
            entry.update(has_public_key=False, multiple_records=True)
        return entry, None
    if cname_target:
        return {"cname_target": cname_target, "cname_without_key": True,
                "has_public_key": False, "revoked": False, "key_type": None,
                "key_bits": None, "testing": False, "multiple_records": False}, None
    return None, None


def fetch_dkim(domain, selectors=COMMON_DKIM_SELECTORS, resolver=None):
    """Returns (selectors_found, failures); failures is [(selector, status)]."""
    selectors = list(selectors)
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        probes = list(pool.map(lambda s: _probe_selector(domain, s, resolver), selectors))
    found, failures = {}, []
    for selector, (entry, failure) in zip(selectors, probes, strict=True):
        if failure:
            failures.append((selector, failure))
        elif entry:
            found[selector] = entry
    return found, failures


def build_dkim(domain, extra_selectors, errors, resolver=None) -> dict:
    """Probe the first MAX_EXTRA_SELECTORS distinct extra selectors (user +
    header-derived) plus COMMON_DKIM_SELECTORS; further extras are ignored."""
    extras = list(dict.fromkeys(extra_selectors))[:MAX_EXTRA_SELECTORS]
    selectors = list(dict.fromkeys([*extras, *COMMON_DKIM_SELECTORS]))
    found, failures = fetch_dkim(domain, selectors, resolver)
    if failures:  # summary only; selectors_failed is the structured list
        errors["dkim"] = f"{len(failures)} selector lookup(s) failed: " + ", ".join(
            f"{selector}: {status}" for selector, status in failures)
    has_key = any(e["has_public_key"] and not e["revoked"] for e in found.values())
    return {
        "selectors_checked": selectors,
        "selectors_found": found,
        "selectors_failed": [selector for selector, _ in failures],
        "found": True if has_key else (None if failures else False),
    }


# ---------------------------------------------- MTA-STS / TLS-RPT / BIMI

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    # RFC 8461 3.3: the policy fetch must not follow redirects.
    def redirect_request(self, *args, **kwargs):
        return None


def _http_get_text(url: str):
    """-> (body text, Content-Type header or None)."""
    opener = urllib.request.build_opener(_NoRedirect)
    with opener.open(url, timeout=MTA_STS_FETCH_TIMEOUT_SECONDS) as resp:
        body = resp.read(MTA_STS_MAX_BYTES).decode("utf-8", errors="replace")
        return body, resp.headers.get("Content-Type")


def parse_mta_sts_policy(text: str) -> dict:
    policy = {"version": None, "mode": None, "mx": [], "max_age": None}
    for line in text.splitlines():
        key, sep, value = line.partition(":")
        if not sep:
            continue
        key, value = key.strip().lower(), value.strip()
        if key == "mx":
            policy["mx"].append(value.lower().rstrip("."))
        elif key == "max_age":
            policy["max_age"] = int(value) if _is_ascii_int(value) else None
        elif key in ("version", "mode"):
            policy[key] = value
    return policy


def validate_mta_sts_policy(policy: dict, content_type) -> list[str]:
    """RFC 8461 3.2 checks -> list of problems (empty when valid)."""
    problems = []
    media_type = (content_type or "").split(";", 1)[0].strip().lower()
    if media_type != "text/plain":
        problems.append(f"Content-Type is {content_type or 'missing'}, not text/plain")
    if policy["version"] != "STSv1":
        problems.append(f"version is {policy['version'] or 'missing'}, not STSv1")
    if policy["mode"] not in MTA_STS_MODES:
        problems.append(
            f"mode is {policy['mode'] or 'missing'}, not one of {', '.join(MTA_STS_MODES)}")
    if policy["max_age"] is None:
        problems.append("max_age missing or not an integer")
    elif policy["max_age"] > MTA_STS_MAX_AGE_LIMIT:
        problems.append(f"max_age {policy['max_age']} exceeds {MTA_STS_MAX_AGE_LIMIT}")
    if policy["mode"] != "none" and not policy["mx"]:
        problems.append("no mx: entries")
    return problems


def mx_matches_pattern(host: str, pattern: str) -> bool:
    host, pattern = host.lower().rstrip("."), pattern.lower().rstrip(".")
    if pattern.startswith("*."):
        head, _, tail = host.partition(".")
        return bool(head) and tail == pattern[2:]
    return host == pattern


def build_mta_sts(domain, mx_hosts, errors, resolver=None) -> dict:
    txts = _dns.txt_records(f"_mta-sts.{domain}", resolver=resolver)
    sts = [t for t in txts if t.lower().startswith("v=stsv1")]
    result = {
        "found": bool(sts), "record": sts[0] if sts else None,
        "id": _tags(sts[0]).get("id") if sts else None,
        "multiple_records": len(sts) > 1,
        "policy_url": None, "policy": None, "policy_valid": None, "policy_errors": [],
        "mx_covered": None,
    }
    if not sts:
        return result
    url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"
    result["policy_url"] = url
    try:
        text, content_type = _http_get_text(url)
    except (urllib.error.URLError, http.client.HTTPException, OSError, ValueError) as exc:
        add_error(errors, "mta_sts", f"policy fetch failed: {exc}")
        return result
    policy = parse_mta_sts_policy(text)
    result["policy"] = policy
    result["policy_errors"] = validate_mta_sts_policy(policy, content_type)
    result["policy_valid"] = not result["policy_errors"]
    if mx_hosts:
        result["mx_covered"] = all(
            any(mx_matches_pattern(h, p) for p in policy["mx"]) for h in mx_hosts)
    return result


def build_tls_rpt(domain, resolver=None) -> dict:
    txts = _dns.txt_records(f"_smtp._tls.{domain}", resolver=resolver)
    rpt = [t for t in txts if t.lower().startswith("v=tlsrptv1")]
    return {
        "found": bool(rpt), "record": rpt[0] if rpt else None,
        "rua": _split_uris(_tags(rpt[0]).get("rua")) if rpt else [],
        "multiple_records": len(rpt) > 1,
    }


def build_bimi(domain, resolver=None) -> dict:
    txts = _dns.txt_records(f"default._bimi.{domain}", resolver=resolver)
    bimi = [t for t in txts if t.lower().startswith("v=bimi1")]
    tags = _tags(bimi[0]) if bimi else {}
    return {
        "found": bool(bimi), "record": bimi[0] if bimi else None,
        "logo_url": tags.get("l") or None, "vmc_url": tags.get("a") or None,
    }


def build_dnssec(domain, resolver=None) -> dict:
    result = _dns.query(domain, "SOA", resolver=resolver)
    if _dns.is_failure(result["status"]):
        raise _dns.DNSLookupError(domain, "SOA", result["status"], result.get("error"))
    return {"ad_flag": result["ad"]}


# ----------------------------------------------------------------- output

SECTIONS = ("mx", "spf", "dmarc", "dkim", "mta_sts", "tls_rpt", "bimi", "dnssec")


def _section(errors, name, fallback, fn, *args):
    """Run one section; any unexpected exception becomes errors[name] + fallback."""
    try:
        return fn(*args)
    except Exception as exc:  # isolate one section's failure
        add_error(errors, name, str(exc) or type(exc).__name__)
        return fallback


def build_output(domain, resolver=None, selectors=()) -> dict:
    """Audit `domain` (validated with normalize_domain; ValueError if invalid).
    `selectors` are extra DKIM selectors probed before the built-in list; they
    are not length-limited here (audit_dns applies validate_selectors)."""
    domain = normalize_domain(domain)
    if resolver is not None and not _dns.is_valid_resolver(resolver):
        raise ValueError("resolver must be an IP address.")
    # One errors dict per section so concurrent sections never share state.
    section_errors = {name: {} for name in SECTIONS}
    unknown = {"found": None}

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        def run(name, fallback, fn, *args):
            return pool.submit(_section, section_errors[name], name, fallback, fn, *args)

        mx_future = run("mx", None, fetch_mx, domain, resolver)
        futures = {
            "dmarc": run("dmarc", _unknown_dmarc(), build_dmarc, domain,
                         section_errors["dmarc"], resolver),
            "dkim": run("dkim", {**unknown, "selectors_checked": [], "selectors_found": {},
                                 "selectors_failed": []},
                        build_dkim, domain, selectors, section_errors["dkim"], resolver),
            "tls_rpt": run("tls_rpt", unknown, build_tls_rpt, domain, resolver),
            "bimi": run("bimi", unknown, build_bimi, domain, resolver),
            "dnssec": run("dnssec", {"ad_flag": None}, build_dnssec, domain, resolver),
        }
        mx_records = mx_future.result()
        mx = _unknown_mx() if mx_records is None else parse_mx(mx_records)
        mx_hosts = [r["exchange"] for r in mx["records"] if r["exchange"] != "."]
        futures["spf"] = run("spf", _unknown_spf(mx["provider"]), _build_spf, domain,
                             mx["provider"], section_errors["spf"], resolver)
        futures["mta_sts"] = run("mta_sts", unknown, build_mta_sts, domain, mx_hosts,
                                 section_errors["mta_sts"], resolver)
        results = {name: future.result() for name, future in futures.items()}

    errors = {}
    for name in SECTIONS:
        errors.update(section_errors[name])
    return {
        "domain": domain,
        "resolver": _dns.effective_resolver(resolver) or "system",
        "mx": mx,
        **{name: results[name] for name in SECTIONS if name != "mx"},
        "errors": errors,
    }


def audit_dns(target: str, *, selectors: list[str] | None = None, resolver=None) -> dict:
    """Validate an email address or domain plus optional DKIM selectors (at most
    20, added to the built-in list), then return build_output's dict.
    Raises ValueError for invalid input before any DNS query."""
    domain = domain_from_arg(target)
    extra = validate_selectors(selectors)
    return build_output(domain, resolver=resolver, selectors=extra)
