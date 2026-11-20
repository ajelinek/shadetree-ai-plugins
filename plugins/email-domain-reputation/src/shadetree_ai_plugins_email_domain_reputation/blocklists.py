"""Check a client domain and its self-hosted sending IPs against public DNS
blocklists (DNSBL / URIBL) and report forward-confirmed reverse DNS per IP.

`build_output(target, ips=())` returns one dict. Invalid target, IP, or
resolver raises ValueError before any DNS query.

Domain lists (queried for the domain and its organizational domain):
    spamhaus_dbl  <d>.dbl.spamhaus.org
    surbl         <d>.multi.surbl.org
    uribl         <d>.multi.uribl.com

IP lists (IPv4; IPv6 only on Spamhaus ZEN, via nibble-reversed names --
the others are reported with status "skipped"):
    spamhaus_zen  zen.spamhaus.org
    barracuda     b.barracudacentral.org
    spamcop       bl.spamcop.net
    psbl          psbl.surriel.com

IPs checked: every `ips` entry (at most MAX_IPS; a string gets source
"argument", an (ip, source) pair keeps the caller's tag) plus, unless
auto_ips=False, the domain's self-hosted IPs from its own top-level SPF
record: single-host ip4:/ip6: terms (no prefix, /32, /128) and the A/AAAA
records of hosts named by top-level a / mx mechanisms (at most
MAX_HOST_MECHANISMS mechanisms and SPF_MX_LIMIT MX hosts each; host lookups
stop once MAX_IPS candidates are found -- each such truncation adds a
"discovery stopped at ...; some self-hosted IPs not checked" note to
errors.auto_ips).
include:/redirect= are deliberately NOT expanded -- shared provider ranges (Google, Microsoft,
ESPs) say nothing about the client. CIDR ranges go to "skipped_ranges",
not expanded. Private/reserved IPs are skipped and the total is capped at
MAX_IPS; both go to "skipped_ips" with a reason.

Each listing is {"listed", "status", "codes": [{"code", "meaning"}]}
(bitmask lists add "bit" per code):
    "not_listed"          listed false (NXDOMAIN / no A answer)
    "listed"              listed true; codes decoded per list
    "query_refused"       listed null -- a "query refused" sentinel
                          (Spamhaus 127.255.255.252/.254/.255 and 127.0.1.255,
                          URIBL/SURBL 127.0.0.1). NOT a listing.
    "unexpected_answer"   listed null -- an answer outside 127.0.0.0/8
    "lookup_failed"       listed null (SERVFAIL / REFUSED / TIMEOUT ...)
    "skipped"             listed null (list doesn't support IPv6)
    "unreliable_resolver" listed null -- a Spamhaus/URIBL/SURBL query came
                          back empty, but the resolver is a known public
                          resolver (PUBLIC_RESOLVERS) or that list's canary
                          did not come back listed. Those lists silently
                          answer NXDOMAIN to public resolvers (including a
                          system resolver that forwards to one), so "not
                          listed" can't be trusted. Barracuda/SpamCop/PSBL
                          are unaffected.

Canaries: once per call, each of those lists' official test entry (Spamhaus
DBL dbltest.com, ZEN 127.0.0.2, URIBL test.uribl.com, SURBL test.surbl.org)
is queried and reported in "resolver_canaries" as "ok" (listed, as it should
be) | "refused" | "no_answer" | "lookup_failed". With the system resolver
there is no way to know whether it forwards to a public resolver, so the
canaries are the only evidence.

"resolver_note" (str|null) explains refusals, a public resolver, or failed
canaries; the fix is to query through a local or ISP resolver that reaches
the lists directly (Spamhaus DQS keys are not implemented).

Output:
    {"domain", "org_domain", "resolver": "system"|IP,
     "resolver_canaries": {<list>: "ok"|"refused"|"no_answer"|"lookup_failed"},
     "domain_listings": {<domain>: {<list>: listing}},
     "ips": [{"ip", "source": argument|spf_ip4|spf_ip6|spf_a|spf_mx|<caller tag>,
              "listings": {<list>: listing},
              "ptr", "fcrdns": true|false|null, "ptr_looks_generic": true|false|null}],
     "skipped_ranges": [{"range", "source"}],
     "skipped_ips": [{"ip", "source", "reason": invalid_ip|private_or_reserved|cap_reached}],
     "resolver_note": str|null,
     "errors": {<section>: message}}

"fcrdns" is true when the PTR name resolves back to the same IP, false when
there is no PTR or it doesn't, null when a lookup failed. "ptr_looks_generic"
is a heuristic: the PTR embeds the IP's octets or words like
dynamic/dhcp/pool/dsl/cable/cust/static-ip.

Fetch and normalize only -- no verdicts or severity.
"""

from __future__ import annotations

import ipaddress
import re
from concurrent.futures import ThreadPoolExecutor

from . import _dns, dns_auth
from ._common import add_error, mechanism_target
from ._domain import domain_from_arg, org_domain

MAX_IPS = 20
MAX_HOST_MECHANISMS = 10  # top-level SPF a/mx mechanisms resolved for auto IPs
# Spamhaus/URIBL/SURBL block these; answers through them (even NXDOMAIN) are untrustworthy.
PUBLIC_RESOLVERS = frozenset({
    "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", "149.112.112.112"})
MAX_WORKERS = 8

REFUSED_NOTE = (
    "One or more blocklists refused the query (sentinel answer, not a listing). "
    "Spamhaus, URIBL and SURBL block queries from public resolvers such as "
    "8.8.8.8, 1.1.1.1 and 9.9.9.9, and rate-limit heavy users. Query through a "
    "local or ISP resolver instead, or use a Spamhaus DQS key (not implemented)."
)
CANARY_NOTE = (
    "The official test entry (canary) of {lists} did not come back listed "
    "through this resolver, so it is probably blocked by those lists (e.g. it "
    "forwards to a public resolver); their \"not listed\" answers are reported "
    "as unreliable_resolver. Query through a local or ISP resolver that reaches "
    "the lists directly."
)

SPAMHAUS_REFUSED = {
    "127.255.255.252": "query refused: typo in DNSBL name",
    "127.255.255.254": "query refused: queried via a public/open resolver",
    "127.255.255.255": "query refused: excessive number of queries",
    "127.0.1.255": "query refused: IP queries are not allowed on DBL",
}
DBL_CODES = {
    "127.0.1.2": "spam domain",
    "127.0.1.4": "phishing domain",
    "127.0.1.5": "malware domain",
    "127.0.1.6": "botnet C&C domain",
    "127.0.1.102": "abused legit spam",
    "127.0.1.103": "abused spammed redirector",
    "127.0.1.104": "abused legit phish",
    "127.0.1.105": "abused legit malware",
    "127.0.1.106": "abused legit botnet C&C",
}
ZEN_CODES = {
    "127.0.0.2": "SBL - Spamhaus Block List",
    "127.0.0.3": "SBL CSS - Spamhaus snowshoe/CSS",
    "127.0.0.4": "XBL - exploited/compromised host",
    "127.0.0.5": "XBL - exploited/compromised host",
    "127.0.0.6": "XBL - exploited/compromised host",
    "127.0.0.7": "XBL - exploited/compromised host",
    "127.0.0.9": "SBL DROP/EDROP - hijacked netblock",
    "127.0.0.10": "PBL - end-user range (ISP maintained)",
    "127.0.0.11": "PBL - end-user range (Spamhaus maintained)",
}
URIBL_BITS = {2: "black", 4: "grey", 8: "red"}
SURBL_BITS = {8: "phishing (PH)", 16: "malware (MW)", 64: "abuse (ABUSE)", 128: "cracked site (CR)"}
SIMPLE_CODES = {"127.0.0.2": "listed"}

GENERIC_PTR_WORDS = re.compile(r"dynamic|dhcp|pool|dsl|cable|cust|static-ip")


def _listing(listed, status, codes=()) -> dict:
    return {"listed": listed, "status": status, "codes": list(codes)}


def _refused(codes) -> dict:
    return _listing(None, "query_refused", codes)


def _decode_table(table, refused=None):
    def decode(addrs):
        if refused and any(a in refused for a in addrs):
            return _refused([{"code": a, "meaning": refused[a]} for a in addrs if a in refused])
        return _listing(True, "listed", [
            {"code": a, "meaning": table.get(a, "unrecognized return code")} for a in addrs])
    return decode


def _decode_bitmask(bits, refused_meaning):
    def decode(addrs):
        if "127.0.0.1" in addrs:
            return _refused([{"code": "127.0.0.1", "meaning": refused_meaning}])
        codes = []
        for addr in addrs:
            mask = int(addr.rsplit(".", 1)[1])
            for bit in (1 << n for n in range(8)):
                if mask & bit:
                    codes.append({"code": addr, "bit": bit,
                                  "meaning": bits.get(bit, f"unrecognized bit {bit}")})
        return _listing(True, "listed", codes)
    return decode


# list key -> (zone, decoder)
DOMAIN_LISTS = {
    "spamhaus_dbl": ("dbl.spamhaus.org", _decode_table(DBL_CODES, SPAMHAUS_REFUSED)),
    "surbl": ("multi.surbl.org", _decode_bitmask(
        SURBL_BITS, "query refused: blocked (public resolver or over the free-use limit)")),
    "uribl": ("multi.uribl.com", _decode_bitmask(
        URIBL_BITS, "query refused: public resolver or over the free-use limit")),
}
IP_LISTS = {
    "spamhaus_zen": ("zen.spamhaus.org", _decode_table(ZEN_CODES, SPAMHAUS_REFUSED)),
    "barracuda": ("b.barracudacentral.org", _decode_table(SIMPLE_CODES)),
    "spamcop": ("bl.spamcop.net", _decode_table(SIMPLE_CODES)),
    "psbl": ("psbl.surriel.com", _decode_table(SIMPLE_CODES)),
}
IPV6_LISTS = frozenset({"spamhaus_zen"})
# Lists that silently answer NXDOMAIN to queries arriving via PUBLIC_RESOLVERS.
PUBLIC_RESOLVER_BLOCKED_LISTS = frozenset({"spamhaus_dbl", "surbl", "uribl", "spamhaus_zen"})
# Official always-listed test entries for those lists -> proves the resolver
# actually reaches them (a forwarding system resolver may not).
CANARIES = {
    "spamhaus_dbl": "dbltest.com.dbl.spamhaus.org",
    "spamhaus_zen": "2.0.0.127.zen.spamhaus.org",
    "uribl": "test.uribl.com.multi.uribl.com",
    "surbl": "test.surbl.org.multi.surbl.org",
}
CANARY_STATUS = {"listed": "ok", "query_refused": "refused", "not_listed": "no_answer"}


# ----------------------------------------------------------- list lookups

def reversed_ip(ip) -> str:
    """Reverse-label form of an IP for DNSBL queries: dotted-quad reversed
    for IPv4, nibble-reversed for IPv6 (no in-addr/ip6.arpa suffix)."""
    return ipaddress.ip_address(ip).reverse_pointer.rsplit(".", 2)[0]


def uses_public_resolver(resolver=None) -> bool:
    return _dns.effective_resolver(resolver) in PUBLIC_RESOLVERS


def probe_canaries(resolver=None) -> dict:
    """Query each blocked list's test entry once -> {list: canary status}."""
    lists = {**DOMAIN_LISTS, **IP_LISTS}
    jobs = [(key, name, lists[key][1], key) for key, name in CANARIES.items()]
    listings = _run_jobs(jobs, resolver, frozenset())
    return {key: CANARY_STATUS.get(listing["status"], "lookup_failed")
            for key, listing in listings.items()}


def untrusted_lists(resolver=None, canaries=None) -> frozenset:
    """Lists whose empty answers can't be trusted: all blocked lists via a
    public resolver, plus any list whose canary isn't ok."""
    if uses_public_resolver(resolver):
        return PUBLIC_RESOLVER_BLOCKED_LISTS
    if canaries is None:
        canaries = probe_canaries(resolver)
    return frozenset(key for key, status in canaries.items() if status != "ok")


def check_list(name, decoder, resolver=None, untrusted=False) -> dict:
    result = _dns.query(name, "A", resolver=resolver)
    if _dns.is_failure(result["status"]):
        return _listing(None, "lookup_failed", [{"code": None, "meaning": result["status"]}])
    addrs = [a["data"] for a in result["answers"] if a["type"] == "A"]
    if not addrs:
        if untrusted:
            return _listing(None, "unreliable_resolver", [{
                "code": None,
                "meaning": "no answer, but this resolver appears blocked by the list "
                           "(public resolver or failed canary)"}])
        return _listing(False, "not_listed")
    if not all(a.startswith("127.") for a in addrs):
        return _listing(None, "unexpected_answer",
                        [{"code": a, "meaning": "answer outside 127.0.0.0/8"} for a in addrs])
    return decoder(addrs)


def _run_jobs(jobs, resolver, untrusted) -> dict:
    """jobs: [(key, query_name, decoder, list_name)] -> {key: listing}, in parallel."""
    def run(job):
        _, name, decoder, list_name = job
        return check_list(name, decoder, resolver, list_name in untrusted)

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        results = pool.map(run, jobs)
        return {job[0]: listing for job, listing in zip(jobs, results)}


def check_domains(domains, resolver=None, untrusted=None) -> dict:
    """untrusted: see untrusted_lists(); None probes the canaries."""
    if untrusted is None:
        untrusted = untrusted_lists(resolver)
    jobs = [((d, key), f"{d}.{zone}", decoder, key)
            for d in domains for key, (zone, decoder) in DOMAIN_LISTS.items()]
    flat = _run_jobs(jobs, resolver, untrusted)
    return {d: {key: flat[(d, key)] for key in DOMAIN_LISTS} for d in domains}


def check_ip_lists(ip, resolver=None, untrusted=None) -> dict:
    """untrusted: see untrusted_lists(); None probes the canaries."""
    if untrusted is None:
        untrusted = untrusted_lists(resolver)
    v6 = ipaddress.ip_address(ip).version == 6
    rev = reversed_ip(ip)
    jobs = [(key, f"{rev}.{zone}", decoder, key) for key, (zone, decoder) in IP_LISTS.items()
            if not v6 or key in IPV6_LISTS]
    listings = _run_jobs(jobs, resolver, untrusted)
    skipped = _listing(None, "skipped", [{"code": None, "meaning": "list does not support IPv6"}])
    return {key: listings.get(key, skipped) for key in IP_LISTS}


# ------------------------------------------------------------- PTR / FCrDNS

def ptr_looks_generic(ptr, ip) -> bool | None:
    if not ptr:
        return None
    ptr = ptr.lower()
    addr = ipaddress.ip_address(ip)
    if addr.version == 4:
        octets = str(addr).split(".")
        for seq in (octets, octets[::-1]):
            if "-".join(seq) in ptr or ".".join(seq) in ptr:
                return True
    return bool(GENERIC_PTR_WORDS.search(ptr))


def check_ptr(ip, resolver=None):
    """-> ({ptr, fcrdns, ptr_looks_generic}, error message or None)."""
    addr = ipaddress.ip_address(ip)
    unknown = {"ptr": None, "fcrdns": None, "ptr_looks_generic": None}
    result = _dns.query(addr.reverse_pointer, "PTR", resolver=resolver)
    if _dns.is_failure(result["status"]):
        return unknown, f"PTR {ip}: {result['status']}"
    names = [a["data"].rstrip(".").lower() for a in result["answers"] if a["type"] == "PTR"]
    if not names:
        return {"ptr": None, "fcrdns": False, "ptr_looks_generic": None}, None
    ptr = names[0]
    out = {"ptr": ptr, "fcrdns": None, "ptr_looks_generic": ptr_looks_generic(ptr, ip)}
    rtype = "A" if addr.version == 4 else "AAAA"
    forward = _dns.query(ptr, rtype, resolver=resolver)
    if _dns.is_failure(forward["status"]):
        return out, f"{rtype} {ptr}: {forward['status']}"
    forward_ips = set()
    for answer in forward["answers"]:
        if answer["type"] == rtype:
            try:
                forward_ips.add(ipaddress.ip_address(answer["data"]))
            except ValueError:
                pass
    out["fcrdns"] = addr in forward_ips
    return out, None


# ------------------------------------------------------------ IP discovery

def _host_ips(host, resolver, errors) -> list[str]:
    ips = []
    for rtype in ("A", "AAAA"):
        try:
            ips += [a["data"] for a in _dns.records(host, rtype, resolver=resolver)]
        except _dns.DNSLookupError as exc:
            add_error(errors, "auto_ips", str(exc))
    return ips


def discover_spf_ips(domain, resolver, errors):
    """Self-hosted candidates from the domain's own top-level SPF record.
    -> ([(ip_string, source)], [{"range", "source"}])."""
    try:
        records = dns_auth.fetch_spf(domain, resolver)
    except _dns.DNSLookupError as exc:
        add_error(errors, "auto_ips", f"SPF lookup failed: {exc}")
        return [], []
    if not records:
        return [], []
    candidates, ranges = [], []
    for term in dns_auth.parse_spf(records)["direct_ips"]:
        kind, _, value = term.partition(":")
        source = f"spf_{kind.lower()}"
        address, _, prefix = value.partition("/")
        full = "32" if kind.lower() == "ip4" else "128"
        if prefix and prefix != full:
            ranges.append({"range": value, "source": source})
        else:
            candidates.append((address, source))

    host_mechanisms = [m for m in dns_auth.parse_spf_terms(records[0])[0]
                       if m["name"] in ("a", "mx")]
    if len(host_mechanisms) > MAX_HOST_MECHANISMS:
        add_error(errors, "auto_ips", f"discovery stopped at {MAX_HOST_MECHANISMS} of "
                  f"{len(host_mechanisms)} a/mx mechanisms; some self-hosted IPs not checked")
    for index, mech in enumerate(host_mechanisms[:MAX_HOST_MECHANISMS]):
        if len(candidates) >= MAX_IPS:
            add_error(errors, "auto_ips", f"discovery stopped at {MAX_IPS} candidate IPs "
                      f"before a/mx mechanism {index + 1}; some self-hosted IPs not checked")
            break
        target = mechanism_target(mech, domain)
        if "%" in target:  # macro -- depends on the connecting client
            continue
        source = f"spf_{mech['name']}"
        if mech["name"] == "a":
            hosts = [target]
        else:
            try:
                hosts = [r["exchange"] for r in dns_auth.fetch_mx(target, resolver)
                         if r["exchange"] != "."]
            except _dns.DNSLookupError as exc:
                add_error(errors, "auto_ips", str(exc))
                hosts = []
            if len(hosts) > dns_auth.SPF_MX_LIMIT:
                add_error(errors, "auto_ips", f"discovery stopped at {dns_auth.SPF_MX_LIMIT} of "
                          f"{len(hosts)} MX hosts for mx:{target}; "
                          "some self-hosted IPs not checked")
                hosts = hosts[:dns_auth.SPF_MX_LIMIT]
        for position, host in enumerate(hosts):
            if len(candidates) >= MAX_IPS:
                add_error(errors, "auto_ips", f"discovery stopped at {MAX_IPS} candidate IPs "
                          f"after {position} of {len(hosts)} hosts for {mech['term']}; "
                          "some self-hosted IPs not checked")
                break
            candidates += [(ip, source) for ip in _host_ips(host, resolver, errors)]
    return candidates, ranges


def select_ips(candidates):
    """Dedupe, drop private/reserved, cap at MAX_IPS.
    -> ([{"ip", "source"}], [{"ip", "source", "reason"}])."""
    selected, skipped, seen = [], [], set()
    for raw, source in candidates:
        try:
            addr = ipaddress.ip_address(raw)
        except ValueError:
            skipped.append({"ip": raw, "source": source, "reason": "invalid_ip"})
            continue
        if addr in seen:
            continue
        seen.add(addr)
        if not addr.is_global:
            skipped.append({"ip": str(addr), "source": source, "reason": "private_or_reserved"})
        elif len(selected) >= MAX_IPS:
            skipped.append({"ip": str(addr), "source": source, "reason": "cap_reached"})
        else:
            selected.append({"ip": str(addr), "source": source})
    return selected, skipped


def _validate_ips(ips) -> list[tuple[str, str]]:
    """User IP strings (source "argument") are validated strictly; (ip, source)
    pairs are caller-tagged and checked later by select_ips."""
    ips = list(ips or ())
    if len(ips) > MAX_IPS:
        raise ValueError(f"Supply at most {MAX_IPS} IP addresses.")
    candidates = []
    for entry in ips:
        if isinstance(entry, tuple) and len(entry) == 2:
            candidates.append((str(entry[0]).strip(), entry[1]))
            continue
        if not isinstance(entry, str):
            raise ValueError("IP addresses must be strings.")
        value = entry.strip()
        try:
            ipaddress.ip_address(value)
        except ValueError:
            raise ValueError(f"Invalid IP address: {entry!r}") from None
        candidates.append((value, "argument"))
    return candidates


# ------------------------------------------------------------------ output

def build_output(target, ips=(), resolver=None, *, auto_ips=True) -> dict:
    """Check `target` (email address or domain) and its IPs. `ips`: at most
    MAX_IPS IP strings (source "argument") or (ip, source) pairs. auto_ips=False
    skips SPF-based discovery. Raises ValueError for invalid input."""
    domain = domain_from_arg(target)
    if resolver is not None and not _dns.is_valid_resolver(resolver):
        raise ValueError("resolver must be an IP address.")
    candidates = _validate_ips(ips)

    errors = {}
    org = org_domain(domain)
    domains = list(dict.fromkeys([domain, org]))
    skipped_ranges = []
    with ThreadPoolExecutor(max_workers=1) as canary_pool:
        # Canaries run once, alongside IP discovery.
        canaries_future = canary_pool.submit(probe_canaries, resolver)
        if auto_ips:
            found, skipped_ranges = discover_spf_ips(domain, resolver, errors)
            candidates += found
        canaries = canaries_future.result()
    selected, skipped_ips = select_ips(candidates)
    untrusted = untrusted_lists(resolver, canaries)

    checked = []
    for entry in selected:
        ptr_info, ptr_error = check_ptr(entry["ip"], resolver)
        if ptr_error:
            add_error(errors, "ptr", ptr_error)
        checked.append({**entry, "listings": check_ip_lists(entry["ip"], resolver, untrusted),
                        **ptr_info})

    domain_listings = check_domains(domains, resolver, untrusted)
    all_listings = [x for lists in domain_listings.values() for x in lists.values()]
    all_listings += [x for ip in checked for x in ip["listings"].values()]
    refused = any(x["status"] == "query_refused" for x in all_listings)

    notes = []
    if refused or uses_public_resolver(resolver):
        notes.append(REFUSED_NOTE)
    failed_canaries = sorted(key for key, status in canaries.items() if status != "ok")
    if failed_canaries:
        notes.append(CANARY_NOTE.format(lists=", ".join(failed_canaries)))

    return {
        "domain": domain,
        "org_domain": org,
        "resolver": _dns.effective_resolver(resolver) or "system",
        "resolver_canaries": canaries,
        "domain_listings": domain_listings,
        "ips": checked,
        "skipped_ranges": skipped_ranges,
        "skipped_ips": skipped_ips,
        "resolver_note": " ".join(notes) or None,
        "errors": errors,
    }
