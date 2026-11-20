"""Domain and hosting-IP DNS blocklist checks (ported from email-domain-reputation).

Spamhaus/URIBL/SURBL refuse public resolvers. Each list's official test entry
(canary) is queried first; if it doesn't come back listed, that list's
"not listed" answers are reported as ``unreliable_resolver`` rather than clean.
"""

from __future__ import annotations

import ipaddress
import socket
import urllib.parse
from concurrent.futures import ThreadPoolExecutor

import dns.exception
import dns.resolver

from ..store import SourceResult

NAME = "blocklists"
SPAMHAUS_REFUSED = {"127.255.255.252", "127.255.255.254", "127.255.255.255", "127.0.1.255"}
DBL_CODES = {"127.0.1.2": "spam domain", "127.0.1.4": "phishing domain",
             "127.0.1.5": "malware domain", "127.0.1.6": "botnet C&C domain",
             "127.0.1.102": "abused legit spam", "127.0.1.103": "abused spammed redirector",
             "127.0.1.104": "abused legit phish", "127.0.1.105": "abused legit malware",
             "127.0.1.106": "abused legit botnet C&C"}
DOMAIN_LISTS = {"spamhaus_dbl": "dbl.spamhaus.org", "surbl": "multi.surbl.org",
                "uribl": "multi.uribl.com"}
IP_LISTS = {"spamhaus_zen": "zen.spamhaus.org", "spamcop": "bl.spamcop.net",
            "barracuda": "b.barracudacentral.org"}
CANARIES = {"spamhaus_dbl": "dbltest.com.dbl.spamhaus.org",
            "spamhaus_zen": "2.0.0.127.zen.spamhaus.org",
            "uribl": "test.uribl.com.multi.uribl.com",
            "surbl": "test.surbl.org.multi.surbl.org"}


def enabled(site: dict) -> tuple[bool, str]:
    return (bool(site.get("blocklists", True)), "blocklists disabled")


def lookup(name: str) -> list[str] | None:
    """A-record answers; [] for NXDOMAIN/no answer; None on resolver failure."""
    try:
        return [r.to_text() for r in dns.resolver.resolve(name, "A", lifetime=5)]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []
    except (dns.exception.DNSException, OSError):
        return None


def interpret(list_name: str, addrs: list[str] | None, trusted: bool) -> dict:
    if addrs is None:
        return {"listed": None, "status": "lookup_failed"}
    if not addrs:
        return ({"listed": False, "status": "not_listed"} if trusted
                else {"listed": None, "status": "unreliable_resolver"})
    if any(a in SPAMHAUS_REFUSED for a in addrs) or (
            list_name in ("uribl", "surbl") and "127.0.0.1" in addrs):
        return {"listed": None, "status": "query_refused", "codes": addrs}
    if not all(a.startswith("127.") for a in addrs):
        return {"listed": None, "status": "unexpected_answer", "codes": addrs}
    meanings = [DBL_CODES.get(a, a) for a in addrs] if list_name == "spamhaus_dbl" else addrs
    return {"listed": True, "status": "listed", "codes": meanings}


def collect(site: dict, store, backfill_days: int = 0) -> SourceResult:
    host = urllib.parse.urlparse(site["url"]).hostname or ""
    domain = host.removeprefix("www.")
    result = SourceResult(NAME)
    with ThreadPoolExecutor(max_workers=8) as pool:
        canary = dict(zip(CANARIES, pool.map(lookup, CANARIES.values())))
        trusted = {k: bool(v) and not any(a in SPAMHAUS_REFUSED for a in v)
                   for k, v in canary.items()}
        jobs = {f"domain:{k}": f"{domain}.{zone}" for k, zone in DOMAIN_LISTS.items()}
        try:
            ips = sorted({ai[4][0] for ai in socket.getaddrinfo(host, 443)
                          if ipaddress.ip_address(ai[4][0]).version == 4})[:3]
        except OSError:
            ips = []
            result.warnings.append(f"Could not resolve {host} for IP blocklist checks.")
        for ip in ips:
            rev = ".".join(reversed(ip.split(".")))
            for k, zone in IP_LISTS.items():
                jobs[f"ip:{ip}:{k}"] = f"{rev}.{zone}"
        answers = dict(zip(jobs, pool.map(lookup, jobs.values())))
    checks = {}
    for job, addrs in answers.items():
        list_name = job.rsplit(":", 1)[-1]
        checks[job] = interpret(list_name, addrs, trusted.get(list_name, True))
    listed = {k: v for k, v in checks.items() if v["listed"]}
    unreliable = [k for k, v in checks.items() if v["status"] in
                  ("unreliable_resolver", "query_refused")]
    result.summary = {"domain": domain, "ips": ips, "listed": len(listed),
                      "unreliable": unreliable}
    result.raw["checks"] = checks
    for job, verdict in listed.items():
        result.findings.append({"source": NAME, "kind": "blocklisted", "severity": "critical",
                                "check": job, "codes": verdict.get("codes")})
    if unreliable:
        result.warnings.append("Some blocklists refused this resolver (public resolvers are "
                               "blocked); their results are unknown, not clean: "
                               + ", ".join(sorted(unreliable)))
    return result
