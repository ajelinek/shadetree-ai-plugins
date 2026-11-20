"""Shared DNS lookup helper built on dnspython.

`query()` keeps the response code (NOERROR / NXDOMAIN / SERVFAIL / REFUSED /
TIMEOUT / ERROR) and the AD flag, because callers must be able to tell "the
record does not exist" apart from "the lookup failed".

Resolver selection: an explicit `resolver=` IP address, else the machine's
own resolver configuration. No public resolver is hard-coded. Query names
are validated before any network call: untrusted names (SPF targets, PTR
answers, DKIM selectors from headers) flow into queries.
"""

from __future__ import annotations

import functools
import ipaddress
import re

import dns.exception
import dns.flags
import dns.name
import dns.rdatatype
import dns.resolver

DEFAULT_TIMEOUT_SECONDS = 6
NO_RECORD_STATUSES = frozenset({"NOERROR", "NXDOMAIN"})
MAX_NAME_LENGTH = 253
ALLOWED_RTYPES = frozenset({
    "A", "AAAA", "CAA", "CNAME", "DNSKEY", "DS", "MX", "NS", "PTR", "SOA", "SRV", "TLSA", "TXT"})
# Letters/digits/hyphen/underscore labels, none starting with '-'.
_LABEL_RE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_-]{0,62}")
_TXT_STRING_RE = re.compile(r'"((?:[^"\\]|\\.)*)"')
_TXT_ESCAPE_RE = re.compile(r"\\(\d{3}|.)")
_QUERY_FLAGS = dns.flags.RD | dns.flags.AD  # AD asks a validating resolver to report DNSSEC


class DNSLookupError(Exception):
    """A lookup failed (SERVFAIL, REFUSED, TIMEOUT, ...) -- distinct from
    NXDOMAIN / no data, which mean the record genuinely does not exist."""

    def __init__(self, name, rtype, status, detail=None):
        self.name, self.rtype, self.status, self.detail = name, rtype, status, detail
        message = f"{rtype} {name}: {status}"
        super().__init__(f"{message} ({detail})" if detail else message)


def effective_resolver(resolver=None):
    """The resolver that query() would use; None means the system resolver."""
    return resolver or None


def is_valid_query_name(name) -> bool:
    """True when `name` has DNS name shape (optional trailing dot)."""
    if not isinstance(name, str):
        return False
    bare = name[:-1] if name.endswith(".") else name
    if not bare or len(bare) > MAX_NAME_LENGTH:
        return False
    return all(_LABEL_RE.fullmatch(label) for label in bare.split("."))


def is_valid_resolver(server) -> bool:
    """An explicit resolver must be an IP address."""
    try:
        ipaddress.ip_address(server)
        return True
    except ValueError:
        return False


def is_failure(status) -> bool:
    """True for anything other than NOERROR / NXDOMAIN."""
    return status not in NO_RECORD_STATUSES


@functools.lru_cache(maxsize=8)
def _resolver(server: str | None) -> dns.resolver.Resolver:
    """Cached resolver; Resolver.resolve is safe to share across threads."""
    if server is None:
        resolver = dns.resolver.Resolver()
    else:
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = [server]
    resolver.flags = _QUERY_FLAGS
    return resolver


def _result(status, answers=(), ad=False, error=None) -> dict:
    result = {"status": status, "answers": list(answers), "ad": ad}
    if error:
        result["error"] = error
    return result


def _answers(response) -> list[dict]:
    """Every answer-section record, CNAME chain entries included."""
    return [
        {"name": rrset.name.to_text(omit_final_dot=True).lower(),
         "type": dns.rdatatype.to_text(rrset.rdtype), "ttl": rrset.ttl, "data": rdata.to_text()}
        for rrset in response.answer for rdata in rrset
    ]


def _no_nameservers_status(exc: dns.resolver.NoNameservers) -> str:
    rcodes = {err[3] for err in exc.kwargs.get("errors") or () if isinstance(err[3], str)}
    return "REFUSED" if rcodes == {"REFUSED"} else "SERVFAIL"


def _short_error(exc: BaseException) -> str:
    text = str(exc).strip() or type(exc).__name__
    return text if len(text) <= 200 else text[:197] + "..."


def query(name, rtype, *, resolver=None, timeout=DEFAULT_TIMEOUT_SECONDS) -> dict:
    """Run one DNS query. Never raises for DNS-level failures -- inspect
    `status` (see is_failure). Invalid name / rtype / resolver -> status
    "ERROR" without any network call."""
    if not is_valid_query_name(name):
        return _result("ERROR", error="invalid_query_name")
    rtype = rtype.upper() if isinstance(rtype, str) else rtype
    if rtype not in ALLOWED_RTYPES:
        return _result("ERROR", error="invalid_query_type")
    server = effective_resolver(resolver)
    if server is not None and not is_valid_resolver(server):
        return _result("ERROR", error="invalid_resolver")
    try:
        answer = _resolver(server).resolve(
            dns.name.from_text(name), rtype, search=False, raise_on_no_answer=False,
            lifetime=timeout)
    except dns.resolver.NXDOMAIN:
        return _result("NXDOMAIN")
    except dns.resolver.NoAnswer:
        return _result("NOERROR")
    except dns.resolver.NoNameservers as exc:
        return _result(_no_nameservers_status(exc), error=_short_error(exc))
    except dns.exception.Timeout:
        return _result("TIMEOUT")
    except (dns.exception.DNSException, OSError) as exc:
        return _result("ERROR", error=_short_error(exc))
    response = answer.response
    return _result("NOERROR", _answers(response), bool(response.flags & dns.flags.AD))


def _unescape_txt(value: str) -> str:
    def repl(match):
        token = match.group(1)
        return chr(int(token)) if token.isascii() and token.isdigit() else token
    return _TXT_ESCAPE_RE.sub(repl, value)


def txt_strings(data: str) -> str:
    """Concatenate the quoted character-strings of TXT presentation text."""
    quoted = _TXT_STRING_RE.findall(data)
    if quoted:
        return "".join(_unescape_txt(segment) for segment in quoted)
    return data.strip('"')


def records(name, rtype, *, resolver=None) -> list[dict]:
    """Answers of exactly `rtype` (CNAME chain entries dropped). Empty list on
    NXDOMAIN / no data; raises DNSLookupError when the lookup itself failed."""
    result = query(name, rtype, resolver=resolver)
    if is_failure(result["status"]):
        raise DNSLookupError(name, rtype, result["status"], result.get("error"))
    return [a for a in result["answers"] if a["type"] == rtype.upper()]


def txt_records(name, *, resolver=None) -> list[str]:
    """Concatenated TXT strings at `name`; same failure semantics as records()."""
    return [txt_strings(a["data"]) for a in records(name, "TXT", resolver=resolver)]
