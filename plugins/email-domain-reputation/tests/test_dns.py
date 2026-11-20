"""Tests for the dnspython-backed _dns layer. No real DNS: the resolver is faked."""

import importlib
from types import SimpleNamespace

import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.resolver
import pytest

PACKAGE = "shadetree_ai_plugins_email_domain_reputation"
_dns = importlib.import_module(f"{PACKAGE}._dns")


class FakeResolver:
    def __init__(self, outcome):
        self.outcome = outcome
        self.calls = []

    def resolve(self, qname, rdtype, **kwargs):
        self.calls.append((qname, rdtype, kwargs))
        if isinstance(self.outcome, BaseException):
            raise self.outcome
        return self.outcome


def response(name, rtype, rrsets, *, ad=False):
    """A real dns.message response wrapped like a dnspython Answer."""
    message = dns.message.make_response(dns.message.make_query(name, rtype))
    for owner, rdtype, ttl, *datas in rrsets:
        rrset = message.find_rrset(message.answer, dns.name.from_text(owner), dns.rdataclass.IN,
                                   dns.rdatatype.from_text(rdtype), create=True)
        for data in datas:
            rrset.add(dns.rdata.from_text("IN", rdtype, data), ttl)
    if ad:
        message.flags |= dns.flags.AD
    return SimpleNamespace(response=message)


@pytest.fixture
def fake(monkeypatch):
    def install(outcome):
        resolver = FakeResolver(outcome)
        monkeypatch.setattr(_dns, "_resolver", lambda server: resolver)
        return resolver
    return install


@pytest.fixture
def no_network(monkeypatch):
    def fail(server):
        raise AssertionError("resolver must not be used")
    monkeypatch.setattr(_dns, "_resolver", fail)


@pytest.mark.parametrize("name", [
    "-f/etc/passwd", "+trace", "-fexample.com", "example.com -f/etc/passwd",
    "a.-f.example.com", "foo/bar.com", "", ".", "a..b", "exa mple.com",
    "x" * 64 + ".com", ("a" * 60 + ".") * 5, "ex\nample.com", None,
])
def test_invalid_names_never_reach_the_resolver(no_network, name):
    result = _dns.query(name, "A")
    assert result == {"status": "ERROR", "answers": [], "ad": False,
                      "error": "invalid_query_name"}
    assert _dns.is_failure(result["status"])


def test_invalid_rtype_and_resolver_never_reach_the_resolver(no_network):
    assert _dns.query("example.com", "-f/etc/passwd")["error"] == "invalid_query_type"
    assert _dns.query("example.com", "ANY")["error"] == "invalid_query_type"
    for server in ("-f/etc/passwd", "resolver.example.net", "+tcp"):
        assert _dns.query("example.com", "A", resolver=server)["error"] == "invalid_resolver"
    with pytest.raises(_dns.DNSLookupError):
        _dns.records("-f/etc/passwd", "A")


def test_resolver_validation_is_ip_only():
    assert _dns.is_valid_resolver("192.0.2.53")
    assert _dns.is_valid_resolver("2001:db8::53")
    assert not _dns.is_valid_resolver("resolver.example.net")
    assert _dns.effective_resolver(None) is None
    assert _dns.effective_resolver("192.0.2.53") == "192.0.2.53"


def test_query_is_absolute_without_search_and_bounded(fake):
    resolver = fake(response("_dmarc.example.com", "TXT", []))
    result = _dns.query("_dmarc.example.com", "txt", timeout=4)
    qname, rdtype, kwargs = resolver.calls[0]
    assert qname.is_absolute() and qname.to_text() == "_dmarc.example.com."
    assert rdtype == "TXT"
    assert kwargs == {"search": False, "raise_on_no_answer": False, "lifetime": 4}
    assert result == {"status": "NOERROR", "answers": [], "ad": False}


def test_answers_include_cname_chain_and_ad_flag(fake):
    fake(response("selector1._domainkey.example.com", "TXT", [
        ("selector1._domainkey.example.com.", "CNAME", 60, "sel1.example.net."),
        ("sel1.example.net.", "TXT", 300, '"v=DKIM1; " "p=ABC"'),
    ], ad=True))
    result = _dns.query("selector1._domainkey.example.com", "TXT")
    assert result["status"] == "NOERROR"
    assert result["ad"] is True
    assert result["answers"][0] == {"name": "selector1._domainkey.example.com", "type": "CNAME",
                                    "ttl": 60, "data": "sel1.example.net."}
    assert result["answers"][1]["data"] == '"v=DKIM1; " "p=ABC"'
    records = _dns.records("selector1._domainkey.example.com", "TXT")
    assert [r["type"] for r in records] == ["TXT"]
    assert _dns.txt_records("selector1._domainkey.example.com") == ["v=DKIM1; p=ABC"]


def no_nameservers(*rcodes):
    request = dns.message.make_query("example.com", "TXT")
    return dns.resolver.NoNameservers(
        request=request, errors=[("192.0.2.53", False, 53, rcode, None) for rcode in rcodes])


@pytest.mark.parametrize("outcome,status", [
    (dns.resolver.NXDOMAIN(), "NXDOMAIN"),
    (dns.resolver.NoAnswer(), "NOERROR"),
    (no_nameservers("REFUSED"), "REFUSED"),
    (no_nameservers("SERVFAIL"), "SERVFAIL"),
    (no_nameservers("REFUSED", "SERVFAIL"), "SERVFAIL"),
    (dns.resolver.LifetimeTimeout(timeout=1.0, errors=[]), "TIMEOUT"),
    (dns.exception.Timeout(), "TIMEOUT"),
    (dns.resolver.NoResolverConfiguration(), "ERROR"),
    (OSError("network unreachable"), "ERROR"),
])
def test_failure_mapping(fake, outcome, status):
    fake(outcome)
    result = _dns.query("example.com", "TXT")
    assert result["status"] == status
    assert result["answers"] == []
    assert _dns.is_failure(status) is (status not in ("NOERROR", "NXDOMAIN"))
    if status == "ERROR":
        assert result["error"]


def test_records_raise_on_failure_and_empty_on_absence(fake):
    fake(no_nameservers("REFUSED"))
    with pytest.raises(_dns.DNSLookupError) as exc:
        _dns.txt_records("bad.example")
    assert exc.value.status == "REFUSED"
    fake(dns.resolver.NXDOMAIN())
    assert _dns.txt_records("missing.example") == []


def test_explicit_resolver_uses_only_that_ip_and_requests_ad():
    _dns._resolver.cache_clear()
    resolver = _dns._resolver("192.0.2.53")
    assert resolver.nameservers == ["192.0.2.53"]
    assert resolver.flags & dns.flags.AD
    assert _dns._resolver("192.0.2.53") is resolver


def test_txt_strings_concatenates_segments_and_unescapes_ascii_digits_only():
    assert _dns.txt_strings('"v=DKIM1; k=rsa; " "p=ABC123"') == "v=DKIM1; k=rsa; p=ABC123"
    assert _dns.txt_strings("plain-text") == "plain-text"
    assert _dns.txt_strings(r'"a\"b\059c"') == 'a"b;c'
