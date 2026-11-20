"""Tests for audit.run_audit, ported from the skill's test_audit.py.

Every section function is mocked at its module boundary, so this suite runs
offline and never touches a real API key.
"""

from pathlib import Path

import pytest
from shadetree_ai_plugins_email_domain_reputation import (
    _dns,
    audit,
    blocklists,
    dns_auth,
    headers,
    registration,
    reputation,
)

KEY = "test-key-SECRET"


def dns_output(spf_record="v=spf1 ip4:192.0.2.0/24 -all", selectors_found=None, has_rua=True,
               dmarc_found=True, provider_include_present=True):
    records = [spf_record] if spf_record else []
    spf = dns_auth.parse_spf(records)
    spf["provider_include_present"] = provider_include_present
    return {
        "domain": "example.com",
        "spf": spf,
        "dmarc": {"found": dmarc_found, "has_rua": has_rua},
        "dkim": {"selectors_found": selectors_found or {}},
        "errors": {},
    }


def headers_output(selectors=("s1",), sending_ip="192.0.2.10", from_org="example.com"):
    return {"from": {"domain": from_org, "org_domain": from_org},
            "selectors": list(selectors), "sending_ip": sending_ip}


def registration_output(nameservers=("ns1.example.net", "ns2.example.net")):
    return {"domain": "example.com", "registration": {"nameservers": list(nameservers)},
            "source": {"ok": True, "error": None, "detail": None}}


REPUTATION_OK = {"signals": {"deliverable": True}, "source": {"ok": True, "error": None,
                                                             "detail": None}}


class Harness:
    """Patches every section boundary; tweak attributes before run()."""

    def __init__(self, monkeypatch):
        self.monkeypatch = monkeypatch
        self.dns = dns_output()
        self.headers = headers_output()
        self.registration = registration_output()
        self.nameservers = ["ns2.example.net.", "NS1.example.net"]
        self.reputation = REPUTATION_OK
        self.calls = {}

    def _record(self, name, value):
        def fn(*args, **kwargs):
            self.calls[name] = (args, kwargs)
            if isinstance(value, Exception):
                raise value
            return value
        return fn

    def run(self, target="user@example.com", **kwargs):
        kwargs.setdefault("api_key", KEY)
        ns_records = (self.nameservers if isinstance(self.nameservers, Exception)
                      else [{"type": "NS", "data": n} for n in self.nameservers])
        mp = self.monkeypatch
        mp.setattr(headers, "analyze_headers", self._record("headers", self.headers))
        mp.setattr(dns_auth, "build_output", self._record("dns", self.dns))
        mp.setattr(blocklists, "build_output",
                   self._record("blocklists", {"domain": "example.com"}))
        mp.setattr(registration, "build_output", self._record("registration", self.registration))
        mp.setattr(_dns, "records", self._record("ns", ns_records))
        mp.setattr(reputation, "check_reputation", self._record("reputation", self.reputation))
        return audit.run_audit(target, **kwargs)


@pytest.fixture
def h(monkeypatch):
    return Harness(monkeypatch)


# ------------------------------------------------------------------ sections

def test_output_shape(h):
    out = h.run("user@example.com")
    assert list(out) == ["target", "domain", "org_domain", "org_domain_approximate",
                         "generated_at", "resolver", "sections", "section_errors", "skipped",
                         "cross_checks"]
    assert list(out["sections"]) == ["dns", "blocklists", "registration", "headers",
                                     "reputation"]
    assert (out["target"], out["domain"], out["org_domain"]) == (
        "user@example.com", "example.com", "example.com")
    assert out["org_domain_approximate"] is False
    assert h.run("shop.example.co.uk")["org_domain_approximate"] is True
    assert out["generated_at"].endswith("+00:00")
    assert out["section_errors"] == {}
    assert out["sections"]["headers"] is None
    assert out["skipped"] == {"headers": "no_raw_headers"}
    assert out["resolver"] == "system"
    assert out["sections"]["reputation"] == REPUTATION_OK
    assert h.calls["reputation"][0] == ("user@example.com", KEY)
    assert set(out["cross_checks"]) == {
        "header_from_matches_target", "header_dkim_selectors_in_dns",
        "header_sending_ip_in_spf", "header_alignment_per_dmarc_policy", "dmarc_rua_present",
        "registration_nameservers_match_dns", "provider_spf_include_present"}


def test_headers_feed_selectors_and_sending_ip(h):
    h.headers = headers_output(selectors=("s1", "extra"), sending_ip="203.0.113.5")
    out = h.run("user@example.com", raw_headers="From: a@example.com\n",
                selectors=["extra", "CLI"], sending_ips=["198.51.100.1"], resolver="10.0.0.53")
    assert out["sections"]["headers"] == h.headers
    assert "headers" not in out["skipped"]
    assert out["resolver"] == "10.0.0.53"
    assert h.calls["dns"][0] == ("example.com", "10.0.0.53", ["extra", "cli", "s1"])
    assert h.calls["blocklists"][0] == (
        "example.com", [("198.51.100.1", "argument"), ("203.0.113.5", "headers")], "10.0.0.53")
    assert h.calls["ns"][0] == ("example.com", "NS")


def test_header_ip_already_given_keeps_argument_source(h):
    h.headers = headers_output(sending_ip="198.51.100.1")
    h.run(raw_headers="x", sending_ips=["198.51.100.1"])
    assert h.calls["blocklists"][0][1] == [("198.51.100.1", "argument")]


def test_reputation_skipped_for_bare_domain(h):
    out = h.run("example.com")
    assert out["sections"]["reputation"] is None
    assert "reputation" not in out["section_errors"]
    assert out["skipped"]["reputation"] == "not_email_target"
    assert "reputation" not in h.calls


def test_reputation_skipped_without_api_key(h):
    out = h.run("user@example.com", api_key=None)
    assert out["sections"]["reputation"] is None
    assert out["skipped"]["reputation"] == "no_api_key"
    assert "reputation" not in out["section_errors"]
    assert "reputation" not in h.calls
    assert out["sections"]["dns"] is not None


def test_section_exception_isolated(h):
    h.dns = RuntimeError("boom")
    out = h.run("user@example.com")
    assert out["sections"]["dns"] is None
    assert out["section_errors"]["dns"] == "RuntimeError: boom"
    assert out["sections"]["blocklists"] is not None
    assert out["sections"]["registration"] is not None
    assert out["sections"]["reputation"] is not None
    assert out["cross_checks"]["dmarc_rua_present"] is None


def test_api_key_scrubbed_from_section_errors(h):
    h.reputation = RuntimeError(f"failed with Bearer {KEY}")
    out = h.run("user@example.com")
    assert out["sections"]["reputation"] is None
    assert KEY not in str(out)
    assert out["section_errors"]["reputation"] == "RuntimeError: failed with Bearer [redacted]"


@pytest.mark.parametrize("target", ["not a domain", "@example.com", "a@b@example", "",
                                    "1.2.3.4", "user@", None])
def test_invalid_target_raises_before_network(h, target):
    with pytest.raises(ValueError):
        h.run(target)
    assert h.calls == {}


@pytest.mark.parametrize("kwargs", [
    {"sending_ips": ["999.1.1.1"]},
    {"sending_ips": [f"192.0.2.{i}" for i in range(21)]},
    {"sending_ips": "192.0.2.1"},
    {"selectors": ["bad selector"]},
    {"selectors": [f"s{i}" for i in range(21)]},
    {"resolver": "dns.example"},
])
def test_invalid_inputs_raise_before_network(h, kwargs):
    with pytest.raises(ValueError):
        h.run("user@example.com", **kwargs)
    assert h.calls == {}


def test_header_ip_over_cap_raises(h):
    h.headers = headers_output(sending_ip="203.0.113.5")
    with pytest.raises(ValueError, match="19"):
        h.run(raw_headers="x", sending_ips=[f"192.0.2.{i}" for i in range(20)])
    assert set(h.calls) == {"headers"}


@pytest.mark.parametrize("raw", ["", "   \n", "just some text\n", "A" * (256 * 1024 + 1)])
def test_invalid_headers_raise(raw):
    with pytest.raises(ValueError):
        audit.validate_inputs("user@example.com", raw_headers=raw)


def test_real_header_fixture_feeds_selectors_and_ip():
    raw = (Path(__file__).parent / "fixtures" / "headers" / "gmail_pass_aligned.eml").read_text()
    inputs = audit.validate_inputs("user@example.com", raw_headers=raw, selectors=["mine"])
    parsed = inputs["headers"]
    assert parsed["from"]["domain"]
    assert inputs["selectors"] == ["mine", "s1"]
    assert inputs["ips"] == [("203.0.113.25", "headers")]


# --------------------------------------------------------------- cross checks

def cross(h, **kwargs):
    kwargs.setdefault("raw_headers", "From: a@example.com\n")
    return h.run("user@example.com", **kwargs)["cross_checks"]


def test_all_true_case(h):
    h.dns = dns_output(selectors_found={"s1": {"has_public_key": True}})
    assert cross(h) == {
        "header_from_matches_target": True,
        "header_dkim_selectors_in_dns": {"s1": True},
        "header_sending_ip_in_spf": True,
        "header_alignment_per_dmarc_policy": {"adkim": "r", "aspf": "r",
                                              "spf_aligned": None, "dkim_aligned": None},
        "dmarc_rua_present": True,
        "registration_nameservers_match_dns": True,
        "provider_spf_include_present": True,
    }


def test_without_headers_header_checks_are_null(h):
    checks = cross(h, raw_headers=None)
    assert checks["header_from_matches_target"] is None
    assert checks["header_dkim_selectors_in_dns"] is None
    assert checks["header_sending_ip_in_spf"] is None


def test_from_mismatch_and_missing_from(h):
    h.headers = headers_output(from_org="other.com")
    assert cross(h)["header_from_matches_target"] is False
    h.headers = {**headers_output(), "from": {"domain": None, "org_domain": None}}
    assert cross(h)["header_from_matches_target"] is None


def test_dkim_selector_missing_or_keyless(h):
    h.headers = headers_output(selectors=("s1", "s2", "s3"))
    h.dns = dns_output(selectors_found={"s1": {"has_public_key": True},
                                        "s2": {"has_public_key": False}})
    assert cross(h)["header_dkim_selectors_in_dns"] == {"s1": True, "s2": False, "s3": False}


def test_dkim_selector_lookup_failed_is_null(h):
    h.headers = headers_output(selectors=("s1", "s2"))
    h.dns = dns_output(selectors_found={})
    h.dns["dkim"]["selectors_failed"] = ["s1"]
    assert cross(h)["header_dkim_selectors_in_dns"] == {"s1": None, "s2": False}


@pytest.mark.parametrize(("ip", "record", "expected"), [
    ("198.51.100.9", "v=spf1 ip4:192.0.2.0/24 -all", False),
    ("198.51.100.9", "v=spf1 ip4:192.0.2.0/24 include:_spf.google.com -all", None),
    ("198.51.100.9", "v=spf1 ip4:192.0.2.1 redirect=_spf.example.net", None),
    ("198.51.100.9", None, False),
    ("2001:db8::5", "v=spf1 ip6:2001:db8::/32 include:x.example -all", True),
    (None, "v=spf1 ip4:192.0.2.0/24 -all", None),
    # +all and lookup ordering
    ("5.6.7.8", "v=spf1 ip4:1.2.3.4 +all", True),
    ("5.6.7.8", "v=spf1 include:x.example +all", True),
    ("5.6.7.8", "v=spf1 -include:x.example +all", None),
    ("5.6.7.8", "v=spf1 ip4:1.2.3.4 ~all", False),
    ("5.6.7.8", "v=spf1 include:x.example ip4:5.6.7.0/24 -all", None),
    ("5.6.7.8", "v=spf1 mx -ip4:5.6.7.8 -all", None),
    ("5.6.7.8", "v=spf1 ip4:5.6.7.8 mx -all", True),
    # non-"+" qualifiers on the matching term
    ("192.0.2.10", "v=spf1 -ip4:192.0.2.10 include:x.example -all", False),
    ("192.0.2.10", "v=spf1 ~ip4:192.0.2.0/24 -all", False),
    ("192.0.2.10", "v=spf1 -ip4:198.51.100.1 +ip4:192.0.2.0/24 -all", True),
])
def test_sending_ip_in_spf(h, ip, record, expected):
    h.headers = headers_output(sending_ip=ip)
    h.dns = dns_output(record)
    assert cross(h)["header_sending_ip_in_spf"] is expected


def test_sending_ip_spf_unknown_when_spf_lookup_failed(h):
    h.dns["spf"]["found"] = None
    assert cross(h)["header_sending_ip_in_spf"] is None


def test_alignment_per_dmarc_policy(h):
    h.headers = {**headers_output(from_org="example.com"),
                 "return_path": {"domain": "bounce.example.com"},
                 "authentication_results": [headers.parse_auth_results(
                     "mx.example; spf=pass smtp.mailfrom=bounce.example.com; "
                     "dkim=pass header.d=example.com")]}
    h.dns["dmarc"].update({"adkim": "s", "aspf": "s"})
    assert cross(h)["header_alignment_per_dmarc_policy"] == {
        "adkim": "s", "aspf": "s", "spf_aligned": False, "dkim_aligned": True}
    h.dns["dmarc"].update({"aspf": "r"})
    assert cross(h)["header_alignment_per_dmarc_policy"]["spf_aligned"] is True
    h.dns = dns_output(dmarc_found=None)
    assert cross(h)["header_alignment_per_dmarc_policy"] == {
        "adkim": None, "aspf": None, "spf_aligned": None, "dkim_aligned": None}
    assert cross(h, raw_headers=None)["header_alignment_per_dmarc_policy"]["adkim"] is None


def test_dmarc_rua(h):
    h.dns = dns_output(has_rua=False)
    assert cross(h)["dmarc_rua_present"] is False
    h.dns = dns_output(dmarc_found=None)
    assert cross(h)["dmarc_rua_present"] is None


def test_nameserver_match_cases(h):
    h.nameservers = ["ns1.example.net", "ns3.example.net"]
    assert cross(h)["registration_nameservers_match_dns"] is False
    h.registration = registration_output(nameservers=())
    assert cross(h)["registration_nameservers_match_dns"] is None


def test_nameserver_lookup_failure_is_null_and_recorded(h):
    h.nameservers = _dns.DNSLookupError("example.com", "NS", "SERVFAIL")
    out = h.run("example.com")
    assert out["cross_checks"]["registration_nameservers_match_dns"] is None
    assert out["section_errors"]["cross_checks"].startswith("live NS lookup: ")
    assert "SERVFAIL" in out["section_errors"]["cross_checks"]
    assert out["sections"]["registration"] is not None


def test_provider_include_copied(h):
    h.dns = dns_output(provider_include_present=False)
    assert cross(h)["provider_spf_include_present"] is False
    h.dns = RuntimeError("boom")
    assert cross(h)["provider_spf_include_present"] is None


def test_sending_ip_never_in_spf_with_multiple_records(h):
    h.headers = headers_output(sending_ip="192.0.2.10")
    h.dns = dns_output("v=spf1 ip4:192.0.2.0/24 +all")
    h.dns["spf"] = dns_auth.parse_spf(["v=spf1 ip4:192.0.2.0/24 +all", "v=spf1 -all"])
    assert cross(h)["header_sending_ip_in_spf"] is False


def test_prefetched_reputation_result_skips_api_call(h):
    prefetched = {"signals": {"deliverable": True},
                  "source": {"ok": True, "error": None, "detail": None}}
    out = h.run("user@example.com", api_key=None, reputation_result=prefetched)
    assert out["sections"]["reputation"] == prefetched
    assert "reputation" not in out["skipped"]
    assert "reputation" not in h.calls


def test_combined_selectors_are_bounded(h):
    h.headers = headers_output(selectors=[f"h{n}" for n in range(20)])
    h.run(raw_headers="From: a@example.com\n", selectors=[f"u{n}" for n in range(20)])
    extras = h.calls["dns"][0][2]
    assert len(extras) == 40 <= dns_auth.MAX_EXTRA_SELECTORS
