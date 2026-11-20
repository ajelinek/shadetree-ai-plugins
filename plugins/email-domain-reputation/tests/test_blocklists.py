"""Tests for blocklists. No real DNS: lookups are mocked at `_dns.query`."""

import importlib
import json

import pytest

PACKAGE = "shadetree_ai_plugins_email_domain_reputation"
blocklists = importlib.import_module(f"{PACKAGE}.blocklists")
_dns = importlib.import_module(f"{PACKAGE}._dns")

# Official test entries answering as listed -> the resolver reaches the lists.
WORKING_CANARIES = {
    ("dbltest.com.dbl.spamhaus.org", "A"): [("A", "127.0.1.2")],
    ("2.0.0.127.zen.spamhaus.org", "A"): [("A", "127.0.0.2"), ("A", "127.0.0.10")],
    ("test.uribl.com.multi.uribl.com", "A"): [("A", "127.0.0.14")],
    ("test.surbl.org.multi.surbl.org", "A"): [("A", "127.0.0.254")],
}

IP = "93.184.216.34"
REV = "34.216.184.93"


def a(*addrs):
    return [("A", x) for x in addrs]


def txt(value):
    return [("TXT", f'"{value}"')]


@pytest.fixture
def dns(monkeypatch):
    """dns(zone, canaries=True) installs a fake `_dns.query` from
    {(name, rtype): [(type, data)] | "STATUS"} (missing key -> NXDOMAIN);
    canaries=True layers WORKING_CANARIES under `zone`. Returns the call log."""
    calls = []

    def install(zone, canaries=True):
        full = {**WORKING_CANARIES, **zone} if canaries else dict(zone)

        def query(name, rtype, *, resolver=None, timeout=6):
            calls.append(name)
            entry = full.get((name.lower(), rtype))
            if entry is None:
                return {"status": "NXDOMAIN", "answers": [], "ad": False}
            if isinstance(entry, str):
                return {"status": entry, "answers": [], "ad": False}
            answers = [{"name": name, "type": t, "ttl": 300, "data": d} for t, d in entry]
            return {"status": "NOERROR", "answers": answers, "ad": False}

        monkeypatch.setattr(_dns, "query", query)
        return calls

    return install


def domain_result(dns, zone, domain="example.com"):
    dns(zone)
    return blocklists.check_domains([domain])[domain]


# ------------------------------------------------------------ domain lists

def test_not_listed_on_nxdomain(dns):
    result = domain_result(dns, {})
    for key in ("spamhaus_dbl", "surbl", "uribl"):
        assert result[key] == {"listed": False, "status": "not_listed", "codes": []}


def test_dbl_listing_decoded(dns):
    dbl = domain_result(
        dns, {("example.com.dbl.spamhaus.org", "A"): a("127.0.1.2", "127.0.1.104")}
    )["spamhaus_dbl"]
    assert dbl["listed"] is True
    assert [c["meaning"] for c in dbl["codes"]] == ["spam domain", "abused legit phish"]


@pytest.mark.parametrize("code", ["127.255.255.254", "127.0.1.255"])
def test_dbl_sentinels_are_refused_not_listed(dns, code):
    dbl = domain_result(dns, {("example.com.dbl.spamhaus.org", "A"): a(code)})["spamhaus_dbl"]
    assert dbl["listed"] is None
    assert dbl["status"] == "query_refused"
    assert dbl["codes"][0]["meaning"].startswith("query refused")


def test_uribl_bitmask_and_refused(dns):
    listed = domain_result(dns, {("example.com.multi.uribl.com", "A"): a("127.0.0.14")})["uribl"]
    assert listed["listed"] is True
    assert [c["meaning"] for c in listed["codes"]] == ["black", "grey", "red"]
    assert [c["bit"] for c in listed["codes"]] == [2, 4, 8]
    refused = domain_result(dns, {("example.com.multi.uribl.com", "A"): a("127.0.0.1")})["uribl"]
    assert refused["status"] == "query_refused"
    assert refused["listed"] is None


def test_surbl_bitmask_and_refused(dns):
    listed = domain_result(dns, {("example.com.multi.surbl.org", "A"): a("127.0.0.88")})["surbl"]
    assert listed["listed"] is True
    assert [c["meaning"] for c in listed["codes"]] == [
        "phishing (PH)", "malware (MW)", "abuse (ABUSE)"]
    refused = domain_result(dns, {("example.com.multi.surbl.org", "A"): a("127.0.0.1")})["surbl"]
    assert refused["status"] == "query_refused"


def test_lookup_failure_is_unknown(dns):
    result = domain_result(dns, {("example.com.multi.surbl.org", "A"): "SERVFAIL"})["surbl"]
    assert result["listed"] is None
    assert result["status"] == "lookup_failed"
    assert result["codes"][0]["meaning"] == "SERVFAIL"


def test_non_loopback_answer_is_unexpected(dns):
    result = domain_result(dns, {("example.com.multi.uribl.com", "A"): a("198.51.100.1")})["uribl"]
    assert result["listed"] is None
    assert result["status"] == "unexpected_answer"


# ---------------------------------------------------------------- IP lists

def test_zen_codes_and_simple_lists(dns):
    dns({
        (f"{REV}.zen.spamhaus.org", "A"): a("127.0.0.4", "127.0.0.10"),
        (f"{REV}.b.barracudacentral.org", "A"): a("127.0.0.2"),
        (f"{REV}.bl.spamcop.net", "A"): "TIMEOUT",
    })
    result = blocklists.check_ip_lists(IP)
    assert result["spamhaus_zen"]["listed"] is True
    assert [c["meaning"] for c in result["spamhaus_zen"]["codes"]] == [
        "XBL - exploited/compromised host", "PBL - end-user range (ISP maintained)"]
    assert result["barracuda"]["status"] == "listed"
    assert result["spamcop"]["status"] == "lookup_failed"
    assert result["psbl"]["status"] == "not_listed"


@pytest.mark.parametrize("code", ["127.255.255.252", "127.255.255.254", "127.255.255.255"])
def test_zen_refused_sentinels(dns, code):
    dns({(f"{REV}.zen.spamhaus.org", "A"): a(code)})
    zen = blocklists.check_ip_lists(IP)["spamhaus_zen"]
    assert zen["status"] == "query_refused"
    assert zen["listed"] is None


def test_ipv6_nibble_format_and_skips_v4_only_lists(dns):
    ip = "2001:db8::1"
    nibbles = "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2"
    assert blocklists.reversed_ip(ip) == nibbles
    dns({(f"{nibbles}.zen.spamhaus.org", "A"): a("127.0.0.3")})
    result = blocklists.check_ip_lists(ip)
    assert result["spamhaus_zen"]["listed"] is True
    for key in ("barracuda", "spamcop", "psbl"):
        assert result[key]["status"] == "skipped"
        assert result[key]["listed"] is None


def test_ipv4_reversal():
    assert blocklists.reversed_ip(IP) == REV


# ------------------------------------------------------------ PTR / FCrDNS

def test_fcrdns_true(dns):
    dns({(f"{REV}.in-addr.arpa", "PTR"): [("PTR", "mail.example.com.")],
         ("mail.example.com", "A"): a(IP)})
    info, err = blocklists.check_ptr(IP)
    assert err is None
    assert info == {"ptr": "mail.example.com", "fcrdns": True, "ptr_looks_generic": False}


def test_fcrdns_false_when_forward_mismatch_or_no_ptr(dns):
    dns({(f"{REV}.in-addr.arpa", "PTR"): [("PTR", "mail.example.com.")],
         ("mail.example.com", "A"): a("198.51.100.9")})
    assert blocklists.check_ptr(IP)[0]["fcrdns"] is False
    dns({})
    info, _ = blocklists.check_ptr(IP)
    assert info == {"ptr": None, "fcrdns": False, "ptr_looks_generic": None}


def test_ptr_failure_is_unknown(dns):
    dns({(f"{REV}.in-addr.arpa", "PTR"): "SERVFAIL"})
    info, err = blocklists.check_ptr(IP)
    assert info["fcrdns"] is None
    assert "SERVFAIL" in err


def test_forward_lookup_failure_leaves_fcrdns_unknown(dns):
    dns({(f"{REV}.in-addr.arpa", "PTR"): [("PTR", "mail.example.com.")],
         ("mail.example.com", "A"): "TIMEOUT"})
    info, err = blocklists.check_ptr(IP)
    assert info["ptr"] == "mail.example.com"
    assert info["fcrdns"] is None
    assert "TIMEOUT" in err


def test_ipv6_ptr_uses_ip6_arpa_and_aaaa(dns):
    ip = "2001:db8::1"
    nibbles = blocklists.reversed_ip(ip)
    dns({(f"{nibbles}.ip6.arpa", "PTR"): [("PTR", "mx.example.com.")],
         ("mx.example.com", "AAAA"): [("AAAA", "2001:db8:0::1")]})
    assert blocklists.check_ptr(ip)[0]["fcrdns"] is True


def test_generic_ptr_heuristic():
    generic = blocklists.ptr_looks_generic
    assert generic("93-184-216-34.isp.example.net", IP) is True
    assert generic("34.216.184.93.static.example.net", IP) is True
    assert generic("host.dynamic.isp.example", IP) is True
    assert generic("c-1.hsd1.cable.example.net", IP) is True
    assert generic("mail.example.com", IP) is False
    assert generic(None, IP) is None


# ------------------------------------------------------------ IP discovery

SPF = ("v=spf1 ip4:93.184.216.34 ip4:198.51.100.0/24 ip4:192.168.1.10 ip4:198.51.100.7/32 "
       "ip6:2001:db8::/32 a mx:mail.example.com include:_spf.google.com -all")
SPF_ZONE = {
    ("example.com", "TXT"): txt(SPF),
    ("example.com", "A"): a("192.0.2.80"),
    ("mail.example.com", "MX"): [("MX", "10 mx1.example.com.")],
    ("mx1.example.com", "A"): a("192.0.2.25", "93.184.216.34"),
}


def test_discovers_single_hosts_and_skips_ranges(dns):
    calls = dns(SPF_ZONE)
    errors = {}
    candidates, ranges = blocklists.discover_spf_ips("example.com", None, errors)
    assert candidates == [
        ("93.184.216.34", "spf_ip4"), ("192.168.1.10", "spf_ip4"), ("198.51.100.7", "spf_ip4"),
        ("192.0.2.80", "spf_a"), ("192.0.2.25", "spf_mx"), ("93.184.216.34", "spf_mx"),
    ]
    assert ranges == [{"range": "198.51.100.0/24", "source": "spf_ip4"},
                      {"range": "2001:db8::/32", "source": "spf_ip6"}]
    assert errors == {}
    assert "_spf.google.com" not in calls  # include: is not expanded


def test_select_skips_private_dedupes_and_caps():
    selected, skipped = blocklists.select_ips(
        [("93.184.216.34", "argument"), ("93.184.216.34", "spf_ip4"), ("10.0.0.1", "spf_ip4")])
    assert selected == [{"ip": "93.184.216.34", "source": "argument"}]
    assert skipped == [{"ip": "10.0.0.1", "source": "spf_ip4", "reason": "private_or_reserved"}]
    many = [(f"93.184.216.{n}", "spf_ip4") for n in range(1, 30)]
    selected, skipped = blocklists.select_ips(many)
    assert len(selected) == blocklists.MAX_IPS
    assert all(s["reason"] == "cap_reached" for s in skipped)


def test_spf_lookup_failure_reported(dns):
    dns({("example.com", "TXT"): "SERVFAIL"})
    errors = {}
    assert blocklists.discover_spf_ips("example.com", None, errors) == ([], [])
    assert "SERVFAIL" in errors["auto_ips"]


# ------------------------------------------------------------------ output

def test_build_output_shape_and_resolver_note(dns):
    dns({
        ("mail.example.com", "TXT"): txt("v=spf1 ip4:93.184.216.34 include:_spf.google.com -all"),
        ("example.com.dbl.spamhaus.org", "A"): a("127.255.255.254"),
    })
    out = blocklists.build_output("mail.example.com")
    assert set(out) == {"domain", "org_domain", "resolver", "resolver_canaries",
                        "domain_listings", "ips", "skipped_ranges", "skipped_ips",
                        "resolver_note", "errors"}
    assert out["domain"] == "mail.example.com"
    assert out["org_domain"] == "example.com"
    assert list(out["domain_listings"]) == ["mail.example.com", "example.com"]
    assert [ip["ip"] for ip in out["ips"]] == ["93.184.216.34"]
    assert out["ips"][0]["source"] == "spf_ip4"
    assert out["resolver_note"] is not None
    assert "_spf.google.com" not in json.dumps(out["ips"])


def test_email_target_uses_its_domain(dns):
    dns({})
    out = blocklists.build_output("Someone@Example.com", auto_ips=False)
    assert out["domain"] == "example.com"


def test_no_auto_ips_and_no_refusal_means_no_note(dns):
    dns({})
    out = blocklists.build_output("example.com", ["93.184.216.35"], auto_ips=False)
    assert out["ips"][0]["source"] == "argument"
    assert list(out["domain_listings"]) == ["example.com"]
    assert out["resolver_note"] is None


def test_public_resolver_nxdomain_is_unreliable_for_spamhaus_uribl_surbl(dns):
    dns({(f"{REV}.b.barracudacentral.org", "A"): a("127.0.0.2")})
    out = blocklists.build_output("example.com", [IP], resolver="1.1.1.1", auto_ips=False)
    for key in ("spamhaus_dbl", "surbl", "uribl"):
        listing = out["domain_listings"]["example.com"][key]
        assert listing["listed"] is None, key
        assert listing["status"] == "unreliable_resolver", key
    ip_listings = out["ips"][0]["listings"]
    assert ip_listings["spamhaus_zen"]["status"] == "unreliable_resolver"
    assert ip_listings["barracuda"]["status"] == "listed"
    for key in ("spamcop", "psbl"):
        assert ip_listings[key] == {"listed": False, "status": "not_listed", "codes": []}


def test_public_resolver_real_listing_still_listed(dns):
    dns({("example.com.dbl.spamhaus.org", "A"): a("127.0.1.2")})
    result = blocklists.check_domains(["example.com"], resolver="8.8.8.8")["example.com"]
    assert result["spamhaus_dbl"]["listed"] is True
    assert result["uribl"]["status"] == "unreliable_resolver"


def test_extra_ips_accept_source_pairs(dns):
    dns({})
    out = blocklists.build_output(
        "example.com", ["93.184.216.35", ("93.184.216.36", "headers")], auto_ips=False)
    assert [(i["ip"], i["source"]) for i in out["ips"]] == [
        ("93.184.216.35", "argument"), ("93.184.216.36", "headers")]


def test_public_resolver_always_gets_note(dns):
    dns({})
    out = blocklists.build_output("example.com", resolver="8.8.8.8", auto_ips=False)
    assert out["resolver"] == "8.8.8.8"
    assert out["resolver_note"] is not None


def test_working_canaries_reported_ok_and_no_note(dns):
    dns({})
    out = blocklists.build_output("example.com", auto_ips=False)
    assert out["resolver"] == "system"
    assert out["resolver_canaries"] == {k: "ok" for k in blocklists.CANARIES}
    assert out["domain_listings"]["example.com"]["uribl"]["status"] == "not_listed"
    assert out["resolver_note"] is None


def test_failed_canary_makes_that_zone_unreliable_on_system_resolver(dns):
    dns({
        **WORKING_CANARIES,
        # DBL canary missing (forwarded to a public resolver), SURBL refused, ZEN SERVFAIL.
        ("dbltest.com.dbl.spamhaus.org", "A"): [],
        ("test.surbl.org.multi.surbl.org", "A"): a("127.0.0.1"),
        ("2.0.0.127.zen.spamhaus.org", "A"): "SERVFAIL",
    }, canaries=False)
    out = blocklists.build_output("example.com", [IP], auto_ips=False)
    assert out["resolver_canaries"] == {
        "spamhaus_dbl": "no_answer", "spamhaus_zen": "lookup_failed",
        "uribl": "ok", "surbl": "refused"}
    listings = out["domain_listings"]["example.com"]
    for key in ("spamhaus_dbl", "surbl"):
        assert listings[key]["status"] == "unreliable_resolver", key
        assert listings[key]["listed"] is None, key
    assert listings["uribl"]["status"] == "not_listed"
    ip_listings = out["ips"][0]["listings"]
    assert ip_listings["spamhaus_zen"]["status"] == "unreliable_resolver"
    for key in ("barracuda", "spamcop", "psbl"):
        assert ip_listings[key]["status"] == "not_listed", key
    assert "spamhaus_dbl" in out["resolver_note"]
    assert "canary" in out["resolver_note"]


def test_failed_canary_does_not_hide_a_real_listing(dns):
    dns({("example.com.dbl.spamhaus.org", "A"): a("127.0.1.2")}, canaries=False)
    out = blocklists.build_output("example.com", auto_ips=False)
    assert out["resolver_canaries"]["spamhaus_dbl"] == "no_answer"
    assert out["domain_listings"]["example.com"]["spamhaus_dbl"]["listed"] is True


def test_canaries_queried_once_per_run(dns):
    calls = dns({})
    blocklists.build_output("mail.example.com", [IP, "93.184.216.35"], auto_ips=False)
    for canary in blocklists.CANARIES.values():
        assert calls.count(canary) == 1, canary


# ------------------------------------------------------------ validation

@pytest.mark.parametrize("target", ["not a domain", "", "https://example.com/x", "1.2.3.4"])
def test_invalid_target_raises(dns, target):
    calls = dns({})
    with pytest.raises(ValueError):
        blocklists.build_output(target)
    assert calls == []


@pytest.mark.parametrize("ips", [["999.1.1.1"], ["example.com"], [42]])
def test_invalid_ip_raises(dns, ips):
    calls = dns({})
    with pytest.raises(ValueError):
        blocklists.build_output("example.com", ips)
    assert calls == []


def test_too_many_ips_raises(dns):
    dns({})
    with pytest.raises(ValueError):
        blocklists.build_output("example.com", [f"93.184.216.{n}" for n in range(1, 22)])


def test_invalid_resolver_raises(dns):
    dns({})
    with pytest.raises(ValueError):
        blocklists.build_output("example.com", resolver="resolver.example")


def test_discovery_bounds_host_mechanisms_mx_hosts_and_candidates(dns):
    mx_hosts = [("MX", f"10 mx{n}.example.com.") for n in range(15)]
    zone = {("example.com", "TXT"): txt(
                "v=spf1 " + " ".join(f"a:h{n}.example.com" for n in range(15)) + " -all"),
            ("mail.example.com", "MX"): mx_hosts}
    zone.update({(f"h{n}.example.com", "A"): a(f"93.184.216.{n + 1}") for n in range(15)})
    calls = dns(zone)
    candidates, _ = blocklists.discover_spf_ips("example.com", None, {})
    assert len(candidates) == blocklists.MAX_HOST_MECHANISMS
    assert not any(f"h{n}.example.com" in calls for n in range(10, 15))

    many_ips = {(f"mx{n}.example.com", "A"): a(*(f"93.184.{n}.{k}" for k in range(1, 4)))
                for n in range(15)}
    calls = dns({("example.com", "TXT"): txt("v=spf1 mx:mail.example.com -all"),
                 ("mail.example.com", "MX"): mx_hosts, **many_ips})
    candidates, _ = blocklists.discover_spf_ips("example.com", None, {})
    assert blocklists.MAX_IPS <= len(candidates) < blocklists.MAX_IPS + 3
    assert "mx7.example.com" not in calls  # stopped once MAX_IPS candidates were found

    calls = dns({("example.com", "TXT"): txt("v=spf1 mx:mail.example.com -all"),
                 ("mail.example.com", "MX"): mx_hosts})
    blocklists.discover_spf_ips("example.com", None, {})
    assert "mx9.example.com" in calls and "mx10.example.com" not in calls


def test_discovery_truncation_is_reported(dns):
    mx_hosts = [("MX", f"10 mx{n}.example.com.") for n in range(12)]
    dns({("example.com", "TXT"): txt(
            "v=spf1 mx:mail.example.com "
            + " ".join(f"a:h{n}.example.com" for n in range(12)) + " -all"),
         ("mail.example.com", "MX"): mx_hosts})
    errors = {}
    blocklists.discover_spf_ips("example.com", None, errors)
    assert "stopped at 10 of 13 a/mx mechanisms" in errors["auto_ips"]
    assert "stopped at 10 of 12 MX hosts for mx:mail.example.com" in errors["auto_ips"]

    dns({("example.com", "TXT"): txt("v=spf1 a:h0.example.com a:h1.example.com -all"),
         ("h0.example.com", "A"): a(*(f"93.184.216.{k}" for k in range(1, 22)))})
    errors = {}
    blocklists.discover_spf_ips("example.com", None, errors)
    assert "stopped at 20 candidate IPs before a/mx mechanism 2" in errors["auto_ips"]


def test_untruncated_discovery_has_no_note(dns):
    dns(SPF_ZONE)
    errors = {}
    blocklists.discover_spf_ips("example.com", None, errors)
    assert "auto_ips" not in errors
