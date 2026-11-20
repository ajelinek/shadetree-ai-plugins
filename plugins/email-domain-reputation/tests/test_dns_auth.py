"""Tests for dns_auth. No real DNS: lookups are mocked at `_dns.query`."""

import http.client
import importlib

import pytest

PACKAGE = "shadetree_ai_plugins_email_domain_reputation"
dns_auth = importlib.import_module(f"{PACKAGE}.dns_auth")
_dns = importlib.import_module(f"{PACKAGE}._dns")

# Real RSA public keys (SubjectPublicKeyInfo, base64 DER) generated with openssl.
RSA_1024 = (
    "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCya1kVDVguL2MhMCR+g+YqzGmvkFbr3jKhBziHk5YRAnuGcm8Mdl25"
    "Xm3d/qWj0/GpMwkKPXx99yxwZpVGKa6uNMPg+9FzRnnjJsMFV/r4Ti9f3S90zBOshhzL89qJ+vuEsn+sYZOGshNqc+/G"
    "tUsEVuSsi7azqZ0WaTIel5fq5QIDAQAB"
)
RSA_2048 = (
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqT2TD8H064QHjLiuiMfxc4JpBBHtxlBzk097hPgRpffb1Gck"
    "YLRyve+uAvTaArBQcShPfqjGPynfL+SaYiyha+l6WBpH2aQXzxoXBLP5jdco4YpuR3CHTSmBsr6iLc753XFlmGAtQA+1"
    "NsjlYe/Qp9F4BD1ry9dlu2208ojCE0yjzPShwECkMFSWgmpZ6A2T76gNgytsahmnfZtSqU9pAm7TO3C7s3cj+uVSpy2Y"
    "JUtr6pwTSROFEzcrFLQEtmAQvYpcHkeFczAOshclYcN2gI8pMic9iFUDBoUFDkO4tZLSalCJctu04stxJg94C/Hm7//k"
    "cjpPFOmEoYImQ8bXiwIDAQAB"
)
MTA_STS_POLICY = (
    "version: STSv1\nmode: enforce\nmx: *.mail.example.com\nmx: backup.example.net\n"
    "max_age: 604800\n"
)


def txt(value):
    return ("TXT", f'"{value}"')


@pytest.fixture
def zone(monkeypatch):
    """Install a fake `_dns.query` from {(name, rtype): answers | status}.

    answers is a list of (type, data) tuples; a string value is a failure
    status (e.g. "SERVFAIL"); a missing key is NXDOMAIN. Returns the call log.
    """
    calls = []

    def install(entries):
        def query(name, rtype, *, resolver=None, timeout=6):
            calls.append((name, rtype, resolver))
            entry = entries.get((name.lower(), rtype))
            if entry is None:
                return {"status": "NXDOMAIN", "answers": [], "ad": False}
            if isinstance(entry, str):
                return {"status": entry, "answers": [], "ad": False}
            answers = [{"name": name, "type": t, "ttl": 300, "data": d} for t, d in entry]
            return {"status": "NOERROR", "answers": answers, "ad": False}
        monkeypatch.setattr(_dns, "query", query)
        return calls
    return install


def policy_fetch(monkeypatch, body=MTA_STS_POLICY, content_type="text/plain", error=None):
    def fetch(url):
        if error:
            raise error
        return body, content_type
    monkeypatch.setattr(dns_auth, "_http_get_text", fetch)


# ------------------------------------------------------------------- MX

def test_null_mx(zone):
    zone({("example.com", "MX"): [("MX", "0 .")]})
    mx = dns_auth.parse_mx(dns_auth.fetch_mx("example.com"))
    assert mx["null_mx"] is True
    assert mx["found"] is False
    assert mx["accepts_mail"] is False
    assert mx["provider"] is None


def test_provider_and_gateway_detection():
    mx = dns_auth.parse_mx([
        {"preference": 10, "exchange": "us-smtp-inbound-1.mimecast.com"},
        {"preference": 20, "exchange": "example-com.mail.protection.outlook.com"},
    ])
    assert mx["provider"] == "mimecast"
    assert mx["security_gateway"] == "mimecast"
    assert "microsoft365" in mx["providers_detected"]
    google = dns_auth.parse_mx([{"preference": 1, "exchange": "aspmx.l.google.com"}])
    assert google["provider"] == "google"
    assert google["security_gateway"] is None


def test_unicode_digit_mx_preference_is_skipped(zone):
    zone({("example.com", "MX"): [("MX", "² mx.example.com.")]})
    assert dns_auth.fetch_mx("example.com") == []


# ------------------------------------------------------------------ SPF

@pytest.mark.parametrize("record,strict", [
    ("v=spf1 include:_spf.google.com -all", True),
    ("v=spf1 ~all", False), ("v=spf1 +all", False),
    ("v=spf1 redirect=example.com", False),
])
def test_spf_preserves_terminal_qualifier(record, strict):
    assert dns_auth.parse_spf([record])["strict"] is strict


def test_multiple_spf_records_cannot_be_strict(zone):
    zone({})
    assert dns_auth.parse_spf(["v=spf1 -all", "v=spf1 -all"])["strict"] is False
    spf, _ = dns_auth.evaluate_spf("example.com", ["v=spf1 -all", "v=spf1 -all"])
    assert spf["multiple_records"] is True
    assert spf["strict"] is False
    assert spf["effective_strict"] is False
    assert spf["permerrors"][0] == "multiple SPF records"


def test_spf_top_level_facts():
    result = dns_auth.parse_spf(["v=spf1 ip4:203.0.113.5 ip6:2001:db8::/32 mx +all"])
    assert result["plus_all"] is True
    assert result["strict"] is False
    assert result["direct_ips"] == ["ip4:203.0.113.5", "ip6:2001:db8::/32"]
    assert result["has_a_or_mx_mechanism"] is True


def test_direct_ip_terms_keep_qualifier():
    result = dns_auth.parse_spf(
        ["v=spf1 ip4:203.0.113.5/32 -ip4:198.51.100.0/24 ~ip6:2001:db8::1 -all"])
    assert result["direct_ip_terms"] == [
        {"qualifier": "+", "value": "203.0.113.5/32"},
        {"qualifier": "-", "value": "198.51.100.0/24"},
        {"qualifier": "~", "value": "2001:db8::1"},
    ]
    assert result["direct_ips"][1] == "ip4:198.51.100.0/24"


def test_nested_include_lookup_counting(zone):
    zone({
        ("example.com", "MX"): [("MX", "10 mail.example.com.")],
        ("a.example.net", "TXT"): [txt("v=spf1 include:b.example.net a -all")],
        ("a.example.net", "A"): [("A", "192.0.2.1")],
        ("b.example.net", "TXT"): [txt("v=spf1 ip4:192.0.2.0/24 ptr -all")],
    })
    spf, errs = dns_auth.evaluate_spf("example.com", ["v=spf1 include:a.example.net mx -all"])
    # include:a + mx + (in a) include:b + a + (in b) ptr = 5
    assert spf["dns_lookup_count"] == 5
    assert spf["has_ptr"] is True
    assert [i["domain"] for i in spf["includes"]] == ["a.example.net", "b.example.net"]
    assert spf["permerrors"] == []
    assert errs == []


def test_lookup_limit_exceeded(zone):
    zone({(f"i{n}.example.net", "TXT"): [txt("v=spf1 -all")] for n in range(11)})
    record = "v=spf1 " + " ".join(f"include:i{n}.example.net" for n in range(11)) + " -all"
    spf, _ = dns_auth.evaluate_spf("example.com", [record])
    assert spf["dns_lookup_count"] == 11
    assert spf["lookup_limit_exceeded"] is True
    assert any("limit exceeded" in p for p in spf["permerrors"])


def test_include_loop_is_detected(zone):
    zone({
        ("a.example.net", "TXT"): [txt("v=spf1 include:b.example.net -all")],
        ("b.example.net", "TXT"): [txt("v=spf1 include:a.example.net -all")],
    })
    spf, _ = dns_auth.evaluate_spf("example.com", ["v=spf1 include:a.example.net -all"])
    assert spf["includes"][-1]["status"] == "loop"
    assert any("loop" in p for p in spf["permerrors"])


def test_void_lookups_and_missing_include(zone):
    zone({})
    spf, _ = dns_auth.evaluate_spf(
        "example.com",
        ["v=spf1 include:gone.example.net a:old.example.com exists:x.example.com -all"])
    assert spf["void_lookup_count"] == 3
    assert spf["void_limit_exceeded"] is True
    assert spf["includes"][0]["status"] == "no_spf_record"
    assert any("has no SPF record" in p for p in spf["permerrors"])


def test_unknown_mechanism_is_permerror(zone):
    zone({})
    spf, _ = dns_auth.evaluate_spf("example.com", ["v=spf1 ipv4:1.2.3.4 -all"])
    assert any("unknown mechanism" in p for p in spf["permerrors"])


def test_provider_include_missing_and_present(zone):
    zone({("_spf.google.com", "TXT"): [txt("v=spf1 ip4:192.0.2.0/24 ~all")],
          ("vendor.example.net", "TXT"): [txt("v=spf1 include:_spf.google.com -all")]})
    missing, _ = dns_auth.evaluate_spf(
        "example.com", ["v=spf1 ip4:203.0.113.5 -all"], provider="microsoft365")
    nested, _ = dns_auth.evaluate_spf(
        "example.com", ["v=spf1 include:vendor.example.net -all"], provider="google")
    assert missing["expected_provider_include"] == "spf.protection.outlook.com"
    assert missing["provider_include_present"] is False
    assert nested["provider_include_present"] is True


def test_nested_servfail_reported_as_lookup_error(zone):
    zone({("a.example.net", "TXT"): "SERVFAIL"})
    spf, errs = dns_auth.evaluate_spf("example.com", ["v=spf1 include:a.example.net -all"])
    assert spf["includes"][0]["status"] == "lookup_failed"
    assert errs == ["TXT a.example.net: SERVFAIL"]
    assert spf["lookup_count_is_minimum"] is True


def test_lookup_count_exact_without_failures(zone):
    zone({("a.example.net", "TXT"): [txt("v=spf1 -all")]})
    spf, _ = dns_auth.evaluate_spf("example.com", ["v=spf1 include:a.example.net -all"])
    assert spf["lookup_count_is_minimum"] is False


def test_redirect_only_record_uses_redirect_target_all(zone):
    zone({("_spf.example.com", "TXT"): [txt("v=spf1 redirect=_spf2.example.com")],
          ("_spf2.example.com", "TXT"): [txt("v=spf1 ip4:192.0.2.0/24 -all")]})
    spf, _ = dns_auth.evaluate_spf("example.com", ["v=spf1 redirect=_spf.example.com"])
    assert spf["all_mechanism"] is None
    assert spf["strict"] is False
    assert spf["effective_all_mechanism"] == "-all"
    assert spf["effective_strict"] is True


def test_effective_all_top_level_and_unresolved_redirect(zone):
    zone({})
    top, _ = dns_auth.evaluate_spf("example.com", ["v=spf1 ip4:192.0.2.1 ~all"])
    assert top["effective_all_mechanism"] == "~all"
    assert top["effective_strict"] is False
    zone({("_spf.example.com", "TXT"): "SERVFAIL"})
    failed, _ = dns_auth.evaluate_spf("example.com", ["v=spf1 redirect=_spf.example.com"])
    assert failed["effective_all_mechanism"] is None
    assert failed["effective_strict"] is None


def test_mx_mechanism_with_more_than_ten_mx_is_permerror(zone):
    many = [("MX", f"10 mx{n}.example.com.") for n in range(11)]
    zone({("example.com", "MX"): many})
    spf, _ = dns_auth.evaluate_spf("example.com", ["v=spf1 mx -all"])
    assert any("11 MX records" in p for p in spf["permerrors"])
    zone({("example.com", "MX"): many[:10]})
    ok, _ = dns_auth.evaluate_spf("example.com", ["v=spf1 mx -all"])
    assert ok["permerrors"] == []


# ---------------------------------------------------------------- DMARC

@pytest.mark.parametrize("records,enforced", [
    (["v=DMARC1; p=reject"], True),
    (["v=DMARC1; p=quarantine; pct=100"], True),
    (["v=DMARC1; p=none"], False),
    (["v=DMARC1; p=reject; pct=50"], False),
    (["v=DMARC1; p=reject; pct=bogus"], False),
    (["v=DMARC1; p=reject; pct=101"], False),
    (["v=DMARC1; p=reject; p=none"], False),
    (["v=DMARC1; p=reject", "v=DMARC1; p=reject"], False),
    (["v=DMARC1; p=reject; sp=bogus"], False),
    ([], False),
])
def test_dmarc_does_not_turn_invalid_or_partial_policy_into_enforcement(records, enforced):
    assert dns_auth.parse_dmarc(records)["enforced"] is enforced


def test_dmarc_invalid_records_are_flagged():
    assert dns_auth.parse_dmarc(["v=DMARC1; p=reject"])["record_valid"] is True
    for record in ("v=DMARC1; p=reject; p=none", "v=DMARC1; p=reject; pct=101",
                   "v=DMARC1; p=reject; garbage"):
        assert dns_auth.parse_dmarc([record])["record_valid"] is False, record
    assert dns_auth.parse_dmarc(["v=DMARC1; p=reject; pct=bogus"])["pct"] is None


def test_dmarc_parses_alignment_and_reporting_tags():
    result = dns_auth.parse_dmarc(
        ["v=DMARC1; p=reject; adkim=s; rua=mailto:d@example.com; ruf=mailto:f@example.com; fo=1"])
    assert result["enforced"] is True
    assert result["adkim"] == "s"
    assert result["aspf"] == "r"
    assert result["ruf"] == ["mailto:f@example.com"]
    assert result["has_rua"] is True
    assert result["policy_valid"] is True
    assert result["fo"] == "1"


def test_dmarc_missing_or_invalid_policy():
    assert dns_auth.parse_dmarc(["v=DMARC1; rua=mailto:a@b.com"])["policy_valid"] is False
    assert dns_auth.parse_dmarc(["v=DMARC1; p=block"])["policy_valid"] is False


def test_dmarc_inherits_from_org_domain_via_sp(zone):
    zone({("_dmarc.example.com", "TXT"): [txt("v=DMARC1; p=reject; sp=none")]})
    errors = {}
    result = dns_auth.build_dmarc("mail.example.com", errors)
    assert result["inherited_from"] == "example.com"
    assert result["effective_policy"] == "none"
    assert result["enforced"] is False
    assert errors == {}


def test_dmarc_external_rua_authorization(zone):
    zone({
        ("_dmarc.example.com", "TXT"): [txt(
            "v=DMARC1; p=none; rua=mailto:r@reports.vendor.net!10m,mailto:x@other.org,"
            "mailto:me@example.com")],
        ("example.com._report._dmarc.reports.vendor.net", "TXT"): [txt("v=DMARC1")],
    })
    result = dns_auth.build_dmarc("example.com", {})
    assert result["rua_external_authorization"] == {"reports.vendor.net": True,
                                                    "other.org": False}


def test_dmarc_external_authorization_failure_is_unknown(zone):
    zone({
        ("_dmarc.example.com", "TXT"): [txt("v=DMARC1; p=none; rua=mailto:r@failing.example")],
        ("example.com._report._dmarc.failing.example", "TXT"): "SERVFAIL",
    })
    errors = {}
    result = dns_auth.build_dmarc("example.com", errors)
    assert result["rua_external_authorization"] == {"failing.example": None}
    assert "external report authorization" in errors["dmarc"]


def test_dmarcbis_tags_and_test_mode_not_enforced():
    result = dns_auth.parse_dmarc(["v=DMARC1; p=reject; t=y; np=reject; psd=n"])
    assert result["testing"] is True
    assert result["np"] == "reject"
    assert result["psd"] == "n"
    assert result["enforced"] is False
    plain = dns_auth.parse_dmarc(["v=DMARC1; p=reject; t=n"])
    assert plain["testing"] is False
    assert plain["enforced"] is True
    assert plain["np"] is None


@pytest.mark.parametrize("domain,needle", [("mail.example.com", "org-domain fallback"),
                                           ("example.com", "SERVFAIL")])
def test_dmarc_lookup_failure_is_unknown_not_missing(zone, domain, needle):
    zone({("_dmarc.example.com", "TXT"): "SERVFAIL"})
    errors = {}
    result = dns_auth.build_dmarc(domain, errors)
    for key in ("found", "has_rua", "enforced", "policy_valid", "record_valid",
                "effective_policy"):
        assert result[key] is None, key
    assert needle in errors["dmarc"]


def test_unicode_digit_pct_is_invalid_not_default():
    # A \178 TXT escape unescapes to U+00B2, which str.isdigit() accepts but int() rejects.
    result = dns_auth.parse_dmarc(["v=DMARC1; p=reject; pct=²"])
    assert result["pct"] is None
    assert result["enforced"] is False


# ----------------------------------------------------------------- DKIM

def test_rsa_key_bits_for_real_keys():
    assert dns_auth.rsa_key_bits(RSA_1024) == 1024
    assert dns_auth.rsa_key_bits(RSA_2048) == 2048
    assert dns_auth.rsa_key_bits("not-base64!") is None


def test_dkim_selector_variants(zone):
    zone({
        ("google._domainkey.example.com", "TXT"): [txt(f"v=DKIM1; k=rsa; t=y; p={RSA_2048}")],
        ("old._domainkey.example.com", "TXT"): [txt("v=DKIM1; p=")],
        ("selector1._domainkey.example.com", "TXT"): [
            ("CNAME", "selector1-example-com._domainkey.example.onmicrosoft.com.")],
        ("selector2._domainkey.example.com", "TXT"): "SERVFAIL",
        ("k1._domainkey.example.com", "TXT"): [txt("v=DKIM1; p=YWJj"), txt("v=DKIM1; p=ZGVm")],
    })
    errors = {}
    dkim = dns_auth.build_dkim("example.com", ["old"], errors)
    found = dkim["selectors_found"]
    assert dkim["selectors_checked"][0] == "old"
    assert found["google"]["key_bits"] == 2048
    assert found["google"]["testing"] is True
    assert found["old"]["revoked"] is True
    assert found["selector1"]["cname_without_key"] is True
    assert found["selector1"]["cname_target"] == (
        "selector1-example-com._domainkey.example.onmicrosoft.com")
    assert found["k1"]["multiple_records"] is True
    assert found["k1"]["has_public_key"] is False
    assert dkim["found"] is True
    assert "selector2: SERVFAIL" in errors["dkim"]
    assert dkim["selectors_failed"] == ["selector2"]


def test_dkim_revoked_and_cname_only_do_not_count_as_found(zone):
    zone({("old._domainkey.example.com", "TXT"): [txt("v=DKIM1; p=")],
          ("selector1._domainkey.example.com", "TXT"): [("CNAME", "x.example.net.")]})
    assert dns_auth.build_dkim("example.com", ["old"], {})["found"] is False


def test_dkim_failures_without_a_hit_are_unknown(zone):
    zone({("google._domainkey.example.com", "TXT"): "TIMEOUT"})
    errors = {}
    dkim = dns_auth.build_dkim("example.com", [], errors)
    assert dkim["found"] is None
    assert dkim["selectors_failed"] == ["google"]
    assert "google: TIMEOUT" in errors["dkim"]


def test_ed25519_key_bits():
    assert dns_auth.parse_dkim_record("v=DKIM1; k=ed25519; p=abc=")["key_bits"] == 256


def test_dkim_segmented_txt_key_is_found(zone):
    zone({("custom._domainkey.example.com", "TXT"): [("TXT", '"v=DKIM1; " "p=YWJj"')]})
    dkim = dns_auth.build_dkim("example.com", ["custom"], {})
    assert dkim["selectors_found"]["custom"]["has_public_key"] is True
    assert "google" in dkim["selectors_checked"]


# -------------------------------------------------------------- MTA-STS

def test_parse_mta_sts_policy():
    assert dns_auth.parse_mta_sts_policy(MTA_STS_POLICY) == {
        "version": "STSv1", "mode": "enforce",
        "mx": ["*.mail.example.com", "backup.example.net"], "max_age": 604800}


def test_mta_sts_wildcard_matches_one_label_only():
    assert dns_auth.mx_matches_pattern("mx1.mail.example.com", "*.mail.example.com")
    assert not dns_auth.mx_matches_pattern("a.b.mail.example.com", "*.mail.example.com")
    assert not dns_auth.mx_matches_pattern("mail.example.com", "*.mail.example.com")


def test_mta_sts_mx_coverage(zone, monkeypatch):
    zone({("_mta-sts.example.com", "TXT"): [txt("v=STSv1; id=2024010101")]})
    policy_fetch(monkeypatch)
    covered = dns_auth.build_mta_sts("example.com", ["mx1.mail.example.com"], {})
    uncovered = dns_auth.build_mta_sts(
        "example.com", ["mx1.mail.example.com", "other.example.org"], {})
    assert covered["id"] == "2024010101"
    assert covered["mx_covered"] is True
    assert uncovered["mx_covered"] is False
    assert covered["policy_valid"] is True
    assert covered["policy_errors"] == []
    assert covered["policy_url"] == "https://mta-sts.example.com/.well-known/mta-sts.txt"


def fetch_policy(zone, monkeypatch, body, content_type="text/plain; charset=utf-8"):
    zone({("_mta-sts.example.com", "TXT"): [txt("v=STSv1; id=1")]})
    policy_fetch(monkeypatch, body, content_type)
    return dns_auth.build_mta_sts("example.com", ["mx1.mail.example.com"], {})


def test_mta_sts_policy_validation_errors(zone, monkeypatch):
    html = fetch_policy(zone, monkeypatch, "<html><body>Welcome</body></html>", "text/html")
    assert html["policy_valid"] is False
    assert any("Content-Type" in e for e in html["policy_errors"])
    assert any("STSv1" in e for e in html["policy_errors"])
    bad = fetch_policy(zone, monkeypatch, "version: STSv1\nmode: strict\nmax_age: 99999999\n")
    joined = " | ".join(bad["policy_errors"])
    assert bad["policy_valid"] is False
    assert "mode is strict" in joined
    assert "exceeds" in joined
    assert "no mx" in joined
    missing_age = fetch_policy(
        zone, monkeypatch, "version: STSv1\nmode: testing\nmx: mx1.mail.example.com\nmax_age: -1\n")
    assert missing_age["policy_errors"] == ["max_age missing or not an integer"]


def test_mta_sts_unicode_digit_max_age_is_not_an_integer():
    policy = dns_auth.parse_mta_sts_policy("version: STSv1\nmode: none\nmax_age: ²\n")
    assert policy["max_age"] is None


def test_mta_sts_mode_none_needs_no_mx(zone, monkeypatch):
    result = fetch_policy(zone, monkeypatch, "version: STSv1\nmode: none\nmax_age: 86400\n")
    assert result["policy_valid"] is True


@pytest.mark.parametrize("error", [http.client.IncompleteRead(b""), OSError("refused")])
def test_mta_sts_fetch_failure_leaves_validity_unknown(zone, monkeypatch, error):
    zone({})
    assert dns_auth.build_mta_sts("example.com", [], {})["policy_valid"] is None
    zone({("_mta-sts.example.com", "TXT"): [txt("v=STSv1; id=1")]})
    policy_fetch(monkeypatch, error=error)
    errors = {}
    result = dns_auth.build_mta_sts("example.com", ["mx.example.com"], errors)
    assert result["found"] is True
    assert result["policy"] is None
    assert result["policy_valid"] is None
    assert "policy fetch failed" in errors["mta_sts"]


def test_mta_sts_fetch_does_not_follow_redirects():
    handler = dns_auth._NoRedirect()
    assert handler.redirect_request(None, None, 301, "Moved", {}, "https://evil.example/") is None


# ---------------------------------------------------------------- output

ZONE = {
    ("example.com", "MX"): [("MX", "1 aspmx.l.google.com.")],
    ("example.com", "TXT"): [txt("google-site-verification=abc"),
                             txt("v=spf1 include:_spf.google.com -all")],
    ("_spf.google.com", "TXT"): [txt("v=spf1 ip4:192.0.2.0/24 ~all")],
    ("_dmarc.example.com", "TXT"): [txt("v=DMARC1; p=reject")],
    ("_smtp._tls.example.com", "TXT"): [txt("v=TLSRPTv1; rua=mailto:tls@example.com")],
    ("default._bimi.example.com", "TXT"): [txt("v=BIMI1; l=https://example.com/logo.svg; a=")],
    ("example.com", "SOA"): [("SOA", "ns1.example.com. host.example.com. 1 2 3 4 5")],
}


def test_build_output_aggregates_all_sections(zone):
    zone(ZONE)
    output = dns_auth.build_output("example.com")
    assert output["resolver"] == "system"
    assert output["mx"]["provider"] == "google"
    assert output["mx"]["accepts_mail"] is True
    assert output["spf"]["strict"] is True
    assert output["spf"]["provider_include_present"] is True
    assert output["dmarc"]["enforced"] is True
    assert output["dkim"]["found"] is False
    assert output["mta_sts"]["found"] is False
    assert output["tls_rpt"]["rua"] == ["mailto:tls@example.com"]
    assert output["bimi"]["logo_url"] == "https://example.com/logo.svg"
    assert output["bimi"]["vmc_url"] is None
    assert output["dnssec"]["ad_flag"] is False
    assert output["errors"] == {}
    assert list(output) == ["domain", "resolver", "mx", "spf", "dmarc", "dkim", "mta_sts",
                            "tls_rpt", "bimi", "dnssec", "errors"]


def test_build_output_failure_is_error_not_missing(zone):
    zone({**ZONE, ("example.com", "MX"): "SERVFAIL", ("example.com", "TXT"): "REFUSED"})
    output = dns_auth.build_output("example.com")
    for key in ("found", "null_mx", "accepts_mail"):
        assert output["mx"][key] is None, key
    for key in ("found", "strict", "plus_all", "effective_strict", "dns_lookup_count"):
        assert output["spf"][key] is None, key
    assert "SERVFAIL" in output["errors"]["mx"]
    assert "REFUSED" in output["errors"]["spf"]
    assert output["dmarc"]["found"] is True


def test_build_output_unexpected_dmarc_error_is_isolated(zone, monkeypatch):
    zone(ZONE)

    def boom(*args, **kwargs):
        raise ValueError("boom")

    monkeypatch.setattr(dns_auth, "fetch_dmarc", boom)
    output = dns_auth.build_output("example.com")
    assert output["dmarc"]["found"] is None
    assert output["dmarc"]["enforced"] is None
    assert "boom" in output["errors"]["dmarc"]
    assert output["spf"]["found"] is True


def test_build_output_passes_explicit_resolver(zone):
    calls = zone({})
    output = dns_auth.build_output("example.com", resolver="192.0.2.53")
    assert output["resolver"] == "192.0.2.53"
    assert calls and all(resolver == "192.0.2.53" for _, _, resolver in calls)


def test_build_output_rejects_invalid_domain_and_resolver_before_dns(zone):
    calls = zone({})
    with pytest.raises(ValueError):
        dns_auth.build_output("not a domain")
    with pytest.raises(ValueError):
        dns_auth.build_output("example.com", resolver="resolver.example.net")
    assert calls == []


# ------------------------------------------------------------ audit_dns

def test_audit_dns_decodes_segmented_txt_and_detects_null_mx(zone):
    zone({
        ("example.com", "MX"): [("MX", "0 .")],
        ("example.com", "TXT"): [("TXT", '"v=spf1 " "-all"')],
        ("_dmarc.example.com", "TXT"): [txt("v=DMARC1; p=reject")],
        ("custom._domainkey.example.com", "TXT"): [("TXT", '"v=DKIM1; " "p=YWJj"')],
    })
    result = dns_auth.audit_dns("person@example.com", selectors=["custom"])
    assert result["domain"] == "example.com"
    assert result["mx"]["null_mx"] is True
    assert result["mx"]["accepts_mail"] is False
    assert result["spf"]["strict"] is True
    assert result["dmarc"]["enforced"] is True
    assert result["dkim"]["selectors_found"]["custom"]["has_public_key"] is True
    assert result["dkim"]["selectors_checked"][0] == "custom"
    assert "google" in result["dkim"]["selectors_checked"]
    assert result["errors"] == {}


def test_audit_dns_failures_are_unknown_and_dkim_errors_survive(zone):
    zone({("example.com", "MX"): "TIMEOUT", ("google._domainkey.example.com", "TXT"): "TIMEOUT"})
    result = dns_auth.audit_dns("example.com")
    assert result["mx"]["found"] is None
    assert result["mx"]["accepts_mail"] is None
    assert result["spf"]["found"] is False
    assert result["dkim"]["found"] is None
    assert "mx" in result["errors"]
    assert "google" in result["dkim"]["selectors_failed"]


def test_absent_mx_is_not_proof_that_mail_cannot_be_received(zone):
    zone({})
    result = dns_auth.audit_dns("example.com")
    assert result["mx"]["found"] is False
    assert result["mx"]["accepts_mail"] is None
    assert result["dmarc"]["found"] is False
    assert result["dmarc"]["inherited_from"] is None


@pytest.mark.parametrize("selectors", [["bad;selector"], ["x."], ["a" * 64], ["x"] * 21])
def test_invalid_or_excessive_selectors_rejected_before_dns(zone, selectors):
    calls = zone({})
    with pytest.raises(ValueError):
        dns_auth.audit_dns("example.com", selectors=selectors)
    assert calls == []


def test_server_imports_are_reexported():
    assert dns_auth.normalize_email("Person@EXAMPLE.com") == "Person@example.com"
    assert dns_auth.domain_from_arg("a@example.com") == "example.com"
    assert dns_auth.validate_selectors(["s1"]) == ["s1"]
    assert dns_auth.is_valid_domain("example.com")
    assert len(dns_auth.COMMON_DKIM_SELECTORS) == 29


# ------------------------------------------------- review regressions (SPF)

def test_wide_deep_include_fanout_stops_at_lookup_limit(zone):
    # 5 includes per level, 10 levels deep: unbounded expansion would issue
    # ~488k queries. Evaluation must stop once the limit is exceeded.
    entries = {}
    for depth in range(10):
        for n in range(5):
            children = " ".join(f"include:d{depth + 1}n{c}.example.net" for c in range(5))
            entries[(f"d{depth}n{n}.example.net", "TXT")] = [txt(f"v=spf1 {children} -all")]
    calls = zone(entries)
    record = "v=spf1 " + " ".join(f"include:d0n{n}.example.net" for n in range(5)) + " -all"
    spf, _ = dns_auth.evaluate_spf("example.com", [record])
    assert spf["dns_lookup_count"] >= 11
    assert spf["lookup_limit_exceeded"] is True
    assert any("lookup limit exceeded" in p for p in spf["permerrors"])
    assert len(calls) <= dns_auth.SPF_LOOKUP_LIMIT


def test_repeated_include_is_queried_once_but_counted_each_time(zone):
    calls = zone({("shared.example.net", "TXT"): [txt("v=spf1 a -all")],
                  ("shared.example.net", "A"): [("A", "192.0.2.1")],
                  ("x.example.net", "TXT"): [txt("v=spf1 include:shared.example.net -all")]})
    spf, _ = dns_auth.evaluate_spf(
        "example.com", ["v=spf1 include:shared.example.net include:x.example.net -all"])
    # include:shared + a + include:x + include:shared + a = 5
    assert spf["dns_lookup_count"] == 5
    assert spf["lookup_limit_exceeded"] is False
    assert [c[:2] for c in calls].count(("shared.example.net", "TXT")) == 1


def test_void_checks_stop_after_void_limit(zone):
    calls = zone({})
    record = "v=spf1 " + " ".join(f"exists:v{n}.example.com" for n in range(8)) + " -all"
    spf, _ = dns_auth.evaluate_spf("example.com", [record])
    assert spf["void_lookup_count"] == dns_auth.SPF_VOID_LIMIT + 1
    assert spf["void_limit_exceeded"] is True
    assert spf["dns_lookup_count"] == 8
    assert len(calls) == dns_auth.SPF_VOID_LIMIT + 1


def test_provider_include_unknown_when_nested_lookup_failed(zone):
    zone({("a.example.net", "TXT"): "SERVFAIL"})
    spf, _ = dns_auth.evaluate_spf(
        "example.com", ["v=spf1 include:a.example.net -all"], provider="google")
    assert spf["lookup_count_is_minimum"] is True
    assert spf["provider_include_present"] is None
    zone({("_spf.google.com", "TXT"): [txt("v=spf1 -all")], ("a.example.net", "TXT"): "SERVFAIL"})
    found, _ = dns_auth.evaluate_spf(
        "example.com", ["v=spf1 include:a.example.net include:_spf.google.com -all"],
        provider="google")
    assert found["provider_include_present"] is True


def test_provider_include_unknown_when_limit_stops_expansion(zone):
    zone({(f"i{n}.example.net", "TXT"): [txt("v=spf1 -all")] for n in range(12)})
    record = "v=spf1 " + " ".join(f"include:i{n}.example.net" for n in range(11))
    spf, _ = dns_auth.evaluate_spf(
        "example.com", [record + " include:_spf.google.com -all"], provider="google")
    assert spf["provider_include_present"] is None


def test_mx_microsoft_host_detected_as_microsoft365():
    mx = dns_auth.parse_mx([{"preference": 0, "exchange": "example-com.o-v1.mx.microsoft"}])
    assert mx["provider"] == "microsoft365"


def test_lookup_error_carries_query_error_detail(zone, monkeypatch):
    monkeypatch.setattr(_dns, "query", lambda name, rtype, **k: {
        "status": "ERROR", "answers": [], "ad": False, "error": "invalid_resolver"})
    spf, errs = dns_auth.evaluate_spf("example.com", ["v=spf1 include:a.example.net -all"])
    assert errs == ["TXT a.example.net: ERROR (invalid_resolver)"]


@pytest.mark.parametrize("record", [
    "v=spf1 include:bad..example.net -all",
    "v=spf1 redirect=bad_host!.example.net",
    "v=spf1 a:-bad.example.net -all",
])
def test_malformed_spf_target_is_permerror_without_query(zone, record):
    calls = zone({})
    spf, errs = dns_auth.evaluate_spf("example.com", [record])
    assert any("invalid_query_name" in p for p in spf["permerrors"])
    assert errs == []
    assert calls == []
    if "a:" not in record:
        assert spf["includes"][0]["status"] == "invalid_query_name"


def test_build_dkim_caps_extra_selectors(zone):
    calls = zone({})
    extras = [f"x{n}" for n in range(dns_auth.MAX_EXTRA_SELECTORS + 15)]
    dkim = dns_auth.build_dkim("example.com", extras, {})
    checked = dkim["selectors_checked"]
    assert checked[:dns_auth.MAX_EXTRA_SELECTORS] == extras[:dns_auth.MAX_EXTRA_SELECTORS]
    assert extras[dns_auth.MAX_EXTRA_SELECTORS] not in checked
    assert len(calls) == len(checked)


def test_redirect_skipped_by_lookup_limit_leaves_effective_all_unknown(zone):
    zone({(f"h{n}.example.com", "A"): [("A", "192.0.2.1")] for n in range(20)}
         | {("r.example", "TXT"): [txt("v=spf1 -all")]})
    record = "v=spf1 " + " ".join(f"a:h{n}.example.com" for n in range(20)) + " redirect=r.example"
    spf, _ = dns_auth.evaluate_spf("example.com", [record])
    assert spf["lookup_limit_exceeded"] is True
    assert spf["includes"][-1]["status"] == "limit_reached"
    assert spf["effective_all_mechanism"] is None
    assert spf["effective_strict"] is None


def test_lookup_limit_makes_count_a_minimum(zone):
    zone({(f"i{n}.example.net", "TXT"): [txt("v=spf1 -all")] for n in range(12)})
    record = "v=spf1 " + " ".join(f"include:i{n}.example.net" for n in range(12)) + " -all"
    spf, errs = dns_auth.evaluate_spf("example.com", [record])
    assert errs == []
    assert spf["lookup_count_is_minimum"] is True
