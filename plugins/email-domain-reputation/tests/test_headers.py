"""Tests for headers.py's header parsing, normalization, and input validation.

Fixtures in fixtures/headers/ are realistic but fake: example domains and
documentation IP ranges only. Each fixture body carries SECRET-BODY-MARKER
so the suite can assert the body never reaches the output.
"""

import importlib
import json
from pathlib import Path

import pytest

headers = importlib.import_module("shadetree_ai_plugins_email_domain_reputation.headers")

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "headers"


def analyze(fixture):
    data = headers.analyze_headers((FIXTURES / fixture).read_text())
    return data, json.dumps(data)


def output(data: bytes):
    return headers.build_output(headers.parse_message(data))


@pytest.fixture(scope="module")
def gmail():
    return analyze("gmail_pass_aligned.eml")


@pytest.fixture(scope="module")
def m365():
    return analyze("m365_dmarc_fail.eml")


@pytest.fixture(scope="module")
def esp():
    return analyze("esp_unaligned_spf.eml")


# --- Gmail, fully aligned ---------------------------------------------------

def test_gmail_from_and_return_path(gmail):
    data, _ = gmail
    assert data["from"] == {"address": "alice@clientco.example", "domain": "clientco.example",
                            "org_domain": "clientco.example"}
    assert data["return_path"]["domain"] == "clientco.example"
    assert data["message_id_domain"] == "mail.clientco.example"
    assert "source" not in data


def test_gmail_folded_authentication_results_parsed(gmail):
    ar = gmail[0]["authentication_results"]
    assert len(ar) == 1
    assert ar[0]["authserv_id"] == "mx.google.com"
    assert ar[0]["spf"]["smtp_mailfrom"] == "alice@clientco.example"
    assert ar[0]["dkim"][0]["header_i"] == "@clientco.example"
    assert ar[0]["dmarc"]["policy"] == "reject"


def test_gmail_receiver_verdict(gmail):
    assert gmail[0]["receiver_verdict"] == {
        "authserv_id": "mx.google.com", "spf": "pass", "dkim": "pass",
        "dmarc": "pass", "compauth": None}


def test_gmail_arc_results_carry_instance(gmail):
    arc = gmail[0]["arc_authentication_results"]
    assert arc[0]["instance"] == 1
    assert arc[0]["authserv_id"] == "mx.google.com"
    assert arc[0]["dmarc"]["result"] == "pass"


def test_gmail_dkim_signature_and_selectors(gmail):
    data, _ = gmail
    sig = data["dkim_signatures"][0]
    assert (sig["d"], sig["s"], sig["a"]) == ("clientco.example", "s1", "rsa-sha256")
    assert sig["h_includes_from"]
    assert sig["aligned_strict"]
    assert sig["receiver_result"] == "pass"
    assert data["selectors"] == ["s1"]


def test_gmail_fully_aligned(gmail):
    alignment = gmail[0]["alignment"]
    assert alignment["spf_aligned"]
    assert alignment["spf_pass_aligned"]
    assert alignment["dkim_aligned"]


def test_gmail_sending_ip_from_received_spf(gmail):
    data, _ = gmail
    assert data["sending_ip"] == "203.0.113.25"
    assert data["sending_host"] == "mail.clientco.example"
    assert data["sending_ip_source"] == "received_spf"


def test_gmail_received_chain_top_down(gmail):
    chain = gmail[0]["received_chain"]
    assert len(chain) == 3
    assert chain[1]["by_host"] == "mx.google.com"
    assert chain[1]["from_ip"] == "203.0.113.25"
    assert chain[2]["from_ip"] == "10.20.0.15"
    assert chain[0]["timestamp"].startswith("2026-11-17T10:15:03")


def test_gmail_subject_present_without_warnings(gmail):
    data, _ = gmail
    assert data["subject_present"]
    assert data["warnings"] == []


@pytest.mark.parametrize("fixture", sorted(p.name for p in FIXTURES.glob("*.eml")))
def test_body_subject_and_unsubscribe_urls_never_echoed(fixture):
    text = (FIXTURES / fixture).read_text()
    _, raw = analyze(fixture)
    subject = next(line.split(":", 1)[1].strip() for line in text.splitlines()
                   if line.startswith("Subject:"))
    for secret in ("SECRET-BODY-MARKER", "SECRET-TOKEN", subject,
                   "https://email.clientco.example", "unsub-a1b2c3"):
        assert secret not in raw


# --- Microsoft 365, DMARC fail -----------------------------------------------

def test_m365_ar_without_authserv_id(m365):
    ar = m365[0]["authentication_results"][0]
    assert ar["authserv_id"] is None
    assert ar["spf"] == {"result": "fail", "smtp_mailfrom": "clientco.example",
                         "client_ip": "198.51.100.77"}
    assert ar["dmarc"]["action"] == "quarantine"
    assert ar["compauth"] == {"result": "fail", "reason": "000"}


def test_m365_receiver_verdict(m365):
    verdict = m365[0]["receiver_verdict"]
    assert (verdict["spf"], verdict["dkim"], verdict["dmarc"], verdict["compauth"]) == (
        "fail", "none", "fail", "fail")


def test_m365_alignment_requires_pass(m365):
    alignment = m365[0]["alignment"]
    assert alignment["spf_aligned"]
    assert alignment["spf_pass_aligned"] is False
    assert alignment["dkim_aligned"] is False


def test_m365_spam_headers(m365):
    spam = m365[0]["spam_headers"]
    assert spam["x_microsoft_antispam"] == {"bcl": 0}
    assert spam["x_ms_exchange_organization_scl"] == 5
    report = spam["x_forefront_antispam_report"]
    assert (report["SFV"], report["SCL"], report["CAT"], report["IPV"], report["SFTY"]) == (
        "SPM", 5, "SPOOF", "NLI", "9.25")
    assert report["CIP"] == "198.51.100.77"


def test_m365_sending_ip_and_no_dkim_warning(m365):
    data, _ = m365
    assert data["sending_ip"] == "198.51.100.77"
    assert data["sending_host"] == "smtp.legacy-host.example"
    assert any(w.startswith("no_dkim_signature") for w in data["warnings"])


def test_m365_chain_heuristic_finds_entry_hop():
    msg = headers.parse_message((FIXTURES / "m365_dmarc_fail.eml").read_bytes())
    chain = [headers.parse_received(v) for v in headers.header_values(msg, "Received")]
    assert headers.chain_entry_ip(chain) == "198.51.100.77"


# --- ESP with unaligned SPF --------------------------------------------------

def test_esp_spf_passes_but_not_aligned(esp):
    data, _ = esp
    alignment = data["alignment"]
    assert data["receiver_verdict"]["spf"] == "pass"
    assert alignment["spf_domain"] == "mg.esp-mail.example"
    assert alignment["spf_aligned"] is False
    assert alignment["spf_pass_aligned"] is False


def test_esp_dkim_aligned_via_client_signature(esp):
    data, _ = esp
    alignment = data["alignment"]
    assert alignment["dkim_aligned"]
    assert alignment["dkim_aligned_domains"] == ["clientco.example"]
    sigs = {s["d"]: s for s in data["dkim_signatures"]}
    assert sigs["clientco.example"]["aligned_relaxed"]
    assert sigs["clientco.example"]["h_includes_from"]
    assert not sigs["mg.esp-mail.example"]["aligned_relaxed"]
    assert not sigs["mg.esp-mail.example"]["h_includes_from"]
    assert data["selectors"] == ["k1"]


def test_esp_list_unsubscribe_one_click(esp):
    assert esp[0]["list_unsubscribe"] == {"present": True, "mailto": True, "https": True,
                                          "one_click": True}


def test_esp_sending_ip_from_ar_comment_without_received_spf(esp):
    data, _ = esp
    assert data["received_spf"] is None
    assert data["sending_ip"] == "198.51.100.42"
    assert data["sending_ip_source"] == "authentication_results"
    assert data["sending_host"] == "m42-7.mg.esp-mail.example"


# --- sending IP fallbacks ----------------------------------------------------

def test_chain_skips_gmail_ip_by_hops_and_private_ips():
    out = output(b"Received: by 2002:a05:6a10::1 with SMTP id x; Tue, 17 Nov 2026 10:00:00 +0000\n"
                 b"Received: from relay.clientco.example (relay.clientco.example [192.168.5.5])\n"
                 b" by mx.google.com with ESMTPS id y; Tue, 17 Nov 2026 10:00:00 +0000\n"
                 b"Received: from edge.clientco.example ([203.0.113.9])"
                 b" by relay.clientco.example;\n"
                 b" Tue, 17 Nov 2026 09:59:59 +0000\n"
                 b"From: a@clientco.example\n\n")
    assert out["sending_ip"] == "203.0.113.9"
    assert out["sending_ip_source"] == "received_chain"
    assert out["sending_host"] == "edge.clientco.example"


def test_x_originating_ip_last_resort():
    out = output(b"From: a@clientco.example\nX-Originating-IP: [198.51.100.200]\n\n")
    assert out["sending_ip"] == "198.51.100.200"
    assert out["sending_ip_source"] == "x_originating_ip"


def test_private_only_yields_none():
    out = output(b"From: a@clientco.example\nX-Originating-IP: [10.1.2.3]\n\n")
    assert out["sending_ip"] is None
    assert any(w.startswith("no_sending_ip") for w in out["warnings"])


# --- List-Id / strict alignment ----------------------------------------------

def test_list_id_present_and_domain():
    out = output(b"From: a@clientco.example\n"
                 b"List-Id: Announcements <Announce.Lists.Example.COM>\n\n")
    assert out["list_id_present"]
    assert out["list_id_domain"] == "announce.lists.example.com"
    bare = output(b"From: a@clientco.example\nList-Id: no brackets here\n\n")
    assert bare["list_id_present"]
    assert bare["list_id_domain"] is None
    none = output(b"From: a@clientco.example\n\n")
    assert not none["list_id_present"]
    assert none["list_id_domain"] is None


def test_build_alignment_strict_modes():
    auth = [headers.parse_auth_results(
        "mx.example; spf=pass smtp.mailfrom=bounce.clientco.example; "
        "dkim=pass header.d=mail.clientco.example")]
    relaxed = headers.build_alignment("clientco.example", None, auth)
    strict = headers.build_alignment("clientco.example", None, auth, aspf="s", adkim="s")
    assert relaxed["spf_pass_aligned"]
    assert relaxed["dkim_aligned"]
    assert strict["spf_pass_aligned"] is False
    assert strict["dkim_aligned"] is False


# --- analyze_headers input handling ------------------------------------------

def test_sent_folder_copy_warns_no_authentication_results():
    data = headers.analyze_headers("From: Alice <alice@clientco.example>\nSubject: x\n\nbody\n")
    assert data["receiver_verdict"] is None
    assert data["alignment"]["dkim_aligned"] is None
    assert any(w.startswith("no_authentication_results") for w in data["warnings"])


def test_headers_only_text_without_body():
    text = (FIXTURES / "gmail_pass_aligned.eml").read_text().split("\n\n", 1)[0]
    data = headers.analyze_headers(text)
    assert data["receiver_verdict"]["dmarc"] == "pass"
    assert data["selectors"] == ["s1"]


def test_crlf_and_pasted_leading_whitespace_tolerated():
    lf = headers.analyze_headers((FIXTURES / "gmail_pass_aligned.eml").read_text())
    text = (FIXTURES / "gmail_pass_aligned.eml").read_text().replace("\n", "\r\n")
    assert headers.analyze_headers("\r\n\r\n  " + text) == lf
    indented = "\n".join("    " + line for line in text.split("\r\n"))
    assert headers.analyze_headers("\n\n" + indented) == lf


@pytest.mark.parametrize("raw", [None, b"From: a@clientco.example\n", 42])
def test_non_string_input_rejected(raw):
    with pytest.raises(ValueError):
        headers.analyze_headers(raw)


@pytest.mark.parametrize("raw", ["", "\n  \n\t"])
def test_empty_input_rejected(raw):
    with pytest.raises(ValueError):
        headers.analyze_headers(raw)


def test_oversize_input_rejected():
    raw = "From: a@clientco.example\nX-Pad: " + "é" * (128 * 1024) + "\n"
    assert len(raw) < 256 * 1024 < len(raw.encode("utf-8"))
    with pytest.raises(ValueError, match="256 KB"):
        headers.analyze_headers(raw)


def test_text_without_headers_rejected():
    with pytest.raises(ValueError):
        headers.analyze_headers("hello there\nthis is not an email\n")


def _signed(selectors, domain="example.com"):
    sigs = "".join(f"DKIM-Signature: v=1; a=rsa-sha256; d={domain}; s={s}; h=from; b=x\n"
                   for s in selectors)
    return f"From: a@{domain}\n{sigs}Subject: hi\n\nbody\n".encode()


def test_header_selectors_capped_and_validated():
    many = [f"sel{n}" for n in range(headers.MAX_HEADER_SELECTORS + 5)]
    data = output(_signed(["bad_sel!", "SEL0", *many]))
    assert data["selectors"] == many[:headers.MAX_HEADER_SELECTORS]
    assert any(w.startswith("too_many_dkim_selectors: 5 ") for w in data["warnings"])
    assert any(w.startswith("invalid_dkim_selector: 1 ") for w in data["warnings"])


def test_header_selectors_under_cap_have_no_selector_warning():
    data = output(_signed(["s1", "s2"]))
    assert data["selectors"] == ["s1", "s2"]
    assert not any("selector" in w for w in data["warnings"])


@pytest.mark.parametrize(("text", "expected"), [
    ("pass (good) x=1", ("pass x=1", ["good"])),
    ("a (outer (inner) tail) b (c)", ("a b", ["inner", "outer   tail", "c"])),
    ("a ) b ( c", ("a ) b ( c", [])),
    ("((a) b", ("( b", ["a"])),
])
def test_strip_comments_semantics(text, expected):
    assert headers.strip_comments(text) == expected


def test_strip_comments_is_linear():
    import time
    start = time.perf_counter()
    text, comments = headers.strip_comments("()" * 120_000)
    assert time.perf_counter() - start < 1.0
    assert text == "" and len(comments) == 120_000
