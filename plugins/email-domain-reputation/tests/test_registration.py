"""Tests for registration. No real network: the HTTP layer is mocked throughout."""

import http.client
import importlib
import io
import json
import urllib.error
import urllib.request
from datetime import UTC, datetime

import pytest

PACKAGE = "shadetree_ai_plugins_email_domain_reputation"
registration = importlib.import_module(f"{PACKAGE}.registration")

NOW = datetime(2026, 11, 19, tzinfo=UTC)

# Trimmed from a real Verisign .com RDAP response (rdap.verisign.com).
VERISIGN_COM = {
    "objectClassName": "domain",
    "ldhName": "EXAMPLE.COM",
    "status": ["client delete prohibited", "client transfer prohibited",
               "client update prohibited", "server delete prohibited"],
    "entities": [{
        "objectClassName": "entity",
        "roles": ["registrar"],
        "vcardArray": ["vcard", [
            ["version", {}, "text", "4.0"],
            ["fn", {}, "text", "RESERVED-Internet Assigned Numbers Authority"],
        ]],
        "entities": [{"objectClassName": "entity", "roles": ["abuse"],
                      "vcardArray": ["vcard", [["fn", {}, "text", "Abuse Contact"]]]}],
    }],
    "events": [
        {"eventAction": "registration", "eventDate": "1995-08-14T04:00:00Z"},
        {"eventAction": "expiration", "eventDate": "2027-08-13T04:00:00Z"},
        {"eventAction": "last changed", "eventDate": "2026-08-14T07:01:39Z"},
        {"eventAction": "last update of RDAP database", "eventDate": "2026-11-19T12:00:00Z"},
    ],
    "secureDNS": {"delegationSigned": True,
                  "dsData": [{"keyTag": 370, "algorithm": 13, "digestType": 2, "digest": "BE74"}]},
    "nameservers": [
        {"objectClassName": "nameserver", "ldhName": "A.IANA-SERVERS.NET"},
        {"objectClassName": "nameserver", "ldhName": "B.IANA-SERVERS.NET"},
    ],
}

# Registrar-style response that omits expiration, secureDNS and nameservers.
MISSING_EXPIRATION = {
    "status": ["active"],
    "entities": [{"roles": ["registrant"], "vcardArray": ["vcard", [["fn", {}, "text", "X"]]]}],
    "events": [{"eventAction": "registration", "eventDate": "2026-11-05T10:00:00Z"}],
}

HOLD_REDEMPTION = {
    "status": ["client hold", "redemption period", "autoRenewPeriod"],
    "entities": [{"roles": ["registrar"],
                  "vcardArray": ["vcard", [["version", {}, "text", "4.0"],
                                           ["fn", {}, "text", "GoDaddy.com, LLC"]]]}],
    "events": [
        {"eventAction": "registration", "eventDate": "2019-11-01T00:00:00Z"},
        {"eventAction": "expiration", "eventDate": "2026-11-01T00:00:00Z"},
    ],
    "secureDNS": {"delegationSigned": False},
    "nameservers": [{"ldhName": "ns1.Example-Parking.com."}],
}


def _ok(raw):
    return (200, json.dumps(raw).encode())


@pytest.fixture
def fake_get(monkeypatch):
    """Replace _http_get; set .response (tuple) or .exc, read .calls."""

    class Fake:
        response = _ok(VERISIGN_COM)
        exc = None
        calls = []

        def __call__(self, url, headers, timeout):
            self.calls.append((url, headers, timeout))
            if self.exc:
                raise self.exc
            return self.response

    fake = Fake()
    fake.calls = []
    monkeypatch.setattr(registration, "_http_get", fake)
    return fake


# --- fetch_rdap ----------------------------------------------------------


def test_success_sends_rdap_headers_to_bootstrap_url(fake_get):
    result = registration.fetch_rdap("example.com")
    assert result["ok"] is True
    url, headers, timeout = fake_get.calls[0]
    assert url == "https://rdap.org/domain/example.com"
    assert headers["Accept"] == "application/rdap+json"
    assert "User-Agent" in headers
    assert timeout == 10


@pytest.mark.parametrize(("status", "error"), [
    (404, "not_found_or_no_rdap"), (429, "rate_limited"), (503, "http_error"),
    (302, "http_error"),
])
def test_status_codes_map_to_source_errors(fake_get, status, error):
    fake_get.response = (status, b"")
    result = registration.fetch_rdap("example.com")
    assert result["ok"] is False
    assert result["error"] == error
    assert result["status_code"] == status
    assert result["raw"] is None


def test_404_detail_mentions_cctld(fake_get):
    fake_get.response = (404, b"")
    assert "ccTLD" in registration.fetch_rdap("example.zz")["detail"]


@pytest.mark.parametrize(("exc", "error"), [
    (TimeoutError("timed out"), "timeout"),
    (http.client.IncompleteRead(b"partial"), "network_error"),
    (http.client.RemoteDisconnected("closed"), "network_error"),
    (OSError("Name or service not known"), "network_error"),
    (registration.ResponseTooLarge(), "invalid_response"),
])
def test_transport_failures(fake_get, exc, error):
    fake_get.exc = exc
    result = registration.fetch_rdap("example.com")
    assert result["ok"] is False
    assert result["error"] == error


@pytest.mark.parametrize("body", [b"<html>", b"[1, 2]"])
def test_invalid_or_non_object_json(fake_get, body):
    fake_get.response = (200, body)
    assert registration.fetch_rdap("example.com")["error"] == "invalid_response"


# --- _http_get (opener mocked) --------------------------------------------


class _FakeResponse(io.BytesIO):
    status = 200


def _install_opener(monkeypatch, behavior):
    handlers = []

    class Opener:
        def open(self, request, timeout):
            return behavior(request, timeout)

    def build_opener(*args):
        handlers.extend(args)
        return Opener()

    monkeypatch.setattr(urllib.request, "build_opener", build_opener)
    return handlers


def test_http_get_installs_https_only_redirect_and_returns_body(monkeypatch):
    handlers = _install_opener(monkeypatch, lambda req, t: _FakeResponse(b'{"a": 1}'))
    status, body = registration._http_get("https://rdap.org/domain/x.com", {}, 10)
    assert (status, body) == (200, b'{"a": 1}')
    assert any(isinstance(h, registration.HttpsOnlyRedirect) for h in handlers)


def test_http_get_caps_response_size(monkeypatch):
    big = b"x" * (registration.MAX_RESPONSE_BYTES + 1)
    _install_opener(monkeypatch, lambda req, t: _FakeResponse(big))
    with pytest.raises(registration.ResponseTooLarge):
        registration._http_get("https://rdap.org/domain/x.com", {}, 10)


def test_http_get_returns_http_error_status(monkeypatch):
    def raise_404(req, t):
        raise urllib.error.HTTPError(req.full_url, 404, "Not Found", {}, io.BytesIO(b"nope"))

    _install_opener(monkeypatch, raise_404)
    assert registration._http_get("https://rdap.org/domain/x.zz", {}, 10) == (404, b"")


@pytest.mark.parametrize(("reason", "expected"), [
    (TimeoutError("slow"), TimeoutError), (ConnectionRefusedError("refused"), OSError),
])
def test_http_get_unwraps_url_errors(monkeypatch, reason, expected):
    def raise_url_error(req, t):
        raise urllib.error.URLError(reason)

    _install_opener(monkeypatch, raise_url_error)
    with pytest.raises(expected):
        registration._http_get("https://rdap.org/domain/x.com", {}, 10)


def test_redirect_handler_refuses_http_downgrade():
    handler = registration.HttpsOnlyRedirect()
    req = urllib.request.Request("https://rdap.org/domain/x.com",
                                 headers={"Accept": "application/rdap+json"})
    assert handler.redirect_request(req, None, 302, "Found", {}, "http://evil.test/x") is None
    followed = handler.redirect_request(
        req, None, 302, "Found", {}, "https://rdap.verisign.com/com/v1/domain/x.com")
    assert followed.full_url == "https://rdap.verisign.com/com/v1/domain/x.com"
    assert followed.get_header("Accept") == "application/rdap+json"


# --- normalize_registration ------------------------------------------------


def test_verisign_com_response():
    reg = registration.normalize_registration(VERISIGN_COM, now=NOW)
    assert reg["registrar"] == "RESERVED-Internet Assigned Numbers Authority"
    assert reg["created"] == "1995-08-14T04:00:00Z"
    assert reg["expires"] == "2027-08-13T04:00:00Z"
    assert reg["last_changed"] == "2026-08-14T07:01:39Z"
    assert reg["domain_age_days"] == 11419
    assert reg["days_until_expiry"] == 267
    assert len(reg["statuses"]) == 4
    assert reg["transfer_locked"] is True
    assert reg["on_hold"] is False
    assert reg["pending_delete"] is False
    assert reg["auto_renew_period"] is False
    assert reg["nameservers"] == ["a.iana-servers.net", "b.iana-servers.net"]
    assert reg["dnssec_delegation_signed"] is True


def test_missing_expiration_and_optional_fields_become_null():
    reg = registration.normalize_registration(MISSING_EXPIRATION, now=NOW)
    assert reg["registrar"] is None
    assert reg["expires"] is None
    assert reg["days_until_expiry"] is None
    assert reg["last_changed"] is None
    assert reg["domain_age_days"] == 13
    assert reg["nameservers"] == []
    assert reg["dnssec_delegation_signed"] is None
    assert reg["transfer_locked"] is False


def test_hold_and_redemption_statuses():
    reg = registration.normalize_registration(HOLD_REDEMPTION, now=NOW)
    assert reg["registrar"] == "GoDaddy.com, LLC"
    assert reg["on_hold"] is True
    assert reg["pending_delete"] is True
    assert reg["auto_renew_period"] is True
    assert reg["days_until_expiry"] == -18
    assert reg["dnssec_delegation_signed"] is False
    assert reg["nameservers"] == ["ns1.example-parking.com"]


def test_epp_camelcase_statuses_also_match():
    reg = registration.normalize_registration(
        {"status": ["serverHold", "pendingDelete", "clientTransferProhibited"]}, now=NOW)
    assert reg["on_hold"] is True
    assert reg["pending_delete"] is True
    assert reg["transfer_locked"] is True


def test_malformed_partial_data_does_not_crash():
    raw = {"events": [{"eventAction": "registration", "eventDate": "not-a-date"}, "junk"],
           "entities": [{"roles": ["registrar"], "vcardArray": "bad"}, "junk"],
           "nameservers": [{"ldhName": None}, "junk"], "secureDNS": "bad", "status": None}
    reg = registration.normalize_registration(raw, now=NOW)
    assert reg["created"] == "not-a-date"
    assert reg["domain_age_days"] is None
    assert reg["registrar"] is None
    assert reg["nameservers"] == []
    assert reg["statuses"] == []
    assert reg["dnssec_delegation_signed"] is None


def test_missing_status_list_leaves_flags_unknown():
    reg = registration.normalize_registration({"ldhName": "example.com"}, now=NOW)
    for key in ("on_hold", "pending_delete", "transfer_locked", "auto_renew_period"):
        assert reg[key] is None, key
    assert registration.normalize_registration({"status": []}, now=NOW)["on_hold"] is False


def test_empty_raw_returns_empty_dict():
    assert registration.normalize_registration(None) == {}


# --- build_output ------------------------------------------------------------


@pytest.mark.parametrize("target", ["not a domain", "localhost", "", "https://x.com/", "a@b@c.com"])
def test_invalid_target_raises_before_network(fake_get, target):
    with pytest.raises(ValueError):
        registration.build_output(target)
    assert fake_get.calls == []


def test_subdomain_email_reduced_to_org_domain(fake_get):
    out = registration.build_output("Person@Mail.Example.co.uk", now=NOW)
    assert out["domain"] == "mail.example.co.uk"
    assert out["registered_domain"] == "example.co.uk"
    assert fake_get.calls[0][0] == "https://rdap.org/domain/example.co.uk"
    assert out["source"] == {"ok": True, "error": None, "detail": None}
    assert out["registration"]["registrar"] == "RESERVED-Internet Assigned Numbers Authority"
    assert out["registration"]["days_until_expiry"] == 267


def test_source_error_yields_empty_registration(fake_get):
    fake_get.response = (404, b"")
    out = registration.build_output("example.zz")
    assert out["source"]["ok"] is False
    assert out["source"]["error"] == "not_found_or_no_rdap"
    assert out["registration"] == {}
    assert set(out) == {"domain", "registered_domain", "registration", "source"}
