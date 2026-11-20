"""RDAP registration lookup, ported from check_registration.py.

`build_output(target)` takes an email address or bare domain (ValueError when
it is invalid, before any network call) and looks up the registered
(organizational) domain, so `mail.example.co.uk` is looked up as
`example.co.uk`. The request goes to the https://rdap.org bootstrap
redirector, which forwards to the TLD's authoritative RDAP server; only https
redirects are followed, with a bounded timeout and response-size cap.

Output contract::

    {
      "domain": str,               # normalized input domain
      "registered_domain": str,    # org domain actually looked up
      "registration": {            # {} when the lookup failed
        "registrar": str | None,
        "created": str | None, "expires": str | None, "last_changed": str | None,
        "domain_age_days": int | None, "days_until_expiry": int | None,
        "statuses": [str],         # RDAP/EPP status strings as published
        "on_hold": bool | None, "pending_delete": bool | None,
        "transfer_locked": bool | None, "auto_renew_period": bool | None,
                                   # null when the response has no status list
        "nameservers": [str],      # lower-case, no trailing dot
        "dnssec_delegation_signed": bool | None,
      },
      "source": {"ok": bool, "error": str | None, "detail": str | None},
    }

source.error is one of: not_found_or_no_rdap (404: unregistered, or a ccTLD
with no RDAP service), rate_limited (429), http_error (any other non-200,
including a refused redirect), timeout, network_error, invalid_response
(not a JSON object, or larger than the size cap).

Fetch and normalization only: no verdict on expiry, hold, or domain age.
"""

from __future__ import annotations

import http.client
import json
import urllib.error
import urllib.parse
import urllib.request
from datetime import UTC, datetime

from ._domain import domain_from_arg, org_domain

RDAP_URL = "https://rdap.org/domain/"
REQUEST_TIMEOUT_SECONDS = 10
MAX_RESPONSE_BYTES = 1024 * 1024
REQUEST_HEADERS = {
    "Accept": "application/rdap+json",
    "User-Agent": "email-domain-reputation-audit/1.0 (rdap lookup)",
}

# RDAP spells EPP statuses with spaces ("client hold", RFC 8056); some servers
# echo the EPP camelCase ("clientHold"). Compare both as lowercase, no spaces.
HOLD_STATUSES = {"clienthold", "serverhold"}
PENDING_DELETE_STATUSES = {"pendingdelete", "redemptionperiod"}
TRANSFER_LOCK_STATUSES = {"clienttransferprohibited"}
AUTO_RENEW_STATUSES = {"autorenewperiod"}


class ResponseTooLarge(Exception):
    pass


class HttpsOnlyRedirect(urllib.request.HTTPRedirectHandler):
    """Follow redirects only to https URLs; anything else surfaces as the 3xx."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if urllib.parse.urlsplit(newurl).scheme.lower() != "https":
            return None
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _error_result(kind, detail=None, status_code=None):
    return {"ok": False, "error": kind, "detail": detail, "status_code": status_code, "raw": None}


def _http_get(url, headers, timeout):
    """Returns (status_code, body) for any HTTP response, including 4xx/5xx
    (error bodies are discarded). Raises TimeoutError, OSError for other
    network failures, http.client.HTTPException for a truncated or malformed
    response, and ResponseTooLarge past MAX_RESPONSE_BYTES."""
    request = urllib.request.Request(url, headers=headers)
    opener = urllib.request.build_opener(HttpsOnlyRedirect())
    try:
        with opener.open(request, timeout=timeout) as response:
            body = response.read(MAX_RESPONSE_BYTES + 1)
            status = response.status
    except urllib.error.HTTPError as exc:
        exc.close()
        return exc.code, b""
    except urllib.error.URLError as exc:
        if isinstance(exc.reason, TimeoutError):
            raise TimeoutError(str(exc.reason)) from exc
        raise OSError(str(exc.reason)) from exc
    if len(body) > MAX_RESPONSE_BYTES:
        raise ResponseTooLarge
    return status, body


def fetch_rdap(domain, timeout=REQUEST_TIMEOUT_SECONDS):
    url = RDAP_URL + urllib.parse.quote(domain)
    try:
        status, body = _http_get(url, REQUEST_HEADERS, timeout)
    except TimeoutError:
        return _error_result("timeout", "RDAP request timed out")
    except ResponseTooLarge:
        return _error_result(
            "invalid_response", f"RDAP response exceeded {MAX_RESPONSE_BYTES} bytes"
        )
    except (OSError, ValueError, http.client.HTTPException) as exc:  # e.g. IncompleteRead
        return _error_result("network_error", str(exc) or type(exc).__name__)

    if status == 404:
        return _error_result(
            "not_found_or_no_rdap",
            "RDAP returned 404: the domain is not registered, or its TLD has no "
            "RDAP service (common for some ccTLDs -- check the registry's WHOIS instead)",
            404,
        )
    if status == 429:
        return _error_result("rate_limited", "RDAP rate limit hit (429)", 429)
    if 300 <= status < 400:
        return _error_result(
            "http_error", f"RDAP returned HTTP {status}; non-https redirect refused", status
        )
    if status != 200:
        return _error_result("http_error", f"RDAP returned HTTP {status}", status)

    try:
        data = json.loads(body)
    except ValueError:
        return _error_result("invalid_response", "RDAP response was not valid JSON")
    if not isinstance(data, dict):
        return _error_result("invalid_response", "RDAP response was not a JSON object")

    return {"ok": True, "error": None, "detail": None, "status_code": 200, "raw": data}


def _parse_date(value):
    """RDAP dates are RFC 3339; returns an aware datetime or None."""
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _event_date(events, action):
    for event in events:
        if event.get("eventAction") == action:
            return event.get("eventDate")
    return None


def _vcard_fn(entity):
    vcard = entity.get("vcardArray")
    if not (isinstance(vcard, list) and len(vcard) > 1 and isinstance(vcard[1], list)):
        return None
    for prop in vcard[1]:
        if isinstance(prop, list) and len(prop) >= 4 and prop[0] == "fn":
            return prop[3] or None
    return None


def _registrar_name(entities):
    for entity in entities:
        if "registrar" in (entity.get("roles") or []):
            return _vcard_fn(entity)
    return None


def _days_between(start, end):
    if start is None or end is None:
        return None
    return (end - start).days


def _list_of_dicts(value):
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []


def normalize_registration(raw, now=None):
    """Flatten an RDAP domain object. `now` (aware datetime) is injectable for tests."""
    if not raw:
        return {}
    now = now or datetime.now(UTC)
    events = _list_of_dicts(raw.get("events"))
    created = _event_date(events, "registration")
    expires = _event_date(events, "expiration")
    last_changed = _event_date(events, "last changed")

    raw_status = raw.get("status")
    statuses = [s for s in raw_status if isinstance(s, str)] if isinstance(raw_status, list) else []
    status_set = {s.replace(" ", "").lower() for s in statuses}

    def flag(matching):
        # No status list at all means unknown, not "flag absent".
        return bool(status_set & matching) if isinstance(raw_status, list) else None

    nameservers = [
        ns["ldhName"].lower().rstrip(".")
        for ns in _list_of_dicts(raw.get("nameservers"))
        if isinstance(ns.get("ldhName"), str)
    ]

    secure_dns = raw.get("secureDNS")
    signed = secure_dns.get("delegationSigned") if isinstance(secure_dns, dict) else None

    return {
        "registrar": _registrar_name(_list_of_dicts(raw.get("entities"))),
        "created": created,
        "expires": expires,
        "last_changed": last_changed,
        "domain_age_days": _days_between(_parse_date(created), now),
        "days_until_expiry": _days_between(now, _parse_date(expires)),
        "statuses": statuses,
        "on_hold": flag(HOLD_STATUSES),
        "pending_delete": flag(PENDING_DELETE_STATUSES),
        "transfer_locked": flag(TRANSFER_LOCK_STATUSES),
        "auto_renew_period": flag(AUTO_RENEW_STATUSES),
        "nameservers": nameservers,
        "dnssec_delegation_signed": signed if isinstance(signed, bool) else None,
    }


def build_output(target, *, now=None):
    """Registration record for an email address or domain; ValueError if invalid."""
    domain = domain_from_arg(target)
    registered_domain = org_domain(domain)
    result = fetch_rdap(registered_domain)
    return {
        "domain": domain,
        "registered_domain": registered_domain,
        "registration": normalize_registration(result["raw"], now=now),
        "source": {"ok": result["ok"], "error": result["error"], "detail": result["detail"]},
    }
