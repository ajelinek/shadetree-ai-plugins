"""Google Safe Browsing lookup (v4 ``threatMatches:find``).

Licensing: Google limits the Safe Browsing API to non-commercial use and points
businesses at the paid Web Risk API. Checking your own site is the intended
low-volume case, but say so when reporting for a client.
"""

from __future__ import annotations

from .. import credentials, http
from ..store import SourceResult

NAME = "safebrowsing"
URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
THREATS = ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"]


def enabled(site: dict) -> tuple[bool, str]:
    return (bool(site.get("safeBrowsing", True)), "safeBrowsing disabled")


def collect(site: dict, store, backfill_days: int = 0) -> SourceResult:
    key = credentials.read("google-api-key")
    if not key:
        raise http.HttpError("setup_required: google-api-key is not stored.")
    urls = [site["url"] + "/"] + [site["url"] + p for p in site.get("keyPaths") or [] if p != "/"]
    body = {"client": {"clientId": "shadetree-website-health", "clientVersion": "0.1.0"},
            "threatInfo": {"threatTypes": THREATS, "platformTypes": ["ANY_PLATFORM"],
                           "threatEntryTypes": ["URL"],
                           "threatEntries": [{"url": u} for u in urls[:50]]}}
    data = http.request("POST", URL, secret_params={"key": key}, json_body=body).data or {}
    result = SourceResult(NAME)
    matches = data.get("matches") or []
    result.summary = {"checked": len(urls[:50]), "flagged": len(matches)}
    for m in matches:
        result.findings.append({"source": NAME, "kind": "safe_browsing", "severity": "critical",
                                "url": (m.get("threat") or {}).get("url"),
                                "threatType": m.get("threatType")})
    return result
