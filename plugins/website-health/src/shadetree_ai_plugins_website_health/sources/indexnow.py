"""IndexNow: key-file reachability check and (confirmed) URL submission.

Participants include Bing, Yandex, Seznam, Naver and Yep; Google does not use
IndexNow. The key is public by design (served at ``/<key>.txt``).
"""

from __future__ import annotations

import urllib.parse

from .. import http
from ..store import SourceResult

NAME = "indexnow"
ENDPOINT = "https://api.indexnow.org/indexnow"
MAX_URLS = 10_000
STATUS = {200: "accepted", 202: "accepted; key validation pending",
          400: "bad request", 403: "key not valid (file missing or mismatched)",
          422: "URLs don't belong to the host or key doesn't match",
          429: "too many requests (possible spam signal)"}


def enabled(site: dict) -> tuple[bool, str]:
    return (bool(site.get("indexnowKey")), "indexnowKey not set")


def key_location(site: dict) -> str:
    return f"{site['url']}/{site['indexnowKey']}.txt"


def collect(site: dict, store, backfill_days: int = 0) -> SourceResult:
    result = SourceResult(NAME)
    location = key_location(site)
    try:
        body = http.request("GET", location, expect_json=False, timeout=15).data.strip()
        ok = body == site["indexnowKey"]
        result.summary = {"keyFile": location, "reachable": True, "matches": ok}
        if not ok:
            result.findings.append({"source": NAME, "kind": "indexnow_key_mismatch",
                                    "severity": "warn", "url": location})
    except http.HttpError as exc:
        result.summary = {"keyFile": location, "reachable": False}
        result.findings.append({"source": NAME, "kind": "indexnow_key_missing",
                                "severity": "warn", "url": location, "error": str(exc)})
    return result


def submit(site: dict, urls: list[str]) -> dict:
    host = urllib.parse.urlparse(site["url"]).hostname
    bad = [u for u in urls if urllib.parse.urlparse(u).hostname != host]
    if bad:
        return {"ok": False, "error": "urls_off_host", "urls": bad[:20]}
    if not urls or len(urls) > MAX_URLS:
        return {"ok": False, "error": f"Submit 1-{MAX_URLS} URLs."}
    body = {"host": host, "key": site["indexnowKey"], "keyLocation": key_location(site),
            "urlList": urls}
    try:
        resp = http.request("POST", ENDPOINT, json_body=body, expect_json=False)
        code = resp.status
    except http.HttpError as exc:
        code = exc.status or 0
    return {"ok": code in (200, 202), "status": code,
            "meaning": STATUS.get(code, "unexpected response"), "submitted": len(urls)}
