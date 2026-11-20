"""Cloudflare GraphQL Analytics (``httpRequests1dGroups``) for proxied zones."""

from __future__ import annotations

from datetime import timedelta

from .. import credentials, dates, http
from ..store import Row, SourceResult

NAME = "cloudflare"
URL = "https://api.cloudflare.com/client/v4/graphql"
QUERY = """query($zone: String!, $start: Date!, $end: Date!) {
  viewer { zones(filter: {zoneTag: $zone}) {
    httpRequests1dGroups(limit: 40, filter: {date_geq: $start, date_leq: $end},
                         orderBy: [date_ASC]) {
      dimensions { date }
      sum { requests cachedRequests threats pageViews bytes
            responseStatusMap { edgeResponseStatus requests } }
      uniq { uniques }
    } } } }"""


def enabled(site: dict) -> tuple[bool, str]:
    return (bool(site.get("cloudflareZoneId")), "cloudflareZoneId not set")


def _token() -> str:
    token = credentials.read("cloudflare-token")
    if not token:
        raise http.HttpError("setup_required: cloudflare-token is not stored.")
    return token


def parse(data: dict) -> list[Row]:
    rows = []
    zones = ((data.get("data") or {}).get("viewer") or {}).get("zones") or []
    for group in (zones[0].get("httpRequests1dGroups") if zones else []) or []:
        day = group["dimensions"]["date"]
        s = group.get("sum") or {}
        requests = s.get("requests") or 0
        rows += [Row("cloudflare.requests", day, requests),
                 Row("cloudflare.pageViews", day, s.get("pageViews")),
                 Row("cloudflare.threats", day, s.get("threats")),
                 Row("cloudflare.uniques", day, (group.get("uniq") or {}).get("uniques"))]
        if requests:
            rows.append(Row("cloudflare.cacheRatio", day,
                            100 * (s.get("cachedRequests") or 0) / requests))
        buckets: dict[str, float] = {}
        for entry in s.get("responseStatusMap") or []:
            cls = f"{str(entry['edgeResponseStatus'])[:1]}xx"
            buckets[cls] = buckets.get(cls, 0) + entry["requests"]
        rows += [Row("cloudflare.status4xx", day, buckets.get("4xx", 0)),
                 Row("cloudflare.status5xx", day, buckets.get("5xx", 0))]
    return rows


def collect(site: dict, store, backfill_days: int = 0) -> SourceResult:
    end = dates.today(site["timezone"])
    start = end - timedelta(days=min(max(28, backfill_days), 30))
    data = http.request("POST", URL, headers={"Authorization": f"Bearer {_token()}"},
                        json_body={"query": QUERY, "variables": {
                            "zone": site["cloudflareZoneId"], "start": start.isoformat(),
                            "end": end.isoformat()}}).data or {}
    if data.get("errors"):
        raise http.HttpError(f"Cloudflare GraphQL: {data['errors'][0].get('message')}")
    store.snapshot(site["name"], NAME, "httpRequests1dGroups", data)
    result = SourceResult(NAME)
    result.rows = parse(data)
    today = end.isoformat()
    for r in result.rows:
        r.provisional = r.period_end == today
    return result


def validate(token: str) -> str:
    data = http.request("GET", "https://api.cloudflare.com/client/v4/user/tokens/verify",
                        headers={"Authorization": f"Bearer {token}"}).data or {}
    return str((data.get("result") or {}).get("status", "unknown"))
