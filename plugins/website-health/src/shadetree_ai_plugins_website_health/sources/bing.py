"""Bing Webmaster Tools JSON API (API-key auth, ``{"d": ...}`` envelope).

Traffic and crawl stats are daily; query and page stats arrive in weekly
buckets. Dates come as ``/Date(1316156400000-0700)/``.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta

from .. import credentials, http
from ..store import Row, SourceResult

NAME = "bing"
BASE = "https://ssl.bing.com/webmaster/api.svc/json"
DATE_RE = re.compile(r"/Date\((-?\d+)([+-]\d{4})?\)/")
CRAWL_FIELDS = {"Code2xx": "crawl2xx", "Code301": "crawl301", "Code302": "crawl302",
                "Code4xx": "crawl4xx", "Code5xx": "crawl5xx", "CrawledPages": "crawledPages",
                "CrawlErrors": "crawlErrors", "InIndex": "inIndex", "InLinks": "inLinks",
                "BlockedByRobotsTxt": "blockedByRobots", "ContainsMalware": "malwarePages",
                "AllOtherCodes": "crawlOtherCodes"}


def enabled(site: dict) -> tuple[bool, str]:
    return (bool(site.get("bingSiteUrl")), "bingSiteUrl not set")


def parse_date(value: str) -> str | None:
    """Return the calendar date Bing meant, honouring its offset annotation."""
    m = DATE_RE.search(str(value or ""))
    if not m:
        return None
    moment = datetime.fromtimestamp(int(m.group(1)) / 1000, UTC)
    if m.group(2):
        sign = 1 if m.group(2)[0] == "+" else -1
        moment += sign * timedelta(hours=int(m.group(2)[1:3]), minutes=int(m.group(2)[3:5]))
    return moment.date().isoformat()


def call(method: str, key: str, **params) -> object:
    try:
        resp = http.request("GET", f"{BASE}/{method}", params=params,
                            secret_params={"apikey": key}, retries=2)
    except http.HttpError as exc:
        body = exc.body if isinstance(exc.body, dict) else {}
        if "InvalidApiKey" in str(body.get("Message", "")):
            raise http.HttpError("Bing rejected the API key (InvalidApiKey). Regenerate it in "
                                 "Bing Webmaster Tools > Settings > API Access; then run doctor.",
                                 exc.status) from None
        raise
    data = resp.data
    return data.get("d") if isinstance(data, dict) and "d" in data else data


def _key() -> str:
    key = credentials.read("bing-api-key")
    if not key:
        raise http.HttpError("setup_required: bing-api-key is not stored.")
    return key


def parse_traffic(items: list, final_before: str) -> list[Row]:
    rows = []
    for it in items or []:
        day = parse_date(it.get("Date"))
        if not day:
            continue
        prov = day >= final_before
        rows += [Row("bing.clicks", day, it.get("Clicks"), provisional=prov),
                 Row("bing.impressions", day, it.get("Impressions"), provisional=prov)]
    return rows


def parse_crawl(items: list) -> list[Row]:
    rows = []
    for it in items or []:
        day = parse_date(it.get("Date"))
        if not day:
            continue
        for field, metric in CRAWL_FIELDS.items():
            if it.get(field) is not None:
                rows.append(Row(f"bing.{metric}", day, it.get(field)))
    return rows


def parse_weekly(items: list, kind: str) -> list[Row]:
    rows = []
    for it in items or []:
        day = parse_date(it.get("Date"))
        label = it.get("Query")
        if not day or not label:
            continue
        dim = f"{kind}={label}"
        rows += [Row("bing.clicks", day, it.get("Clicks"), grain="week", dim=dim),
                 Row("bing.impressions", day, it.get("Impressions"), grain="week", dim=dim),
                 Row("bing.position", day, it.get("AvgImpressionPosition"), grain="week",
                     dim=dim)]
    return rows


def collect(site: dict, store, backfill_days: int = 0) -> SourceResult:
    key = _key()
    site_url = site["bingSiteUrl"]
    result = SourceResult(NAME)
    final_before = (datetime.now(UTC).date() - timedelta(days=2)).isoformat()
    traffic = call("GetRankAndTrafficStats", key, siteUrl=site_url)
    store.snapshot(site["name"], NAME, "traffic", traffic)
    result.rows += parse_traffic(traffic, final_before)
    calls = {"GetCrawlStats": parse_crawl,
             "GetQueryStats": lambda d: parse_weekly(d, "query"),
             "GetPageStats": lambda d: parse_weekly(d, "page")}
    for method, parser in calls.items():
        try:
            data = call(method, key, siteUrl=site_url)
            store.snapshot(site["name"], NAME, method, data)
            result.rows += parser(data)
        except http.HttpError as exc:
            result.warnings.append(f"{method}: {exc}")
    try:
        issues = call("GetCrawlIssues", key, siteUrl=site_url) or []
        store.snapshot(site["name"], NAME, "GetCrawlIssues", issues)
        if issues:
            result.findings.append({"source": NAME, "kind": "crawl_issues", "count": len(issues),
                                    "sample": [{"url": i.get("Url"), "issues": i.get("Issues"),
                                                "httpCode": i.get("HttpCode")}
                                               for i in issues[:20]]})
    except http.HttpError as exc:
        result.warnings.append(f"GetCrawlIssues: {exc}")
    try:
        feeds = call("GetFeeds", key, siteUrl=site_url) or []
        store.snapshot(site["name"], NAME, "GetFeeds", feeds)
        for feed in feeds:
            status = str(feed.get("Status", ""))
            if status and status.lower() not in ("success", "ok", "processed", "0"):
                result.findings.append({"source": NAME, "kind": "sitemap_issue",
                                        "path": feed.get("Url"), "status": status,
                                        "lastCrawled": parse_date(feed.get("LastCrawled"))})
    except http.HttpError as exc:
        result.warnings.append(f"GetFeeds: {exc}")
    return result


def discover() -> list[dict]:
    sites = call("GetUserSites", _key()) or []
    return [{"bingSiteUrl": s.get("Url"), "verified": s.get("IsVerified")} for s in sites]


def url_info(site: dict, url: str) -> dict:
    info = call("GetUrlInfo", _key(), siteUrl=site["bingSiteUrl"], url=url) or {}
    return {"url": url, "httpStatus": info.get("HttpStatus"),
            "lastCrawled": parse_date(info.get("LastCrawledDate")),
            "discovered": parse_date(info.get("DiscoveryDate")),
            "documentSize": info.get("DocumentSize"), "anchorCount": info.get("AnchorCount")}
