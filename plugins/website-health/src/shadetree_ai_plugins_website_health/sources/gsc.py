"""Google Search Console: search analytics, sitemaps, sampled URL Inspection.

Pulls 14 days with ``dataState=all`` and marks every day at or after the API's
``firstIncompleteDate`` provisional, instead of guessing a fixed lag. URL
Inspection is capped at 2,000/day/property, so it is sampled.
"""

from __future__ import annotations

import urllib.parse
from datetime import timedelta

from .. import dates, google_auth, http
from ..store import Flag, Row, SourceResult

NAME = "gsc"
BASE = "https://searchconsole.googleapis.com/webmasters/v3"
INSPECT = "https://searchconsole.googleapis.com/v1/urlInspection/index:inspect"
WINDOW_DAYS = 14
FINAL_LAG_DAYS = 3
INSPECTION_DAILY_BUDGET = 200


def enabled(site: dict) -> tuple[bool, str]:
    return (bool(site.get("gscSiteUrl")), "gscSiteUrl not set")


def _site_path(site_url: str) -> str:
    return urllib.parse.quote(site_url, safe="")


def query(site_url: str, body: dict) -> dict:
    resp = http.request("POST", f"{BASE}/sites/{_site_path(site_url)}/searchAnalytics/query",
                        headers=google_auth.headers(NAME), json_body=body, retries=1)
    return resp.data or {}


def first_incomplete(data: dict) -> str | None:
    meta = data.get("metadata") or {}
    value = meta.get("firstIncompleteDate") or meta.get("first_incomplete_date")
    return value[:10] if value else None


def parse_daily(data: dict, provisional_from: str) -> list[Row]:
    rows = []
    for r in data.get("rows") or []:
        day = r["keys"][0]
        prov = day >= provisional_from
        rows += [Row("gsc.clicks", day, r.get("clicks"), provisional=prov),
                 Row("gsc.impressions", day, r.get("impressions"), provisional=prov),
                 Row("gsc.ctr", day, r.get("ctr"), provisional=prov),
                 Row("gsc.position", day, r.get("position"), provisional=prov)]
    return rows


def parse_dim(data: dict, provisional_from: str, kind: str) -> list[Row]:
    rows = []
    for r in data.get("rows") or []:
        day, key = r["keys"][0], r["keys"][1]
        prov = day >= provisional_from
        dim = f"{kind}={key}"
        rows += [Row("gsc.clicks", day, r.get("clicks"), dim=dim, provisional=prov),
                 Row("gsc.impressions", day, r.get("impressions"), dim=dim, provisional=prov),
                 Row("gsc.position", day, r.get("position"), dim=dim, provisional=prov)]
    return rows


def parse_sitemaps(data: dict) -> list[dict]:
    findings = []
    for sm in data.get("sitemap") or []:
        errors, warns = int(sm.get("errors") or 0), int(sm.get("warnings") or 0)
        contents = sm.get("contents") or []
        submitted = sum(int(c.get("submitted") or 0) for c in contents)
        if errors or warns:
            findings.append({"source": NAME, "kind": "sitemap_issue", "path": sm.get("path"),
                             "errors": errors, "warnings": warns,
                             "lastDownloaded": sm.get("lastDownloaded"), "submitted": submitted})
        if sm.get("isPending"):
            findings.append({"source": NAME, "kind": "sitemap_pending", "path": sm.get("path")})
    return findings


def collect(site: dict, store, backfill_days: int = 0) -> SourceResult:
    tz = site["timezone"]
    end = dates.days_ago(tz, 0)
    start = end - timedelta(days=max(WINDOW_DAYS, backfill_days))
    site_url = site["gscSiteUrl"]
    result = SourceResult(NAME)
    base = {"startDate": start.isoformat(), "endDate": end.isoformat(), "type": "web",
            "dataState": "all", "aggregationType": "auto"}
    daily = query(site_url, {**base, "dimensions": ["date"], "rowLimit": 500})
    store.snapshot(site["name"], NAME, "daily", daily)
    provisional_from = first_incomplete(daily) or (end - timedelta(days=FINAL_LAG_DAYS)).isoformat()
    result.rows += parse_daily(daily, provisional_from)
    pages = query(site_url, {**base, "dimensions": ["date", "page"], "rowLimit": 5000})
    result.rows += parse_dim(pages, provisional_from, "page")
    queries = query(site_url, {**base, "dimensions": ["date", "query"], "rowLimit": 5000})
    result.rows += parse_dim(queries, provisional_from, "query")
    try:
        sitemaps = http.request("GET", f"{BASE}/sites/{_site_path(site_url)}/sitemaps",
                                headers=google_auth.headers(NAME)).data or {}
        result.findings += parse_sitemaps(sitemaps)
        result.raw["sitemaps"] = sitemaps
    except http.HttpError as exc:
        result.warnings.append(f"sitemaps: {exc}")
    result.summary = {"start": start.isoformat(), "end": end.isoformat(),
                      "provisionalFrom": provisional_from}
    for data, label in ((pages, "page"), (queries, "query")):
        if len(data.get("rows") or []) >= 5000:
            result.flags.append(Flag(NAME, end.isoformat(), "row_limit",
                                     f"{label} breakdown hit the 5,000-row cap"))
    return result


def inspect(site: dict, store, urls: list[str]) -> dict:
    used = store.calls_today(site["name"], "gsc_inspect")
    remaining = INSPECTION_DAILY_BUDGET - used
    results, skipped = [], []
    for url in urls:
        if remaining <= 0:
            skipped.append(url)
            continue
        try:
            resp = http.request("POST", INSPECT, headers=google_auth.headers(NAME), json_body={
                "inspectionUrl": url, "siteUrl": site["gscSiteUrl"]})
            store.record_call(site["name"], "gsc_inspect")
            remaining -= 1
            results.append(summarize_inspection(url, resp.data or {}))
        except http.HttpError as exc:
            results.append({"url": url, "error": str(exc)})
            if exc.status == 429:
                break
    return {"results": results, "skippedForBudget": skipped,
            "budgetRemainingToday": max(remaining, 0)}


def summarize_inspection(url: str, data: dict) -> dict:
    res = data.get("inspectionResult") or {}
    idx = res.get("indexStatusResult") or {}
    rich = res.get("richResultsResult") or {}
    out = {
        "url": url, "verdict": idx.get("verdict"), "coverageState": idx.get("coverageState"),
        "indexingState": idx.get("indexingState"), "robotsTxtState": idx.get("robotsTxtState"),
        "pageFetchState": idx.get("pageFetchState"), "lastCrawlTime": idx.get("lastCrawlTime"),
        "googleCanonical": idx.get("googleCanonical"), "userCanonical": idx.get("userCanonical"),
        "richResultsVerdict": rich.get("verdict"),
        "richResultIssues": [
            {"type": item.get("richResultType"),
             "issues": [i.get("issueMessage") for i in item.get("issues", [])]}
            for item in rich.get("detectedItems", [])
            if any(i.get("severity") == "ERROR" for i in item.get("issues", []))],
    }
    if out["googleCanonical"] and out["userCanonical"] and \
            out["googleCanonical"] != out["userCanonical"]:
        out["canonicalMismatch"] = True
    return out


def discover() -> list[dict]:
    resp = http.request("GET", f"{BASE}/sites", headers=google_auth.headers(NAME))
    return [{"gscSiteUrl": s["siteUrl"], "permission": s.get("permissionLevel")}
            for s in (resp.data or {}).get("siteEntry", [])]
