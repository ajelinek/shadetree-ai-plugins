"""Sentry: daily error counts (stats_v2) and new issues for one project."""

from __future__ import annotations

from datetime import UTC, datetime

from .. import credentials, dates, http
from ..store import Row, SourceResult

NAME = "sentry"


def enabled(site: dict) -> tuple[bool, str]:
    return (bool(site.get("sentryOrg") and site.get("sentryProject")),
            "sentryOrg / sentryProject not set")


def _headers() -> dict:
    token = credentials.read("sentry-token")
    if not token:
        raise http.HttpError("setup_required: sentry-token is not stored.")
    return {"Authorization": f"Bearer {token}"}


def parse_stats(data: dict, tz: str) -> list[Row]:
    rows = []
    intervals = data.get("intervals") or []
    totals = [0.0] * len(intervals)
    for group in data.get("groups") or []:
        if (group.get("by") or {}).get("outcome", "accepted") != "accepted":
            continue
        for i, v in enumerate((group.get("series") or {}).get("sum(quantity)") or []):
            totals[i] += v or 0
    for stamp, total in zip(intervals, totals):
        day = dates.utc_to_local_date(datetime.fromisoformat(stamp.replace("Z", "+00:00")), tz)
        rows.append(Row("sentry.errors", day, total))
    return rows


def collect(site: dict, store, backfill_days: int = 0) -> SourceResult:
    base = (site.get("sentryBaseUrl") or "https://sentry.io").rstrip("/") + "/api/0"
    org, slug = site["sentryOrg"], site["sentryProject"]
    headers = _headers()
    project = http.request("GET", f"{base}/projects/{org}/{slug}/", headers=headers).data or {}
    stats = http.request("GET", f"{base}/organizations/{org}/stats_v2/", headers=headers, params={
        "field": "sum(quantity)", "category": "error", "interval": "1d", "statsPeriod": "28d",
        "groupBy": "outcome", "project": project.get("id")}).data or {}
    store.snapshot(site["name"], NAME, "stats_v2", stats)
    result = SourceResult(NAME)
    result.rows = parse_stats(stats, site["timezone"])
    today = dates.today(site["timezone"]).isoformat()
    for r in result.rows:
        r.provisional = r.period_end == today
    issues = http.request("GET", f"{base}/projects/{org}/{slug}/issues/", headers=headers, params={
        "query": "is:unresolved firstSeen:-24h", "statsPeriod": "24h", "sort": "freq",
        "limit": 25}).data or []
    result.summary["newIssues24h"] = len(issues)
    for issue in issues[:10]:
        result.findings.append({
            "source": NAME, "kind": "new_issue", "severity": "warn",
            "title": issue.get("title"), "culprit": issue.get("culprit"),
            "count": issue.get("count"), "firstSeen": issue.get("firstSeen"),
            "release": (issue.get("firstRelease") or {}).get("version"),
            "link": issue.get("permalink")})
    result.summary["checkedAt"] = datetime.now(UTC).isoformat()
    return result


def validate(token: str, base_url: str = "https://sentry.io") -> str:
    http.request("GET", f"{base_url.rstrip('/')}/api/0/",
                 headers={"Authorization": f"Bearer {token}"})
    return "token accepted"
