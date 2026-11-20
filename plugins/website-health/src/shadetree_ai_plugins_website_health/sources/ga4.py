"""GA4 Data API: daily totals, key events, signups, channels, landing pages, AI referrers.

Daily data lands ~12h after the day ends and is revised for 24-48h; late hits can
arrive for 7 days. Every run re-fetches the trailing 7 days and marks the last 2
provisional. Response quality metadata is recorded as flags so detection can lower
confidence on thresholded, sampled, (other)-rolled-up or truncated days.
"""

from __future__ import annotations

from datetime import timedelta

from .. import dates, google_auth, http
from ..store import Flag, Row, SourceResult

NAME = "ga4"
BASE = "https://analyticsdata.googleapis.com/v1beta"
ADMIN = "https://analyticsadmin.googleapis.com/v1beta"
TOTALS = ["sessions", "engagedSessions", "engagementRate", "activeUsers", "newUsers",
          "keyEvents", "screenPageViews"]
REFETCH_DAYS = 7
PROVISIONAL_DAYS = 2


def enabled(site: dict) -> tuple[bool, str]:
    return (bool(site.get("ga4PropertyId")), "ga4PropertyId not set")


def build_requests(start: str, end: str, signup_event: str) -> list[dict]:
    date_range = [{"startDate": start, "endDate": end}]
    return [
        {"dateRanges": date_range, "dimensions": [{"name": "date"}],
         "metrics": [{"name": m} for m in TOTALS], "returnPropertyQuota": True},
        {"dateRanges": date_range, "dimensions": [{"name": "date"}],
         "metrics": [{"name": "eventCount"}],
         "dimensionFilter": {"filter": {"fieldName": "eventName",
                                        "stringFilter": {"value": signup_event}}}},
        {"dateRanges": date_range,
         "dimensions": [{"name": "date"}, {"name": "sessionDefaultChannelGroup"}],
         "metrics": [{"name": "sessions"}, {"name": "keyEvents"}], "limit": 10000},
        {"dateRanges": date_range, "dimensions": [{"name": "date"}, {"name": "sessionSource"}],
         "metrics": [{"name": "sessions"}], "limit": 10000},
        {"dateRanges": date_range, "dimensions": [{"name": "date"}, {"name": "landingPage"}],
         "metrics": [{"name": "sessions"}, {"name": "keyEvents"}], "limit": 10000,
         "orderBys": [{"metric": {"metricName": "sessions"}, "desc": True}]},
    ]


def _rows(report: dict) -> list[tuple[list[str], list[float]]]:
    out = []
    for row in report.get("rows") or []:
        dims = [d.get("value", "") for d in row.get("dimensionValues", [])]
        mets = []
        for m in row.get("metricValues", []):
            try:
                mets.append(float(m.get("value", "")))
            except ValueError:
                mets.append(None)
        out.append((dims, mets))
    return out


def quality_flags(report: dict, start: str, end: str) -> list[Flag]:
    meta = report.get("metadata") or {}
    flags: list[Flag] = []
    span = f"{start}..{end}"
    if meta.get("subjectToThresholding"):
        flags.append(Flag(NAME, end, "thresholded", f"rows may be withheld ({span})"))
    if meta.get("dataLossFromOtherRow"):
        flags.append(Flag(NAME, end, "other_row", f"rows folded into (other) ({span})"))
    if meta.get("samplingMetadatas"):
        flags.append(Flag(NAME, end, "sampled", str(meta["samplingMetadatas"])[:200]))
    for reason in meta.get("dataTruncationReasons") or []:
        flags.append(Flag(NAME, end, "truncated", str(reason)[:200]))
    return flags


def parse(reports: list[dict], ai_referrers: list[str], provisional_from: str,
          start: str, end: str) -> SourceResult:
    result = SourceResult(NAME)

    def row(metric: str, day: str, value, dim: str = "") -> None:
        result.rows.append(Row(f"ga4.{metric}", day, value, dim=dim,
                               provisional=day >= provisional_from))

    totals, signups, channels, sources, landing = (reports + [{}] * 5)[:5]
    headers = [h["name"] for h in totals.get("metricHeaders", [])] or TOTALS
    for dims, mets in _rows(totals):
        day = dates.parse_ga4_date(dims[0])
        for name, value in zip(headers, mets):
            row(name, day, value)
    for dims, mets in _rows(signups):
        row("signupEvents", dates.parse_ga4_date(dims[0]), mets[0])
    for dims, mets in _rows(channels):
        day = dates.parse_ga4_date(dims[0])
        row("sessions", day, mets[0], dim=f"channel={dims[1]}")
        row("keyEvents", day, mets[1], dim=f"channel={dims[1]}")
    ai_set = {r.lower() for r in ai_referrers}
    ai_totals: dict[str, float] = {}
    for dims, mets in _rows(sources):
        day = dates.parse_ga4_date(dims[0])
        src = dims[1].lower()
        if src in ai_set or any(src.endswith("." + r) for r in ai_set):
            ai_totals[day] = ai_totals.get(day, 0) + (mets[0] or 0)
            row("aiReferralSessions", day, mets[0], dim=f"source={src}")
    for day in dates.date_range(dates.date.fromisoformat(start), dates.date.fromisoformat(end)):
        key = day.isoformat()
        if any(r.period_end == key and r.metric == "ga4.sessions" and not r.dim
               for r in result.rows):
            row("aiReferralSessions", key, ai_totals.get(key, 0.0))
    for dims, mets in _rows(landing)[:2000]:
        day = dates.parse_ga4_date(dims[0])
        row("sessions", day, mets[0], dim=f"page={dims[1]}")
        row("keyEvents", day, mets[1], dim=f"page={dims[1]}")
    for report in reports:
        result.flags.extend(quality_flags(report, start, end))
    quota = (totals.get("propertyQuota") or {}).get("tokensPerDay") or {}
    if quota:
        result.summary["tokensPerDay"] = quota
    return result


def collect(site: dict, store, backfill_days: int = 0) -> SourceResult:
    tz = site["timezone"]
    end = dates.days_ago(tz, 0)
    start = end - timedelta(days=max(REFETCH_DAYS, backfill_days))
    provisional_from = (end - timedelta(days=PROVISIONAL_DAYS - 1)).isoformat()
    prop = site["ga4PropertyId"]
    resp = http.request(
        "POST", f"{BASE}/properties/{prop}:batchRunReports", headers=google_auth.headers(NAME),
        json_body={"requests": build_requests(start.isoformat(), end.isoformat(),
                                              site.get("ga4SignupEvent") or "sign_up")},
        retries=1)
    store.snapshot(site["name"], NAME, "batchRunReports", resp.data)
    result = parse(resp.data.get("reports", []), site.get("aiReferrers") or [],
                   provisional_from, start.isoformat(), end.isoformat())
    result.summary.update({"start": start.isoformat(), "end": end.isoformat(),
                           "provisionalFrom": provisional_from})
    return result


def realtime(site: dict) -> dict:
    resp = http.request(
        "POST", f"{BASE}/properties/{site['ga4PropertyId']}:runRealtimeReport",
        headers=google_auth.headers(NAME),
        json_body={"metrics": [{"name": "activeUsers"}, {"name": "keyEvents"}],
                   "dimensions": [{"name": "minutesAgo"}], "limit": 30})
    total = 0.0
    for _dims, mets in _rows(resp.data):
        total += mets[0] or 0
    return {"activeUsersLast30Min": total}


def discover() -> list[dict]:
    resp = http.request("GET", f"{ADMIN}/accountSummaries", headers=google_auth.headers(NAME),
                        params={"pageSize": 200})
    out = []
    for account in resp.data.get("accountSummaries", []):
        for prop in account.get("propertySummaries", []):
            out.append({"account": account.get("displayName"),
                        "ga4PropertyId": prop["property"].removeprefix("properties/"),
                        "name": prop.get("displayName")})
    return out


def key_events(site: dict) -> list[str]:
    resp = http.request("GET", f"{ADMIN}/properties/{site['ga4PropertyId']}/keyEvents",
                        headers=google_auth.headers(NAME))
    return [e.get("eventName") for e in resp.data.get("keyEvents", [])]
