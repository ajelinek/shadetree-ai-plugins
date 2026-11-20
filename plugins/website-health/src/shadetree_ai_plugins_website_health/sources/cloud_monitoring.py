"""Google Cloud Monitoring time series (service account, monitoring.read).

Two presets plus any custom queries in ``cloudMonitoringQueries``:

- ``uptime``: ``monitoring.googleapis.com/uptime_check/check_passed`` (Cloud uptime checks)
- ``hosting``: Firebase Hosting responses grouped by status class. Requires Cloud
  Logging to be linked to Firebase Hosting; the metric type is configurable because
  it depends on that integration.

Custom query shape: ``{"name": "responses5xx", "filter": "metric.type=\\"...\\"",
"aligner": "ALIGN_SUM", "reducer": "REDUCE_SUM", "groupBy": ["metric.label.status"]}``.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from .. import dates, google_auth, http
from ..store import Row, SourceResult

NAME = "cloud_monitoring"
URL = "https://monitoring.googleapis.com/v3/projects/{project}/timeSeries"
PRESETS = {
    "uptime": {"name": "uptimeCheckPassed",
               "filter": 'metric.type="monitoring.googleapis.com/uptime_check/check_passed"',
               "aligner": "ALIGN_FRACTION_TRUE", "reducer": "REDUCE_MEAN", "groupBy": []},
    "hosting": {"name": "responses",
                "filter": 'metric.type="logging.googleapis.com/user/firebase-hosting-responses"',
                "aligner": "ALIGN_SUM", "reducer": "REDUCE_SUM",
                "groupBy": ["metric.label.status"]},
}


def enabled(site: dict) -> tuple[bool, str]:
    return (bool(site.get("cloudMonitoringProjectId") and site.get("cloudMonitoringQueries")),
            "cloudMonitoringProjectId / cloudMonitoringQueries not set")


def resolve(query) -> dict:
    return PRESETS[query] if isinstance(query, str) else query


def parse(data: dict, name: str, tz: str) -> list[Row]:
    rows: dict[tuple[str, str], float] = {}
    for series in data.get("timeSeries") or []:
        labels = (series.get("metric") or {}).get("labels") or {}
        status = labels.get("status") or labels.get("response_code") or ""
        for point in series.get("points") or []:
            end = point["interval"]["endTime"]
            day = dates.utc_to_local_date(
                datetime.fromisoformat(end.replace("Z", "+00:00")) - timedelta(seconds=1), tz)
            val = point.get("value") or {}
            v = float(val.get("doubleValue", val.get("int64Value", 0)) or 0)
            bucket = f"status={status[:1]}xx" if status[:1].isdigit() else ""
            rows[day, bucket] = rows.get((day, bucket), 0) + v
    out = [Row(f"cloud_monitoring.{name}", day, v, dim=dim) for (day, dim), v in rows.items()]
    by_day: dict[str, float] = {}
    for (day, dim), v in rows.items():
        if dim == "status=5xx":
            by_day[day] = by_day.get(day, 0) + v
    out += [Row("cloud_monitoring.responses5xx", day, v) for day, v in by_day.items()]
    return out


def collect(site: dict, store, backfill_days: int = 0) -> SourceResult:
    result = SourceResult(NAME)
    end = datetime.now(UTC).replace(minute=0, second=0, microsecond=0)
    start = end - timedelta(days=max(28, backfill_days))
    for q in site["cloudMonitoringQueries"]:
        q = resolve(q)
        params = {"filter": q["filter"], "interval.startTime": start.isoformat(),
                  "interval.endTime": end.isoformat(),
                  "aggregation.alignmentPeriod": "86400s",
                  "aggregation.perSeriesAligner": q.get("aligner", "ALIGN_SUM"),
                  "aggregation.crossSeriesReducer": q.get("reducer", "REDUCE_SUM"),
                  "aggregation.groupByFields": q.get("groupBy") or None}
        try:
            data = http.request("GET", URL.format(project=site["cloudMonitoringProjectId"]),
                                params=params, headers=google_auth.headers(NAME)).data or {}
        except http.HttpError as exc:
            result.warnings.append(f"{q['name']}: {exc}")
            continue
        store.snapshot(site["name"], NAME, q["name"], data)
        result.rows += parse(data, q["name"], site["timezone"])
        if not data.get("timeSeries"):
            result.warnings.append(f"{q['name']}: no time series matched {q['filter']}")
    return result
