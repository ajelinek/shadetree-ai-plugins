"""Chrome UX Report API: field Core Web Vitals (p75, rolling 28 days).

``queryHistoryRecord`` gives up to 40 weekly collection periods; stored at
``week`` grain keyed by each period's last date. A 404 means the origin/URL has
too little Chrome traffic, which is reported as "insufficient data", not an error.
"""

from __future__ import annotations

from .. import credentials, http
from ..store import Row, SourceResult

NAME = "crux"
BASE = "https://chromeuxreport.googleapis.com/v1/records"
METRICS = {
    "largest_contentful_paint": "lcpP75",
    "interaction_to_next_paint": "inpP75",
    "cumulative_layout_shift": "clsP75",
    "first_contentful_paint": "fcpP75",
    "experimental_time_to_first_byte": "ttfbP75",
}
# web.dev "good" / "poor" boundaries at p75.
THRESHOLDS = {"lcpP75": (2500, 4000), "inpP75": (200, 500), "clsP75": (0.1, 0.25),
              "fcpP75": (1800, 3000), "ttfbP75": (800, 1800)}
FORM_FACTORS = ("PHONE", "DESKTOP")


def enabled(site: dict) -> tuple[bool, str]:
    return (True, "")


def _date(d: dict) -> str:
    return f"{d['year']:04d}-{d['month']:02d}-{d['day']:02d}"


def rating(metric: str, value: float) -> str:
    good, poor = THRESHOLDS[metric]
    return "good" if value <= good else "poor" if value > poor else "needs_improvement"


def parse_history(data: dict, dim: str) -> list[Row]:
    record = data.get("record") or {}
    periods = record.get("collectionPeriods") or []
    rows = []
    for api_name, metric in METRICS.items():
        series = ((record.get("metrics") or {}).get(api_name) or {}).get(
            "percentilesTimeseries") or {}
        for period, value in zip(periods, series.get("p75s") or []):
            if value is None:
                continue
            rows.append(Row(f"crux.{metric}", _date(period["lastDate"]), float(value),
                            grain="week", dim=dim, period_start=_date(period["firstDate"])))
    return rows


def _query(endpoint: str, key: str, body: dict) -> dict | None:
    try:
        return http.request("POST", f"{BASE}:{endpoint}", secret_params={"key": key},
                            json_body=body, retries=1).data
    except http.HttpError as exc:
        if exc.status == 404:
            return None
        raise


def collect(site: dict, store, backfill_days: int = 0) -> SourceResult:
    key = credentials.read("google-api-key")
    if not key:
        raise http.HttpError("setup_required: google-api-key is not stored.")
    result = SourceResult(NAME)
    targets = [("origin", site["url"], "")] + [
        ("url", u if u.startswith("http") else site["url"] + u, f"url={u}")
        for u in site.get("cruxUrls") or []]
    insufficient = []
    for kind, target, base_dim in targets:
        for ff in FORM_FACTORS:
            dim = ",".join(x for x in (base_dim, f"formFactor={ff}") if x)
            body = {kind: target, "formFactor": ff, "metrics": list(METRICS)}
            data = _query("queryHistoryRecord", key, body)
            if data is None:
                insufficient.append(f"{target} ({ff})")
                continue
            store.snapshot(site["name"], NAME, f"history-{kind}-{ff}", data)
            rows = parse_history(data, dim)
            result.rows += rows
            if kind == "origin" and ff == "PHONE":
                # Site total = phone origin (most traffic); keep a dim-less copy for detection.
                result.rows += [Row(r.metric, r.period_end, r.value, grain="week",
                                    period_start=r.period_start) for r in rows]
            latest = {}
            for r in rows:
                if r.period_end >= latest.get(r.metric, ("", 0))[0]:
                    latest[r.metric] = (r.period_end, r.value)
            for metric, (_, value) in latest.items():
                verdict = rating(metric, value)
                if verdict != "good" and metric in ("lcpP75", "inpP75", "clsP75"):
                    result.findings.append({"source": NAME, "kind": "core_web_vital",
                                            "target": target, "formFactor": ff,
                                            "metric": metric, "p75": value, "rating": verdict})
    if insufficient:
        result.warnings.append("CrUX has insufficient traffic data for: "
                               + ", ".join(insufficient))
    return result
