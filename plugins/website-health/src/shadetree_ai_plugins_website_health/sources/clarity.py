"""Microsoft Clarity Data Export API (project-live-insights).

Hard limits: 10 calls/project/day shared with every other tool, only the last
1-3 rolling days (24/48/72h from call time, UTC), 1,000 rows, no pagination, no
backfill. With no scheduler, each run asks for just enough days to cover the
time since the previous snapshot; anything older than 72h is a permanent gap.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from .. import credentials, http
from ..store import Flag, Row, SourceResult

NAME = "clarity"
URL = "https://www.clarity.ms/export-data/api/v1/project-live-insights"
DAILY_BUDGET = 3
MIN_HOURS_BETWEEN_RUNS = 12

FRICTION = {
    "deadclickcount": "deadClickPct", "rageclickcount": "rageClickPct",
    "excessivescroll": "excessiveScrollPct", "quickbackclick": "quickbackPct",
    "scripterrorcount": "scriptErrorPct", "errorclickcount": "errorClickPct",
}


class ClarityQuotaError(RuntimeError):
    pass


def enabled(site: dict) -> tuple[bool, str]:
    return (bool(site.get("clarityProjectId")), "clarityProjectId not set")


def _num(value) -> float | None:
    if value is None or value == "":
        return None
    try:
        return float(str(value).replace("%", ""))
    except ValueError:
        return None


def _lower(item: dict) -> dict:
    return {str(k).lower(): v for k, v in item.items()}


def parse(blocks: list[dict], period_end: str, period_start: str, grain: str,
          by_url: bool = False) -> list[Row]:
    rows: list[Row] = []

    def add(metric: str, value, dim: str = "") -> None:
        v = _num(value)
        if v is not None:
            rows.append(Row(f"clarity.{metric}", period_end, v, grain=grain, dim=dim,
                            period_start=period_start))

    for block in blocks or []:
        name = str(block.get("metricName", "")).replace(" ", "").lower()
        for raw in block.get("information") or []:
            item = _lower(raw)
            dim = f"page={item['url']}" if by_url and item.get("url") else ""
            if by_url and not dim:
                continue
            if name == "traffic":
                add("sessions", item.get("totalsessioncount"), dim)
                add("botSessions", item.get("totalbotsessioncount"), dim)
                add("distinctUsers", item.get("distinctusercount", item.get("distantusercount")),
                    dim)
                add("pagesPerSession", item.get("pagespersessionpercentage"), dim)
                sessions = _num(item.get("totalsessioncount"))
                bots = _num(item.get("totalbotsessioncount"))
                if sessions and bots is not None:
                    add("botSharePct", 100 * bots / (sessions + bots), dim)
            elif name in FRICTION:
                add(FRICTION[name], item.get("sessionswithmetricpercentage"), dim)
                add(FRICTION[name].replace("Pct", "Sessions"), item.get("subtotal"), dim)
            elif name == "scrolldepth":
                add("scrollDepthPct", item.get("averagescrolldepth"), dim)
            elif name == "engagementtime":
                add("totalTime", item.get("totaltime"), dim)
                add("activeTime", item.get("activetime"), dim)
    return rows


def plan_window(last_call_iso: str | None, now: datetime) -> tuple[int, float | None]:
    """Return (numOfDays, gap_hours_lost) for a call made at ``now``."""
    if not last_call_iso:
        return 1, None
    hours = (now - datetime.fromisoformat(last_call_iso)).total_seconds() / 3600
    if hours <= 24:
        return 1, None
    if hours <= 48:
        return 2, None
    return 3, (hours - 72 if hours > 72 else None)


def _call(token: str, num_days: int, dimension: str | None) -> list[dict]:
    params = {"numOfDays": num_days}
    if dimension:
        params["dimension1"] = dimension
    try:
        resp = http.request("GET", URL, params=params,
                            headers={"Authorization": f"Bearer {token}"})
    except http.HttpError as exc:
        if exc.status == 429:
            raise ClarityQuotaError("Clarity's 10-calls/day quota is used up for this project "
                                    "(possibly by another tool). Try again after it resets.")
        if exc.status == 401:
            raise http.HttpError("Clarity token rejected (401). A project admin must "
                                 "generate a new one; then run doctor.", 401) from None
        if exc.status == 403:
            raise http.HttpError("Clarity token belongs to a different project (403).",
                                 403) from None
        raise
    return resp.data if isinstance(resp.data, list) else []


def collect(site: dict, store, backfill_days: int = 0, force: bool = False) -> SourceResult:
    result = SourceResult(NAME)
    name = site["name"]
    token = credentials.read("clarity-token", name)
    if not token:
        raise http.HttpError(f"setup_required: clarity-token.{name} is not stored.")
    now = datetime.now(UTC)
    last = store.get(name, "clarity.lastCallAt")
    if last and not force:
        age = (now - datetime.fromisoformat(last)).total_seconds() / 3600
        if age < MIN_HOURS_BETWEEN_RUNS:
            result.warnings.append(f"Clarity was snapshotted {age:.1f}h ago; skipped to save the "
                                   "10-calls/day quota.")
            result.summary["skipped"] = True
            return result
    used = store.calls_today(name, NAME)
    if used + 2 > DAILY_BUDGET:
        result.warnings.append(f"Clarity call budget for today reached ({used}/{DAILY_BUDGET}).")
        result.summary["skipped"] = True
        return result
    num_days, lost = plan_window(last, now)
    grain = {1: "rolling24h", 2: "rolling48h", 3: "rolling72h"}[num_days]
    period_end = now.date().isoformat()
    period_start = (now - timedelta(days=num_days)).date().isoformat()
    store.record_call(name, NAME)
    totals = _call(token, num_days, None)
    store.put(name, "clarity.lastCallAt", now.replace(microsecond=0).isoformat())
    store.snapshot(name, NAME, f"totals-{num_days}d", totals)
    result.rows += parse(totals, period_end, period_start, grain)
    try:
        store.record_call(name, NAME)
        pages = _call(token, num_days, "URL")
        store.snapshot(name, NAME, f"by-url-{num_days}d", pages)
        result.rows += parse(pages, period_end, period_start, grain, by_url=True)
    except (http.HttpError, ClarityQuotaError) as exc:
        result.warnings.append(f"Clarity per-URL breakdown: {exc}")
    if lost:
        result.flags.append(Flag(NAME, period_end, "gap",
                                 f"~{lost:.0f}h of Clarity data before this window is lost"))
        result.warnings.append(f"Clarity: about {lost:.0f} hours since the last snapshot are "
                               "beyond the API's 72h window and can't be recovered.")
    if num_days > 1:
        result.warnings.append(f"Clarity window is {num_days} days aggregated (no per-day split).")
    result.summary.update({"numOfDays": num_days, "grain": grain,
                           "callsUsedToday": store.calls_today(name, NAME)})
    return result
