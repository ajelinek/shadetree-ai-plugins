"""UptimeRobot (v2 API, read-only key): uptime ratios and recent down events."""

from __future__ import annotations

from datetime import UTC, datetime

from .. import credentials, dates, http
from ..store import Row, SourceResult

NAME = "uptime"
URL = "https://api.uptimerobot.com/v2/getMonitors"
STATUS = {0: "paused", 1: "not checked yet", 2: "up", 8: "seems down", 9: "down"}


def enabled(site: dict) -> tuple[bool, str]:
    return (bool(site.get("uptimeRobotMonitorIds")), "uptimeRobotMonitorIds not set")


def collect(site: dict, store, backfill_days: int = 0) -> SourceResult:
    key = credentials.read("uptimerobot-key")
    if not key:
        raise http.HttpError("setup_required: uptimerobot-key is not stored.")
    ids = "-".join(str(i) for i in site["uptimeRobotMonitorIds"])
    data = http.request("POST", URL, form={"api_key": key, "format": "json", "monitors": ids,
                                           "custom_uptime_ratios": "1-7-30", "logs": 1,
                                           "logs_limit": 50}).data or {}
    if data.get("stat") != "ok":
        raise http.HttpError(f"UptimeRobot: {(data.get('error') or {}).get('message', data)}")
    result = SourceResult(NAME)
    today = dates.today(site["timezone"]).isoformat()
    for mon in data.get("monitors", []):
        ratios = str(mon.get("custom_uptime_ratio", "")).split("-")
        dim = f"monitor={mon.get('friendly_name')}"
        if ratios and ratios[0]:
            result.rows.append(Row("uptime.ratio24h", today, float(ratios[0]), dim=dim))
        status = STATUS.get(mon.get("status"), str(mon.get("status")))
        downs = [{"at": datetime.fromtimestamp(log["datetime"], UTC).isoformat(),
                  "durationSec": log.get("duration"), "reason": (log.get("reason") or {}).get(
                      "detail")} for log in mon.get("logs", []) if log.get("type") == 1]
        result.summary[mon.get("friendly_name")] = {"status": status, "uptime": ratios,
                                                    "recentDowns": downs[:10]}
        if mon.get("status") in (8, 9):
            result.findings.append({"source": NAME, "kind": "monitor_down", "severity": "critical",
                                    "monitor": mon.get("friendly_name")})
    return result


def validate(key: str) -> str:
    data = http.request("POST", "https://api.uptimerobot.com/v2/getAccountDetails",
                        form={"api_key": key, "format": "json"}).data or {}
    if data.get("stat") != "ok":
        raise http.HttpError("UptimeRobot rejected the key.")
    return f"{(data.get('account') or {}).get('monitor_limit', '?')} monitor limit"
