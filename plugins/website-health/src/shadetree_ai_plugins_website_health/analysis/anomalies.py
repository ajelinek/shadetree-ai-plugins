"""Deterministic anomaly detection over the history store (no interpretation).

Port of detect-anomalies.mjs with three changes: baselines only compare rows of
the same grain, provisional periods are never the target or part of the
baseline, and the target period's data-quality flags are attached.
"""

from __future__ import annotations

import statistics
from collections import Counter
from typing import Any

from ..store import Store

MIN_POINTS = {"day": 7, "week": 3, "rolling24h": 5}
LOWER_IS_BETTER = ("position", "crawlErrors", "crawl4xx", "crawl5xx", "Pct", "P75", "5xx",
                   "4xx", "ttfbMs", "botShare", "malwarePages", "blockedByRobots")
EXEMPT_LOWER = ("scrollDepthPct",)


def higher_is_better(metric: str) -> bool:
    if any(x in metric for x in EXEMPT_LOWER):
        return True
    return not any(x in metric for x in LOWER_IS_BETTER)


def evaluate(values: list[float], actual: float, cfg: dict[str, Any]) -> dict[str, Any]:
    mean = statistics.fmean(values)
    method = cfg["method"]
    if method == "zscore":
        sd = statistics.stdev(values) if len(values) > 1 else 0
        if sd == 0:
            return {"status": "skipped", "reason": "zero variance in baseline"}
        delta = (actual - mean) / sd
    elif method == "percentChange":
        if mean == 0:
            return {"status": "skipped", "reason": "baseline mean is 0"}
        delta = (actual - mean) / mean
    elif method == "absoluteDelta":
        delta = actual - mean
    else:
        return {"status": "skipped", "reason": f"unknown method {method!r}"}
    magnitude = abs(delta)
    severity = "critical" if magnitude >= cfg["critical"] else \
        "warn" if magnitude >= cfg["warn"] else None
    return {"status": "anomaly" if severity else "healthy", "severity": severity,
            "baseline": mean, "actual": actual, "delta": delta}


def detect(store: Store, site: dict, target: str | None = None) -> dict[str, Any]:
    anomalies, healthy, skipped = [], [], []
    for metric, cfg in site["anomalyThresholds"].items():
        rows = store.series(site["name"], metric)
        if not rows:
            continue
        grain = Counter(r["grain"] for r in rows).most_common(1)[0][0]
        if grain == "rolling24h" or any(r["grain"] == "rolling24h" for r in rows):
            grain = "rolling24h"
        rows = [r for r in rows if r["grain"] == grain and r["value"] is not None]
        final = [r for r in rows if not r["provisional"]]
        if target:
            candidates = [r for r in final if r["period_end"] <= target]
        else:
            candidates = final
        if not candidates:
            skipped.append({"metric": metric, "reason": "no finalized data yet"
                            if rows else "no data"})
            continue
        current = candidates[-1]
        prior = [r["value"] for r in final if r["period_end"] < current["period_end"]]
        prior = prior[-int(cfg.get("baselineDays", 28)):]
        need = MIN_POINTS.get(grain, 3)
        if len(prior) < need:
            skipped.append({"metric": metric, "reason":
                            f"insufficient baseline ({len(prior)} of {need} {grain} points)"})
            continue
        result = evaluate(prior, current["value"], cfg)
        if result["status"] == "skipped":
            skipped.append({"metric": metric, "reason": result["reason"]})
            continue
        if result["status"] == "healthy":
            healthy.append(metric)
            continue
        source = metric.split(".", 1)[0]
        worse = (current["value"] < result["baseline"]) == higher_is_better(metric)
        flags = [f for f in store.flags_for(site["name"], current["period_end"])
                 if f["source"] == source]
        anomalies.append({
            "metric": metric, "period": current["period_end"], "grain": grain,
            "baseline": round(result["baseline"], 4), "actual": current["value"],
            "delta": round(result["delta"], 4), "method": cfg["method"],
            "direction": "regression" if worse else "improvement",
            "severityDraft": result["severity"], "source": source, "qualityFlags": flags,
            "topContributors": contributors(store, site["name"], metric, current["period_end"],
                                            grain),
        })
    anomalies.sort(key=lambda a: (a["direction"] != "regression", a["severityDraft"] != "critical"))
    return {"anomalies": anomalies, "healthy": healthy, "skipped": skipped}


def contributors(store: Store, site: str, metric: str, period: str, grain: str) -> list[dict]:
    """Largest per-dimension movers vs. the prior period, for localization."""
    now = {d["dim"]: d["value"] for d in store.dims(site, metric, period, grain)}
    if not now:
        return []
    earlier = [r["period_end"] for r in store.series(site, metric, grain=grain)
               if r["period_end"] < period]
    if not earlier:
        return []
    before = {d["dim"]: d["value"] for d in store.dims(site, metric, earlier[-1], grain)}
    moves = [{"dim": dim, "before": before.get(dim, 0), "after": value,
              "change": (value or 0) - (before.get(dim) or 0)}
             for dim, value in now.items()]
    for dim in set(before) - set(now):
        moves.append({"dim": dim, "before": before[dim], "after": 0, "change": -before[dim]})
    moves.sort(key=lambda m: abs(m["change"]), reverse=True)
    return moves[:5]
