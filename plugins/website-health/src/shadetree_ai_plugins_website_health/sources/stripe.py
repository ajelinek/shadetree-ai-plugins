"""Stripe business signals (restricted read-only key): charges, checkouts, cancellations."""

from __future__ import annotations

from collections import defaultdict
from datetime import timedelta

from .. import credentials, dates, http
from ..store import Row, SourceResult

NAME = "stripe"
BASE = "https://api.stripe.com/v1"
MAX_PAGES = 50


def enabled(site: dict) -> tuple[bool, str]:
    return (bool(site.get("stripe")), "stripe not enabled")


def _key() -> str:
    key = credentials.read("stripe-key")
    if not key:
        raise http.HttpError("setup_required: stripe-key is not stored.")
    return key


def list_all(path: str, key: str, params: dict) -> list[dict]:
    items, after = [], None
    for _ in range(MAX_PAGES):
        page = http.request("GET", f"{BASE}/{path}", headers={"Authorization": f"Bearer {key}"},
                            params={**params, "limit": 100, "starting_after": after},
                            retries=2).data or {}
        items += page.get("data", [])
        if not page.get("has_more") or not page.get("data"):
            break
        after = page["data"][-1]["id"]
    return items


def aggregate(charges: list[dict], sessions: list[dict], events: list[dict], tz: str,
              start: str) -> list[Row]:
    sums: dict[tuple[str, str], float] = defaultdict(float)
    for c in charges:
        day = dates.epoch_ms_to_local_date(c["created"] * 1000, tz)
        if c.get("status") == "succeeded":
            sums[day, "chargesSucceeded"] += 1
            sums[day, f"revenue|currency={c.get('currency', '').upper()}"] += \
                (c.get("amount", 0) - c.get("amount_refunded", 0)) / 100
        elif c.get("status") == "failed":
            sums[day, "chargesFailed"] += 1
    for s in sessions:
        day = dates.epoch_ms_to_local_date(s["created"] * 1000, tz)
        sums[day, "checkoutsStarted"] += 1
        if s.get("status") == "complete":
            sums[day, "checkoutsCompleted"] += 1
    for e in events:
        sums[dates.epoch_ms_to_local_date(e["created"] * 1000, tz), "subscriptionsCanceled"] += 1
    rows = []
    for day in dates.date_range(dates.date.fromisoformat(start), dates.today(tz)):
        d = day.isoformat()
        for metric in ("chargesSucceeded", "chargesFailed", "checkoutsStarted",
                       "checkoutsCompleted", "subscriptionsCanceled"):
            rows.append(Row(f"stripe.{metric}", d, sums.get((d, metric), 0.0),
                            provisional=d == dates.today(tz).isoformat()))
    for (d, metric), value in sums.items():
        if metric.startswith("revenue|"):
            rows.append(Row("stripe.revenue", d, value, dim=metric.split("|", 1)[1]))
    return rows


def collect(site: dict, store, backfill_days: int = 0) -> SourceResult:
    key = _key()
    tz = site["timezone"]
    start = dates.today(tz) - timedelta(days=min(max(28, backfill_days), 29))
    gte = int(dates.day_bounds_utc(start.isoformat(), tz)[0].timestamp())
    charges = list_all("charges", key, {"created[gte]": gte})
    sessions = list_all("checkout/sessions", key, {"created[gte]": gte})
    events = list_all("events", key, {"type": "customer.subscription.deleted",
                                      "created[gte]": gte})
    result = SourceResult(NAME)
    result.rows = aggregate(charges, sessions, events, tz, start.isoformat())
    result.summary = {"charges": len(charges), "checkoutSessions": len(sessions),
                      "cancellations": len(events)}
    return result


def validate(key: str) -> str:
    http.request("GET", f"{BASE}/balance", headers={"Authorization": f"Bearer {key}"})
    return "balance readable"
