"""Timezone-aware date helpers."""

from __future__ import annotations

from datetime import UTC, date, datetime, timedelta
from zoneinfo import ZoneInfo


def today(tz: str) -> date:
    return datetime.now(ZoneInfo(tz)).date()


def iso(d: date) -> str:
    return d.isoformat()


def days_ago(tz: str, n: int) -> date:
    return today(tz) - timedelta(days=n)


def date_range(start: date, end: date) -> list[date]:
    return [start + timedelta(days=i) for i in range((end - start).days + 1)]


def epoch_ms_to_local_date(ms: int | float | str, tz: str) -> str:
    return datetime.fromtimestamp(int(ms) / 1000, UTC).astimezone(ZoneInfo(tz)).date().isoformat()


def utc_to_local_date(value: datetime, tz: str) -> str:
    return value.astimezone(ZoneInfo(tz)).date().isoformat()


def day_bounds_utc(day: str, tz: str) -> tuple[datetime, datetime]:
    local = datetime.fromisoformat(day).replace(tzinfo=ZoneInfo(tz))
    return local.astimezone(UTC), (local + timedelta(days=1)).astimezone(UTC)


def parse_ga4_date(value: str) -> str:
    return f"{value[:4]}-{value[4:6]}-{value[6:8]}"
