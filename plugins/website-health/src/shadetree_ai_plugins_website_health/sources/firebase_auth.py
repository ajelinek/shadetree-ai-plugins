"""Firebase Auth signups via Identity Toolkit ``accounts:batchGet`` (service account).

Server-side truth for signups. Users are bucketed by ``createdAt`` in the site's
timezone; provider mix uses each user's *first* linked provider so a later-linked
provider is not double-counted. Only counts leave this module, never PII.
"""

from __future__ import annotations

from collections import Counter
from datetime import timedelta

from .. import dates, google_auth, http
from ..store import Row, SourceResult

NAME = "firebase_auth"
URL = "https://identitytoolkit.googleapis.com/v1/projects/{project}/accounts:batchGet"
MAX_PAGES = 200


def enabled(site: dict) -> tuple[bool, str]:
    return (bool(site.get("firebaseProjectId")), "firebaseProjectId not set")


def first_provider(user: dict) -> str:
    infos = user.get("providerUserInfo") or []
    if infos:
        return infos[0].get("providerId") or "unknown"
    if user.get("phoneNumber"):
        return "phone"
    return "anonymous" if not user.get("email") else "password"


def aggregate(users: list[dict], tz: str, start: str) -> list[Row]:
    totals: Counter[str] = Counter()
    by_provider: Counter[tuple[str, str]] = Counter()
    for user in users:
        created = user.get("createdAt")
        if not created:
            continue
        day = dates.epoch_ms_to_local_date(created, tz)
        if day < start:
            continue
        totals[day] += 1
        by_provider[day, first_provider(user)] += 1
    rows = []
    for day in dates.date_range(dates.date.fromisoformat(start), dates.today(tz)):
        key = day.isoformat()
        rows.append(Row("firebase_auth.signups", key, float(totals.get(key, 0)),
                        provisional=key == dates.today(tz).isoformat()))
    for (day, provider), count in by_provider.items():
        rows.append(Row("firebase_auth.signups", day, float(count), dim=f"provider={provider}"))
    return rows


def fetch_users(project: str) -> list[dict]:
    users, token = [], None
    for _ in range(MAX_PAGES):
        params = {"maxResults": 1000, "nextPageToken": token}
        resp = http.request("GET", URL.format(project=project), params=params,
                            headers=google_auth.headers(NAME), retries=1)
        data = resp.data or {}
        users += data.get("users", [])
        token = data.get("nextPageToken")
        if not token:
            break
    return users


def collect(site: dict, store, backfill_days: int = 0) -> SourceResult:
    tz = site["timezone"]
    start = (dates.today(tz) - timedelta(days=max(35, backfill_days))).isoformat()
    users = fetch_users(site["firebaseProjectId"])
    result = SourceResult(NAME)
    result.rows = aggregate(users, tz, start)
    result.summary = {"totalUsers": len(users), "since": start}
    return result
