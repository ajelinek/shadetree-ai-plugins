"""SQLite history store plus raw snapshots.

Rows are keyed by (site, metric, dim, period_end, grain). ``metric`` is
``<source>.<name>``; ``dim`` is "" for site totals or e.g. ``page=/pricing``.
``grain`` is one of: day, week, rolling24h, rolling72h, rolling28d, instant.
Upserting the same key replaces the value, which is how provisional days get
corrected on later runs.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from shadetree_ai_plugins_common.paths import state_dir

from .config import PLUGIN

SCHEMA = """
CREATE TABLE IF NOT EXISTS metrics (
  site TEXT NOT NULL, metric TEXT NOT NULL, dim TEXT NOT NULL DEFAULT '',
  period_start TEXT NOT NULL, period_end TEXT NOT NULL, grain TEXT NOT NULL,
  value REAL, provisional INTEGER NOT NULL DEFAULT 0, fetched_at TEXT NOT NULL,
  PRIMARY KEY (site, metric, dim, period_end, grain));
CREATE TABLE IF NOT EXISTS flags (
  site TEXT NOT NULL, source TEXT NOT NULL, date TEXT NOT NULL, flag TEXT NOT NULL,
  detail TEXT, fetched_at TEXT NOT NULL, PRIMARY KEY (site, source, date, flag));
CREATE TABLE IF NOT EXISTS calls (
  site TEXT NOT NULL, source TEXT NOT NULL, utc_day TEXT NOT NULL, count INTEGER NOT NULL,
  PRIMARY KEY (site, source, utc_day));
CREATE TABLE IF NOT EXISTS kv (
  site TEXT NOT NULL, key TEXT NOT NULL, value TEXT NOT NULL, PRIMARY KEY (site, key));
"""


@dataclass
class Row:
    metric: str
    period_end: str
    value: float | None
    grain: str = "day"
    dim: str = ""
    period_start: str | None = None
    provisional: bool = False


@dataclass
class Flag:
    source: str
    date: str
    flag: str
    detail: str = ""


@dataclass
class SourceResult:
    """What every source's ``collect`` returns."""

    source: str
    rows: list[Row] = field(default_factory=list)
    flags: list[Flag] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)
    summary: dict[str, Any] = field(default_factory=dict)


def now_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


class Store:
    def __init__(self, root: Path | None = None):
        self.root = root or state_dir(PLUGIN)
        self.root.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(self.root / "history.sqlite3")
        self.db.row_factory = sqlite3.Row
        self.db.executescript(SCHEMA)

    def close(self) -> None:
        self.db.close()

    # ----------------------------------------------------------- metrics
    def upsert(self, site: str, rows: Iterable[Row]) -> int:
        fetched = now_iso()
        data = [(site, r.metric, r.dim, r.period_start or r.period_end, r.period_end, r.grain,
                 r.value, int(r.provisional), fetched) for r in rows]
        self.db.executemany(
            "INSERT INTO metrics VALUES (?,?,?,?,?,?,?,?,?) ON CONFLICT "
            "(site, metric, dim, period_end, grain) DO UPDATE SET value=excluded.value, "
            "period_start=excluded.period_start, provisional=excluded.provisional, "
            "fetched_at=excluded.fetched_at", data)
        self.db.commit()
        return len(data)

    def series(self, site: str, metric: str, *, dim: str = "", grain: str | None = None,
               start: str | None = None, end: str | None = None) -> list[dict[str, Any]]:
        sql = "SELECT * FROM metrics WHERE site=? AND metric=? AND dim=?"
        args: list[Any] = [site, metric, dim]
        if grain:
            sql += " AND grain=?"
            args.append(grain)
        if start:
            sql += " AND period_end>=?"
            args.append(start)
        if end:
            sql += " AND period_end<=?"
            args.append(end)
        rows = self.db.execute(sql + " ORDER BY period_end", args).fetchall()
        return [dict(r) for r in rows]

    def metrics(self, site: str) -> list[str]:
        rows = self.db.execute("SELECT DISTINCT metric FROM metrics WHERE site=? AND dim=''",
                               (site,)).fetchall()
        return sorted(r[0] for r in rows)

    def dims(self, site: str, metric: str, period_end: str, grain: str = "day") -> list[dict]:
        rows = self.db.execute(
            "SELECT dim, value FROM metrics WHERE site=? AND metric=? AND period_end=? "
            "AND grain=? AND dim!='' ORDER BY value DESC", (site, metric, period_end, grain))
        return [dict(r) for r in rows]

    # ------------------------------------------------------------- flags
    def add_flags(self, site: str, flags: Iterable[Flag]) -> None:
        fetched = now_iso()
        self.db.executemany(
            "INSERT OR REPLACE INTO flags VALUES (?,?,?,?,?,?)",
            [(site, f.source, f.date, f.flag, f.detail, fetched) for f in flags])
        self.db.commit()

    def flags_for(self, site: str, date: str) -> list[dict[str, Any]]:
        rows = self.db.execute("SELECT source, flag, detail FROM flags WHERE site=? AND date=?",
                               (site, date)).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------- quota
    def calls_today(self, site: str, source: str) -> int:
        day = datetime.now(UTC).date().isoformat()
        row = self.db.execute("SELECT count FROM calls WHERE site=? AND source=? AND utc_day=?",
                              (site, source, day)).fetchone()
        return row[0] if row else 0

    def record_call(self, site: str, source: str, n: int = 1) -> None:
        day = datetime.now(UTC).date().isoformat()
        self.db.execute(
            "INSERT INTO calls VALUES (?,?,?,?) ON CONFLICT (site, source, utc_day) "
            "DO UPDATE SET count=count+excluded.count", (site, source, day, n))
        self.db.commit()

    # ---------------------------------------------------------------- kv
    def get(self, site: str, key: str, default: Any = None) -> Any:
        row = self.db.execute("SELECT value FROM kv WHERE site=? AND key=?",
                              (site, key)).fetchone()
        return json.loads(row[0]) if row else default

    def put(self, site: str, key: str, value: Any) -> None:
        self.db.execute("INSERT OR REPLACE INTO kv VALUES (?,?,?)",
                        (site, key, json.dumps(value)))
        self.db.commit()

    # --------------------------------------------------------- snapshots
    def snapshot(self, site: str, source: str, name: str, payload: Any) -> Path:
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        folder = self.root / "raw" / site / source
        folder.mkdir(parents=True, exist_ok=True)
        path = folder / f"{stamp}-{name}.json"
        path.write_text(json.dumps(payload, indent=1, default=str), encoding="utf-8")
        return path
