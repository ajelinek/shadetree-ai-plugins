"""Site configuration: non-secret IDs per site, stored in the plugin state dir.

``~/.shadetree-ai-plugins/website-health/config.json``::

    {"sites": {"prod": {"url": "https://example.com", "timezone": "America/New_York",
                         "ga4PropertyId": "123456789", ...}}}
"""

from __future__ import annotations

import copy
import json
import re
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from shadetree_ai_plugins_common.paths import state_dir

PLUGIN = "website-health"
SITE_NAME = re.compile(r"[a-z0-9][a-z0-9_-]{0,39}")

AI_REFERRERS = [
    "chatgpt.com", "chat.openai.com", "perplexity.ai", "www.perplexity.ai",
    "copilot.microsoft.com", "gemini.google.com", "claude.ai", "you.com",
    "phind.com", "poe.com", "meta.ai", "grok.com", "chat.deepseek.com",
]

DEFAULT_THRESHOLDS: dict[str, dict[str, Any]] = {
    "ga4.sessions": {"method": "zscore", "baselineDays": 28, "warn": 2.0, "critical": 3.0},
    "ga4.engagedSessions": {"method": "zscore", "baselineDays": 28, "warn": 2.0, "critical": 3.0},
    "ga4.keyEvents": {"method": "percentChange", "baselineDays": 7, "warn": 0.15,
                      "critical": 0.30},
    "ga4.aiReferralSessions": {"method": "percentChange", "baselineDays": 28, "warn": 0.30,
                               "critical": 0.60},
    "firebase_auth.signups": {"method": "percentChange", "baselineDays": 7, "warn": 0.15,
                              "critical": 0.30},
    "gsc.clicks": {"method": "zscore", "baselineDays": 28, "warn": 2.0, "critical": 3.0},
    "gsc.impressions": {"method": "zscore", "baselineDays": 28, "warn": 2.0, "critical": 3.0},
    "gsc.position": {"method": "absoluteDelta", "baselineDays": 28, "warn": 3, "critical": 6},
    "bing.clicks": {"method": "zscore", "baselineDays": 28, "warn": 2.0, "critical": 3.0},
    "bing.impressions": {"method": "zscore", "baselineDays": 28, "warn": 2.0, "critical": 3.0},
    "bing.crawlErrors": {"method": "zscore", "baselineDays": 28, "warn": 2.0, "critical": 3.0},
    "clarity.rageClickPct": {"method": "absoluteDelta", "baselineDays": 14, "warn": 2.0,
                             "critical": 5.0},
    "clarity.deadClickPct": {"method": "absoluteDelta", "baselineDays": 14, "warn": 3.0,
                             "critical": 6.0},
    "clarity.scriptErrorPct": {"method": "absoluteDelta", "baselineDays": 14, "warn": 2.0,
                               "critical": 5.0},
    "clarity.errorClickPct": {"method": "absoluteDelta", "baselineDays": 14, "warn": 2.0,
                              "critical": 5.0},
    "crux.lcpP75": {"method": "percentChange", "baselineDays": 4, "warn": 0.10,
                    "critical": 0.25},
    "crux.inpP75": {"method": "percentChange", "baselineDays": 4, "warn": 0.10,
                    "critical": 0.25},
    "crux.clsP75": {"method": "absoluteDelta", "baselineDays": 4, "warn": 0.03,
                    "critical": 0.08},
    "psi.performance": {"method": "absoluteDelta", "baselineDays": 4, "warn": 10,
                        "critical": 20},
    "psi.accessibility": {"method": "absoluteDelta", "baselineDays": 4, "warn": 5,
                          "critical": 10},
    "psi.seo": {"method": "absoluteDelta", "baselineDays": 4, "warn": 5, "critical": 10},
    "psi.lcpMs": {"method": "percentChange", "baselineDays": 4, "warn": 0.25, "critical": 0.5},
    "psi.tbtMs": {"method": "percentChange", "baselineDays": 4, "warn": 0.4, "critical": 0.8},
    "psi.totalBytes": {"method": "percentChange", "baselineDays": 4, "warn": 0.25,
                       "critical": 0.5},
    "cloud_monitoring.responses5xx": {"method": "zscore", "baselineDays": 28, "warn": 2.5,
                                      "critical": 4.0},
}

DEFAULT_SITE: dict[str, Any] = {
    "url": None,
    "timezone": "UTC",
    "ga4PropertyId": None,
    "ga4SignupEvent": "sign_up",
    "gscSiteUrl": None,
    "bingSiteUrl": None,
    "clarityProjectId": None,
    "firebaseProjectId": None,
    "githubRepos": [],
    "keyPaths": ["/"],
    "contentMarkers": {},
    "cruxUrls": [],
    "indexnowKey": None,
    "cloudMonitoringProjectId": None,
    "cloudMonitoringQueries": [],
    "safeBrowsing": True,
    "blocklists": True,
    "aiReferrers": AI_REFERRERS,
    "correlation": {"windowHours": 48, "bufferHours": 6},
    "anomalyThresholds": {},
}

STRING_FIELDS = {"url", "timezone", "ga4PropertyId", "ga4SignupEvent", "gscSiteUrl",
                 "bingSiteUrl", "clarityProjectId", "firebaseProjectId", "indexnowKey",
                 "cloudMonitoringProjectId"}
LIST_FIELDS = {"githubRepos", "keyPaths", "cruxUrls", "aiReferrers",
               "cloudMonitoringQueries"}
BOOL_FIELDS = {"safeBrowsing", "blocklists"}
DICT_FIELDS = {"contentMarkers", "correlation", "anomalyThresholds"}


class ConfigError(ValueError):
    pass


def atomic_write_text(path: Path, text: str) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    tmp.replace(path)


def config_path() -> Path:
    return state_dir(PLUGIN) / "config.json"


def load() -> dict[str, Any]:
    path = config_path()
    if not path.exists():
        return {"sites": {}}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except ValueError as exc:
        raise ConfigError(f"{path} is not valid JSON: {exc}") from None
    data.setdefault("sites", {})
    return data


def save(data: dict[str, Any]) -> None:
    atomic_write_text(config_path(), json.dumps(data, indent=2, sort_keys=True) + "\n")


def site(name: str) -> dict[str, Any]:
    """Return a site's config merged over defaults."""
    sites = load()["sites"]
    if name not in sites:
        known = ", ".join(sorted(sites)) or "none configured"
        raise ConfigError(f"Unknown site {name!r} (known: {known}). Use configure_site first.")
    merged = copy.deepcopy(DEFAULT_SITE)
    merged.update(sites[name])
    merged["name"] = name
    merged["anomalyThresholds"] = {**DEFAULT_THRESHOLDS, **(sites[name].get("anomalyThresholds")
                                                            or {})}
    merged["correlation"] = {**DEFAULT_SITE["correlation"], **(sites[name].get("correlation")
                                                               or {})}
    return merged


def validate_changes(changes: dict[str, Any]) -> dict[str, Any]:
    clean: dict[str, Any] = {}
    for key, value in changes.items():
        if key not in DEFAULT_SITE:
            raise ConfigError(f"Unknown setting {key!r}.")
        if value is None:
            clean[key] = None
            continue
        if key in STRING_FIELDS and not isinstance(value, str):
            raise ConfigError(f"{key} must be a string.")
        if key in LIST_FIELDS and not isinstance(value, list):
            raise ConfigError(f"{key} must be a list.")
        if key in BOOL_FIELDS and not isinstance(value, bool):
            raise ConfigError(f"{key} must be true or false.")
        if key in DICT_FIELDS and not isinstance(value, dict):
            raise ConfigError(f"{key} must be an object.")
        clean[key] = value
    if clean.get("timezone"):
        try:
            ZoneInfo(clean["timezone"])
        except (ZoneInfoNotFoundError, ValueError):
            raise ConfigError(f"Unknown timezone {clean['timezone']!r}.") from None
    if clean.get("url") and not re.match(r"https?://[^/\s]+", clean["url"]):
        raise ConfigError("url must start with http:// or https://")
    if clean.get("url"):
        clean["url"] = clean["url"].rstrip("/")
    if clean.get("ga4PropertyId"):
        clean["ga4PropertyId"] = clean["ga4PropertyId"].removeprefix("properties/")
        if not clean["ga4PropertyId"].isdigit():
            raise ConfigError("ga4PropertyId must be the numeric GA4 property ID.")
    gsc = clean.get("gscSiteUrl")
    if gsc and not (gsc.startswith("sc-domain:") or re.match(r"https?://.+/$", gsc)):
        raise ConfigError("gscSiteUrl must be 'sc-domain:example.com' or a URL ending in '/'.")
    for path in clean.get("keyPaths") or []:
        if not isinstance(path, str) or not path.startswith("/"):
            raise ConfigError("keyPaths entries must be paths starting with '/'.")
    if clean.get("indexnowKey") and not re.fullmatch(r"[A-Za-z0-9-]{8,128}", clean["indexnowKey"]):
        raise ConfigError("indexnowKey must be 8-128 characters of a-z, A-Z, 0-9 or '-'.")
    return clean


def upsert_site(name: str, changes: dict[str, Any]) -> dict[str, Any]:
    if not SITE_NAME.fullmatch(name):
        raise ConfigError("Site names are 1-40 chars of lowercase letters, digits, '-' or '_'.")
    clean = validate_changes(changes)
    data = load()
    current = data["sites"].get(name, {})
    if not current and not (clean.get("url") or current.get("url")):
        raise ConfigError("A new site needs a url.")
    current.update(clean)
    data["sites"][name] = {k: v for k, v in current.items() if v is not None}
    save(data)
    return site(name)


def remove_site(name: str) -> bool:
    data = load()
    removed = data["sites"].pop(name, None) is not None
    if removed:
        save(data)
    return removed


def import_legacy(path: Path) -> dict[str, Any]:
    """Map a skills-stash ``.claude/website-health-analytics.json`` onto site configs."""
    legacy = json.loads(path.read_text(encoding="utf-8"))
    imported = {}
    for entry in legacy.get("sites", []):
        name = re.sub(r"[^a-z0-9_-]", "-", str(entry.get("name", "site")).lower())[:40]
        gsc = entry.get("gscSiteUrl")
        url = entry.get("url") or (gsc if gsc and gsc.startswith("http") else None)
        if not url and gsc and gsc.startswith("sc-domain:"):
            url = "https://" + gsc.removeprefix("sc-domain:")
        changes = {"url": url, "timezone": legacy.get("timezone", "UTC"),
                   "ga4PropertyId": entry.get("ga4PropertyId"), "gscSiteUrl": gsc,
                   "githubRepos": legacy.get("githubRepos", [])}
        corr = legacy.get("correlation") or {}
        changes["correlation"] = {k: corr[k] for k in ("windowHours", "bufferHours") if k in corr}
        thresholds = {}
        for metric, cfg in (legacy.get("anomalyThresholds") or {}).items():
            renamed = LEGACY_METRICS.get(metric)
            if renamed:
                thresholds[renamed] = cfg
        changes["anomalyThresholds"] = thresholds
        imported[name] = upsert_site(name, {k: v for k, v in changes.items() if v})
    return imported


LEGACY_METRICS = {
    "sessions": "ga4.sessions", "conversions": "ga4.keyEvents", "signups": "firebase_auth.signups",
    "clicks": "gsc.clicks", "impressions": "gsc.impressions", "avgPosition": "gsc.position",
}
