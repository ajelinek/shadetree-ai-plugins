"""Run sources for a site, persist results, and summarize per-source status."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from shadetree_ai_plugins_common.secrets import SecretStoreError

from . import credentials, google_auth, http
from .sources import REGISTRY
from .sources.clarity import ClarityQuotaError
from .store import SourceResult, Store

REMINDER_DAYS = 30


def credential_state(source: str, site: str) -> str | None:
    """None if the source needs no credential, else stored/missing/keychain_error."""
    cred = credentials.BY_SOURCE.get(source)
    if not cred:
        return None
    return credentials.status(cred.key, site if cred.per_site else None)


def source_status(site: dict, source: str) -> dict[str, Any]:
    module = REGISTRY[source]
    ok, reason = module.enabled(site)
    cred = credentials.BY_SOURCE.get(source)
    state = credential_state(source, site["name"])
    status = "ready"
    if not ok:
        status = "not_configured"
    elif state in ("missing", "keychain_error"):
        status = "setup_required" if state == "missing" else "keychain_error"
    out = {"source": source, "status": status}
    if not ok:
        out["reason"] = reason
    if cred:
        out["credential"] = cred.keychain_key(site["name"] if cred.per_site else None)
        out["credentialState"] = state
    return out


def collect(store: Store, site: dict, sources: list[str] | None = None,
            backfill_days: int = 0, force: bool = False) -> dict[str, Any]:
    names = sources or list(REGISTRY)
    unknown = [n for n in names if n not in REGISTRY]
    if unknown:
        return {"ok": False, "error": "unknown_source", "sources": unknown,
                "known": list(REGISTRY)}
    report: dict[str, Any] = {}
    for name in names:
        status = source_status(site, name)
        if status["status"] != "ready":
            report[name] = status
            continue
        try:
            kwargs = {"force": force} if name == "clarity" else {}
            result: SourceResult = REGISTRY[name].collect(site, store, backfill_days, **kwargs)
        except (http.HttpError, google_auth.GoogleAuthError, ClarityQuotaError,
                SecretStoreError) as exc:
            message = str(exc)
            report[name] = {"source": name, "status": "setup_required"
                            if message.startswith("setup_required") else "error",
                            "error": message, **grant_hint(name, exc)}
            continue
        store.upsert(site["name"], result.rows)
        store.add_flags(site["name"], result.flags)
        store.put(site["name"], f"findings.{name}", {
            "at": datetime.now(UTC).isoformat(), "findings": result.findings})
        report[name] = {"source": name, "status": "ok", "rows": len(result.rows),
                        "provisionalRows": sum(r.provisional for r in result.rows),
                        "flags": [f.__dict__ for f in result.flags],
                        "warnings": result.warnings, "findings": result.findings,
                        "summary": result.summary}
    return {"ok": True, "site": site["name"], "sources": report}


def grant_hint(source: str, exc: Exception) -> dict[str, str]:
    """Turn a 403 on a Google source into the exact grant the service account lacks."""
    status = getattr(exc, "status", None)
    if status != 403 or source not in google_auth.SCOPES:
        return {}
    email = google_auth.service_account_email() or "the service account"
    where = {
        "ga4": "GA4 Admin > Property access management: add it as Viewer",
        "gsc": "Search Console > Settings > Users and permissions: add it (Full)",
        "firebase_auth": "Firebase project IAM: grant Firebase Authentication Viewer, and "
                         "enable the Identity Toolkit API",
        "cloud_monitoring": "Cloud project IAM: grant Monitoring Viewer",
    }[source]
    return {"fix": f"Grant {email} access. {where}. Also confirm the API is enabled in the "
                   "service account's Cloud project."}


def reminders(store: Store, site: dict) -> list[str]:
    out = []
    last = store.get(site["name"], "reminder.aiReports")
    today = datetime.now(UTC).date()
    if not last or (today - datetime.fromisoformat(last).date()).days >= REMINDER_DAYS:
        out.append("Monthly: check Bing Webmaster Tools > AI Performance and Search Console's "
                   "generative-AI report by hand (neither has an API).")
        store.put(site["name"], "reminder.aiReports", today.isoformat())
    return out
