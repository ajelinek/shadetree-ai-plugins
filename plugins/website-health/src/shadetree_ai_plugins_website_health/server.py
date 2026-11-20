"""Local MCP boundary for website-health. Judgment lives in the bundled skill."""

from __future__ import annotations

import functools
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from fastmcp import FastMCP

from . import collector, config, credentials, google_auth, http
from .analysis import anomalies
from .analysis import correlate as correlation
from .audit import run as audit
from .credentials import CREDENTIALS
from .sources import REGISTRY, bing, ga4, gsc, indexnow, links, psi
from .store import Store

READ = {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True,
        "openWorldHint": True}
LOCAL = {**READ, "openWorldHint": False}
WRITE_LOCAL = {"readOnlyHint": False, "destructiveHint": False, "idempotentHint": True,
               "openWorldHint": False}

mcp = FastMCP(
    "shadetree-ai-plugins-website-health",
    instructions=(
        "Cross-source website health checks. Start with check_setup; if credentials are "
        "missing, show the user its doctor_command to run in their own terminal. Never ask "
        "for, accept, or echo keys in chat. Use health_report for a daily check, then "
        "correlate on regressions and follow the bundled website-health skill's rubric. "
        "indexnow_submit is the only external write: confirm with the user first."),
)


def _root() -> Path:
    return Path(__file__).resolve().parents[2]


def doctor_command() -> str:
    return (f'uv run --project "{_root()}" --locked python -m '
            "shadetree_ai_plugins_website_health doctor")


@contextmanager
def _store():
    store = Store()
    try:
        yield store
    finally:
        store.close()


def _site(name: str) -> dict:
    return config.site(name)


def _guard(fn):
    """Return structured errors instead of raising config/HTTP failures."""
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except config.ConfigError as exc:
            return {"ok": False, "error": "config", "detail": str(exc)}
        except (http.HttpError, google_auth.GoogleAuthError) as exc:
            detail = str(exc)
            if detail.startswith("setup_required"):
                return {"ok": False, "error": "setup_required", "detail": detail,
                        "doctor_command": doctor_command()}
            return {"ok": False, "error": "api", "detail": detail}
    return wrapper


@mcp.tool(annotations=LOCAL)
def check_setup(site: str | None = None) -> dict:
    """Report credential and per-source readiness without any network call.

    Shows which keychain entries are stored (never their values) and, per site,
    whether each source is ready, not configured, or needs a credential. Give the
    user doctor_command to enter missing credentials in their own terminal.
    """
    try:
        sites = config.load()["sites"]
    except config.ConfigError as exc:
        return {"ok": False, "error": "config", "detail": str(exc)}
    creds = []
    for cred in CREDENTIALS:
        names = [n for n, s in sites.items() if s.get("clarityProjectId")] if cred.per_site \
            else [None]
        for n in names:
            creds.append({"credential": cred.keychain_key(n), "label": cred.label,
                          "sources": list(cred.sources),
                          "state": credentials.status(cred.key, n)})
    out: dict[str, Any] = {"ok": True, "credentials": creds, "doctor_command": doctor_command(),
                           "configPath": str(config.config_path()), "sites": {}}
    email = google_auth.service_account_email() if credentials.status(
        "google-service-account") == "stored" else None
    if email:
        out["serviceAccountEmail"] = email
    targets = [site] if site else list(sites)
    for name in targets:
        try:
            s = _site(name)
        except config.ConfigError as exc:
            return {"ok": False, "error": "config", "detail": str(exc)}
        out["sites"][name] = [collector.source_status(s, src) for src in REGISTRY]
    if not sites:
        out["next"] = "No sites yet: run discover_properties, then configure_site."
    return out


@mcp.tool(annotations=READ)
def discover_properties() -> dict:
    """List GA4 properties, Search Console sites and Bing sites the stored credentials see.

    Use the IDs to fill configure_site. Sources without a credential are reported
    as setup_required rather than failing the whole call.
    """
    out: dict[str, Any] = {"ok": True}
    for name, fn in (("ga4", ga4.discover), ("gsc", gsc.discover), ("bing", bing.discover)):
        try:
            out[name] = fn()
        except (http.HttpError, google_auth.GoogleAuthError) as exc:
            out[name] = {"error": str(exc)}
    out["serviceAccountEmail"] = google_auth.service_account_email()
    out["note"] = ("Clarity project IDs are in the Clarity URL (clarity.microsoft.com/projects/"
                   "view/<id>).")
    return out


@mcp.tool(annotations=WRITE_LOCAL)
def configure_site(name: str, settings: dict[str, Any]) -> dict:
    """Create or update a site's non-secret settings (never credentials).

    settings keys: url, timezone, ga4PropertyId, ga4SignupEvent, gscSiteUrl
    ('sc-domain:x.com' or 'https://x.com/'), bingSiteUrl, clarityProjectId,
    firebaseProjectId, githubRepos ['org/repo'], keyPaths ['/', '/pricing'],
    contentMarkers {'/': 'text that must appear'}, cruxUrls, indexnowKey,
    cloudMonitoringProjectId, cloudMonitoringQueries
    (['uptime','hosting'] presets or custom), safeBrowsing (bool),
    blocklists (bool), aiReferrers, correlation, anomalyThresholds. Use null to clear.
    """
    try:
        return {"ok": True, "site": config.upsert_site(name, settings)}
    except config.ConfigError as exc:
        return {"ok": False, "error": "config", "detail": str(exc)}


@mcp.tool(annotations=LOCAL)
def list_sites() -> dict:
    """Show every configured site with its settings merged over defaults."""
    try:
        sites = config.load()["sites"]
        return {"ok": True, "sites": {n: config.site(n) for n in sites}}
    except config.ConfigError as exc:
        return {"ok": False, "error": "config", "detail": str(exc)}


@mcp.tool(annotations={**WRITE_LOCAL, "destructiveHint": True})
def remove_site(name: str) -> dict:
    """Remove a site's config. History and raw snapshots are kept on disk."""
    return {"ok": config.remove_site(name)}


@mcp.tool(annotations=WRITE_LOCAL)
def import_legacy_config(path: str) -> dict:
    """Import a skills-stash .claude/website-health-analytics.json into site configs."""
    try:
        return {"ok": True, "imported": config.import_legacy(Path(path).expanduser())}
    except (OSError, ValueError) as exc:
        return {"ok": False, "error": "config", "detail": str(exc)}


@mcp.tool(annotations={**READ, "idempotentHint": False})
@_guard
def collect(site: str, sources: list[str] | None = None, backfill_days: int = 0,
            force_clarity: bool = False, force: bool = False) -> dict:
    """Fetch sources for a site and upsert the history store.

    sources: subset of probe, blocklists, safebrowsing, indexnow, ga4, gsc,
    firebase_auth, crux, psi, clarity, bing, cloud_monitoring (default: all ready
    ones). backfill_days widens sources that
    support history. Clarity is skipped if snapshotted <12h ago and PageSpeed (psi)
    if it ran <6 days ago, unless ``force`` (or the older ``force_clarity``); Clarity has
    a hard 10 calls/day quota and no backfill.
    """
    with _store() as store:
        return collector.collect(store, _site(site), sources, max(0, min(backfill_days, 480)),
                                 force or force_clarity)


@mcp.tool(annotations={**READ, "idempotentHint": False})
@_guard
def probe_site(site: str) -> dict:
    """Live, credential-free checks: status/redirects, TTFB, TLS, DNS, robots, sitemap,
    noindex/canonical/title/h1/JSON-LD and security headers, diffed against last probe."""
    with _store() as store:
        return collector.collect(store, _site(site), ["probe"])["sources"]["probe"]


@mcp.tool(annotations=LOCAL)
@_guard
def detect_anomalies(site: str, period: str | None = None) -> dict:
    """Deterministic anomaly detection on stored history (run collect first).

    Compares the latest finalized period (or the one at/before ``period``) to a
    same-grain baseline. Results include direction, draft severity, data-quality
    flags and the top per-dimension contributors.
    """
    with _store() as store:
        return {"ok": True, **anomalies.detect(store, _site(site), period)}


@mcp.tool(annotations=READ)
@_guard
def correlate(site: str, day: str, source: str | None = None,
              repos: list[str] | None = None) -> dict:
    """Rank deploys, workflow runs, merged PRs and commits preceding an anomaly on ``day``.

    ``source`` (e.g. 'gsc', 'probe') widens the look-back by that source's lag.
    Requires the gh CLI logged in.
    """
    return correlation.correlate(_site(site), day, source, repos)


@mcp.tool(annotations={**READ, "idempotentHint": False})
@_guard
def health_report(site: str) -> dict:
    """Daily check: collect every ready source, detect anomalies, gather findings.

    Returns an overall status (red/yellow/green), regressions, findings by source,
    per-source status and freshness, and reminders. Uses Clarity quota if due.
    """
    s = _site(site)
    with _store() as store:
        run = collector.collect(store, s)
        detection = anomalies.detect(store, s)
        findings = []
        for name, info in run["sources"].items():
            findings += info.get("findings") or []
        freshness = {}
        for metric in store.metrics(s["name"]):
            rows = store.series(s["name"], metric)
            final = [r["period_end"] for r in rows if not r["provisional"]]
            freshness.setdefault(metric.split(".", 1)[0], final[-1] if final else None)
        regressions = [a for a in detection["anomalies"] if a["direction"] == "regression"]
        severities = {f.get("severity") for f in findings} | {
            a["severityDraft"] for a in regressions}
        overall = "red" if "critical" in severities else "yellow" if "warn" in severities \
            else "green"
        return {"ok": True, "site": s["name"], "url": s["url"], "overall": overall,
                "regressions": regressions,
                "improvements": [a for a in detection["anomalies"]
                                 if a["direction"] == "improvement"],
                "findings": findings,
                "sources": {n: {k: v for k, v in i.items() if k != "findings"}
                            for n, i in run["sources"].items()},
                "latestFinalPeriod": freshness, "skippedMetrics": detection["skipped"],
                "reminders": collector.reminders(store, s)}


@mcp.tool(annotations=LOCAL)
@_guard
def list_metrics(site: str) -> dict:
    """List stored metric names for a site."""
    with _store() as store:
        return {"ok": True, "metrics": store.metrics(_site(site)["name"])}


@mcp.tool(annotations=LOCAL)
@_guard
def get_timeseries(site: str, metric: str, dim: str = "", start: str | None = None,
                   end: str | None = None, grain: str | None = None) -> dict:
    """Stored rows for one metric (dim '' = site total, e.g. 'page=/pricing')."""
    with _store() as store:
        rows = store.series(_site(site)["name"], metric, dim=dim, grain=grain, start=start,
                            end=end)
        return {"ok": True, "metric": metric, "dim": dim, "rows": [
            {k: r[k] for k in ("period_start", "period_end", "grain", "value", "provisional")}
            for r in rows]}


@mcp.tool(annotations=LOCAL)
@_guard
def get_breakdown(site: str, metric: str, period: str, grain: str = "day") -> dict:
    """Per-dimension values (pages, queries, channels, providers) for one period."""
    with _store() as store:
        return {"ok": True, "rows": store.dims(_site(site)["name"], metric, period, grain)}


@mcp.tool(annotations={**READ, "idempotentHint": False})
@_guard
def inspect_urls(site: str, urls: list[str] | None = None) -> dict:
    """Search Console URL Inspection (Google's indexed verdict, canonical, rich results).

    Default URLs: keyPaths plus the top GSC landing pages. Capped at 200/day here
    (Google allows 2,000/day per property).
    """
    s = _site(site)
    with _store() as store:
        if not urls:
            urls = [s["url"] + p for p in s["keyPaths"]]
            final = [r["period_end"] for r in store.series(s["name"], "gsc.clicks")
                     if not r["provisional"]]
            if final:
                top = store.dims(s["name"], "gsc.clicks", final[-1])
                urls += [d["dim"].removeprefix("page=") for d in top
                         if d["dim"].startswith("page=")][:10]
        return {"ok": True, **gsc.inspect(s, store, list(dict.fromkeys(urls))[:50])}


@mcp.tool(annotations=READ)
@_guard
def bing_url_info(site: str, url: str) -> dict:
    """Bing's crawl/index metadata for one URL (status, last crawled, discovered)."""
    return {"ok": True, **bing.url_info(_site(site), url)}


@mcp.tool(annotations={**READ, "idempotentHint": False})
@_guard
def run_pagespeed(site: str, urls: list[str] | None = None, strategy: str = "mobile") -> dict:
    """Lighthouse lab run via PageSpeed Insights (a free google-api-key is strongly advised;
    keyless calls often hit Google's shared quota); also returns Chrome
    field Core Web Vitals, ranked opportunities with estimated savings, and diffs vs the last
    run. Stores today's scores/timings so performance trends.

    Run after a deploy. Default URLs: up to 5 keyPaths. strategy: mobile|desktop.
    """
    if strategy not in ("mobile", "desktop"):
        return {"ok": False, "error": "strategy must be mobile or desktop"}
    with _store() as store:
        return {"ok": True, **psi.run(_site(site), store, urls, strategy)}


@mcp.tool(annotations={**READ, "idempotentHint": False})
@_guard
def crawl_links(site: str, max_pages: int = 100, check_external: bool = True) -> dict:
    """Capped same-origin crawl reporting broken links and the pages they appear on."""
    return {"ok": True, **links.crawl(_site(site), max_pages, check_external)}


@mcp.tool(annotations={**READ, "idempotentHint": False})
@_guard
def audit_site(site: str, max_pages: int = 50, sections: list[str] | None = None) -> dict:
    """Account-free site audit: SEO, accessibility, performance, AI-bot access, delivery.

    Crawls up to max_pages same-origin pages (cap 200) and returns grouped findings with
    severity, category (seo, accessibility, performance, usability, security, ai, analytics)
    and new/persisting/resolved status versus the previous audit. sections: any of pages,
    ai, delivery (default all). The ai section checks robots.txt per AI/search bot, fetches
    key pages with each bot's user agent to expose CDN/WAF blocks, content in raw HTML,
    llms.txt and Common Crawl presence. Needs no credentials and adds nothing to the site;
    it duplicates nothing GA4/Search Console already report. Run after deploys and weekly.
    """
    with _store() as store:
        return audit.run(_site(site), store, max_pages, sections)


@mcp.tool(annotations={**READ, "idempotentHint": False})
@_guard
def ga4_realtime(site: str) -> dict:
    """Active users in the last 30 minutes (quick post-deploy sanity check)."""
    return {"ok": True, **ga4.realtime(_site(site))}


@mcp.tool(annotations={"readOnlyHint": False, "destructiveHint": False,
                       "idempotentHint": False, "openWorldHint": True})
@_guard
def indexnow_submit(site: str, urls: list[str]) -> dict:
    """Submit changed URLs to IndexNow (Bing, Yandex, Seznam, Naver, Yep; not Google).

    External write: confirm the URL list with the user before calling. Requires
    indexnowKey in config and the key file served at <url>/<key>.txt.
    """
    s = _site(site)
    if not s.get("indexnowKey"):
        return {"ok": False, "error": "config", "detail": "Set indexnowKey with configure_site."}
    return indexnow.submit(s, urls)


@mcp.tool(annotations=LOCAL)
@_guard
def latest_findings(site: str) -> dict:
    """Findings from each source's most recent collect, without fetching again."""
    s = _site(site)
    with _store() as store:
        return {"ok": True, "findings": {n: store.get(s["name"], f"findings.{n}")
                                         for n in REGISTRY
                                         if store.get(s["name"], f"findings.{n}")}}
