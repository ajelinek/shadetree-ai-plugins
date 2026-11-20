"""PageSpeed Insights v5: Lighthouse lab runs plus the field data PSI embeds.

Best with a free ``google-api-key`` (same one CrUX uses; no extra account beyond the Cloud
project the Google credentials already need). Keyless calls share one global quota that is
often exhausted (HTTP 429), so a 429 is reported as a warning, never a failed source.
Scores and lab timings are stored as weekly points so performance has a trend and the
anomaly detector can flag regressions. The same response carries Chrome field data (the
CrUX numbers), which covers sites that have no CrUX key.

As a source in ``collect`` it runs at most once every ``INTERVAL_DAYS`` (lab runs are slow
and noisy); ``run`` is the on-demand post-deploy tool and always runs.
"""

from __future__ import annotations

from datetime import UTC, datetime

from .. import credentials, dates, http
from ..store import Row, SourceResult

NAME = "psi"
URL = "https://www.googleapis.com/pagespeedonline/v5/runPagespeed"
CATEGORIES = ["performance", "accessibility", "best-practices", "seo"]
INTERVAL_DAYS = 6
COLLECT_PAGES = 3
FIELD = {"LARGEST_CONTENTFUL_PAINT_MS": ("lcpP75", 1), "INTERACTION_TO_NEXT_PAINT": ("inpP75", 1),
         "CUMULATIVE_LAYOUT_SHIFT_SCORE": ("clsP75", 0.01),
         "FIRST_CONTENTFUL_PAINT_MS": ("fcpP75", 1),
         "EXPERIMENTAL_TIME_TO_FIRST_BYTE": ("ttfbP75", 1)}
CWV = ("lcpP75", "inpP75", "clsP75")
SCORE_NAMES = {"performance": "performance", "accessibility": "accessibility",
               "best-practices": "bestPractices", "seo": "seo"}
LAB = {"largest-contentful-paint": "lcpMs", "first-contentful-paint": "fcpMs",
       "total-blocking-time": "tbtMs", "speed-index": "speedIndexMs",
       "cumulative-layout-shift": "layoutShift", "server-response-time": "serverResponseMs",
       "total-byte-weight": "totalBytes", "dom-size": "domNodes"}


def enabled(site: dict) -> tuple[bool, str]:
    return (bool(site.get("url")), "url not set")


def _opportunities(audits: dict) -> list[dict]:
    out = []
    for audit_id, audit in audits.items():
        details = audit.get("details") or {}
        # Classic opportunities report overallSavingsMs; newer Lighthouse "insight" audits
        # report per-metric savings.
        ms = details.get("overallSavingsMs") or max(
            (audit.get("metricSavings") or {}).values(), default=0) or 0
        nbytes = details.get("overallSavingsBytes") or 0
        if (ms >= 100 or nbytes >= 20_000) and (audit.get("score") or 0) < 0.9:
            out.append({"id": audit_id, "title": audit.get("title"), "savingsMs": round(ms),
                        "savingsBytes": round(nbytes)})
    out.sort(key=lambda a: (-a["savingsMs"], -a["savingsBytes"]))
    return out[:8]


def _field(data: dict) -> dict:
    """Field (CrUX) percentiles PSI returns for the URL, falling back to the origin."""
    for key, scope in (("loadingExperience", "url"), ("originLoadingExperience", "origin")):
        exp = data.get(key) or {}
        metrics = exp.get("metrics") or {}
        if not metrics or (key == "loadingExperience" and exp.get("origin_fallback")):
            continue
        values = {}
        for api_name, (name, scale) in FIELD.items():
            m = metrics.get(api_name)
            if m and m.get("percentile") is not None:
                values[name] = {"p75": m["percentile"] * scale, "category": m.get("category")}
        if values:
            return {"scope": scope, "metrics": values}
    return {}


def summarize(data: dict) -> dict:
    lh = data.get("lighthouseResult") or {}
    cats = {k: round((v.get("score") or 0) * 100) for k, v in (lh.get("categories") or {}).items()}
    audits = lh.get("audits") or {}
    opportunities = _opportunities(audits)
    skip = {o["id"] for o in opportunities}
    failing = []
    for audit_id, audit in audits.items():
        score = audit.get("score")
        if audit_id not in skip and score is not None \
                and audit.get("scoreDisplayMode") in ("binary", "numeric") and score < 0.9:
            failing.append({"id": audit_id, "title": audit.get("title"), "score": score,
                            "displayValue": audit.get("displayValue")})
    failing.sort(key=lambda a: a["score"])
    lab = {name: (audits.get(audit_id) or {}).get("numericValue")
           for audit_id, name in LAB.items()}
    return {"url": lh.get("finalDisplayedUrl") or lh.get("requestedUrl"), "scores": cats,
            "lab": lab, "opportunities": opportunities, "failingAudits": failing[:25],
            "field": _field(data), "lighthouseVersion": lh.get("lighthouseVersion")}


def _path(site: dict, url: str) -> str:
    return url[len(site["url"]):] or "/" if url.startswith(site["url"]) else url


def _dim(site: dict, url: str, strategy: str, total: bool) -> str:
    parts = [] if strategy == "mobile" else [f"strategy={strategy}"]
    if not total:
        parts.append(f"page={_path(site, url)}")
    return ",".join(parts)


def rows(site: dict, url: str, strategy: str, summary: dict, day: str,
         total: bool) -> list[Row]:
    out = []

    def add(metric, value, dim):
        if value is not None:
            out.append(Row(f"psi.{metric}", day, float(value), grain="week", dim=dim))

    for dim in {_dim(site, url, strategy, False), *([_dim(site, url, strategy, True)]
                                                    if total else [])}:
        for category, name in SCORE_NAMES.items():
            add(name, summary["scores"].get(category), dim)
        for name, value in summary["lab"].items():
            add(name, value, dim)
    if total:
        dim = _dim(site, url, strategy, True)
        for name, info in summary["field"].get("metrics", {}).items():
            add("field" + name[0].upper() + name[1:], info["p75"], dim)
    return out


def _call(url: str, strategy: str, key: str | None) -> dict:
    params = {"url": url, "strategy": strategy, "category": CATEGORIES}
    return http.request("GET", URL, params=params, secret_params={"key": key} if key else None,
                        timeout=120).data


def _findings(url: str, strategy: str, summary: dict, has_crux_key: bool) -> list[dict]:
    out = []
    scores = summary["scores"]
    top = [o["title"] for o in summary["opportunities"][:3]]

    def add(kind, severity, **detail):
        out.append({"source": NAME, "kind": kind, "severity": severity, "url": url,
                    "strategy": strategy, **detail})

    perf = scores.get("performance")
    if perf is not None and perf < 50:
        add("lighthouse_performance_poor", "warn", score=perf, topOpportunities=top)
    elif perf is not None and perf < 75:
        add("lighthouse_performance_needs_work", "info", score=perf, topOpportunities=top)
    for category, kind in (("accessibility", "lighthouse_accessibility_low"),
                           ("seo", "lighthouse_seo_low")):
        if scores.get(category) is not None and scores[category] < 90:
            add(kind, "warn", score=scores[category])
    if scores.get("best-practices") is not None and scores["best-practices"] < 90:
        add("lighthouse_best_practices_low", "info", score=scores["best-practices"])
    if not has_crux_key:  # CrUX covers this when a key is stored
        field = summary["field"]
        for name, info in field.get("metrics", {}).items():
            if name in CWV and info.get("category") in ("AVERAGE", "SLOW"):
                add("core_web_vital", "warn" if info["category"] == "SLOW" else "info",
                    metric=name, p75=info["p75"], rating=info["category"],
                    scope=field["scope"])
    return out


def _analyze(site: dict, store, urls: list[str], strategy: str, key: str | None,
             day: str, total_first: bool) -> tuple[list[dict], list[Row], list[dict], list[str]]:
    results, all_rows, findings, warnings = [], [], [], []
    previous = store.get(site["name"], f"psi.last.{strategy}", {})
    for i, url in enumerate(urls):
        try:
            summary = summarize(_call(url, strategy, key))
        except http.HttpError as exc:
            results.append({"url": url, "error": str(exc)})
            if exc.status == 429:
                warnings.append("PageSpeed quota exceeded" + (
                    "." if key else " (Google's shared keyless quota is often exhausted): "
                    "store a free google-api-key with doctor."))
                break
            continue
        prior = previous.get(url)
        if prior:
            summary["scoreDelta"] = {k: v - prior["scores"].get(k, v)
                                     for k, v in summary["scores"].items()}
            prior_ids = {a["id"] for a in prior.get("failingAudits", [])}
            summary["newlyFailing"] = [a for a in summary["failingAudits"]
                                       if a["id"] not in prior_ids]
        previous[url] = {"scores": summary["scores"], "failingAudits": summary["failingAudits"]}
        all_rows += rows(site, url, strategy, summary, day, total=total_first and i == 0)
        findings += _findings(url, strategy, summary, bool(key))
        results.append(summary)
    store.put(site["name"], f"psi.last.{strategy}", previous)
    return results, all_rows, findings, warnings


def collect(site: dict, store, backfill_days: int = 0, force: bool = False) -> SourceResult:
    result = SourceResult(NAME)
    today = dates.today(site["timezone"])
    last = store.get(site["name"], "psi.lastRun")
    if last and not force and (today - datetime.fromisoformat(last).date()).days < INTERVAL_DAYS:
        result.findings = store.get(site["name"], "psi.findings", [])
        result.summary = {"skipped": f"ran {last}; next after {INTERVAL_DAYS} days "
                                     "(force to override)"}
        return result
    key = credentials.read("google-api-key")
    urls = [site["url"] + p for p in (site.get("keyPaths") or ["/"])[:COLLECT_PAGES]]
    results, rows_, findings, warnings = _analyze(site, store, urls, "mobile", key,
                                                  today.isoformat(), total_first=True)
    result.rows, result.findings, result.warnings = rows_, findings, warnings
    result.summary = {"strategy": "mobile", "pages": [
        {"url": r.get("url"), "scores": r.get("scores"), "error": r.get("error")}
        for r in results], "keyless": not key}
    if any("scores" in r for r in results):
        store.put(site["name"], "psi.lastRun", today.isoformat())
        store.put(site["name"], "psi.findings", findings)
    return result


def run(site: dict, store, urls: list[str] | None = None, strategy: str = "mobile") -> dict:
    """On-demand run (after a deploy): stores today's points and diffs against the last run."""
    key = credentials.read("google-api-key")
    targets = urls or [site["url"] + p for p in (site.get("keyPaths") or ["/"])[:5]]
    day = datetime.now(UTC).date().isoformat()
    results, rows_, findings, warnings = _analyze(site, store, targets, strategy, key, day,
                                                  total_first=not urls)
    store.upsert(site["name"], rows_)
    out = {"strategy": strategy, "results": results, "findings": findings}
    if warnings:
        out["warnings"] = warnings
    if not key:
        out["note"] = ("No google-api-key stored; ran unauthenticated against Google's shared "
                       "quota, which is often exhausted. Store a free key with doctor.")
    return out
