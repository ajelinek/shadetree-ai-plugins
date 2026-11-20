"""PageSpeed Insights v5: Lighthouse lab runs on key URLs (run after deploys)."""

from __future__ import annotations

from .. import credentials, http

NAME = "psi"
URL = "https://www.googleapis.com/pagespeedonline/v5/runPagespeed"
CATEGORIES = ["performance", "accessibility", "best-practices", "seo"]


def summarize(data: dict) -> dict:
    lh = data.get("lighthouseResult") or {}
    cats = {k: round((v.get("score") or 0) * 100) for k, v in (lh.get("categories") or {}).items()}
    audits = lh.get("audits") or {}
    failing = []
    for audit_id, audit in audits.items():
        score = audit.get("score")
        if score is not None and audit.get("scoreDisplayMode") in ("binary", "numeric") \
                and score < 0.9:
            failing.append({"id": audit_id, "title": audit.get("title"), "score": score,
                            "displayValue": audit.get("displayValue")})
    failing.sort(key=lambda a: a["score"])
    lab = {k: (audits.get(k) or {}).get("numericValue") for k in (
        "largest-contentful-paint", "cumulative-layout-shift", "total-blocking-time",
        "first-contentful-paint", "speed-index")}
    return {"url": lh.get("finalDisplayedUrl") or lh.get("requestedUrl"), "scores": cats,
            "lab": lab, "failingAudits": failing[:25],
            "lighthouseVersion": lh.get("lighthouseVersion")}


def run(site: dict, store, urls: list[str] | None = None, strategy: str = "mobile") -> dict:
    key = credentials.read("google-api-key")
    targets = urls or [site["url"] + p for p in (site.get("keyPaths") or ["/"])[:5]]
    results = []
    previous = store.get(site["name"], f"psi.last.{strategy}", {})
    for url in targets:
        params = {"url": url, "strategy": strategy, "category": CATEGORIES}
        try:
            data = http.request("GET", URL, params=params,
                                secret_params={"key": key} if key else None, timeout=120).data
        except http.HttpError as exc:
            results.append({"url": url, "error": str(exc)})
            continue
        summary = summarize(data)
        prior = previous.get(url)
        if prior:
            summary["scoreDelta"] = {k: v - prior["scores"].get(k, v)
                                     for k, v in summary["scores"].items()}
            prior_ids = {a["id"] for a in prior.get("failingAudits", [])}
            summary["newlyFailing"] = [a for a in summary["failingAudits"]
                                       if a["id"] not in prior_ids]
        previous[url] = {"scores": summary["scores"], "failingAudits": summary["failingAudits"]}
        results.append(summary)
    store.put(site["name"], f"psi.last.{strategy}", previous)
    out = {"strategy": strategy, "results": results}
    if not key:
        out["note"] = "No google-api-key stored; ran unauthenticated (low shared quota)."
    return out
