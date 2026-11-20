"""Orchestrates ``audit_site``: crawl, per-page checks, AI access, delivery, issue history."""

from __future__ import annotations

import re
import urllib.parse
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor

from .. import dates
from ..sources.probe import Fetch, fetch, sitemap_urls
from ..store import Store
from . import ai_access, delivery, pages
from . import robots as robots_mod

SECTIONS = ("pages", "ai", "delivery")
SEVERITY_RANK = {"critical": 0, "warn": 1, "info": 2}
SKIP_EXT = re.compile(r"\.(pdf|jpe?g|png|gif|webp|avif|svg|ico|zip|gz|mp[34]|css|js|json|xml|"
                      r"txt|woff2?|ttf)$", re.I)
WORKERS = 6
MAX_PAGES_LIMIT = 200
DEEP = 4
EXAMPLES = 5


def crawl(base: str, seeds: list[str], max_pages: int) -> dict:
    origin = urllib.parse.urlparse(base).netloc
    frontier = deque((u, 0) for u in seeds)
    seen = {u for u, _ in frontier}
    fetched: dict[str, Fetch] = {}
    depth: dict[str, int] = {}
    referrers: dict[str, set[str]] = defaultdict(set)
    snaps: list[dict] = []
    done_final: set[str] = set()
    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        while frontier and len(fetched) < max_pages:
            batch = []
            while frontier and len(batch) < WORKERS and len(fetched) + len(batch) < max_pages:
                batch.append(frontier.popleft())
            for (url, d), f in zip(batch, pool.map(lambda item: fetch(item[0]), batch)):
                fetched[url], depth[url] = f, d
                if f.error or not f.status or f.status >= 400 \
                        or "html" not in f.headers.get("content-type", ""):
                    continue
                if f.url in done_final:
                    continue
                done_final.add(f.url)
                snap = pages.snapshot(f, url)
                snap["depth"] = d
                snaps.append(snap)
                for link in snap["links"]:
                    target = urllib.parse.urljoin(f.url or url, link["href"]).split("#", 1)[0]
                    parsed = urllib.parse.urlparse(target)
                    if parsed.scheme not in ("http", "https") or parsed.netloc != origin:
                        continue
                    referrers[target].add(url)
                    if target not in seen and not SKIP_EXT.search(parsed.path):
                        seen.add(target)
                        frontier.append((target, d + 1))
    return {"snaps": snaps, "fetched": fetched, "referrers": referrers, "depth": depth,
            "complete": not frontier}


def _norm(url: str) -> str:
    return url.split("#", 1)[0].rstrip("/")


def _sitemap(base: str, robots: robots_mod.Robots) -> list[str]:
    candidates = robots.sitemaps or [base + "/sitemap-index.xml", base + "/sitemap.xml"]
    urls: list[str] = []
    for candidate in candidates:
        found, _errors = sitemap_urls(candidate)
        urls += found
        if found and not robots.sitemaps:
            break
    return sorted(set(urls))


def cross_findings(crawled: dict, sitemap: list[str], robots: robots_mod.Robots,
                   base: str) -> list[dict]:
    out: list[dict] = []
    snaps, fetched, referrers = crawled["snaps"], crawled["fetched"], crawled["referrers"]

    def add(kind, severity, category, **detail):
        out.append({"section": "pages", "category": category, "kind": kind,
                    "severity": severity, **detail})

    indexable = [s for s in snaps if not s["noindex"]]
    for field, kind, severity in (("title", "duplicate_titles", "warn"),
                                  ("description", "duplicate_descriptions", "info"),
                                  ("h1", "duplicate_h1", "info")):
        groups: dict[str, list[str]] = defaultdict(list)
        for s in indexable:
            if s[field]:
                groups[s[field].strip().lower()].append(s["url"])
        for value, urls in groups.items():
            if len(urls) > 1:
                add(kind, severity, "seo", value=value[:80], urls=urls[:6], pages=len(urls))
    broken = [{"url": u, "status": f.status, "foundOn": sorted(referrers.get(u, []))[:3]}
              for u, f in fetched.items() if f.error or not f.status or f.status >= 400]
    if broken:
        add("broken_internal_links", "warn", "usability", count=len(broken), urls=broken[:10])
    redirected = [u for u, f in fetched.items() if f.chain]
    if redirected:
        add("internal_links_to_redirects", "info", "performance", count=len(redirected),
            urls=redirected[:10], note="Link straight to the final URL; each redirect is a "
            "wasted round trip and a crawl detour.")
    deep = [s["url"] for s in snaps if s["depth"] > DEEP]
    if deep:
        add("deep_pages", "info", "seo", count=len(deep), urls=deep[:10],
            note=f"More than {DEEP} clicks from the home page.")
    by_final = {_norm(s["finalUrl"] or s["url"]): s for s in snaps}
    if sitemap:
        noindex, elsewhere, blocked, redirects = [], [], [], []
        for url in sitemap:
            allowed, _rule = robots_mod.check(robots, "Googlebot",
                                              urllib.parse.urlparse(url).path or "/")
            if not allowed:
                blocked.append(url)
            f = fetched.get(url)
            snap = by_final.get(_norm(url))
            if f is not None and f.chain:
                redirects.append(url)
            if snap and snap["noindex"]:
                noindex.append(url)
            elif snap and snap["canonical"] and urllib.parse.urlparse(snap["canonical"]).netloc \
                    and _norm(snap["canonical"]) != _norm(snap["finalUrl"] or url):
                elsewhere.append(url)
        for kind, severity, urls in (
                ("sitemap_url_blocked_by_robots", "warn", blocked),
                ("sitemap_url_noindex", "warn", noindex),
                ("sitemap_url_canonical_elsewhere", "warn", elsewhere),
                ("sitemap_url_redirects", "info", redirects)):
            if urls:
                add(kind, severity, "seo", count=len(urls), urls=urls[:10])
        if crawled["complete"]:
            known = {_norm(u) for u in referrers} | {_norm(u) for u in fetched}
            orphans = [u for u in sitemap if _norm(u) not in known]
            if orphans:
                add("orphan_pages", "warn", "seo", count=len(orphans), urls=orphans[:10],
                    note="In the sitemap but no crawled page links to them.")
            in_map = {_norm(u) for u in sitemap}
            missing = [s["url"] for s in indexable
                       if _norm(s["finalUrl"] or s["url"]) not in in_map]
            if missing:
                add("pages_missing_from_sitemap", "info", "seo", count=len(missing),
                    urls=missing[:10])
    return out


def group(findings: list[dict]) -> list[dict]:
    """Collapse repeated per-page findings into one entry per kind with a few examples."""
    by_kind: dict[str, list[dict]] = defaultdict(list)
    for f in findings:
        by_kind[f["kind"]].append(f)
    out = []
    for kind, items in by_kind.items():
        severity = min((i["severity"] for i in items), key=SEVERITY_RANK.get)
        first = items[0]
        examples = [{k: v for k, v in i.items()
                     if k not in ("section", "category", "kind", "severity", "note")}
                    for i in items[:EXAMPLES]]
        entry = {"kind": kind, "severity": severity, "category": first["category"],
                 "section": first["section"], "occurrences": len(items), "examples": examples}
        if first.get("note"):
            entry["note"] = first["note"]
        out.append(entry)
    out.sort(key=lambda e: (SEVERITY_RANK[e["severity"]], -e["occurrences"], e["kind"]))
    return out


def track(store: Store, site: dict, grouped: list[dict], sections: set[str]) -> dict:
    """Issue lifecycle across audits: new, persisting (with age) and resolved."""
    today = dates.today(site["timezone"]).isoformat()
    history = store.get(site["name"], "audit.history", {})
    current = {g["kind"]: g for g in grouped}
    new, resolved = [], []
    for kind, g in current.items():
        entry = history.get(kind)
        if not entry or entry.get("resolvedOn"):
            history[kind] = {"firstSeen": today, "section": g["section"]}
            new.append(kind)
        history[kind].update({"lastSeen": today, "severity": g["severity"],
                              "occurrences": g["occurrences"]})
        history[kind].pop("resolvedOn", None)
        g["status"] = "new" if kind in new else "persisting"
        g["firstSeen"] = history[kind]["firstSeen"]
    for kind, entry in history.items():
        if kind not in current and not entry.get("resolvedOn") and entry["section"] in sections:
            entry["resolvedOn"] = today
            resolved.append(kind)
    store.put(site["name"], "audit.history", history)
    return {"new": sorted(new), "resolved": sorted(resolved),
            "persisting": len(current) - len(new)}


def _compact_policy(matrix: list[dict]) -> list[dict]:
    return [{"bot": r["bot"], "vendor": r["vendor"], "role": r["role"], "allowed": r["allowed"],
             **({"blockedPaths": [p for p, v in r["paths"].items() if not v["allowed"]]}
                if not r["allowed"] else {}), **({"note": r["note"]} if r.get("note") else {})}
            for r in matrix]


def _compact_bot_fetch(results: list[dict]) -> list[dict]:
    worst: dict[str, dict] = {}
    for r in results:
        cur = worst.get(r["bot"])
        if cur is None or (cur["result"] == "ok" and r["result"] != "ok"):
            worst[r["bot"]] = r
    return [{"bot": b, "role": r["role"], "result": r["result"], "status": r["status"]}
            for b, r in worst.items()]


def run(site: dict, store: Store, max_pages: int = 50,
        sections: list[str] | None = None) -> dict:
    wanted = set(sections or SECTIONS)
    unknown = wanted - set(SECTIONS)
    if unknown:
        return {"ok": False, "error": "unknown_section", "sections": sorted(unknown),
                "known": list(SECTIONS)}
    base = site["url"]
    host = urllib.parse.urlparse(base).hostname or ""
    paths = site.get("keyPaths") or ["/"]
    max_pages = max(1, min(max_pages, MAX_PAGES_LIMIT))
    robots_fetch = fetch(base + "/robots.txt")
    robots = robots_mod.parse(robots_fetch.body) if robots_fetch.status == 200 else None
    findings: list[dict] = []
    out: dict = {"ok": True, "site": site["name"], "url": base, "sections": sorted(wanted)}

    seeds = list(dict.fromkeys([base + "/"] + [base + p for p in paths]))
    crawled = crawl(base, seeds, max_pages)
    snaps = crawled["snaps"]
    out.update({"pagesCrawled": len(crawled["fetched"]), "htmlPages": len(snaps),
                "crawlComplete": crawled["complete"]})
    for snap in snaps:
        is_home = urllib.parse.urlparse(snap["finalUrl"] or snap["url"]).path in ("", "/")
        for f in pages.page_findings(snap, is_home=is_home, site=site):
            if f["category"] == "ai":
                f["section"] = "ai"
            findings.append(f)
    findings += pages.tag_findings(snaps, site)
    findings += cross_findings(crawled, _sitemap(base, robots or robots_mod.Robots()),
                               robots or robots_mod.Robots(), base)

    if "ai" in wanted:
        matrix = ai_access.policy(robots, paths)
        findings += ai_access.policy_findings(matrix, (robots.signals if robots else {}))
        results, bot_findings = ai_access.fetch_as_bots(base, paths[:2])
        findings += bot_findings
        llms, llms_findings = ai_access.llms_txt(base)
        findings += llms_findings
        out["ai"] = {
            "robotsTxt": "found" if robots else f"missing ({robots_fetch.status})",
            "policy": _compact_policy(matrix), "botFetch": _compact_bot_fetch(results),
            "llmsTxt": llms, "commonCrawl": ai_access.common_crawl(host),
            "contentSignals": robots.signals if robots else {},
            "caveat": "Bot fetches use each bot's user-agent string only. CDNs that verify "
                      "bots by IP may treat the real crawler differently."}
    if "delivery" in wanted:
        host_info, host_findings = delivery.host_config(base)
        asset_stats, asset_findings = delivery.assets(snaps, base)
        findings += host_findings + asset_findings
        out["delivery"] = {"host": host_info, "assets": asset_stats}

    findings = [f for f in findings if f["section"] in wanted]
    grouped = group(findings)
    out["history"] = track(store, site, grouped, wanted)
    out["findings"] = grouped
    out["summary"] = {
        "bySeverity": {s: sum(g["severity"] == s for g in grouped) for s in SEVERITY_RANK},
        "byCategory": {c: sum(g["category"] == c for g in grouped)
                       for c in sorted({g["category"] for g in grouped})}}
    out["pages"] = [{"url": s["url"], "depth": s["depth"], "words": s["words"],
                     "title": s["title"], "h1": s["h1"], "noindex": s["noindex"]}
                    for s in snaps[:60]]
    store.put(site["name"], "audit.last", {"date": dates.today(site["timezone"]).isoformat(),
                                           "summary": out["summary"]})
    store.snapshot(site["name"], "audit", "audit", {**out, "findingsRaw": findings})
    return out
