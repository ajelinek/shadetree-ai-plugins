"""AI crawler and LLM access validation. Everything here is account-free.

Three layers, because each catches something the others miss:

1. ``policy``: what robots.txt says per bot (and Content-Signal lines).
2. ``fetch_as_bots``: what the server actually returns to each bot's user agent, which
   catches CDN/WAF blocks robots.txt never mentions. A spoofed user agent cannot prove the
   *real* bot gets through (WAFs often verify by IP), so a block here is strong evidence
   and a pass is only weak evidence.
3. Site-side readiness (``llms_txt``, ``common_crawl``); page-level readiness (content in raw
   HTML, snippet limits, structured data) lives in ``pages``.

The bot list changes often. Names come from vendor docs and secondary guides as of
2026-11; keep this table the one place to edit.
"""

from __future__ import annotations

import re
import urllib.parse
from concurrent.futures import ThreadPoolExecutor

from .. import http
from ..sources.probe import Fetch, fetch
from . import robots as robots_mod

TRAINING, SEARCH, USER, INDEX = "training", "search", "user", "index"

# token = robots.txt product token; ua = identifying user agent (None: robots-only control token).
BOTS: list[dict] = [
    {"token": "Googlebot", "vendor": "Google", "role": INDEX,
     "ua": "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"},
    {"token": "Bingbot", "vendor": "Microsoft", "role": INDEX,
     "ua": "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)"},
    {"token": "OAI-SearchBot", "vendor": "OpenAI", "role": SEARCH,
     "ua": "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; "
           "OAI-SearchBot/1.0; +https://openai.com/searchbot"},
    {"token": "ChatGPT-User", "vendor": "OpenAI", "role": USER,
     "ua": "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; "
           "ChatGPT-User/1.0; +https://openai.com/bot"},
    {"token": "GPTBot", "vendor": "OpenAI", "role": TRAINING,
     "ua": "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; "
           "GPTBot/1.1; +https://openai.com/gptbot"},
    {"token": "Claude-SearchBot", "vendor": "Anthropic", "role": SEARCH,
     "ua": "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; "
           "Claude-SearchBot/1.0; +Claude-SearchBot@anthropic.com)"},
    {"token": "Claude-User", "vendor": "Anthropic", "role": USER,
     "ua": "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; "
           "Claude-User/1.0; +Claude-User@anthropic.com)"},
    {"token": "ClaudeBot", "vendor": "Anthropic", "role": TRAINING,
     "ua": "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; "
           "ClaudeBot/1.0; +claudebot@anthropic.com)"},
    {"token": "PerplexityBot", "vendor": "Perplexity", "role": SEARCH,
     "ua": "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; "
           "PerplexityBot/1.0; +https://perplexity.ai/perplexitybot)"},
    {"token": "Perplexity-User", "vendor": "Perplexity", "role": USER,
     "ua": "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; "
           "Perplexity-User/1.0; +https://perplexity.ai/perplexity-user)"},
    {"token": "Google-Extended", "vendor": "Google", "role": TRAINING, "ua": None,
     "note": "control token for Gemini/Vertex training; does not affect Search"},
    {"token": "Applebot-Extended", "vendor": "Apple", "role": TRAINING, "ua": None,
     "note": "control token for Apple model training"},
    {"token": "CCBot", "vendor": "Common Crawl", "role": TRAINING,
     "ua": "CCBot/2.0 (https://commoncrawl.org/faq/)"},
    {"token": "Meta-ExternalAgent", "vendor": "Meta", "role": TRAINING,
     "ua": "meta-externalagent/1.1 (+https://developers.facebook.com/docs/sharing/"
           "webmasters/crawler)"},
    {"token": "Bytespider", "vendor": "ByteDance", "role": TRAINING,
     "ua": "Mozilla/5.0 (compatible; Bytespider; spider-feedback@bytedance.com)"},
    {"token": "anthropic-ai", "vendor": "Anthropic", "role": TRAINING, "ua": None,
     "note": "legacy token; ClaudeBot is current"},
]

BLOCK_STATUSES = {401, 403, 406, 429, 451, 503}
CHALLENGE = re.compile(r"just a moment|cf-chl|captcha|attention required|access denied|"
                       r"enable javascript and cookies|verify you are (a )?human", re.I)


def policy(robots: robots_mod.Robots | None, paths: list[str]) -> list[dict]:
    """Per-bot allow/deny from robots.txt for each path (no robots.txt = all allowed)."""
    robots = robots or robots_mod.Robots()
    out = []
    for bot in BOTS:
        verdicts = {}
        for path in paths:
            allowed, rule = robots_mod.check(robots, bot["token"], path)
            verdicts[path] = {"allowed": allowed, **({"rule": rule} if rule else {})}
        out.append({"bot": bot["token"], "vendor": bot["vendor"], "role": bot["role"],
                    "allowed": all(v["allowed"] for v in verdicts.values()),
                    "paths": verdicts, **({"note": bot["note"]} if bot.get("note") else {})})
    return out


def policy_findings(matrix: list[dict], signals: dict[str, str]) -> list[dict]:
    findings = []

    def add(kind, severity, **detail):
        findings.append({"section": "ai", "category": "ai", "kind": kind,
                         "severity": severity, **detail})

    blocked = {r["bot"]: r for r in matrix if not r["allowed"]}
    for role, kind, severity, note in (
            (INDEX, "search_engine_blocked_by_robots", "critical",
             "Blocks organic search; confirm this is intended."),
            (SEARCH, "ai_search_bot_blocked_by_robots", "warn",
             "Blocks citation in AI search answers (the bot that finds pages to cite)."),
            (USER, "ai_user_agent_blocked_by_robots", "info",
             "Assistants can't open the page when a user shares or asks about its URL.")):
        hits = [b for b, r in blocked.items() if r["role"] == role]
        if hits:
            add(kind, severity, bots=hits, note=note)
    training = [b for b, r in blocked.items() if r["role"] == TRAINING]
    if training:
        add("ai_training_blocked_by_robots", "info", bots=training,
            note="A policy choice; training opt-out does not remove you from AI search.")
    if signals:
        add("content_signals_declared", "info", signals=signals)
        if signals.get("search") == "no":
            add("content_signal_search_no", "warn", signals=signals,
                note="Content-Signal search=no asks search engines not to use the content.")
    return findings


def _fetch(url: str, ua: str | None) -> Fetch:
    return fetch(url, headers={"User-Agent": ua} if ua else None)


def classify(base: Fetch, bot: Fetch) -> str:
    if bot.error or not bot.status:
        return "error"
    if base.status and base.status < 400 and bot.status in BLOCK_STATUSES:
        return "blocked"
    if bot.status < 400 and CHALLENGE.search(bot.body[:5000]) and \
            not CHALLENGE.search(base.body[:5000]):
        return "challenge"
    if base.body and bot.body and len(bot.body) < 0.5 * len(base.body):
        return "different_content"
    return "ok"


def fetch_as_bots(base_url: str, paths: list[str]) -> tuple[list[dict], list[dict]]:
    """Fetch each path as each fetch-capable bot and compare with the default fetch."""
    bots = [b for b in BOTS if b["ua"]]
    targets = [base_url + p for p in paths]
    with ThreadPoolExecutor(max_workers=6) as pool:
        baseline = dict(zip(targets, pool.map(lambda u: _fetch(u, None), targets)))
        jobs = [(b, u) for b in bots for u in targets]
        fetched = list(pool.map(lambda j: _fetch(j[1], j[0]["ua"]), jobs))
    results = []
    for (bot, url), f in zip(jobs, fetched):
        results.append({"bot": bot["token"], "role": bot["role"], "url": url, "status": f.status,
                        "result": classify(baseline[url], f),
                        **({"error": f.error} if f.error else {})})
    findings = []
    bad = [r for r in results if r["result"] in ("blocked", "challenge", "different_content")]
    for role, kind, severity in ((INDEX, "search_bot_blocked_by_server", "critical"),
                                 (SEARCH, "ai_search_bot_blocked_by_server", "warn"),
                                 (USER, "ai_user_agent_blocked_by_server", "warn"),
                                 (TRAINING, "ai_training_bot_blocked_by_server", "info")):
        hits = [r for r in bad if r["role"] == role]
        if hits:
            findings.append({
                "section": "ai", "category": "ai", "kind": kind, "severity": severity,
                "examples": [{k: r[k] for k in ("bot", "url", "status", "result")}
                             for r in hits[:6]],
                "note": "Server answered this bot's user agent differently from a normal "
                        "fetch (CDN/WAF rule such as 'block AI bots'). robots.txt can say "
                        "'allowed' while the firewall refuses."})
    return results, findings


def llms_txt(base_url: str) -> tuple[dict, list[dict]]:
    """Check /llms.txt. Informational: no major AI search provider is confirmed to use it."""
    f = fetch(base_url + "/llms.txt")
    findings: list[dict] = []
    info: dict = {"present": f.status == 200, "status": f.status}
    if f.status != 200:
        findings.append({"section": "ai", "category": "ai", "kind": "llms_txt_missing",
                         "severity": "info",
                         "note": "Optional. Google says it isn't needed for AI features and "
                                 "large studies show most llms.txt files get no AI requests."})
        return info, findings
    lines = [ln.strip() for ln in f.body.splitlines() if ln.strip()]
    links = re.findall(r"\[[^\]]+\]\((https?://[^)\s]+|/[^)\s]*)\)", f.body)
    info.update({"startsWithH1": bool(lines) and lines[0].startswith("# "),
                 "hasSummary": any(ln.startswith(">") for ln in lines), "links": len(links)})
    if not info["startsWithH1"] or not links:
        findings.append({"section": "ai", "category": "ai", "kind": "llms_txt_malformed",
                         "severity": "info",
                         "note": "Spec: an H1 title, an optional > summary, then H2 sections "
                                 "of [title](url) links."})
    sample = [urllib.parse.urljoin(base_url + "/", u) for u in links[:10]]
    with ThreadPoolExecutor(max_workers=6) as pool:
        checks = list(pool.map(lambda u: fetch(u, method="HEAD", read_body=False), sample))
    broken = [{"url": c.url, "status": c.status} for c in checks
              if c.error or not c.status or c.status >= 400]
    if broken:
        findings.append({"section": "ai", "category": "ai", "kind": "llms_txt_broken_links",
                         "severity": "warn", "urls": broken})
    return info, findings


def common_crawl(host: str, crawls: int = 3) -> dict:
    """Is the domain in the latest Common Crawl archives (a feed for many LLM datasets)?"""
    try:
        listing = http.request("GET", "https://index.commoncrawl.org/collinfo.json",
                               timeout=20).data or []
    except http.HttpError as exc:
        return {"checked": False, "error": str(exc)}
    seen, checked = [], 0
    for entry in listing[:crawls]:
        api = entry.get("cdx-api")
        if not api:
            continue
        checked += 1
        try:
            text = http.request("GET", api, params={"url": host, "matchType": "domain",
                                                    "output": "json", "limit": "1"},
                                timeout=45, expect_json=False).data
        except http.HttpError as exc:
            if exc.status == 404:  # "No Captures found"
                continue
            return {"checked": False, "error": str(exc)}
        if text and text.strip():
            seen.append(entry.get("id"))
    return {"checked": True, "crawlsChecked": checked, "foundIn": seen}
