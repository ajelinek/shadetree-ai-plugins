import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from shadetree_ai_plugins_website_health.audit import ai_access, delivery, pages, run
from shadetree_ai_plugins_website_health.audit import robots as robots_mod
from shadetree_ai_plugins_website_health.sources.probe import Fetch

HOME = """<!doctype html><html><head><title>Acme Plumbing</title>
<meta name="description" content="Plumbing help.">
<link rel="canonical" href="{base}/">
<script src="/static/app.js"></script>
<script async src="https://www.googletagmanager.com/gtag/js?id=G-ABC123XYZ"></script>
<script type="application/ld+json">{{"@type": "Organization", "name": "Acme"}}</script>
</head><body><main><h1>Acme Plumbing</h1>
<img src="/static/hero.png"><a href="/about">About</a><a href="/thin">more</a>
<a href="/gone">Gone</a>{filler}</main></body></html>"""
FILLER = "<p>" + "word " * 250 + "</p>"
ABOUT = ('<!doctype html><html lang="en"><head><title>Acme Plumbing</title>'
         '<meta name="viewport" content="width=device-width">'
         '<link rel="canonical" href="{base}/about"></head><body><main><h1>About</h1>'
         + FILLER + '<a href="/">Home</a></main></body></html>')
THIN = ('<!doctype html><html lang="en"><head><title>Thin</title></head>'
        '<body><div id="root"></div><script src="a.js"></script></body></html>')
ROBOTS = ("User-agent: GPTBot\nDisallow: /\n\nUser-agent: *\nAllow: /\n"
          "Content-Signal: ai-train=no, search=yes\nSitemap: {base}/sitemap.xml\n")
SITEMAP = ('<?xml version="1.0"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
           '<url><loc>{base}/</loc></url><url><loc>{base}/about</loc></url>'
           '<url><loc>{base}/orphan</loc></url></urlset>')
ORPHAN = ('<!doctype html><html lang="en"><head><title>Orphan page here</title></head>'
          '<body><main><h1>O</h1>' + FILLER + '</main></body></html>')


class Handler(BaseHTTPRequestHandler):
    def _send(self, head=False):
        ua = self.headers.get("User-Agent", "")
        base = self.server.base
        routes = {
            "/": ("text/html", HOME.format(base=base, filler=FILLER)),
            "/about": ("text/html", ABOUT.format(base=base)),
            "/thin": ("text/html", THIN),
            "/orphan": ("text/html", ORPHAN),
            "/robots.txt": ("text/plain", ROBOTS.format(base=base)),
            "/sitemap.xml": ("application/xml", SITEMAP.format(base=base)),
            "/llms.txt": ("text/plain", "# Acme\n> Plumbers\n## Docs\n- [About](/about)\n"
                                        "- [Missing](/nope)\n"),
            "/static/app.js": ("application/javascript", "x" * 5000),
            "/static/hero.png": ("image/png", "p" * 300000),
        }
        if "PerplexityBot" in ua:
            self.send_response(403)
            self.end_headers()
            return
        if self.path not in routes:
            self.send_response(404)
            self.end_headers()
            return
        ctype, body = routes[self.path]
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if not head:
            self.wfile.write(body.encode())

    def do_GET(self):
        self._send()

    def do_HEAD(self):
        self._send(head=True)

    def log_message(self, *args):
        pass


@pytest.fixture
def server():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    srv.base = f"http://127.0.0.1:{srv.server_address[1]}"
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv.base
    srv.shutdown()


# ----------------------------------------------------------------- robots
def test_robots_longest_match_and_specific_group():
    r = robots_mod.parse("User-agent: *\nDisallow: /private\nAllow: /private/ok\n\n"
                         "User-agent: GPTBot\nDisallow: /\n")
    assert robots_mod.check(r, "Googlebot", "/private/x") == (False, "/private")
    assert robots_mod.check(r, "Googlebot", "/private/ok/page")[0] is True
    assert robots_mod.check(r, "GPTBot", "/anything") == (False, "/")
    assert robots_mod.check(r, "gptbot", "/")[0] is False  # tokens are case-insensitive


def test_robots_wildcards_end_anchor_and_empty_disallow():
    r = robots_mod.parse("User-agent: a\nUser-agent: b\nDisallow: /*.pdf$\nDisallow:\n")
    assert robots_mod.check(r, "b", "/files/x.pdf")[0] is False
    assert robots_mod.check(r, "b", "/files/x.pdf?v=1")[0] is True
    assert robots_mod.check(robots_mod.Robots(), "GPTBot", "/")[0] is True


def test_robots_parses_content_signals_and_sitemaps():
    r = robots_mod.parse("User-agent: *\nContent-Signal: search=yes, ai-train=no\n"
                         "Sitemap: https://e.com/s.xml")
    assert r.signals == {"search": "yes", "ai-train": "no"}
    assert r.sitemaps == ["https://e.com/s.xml"]


# --------------------------------------------------------------- ai access
def test_policy_flags_blocked_search_bot_but_only_notes_training_block():
    r = robots_mod.parse("User-agent: OAI-SearchBot\nDisallow: /\n\nUser-agent: GPTBot\n"
                         "Disallow: /\n")
    matrix = ai_access.policy(r, ["/"])
    kinds = {f["kind"]: f for f in ai_access.policy_findings(matrix, {})}
    assert kinds["ai_search_bot_blocked_by_robots"]["severity"] == "warn"
    assert kinds["ai_training_blocked_by_robots"]["severity"] == "info"
    assert "search_engine_blocked_by_robots" not in kinds


def test_classify_detects_waf_block_challenge_and_thin_response():
    base = Fetch("u", status=200, body="x" * 1000)
    assert ai_access.classify(base, Fetch("u", status=403)) == "blocked"
    assert ai_access.classify(base, Fetch("u", status=200, body="Just a moment...")) \
        == "challenge"
    assert ai_access.classify(base, Fetch("u", status=200, body="x" * 100)) \
        == "different_content"
    assert ai_access.classify(base, Fetch("u", status=200, body="x" * 900)) == "ok"


def test_fetch_as_bots_reports_server_side_block(server):
    results, findings = ai_access.fetch_as_bots(server, ["/"])
    by_bot = {r["bot"]: r["result"] for r in results}
    assert by_bot["PerplexityBot"] == "blocked" and by_bot["GPTBot"] == "ok"
    assert [f["kind"] for f in findings] == ["ai_search_bot_blocked_by_server"]


def test_llms_txt_validates_and_reports_broken_links(server):
    info, findings = ai_access.llms_txt(server)
    assert info["present"] and info["startsWithH1"] and info["links"] == 2
    assert [f["kind"] for f in findings] == ["llms_txt_broken_links"]


# ------------------------------------------------------------------- pages
def test_page_findings_cover_seo_accessibility_and_performance():
    html = HOME.format(base="https://e.com", filler="")
    snap = pages.snapshot(Fetch("https://e.com/", status=200, body=html,
                                headers={"content-type": "text/html"}), "https://e.com/")
    kinds = {f["kind"] for f in pages.page_findings(snap, is_home=True, site={})}
    assert {"missing_html_lang", "missing_viewport", "images_missing_alt",
            "images_without_dimensions", "render_blocking_scripts", "missing_social_tags",
            "structured_data_incomplete"} <= kinds
    assert snap["tags"]["ga4"] == ["G-ABC123XYZ"]
    assert "missing_title" not in kinds and "no_entity_schema" not in kinds


def test_client_rendered_page_is_flagged_for_ai_crawlers():
    snap = pages.snapshot(Fetch("https://e.com/t", status=200, body=THIN), "https://e.com/t")
    found = {f["kind"] for f in pages.page_findings(snap, is_home=False, site={})}
    assert "client_rendered_suspect" in found and "thin_content" in found


def test_tag_findings_check_configured_accounts_against_html():
    with_tag = pages.snapshot(Fetch("https://e.com/", status=200, body=HOME.format(
        base="x", filler="")), "https://e.com/")
    without = pages.snapshot(Fetch("https://e.com/a", status=200, body=THIN), "https://e.com/a")
    site = {"ga4PropertyId": "1", "clarityProjectId": "abc123"}
    kinds = {f["kind"] for f in pages.tag_findings([with_tag, without], site)}
    assert {"analytics_tag_missing", "clarity_tag_not_found"} <= kinds


# ---------------------------------------------------------------- delivery
def test_assets_flag_missing_compression_cache_and_large_images(server):
    snap = pages.snapshot(Fetch(server + "/", status=200, body=HOME.format(base=server,
                          filler="")), server + "/")
    snap["finalUrl"] = server + "/"
    stats, findings = delivery.assets([snap], server)
    kinds = {f["kind"] for f in findings}
    assert {"assets_not_compressed", "assets_without_cache_headers", "large_images",
            "legacy_image_formats"} <= kinds
    assert stats["checked"] == 2


def test_host_config_flags_soft_404_and_slow_ttfb(monkeypatch):
    def fake(url, method="GET", read_body=True, headers=None):
        status = 404 if url.endswith("security.txt") else 200
        f = Fetch(url, status=status, ttfb_ms=2000.0, headers={"content-encoding": "br"})
        f.url = url
        return f

    monkeypatch.setattr(delivery, "fetch", fake)
    monkeypatch.setattr(delivery, "negotiated_protocol", lambda host: "http/1.1")
    _info, findings = delivery.host_config("https://example.com")
    kinds = {f["kind"] for f in findings}
    assert {"ttfb_poor", "no_http2", "soft_404", "security_txt_missing"} <= kinds


def test_csp_and_cache_helpers():
    assert delivery._csp_weak("script-src 'self' 'unsafe-inline'")
    assert not delivery._csp_weak("script-src 'self' 'nonce-abc' 'unsafe-inline'")
    assert delivery.max_age("public, max-age=600") == 600 and delivery.max_age(None) is None


# -------------------------------------------------------------- end to end
def test_audit_run_end_to_end_with_history(server, store, monkeypatch):
    monkeypatch.setattr(ai_access, "common_crawl",
                        lambda host: {"checked": True, "foundIn": []})
    site = {"name": "t", "url": server, "timezone": "UTC", "keyPaths": ["/"],
            "ga4PropertyId": "1"}
    out = run.run(site, store, max_pages=20, sections=["pages", "ai"])
    kinds = {g["kind"]: g for g in out["findings"]}
    assert out["crawlComplete"] and out["htmlPages"] == 3
    assert "duplicate_titles" in kinds and "broken_internal_links" in kinds
    assert "orphan_pages" in kinds and "analytics_tag_missing" in kinds
    assert kinds["ai_search_bot_blocked_by_server"]["category"] == "ai"
    assert {p["bot"]: p["allowed"] for p in out["ai"]["policy"]}["GPTBot"] is False
    assert out["ai"]["contentSignals"] == {"ai-train": "no", "search": "yes"}
    assert all(g["status"] == "new" for g in out["findings"])
    again = run.run(site, store, max_pages=20, sections=["pages", "ai"])
    assert again["history"]["new"] == [] and again["history"]["persisting"] == len(
        again["findings"])
    assert run.run(site, store, sections=["bogus"])["error"] == "unknown_section"


def test_history_marks_fixed_issues_resolved(store):
    site = {"name": "t", "timezone": "UTC"}
    g = [{"kind": "k", "severity": "warn", "category": "seo", "section": "pages",
          "occurrences": 1, "examples": []}]
    assert run.track(store, site, g, {"pages"})["new"] == ["k"]
    assert run.track(store, site, [], {"ai"})["resolved"] == []  # other section: untouched
    assert run.track(store, site, [], {"pages"})["resolved"] == ["k"]
    assert run.track(store, site, g, {"pages"})["new"] == ["k"]  # regressed: new again


async def test_audit_site_tool_runs_through_mcp(server):
    from fastmcp import Client
    from shadetree_ai_plugins_website_health import config
    from shadetree_ai_plugins_website_health.server import mcp

    config.upsert_site("local", {"url": server})
    async with Client(mcp) as client:
        out = (await client.call_tool("audit_site", {"site": "local", "max_pages": 5,
                                                     "sections": ["pages"]})).data
    assert out["ok"] and out["htmlPages"] >= 1 and out["summary"]["bySeverity"]["warn"] >= 1
