import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from shadetree_ai_plugins_website_health.sources import blocklists, indexnow, links, probe

PAGES = {
    "/": (200, '<html><head><title>Home</title><link rel="canonical" href="/">'
               '<script type="application/ld+json">{"@type": "Organization"}</script>'
               '</head><body><h1>Hi</h1><a href="/about">a</a><a href="/gone">g</a>'
               '</body></html>'),
    "/about": (200, "<html><head><title>About</title><meta name='robots' content='noindex'>"
                    "</head><body><h1>About</h1></body></html>"),
    "/robots.txt": (200, "User-agent: *\nDisallow:\nSitemap: {base}/sitemap.xml\n"),
    "/sitemap.xml": (200, '<?xml version="1.0"?><urlset xmlns="http://www.sitemaps.org/'
                          'schemas/sitemap/0.9"><url><loc>{base}/</loc></url><url><loc>{base}'
                          '/gone</loc></url></urlset>'),
    "/old": (301, ""),
    "/KEY12345.txt": (200, "KEY12345"),
}


class Handler(BaseHTTPRequestHandler):
    def _send(self, body=True):
        status, text = PAGES.get(self.path, (404, "nope"))
        text = text.replace("{base}", self.server.base)
        self.send_response(status)
        if status == 301:
            self.send_header("Location", "/")
        self.send_header("Content-Type", "text/html")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        if body:
            self.wfile.write(text.encode())

    def do_GET(self):
        self._send()

    def do_HEAD(self):
        self._send(body=False)

    def log_message(self, *args):
        pass


@pytest.fixture
def server():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    srv.base = f"http://127.0.0.1:{srv.server_address[1]}"
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    yield srv.base
    srv.shutdown()


def test_probe_finds_noindex_broken_sitemap_urls_and_diffs(server, store):
    site = {"name": "t", "url": server, "timezone": "UTC", "keyPaths": ["/", "/about"],
            "contentMarkers": {"/": "Hi"}}
    first = probe.collect(site, store)
    kinds = {f["kind"] for f in first.findings}
    assert "noindex" in kinds and "sitemap_broken_urls" in kinds
    assert first.summary["pages"]["/"]["jsonldTypes"] == ["Organization"]
    original = PAGES["/"]
    PAGES["/"] = (200, original[1].replace('<link rel="canonical" href="/">', ""))
    try:
        second = probe.collect(site, store)
    finally:
        PAGES["/"] = original
    assert "canonical_changed" in {f["kind"] for f in second.findings}


def test_fetch_records_redirect_chain(server):
    f = probe.fetch(server + "/old")
    assert f.status == 200 and f.chain[0]["status"] == 301


def test_link_crawl_reports_broken_internal_link(server):
    result = links.crawl({"url": server}, max_pages=10, check_external=False)
    assert any(b["url"].endswith("/gone") and b["internal"] for b in result["broken"])


def test_indexnow_key_file_check(server, store):
    ok = indexnow.collect({"url": server, "indexnowKey": "KEY12345"}, store)
    assert ok.summary["matches"] is True
    bad = indexnow.collect({"url": server, "indexnowKey": "OTHERKEY1"}, store)
    assert bad.findings[0]["kind"] == "indexnow_key_missing"
    assert indexnow.submit({"url": server, "indexnowKey": "KEY12345"},
                           ["https://elsewhere.test/x"])["error"] == "urls_off_host"


def test_robots_parse_detects_disallow_all():
    parsed = probe.parse_robots("User-agent: *\nDisallow: /\nSitemap: https://e.com/s.xml")
    assert parsed == {"sitemaps": ["https://e.com/s.xml"], "disallowAll": True}


def test_blocklist_refusal_is_unknown_not_clean():
    assert blocklists.interpret("spamhaus_dbl", ["127.255.255.254"], True)["status"] == \
        "query_refused"
    assert blocklists.interpret("spamhaus_dbl", [], False)["status"] == "unreliable_resolver"
    assert blocklists.interpret("spamhaus_dbl", ["127.0.1.4"], True)["codes"] == \
        ["phishing domain"]
