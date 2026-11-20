"""Live-site probe: no credentials, catches deploy regressions within minutes.

Checks HTTP status and redirect chain, TTFB, content markers, TLS expiry, DNS,
robots.txt, sitemap (count diff + sampled URL status), on-page SEO tags
(noindex, canonical, title, h1, JSON-LD validity) and security headers, then
diffs each key page against the previous probe to surface regressions.
"""

from __future__ import annotations

import json
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import UTC, datetime
from html.parser import HTMLParser

from .. import dates
from ..http import USER_AGENT
from ..store import Row, SourceResult

NAME = "probe"
TIMEOUT = 20
MAX_BODY = 5 * 1024 * 1024
MAX_REDIRECTS = 10
SITEMAP_SAMPLE = 20
SECURITY_HEADERS = ("strict-transport-security", "content-security-policy",
                    "x-content-type-options", "referrer-policy", "permissions-policy")
SM_NS = "{http://www.sitemaps.org/schemas/sitemap/0.9}"


def enabled(site: dict) -> tuple[bool, str]:
    return (bool(site.get("url")), "url not set")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


@dataclass
class Fetch:
    url: str
    status: int | None = None
    chain: list[dict] = field(default_factory=list)
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""
    ttfb_ms: float | None = None
    total_ms: float | None = None
    error: str | None = None


def fetch(url: str, method: str = "GET", read_body: bool = True) -> Fetch:
    result = Fetch(url)
    current = url
    start = time.monotonic()
    for _ in range(MAX_REDIRECTS + 1):
        req = urllib.request.Request(current, method=method, headers={"User-Agent": USER_AGENT})
        t0 = time.monotonic()
        try:
            resp = _OPENER.open(req, timeout=TIMEOUT)
        except urllib.error.HTTPError as exc:
            resp = exc
        except (urllib.error.URLError, OSError, ValueError) as exc:
            result.error = str(getattr(exc, "reason", exc))
            return result
        ttfb = (time.monotonic() - t0) * 1000
        status = resp.status if hasattr(resp, "status") else resp.code
        headers = {k.lower(): v for k, v in resp.headers.items()}
        location = headers.get("location")
        if 300 <= status < 400 and location:
            result.chain.append({"url": current, "status": status})
            resp.close()
            current = urllib.parse.urljoin(current, location)
            continue
        result.url, result.status, result.headers, result.ttfb_ms = current, status, headers, ttfb
        if read_body and method == "GET":
            try:
                raw = resp.read(MAX_BODY)
                result.body = raw.decode(resp.headers.get_content_charset() or "utf-8", "replace")
            except OSError as exc:
                result.error = f"body read failed: {exc}"
        resp.close()
        result.total_ms = (time.monotonic() - start) * 1000
        return result
    result.error = "too many redirects"
    return result


class PageParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.title, self.canonical, self.robots, self.description = None, None, None, None
        self.h1, self.jsonld, self._in = 0, [], None
        self._buf: list[str] = []

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "title":
            self._in, self._buf = "title", []
        elif tag == "h1":
            self.h1 += 1
        elif tag == "link" and "canonical" in a.get("rel", "").lower().split():
            self.canonical = a.get("href")
        elif tag == "meta":
            name = a.get("name", "").lower()
            if name in ("robots", "googlebot"):
                self.robots = ((self.robots or "") + "," + a.get("content", "")).strip(",")
            elif name == "description":
                self.description = a.get("content")
        elif tag == "script" and a.get("type", "").lower() == "application/ld+json":
            self._in, self._buf = "jsonld", []

    def handle_data(self, data):
        if self._in:
            self._buf.append(data)

    def handle_endtag(self, tag):
        if self._in == "title" and tag == "title":
            self.title = "".join(self._buf).strip()
            self._in = None
        elif self._in == "jsonld" and tag == "script":
            self.jsonld.append("".join(self._buf))
            self._in = None


def jsonld_types(blocks: list[str]) -> tuple[list[str], int]:
    types, invalid = [], 0
    for block in blocks:
        try:
            data = json.loads(block)
        except ValueError:
            invalid += 1
            continue
        items = data if isinstance(data, list) else data.get("@graph", [data]) \
            if isinstance(data, dict) else []
        for item in items:
            t = item.get("@type") if isinstance(item, dict) else None
            types += t if isinstance(t, list) else [t] if t else []
    return sorted(set(types)), invalid


def page_snapshot(f: Fetch, marker: str | None) -> dict:
    parser = PageParser()
    if f.body:
        try:
            parser.feed(f.body)
        except Exception:  # noqa: BLE001 - malformed HTML must not abort the probe
            pass
    types, invalid = jsonld_types(parser.jsonld)
    robots = ",".join(x for x in (parser.robots, f.headers.get("x-robots-tag")) if x).lower()
    snap = {
        "finalUrl": f.url, "status": f.status, "redirects": len(f.chain),
        "ttfbMs": round(f.ttfb_ms) if f.ttfb_ms else None, "title": parser.title,
        "canonical": parser.canonical, "noindex": "noindex" in robots, "h1Count": parser.h1,
        "hasDescription": bool(parser.description), "jsonldTypes": types,
        "jsonldInvalid": invalid,
        "securityHeaders": sorted(h for h in SECURITY_HEADERS if h in f.headers),
    }
    if marker:
        snap["markerFound"] = marker in f.body
    if f.error:
        snap["error"] = f.error
    return snap


def diff_pages(path: str, old: dict | None, new: dict) -> list[dict]:
    findings = []

    def add(kind: str, severity: str, **detail):
        findings.append({"source": NAME, "kind": kind, "severity": severity, "path": path,
                         **detail})

    if new.get("error") or not new.get("status") or new["status"] >= 400:
        add("page_down", "critical", status=new.get("status"), error=new.get("error"))
        return findings
    if new["noindex"]:
        add("noindex", "critical" if not (old or {}).get("noindex") else "warn")
    if new.get("markerFound") is False:
        add("content_marker_missing", "critical")
    if new["h1Count"] != 1:
        add("h1_count", "info", count=new["h1Count"])
    if not new["title"]:
        add("missing_title", "warn")
    if new["jsonldInvalid"]:
        add("jsonld_invalid", "warn", blocks=new["jsonldInvalid"])
    if not old:
        return findings
    if old.get("canonical") != new.get("canonical"):
        add("canonical_changed", "warn", before=old.get("canonical"), after=new.get("canonical"))
    if old.get("title") and old.get("title") != new.get("title"):
        add("title_changed", "info", before=old.get("title"), after=new.get("title"))
    lost = sorted(set(old.get("securityHeaders", [])) - set(new["securityHeaders"]))
    if lost:
        add("security_header_removed", "warn", headers=lost)
    lost_types = sorted(set(old.get("jsonldTypes", [])) - set(new["jsonldTypes"]))
    if lost_types:
        add("structured_data_removed", "warn", types=lost_types)
    if new["redirects"] > old.get("redirects", 0):
        add("redirect_added", "info", redirects=new["redirects"])
    if old.get("ttfbMs") and new.get("ttfbMs") and new["ttfbMs"] > 2 * old["ttfbMs"] + 200:
        add("ttfb_regression", "warn", before=old["ttfbMs"], after=new["ttfbMs"])
    return findings


def tls_info(host: str, port: int = 443) -> dict:
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=TIMEOUT) as sock, \
                ctx.wrap_socket(sock, server_hostname=host) as tls:
            cert = tls.getpeercert()
            version = tls.version()
    except ssl.SSLCertVerificationError as exc:
        return {"valid": False, "error": exc.verify_message or str(exc)}
    except (OSError, ssl.SSLError) as exc:
        return {"valid": False, "error": str(exc)}
    expires = datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notAfter"]), UTC)
    issuer = dict(x[0] for x in cert.get("issuer", ()))
    return {"valid": True, "expires": expires.isoformat(), "tlsVersion": version,
            "daysLeft": (expires - datetime.now(UTC)).days,
            "issuer": issuer.get("organizationName") or issuer.get("commonName")}


def dns_info(host: str) -> dict:
    try:
        infos = socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)
    except OSError as exc:
        return {"resolves": False, "error": str(exc)}
    v4 = sorted({i[4][0] for i in infos if i[0] == socket.AF_INET})
    v6 = sorted({i[4][0] for i in infos if i[0] == socket.AF_INET6})
    return {"resolves": True, "a": v4, "aaaa": v6}


def parse_robots(text: str) -> dict:
    sitemaps, disallow_all, agent = [], False, None
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if ":" not in line:
            continue
        key, value = (x.strip() for x in line.split(":", 1))
        key = key.lower()
        if key == "sitemap":
            sitemaps.append(value)
        elif key == "user-agent":
            agent = value
        elif key == "disallow" and agent == "*" and value == "/":
            disallow_all = True
    return {"sitemaps": sitemaps, "disallowAll": disallow_all}


def sitemap_urls(url: str, depth: int = 0) -> tuple[list[str], list[str]]:
    """Return (page URLs, errors); follows one level of sitemap index."""
    f = fetch(url)
    if f.error or f.status != 200:
        return [], [f"{url}: {f.error or f.status}"]
    try:
        root = ET.fromstring(f.body.encode())
    except ET.ParseError as exc:
        return [], [f"{url}: invalid XML ({exc})"]
    locs = [el.text.strip() for el in root.iter(f"{SM_NS}loc") if el.text]
    if root.tag == f"{SM_NS}sitemapindex" and depth == 0:
        urls, errors = [], []
        for child in locs[:50]:
            u, e = sitemap_urls(child, 1)
            urls += u
            errors += e
        return urls, errors
    return locs, []


def collect(site: dict, store, backfill_days: int = 0) -> SourceResult:
    base = site["url"]
    host = urllib.parse.urlparse(base).hostname or ""
    result = SourceResult(NAME)
    today = dates.today(site["timezone"]).isoformat()
    dns_res = dns_info(host)
    tls = tls_info(host) if base.startswith("https") else {"valid": None}
    result.summary.update({"dns": dns_res, "tls": tls})
    if not dns_res["resolves"]:
        result.findings.append({"source": NAME, "kind": "dns_failure", "severity": "critical",
                                "error": dns_res.get("error")})
    if tls.get("valid") is False:
        result.findings.append({"source": NAME, "kind": "tls_invalid", "severity": "critical",
                                "error": tls.get("error")})
    elif tls.get("daysLeft") is not None:
        result.rows.append(Row("probe.tlsDaysLeft", today, tls["daysLeft"]))
        if tls["daysLeft"] < 14:
            result.findings.append({"source": NAME, "kind": "tls_expiring",
                                    "severity": "critical" if tls["daysLeft"] < 7 else "warn",
                                    "daysLeft": tls["daysLeft"]})
    if base.startswith("https"):
        plain = fetch("http://" + host + "/", read_body=False)
        if plain.status and not plain.url.startswith("https://"):
            result.findings.append({"source": NAME, "kind": "http_not_redirected",
                                    "severity": "warn"})
    markers = site.get("contentMarkers") or {}
    paths = site.get("keyPaths") or ["/"]
    with ThreadPoolExecutor(max_workers=6) as pool:
        fetched = dict(zip(paths, pool.map(lambda p: fetch(base + p), paths)))
    previous = store.get(site["name"], "probe.pages", {})
    pages = {}
    for path, f in fetched.items():
        snap = page_snapshot(f, markers.get(path))
        pages[path] = snap
        result.findings += diff_pages(path, previous.get(path), snap)
        if snap.get("ttfbMs") is not None:
            result.rows.append(Row("probe.ttfbMs", today, snap["ttfbMs"], dim=f"page={path}"))
    home = pages.get("/") or next(iter(pages.values()), {})
    if home.get("ttfbMs") is not None:
        result.rows.append(Row("probe.ttfbMs", today, home["ttfbMs"]))
    if home and not home.get("securityHeaders"):
        result.findings.append({"source": NAME, "kind": "no_security_headers", "severity": "info"})
    up = all((p.get("status") or 0) < 400 and not p.get("error") for p in pages.values())
    result.rows.append(Row("probe.up", today, 1.0 if up else 0.0))
    store.put(site["name"], "probe.pages", pages)
    result.summary["pages"] = pages

    robots_f = fetch(base + "/robots.txt")
    robots = parse_robots(robots_f.body) if robots_f.status == 200 else {"sitemaps": [],
                                                                         "disallowAll": False}
    result.summary["robots"] = {"status": robots_f.status, **robots}
    if robots_f.status and robots_f.status >= 500:
        result.findings.append({"source": NAME, "kind": "robots_5xx", "severity": "critical",
                                "status": robots_f.status})
    if robots["disallowAll"]:
        result.findings.append({"source": NAME, "kind": "robots_disallow_all",
                                "severity": "critical"})
    candidates = robots["sitemaps"] or [base + "/sitemap-index.xml", base + "/sitemap.xml"]
    urls, errors = [], []
    for candidate in candidates:
        u, e = sitemap_urls(candidate)
        urls += u
        errors += e
        if u and not robots["sitemaps"]:
            errors = []  # guessed locations: only the one that worked matters
            break
    urls = sorted(set(urls))
    prev_count = store.get(site["name"], "probe.sitemapCount")
    result.rows.append(Row("probe.sitemapUrls", today, float(len(urls))))
    result.summary["sitemap"] = {"sources": candidates, "urls": len(urls), "errors": errors[:10],
                                 "previous": prev_count}
    if not urls:
        result.findings.append({"source": NAME, "kind": "sitemap_missing", "severity": "warn",
                                "errors": errors[:5]})
    elif prev_count and len(urls) < 0.8 * prev_count:
        result.findings.append({"source": NAME, "kind": "sitemap_shrank", "severity": "warn",
                                "before": prev_count, "after": len(urls)})
    if urls:
        store.put(site["name"], "probe.sitemapCount", len(urls))
        step = max(1, len(urls) // SITEMAP_SAMPLE)
        sample = urls[::step][:SITEMAP_SAMPLE]
        with ThreadPoolExecutor(max_workers=6) as pool:
            checks = list(pool.map(lambda u: fetch(u, method="HEAD", read_body=False), sample))
        broken = [{"url": c.url, "status": c.status, "error": c.error} for c in checks
                  if c.error or not c.status or c.status >= 400]
        redirected = [c.url for c in checks if c.chain]
        result.summary["sitemap"].update({"sampled": len(sample), "broken": broken,
                                          "redirected": len(redirected)})
        if broken:
            result.findings.append({"source": NAME, "kind": "sitemap_broken_urls",
                                    "severity": "warn", "urls": broken})
        if redirected:
            result.findings.append({"source": NAME, "kind": "sitemap_redirected_urls",
                                    "severity": "info", "count": len(redirected)})
    return result
