"""Delivery and performance checks from plain HTTP: no account, nothing added to the site.

PageSpeed Insights gives deep Lighthouse detail on a few URLs. These checks are the broad,
cheap complement: they run across every crawled page's first-party assets and the host
configuration (compression, caching, HTTP/2, redirects, TTFB, soft 404s, header quality).
"""

from __future__ import annotations

import re
import socket
import ssl
import statistics
import urllib.parse
from concurrent.futures import ThreadPoolExecutor

from ..sources.probe import TIMEOUT, fetch

ASSET_CAP = 60
TEXT_TYPES = ("javascript", "css", "svg", "json", "xml", "html", "font/ttf", "font/otf")
IMAGE_TYPES = ("image/jpeg", "image/png", "image/gif", "image/bmp")
FINGERPRINT = re.compile(r"[.\-_][0-9a-f]{8,}[.\-_]|\.[0-9a-f]{8,}\.")
ENCODINGS = {"Accept-Encoding": "gzip, deflate, br, zstd"}
LARGE_IMAGE = 200_000
LARGE_SCRIPT = 250_000
JS_BUDGET = 500_000


def finding(kind: str, severity: str, category: str, **detail) -> dict:
    return {"section": "delivery", "category": category, "kind": kind, "severity": severity,
            **detail}


def negotiated_protocol(host: str, port: int = 443) -> str | None:
    ctx = ssl.create_default_context()
    ctx.set_alpn_protocols(["h2", "http/1.1"])
    try:
        with socket.create_connection((host, port), timeout=TIMEOUT) as sock, \
                ctx.wrap_socket(sock, server_hostname=host) as tls:
            return tls.selected_alpn_protocol() or "http/1.1"
    except (OSError, ssl.SSLError):
        return None


def max_age(cache_control: str | None) -> int | None:
    m = re.search(r"(?:s-)?max-age=(\d+)", cache_control or "", re.I)
    return int(m.group(1)) if m else None


def _csp_weak(csp: str) -> bool:
    for directive in csp.split(";"):
        name, _, value = directive.strip().partition(" ")
        if name not in ("script-src", "default-src"):
            continue
        if "'unsafe-eval'" in value:
            return True
        if "'unsafe-inline'" in value and "nonce-" not in value \
                and "'strict-dynamic'" not in value:
            return True
    return False


def host_config(base: str) -> tuple[dict, list[dict]]:
    """Protocol, redirect hygiene, soft 404, TTFB and header quality for the site's origin."""
    parsed = urllib.parse.urlparse(base)
    host, https = parsed.hostname or "", parsed.scheme == "https"
    findings: list[dict] = []
    info: dict = {}
    if https:
        proto = negotiated_protocol(host)
        info["protocol"] = proto
        if proto == "http/1.1":
            findings.append(finding("no_http2", "info", "performance",
                                    note="Server negotiates HTTP/1.1; HTTP/2 or 3 loads many "
                                         "assets faster."))
    samples = [fetch(base + "/", read_body=False) for _ in range(3)]
    ttfb = [s.ttfb_ms for s in samples if s.ttfb_ms]
    home = samples[0]
    if ttfb:
        median = statistics.median(ttfb)
        info["ttfbMedianMs"] = round(median)
        if median > 1800:
            findings.append(finding("ttfb_poor", "critical", "performance",
                                    medianMs=round(median)))
        elif median > 800:
            findings.append(finding("ttfb_slow", "warn", "performance", medianMs=round(median),
                                    note="web.dev: good TTFB is 800 ms or less."))
    if "alt-svc" in home.headers:
        info["http3Advertised"] = "h3" in home.headers["alt-svc"]
    # HTML compression.
    html = fetch(base + "/", method="HEAD", read_body=False, headers=ENCODINGS)
    info["htmlEncoding"] = html.headers.get("content-encoding")
    length = int(html.headers.get("content-length") or 0)
    if not info["htmlEncoding"] and (length > 1500 or not length):
        findings.append(finding("html_not_compressed", "warn", "performance",
                                note="No gzip/br/zstd on the HTML response."))
    # Redirect hygiene: plain http and the www/apex twin must reach the canonical origin
    # in one permanent hop.
    twins = []
    if https:
        twins.append(("http", f"http://{host}/"))
    twin_host = host.removeprefix("www.") if host.startswith("www.") else "www." + host
    twins.append(("www_apex", f"{parsed.scheme}://{twin_host}/"))
    for label, url in twins:
        f = fetch(url, read_body=False)
        if f.error or not f.status:
            continue  # the twin simply doesn't exist
        landed = urllib.parse.urlparse(f.url).netloc
        if landed != parsed.netloc or (https and not f.url.startswith("https://")):
            findings.append(finding("host_variant_not_redirected", "warn", "seo", variant=label,
                                    url=url, landedOn=f.url,
                                    note="Duplicate host serving content splits ranking signals."))
        elif len(f.chain) > 1:
            findings.append(finding("redirect_chain", "warn", "performance", url=url,
                                    hops=len(f.chain), chain=[c["url"] for c in f.chain]))
        elif f.chain and f.chain[0]["status"] in (302, 307):
            findings.append(finding("temporary_redirect_to_canonical", "info", "seo", url=url,
                                    status=f.chain[0]["status"]))
    soft = fetch(base + "/__wh-audit-404-check", read_body=False)
    info["notFoundStatus"] = soft.status
    if soft.status == 200:
        findings.append(finding("soft_404", "warn", "seo",
                                note="A made-up URL returned 200; missing pages should return "
                                     "404 so search engines drop them."))
    # Security header quality (presence is checked by the probe).
    h = home.headers
    hsts = h.get("strict-transport-security")
    if https and hsts is not None:
        age = max_age(hsts) or 0
        if age < 15_552_000:
            findings.append(finding("hsts_short", "info", "security", maxAge=age))
    csp = h.get("content-security-policy", "")
    if _csp_weak(csp):
        findings.append(finding("csp_weak", "info", "security",
                                note="CSP allows unsafe-inline/unsafe-eval scripts."))
    if not (h.get("x-frame-options") or "frame-ancestors" in csp):
        findings.append(finding("clickjacking_protection_missing", "info", "security"))
    leaked = [k for k in ("x-powered-by",) if k in h] + (
        ["server"] if re.search(r"\d+\.\d+", h.get("server", "")) else [])
    if leaked:
        findings.append(finding("server_version_disclosed", "info", "security", headers=leaked))
    sec = fetch(base + "/.well-known/security.txt", read_body=False)
    if sec.status != 200:
        findings.append(finding("security_txt_missing", "info", "security"))
    return info, findings


def _asset_candidates(snaps: list[dict], origin: str) -> list[str]:
    counts: dict[str, int] = {}
    for snap in snaps:
        base = snap["finalUrl"] or snap["url"]
        urls = [s["src"] for s in snap["scripts"]] + [s["href"] for s in snap["stylesheets"]] \
            + [i["src"] for i in snap["images"]] + [p["href"] for p in snap["preload"]]
        for raw in urls:
            if not raw or raw.startswith(("data:", "javascript:")):
                continue
            url = urllib.parse.urljoin(base, raw).split("#", 1)[0]
            if urllib.parse.urlparse(url).netloc == origin:
                counts[url] = counts.get(url, 0) + 1
    ranked = sorted(counts, key=lambda u: (-counts[u], u))
    return ranked[:ASSET_CAP]


def assets(snaps: list[dict], base: str) -> tuple[dict, list[dict]]:
    origin = urllib.parse.urlparse(base).netloc
    urls = _asset_candidates(snaps, origin)
    if not urls:
        return {"checked": 0}, []
    with ThreadPoolExecutor(max_workers=6) as pool:
        heads = list(pool.map(
            lambda u: fetch(u, method="HEAD", read_body=False, headers=ENCODINGS), urls))
    findings: list[dict] = []
    broken, uncompressed, no_cache, short_cache = [], [], [], []
    big_images, legacy, big_scripts = [], [], []
    js_total = 0
    for url, f in zip(urls, heads):
        if f.error or not f.status or f.status >= 400:
            broken.append({"url": url, "status": f.status})
            continue
        ctype = f.headers.get("content-type", "").lower()
        size = int(f.headers.get("content-length") or 0)
        encoded = f.headers.get("content-encoding")
        if any(t in ctype for t in TEXT_TYPES) and not encoded and size > 2048:
            uncompressed.append({"url": url, "bytes": size})
        cc = f.headers.get("cache-control")
        age = max_age(cc)
        if not cc and "etag" not in f.headers:
            no_cache.append(url)
        elif (age is not None and age < 86_400 and "immutable" not in (cc or "")) \
                or (cc and "no-store" in cc):
            short_cache.append({"url": url, "maxAge": age})
        elif FINGERPRINT.search(url) and age is not None and age < 2_592_000:
            short_cache.append({"url": url, "maxAge": age, "fingerprinted": True})
        if ctype.startswith("image/") and size > LARGE_IMAGE:
            big_images.append({"url": url, "bytes": size})
        if ctype in IMAGE_TYPES and size > 30_000:
            legacy.append({"url": url, "bytes": size, "type": ctype})
        if "javascript" in ctype:
            js_total += size
            if size > LARGE_SCRIPT:
                big_scripts.append({"url": url, "bytes": size})
    checked = len(urls)
    stats = {"checked": checked, "firstPartyJsBytes": js_total}
    if broken:
        findings.append(finding("broken_assets", "warn", "performance", count=len(broken),
                                urls=broken[:10]))
    if uncompressed:
        findings.append(finding("assets_not_compressed", "warn", "performance",
                                count=len(uncompressed), urls=uncompressed[:10]))
    if no_cache:
        findings.append(finding("assets_without_cache_headers", "warn", "performance",
                                count=len(no_cache), urls=no_cache[:10],
                                note="Repeat visitors re-download these every time."))
    if short_cache:
        findings.append(finding("assets_short_cache", "info", "performance",
                                count=len(short_cache), urls=short_cache[:10],
                                note="Fingerprinted assets can use max-age=31536000, immutable."))
    if big_images:
        findings.append(finding("large_images", "warn", "performance", count=len(big_images),
                                urls=sorted(big_images, key=lambda i: -i["bytes"])[:10]))
    if legacy:
        findings.append(finding("legacy_image_formats", "info", "performance",
                                count=len(legacy), urls=legacy[:10],
                                note="JPEG/PNG over 30 KB; WebP/AVIF is typically 25-50% "
                                     "smaller."))
    if big_scripts:
        findings.append(finding("large_scripts", "info", "performance", urls=big_scripts[:10]))
    if js_total > JS_BUDGET:
        findings.append(finding("first_party_js_heavy", "warn", "performance",
                                bytes=js_total, note="First-party JS over 500 KB (compressed "
                                "size where reported); hurts INP and LCP on mid-range phones."))
    return stats, findings
