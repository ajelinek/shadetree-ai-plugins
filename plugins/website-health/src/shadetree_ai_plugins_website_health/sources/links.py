"""Capped same-origin crawl that reports broken internal and external links."""

from __future__ import annotations

import urllib.parse
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from html.parser import HTMLParser

from .probe import fetch

MAX_PAGES_LIMIT = 500


class LinkParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        href = a.get("href") if tag in ("a", "link") else a.get("src") if tag in (
            "img", "script") else None
        if href and not href.startswith(("mailto:", "tel:", "javascript:", "#", "data:")):
            self.links.append(href)


def crawl(site: dict, max_pages: int = 100, check_external: bool = True) -> dict:
    base = site["url"]
    origin = urllib.parse.urlparse(base).netloc
    max_pages = max(1, min(max_pages, MAX_PAGES_LIMIT))
    queue, seen, crawled = deque([base + "/"]), {base + "/"}, 0
    referrers: dict[str, set[str]] = {}
    status: dict[str, tuple[int | None, str | None]] = {}
    while queue and crawled < max_pages:
        url = queue.popleft()
        f = fetch(url)
        crawled += 1
        status[url] = (f.status, f.error)
        if f.error or not f.status or f.status >= 400 or \
                "html" not in f.headers.get("content-type", ""):
            continue
        parser = LinkParser()
        try:
            parser.feed(f.body)
        except Exception:  # noqa: BLE001
            continue
        for href in parser.links:
            target = urllib.parse.urljoin(f.url, href).split("#", 1)[0]
            if not target.startswith("http"):
                continue
            referrers.setdefault(target, set()).add(url)
            if urllib.parse.urlparse(target).netloc == origin and target not in seen:
                seen.add(target)
                queue.append(target)
    unchecked = [u for u in referrers if u not in status and (
        check_external or urllib.parse.urlparse(u).netloc == origin)][:1000]

    def head(u):
        r = fetch(u, method="HEAD", read_body=False)
        if r.status in (405, 403, 501):
            r = fetch(u, read_body=False)
        return u, (r.status, r.error)

    with ThreadPoolExecutor(max_workers=8) as pool:
        status.update(dict(pool.map(head, unchecked)))
    broken = []
    for url, (code, error) in status.items():
        if error or not code or code >= 400:
            broken.append({"url": url, "status": code, "error": error,
                           "internal": urllib.parse.urlparse(url).netloc == origin,
                           "foundOn": sorted(referrers.get(url, []))[:5]})
    broken.sort(key=lambda b: (not b["internal"], b["url"]))
    return {"pagesCrawled": crawled, "linksChecked": len(status), "broken": broken[:200],
            "truncated": bool(queue)}
