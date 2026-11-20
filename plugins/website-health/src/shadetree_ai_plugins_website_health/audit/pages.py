"""Per-page SEO, accessibility, performance-hint, AI-readiness and analytics-tag checks.

``RichPageParser`` extends the probe's ``PageParser`` (title, canonical, robots, h1, JSON-LD)
with what an audit needs. All checks run on the raw HTML the server sends, which is what
most AI crawlers and the first stage of Googlebot see.
"""

from __future__ import annotations

import json
import re
import urllib.parse

from ..sources.probe import Fetch, PageParser, jsonld_types

SKIP_TEXT = {"script", "style", "noscript", "template", "svg"}
FORM_FIELDS = {"input", "textarea", "select"}
UNLABELLED_OK = {"hidden", "submit", "button", "image", "reset"}
GENERIC_ANCHORS = {"click here", "here", "read more", "more", "learn more", "link", "this"}
MOUNT_IDS = {"root", "app", "__next", "__nuxt", "___gatsby"}
SNIPPET_LIMITS = ("nosnippet", "max-snippet", "noarchive", "noimageai", "noai")
FONT_HOSTS = ("fonts.googleapis.com", "fonts.gstatic.com")

# Recommended properties per schema.org type (Google's rich-result guidance, trimmed).
SCHEMA_PROPS = {
    "Organization": ("name", "url", "logo", "sameAs"),
    "WebSite": ("name", "url"),
    "Article": ("headline", "datePublished", "author", "image"),
    "BlogPosting": ("headline", "datePublished", "author", "image"),
    "NewsArticle": ("headline", "datePublished", "author", "image"),
    "LocalBusiness": ("name", "address", "telephone", "url"),
    "Product": ("name", "offers"),
    "BreadcrumbList": ("itemListElement",),
    "FAQPage": ("mainEntity",),
    "Person": ("name",),
}
ARTICLE_TYPES = {"Article", "BlogPosting", "NewsArticle"}

GA4_RE = re.compile(r"googletagmanager\.com/gtag/js\?id=(G-[A-Z0-9]+)", re.I)
GTM_RE = re.compile(
    r"googletagmanager\.com/gtm\.js\?id=(GTM-[A-Z0-9]+)|['\"](GTM-[A-Z0-9]{4,})['\"]", re.I)
CLARITY_RE = re.compile(
    r"clarity\.ms/tag/([a-z0-9]+)|\"clarity\",\s*\"script\",\s*\"([a-z0-9]+)\"", re.I)


class RichPageParser(PageParser):
    def __init__(self):
        super().__init__()
        self.lang = self.viewport = self.author = None
        self.og: set[str] = set()
        self.twitter_card = False
        self.hreflang: list[str] = []
        self.headings: list[int] = []
        self.h1_text: str | None = None
        self.images: list[dict] = []
        self.scripts: list[dict] = []
        self.stylesheets: list[dict] = []
        self.preconnect: list[str] = []
        self.preload: list[dict] = []
        self.links: list[dict] = []
        self.resources: list[str] = []
        self.elements = 0
        self.words = 0
        self.time_tags = 0
        self.landmarks: set[str] = set()
        self.unlabelled_fields = self.nameless_buttons = 0
        self._in_head = False
        self._skip = 0
        self._label_depth = 0
        self._labels_for: set[str] = set()
        self._fields: list[tuple[str, bool]] = []  # (id, already labelled)
        self._anchor: dict | None = None
        self._button: dict | None = None
        self._h1_open = False
        self._h1_buf: list[str] = []
        self.mount_div = False
        self.inline_script_bytes = 0
        self._inline_buf: list[str] | None = None

    # ------------------------------------------------------------------ tags
    def handle_starttag(self, tag, attrs):
        super().handle_starttag(tag, attrs)
        a = {k.lower(): (v or "") for k, v in attrs}
        self.elements += 1
        if tag == "html":
            self.lang = a.get("lang") or None
        elif tag == "head":
            self._in_head = True
        elif tag == "meta":
            name, prop = a.get("name", "").lower(), a.get("property", "").lower()
            if name == "viewport":
                self.viewport = a.get("content")
            elif name == "author":
                self.author = a.get("content")
            elif name == "twitter:card":
                self.twitter_card = True
            if prop.startswith("og:"):
                self.og.add(prop)
        elif tag == "link":
            rel = a.get("rel", "").lower().split()
            href = a.get("href", "")
            if "alternate" in rel and a.get("hreflang"):
                self.hreflang.append(a["hreflang"])
            if "stylesheet" in rel:
                self.stylesheets.append({"href": href, "media": a.get("media", "")})
                self.resources.append(href)
            elif "preconnect" in rel or "dns-prefetch" in rel:
                self.preconnect.append(href)
            elif "preload" in rel:
                self.preload.append({"href": href, "as": a.get("as", "")})
        elif tag == "script":
            if a.get("src"):
                self.scripts.append({"src": a["src"], "async": "async" in a, "defer": "defer" in a,
                                     "module": a.get("type", "").lower() == "module",
                                     "inHead": self._in_head})
                self.resources.append(a["src"])
            elif a.get("type", "").lower() not in ("application/ld+json", "application/json"):
                self._inline_buf = []
        elif tag == "img":
            self.images.append({"src": a.get("src") or a.get("data-src", ""),
                                "hasAlt": "alt" in a, "width": a.get("width"),
                                "height": a.get("height"), "lazy": a.get("loading") == "lazy",
                                "srcset": bool(a.get("srcset"))})
            self.resources.append(a.get("src", ""))
            if self._anchor is not None and a.get("alt"):
                self._anchor["named"] = True
        elif tag == "iframe":
            self.resources.append(a.get("src", ""))
        elif tag in ("main", "nav", "header", "footer"):
            self.landmarks.add(tag)
        elif tag == "time":
            self.time_tags += 1
        elif tag == "label":
            self._label_depth += 1
            if a.get("for"):
                self._labels_for.add(a["for"])
        elif tag in FORM_FIELDS:
            if a.get("type", "text").lower() not in UNLABELLED_OK:
                named = bool(self._label_depth or a.get("aria-label") or a.get("aria-labelledby")
                             or a.get("title"))
                self._fields.append((a.get("id", ""), named))
        elif tag == "button":
            self._button = {"named": bool(a.get("aria-label") or a.get("title")), "text": 0}
        elif tag == "a":
            self._anchor = {"href": a.get("href", ""), "rel": a.get("rel", "").lower(),
                            "named": bool(a.get("aria-label") or a.get("title")), "text": []}
        elif tag in ("h1", "h2", "h3", "h4", "h5", "h6"):
            self.headings.append(int(tag[1]))
            if tag == "h1" and self.h1_text is None:
                self._h1_open, self._h1_buf = True, []
        if tag == "div" and a.get("id") in MOUNT_IDS:
            self.mount_div = True
        if tag in SKIP_TEXT:
            self._skip += 1

    def handle_endtag(self, tag):
        super().handle_endtag(tag)
        if tag == "head":
            self._in_head = False
        elif tag == "label":
            self._label_depth = max(0, self._label_depth - 1)
        elif tag == "h1" and self._h1_open:
            self.h1_text, self._h1_open = " ".join("".join(self._h1_buf).split()), False
        elif tag == "button" and self._button is not None:
            if not (self._button["named"] or self._button["text"]):
                self.nameless_buttons += 1
            self._button = None
        elif tag == "a" and self._anchor is not None:
            text = " ".join("".join(self._anchor.pop("text")).split())
            self.links.append({**self._anchor, "text": text})
            self._anchor = None
        elif tag == "script" and self._inline_buf is not None:
            self.inline_script_bytes += len("".join(self._inline_buf))
            self._inline_buf = None
        if tag in SKIP_TEXT:
            self._skip = max(0, self._skip - 1)

    def handle_data(self, data):
        super().handle_data(data)
        if self._inline_buf is not None:
            self._inline_buf.append(data)
        if self._skip or self._in_head or not data.strip():
            return
        self.words += len(data.split())
        if self._h1_open:
            self._h1_buf.append(data)
        if self._button is not None:
            self._button["text"] += 1
        if self._anchor is not None:
            self._anchor["text"].append(data)

    def close(self):
        super().close()
        self.unlabelled_fields = sum(1 for fid, named in self._fields
                                     if not named and fid not in self._labels_for)


# ---------------------------------------------------------------- snapshots
def _structured(blocks: list[str]) -> list[dict]:
    """Flatten JSON-LD blocks into items (type list + property names)."""
    items: list[dict] = []
    for block in blocks:
        try:
            data = json.loads(block)
        except ValueError:
            continue
        nodes = data if isinstance(data, list) else data.get("@graph", [data]) \
            if isinstance(data, dict) else []
        for node in nodes:
            if isinstance(node, dict) and node.get("@type"):
                t = node["@type"]
                items.append({"types": t if isinstance(t, list) else [t],
                              "props": {k for k, v in node.items() if v not in (None, "", [])}})
    return items


def detect_tags(body: str) -> dict[str, list[str]]:
    clarity = {x or y for x, y in CLARITY_RE.findall(body)}
    gtm = {x or y for x, y in GTM_RE.findall(body)}
    return {"ga4": sorted(set(GA4_RE.findall(body))), "gtm": sorted(gtm),
            "clarity": sorted(clarity)}


def snapshot(f: Fetch, url: str) -> dict:
    parser = RichPageParser()
    try:
        parser.feed(f.body)
        parser.close()
    except Exception:  # noqa: BLE001 - malformed HTML must not abort an audit
        pass
    robots = ",".join(x for x in (parser.robots, f.headers.get("x-robots-tag")) if x).lower()
    items = _structured(parser.jsonld)
    types, invalid = jsonld_types(parser.jsonld)
    host = urllib.parse.urlparse(f.url or url).netloc
    resources = [urllib.parse.urljoin(f.url or url, r) for r in parser.resources if r
                 and not r.startswith(("data:", "javascript:"))]
    third = sorted({urllib.parse.urlparse(r).netloc for r in resources} - {host, ""})
    return {
        "url": url, "finalUrl": f.url, "status": f.status, "redirected": bool(f.chain),
        "contentType": f.headers.get("content-type", ""), "bytes": len(f.body.encode()),
        "title": parser.title, "description": parser.description,
        "canonical": parser.canonical, "robots": robots, "noindex": "noindex" in robots,
        "lang": parser.lang, "viewport": parser.viewport, "og": sorted(parser.og),
        "twitterCard": parser.twitter_card, "hreflang": parser.hreflang,
        "h1": parser.h1_text, "h1Count": parser.h1, "headings": parser.headings,
        "words": parser.words, "elements": parser.elements, "landmarks": sorted(parser.landmarks),
        "images": parser.images, "scripts": parser.scripts, "stylesheets": parser.stylesheets,
        "preconnect": parser.preconnect, "preload": parser.preload,
        "links": parser.links, "resources": resources, "thirdParties": third,
        "timeTags": parser.time_tags, "author": parser.author,
        "unlabelledFields": parser.unlabelled_fields, "namelessButtons": parser.nameless_buttons,
        "jsonldTypes": types, "jsonldInvalid": invalid, "structured": items,
        "mountDiv": parser.mount_div, "tags": detect_tags(f.body),
        "inlineScriptBytes": parser.inline_script_bytes,
        "headers": {k: f.headers[k] for k in ("x-robots-tag", "content-encoding", "cache-control",
                                              "content-length") if k in f.headers},
    }


# ----------------------------------------------------------------- findings
def page_findings(snap: dict, *, is_home: bool, site: dict) -> list[dict]:
    """Findings for one HTML page. ``section`` is 'pages'; the run groups by kind."""
    out: list[dict] = []
    url = snap["url"]

    def add(kind: str, severity: str, category: str, **detail):
        out.append({"section": "pages", "category": category, "kind": kind,
                    "severity": severity, "url": url, **detail})

    title, desc = snap["title"], snap["description"]
    if not title:
        add("missing_title", "warn", "seo")
    elif len(title) > 60:
        add("title_too_long", "info", "seo", length=len(title))
    elif len(title) < 15:
        add("title_too_short", "info", "seo", length=len(title))
    if not desc:
        add("missing_description", "warn", "seo")
    elif len(desc) > 160 or len(desc) < 70:
        add("description_length", "info", "seo", length=len(desc))
    if snap["h1Count"] == 0:
        add("missing_h1", "warn", "seo")
    elif snap["h1Count"] > 1:
        add("multiple_h1", "info", "seo", count=snap["h1Count"])
    heads = snap["headings"]
    if any(b - a > 1 for a, b in zip(heads, heads[1:])):
        add("heading_order_skips", "info", "accessibility")
    canonical = snap["canonical"]
    if not canonical:
        add("missing_canonical", "warn", "seo")
    else:
        parsed = urllib.parse.urlparse(canonical)
        if not parsed.netloc:
            add("canonical_not_absolute", "warn", "seo", canonical=canonical)
        elif parsed.netloc != urllib.parse.urlparse(snap["finalUrl"] or snap["url"]).netloc:
            add("canonical_other_host", "warn", "seo", canonical=canonical)
    if not snap["viewport"]:
        add("missing_viewport", "warn", "usability")
    if not snap["lang"]:
        add("missing_html_lang", "warn", "accessibility")
    if "main" not in snap["landmarks"]:
        add("missing_main_landmark", "info", "accessibility")
    if not {"og:title", "og:description", "og:image"} <= set(snap["og"]) \
            or not snap["twitterCard"]:
        add("missing_social_tags", "info", "seo", have=snap["og"])
    if snap["words"] < 200 and not is_home:
        add("thin_content", "info", "seo", words=snap["words"])
    internal = [lk for lk in snap["links"] if not lk["href"].startswith(("http://", "https://"))
                or urllib.parse.urlparse(lk["href"]).netloc
                == urllib.parse.urlparse(snap["finalUrl"] or url).netloc]
    if not internal:
        add("no_internal_links", "info", "seo")
    generic = [lk for lk in snap["links"] if lk["text"].lower() in GENERIC_ANCHORS]
    if generic:
        add("generic_link_text", "info", "accessibility", count=len(generic))
    nameless = [lk for lk in snap["links"] if not lk["text"] and not lk["named"]]
    if nameless:
        add("links_without_name", "warn", "accessibility", count=len(nameless))
    no_alt = [i["src"] for i in snap["images"] if not i["hasAlt"]]
    if no_alt:
        add("images_missing_alt", "warn", "accessibility", count=len(no_alt), examples=no_alt[:3])
    if snap["unlabelledFields"]:
        add("form_fields_without_label", "warn", "accessibility", count=snap["unlabelledFields"])
    if snap["namelessButtons"]:
        add("buttons_without_name", "warn", "accessibility", count=snap["namelessButtons"])
    # Performance hints visible in the HTML itself.
    no_dims = [i["src"] for i in snap["images"] if not (i["width"] and i["height"])]
    if no_dims:
        add("images_without_dimensions", "warn", "performance", count=len(no_dims),
            examples=no_dims[:3], note="Missing width/height causes layout shift (CLS).")
    blocking = [s["src"] for s in snap["scripts"]
                if s["inHead"] and not (s["async"] or s["defer"] or s["module"])]
    if blocking:
        add("render_blocking_scripts", "warn", "performance", count=len(blocking),
            examples=blocking[:3])
    if len(snap["images"]) > 4 and not any(i["lazy"] for i in snap["images"]):
        add("no_lazy_loading", "info", "performance", images=len(snap["images"]))
    if len(snap["stylesheets"]) > 3:
        add("many_stylesheets", "info", "performance", count=len(snap["stylesheets"]))
    if len(snap["thirdParties"]) > 10:
        add("many_third_party_hosts", "info", "performance", count=len(snap["thirdParties"]),
            hosts=snap["thirdParties"][:12])
    if any(h in FONT_HOSTS for h in snap["thirdParties"]) and not snap["preconnect"]:
        add("web_fonts_without_preconnect", "info", "performance")
    if snap["elements"] > 1500:
        add("dom_too_large", "warn", "performance", elements=snap["elements"])
    if snap["bytes"] > 500_000:
        add("html_very_large", "warn", "performance", bytes=snap["bytes"])
    if snap["finalUrl"] and snap["finalUrl"].startswith("https://"):
        mixed = [r for r in snap["resources"] if r.startswith("http://")]
        if mixed:
            add("mixed_content", "warn", "security", count=len(mixed), examples=mixed[:3])
    # AI readiness from raw HTML.
    if snap["words"] < 80 and (snap["mountDiv"] or len(snap["scripts"]) > 3):
        add("client_rendered_suspect", "warn", "ai", words=snap["words"],
            note="Little text in the raw HTML. Most AI crawlers don't run JavaScript, so they "
                 "may see an empty page.")
    limits = [t for t in snap["robots"].replace(" ", "").split(",")
              if t.startswith(SNIPPET_LIMITS) and t != "noindex"]
    if limits:
        add("snippet_limits", "info", "ai", directives=limits,
            note="These limit snippets in search and AI features. Confirm intent.")
    kinds = {t for item in snap["structured"] for t in item["types"]}
    for item in snap["structured"]:
        for t in item["types"]:
            wanted = SCHEMA_PROPS.get(t)
            missing = [p for p in wanted or () if p not in item["props"]]
            if missing:
                add("structured_data_incomplete", "info", "seo", type=t, missing=missing)
            if t in ARTICLE_TYPES and "author" not in item["props"] \
                    and "datePublished" not in item["props"]:
                add("article_without_author_or_date", "warn", "ai")
    if is_home and not kinds & {"Organization", "LocalBusiness", "WebSite", "Person"}:
        add("no_entity_schema", "info", "ai",
            note="No Organization/LocalBusiness/WebSite JSON-LD on the home page; entity "
                 "markup helps search and AI systems identify the site.")
    if snap["jsonldInvalid"]:
        add("jsonld_invalid", "warn", "seo", blocks=snap["jsonldInvalid"])
    # Analytics tags (also verified across pages in ``tag_findings``).
    tags = snap["tags"]
    if len(tags["ga4"]) > 1:
        add("multiple_ga4_ids", "info", "analytics", ids=tags["ga4"])
    return out


def tag_findings(snaps: list[dict], site: dict) -> list[dict]:
    """Cross-check installed tags against the configured GA4/Clarity accounts."""
    out: list[dict] = []
    pages = [s for s in snaps if s["status"] == 200]
    if not pages:
        return out

    def add(kind, severity, **detail):
        out.append({"section": "pages", "category": "analytics", "kind": kind,
                    "severity": severity, **detail})

    gtm_anywhere = any(s["tags"]["gtm"] for s in pages)
    if site.get("ga4PropertyId"):
        missing = [s["url"] for s in pages if not s["tags"]["ga4"] and not s["tags"]["gtm"]]
        if missing:
            add("analytics_tag_missing", "warn", count=len(missing), urls=missing[:10],
                note="GA4 is configured for this site but these pages carry no gtag or GTM "
                     "snippet, so their traffic is silently missing from reports.")
    if site.get("clarityProjectId"):
        ids = {i for s in pages for i in s["tags"]["clarity"]}
        if ids and site["clarityProjectId"] not in ids:
            add("clarity_project_mismatch", "warn", found=sorted(ids),
                configured=site["clarityProjectId"])
        elif not ids:
            add("clarity_tag_not_found", "info" if gtm_anywhere else "warn",
                note="No Clarity snippet in the HTML" + (
                    "; it may load through GTM." if gtm_anywhere else "."))
    return out
