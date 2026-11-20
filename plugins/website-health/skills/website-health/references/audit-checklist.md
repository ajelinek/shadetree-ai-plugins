# Audit checklist

`audit_site(site, max_pages=50, sections=...)` crawls the site and returns findings grouped by
`kind`, each with `severity`, `category`, `occurrences`, a few `examples`, and `status`
(new / persisting, with `firstSeen`). `history.resolved` lists kinds fixed since the last
audit. Nothing here needs an account or adds anything to the site.

Sections: `pages` (per-page SEO, accessibility, performance hints, tags, cross-page),
`ai` (bot access and LLM readiness), `delivery` (host and asset configuration).
If `crawlComplete` is false the crawl hit `max_pages`: orphan and missing-from-sitemap
checks are skipped, so say the crawl was partial and offer a larger `max_pages`.

Report order: critical first, then warn, grouped by category. Fixes are for a coding agent:
name the file to edit (see [code-remediation.md](code-remediation.md) suspect files).

## AI and LLM access (category `ai`)

| Kind | Meaning | Fix |
|---|---|---|
| `search_engine_blocked_by_robots` (critical) | Googlebot/Bingbot is disallowed for a key path | Remove the rule in `robots.txt`; confirm it isn't a leftover staging block |
| `ai_search_bot_blocked_by_robots` (warn) | OAI-SearchBot, Claude-SearchBot or PerplexityBot disallowed: the site can't be cited in those AI answers | Allow those tokens; blocking GPTBot/ClaudeBot (training) is separate |
| `ai_user_agent_blocked_by_robots` (info) | ChatGPT-User, Claude-User or Perplexity-User disallowed: assistants can't open a URL a user pastes | Allow unless deliberate |
| `ai_training_blocked_by_robots` (info) | Training bots (GPTBot, ClaudeBot, Google-Extended, CCBot...) disallowed | Policy choice. Does not remove the site from AI search |
| `*_blocked_by_server` | The server returned 403/429/503, a challenge page, or a much smaller page to that bot's user agent. `robots.txt` may say allowed while a CDN/WAF "block AI bots" rule refuses | Allow the bot in the CDN/WAF (Cloudflare: Security > Bots > AI crawl control). Confirm the real bot, not just the user agent, is allowed |
| `client_rendered_suspect` (warn) | Almost no text in the raw HTML and a JS mount point. Most AI crawlers don't run JavaScript | Server-render or pre-render the content (Astro/Next SSR/SSG) |
| `snippet_limits` (info) | `nosnippet`, `max-snippet`, `noarchive`, `noai` in meta or `X-Robots-Tag` | Remove if unintended; they limit search and AI snippets |
| `content_signals_declared` / `content_signal_search_no` | `Content-Signal` lines in robots.txt (search / ai-input / ai-train) | Confirm they match intent; `search=no` is rarely wanted |
| `no_entity_schema` (info) | No Organization/LocalBusiness/WebSite JSON-LD on the home page | Add Organization JSON-LD with `name`, `url`, `logo`, `sameAs` |
| `article_without_author_or_date` (warn) | Article markup lacks `author` and `datePublished` | Add both; visible byline and date too |
| `llms_txt_missing` / `_malformed` / `_broken_links` | Optional file. Unproven value; broken links in it are worth fixing | Add only if cheap; never block other work on it |

`ai.commonCrawl.foundIn` lists recent Common Crawl archives containing the domain (a feed for
many LLM datasets). An empty list on a new or tiny site is normal, not a defect.

How to present the AI verdict: one line per role (search, user, training) saying allowed,
blocked by robots, or blocked by server; then the fixes. Offer the brand-visibility spot
check (below) as a separate, clearly labeled sample.

**Brand-visibility spot check (no account).** Use the session's own web search for 3-5
queries a customer would ask (brand name, "<service> in <city>", the main category).
Record whether the site appears, how it is described, and which competitors appear. It is a
sample, not a metric; say so.

## SEO (category `seo`)

| Kind | Fix |
|---|---|
| `missing_title`, `title_too_long` (>60), `title_too_short` (<15) | Unique descriptive `<title>`, about 50-60 characters |
| `missing_description`, `description_length` | Meta description of about 70-160 characters that earns the click |
| `missing_h1`, `multiple_h1` | One `<h1>` per page that states the topic |
| `missing_canonical`, `canonical_not_absolute`, `canonical_other_host` | Absolute self-referencing canonical on the preferred host |
| `duplicate_titles`, `duplicate_descriptions`, `duplicate_h1` | Make each page's tags unique or consolidate the pages |
| `missing_social_tags` | `og:title`, `og:description`, `og:image`, `twitter:card` |
| `thin_content` (<200 words), `no_internal_links`, `deep_pages` | Expand or merge; link from related pages; flatten navigation |
| `structured_data_incomplete`, `jsonld_invalid` | Add the listed properties; fix the JSON |
| `sitemap_url_blocked_by_robots`, `_noindex`, `_canonical_elsewhere`, `_redirects` | Sitemap should list only indexable, canonical, 200 URLs: fix the page or drop it from the sitemap |
| `orphan_pages`, `pages_missing_from_sitemap` | Link orphans from the site; add indexable pages to the sitemap |
| `host_variant_not_redirected`, `temporary_redirect_to_canonical`, `soft_404` | 301 `http` and the www/apex twin to the canonical origin; make missing URLs return 404 |

## Accessibility and usability (categories `accessibility`, `usability`)

| Kind | Fix |
|---|---|
| `missing_html_lang`, `missing_viewport` | `<html lang="en">`; `<meta name="viewport" content="width=device-width, initial-scale=1">` |
| `images_missing_alt` | `alt` text (use `alt=""` only for decorative images) |
| `form_fields_without_label`, `buttons_without_name`, `links_without_name` | Visible `<label for>` or `aria-label`; text or `aria-label` on icon buttons and links |
| `generic_link_text`, `heading_order_skips`, `missing_main_landmark` | Descriptive link text; don't skip heading levels; wrap content in `<main>` |
| `broken_internal_links` | Fix or remove; examples list the pages that link to them |

These are static checks on HTML. Colour contrast, keyboard use and focus order need a real
browser: see [browser-audit.md](browser-audit.md).

## Performance (category `performance`)

Page hints from the HTML:

| Kind | Fix |
|---|---|
| `images_without_dimensions` | `width` and `height` attributes (or CSS aspect-ratio): prevents layout shift |
| `render_blocking_scripts` | `defer` or `async`, or move to the end of the body |
| `no_lazy_loading` | `loading="lazy"` on below-the-fold images (not the LCP image) |
| `many_stylesheets`, `many_third_party_hosts`, `web_fonts_without_preconnect` | Bundle CSS; remove unneeded third-party tags; `<link rel="preconnect">` for font hosts |
| `dom_too_large`, `html_very_large` | Reduce nodes; paginate or lazy-render long lists |

Delivery (section `delivery`):

| Kind | Fix |
|---|---|
| `ttfb_poor` (>1800 ms), `ttfb_slow` (>800 ms) | Cache HTML at the edge/CDN, use static or pre-rendered pages, fix slow server work |
| `html_not_compressed`, `assets_not_compressed` | Enable brotli/gzip for text responses |
| `assets_without_cache_headers`, `assets_short_cache` | `Cache-Control: public, max-age=31536000, immutable` on fingerprinted assets |
| `large_images`, `legacy_image_formats` | Resize to display size; serve WebP/AVIF with `srcset` |
| `large_scripts`, `first_party_js_heavy` | Code-split, drop unused libraries, defer hydration |
| `no_http2`, `redirect_chain`, `internal_links_to_redirects`, `broken_assets` | Enable HTTP/2+; collapse redirects; link to final URLs; fix 404 assets |

Lab and field detail comes from PageSpeed (`run_pagespeed`, and weekly in `collect`):
`psi.performance`, `psi.lcpMs`, `psi.tbtMs`, `psi.totalBytes` and so on, per page and
`strategy=desktop`. `opportunities` lists the biggest estimated savings first. Lab scores
move a few points run to run, so act on a sustained drop, not one reading.

## Security (category `security`)

| Kind | Fix |
|---|---|
| `mixed_content` (warn) | Load every resource over `https://` |
| `hsts_short`, `csp_weak`, `clickjacking_protection_missing`, `server_version_disclosed` | Longer HSTS max-age; a CSP without `unsafe-inline`/`unsafe-eval`; `frame-ancestors` or `X-Frame-Options`; hide version banners |
| `security_txt_missing` (info) | `/.well-known/security.txt` with a contact |

Domain registration expiry and email authentication (SPF, DKIM, DMARC) are not audited
here. If the `email-domain-reputation` plugin is installed, use it for those.

## Analytics tag cross-check (category `analytics`)

| Kind | Meaning |
|---|---|
| `analytics_tag_missing` (warn) | GA4 is configured but these pages carry no gtag or GTM snippet, so their traffic is missing from reports |
| `clarity_project_mismatch` (warn) | The Clarity snippet's project ID differs from `clarityProjectId`: you are reading the wrong project |
| `clarity_tag_not_found` | No Clarity snippet in the HTML (may load via GTM, in which case it is only `info`) |
| `multiple_ga4_ids` (info) | More than one GA4 measurement ID on a page; may double count |

This is the check that ties the account data to the live site: if it fails, distrust the
account numbers for the affected pages.
