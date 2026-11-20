# Changelog

## Unreleased

- Shortened the skill `description` to under 1024 characters; trigger phrases moved to `when_to_use`.

- `audit_site`: account-free crawl audit across `pages`, `ai` and `delivery` sections.
  Per-page SEO, accessibility, performance hints and mixed content; duplicate tags,
  broken and redirecting internal links, orphan pages and sitemap consistency; structured
  data completeness; GA4/GTM/Clarity tag presence checked against the configured accounts;
  host configuration (HTTP/2, TTFB, redirect hygiene, soft 404, header quality) and
  first-party asset compression, caching and size. Findings are grouped by kind and tracked
  across audits (new, persisting, resolved).
- AI and LLM access validation: robots.txt matched per bot with Google-style longest-match
  rules (search, user and training bots), real fetches with each bot's user agent to expose
  CDN/WAF blocks, raw-HTML content check for non-JS crawlers, snippet limits, `Content-Signal`,
  `llms.txt` validation and Common Crawl presence.
- PageSpeed is now a stored source: scores, lab timings, page weight and field vitals as
  weekly series with anomaly thresholds, ranked opportunities, and a once-per-6-days gate in
  `collect`. Works without a key but keyless quota is often exhausted (reported as a
  warning). `collect` gains `force` (also re-runs PageSpeed).
- `health_report` reminds you when no audit has run in 14 days.
- New references: `audit-checklist.md` and `browser-audit.md` (real-browser performance,
  axe-core accessibility, raw-vs-rendered, local Lighthouse).

## 0.1.0 - 2026-11-19

- First release, replacing the `skills-stash` `website-health-analytics` skill.
- Local FastMCP server that fetches every source itself (no third-party CLIs):
  GA4 Data/Admin API, Search Console (search analytics, sitemaps, URL
  Inspection), Bing Webmaster Tools, Microsoft Clarity Data Export, CrUX
  history, PageSpeed Insights, Firebase Auth (Identity Toolkit), Safe
  Browsing, DNS blocklists, IndexNow and Cloud Monitoring.
- Credential-free live-site probe (status, redirects, TTFB, TLS, DNS,
  robots, sitemap, noindex/canonical/title/h1/JSON-LD, security headers)
  with per-page regression diffs, plus a capped broken-link crawl.
- SQLite history with provisional-period upserts, per-source grains, and
  GA4 quality flags (thresholding, `(other)`, sampling, truncation).
- `keyEvents` replaces the deprecated GA4 `conversions`.
- Interactive `doctor` command for entering and validating every
  credential; all secrets in the OS keychain. Google uses a service-account
  key so data can live in a different account.
