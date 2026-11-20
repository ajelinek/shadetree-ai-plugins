# Changelog

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
