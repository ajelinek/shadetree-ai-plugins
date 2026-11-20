# website-health

Cross-source website health checks plus an account-free site audit for Claude: GA4, Google Search Console,
Bing Webmaster Tools, Microsoft Clarity, CrUX/PageSpeed Insights, a live-site
probe, Firebase Auth signups, Safe Browsing and DNS blocklists, plus optional
Cloud Monitoring (Firebase Hosting status codes and uptime checks). Regressions are
correlated with GitHub deploys, PRs and commits so Claude can point at the
change that caused them and propose a fix.

`audit_site` needs no account and adds nothing to your site. It crawls the site and checks
SEO (titles, descriptions, canonicals, duplicates, sitemap consistency, structured data),
accessibility basics, performance (compression, caching, images, scripts, TTFB, HTTP/2,
redirects), security headers, whether GA4/Clarity tags are really on every page, and AI
access: robots.txt per AI and search bot, real fetches as each bot's user agent to expose
CDN blocks, content present in raw HTML, `Content-Signal`, `llms.txt` and Common Crawl.
Findings are tracked between audits as new, persisting or resolved. PageSpeed scores and
timings are stored weekly so performance has a trend.

## Install

```
/plugin marketplace add ajelinek/shadetree-ai-plugins
/plugin install website-health@shadetree-ai-plugins
```

Requires `uv` on `PATH`. Deploy correlation also needs the GitHub CLI
(`gh auth login`).

## Set up

1. Ask Claude to "check website health setup". It calls `check_setup` and
   gives you a `doctor` command.
2. Run that command **in your own terminal**. It asks for each credential
   with hidden input (Enter skips one) and validates it. Credentials are
   stored only in the OS keychain (macOS Keychain, Windows Credential
   Locker, Linux Secret Service).
3. Grant the Google service account's email access in the account that owns
   the data (GA4 Viewer, Search Console user, Firebase Authentication
   Viewer). Doctor tells you which grants are missing.
4. Ask Claude to discover your properties and configure your site.

Full detail: `skills/website-health/references/setup.md`.

## Data and privacy

- Runs locally. Requests go only to the APIs you configure and to your own
  site.
- History lives in `~/.shadetree-ai-plugins/website-health/` (SQLite plus
  raw JSON snapshots). Firebase Auth exports are reduced to daily counts; no
  user emails are stored.
- The only external write is `indexnow_submit`, which Claude confirms with
  you first.

## Limits worth knowing

- Clarity allows 10 API calls per project per day and returns only the last
  1–3 days, so a check gaps if runs are more than 3 days apart.
- PageSpeed works without a key, but Google's shared keyless quota is usually exhausted; a
  free `google-api-key` (set with doctor) makes it reliable. `skills/website-health/references/browser-audit.md`
  covers an account-free alternative (browser measurement, local Lighthouse).
- The AI-bot fetch test sends each bot's user-agent string to your own site only. CDNs that
  verify bots by IP may treat the real crawler differently, so a block is strong evidence
  and a pass is weak.
- There's no built-in scheduler: data is collected when you run a check.
  Every source except Clarity backfills on the next run.
- Bing's AI Performance report and Search Console's generative-AI report
  have no API; the daily report reminds you monthly to check them.
