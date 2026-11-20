# Plan: `website-health` plugin

Branch `feat/website-health`, worktree `../plugin-stash-website-health`.
Research behind every number here: [research-report.md](research-report.md)
and [research-notes/](research-notes/).

## Goal

Replace the `skills-stash/website-health-analytics` skill with a
server-backed plugin in this marketplace. It should do everything the
report recommends, including every optional source. It follows the
same pattern as `email-domain-reputation`:

- a FastMCP server
- credentials in the macOS Keychain via `shadetree_ai_plugins_common.secrets`
- a skill that drives the server's tools
- fixture tests

## Decisions

| # | Decision | Why |
|---|---|---|
| D1 | Move the skill into this repo as `plugins/website-health`, server-backed and written in Python. Port the four `.mjs` scripts to Python. | The repo already does this for skills that hold keys, and Python is its house language. A server is justified twice over: secrets in the keychain, and persistent state (the daily Clarity snapshots and the stored metrics history). With a uv lockfile we can use `google-auth`, so Python's lack of JWT signing in the standard library no longer matters. That reverses the report's Node recommendation. |
| D2 | Fetch every source ourselves through its REST API. Drop the Bin-Huang CLIs entirely. | They only pass responses through, they're unpinned, and each has one maintainer. Owning the fetch layer also lets us read GA4's quality flags and GSC's `first_incomplete_date`. |
| D3 | **Google auth: a service-account key (the "app key"), stored in the Keychain as one JSON secret.** No browser OAuth sign-in. | The Google account that owns the GA4, Search Console and Firebase data is not the one you work in. A service account belongs to a Cloud project, not a person, so you grant its email access on each property in the other account and nothing depends on whoever is signed in. A plain API key can't do this: Google only accepts API keys for public data (CrUX, PageSpeed Insights, Safe Browsing), not for private GA4 or Search Console data. |
| D4 | Keep every other secret in the Keychain under the `shadetree-ai-plugins:website-health` service. Each site's non-secret IDs live in `~/.shadetree-ai-plugins/website-health/config.json`. | These are the repo's existing rules: no `.env`, no plaintext fallback, and a key never appears as a CLI argument, in chat, or in an env var. |
| D5 | Store history in SQLite under the plugin's state directory, keyed by `(site, source, metric, date, granularity)`. Every row carries a `provisional` flag. Raw responses are also kept as dated JSON files. | Rows have to be upserted over the 7-day GA4 re-fetch window and GSC's provisional days. Sources also report at different grains (daily, weekly, rolling 24 hours, rolling 28 days), and one row per date can't hold that. |
| D6 | **No scheduler.** Data is collected only when you run a check. Clarity calls ask for up to 3 days to cover the time since the last run; that window is stored as one aggregate row, and anything older than 3 days is recorded as a gap. | You chose not to build a schedule. Every other source can backfill, so only Clarity history gets thinner when runs are more than 3 days apart, and the report says when that happened. |
| D7 | GitHub correlation keeps using the `gh` CLI, which handles its own Keychain auth. | `gh` already stores its token in the Keychain, so there's nothing new to manage. |

## Credentials and how each is obtained

When I use the browser, I only get as far as the page that shows the key.
**You** copy the key and run the setup command in your own terminal. A key
never passes through chat, tool arguments or files. That's the repo's rule
(see `email-domain-reputation` SKILL.md § Local setup).

| Keychain key | Source | Browser-assisted steps |
|---|---|---|
| `google-service-account` | GA4, Search Console, Firebase Auth, Cloud Monitoring | In Cloud Console:<br>1. Pick or create a project.<br>2. Enable the Analytics Data, Analytics Admin, Search Console, Identity Toolkit and Cloud Monitoring APIs.<br>3. Create a service account and download a JSON key.<br>4. You run `credentials set-file google-service-account <json>`. It stores the key in the Keychain and offers to delete the downloaded file.<br>Then, **signed in to the account that owns the data**, grant the service account's email:<br>- GA4: Viewer on each property<br>- Search Console: a user on each property (Full, since Restricted can't use every API)<br>- Firebase project IAM: Firebase Authentication Viewer, and Monitoring Viewer for Hosting metrics |
| `google-api-key` | CrUX, PageSpeed Insights, Safe Browsing | Cloud Console → Credentials → API key, restricted to those three APIs. |
| `clarity-token:<site>` | Microsoft Clarity | Clarity project → Settings → Data Export → Generate token. This needs project-admin rights. |
| `bing-api-key` | Bing Webmaster Tools | Bing Webmaster Tools → Settings → API Access → API Key. |
| `cloudflare-token` | Cloudflare GraphQL | Cloudflare → My Profile → API Tokens, with **Account Analytics: Read** and **Zone Analytics: Read** scoped to the zone. |
| `stripe-key` | Stripe | Dashboard → Developers → API keys → **restricted** key with read access to Charges, Checkout Sessions and Subscriptions. |
| `sentry-token` | Sentry | User Settings → Auth Tokens, with `org:read`, `project:read` and `event:read`. |
| `uptimerobot-key` | UptimeRobot | My Settings → API → **read-only** main API key. |

**Microsoft sources across accounts.** Both work like the service
account: the credential isn't tied to whoever is signed in.

- **Clarity:** an admin of the project in the account that owns the site
  generates the token. Alternatively, that account adds your working
  account as a project admin.
- **Bing:** the key covers every site its user can see. Generate it in
  the account that owns the sites, or have that account add your working
  account under Settings → Users and use your own key.

### One command to enter everything: `doctor`

You run `uv run --project <plugin> python -m shadetree_ai_plugins_website_health doctor`
in your own terminal. `check_setup` returns that exact command. Doctor:

1. Shows every credential with its status: stored, missing, or failing.
2. Prompts for each missing one with hidden input. Enter skips it,
   `r` replaces it, and `d` deletes it. The service account takes a
   file path instead of a pasted value.
3. Validates each credential right away with one cheap, quota-free call:
   - Google service account: mint a token, then call `accountSummaries`
   - Google API key: a CrUX query
   - Bing: `GetUserSites`
   - Cloudflare: `/user/tokens/verify`
   - Stripe: `/v1/balance`
   - Sentry: `/api/0/`
   - UptimeRobot: `getAccountDetails`

   Clarity isn't validated, because every call uses one of its 10 daily
   requests. Doctor only checks the token's format.
4. Prints a summary table and the grants still missing, for example
   "service account can't see GA4 property 123 — add it as Viewer".

`--only <source>` limits doctor to one source. Each credential can still
be set with the shared `secret_setup` commands; doctor is a wrapper over
the same storage.

The IndexNow key is public by design because it's served at `/<key>.txt`,
so it lives in the site config and not the Keychain. Every source is
optional except the live-site probe. `check_setup` reports a missing source
as `not_configured`, not as a failure.

## Shared-package changes (`packages/common`)

1. Add a `set-file` action to `secret_setup`. It reads a credential file
   and checks it's valid JSON. It stores the compact JSON (the current
   `set` action rejects whitespace), then offers to delete the source file.
2. Add tests for it, then re-vendor `common` into every plugin with
   `scripts/vendor_common.py`.

The plugin itself turns the stored key into access tokens with
`google-auth`, kept in memory only.

## Plugin layout

```
plugins/website-health/
  .claude-plugin/plugin.json  .mcp.json  fastmcp.json  hooks/  pyproject.toml  uv.lock
  src/shadetree_ai_plugins_website_health/
    server.py        # tools (below)
    config.py        # site config load/validate/migrate from old .claude/website-health-analytics.json
    store.py         # SQLite store + raw snapshots, provisional upserts
    quota.py         # per-source call budgets (Clarity 3/day, URL Inspection, PSI)
    sources/ ga4.py gsc.py clarity.py bing.py firebase_auth.py github.py crux.py psi.py
             probe.py links.py safebrowsing.py blocklists.py indexnow.py
             uptime.py cloud_monitoring.py cloudflare.py stripe.py sentry.py
    analysis/ normalize.py anomalies.py correlate.py   # ports of the .mjs scripts
  skills/website-health/SKILL.md + references/
  tests/fixtures/<source>/…  tests/test_<module>.py  tests/test_server.py
```

## MCP tools

| Tool | Purpose |
|---|---|
| `check_setup(site?)` | Status for each source: `ok`, `not_configured` or `failing`, with the exact setup command. It makes no paid or quota-limited calls. |
| `discover_properties()` | Lists the GA4 properties, Search Console sites and Bing sites your credentials can see, to help fill in a site's config. |
| `configure_site(...)` / `list_sites()` | Create, update or show a site's IDs, key paths, repos and enabled sources. |
| `collect(site, sources?, backfill_days?)` | Fetches each source, writes snapshots, upserts the store and enforces quotas. It returns quality warnings for each source. |
| `probe_site(site)` | Live checks needing no auth: HTTP status and redirects, response time, a content marker, TLS expiry, DNS, robots.txt, the sitemap diff, `noindex`/canonical/title/h1/JSON-LD on key pages, and security headers. |
| `detect_anomalies(site, date?)` | Deterministic detection that knows each source's grain and skips provisional days. |
| `correlate(site, metric, date)` | Ranks deploys, workflow runs, PRs and commits through `gh`, with a lag window per source. |
| `health_report(site, date?)` | Runs probe, collect and detect, then produces the daily report payload. |
| `get_timeseries(site, metrics, start, end)` | Drill-down data. |
| `inspect_urls(site, urls?)` | Sampled Search Console URL Inspection: the top landing pages plus URLs from the latest deploy. |
| `run_pagespeed(site, urls?)` | A PageSpeed Insights lab run. The skill calls it after a deploy. |
| `crawl_links(site, max_pages)` | A capped broken-link crawl. |
| `indexnow_submit(site, urls)` | The one write action. The skill confirms with you before calling it. |

## Sources: what gets built

All of these follow the report. Each one gets fixture tests for its parser
and its error mapping.

| Source | Calls | Canonical metrics |
|---|---|---|
| GA4 | Data API `batchRunReports` and `runRealtimeReport`, `getMetadata`, and Admin `accountSummaries`/`keyEvents`. Re-fetch the last 7 days. | sessions, engagedSessions, engagementRate, activeUsers, newUsers, **keyEvents** (`conversions` stays a read alias), sign_up, AI-referrer sessions, sessions by channel, device and landing page. Records `subjectToThresholding`, `dataLossFromOtherRow`, `samplingMetadatas` and `dataTruncationReasons`. |
| Search Console | `searchanalytics.query` with `dataState=all` over 14 days, `sitemaps.list`, and sampled URL Inspection | clicks, impressions, ctr, position, by query and page. Days from `first_incomplete_date` onward are marked provisional. Uses the branded filter where the property is eligible. |
| Clarity | One call plus one with the URL dimension per run, with `numOfDays` set from the time since the last snapshot (1–3). Budget of 3 calls a day; no retry on a 429. | sessions, bot share, distinct users, pages per session, scroll depth, engagement time, and the rage, dead, error-click, quickback, excessive-scroll and script-error percentages, per page. Rolling 24-hour grain. |
| Bing | `GetUserSites`, `GetRankAndTrafficStats` and `GetCrawlStats` (daily); `GetQueryStats` and `GetPageStats` (weekly); `GetCrawlIssues`, `GetFeeds` | clicks and impressions, crawl status-code counts, crawl issues, sitemap status |
| Firebase Auth | Identity Toolkit `accounts:batchGet` with the service account, falling back to `firebase auth:export` | signups, and signups by first provider |
| GitHub | `gh api` deployments, workflow runs, PRs and commits | correlation candidates |
| Live probe | stdlib `ssl`, `socket`, `urllib` and `html.parser` | uptime, TTFB, TLS days left, sitemap URL count, regression flags |
| CrUX | `queryRecord` by origin and key URLs, and `queryHistoryRecord`, for both PHONE and DESKTOP | LCP, INP, CLS, FCP and TTFB at p75 over a rolling 28-day window. Treats a 404 as low traffic. |
| PageSpeed Insights | `runPagespeed` on key URLs, triggered by deploys | Lighthouse scores, plus a diff of failing audits |
| Safe Browsing | v4 `threatMatches:find` (v5 needs client-side hash-prefix handling; revisit if v4 is retired) | flagged or clean. The report notes that the API is licensed for non-commercial use and that Web Risk is the paid alternative for businesses. |
| Blocklists | DNSBL lookups, ported from the skills-stash `check_blocklists.py` | the domain's blocklist status |
| IndexNow | Checks that the key file is reachable, and submits URLs when you confirm | key status |
| Uptime | UptimeRobot `getMonitors`, or Cloud Monitoring uptime checks | uptime % and incidents |
| Firebase Hosting | Cloud Monitoring `response_count` by status. This needs Cloud Logging linked to Hosting. | 2xx, 3xx, 4xx and 5xx counts |
| Cloudflare | GraphQL `httpRequests1dGroups` | requests, cache ratio, threats, 4xx and 5xx |
| Stripe | Charges, Checkout Sessions and Subscriptions, listed per day | revenue, checkouts started and completed, failed payments, churn |
| Sentry | `stats_v2` plus top issues for the project | error events, new issues, release correlation |
| AI visibility | The GA4 AI-referrer report, plus a monthly reminder in the report to check Bing AI Performance and the Search Console generative-AI report by hand | AI-referred sessions |

## Analysis changes

- **Granularity:** the normalizer and the anomaly detector know each
  source's grain. A z-score is never computed across mismatched windows.
- **Provisional days:** no alert on a provisional day. Lower confidence on
  days that GA4 flagged as thresholded or truncated.
- **Lag order:** correlation follows the order in which sources see a
  regression, from fastest to slowest:
  1. the live probe (minutes)
  2. Clarity and Sentry (about 24 hours)
  3. GA4 (about 12–48 hours)
  4. Search Console and Bing (2–3 days)
  5. CrUX (weeks)

  If they agree in that order, the report says so as evidence.
- **Interpretation notes:**
  - AI Overviews and AI Mode impressions are folded into the Search
    Console `web` totals.
  - Clarity's consent enforcement for EEA, UK and Swiss visitors started
    2025-10-31 and changes their session counts.
  - Bing's query and page stats come in weekly buckets.
- **Remediation:** the metric→suspect-file table gains the new sources:
  - probe regression → `firebase.json`, the layout's `<head>`, `robots.txt`
  - CWV and PageSpeed audit → images, fonts and scripts
  - Clarity rage clicks → the component on that URL
  - Sentry → the stack frame
  - Stripe → checkout code

## Build sequence

Each phase is a commit and leaves tests green.

1. **Scaffold:** plugin skeleton, config, store, quota, `check_setup`,
   the `doctor` command, and vendored `common`.
2. **Common auth:** the `set-file` action and its tests.
3. **Probe and analysis core:** the live probe, blocklists, the link
   crawl, and the Python ports of normalize, anomalies and correlate
   (the existing behavior, plus granularity and provisional handling).
4. **Google sources:** GA4, Search Console with URL Inspection, Firebase
   Auth, CrUX, PageSpeed Insights, Safe Browsing, and Cloud Monitoring.
5. **Microsoft sources:** Clarity and Bing, plus IndexNow.
6. **Optional sources:** UptimeRobot, Cloudflare, Stripe and Sentry.
7. **Report and skill:** `health_report` and the skill with its
   references (ported and updated, including `keyEvents`).
8. **Release prep:**
   - register the plugin in `marketplace.json`
   - README and CHANGELOG
   - update `docs/plugin-authoring.md` to mark the migration as done
   - run `uv sync --all-packages --locked`, `ruff`, `pytest` and
     `claude plugin validate . --strict`
9. **Live setup and verification (browser-assisted):** get each
   credential as described above, then run `discover_properties`,
   `configure_site`, `collect` and `health_report` against a real site.
   This settles the open items:
   - Clarity's field casing and the Country dimension string
   - the response shapes of Bing's `GetCrawlIssues` and `GetFeeds`
   - that the service account's IAM roles are enough for Firebase Auth
     and Hosting metrics
10. **Cleanup in skills-stash:** delete `website-health-analytics`, its
    README row and its `npx skills add` line, rebuild `dist/`, and commit
    that separately.

## Risks to watch

- **Service-account key creation blocked:** if the Cloud project sits under
  a Google Cloud organization created after May 2024, key creation is off
  by default. A project with no organization (a personal Gmail-owned
  project) isn't affected; otherwise an org admin has to allow it for
  that project.
- **Key handling:** a service-account key doesn't expire. Keep it only in
  the Keychain, grant it read-only roles, and rotate it if it ever leaks.
- **Clarity gaps:** with no scheduler, runs more than 3 days apart leave
  Clarity gaps that can't be filled.
- **Clarity token deprecation:** the Clarity MCP server is deprecating
  token auth. If Microsoft deprecates Data Export tokens too, the
  `clarity` source has to move to OAuth.
