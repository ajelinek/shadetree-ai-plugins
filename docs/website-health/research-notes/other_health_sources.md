# Additional Website Health Data Sources (beyond GA4, GSC, Bing WMT, Clarity, Firebase Auth, GitHub deploys)

Scope: small Astro/Firebase-hosted sites, daily health check, correlate anomalies with deploys, recommend code fixes. Researched 2026-11-19. Fifteen tool calls: about half fetched primary docs and half used search results, which leaned on third-party aggregators. Each item below says which kind of source backs it.

## Performance / Core Web Vitals (CrUX API, CrUX History API, PageSpeed Insights, web-vitals RUM)

### Takeaway
CrUX API (daily 28-day rolling field data) plus CrUX History API (weekly, up to 40 periods) is the best free field-CWV source: one API key, 150 QPM, stdlib POST. A 28-day window lags too much for per-deploy correlation, though. PSI/Lighthouse lab runs on key URLs after each deploy catch regressions right away. A web-vitals → GA4 event pipeline is the only same-day field signal, and it needs code in the site.

### Cited Findings
- CrUX API endpoint: `POST https://chromeuxreport.googleapis.com/v1/records:queryRecord?key=API_KEY`. Requires a Google Cloud API key with the Chrome UX Report API enabled — [CrUX API docs](https://developer.chrome.com/docs/crux/api)
- Quota: 150 queries/minute per Google Cloud project, free. You cannot pay for more quota — [CrUX API docs](https://developer.chrome.com/docs/crux/api)
- Data is a 28-day rolling average, about 2 days behind. Updated daily around 04:00 UTC, best effort, no SLA. Same-day repeat calls return identical results — [CrUX API docs](https://developer.chrome.com/docs/crux/api)
- `origin` aggregates across all pages, `url` covers one page. The API does basic URL normalization and does not follow redirects — [CrUX API docs](https://developer.chrome.com/docs/crux/api)
- Metrics: CLS, FCP, INP, LCP, experimental_time_to_first_byte, round_trip_time, navigation_types, form_factors, plus an LCP breakdown (resource type, TTFB, load delay/duration, render delay) and experimental soft-navigation variants. Form factors are DESKTOP/PHONE/TABLET, or all if omitted. The API returns histograms, p75, and fractions — [CrUX API docs](https://developer.chrome.com/docs/crux/api)
- CrUX History API: `POST .../v1/records:queryHistoryRecord`. Weekly collection periods. `collectionPeriodCount` runs 1–40 (default 25, so 40 weeks ≈ 10 months). Updated Mondays around 04:00 UTC with data through the previous Saturday. Shares the 150 QPM quota. Note that the page's own intro says "six months," which conflicts with the 40-period figure — [CrUX History API docs](https://developer.chrome.com/docs/crux/history-api)
- PSI v5 endpoint: `GET https://www.googleapis.com/pagespeedonline/v5/runPagespeed?url=...&key=...`. Returns `lighthouseResult` (audits, categories, lighthouseVersion, fetchTime) and CrUX `loadingExperience`/`originLoadingExperience`. Google says it **plans to discontinue CrUX data in PSI** and points to the CrUX API instead — [PSI get started](https://developers.google.com/speed/docs/insights/v5/get-started)
- PSI quota is commonly cited as 25,000/day and 400 per 100 seconds per key. Screaming Frog and Unlighthouse instead cite 60 per 100 seconds per user and about 240/min per project. I found no official Google quota page; check the Cloud Console quotas page — [Unlighthouse](https://unlighthouse.dev/learn-lighthouse/pagespeed-insights-api/rate-limits); [Screaming Frog](https://www.screamingfrog.co.uk/guides/pagespeed-insights-integration); [apis.io](https://apis.io/rate-limits/google-chrome/google-chrome-rate-limits/)
- Google added an llms.txt audit to Lighthouse on May 5, 2026, so PSI/Lighthouse output may now include that check — [PPC Land](https://ppc.land/google-adds-llms-txt-to-lighthouse-as-agentic-web-standards-heat-up/)

### Inferences
- CrUX URL-level data is often missing for low-traffic small-business pages, which fall below the eligibility threshold. Origin-level data is the realistic default. The script should treat a 404 "data not found" as "insufficient traffic" and not as an error.
- Because of the 28-day window, a deploy-caused CWV regression shows up gradually over about 1–4 weeks. Weekly History API periods give cleaner before/after-deploy comparisons than daily queryRecord deltas.
- PSI (Lighthouse lab) is the deploy-correlated signal. Run mobile `strategy` on homepage plus 3–5 key templates daily or on each deploy. Lighthouse scores vary 5–10 points between runs, so alert on audit-level changes (LCP element, render-blocking resources, total byte weight, unused JS) rather than on the score. A PSI call takes about 10–30 s per URL.
- Effort, both stdlib (`urllib.request` + `json`): CrUX/History is low effort (about 50 lines). PSI is low effort (a GET with a long timeout).
- web-vitals RUM: the `web-vitals` JS library can send LCP/INP/CLS as GA4 events. That needs a site code change plus a GA4 custom-dimension setup, and it then rides the existing GA4 Data API integration. It is the only same-day field CWV source and is worth recommending as an optional code fix.

### Gaps
- No official Google page found for current PSI quotas. The numbers above are from third parties.
- Did not verify the exact CrUX eligibility threshold or whether the PSI strategy/category params changed in 2026. The get-started page fetched didn't document them.

## Uptime, TLS, DNS & HTTP status

### Takeaway
A daily agent cannot detect outages between runs, so real uptime needs an always-on external monitor. UptimeRobot's free tier (50 monitors, 5-minute checks, REST API on all plans) is the simplest. Google Cloud Monitoring uptime checks are an alternative that fits Firebase projects (1M free executions per project). TLS expiry, DNS resolution, and HTTP status/redirect checks are trivial stdlib probes the daily script should run itself.

### Cited Findings
- UptimeRobot Free: 50 monitors at a 5-minute interval, HTTP/port/ping/keyword monitors, 1 status page, 5 integrations. The Platform REST API is included on every plan, Free included — [UptimeRobot pricing](https://uptimerobot.com/pricing.md)
- Commercial use of UptimeRobot Free is **disputed**. A third-party 2026 article says the free plan has been non-commercial only since Dec 1, 2024, while UptimeRobot's own blog says it's allowed for commercial use within the fair-use limits. Check the current ToS — [dev.to](https://dev.to/r0tten0x/uptimerobot-free-plan-in-2026-the-limits-thatll-actually-bite-you-445g); [UptimeRobot knowledge hub](https://uptimerobot.com/knowledge-hub/monitoring/what-is-uptimerobot/)
- UptimeRobot has published a post on AI agents setting up monitoring without signup — [UptimeRobot blog](https://uptimerobot.com/blog/your-ai-agent-can-now-set-up-uptime-monitoring-no-signup-required/)
- Google Cloud Monitoring uptime checks: $0.30 per 1,000 executions after 1 million free executions per Google Cloud project. Synthetic monitors are priced separately ($1.20/1k, 100 free per billing account). Pricing table was effective Oct 1, 2022; I could not confirm it is unchanged in 2026 — [Google Cloud Observability pricing](https://cloud.google.com/monitoring/pricing)

### Inferences
- Firebase Hosting projects already have a GCP project, so Cloud Monitoring uptime checks fit well. One HTTPS check every 5 minutes from 3+ regions is about 26k executions/month, well inside the free tier. Reading the results takes the Monitoring API with OAuth/service-account auth, which is heavier than an UptimeRobot API key. Querying `monitoring.googleapis.com` timeSeries from stdlib needs JWT signing for a service account. That isn't feasible in pure stdlib without RSA, so you'd shell out to `gcloud auth print-access-token`. Medium effort.
- UptimeRobot v2/v3 API with one API key returns monitor status, uptime ratios, and response-time logs. Low effort with stdlib.
- Probes the daily script can run itself, all stdlib with near-zero effort:
  - TLS cert expiry and issuer: `ssl.create_default_context()` + `socket.create_connection` + `getpeercert()['notAfter']`. Alert at under 21 days. Firebase/Cloudflare auto-renew, but custom-domain DNS changes can silently break renewal.
  - DNS: `socket.getaddrinfo` for apex and www. Compare against expected records.
  - HTTP: status code, redirect chain (http→https, apex→www) length under 2, TTFB timing, and response body containing an expected marker string, all with `http.client`/`urllib`.
- Firebase status and Cloudflare status: a status-page JSON feed lets the agent rule out a platform incident before blaming a deploy. (Not verified this session: status.firebase.google.com publishes a JSON incidents feed, and cloudflarestatus.com is a Statuspage `/api/v2/summary.json`.)

### Gaps
- Better Stack free-tier limits and API not researched (no time budget left).
- UptimeRobot API v3 specifics (endpoints, rate limit) not fetched.

## Crawlability & technical SEO probes (plain HTTP)

### Takeaway
Most technical-SEO regressions a deploy can cause are detectable with plain HTTP and stdlib HTML parsing: robots.txt disallow-all, sitemap 404 or stale entries, accidental `noindex`, canonical pointing at a staging domain, broken internal links, redirect chains, missing security headers, and invalid JSON-LD. Google's Rich Results Test has no public API. The GSC URL Inspection API (2,000/day/site) returns Google's rich-results and indexing verdict per URL and is the closest substitute.

### Cited Findings
- URL Inspection API quota: 2,000 queries/day and 600/min per site. Search Analytics: 1,200 QPM per site/user — [Search Console API limits](https://developers.google.com/webmaster-tools/limits)
- Rich Results Test supports JSON-LD, RDFa, and Microdata and reports detected rich-result types with errors and warnings. Google-specific validation was removed from the old Structured Data Testing Tool, which moved to the Schema Markup Validator (validator.schema.org) — [Google: Test your structured data](https://developers.google.com/search/docs/appearance/structured-data); [Rich Results Test help](https://support.google.com/webmasters/answer/7445569)
- No Google API for the Rich Results Test was found. Batch testing exists only through third-party scrapers such as Apify actors — [Apify rich results tester](https://apify.com/alizarin_refrigerator-owner/rich-results-tester)

### Inferences
- Recommended stdlib probe set, run against the live site daily. Each item is a low-effort `urllib` + `html.parser` + `json` check:
  1. `robots.txt`: 200, parses with `urllib.robotparser`, does not disallow `/` for Googlebot/Bingbot, lists the sitemap URL. Report AI crawler directives (GPTBot, ClaudeBot, PerplexityBot, Google-Extended) as informational.
  2. Sitemap: fetch (handle sitemap-index, which Astro's `@astrojs/sitemap` emits as `sitemap-index.xml`), parse with `xml.etree`, HEAD/GET each URL (cap about 200), and flag non-200s, redirects, and URLs whose canonical differs. Diff the URL count against yesterday's snapshot. A large drop after a deploy is a strong signal.
  3. Per key page: `<meta name="robots">` and the `X-Robots-Tag` header for noindex, `<link rel=canonical>` host/scheme matches production, `<title>`/meta description present and non-duplicate, a single `<h1>`, `hreflang` if used.
  4. Broken internal links: crawl links from sitemap pages (same-host only, rate-limited), report 4xx/5xx.
  5. JSON-LD: extract `<script type="application/ld+json">`, check it parses with `json.loads`, and check that required props exist for the types used (Organization, LocalBusiness, Article, Product, FAQ). This is a syntax and required-field check, not full Google eligibility. Use the URL Inspection API's rich-results section for Google's verdict on a few key URLs. That API rides the GSC auth the skill already has, and 2,000/day is ample.
  6. Security headers: HSTS, Content-Security-Policy, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, X-Frame-Options/frame-ancestors. Firebase Hosting sets these via `firebase.json` `headers`, so a regression is a direct code fix.
- These probes map 1:1 to code fixes in the repo (`firebase.json` headers/redirects, Astro layout meta, `astro.config` site URL for canonicals), which is the skill's goal.

### Gaps
- Did not confirm the exact field structure of the URL Inspection API's `richResultsResult` in 2026 (search didn't return the reference page).
- No 2026-verified free API for full Schema.org validation. validator.schema.org has no documented public API.

## Edge/CDN analytics (Cloudflare GraphQL, Firebase Hosting logs/metrics)

### Takeaway
If a site is proxied through Cloudflare (even the Free plan), the GraphQL Analytics API gives daily requests, bandwidth, cache ratio, threats, and status-code breakdowns, a server-side traffic signal independent of JS analytics and ad blockers. Firebase Hosting has native `response_count` (by HTTP status) and `log_bytes` metrics once Cloud Logging is linked. That makes a 5xx/404 spike after a deploy directly observable.

### Cited Findings
- Cloudflare GraphQL default rate limit is 300 queries per 5-minute window per user, on top of general API limits. Zone-scoped queries take up to 10 zones — [Cloudflare GraphQL limits](https://developers.cloudflare.com/analytics/graphql-api/limits/)
- Adaptive datasets (`httpRequestsAdaptiveGroups`, `firewallEventsAdaptive`) retain at least 31 days on every plan, including Free/Pro, as of an Oct 2, 2026 changelog. Aggregated datasets (`httpRequests1hGroups`, `httpRequests1dGroups`) keep their per-plan limits — [Cloudflare changelog 2026-10-02](https://developers.cloudflare.com/changelog/post/2026-10-02-30-days-analytics-on-every-plan/)
- A docs mirror lists `httpRequests1dGroups` retention as 365 days on all plans including Free. This is unverified against the canonical page, which tells users to query each dataset's settings for exact limits — [docs mirror](https://cloudflare-docs-6l3.pages.dev/analytics/graphql-api/limits); [Cloudflare GraphQL limits](https://developers.cloudflare.com/analytics/graphql-api/limits/)
- Firebase Hosting: link the project to Cloud Logging in the Firebase console per site. Log entries include HTTP status. Auto-generated metrics are `log_bytes` and `response_count`, which includes HTTP status so you can plot responses by status. Usage counts against the Cloud Logging free monthly tier per project. Logs can be exported to BigQuery — [Firebase Hosting web request logs and metrics](https://firebase.google.com/docs/hosting/web-request-logs-and-metrics)

### Inferences
- Cloudflare: a single POST to `https://api.cloudflare.com/client/v4/graphql` with a scoped API token (Analytics:Read) works in stdlib. Low effort. `httpRequests1dGroups` gives requests, pageViews, bytes, cachedRequests, `responseStatusMap`, threats, and countryMap. This is only relevant if DNS is proxied through Cloudflare. Firebase-hosted sites often aren't, so treat it as conditional.
- Firebase Hosting `response_count` by status is the best "did the deploy break pages" server-side signal for Firebase sites. Reading it takes the Cloud Monitoring timeSeries API with GCP OAuth (gcloud token or service account). Medium effort, and logging must be linked first (a one-time manual step). It also catches 404 spikes from removed or renamed routes after an Astro restructure.

### Gaps
- Exact Firebase Hosting metric names for the Monitoring API (e.g. `firebasehosting.googleapis.com/network/...`) and their ingestion lag were not verified.
- Free-plan field availability in `httpRequests1dGroups` (e.g. whether `responseStatusMap` is present on Free) was not confirmed.

## Errors (Sentry, Crashlytics, Clarity JS errors)

### Takeaway
For JS error tracking on a small site, Sentry's free Developer plan (about 5K errors/month, 1 user) plus its REST API is the practical choice, and Sentry release tracking ties errors directly to deploys. Firebase Crashlytics is mobile-only (Android/iOS/Flutter/Unity), not web. If Clarity is already integrated, its JS-error and "error click" signals are a zero-cost substitute.

### Cited Findings
- Sentry Developer plan: free, about 5K errors/month, 1 user, no time limit. Team is about $26/mo annual ($29 monthly), Business about $80/mo annual ($89 monthly). These are third-party aggregator figures; verify at sentry.io/pricing — [Activepieces Nov 2026](https://www.activepieces.com/blog/sentry-pricing-2026-developer-team-business-plans); [Last9](https://last9.io/blog/sentry-pricing/); [Sentry pricing](https://sentry.io/pricing/)

### Inferences
- Sentry REST API with an auth token (`/api/0/projects/{org}/{project}/issues/?statsPeriod=24h`, plus releases endpoints) works in stdlib. Low effort. Its "release" concept matches GitHub deploy SHAs, which is the deploy correlation this skill wants. Only relevant if the site has interactive islands or forms; pure static Astro sites have few JS errors.
- Crashlytics: from prior knowledge, Crashlytics does not support web apps. Skip it for web.
- Clarity JS errors: the Clarity Data Export API is already in scope for this skill. Whether the export includes JS-error metrics should be checked by the Clarity researcher.

### Gaps
- Did not fetch Sentry's official API rate limits or current free-tier quota page directly.
- Did not verify a primary source for "Crashlytics doesn't support web" in 2026.

## AI search visibility (Bing AI Performance, GSC AI Mode, llms.txt, AI citation APIs)

### Takeaway
As of late 2026, neither Microsoft nor Google exposes AI-citation or AI-impression data through an API. Bing's AI Performance report (Feb 2026) and GSC's Generative AI performance report (June/Aug 2026) are both UI-only. A daily skill can at most (a) remind the user to check them, and (b) infer AI-referral traffic from GA4 referrers (chatgpt.com, perplexity.ai, copilot.microsoft.com, gemini.google.com). llms.txt is low value for search visibility.

### Cited Findings
- Bing Webmaster Tools AI Performance report launched in beta Feb 10, 2026. It tracks citations in Copilot, Bing AI summaries, and some partners, including cited URLs and grounding queries. It shows no ranking or click attribution and covers Microsoft surfaces only — [Search Engine Land](https://searchengineland.com/bing-webmaster-tools-ai-performance-report-468751); [Search Engine Journal](https://www.searchenginejournal.com/bing-webmaster-tools-adds-ai-citation-performance-data/566874/)
- No public API for Bing AI Performance as of mid-2026. A Microsoft rep said API access is on the roadmap with no date — [CXL](https://cxl.com/blog/bing-ai-visibility-tracking-webmaster-tools/); [llmrush](https://llmrush.org/blog/bing-webmaster-tools-ai-performance/); [Hikoo](https://www.tryhikoo.com/en/blog/guides/bing-webmaster-tools-ai-performance-complete-guide-2026/)
- GSC Generative AI performance report: launched June 3, 2026 and rolled out to all properties Aug 11, 2026. It counts impressions only and combines AI Overviews with AI Mode. Clicks appear only in the main Performance report — [crawlraven](https://crawlraven.com/blog/gsc-ai-performance-reports); [Hikoo](https://www.tryhikoo.com/en/blog/guides/search-console-ai-overviews-impressions/)
- GSC API: testers found every candidate `type` value rejected (400 INVALID_ARGUMENT). `searchAppearance` returns nothing AI-related and the BigQuery bulk export has no AI column. Google's help text reportedly says AI data is included in Web search-type totals — [AskedAbout](https://askedabout.com/news/can-you-get-search-console-generative-ai-data-from-the-api)
- Google confirmed (Aug 2026, Mueller) that AI Mode follow-up turns are logged as new queries in the standard performance report. These are long, conversational query rows — [Suganthan](https://suganthan.com/blog/ai-mode-queries-search-console/); [indexlab](https://www.indexlab.ai/blog/search-console-ai-mode-conversation-leak)
- llms.txt: Google Search doesn't use it (Illyes, July 2025; Google guidance updated May–June 2026, with sources disagreeing on the date). Ahrefs found 97% of 137K sites' llms.txt files got zero requests in May 2026. Yet Google added an llms.txt audit to Lighthouse on May 5, 2026 — [Ahrefs study](https://ahrefs.com/blog/llmstxt-study/); [Optimizely](https://www.optimizely.com/field-notes/articles/does-llms-txt-work/); [PPC Land](https://ppc.land/google-adds-llms-txt-to-lighthouse-as-agentic-web-standards-heat-up/)

### Inferences
- Cheapest AI-visibility signal: a GA4 Data API report of sessions by `sessionSource` matching AI-assistant domains, trended daily. This uses the existing GA4 integration, so effort is near zero.
- GSC heuristic: flag queries with more than about 8 words or a conversational shape as likely AI Mode follow-ups. This is an approximation, not ground truth.
- llms.txt: at most a "file exists and returns 200" probe. Don't treat it as a health signal.
- Third-party AI citation trackers (Otterly, Profound, etc.) are paid. Skip them for small business.

### Gaps
- Status after Aug 2026 of a GSC API for AI data, and after July 2026 for Bing, is unconfirmed. These are third-party sources, not Google/Microsoft docs.

## Business signals (Stripe, form submissions)

### Takeaway
For sites that sell, daily Stripe charge/checkout counts are the single most important "did the deploy break revenue" signal. Form submission counts usually come from GA4 events the skill already reads, or from wherever the forms post (Firestore, Formspree, etc.).

### Cited Findings
- None fetched this session (out of budget).

### Inferences
- Stripe REST API: `GET /v1/charges` or `/v1/checkout/sessions` with `created[gte]` and a restricted read-only key. Basic auth over HTTPS works in stdlib. Low effort. Alert on a zero-charge day versus the trailing average, or on a jump in the failure rate, especially right after a deploy that touched checkout code. Use a restricted key with read-only scope.
- Forms: if forms write to Firestore via Firebase, counting docs per day needs the Firestore REST API with OAuth (medium effort). The simpler path is a GA4 `generate_lead`/form_submit event already captured. Zero submissions after a deploy is a classic broken-form regression.

### Gaps
- Stripe rate limits and API version details were not verified this session (Stripe docs skill available in the repo).

## Security & reputation (Safe Browsing, blocklists)

### Takeaway
A daily Safe Browsing lookup of the origin is cheap insurance: a hacked or flagged site loses nearly all traffic overnight. Note that the Safe Browsing API is non-commercial only. Google directs commercial users to the paid Web Risk API, which matters for a business site.

### Cited Findings
- Safe Browsing v5: `hashes:search` and `hashLists` (list/batchGet/get) are v5. `urls:search` is v5alpha1. Auth is an API key as a `key` param — [Safe Browsing reference](https://developers.google.com/safe-browsing/reference)
- "The Safe Browsing API is for non-commercial use only." Commercial use should go to the Web Risk API — [Safe Browsing reference](https://developers.google.com/safe-browsing/reference)
- The reference page doesn't state quotas or whether v4 is deprecated — [Safe Browsing reference](https://developers.google.com/safe-browsing/reference)

### Inferences
- `urls:search` (v5alpha1) with the origin and key pages is the simplest stdlib call. The hash-prefix flow (`hashes:search`) needs SHA-256 prefix computation, which `hashlib` handles. Low effort either way.
- Licensing: a small-business site checking its own domain is arguably commercial, so mention Web Risk as the compliant option. Web Risk pricing and free tier were not verified.
- Domain and email blocklists (Spamhaus DBL via DNS lookup, etc.) overlap with the repo's existing `email-domain-reputation` skill (`check_blocklists.py`). Reuse it rather than duplicating.
- GSC already surfaces "Security issues" and "Manual actions," but the Search Console API does not expose them (prior knowledge, unverified here). Keep this as a manual reminder.

### Gaps
- Web Risk API free tier and pricing not researched.
- Whether Safe Browsing v4 `threatMatches:find` is formally deprecated is not stated on the v5 reference page.

## Recommended tiering for a small-business daily health check

### Takeaway
Must-have signals are cheap stdlib probes plus a few free APIs that catch site-down, deindexed, and broken-revenue failures and map directly to code fixes. Nice-to-have signals add depth (CWV lab, edge logs, Sentry) at moderate setup cost. AI-citation APIs and paid trackers are skipped because the data either doesn't exist via API or costs money.

### Cited Findings
- Tiering is a synthesis of the sections above; supporting citations are in each section.

### Inferences
**Must-have.** All are free, stdlib, and either deploy-correlatable or catastrophic if missed:

| Signal | Catches | API / auth | Quota / lag | Effort |
|---|---|---|---|---|
| HTTP status, redirects, TTFB, content marker (self-probe) | Site down, broken routes, redirect loops after deploy | Plain HTTPS, no auth | Unlimited, real-time | Very low |
| TLS cert expiry + DNS resolution (self-probe) | Expiring or broken certs, DNS misconfig | `ssl`/`socket`, no auth | Real-time | Very low |
| robots.txt + sitemap + noindex/canonical probe | Accidental deindexing, staging canonicals, sitemap 404s | Plain HTTPS | Real-time | Low |
| Security headers probe | Lost HSTS/CSP after `firebase.json` change | Plain HTTPS | Real-time | Very low |
| CrUX API (origin) + History | Field CWV regressions (LCP/INP/CLS) | API key; 150 QPM | ~2-day lag, 28-day window; weekly history | Low |
| Stripe charges/checkout (if selling) | Broken checkout or revenue drop | Restricted key, basic auth | Near real-time | Low |
| Safe Browsing lookup | Hacked or flagged site | API key (non-commercial caveat → Web Risk) | Near real-time | Low |

**Nice-to-have:**
- PSI/Lighthouse lab on 3–5 key URLs per deploy (API key, ~25k/day unverified). Catches per-deploy performance regressions before CrUX shows them.
- External uptime monitor (UptimeRobot Free or GCP uptime checks), read via API. Catches outages between daily runs. Requires a one-time monitor setup.
- Firebase Hosting `response_count` by status (Cloud Logging link + GCP OAuth). Server-side 404/5xx spikes. Medium effort.
- Cloudflare GraphQL `httpRequests1dGroups`, only if proxied through Cloudflare. Ad-blocker-proof traffic and status codes.
- Sentry (free about 5K errors/month), only for sites with meaningful JS. Release-tagged errors.
- Broken-link crawl (capped) and JSON-LD parse checks. URL Inspection API for rich-results and indexing on a few key URLs (2,000/day).
- AI referral traffic via GA4 `sessionSource` (zero extra integration).
- web-vitals → GA4 events, as a recommended code change rather than a data pull.

**Skip / manual reminder only:**
- Bing AI Performance and GSC Generative AI reports: no API as of mid/late 2026, so they stay a monthly manual check.
- Paid AI-citation trackers, paid uptime tiers, Web Risk unless licensing demands it.
- llms.txt as a health metric (existence check at most).
- Crashlytics (no web support).
- Better Stack and other secondary uptime vendors (redundant with UptimeRobot/GCP for small sites).
- Status-page polling of Firebase/Cloudflare: only on anomaly, to rule out a platform incident. Not a daily metric.

### Gaps
- Better Stack, Web Risk pricing, Stripe limits, Sentry API limits, and Firebase Hosting Monitoring metric names were not verified within the research budget.
