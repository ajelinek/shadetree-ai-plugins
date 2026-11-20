# Metric definitions

Metric names are `<source>.<name>`. `dim` is `""` for site totals, otherwise
`page=`, `query=`, `channel=`, `source=`, `provider=`, `formFactor=`,
`monitor=`, `currency=` or `status=`.

| Metric | Grain | Meaning and caveats |
|---|---|---|
| `ga4.sessions`, `engagedSessions`, `engagementRate`, `activeUsers`, `newUsers`, `screenPageViews` | day | GA4 Data API. Last 2 days provisional; re-fetched for 7 days. `newUsers` is cookie-based and directional. |
| `ga4.keyEvents` | day | GA4 key events. **`conversions` was renamed `keyEvents` in May 2024**; old configs are mapped on import. Only as good as the event setup. |
| `ga4.signupEvents` | day | Count of the `ga4SignupEvent` event (default `sign_up`). Client-side: ad blockers and consent suppress it. |
| `ga4.aiReferralSessions` | day | Sessions whose source is an AI assistant domain (`aiReferrers`). The only AI-visibility signal with an API. |
| `firebase_auth.signups` | day | **Authoritative** signups (server-side). `provider=` uses each user's first linked provider. If it diverges from `ga4.signupEvents` by more than 20%, that's an instrumentation gap, not a signup anomaly. |
| `gsc.clicks`, `impressions`, `ctr`, `position` | day | Search Console `web`, `dataState=all`. Days from `firstIncompleteDate` on are provisional. AI Overviews/AI Mode impressions are folded in. A higher `position` is worse. |
| `bing.clicks`, `impressions` | day | Bing `GetRankAndTrafficStats`. Last 2 days treated as provisional. |
| `bing.*` with `query=`/`page=` | week | Weekly buckets from `GetQueryStats` / `GetPageStats`. |
| `bing.crawl2xx/301/302/4xx/5xx`, `crawlErrors`, `inIndex`, `blockedByRobots`, `malwarePages` | day | Bing crawl stats (~6 months). Crawl status codes Google doesn't expose by API. |
| `clarity.sessions`, `botSessions`, `botSharePct`, `distinctUsers`, `pagesPerSession` | rolling24h | Clarity traffic for the 24h before the snapshot (UTC). 48h/72h windows after missed days are stored separately and never compared to 24h rows. |
| `clarity.rageClickPct`, `deadClickPct`, `errorClickPct`, `scriptErrorPct`, `quickbackPct`, `excessiveScrollPct` | rolling24h | Percent of sessions with that behavior. `page=` rows localize it. The only client-side UX-friction signals in the stack. |
| `clarity.scrollDepthPct`, `activeTime`, `totalTime` | rolling24h | Engagement. Time units as Clarity reports them. |
| `crux.lcpP75`, `inpP75`, `clsP75`, `fcpP75`, `ttfbP75` | week | Field p75 over a 28-day window, phone origin for the total. Good ≤ 2500 ms LCP, ≤ 200 ms INP, ≤ 0.1 CLS. |
| `probe.up`, `ttfbMs`, `tlsDaysLeft`, `sitemapUrls` | day | Live probe (one value per day, last run wins). |
| `cloudflare.requests`, `pageViews`, `uniques`, `threats`, `cacheRatio`, `status4xx`, `status5xx` | day | Cloudflare edge analytics, only if the site is proxied. |
| `cloud_monitoring.responses5xx`, `responses` (`status=`), `uptimeCheckPassed` | day | Cloud Monitoring queries (Firebase Hosting log metric, uptime checks). |
| `uptime.ratio24h` (`monitor=`) | day | UptimeRobot 24h uptime %. |
| `stripe.chargesSucceeded`, `chargesFailed`, `checkoutsStarted`, `checkoutsCompleted`, `subscriptionsCanceled`, `revenue` | day | Stripe, net of refunds for revenue; today provisional. |
| `sentry.errors` | day | Accepted error events for the project; today provisional. |

## Tier-specific usage ("$20 tier")

No GA4 event tracks tier usage yet. Don't infer it from page paths.
Recommend (P3) a custom event such as `tier_usage` with a `tier` parameter,
fired where tier-gated features are used.
