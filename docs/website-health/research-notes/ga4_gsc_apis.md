# GA4 Data API and Google Search Console API: auth, endpoints, quotas, lag, and the Bin-Huang CLIs (as of 2026-11-19)

## GA4 Data API v1beta and Admin API: auth, quotas, sampling/thresholding, freshness, health metrics, 2024-2026 changes

### Takeaway
GA4 Data API quotas are token-based per property (standard: 200k tokens/day, 40k/hour, 14k per project per property per hour, 10 concurrent). A daily health check that makes about 5-20 simple reports costs well under 1% of that. The real constraints are processing lag (daily data about 12h on standard, with revisions for 24-48h and late hits up to 7 days) and response-quality flags: `subjectToThresholding`, `samplingMetadatas`, `dataLossFromOtherRow`, and the new `dataTruncationReasons`. Use `keyEvents`, not the deprecated `conversions`.

### Cited Findings
**Quotas (Data API v1, standard / Analytics 360)**
- Core tokens per property per day: 200,000 / 2,000,000. Per hour: 40,000 / 400,000. Per project per property per hour: 14,000 / 140,000. Core concurrent requests per property: 10 / 50. Core server errors per project per property per hour: 10 / 50. — [GA4 Data API quotas](https://developers.google.com/analytics/devguides/reporting/data/v1/quotas)
- Realtime and Funnel have their own buckets with the same numbers (200k/day, 40k/hour, 14k per project per property per hour, 10 concurrent). — [GA4 Data API quotas](https://developers.google.com/analytics/devguides/reporting/data/v1/quotas)
- New Chat tokens bucket: 3,750,000/day and 500,000/hour per property, the same on standard and 360. — [GA4 Data API quotas](https://developers.google.com/analytics/devguides/reporting/data/v1/quotas)
- "Potentially thresholded requests" are capped at 120 per property per hour. The cap applies to requests that use `userAgeBracket`, `userGender`, `brandingInterest`, `audienceId`, or `audienceName`. None of the core health dimensions trigger it. — [GA4 Data API quotas](https://developers.google.com/analytics/devguides/reporting/data/v1/quotas)
- Most requests cost 10 tokens or fewer, and the example simple query cost 1 token. Cost depends on row count, the number of dimensions and metrics, filter complexity, date-range length, high-cardinality dimensions (for example `pagePath`), and property volume. `"returnPropertyQuota": true` returns tokens consumed and remaining. — [GA4 Data API quotas](https://developers.google.com/analytics/devguides/reporting/data/v1/quotas)
- `batchRunReports` holds up to 5 reports per call, but each report counts individually toward token and concurrency quotas. 500/503 errors count against the server-error quota, and once that quota is exhausted, all requests from the project to the property are blocked. Daily quotas reset at midnight Pacific. Hourly quotas refresh within an hour, not necessarily on the hour. — [GA4 Data API quotas](https://developers.google.com/analytics/devguides/reporting/data/v1/quotas)
- 2024-06-28: new quota of 10,000 client errors per project per property per 15 minutes. Exceeding it temporarily blocks the property. — [Data API changelog](https://developers.google.com/analytics/devguides/reporting/data/v1/changelog)
- 2024-09-18: `properties.getPropertyQuotasSnapshot` added to view current quotas by category. — [Data API changelog](https://developers.google.com/analytics/devguides/reporting/data/v1/changelog)

**Freshness / processing lag**
- Realtime: "typically a few minutes", with limited dimensions and metrics. Intraday: 2-6 hours on standard, about 1 hour on 360. Daily: 12 hours (Standard and Premium Normal), 18 hours (Premium Large), 24+ hours (Premium XLarge). Property size tiers are by events over the prior 31 days: Normal is under 25B, Large is 25B+, XLarge is 250B+. — [GA4 data freshness (Analytics Help)](https://support.google.com/analytics/answer/11198161)
- Overall processing "can take 24-48 hours" and report data may change during that time. Some data can arrive up to 7 days after collection. — [GA4 data freshness](https://support.google.com/analytics/answer/11198161)
- Recent data can change between retrievals, so reports pulled minutes apart may differ. — [Reporting data expectations](https://developers.google.com/analytics/devguides/reporting/data/v1/reporting-data-expectations)

**Sampling / thresholding / (other)**
- `subjectToThresholding` = true means rows below minimum user thresholds may be withheld. A report can be flagged even when no rows are actually missing. Thresholding is more common with high-cardinality or custom dimensions. — [Reporting data expectations](https://developers.google.com/analytics/devguides/reporting/data/v1/reporting-data-expectations)
- `samplingMetadatas` has one entry per date range (events read, total sampling space) and is undefined when results are not sampled. `dataLossFromOtherRow` flags data rolled into `(other)`. `(other)` is "more common in reports that include dimensions with more than 500 unique values per day." Adding dimensions can change metric totals. — [Reporting data expectations](https://developers.google.com/analytics/devguides/reporting/data/v1/reporting-data-expectations); [ResponseMetaData v1beta](https://developers.google.com/analytics/devguides/reporting/data/v1/rest/v1beta/ResponseMetaData)
- `samplingLevel`, including `UNSAMPLED` on 360 with up to 1B events, is available only on the async report-task method (v1alpha `runReportTask` / `reportTasks`), not on v1beta `runReport`. — [Data API changelog](https://developers.google.com/analytics/devguides/reporting/data/v1/changelog), 2024-10-15 and 2024-05-08 entries

**Changes 2024-2026 (flag for implementation)**
- DEPRECATION (2024-05-06): conversions became key events. `isConversionEvent` was replaced by `isKeyEvent`, `conversions` by `keyEvents`, `sessionConversionRate` by `sessionKeyEventRate`, `userConversionRate` by `userKeyEventRate`, `purchaserConversionRate` by `purchaserRate`, `firstTimePurchaserConversionRate` by `firstTimePurchaserRate`, and `advertiserAdCostPerConversion` by `advertiserAdCostPerKeyEvent`. `getMetadata` exposes `deprecatedApiNames`. These names are deprecated, not removed. — [Data API changelog](https://developers.google.com/analytics/devguides/reporting/data/v1/changelog)
- 2024-03-25: added `sessionPrimaryChannelGroup`, `primaryChannelGroup`, and `firstUserPrimaryChannelGroup`, plus manual traffic-source dimensions. — [changelog](https://developers.google.com/analytics/devguides/reporting/data/v1/changelog)
- 2024-05-14: `comparisons` added to v1beta core reporting. 2024-10-20: `EmptyFilter`. — [changelog](https://developers.google.com/analytics/devguides/reporting/data/v1/changelog)
- 2026-04-23 (v1alpha): conversion reporting. `runReport` takes a `ConversionSpec` (action IDs, attribution model `DATA_DRIVEN`/`LAST_CLICK`), with a new `Section` in metadata. It may not be available for every property. — [changelog](https://developers.google.com/analytics/devguides/reporting/data/v1/changelog)
- 2026-09-14: `dataTruncationReasons` added to `ResponseMetaData` in v1beta and v1alpha. It lists the truncation type, a message, and affected dates. — [changelog](https://developers.google.com/analytics/devguides/reporting/data/v1/changelog)
- 2026-09-14 (v1alpha): `properties.chat` handles natural-language querying, uses the new scope `analytics.chatbot.read`, and is AI-based and "may show inaccurate information." It is not suitable for deterministic health checks. — [changelog](https://developers.google.com/analytics/devguides/reporting/data/v1/changelog)

**Admin API (listing properties / key events)**
- `GET /v1beta/accountSummaries` lists accounts and properties. `GET /v1beta/{parent=properties/*}/keyEvents` lists key events. `dataStreams` and `dataRetentionSettings` are in v1beta. `reportingDataAnnotations` is v1alpha only. DEPRECATION: the whole `conversionEvents` resource is deprecated in v1beta and v1alpha, so use `keyEvents`. — [Admin API REST reference](https://developers.google.com/analytics/devguides/config/admin/v1/rest)

**Auth**
- The read scope is `https://www.googleapis.com/auth/analytics.readonly`. Writes need `analytics.edit`. — [google-analytics-mcp README](https://github.com/googleanalytics/google-analytics-mcp); [Bin-Huang/google-analytics-cli README](https://github.com/Bin-Huang/google-analytics-cli)
- Service-account path: enable `analyticsdata.googleapis.com` and `analyticsadmin.googleapis.com`, create a JSON key, and add the SA's `client_email` in GA Admin > Account/Property access management. Viewer is enough for reporting. — [Bin-Huang/google-analytics-cli README](https://github.com/Bin-Huang/google-analytics-cli) (third-party, but consistent with Google setup flows)
- Gotcha: Google Cloud organizations created on or after 2024-05-03 block SA key creation by default (`constraints/iam.managed.disableServiceAccountKeyCreation`). — [Bin-Huang/google-analytics-cli README](https://github.com/Bin-Huang/google-analytics-cli), citing [Secure-by-default orgs](https://docs.cloud.google.com/resource-manager/docs/secure-by-default-organizations)
- Gotcha for ADC: `gcloud auth application-default login` without `--client-id-file` uses gcloud's own OAuth client, which Google "usually blocks" for Analytics scopes ("This app is blocked"). The workaround is your own Desktop OAuth client plus `--scopes=...analytics.readonly,...cloud-platform`, then `gcloud auth application-default set-quota-project`. External-audience apps in Testing status expire refresh tokens after 7 days. — [Bin-Huang/google-analytics-cli README](https://github.com/Bin-Huang/google-analytics-cli) (third-party; consistent with [Google OAuth2 docs](https://developers.google.com/identity/protocols/oauth2))
- Data API methods used by a health check: `properties.runReport`, `batchRunReports` (≤5), `runRealtimeReport`, `checkCompatibility`, and `getMetadata` (`properties/{id}/metadata`). All are wrapped by the Bin-Huang CLI (verified in source, `src/commands/reporting.ts`). — [Bin-Huang/google-analytics-cli source](https://github.com/Bin-Huang/google-analytics-cli)

### Inferences
- A daily check (for example yesterday vs. the prior 7/28 days for sessions, engagedSessions, engagementRate, keyEvents by sessionDefaultChannelGroup, deviceCategory, and top landingPage) should cost about 10-50 tokens a day, far below 200k. Quota matters only for multi-property agencies or tight polling loops. The 14k per project per property per hour cap is the one most likely to bite if several tools share a Cloud project.
- To avoid false alarms, compare "yesterday" only after about 12h past property midnight on standard properties, and treat the last 2 days as provisional, re-pulled the next day. Realtime is useful only as a "tag is firing" liveness check (activeUsers > 0 in the last 30 minutes).
- `landingPage` (or `landingPagePlusQueryString`) is high cardinality, so expect `(other)` and thresholding flags. Limit rows and order by sessions. Each run should log `subjectToThresholding`, `samplingMetadatas`, `dataLossFromOtherRow`, and `dataTruncationReasons` and downgrade alert confidence when they are set.
- Prefer `sessionDefaultChannelGroup` for comparability with the GA UI defaults. `sessionPrimaryChannelGroup` exists if the property uses custom channel groups.

### Gaps
- I did not fetch the Data API dimensions/metrics schema page this session. The exact API names `engagedSessions`, `engagementRate`, `landingPage`, `deviceCategory`, and `sessionDefaultChannelGroup` come from prior knowledge and the CLI's passthrough, not a fresh fetch. Verify them via `getMetadata` at runtime.
- No 2025-dated Data API changelog entries were found, which is unusual. The changelog fetch returned none, possibly because of truncation.
- Whether v1beta `runReport` can be sampled on standard properties was not confirmed. Docs only say `samplingMetadatas` appears when sampling occurs.

## Google Search Console API: searchanalytics.query, URL Inspection, sitemaps/sites, auth, lag, limits, 2025-2026 changes

### Takeaway
`searchanalytics.query` now supports an `hour` dimension (`dataState=hourly_all`, about 10 days back), `dataState=all` for fresh data, `type=webMultimodal`, `brandedClassification` (eligible properties only, data from 2026-02-21), and `filterLists` for multi-country/device. Final data lags about 2-3 days. Load limits (1,200 QPM per site and per user, plus 10-minute and daily "load" quotas) are generous for daily checks. URL Inspection allows 2,000 calls/day and 600/min per property, which is the binding constraint for per-URL index checks.

### Cited Findings
**searchanalytics.query**
- Group-by dimensions: `country`, `device`, `page`, `query`, `searchAppearance`, `brandedClassification`, plus `date` and `hour`. — [searchanalytics.query reference](https://developers.google.com/webmaster-tools/v1/searchanalytics/query)
- `type`: `web` (default), `image`, `video`, `news`, `discover`, `googleNews`, `webMultimodal`. DEPRECATION: `searchType` is deprecated in favor of `type`. — [searchanalytics.query reference](https://developers.google.com/webmaster-tools/v1/searchanalytics/query)
- `dataState`: `final` (default, finalized only), `all` (includes fresh data), `hourly_all` (hourly breakdown, partial; use with `hour`). Response `metadata.first_incomplete_date` is returned when grouping by date with `all`, and `first_incomplete_hour` when grouping by hour with `hourly_all`. Times are America/Los_Angeles. — [searchanalytics.query reference](https://developers.google.com/webmaster-tools/v1/searchanalytics/query)
- `aggregationType`: `auto`, `byPage`, `byProperty`, `byNewsShowcasePanel`. `byProperty` is not allowed with a page dimension or filter, or for discover/googleNews. — [reference](https://developers.google.com/webmaster-tools/v1/searchanalytics/query)
- `rowLimit` is 1-25,000 (default 1,000), and you page with `startRow`. The API returns top rows and doesn't guarantee all rows. Filter groups support only `and`. Operators: `contains`, `equals`, `notContains`, `notEquals`, `includingRegex`, `excludingRegex` (RE2). Expressions can be up to 4,096 chars. `filterLists` is allowed only for `country` and `device`, and you can't filter the same dimension through both `filters` and `filterLists`. — [reference](https://developers.google.com/webmaster-tools/v1/searchanalytics/query)
- `brandedClassification` supports only `equals`, can't be combined with a `query` filter, and has data starting 2026-02-21. — [reference](https://developers.google.com/webmaster-tools/v1/searchanalytics/query)
- Response rows hold `keys`, `clicks`, `impressions`, `ctr` (0-1), and `position`. Scopes: `webmasters.readonly` or `webmasters`. — [reference](https://developers.google.com/webmaster-tools/v1/searchanalytics/query)
- The API "exposes a maximum of 50K rows of data per day per search type," sorted by clicks. To get everything, query one day at a time per `type` and page by 25,000 until 0 rows. When grouping by page or query, "our system may drop some data." — [Getting all your data](https://developers.google.com/webmaster-tools/v1/how-tos/all-your-data)
- Data lag: "Data is typically available after 2-3 days." To find the latest available date, query grouped by date for the past 10 days. — [Getting all your data](https://developers.google.com/webmaster-tools/v1/how-tos/all-your-data)

**Limits**
- Search Analytics: 1,200 QPM per site, 1,200 QPM per user, and 30,000,000 QPD / 40,000 QPM per project. A separate "load" quota has a 10-minute short-term window (if exceeded, wait 15 minutes) and a 1-day long-term window. To reduce load, avoid page/query grouping and filtering, shorten date ranges, and don't re-run identical queries. — [Search Console API usage limits](https://developers.google.com/webmaster-tools/limits)
- URL Inspection: 2,000 QPD and 600 QPM per site, and 10,000,000 QPD / 15,000 QPM per project. — [usage limits](https://developers.google.com/webmaster-tools/limits)
- All other resources (sites, sitemaps): 20 QPS and 200 QPM per user, and 100,000,000 QPD per project. — [usage limits](https://developers.google.com/webmaster-tools/limits)

**URL Inspection API**
- `POST https://searchconsole.googleapis.com/v1/urlInspection/index:inspect` with `inspectionUrl`, `siteUrl`, and optional `languageCode`. URL-prefix properties need a trailing slash (`https://www.example.com/`). Domain properties use `sc-domain:example.com`. The result reflects the indexed version, and live URLs cannot be tested. — [urlInspection.index.inspect](https://developers.google.com/webmaster-tools/v1/urlInspection.index/inspect)

**2025-2026 changes**
- 2025-04-09: hourly data. Adds the `HOUR` dimension and `HOURLY_ALL` dataState, with up to 10 days of hourly data through the API (the UI shows 24h). — [Search Central blog: hourly data](https://developers.google.com/search/blog/2025/04/san-hourly-data); [Search Engine Land](https://searchengineland.com/google-search-analytics-api-gains-hourly-break-down-for-past-10-days-454167)
- 2026-06-03: Search Console added generative AI performance reports for impressions in AI Overviews, AI Mode, and Discover gen-AI features. They rolled out to all sites by 2026-08-31, and "this data is included in the overall performance report." The post does not say the separate AI breakdown is exposed via the API. — [Search Central blog: Gen AI performance reports](https://developers.google.com/search/blog/2026/06/gen-ai-performance-reports)
- 2026-09-24: multimodal search reporting in the UI (Lens, Circle to Search, image uploads). — [Search Central blog: web multimodal](https://developers.google.com/search/blog/2026/09/web-multimodal-in-sc)
- 2026-11-16: the API gained the branded queries filter (`brandedClassification`, eligible properties only; others get empty rows), `type=webMultimodal` (also in BigQuery bulk export), and `filterLists` for multi-country/multi-device. — [Search Central blog: Search Analytics API update](https://developers.google.com/search/blog/2026/11/search-analytics-api-update)
- A search snippet said Google would remove some structured-data types from Search Console and its API starting January 2026. I did not verify which types. — [Search Central blog index](https://developers.google.com/search/blog)

**Auth**
- Service account: add the SA `client_email` under Search Console Settings > Users and permissions with Restricted permission (read-only: sites, query, sitemaps, inspect). Only an Owner can add users. There is no "all properties at once" option. — [Bin-Huang/google-search-console-cli README](https://github.com/Bin-Huang/google-search-console-cli), citing [Google help 7687615](https://support.google.com/webmasters/answer/7687615)
- The API to enable is `searchconsole.googleapis.com`. Search analytics, sites, and sitemaps sit under the Webmasters v3 surface, and URL inspection under Search Console v1. — [Bin-Huang/google-search-console-cli README](https://github.com/Bin-Huang/google-search-console-cli)

### Inferences
- For a daily health check, pull `dataState=all` grouped by `date` over the last 10-14 days. Use `first_incomplete_date` to mark provisional days, and compare only finalized days (about 3 days back) for alerting. Use `hourly_all` only for "is search traffic collapsing right now" checks.
- AI Overviews / AI Mode impressions are folded into `web` totals, so a rise in impressions with flat clicks may reflect AI surfaces. The API cannot separate them (unconfirmed; see Gaps).
- With URL Inspection at 2,000/day per property, sample key URLs (for example the top 50 landing pages plus recently changed URLs) instead of inspecting every URL. Keep `siteUrl` exactly as GSC lists it (`sc-domain:` vs trailing-slash URL-prefix), or calls 403.
- Daily single-day queries for one site stay far below the 1,200 QPM and load quotas. The load quota matters only for page×query grouping over long ranges.
- BigQuery bulk export (which now includes webMultimodal) avoids the 50k rows/day cap. It is overkill for a lightweight daily check but the right path for large sites.

### Gaps
- Not confirmed whether the Gen AI (AI Overviews / AI Mode) breakdown is in the API, for example as a `searchAppearance` value. The blog post is silent.
- The `brandedClassification` enum values and eligibility criteria were not retrieved (the linked eligibility post was not fetched).
- `UrlInspectionResult` subfields (`indexStatusResult.verdict`, `coverageState`, `lastCrawlTime`, `googleCanonical`, and so on) and the status of `mobileUsabilityResult` were not confirmed this session.
- Which structured-data types are being removed starting January 2026 was not verified.

## Assessment of Bin-Huang/google-analytics-cli and Bin-Huang/google-search-console-cli, plus alternatives

### Takeaway
Both CLIs are small, recent (created March 2026), Apache-2.0, single-maintainer TypeScript wrappers over Google's official Node clients. They emit JSON and cover all needed endpoints: realtime, checkCompatibility, metadata, and key events for GA, and `hour`/`hourly_all`, URL inspection (incl. batch), sitemaps, and auto-pagination for GSC. They are low-adoption (39 and 24 stars, a few hundred npm downloads a month), and pulling `googleapis` and `@google-analytics/*` via `npx` adds a large transitive dependency tree, which is the main supply-chain cost.

### Cited Findings
- google-analytics-cli: 39 stars, 7 forks, 0 open issues, created 2026-03-13, last push 2026-10-19, Apache-2.0, TypeScript. npm v1.2.1 published 2026-10-14. 196 npm downloads 2026-10-20 to 11-18. — GitHub API and npm registry queried 2026-11-19: [repo](https://github.com/Bin-Huang/google-analytics-cli), [npm downloads API](https://api.npmjs.org/downloads/point/last-month/google-analytics-cli)
- google-search-console-cli: 24 stars, 5 forks, 1 open issue, created 2026-03-16, last push 2026-10-19, Apache-2.0. npm v1.1.2 published 2026-10-14. 322 downloads in the same window. — [repo](https://github.com/Bin-Huang/google-search-console-cli), [npm downloads API](https://api.npmjs.org/downloads/point/last-month/google-search-console-cli)
- Recent commits are mostly docs, onboarding, and small fixes ("fix/empty-profile", "fix/inspect-batch-truncated-output"). Single author, Benn Huang. — GitHub commits API, 2026-11-19
- Dependencies: the GA CLI uses `@google-analytics/admin ^9.0.1`, `@google-analytics/data ^5.2.1`, and `commander ^14.0.3` (node ≥20). The GSC CLI uses `googleapis ~178.0.0` and `commander` (node ≥18). Neither has preinstall/postinstall scripts. Versions use caret/tilde ranges, so an npx run can resolve new transitive versions. — package.json in each [repo](https://github.com/Bin-Huang/google-analytics-cli), checked 2026-11-19
- GA CLI commands: `accounts`, `properties`, `property`, `data-streams`, `key-events`, `custom-dims`, `metadata`, `check-compatibility`, `report`, `pivot-report`, `batch-report`, `realtime`, audience exports, `admin-custom-dimensions/metrics`, `data-retention`, `ads-links`, `annotations`, `change-history`, `access-report`, `profiles`. Supports `--return-property-quota`. Responses are passed through as JSON with "no transformation or aggregation." — [source](https://github.com/Bin-Huang/google-analytics-cli) and README
- GA CLI auth order: `--credentials` flag, then `--profile`/`GA_CLI_PROFILE` (`~/.config/google-analytics-cli/profiles/<name>.json`), then `GOOGLE_APPLICATION_CREDENTIALS`, then `~/.config/google-analytics-cli/credentials.json`, then gcloud ADC. — [README](https://github.com/Bin-Huang/google-analytics-cli)
- GSC CLI commands: `sites`, `site`, `site-add`, `site-remove`, `query`, `sitemaps`, `sitemap`, `sitemap-submit`, `sitemap-delete`, `inspect`, `inspect-batch`. `query` supports `--dimensions` (incl. `hour`), `--type` (help text lists web, image, video, news, discover, and googleNews but not `webMultimodal`, though the value appears to pass through), `--data-state all|final|hourly_all`, `--dimension-filter <json>`, `--aggregation-type`, `--row-limit`, `--start-row`, and `--all` (auto-paginates at 25k). There are no explicit `filterLists` or `brandedClassification` flags. — [src/commands/query.ts](https://github.com/Bin-Huang/google-search-console-cli)
- GSC CLI auth order: `--credentials`, then `GOOGLE_APPLICATION_CREDENTIALS`, then `~/.config/google-search-console-cli/credentials.json`, then gcloud ADC. — [README](https://github.com/Bin-Huang/google-search-console-cli)

**Alternatives**
- Official `googleanalytics/google-analytics-mcp`: about 3.8k stars, Apache-2.0, Python 3.10+, last push 2026-11-16, run via `pipx run analytics-mcp`. Tools: `get_account_summaries`, `get_property_details`, `list_key_events`, `list_google_ads_links`, `list_property_annotations`, `run_report`, `run_funnel_report`, `run_conversions_report`, `run_realtime_report`, `get_custom_dimensions_and_metrics`, and write tools gated by `--allow-write`. Auth is ADC with `analytics.readonly`, plus SA impersonation and OAuth modes. GA only, no GSC. — [GitHub](https://github.com/googleanalytics/google-analytics-mcp)
- GSC MCP servers are all community-maintained and low-adoption: surendranb/google-search-console-mcp (about 38 stars), AminForou/mcp-gsc (0.4.1 release in September 2026), sofianbettayeb/gsc-mcp-server (about 5), and others. No official Google GSC MCP was found. — [surendranb](https://github.com/surendranb/google-search-console-mcp), [aminforou README](https://raw.githubusercontent.com/aminforou/mcp-gsc/HEAD/README.md), [sofianbettayeb](https://github.com/sofianbettayeb/gsc-mcp-server). Star counts come from directory snapshots and may lag.
- The Google API Python client and Node `googleapis` / `@google-analytics/data` are the official libraries the CLIs themselves wrap. — [GSC CLI README](https://github.com/Bin-Huang/google-search-console-cli), [GA CLI README](https://github.com/Bin-Huang/google-analytics-cli)

### Inferences
- Maintenance risk: both CLIs are 8 months old with one maintainer and are already shipping new GSC features (hourly). They lag the 2026-11-16 API additions in flags but not in raw passthrough (`--dimension-filter` JSON). An abandoned repo would still keep working because they are thin passthroughs over stable APIs.
- Supply-chain risk: `npx skills add` plus `npx google-*-cli` run unpinned code from a single maintainer's npm account with credential-file access to analytics data. The main exposure is account or package takeover plus floating transitive ranges (`googleapis` is a very large package). Pinning exact versions (`npx google-analytics-cli@1.2.1`) or vendoring reduces it.
- The official analytics-mcp is the most trustworthy GA option but is an MCP server (Python, pipx), not a CLI. That suits interactive agents better than a deterministic scripted daily check, and it does not cover GSC.

### Gaps
- No npm provenance/attestation check was done, and maintainer 2FA status is unknown.
- I did not measure transitive dependency counts or install size.
- Current GitHub star counts for the GSC MCP alternatives were not verified directly.

## Recommendation: keep the third-party CLIs or self-implement stdlib scripts calling REST with a service-account JWT

### Takeaway
Self-implementing is cheap and attractive. A health check needs only about 6 REST calls (GA `runReport`/`batchRunReports`, `runRealtimeReport`, `getMetadata`, Admin `accountSummaries`/`keyEvents`, and GSC `searchanalytics.query`, `urlInspection`, `sitemaps.list`, `sites.list`), all plain JSON POST/GET with a Bearer token. The only nontrivial piece is RS256 JWT signing for the service-account token exchange, which Node does natively but Python's stdlib does not. Recommended: self-implement in Node (zero deps) or in Python with a single pinned dependency or an `openssl` subprocess for signing, and support an ADC/access-token fallback. Keep the Bin-Huang CLIs only as an optional documented fallback, version-pinned.

### Cited Findings
- All needed endpoints are documented REST: GA Data API quotas and methods ([quotas](https://developers.google.com/analytics/devguides/reporting/data/v1/quotas)), Admin `accountSummaries` and `keyEvents` ([Admin REST](https://developers.google.com/analytics/devguides/config/admin/v1/rest)), GSC `searchanalytics.query` ([ref](https://developers.google.com/webmaster-tools/v1/searchanalytics/query)), and URL inspection at `POST searchconsole.googleapis.com/v1/urlInspection/index:inspect` ([ref](https://developers.google.com/webmaster-tools/v1/urlInspection.index/inspect)).
- The CLIs pass responses through untransformed, so a self-implementation gives up no logic beyond auth, pagination (`--all`), and multi-profile handling. — [GA CLI README](https://github.com/Bin-Huang/google-analytics-cli), [GSC query.ts](https://github.com/Bin-Huang/google-search-console-cli)
- SA key creation is blocked by default in Google Cloud orgs created on or after 2024-05-03, and gcloud's default OAuth client is usually blocked for Analytics scopes. Auth must therefore support both an SA JSON key and a user OAuth/ADC token. — [GA CLI README](https://github.com/Bin-Huang/google-analytics-cli)

### Inferences
- Service-account flow (standard Google OAuth2 SA flow; [docs](https://developers.google.com/identity/protocols/oauth2/service-account), not re-fetched this session): build a JWT with header `{"alg":"RS256","typ":"JWT"}` and claims `iss`=client_email, `scope`=space-separated (`analytics.readonly` and `webmasters.readonly`), `aud`=`https://oauth2.googleapis.com/token`, `iat`, and `exp` ≤ iat+3600. Sign it with the private_key and POST `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=<jwt>` to get an access token valid about 1h. One SA can carry both scopes.
- Node: `crypto.createSign('RSA-SHA256')` plus global `fetch` (Node ≥18) make a zero-dependency implementation of about 150 lines feasible.
- Python: stdlib has `urllib`/`json` but no RSA signing. Options are (a) shelling out to `openssl dgst -sha256 -sign`, (b) one pinned dependency (`cryptography` or `google-auth`), or (c) accepting a bearer token from `gcloud auth application-default print-access-token`. The repo's existing email-domain-reputation scripts are Python, which favors (a) or (c) for stdlib purity.
- Fallback auth: also accept `GOOGLE_APPLICATION_CREDENTIALS` of type `authorized_user` (refresh_token grant to `oauth2.googleapis.com/token`, stdlib-only), which covers ADC users without a JWT. Send the `x-goog-user-project` header when using user credentials.
- Benefits of self-implementing: no unpinned npx execution, deterministic output schema tailored for cross-source comparison, built-in quality-flag handling (thresholding, `first_incomplete_date`), and immediate support for new fields (`filterLists`, `brandedClassification`, `webMultimodal`). Cost: owning about 300-500 lines plus tests, and tracking deprecations (conversions→keyEvents, `searchType`→`type`).
- When to keep the CLIs: if the skill's audience values `npx skills add` one-liners and broad ad-hoc GA admin coverage (audiences, change history) over determinism. In that case pin exact versions.

### Gaps
- Not checked: whether Google plans a v1 GA of the Data API or deprecation of v1beta (no such notice in the changelog).
- The SA JWT flow details were not re-fetched this session. They are stable, well-known Google OAuth2 behavior, but verify against the linked docs during implementation.
