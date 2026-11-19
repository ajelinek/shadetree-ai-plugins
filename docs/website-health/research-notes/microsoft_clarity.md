# Microsoft Clarity: Programmatic Data Access (state as of 2026-11-19)

## Clarity Data Export API (project-live-insights): endpoint, auth, params, response, metrics

### Takeaway
There is one documented, token-authenticated REST endpoint for aggregate dashboard data: `GET https://www.clarity.ms/export-data/api/v1/project-live-insights`. It takes a Bearer JWT that a project admin generates per project. Parameters are `numOfDays` (1|2|3) and up to three `dimensionN` breakdowns. It returns a JSON array of `{metricName, information:[...]}` blocks. Field casing differs between the official sample and real-world clients, so parse keys case-insensitively.

### Cited Findings
- **Endpoint:** `GET https://www.clarity.ms/export-data/api/v1/project-live-insights`. It "fetches the dashboard data structured in JSON format over a specified date range and can break down insights by up to three dimensions." The doc page was last updated 2025-12-05 (ms.date 2024-11-26). — [Clarity Data Export API](https://learn.microsoft.com/en-us/clarity/setup-and-installation/clarity-data-export-api)
- **Auth header:** `Authorization: Bearer <Your_API_Token>`. The token is a JWT. The doc samples also send `Content-Type: application/json`. — [Data Export API](https://learn.microsoft.com/en-us/clarity/setup-and-installation/clarity-data-export-api)
- **Token generation:**
  - Path: Clarity project > Settings > Data Export > Generate new API token.
  - "Only project admins can manage access tokens."
  - Token name rules: 4–32 characters; A-Z, a-z, 0-9, `-`, `_` and `.` allowed; no spaces or `@#$%&*!`; unique within the project.
  - Microsoft advises replacing the token promptly when a user with access is removed from the project.
  - Source: [Data Export API](https://learn.microsoft.com/en-us/clarity/setup-and-installation/clarity-data-export-api)
- **Scope:** the docs define no scopes. A token is bound to the project it was generated in. A 403 means the token is "not authorized for operation". — [Data Export API](https://learn.microsoft.com/en-us/clarity/setup-and-installation/clarity-data-export-api)
  - PostHog's production connector reads it the same way: "A Clarity token only ever grants access to the project it was generated in, so a 403 means the token belongs to another project." — [PostHog microsoft_clarity.py](https://github.com/PostHog/posthog/blob/master/products/warehouse_sources/sources/microsoft_clarity/microsoft_clarity.py)
- **Query params:**
  - `numOfDays`: 1, 2 or 3, meaning "the last 24, 48, or 72 hours" since the API call. It is a rolling window, not calendar days.
  - `dimension1`, `dimension2`, `dimension3`: optional breakdowns.
  - Source: [Data Export API](https://learn.microsoft.com/en-us/clarity/setup-and-installation/clarity-data-export-api)
- **Documented dimensions:** Browser, Device, Country/Region, OS, Source, Medium, Campaign, Channel, URL. — [Data Export API](https://learn.microsoft.com/en-us/clarity/setup-and-installation/clarity-data-export-api)
- **Documented metrics:** Scroll Depth, Engagement Time, Traffic, Popular Pages, Browser, Device, OS, Country/Region, Page Title, Referrer URL, Dead Click Count, Excessive Scroll, Rage Click Count, Quickback Click, Script Error Count, Error Click Count. — [Data Export API](https://learn.microsoft.com/en-us/clarity/setup-and-installation/clarity-data-export-api)
- **Timezone:** results are in UTC. — [Data Export API](https://learn.microsoft.com/en-us/clarity/setup-and-installation/clarity-data-export-api)
- **Official sample response** (Traffic with dimension1=OS):
  - Shape: `[{"metricName":"Traffic","information":[{"totalSessionCount":"9554","totalBotSessionCount":"8369","distantUserCount":"189733","PagesPerSessionPercentage":1.0931,"OS":"Other"}, ...]}]`.
  - Counts are strings and ratios are numbers.
  - A dimension appears as an extra key named after the dimension.
  - Microsoft notes that "additional metrics and dimensions may be included in the full API response."
  - Source: [Data Export API](https://learn.microsoft.com/en-us/clarity/setup-and-installation/clarity-data-export-api)
- **Field naming discrepancy:** the official sample uses `distantUserCount` and `PagesPerSessionPercentage`. Real clients use different spellings:
  - [pig-mesh/pig ClarityFetchTaskHandler.java](https://github.com/pig-mesh/pig/blob/master/pig-upms/pig-upms-biz/src/main/java/com/pig4cloud/pig/admin/handler/ClarityFetchTaskHandler.java) reads `distinctUserCount` and `pagesPerSessionPercentage`.
  - [5hirish/duct fetch.py](https://github.com/5hirish/duct/blob/main/backend/service/clarity/fetch.py) lowercases keys (`distinctusercount`) before lookup, which suggests casing is unreliable.
- **Full real-shaped response (no dimensions)**, from a project's mock. metricName values and per-metric fields:
  - **Friction metrics** use `{sessionsCount, sessionsWithMetricPercentage, sessionsWithoutMetricPercentage, pagesViews, subTotal}`. These are `DeadClickCount`, `ExcessiveScroll`, `RageClickCount`, `QuickbackClick`, `ScriptErrorCount` and `ErrorClickCount`.
  - `ScrollDepth` returns `{averageScrollDepth}`.
  - `Traffic` returns `{totalSessionCount, totalBotSessionCount, distinctUserCount, pagesPerSessionPercentage}`.
  - `EngagementTime` returns `{totalTime, activeTime}`, presumably in seconds.
  - `Browser`, `Device`, `OS`, `Country`, `PageTitle` and `ReferrerUrl` return lists of `{name, sessionsCount}`.
  - `PopularPages` returns a list of `{url, visitsCount}`.
  - Source: [cuentoneta clarity.mock.ts](https://github.com/cuentoneta/cuentoneta/blob/main/src/api/_mocks/clarity.mock.ts). This is community-sourced, not official.
- **Error codes:**
  - 401: missing, invalid or expired token.
  - 403: token not authorized.
  - 400: invalid parameters.
  - 429: "Exceeded daily limit".
  - Source: [Data Export API](https://learn.microsoft.com/en-us/clarity/setup-and-installation/clarity-data-export-api)

### Inferences
- A single no-dimension call returns every metric block at project level. That gives sessions, bot sessions, users, pages per session, scroll depth, engagement time, all six friction metrics, top-N browser/device/OS/country/page title/referrer, and popular pages. It is the best value per quota unit for a daily health check.
- A second call with `dimension1=URL` gives per-URL friction, which can pinpoint pages with rage clicks or script errors. The duct project uses exactly this "overall + URL" two-call budget ([duct fetch.py](https://github.com/5hirish/duct/blob/main/backend/service/clarity/fetch.py)).
- The parser should use case-insensitive key lookup, coerce string counts to int, and tolerate unknown metric blocks.
- "Device" values seen are Mobile, PC and Tablet. "OS" values include Android, Windows, IOS, MacOSX and Linux. These come from the community mock.

### Gaps
- The exact accepted string for the Country/Region dimension (`Country`, `Country/Region` or `CountryRegion`) is not stated. Test it empirically.
- No official JSON schema exists, and Microsoft does not document units for EngagementTime.
- Microsoft does not document token expiry or lifetime. 401 "expired token" implies tokens can expire.
- Microsoft does not document whether bot sessions are excluded from the friction metrics.

## Hard limits and their implications

### Takeaway
The limits are hard:
- 10 requests per project per day.
- Only the last 1–3 days (rolling 24/48/72 h).
- At most 3 dimensions per request.
- At most 1,000 rows per response, with no pagination.

History is impossible to backfill, so the skill must snapshot daily and store results itself.

### Cited Findings
- "Maximum of 10 API requests are allowed per project per day." — [Data Export API](https://learn.microsoft.com/en-us/clarity/setup-and-installation/clarity-data-export-api)
- "Data retrieval is confined to the previous 1 to 3 days." — [Data Export API](https://learn.microsoft.com/en-us/clarity/setup-and-installation/clarity-data-export-api)
- "Maximum of three dimensions can be passed in a single request." — [Data Export API](https://learn.microsoft.com/en-us/clarity/setup-and-installation/clarity-data-export-api)
- "The response is limited to 1,000 rows and can't be paginated." — [Data Export API](https://learn.microsoft.com/en-us/clarity/setup-and-installation/clarity-data-export-api)
- PostHog's connector works under the same constraints:
  - It treats the quota as a hard cap and does not retry a 429 that survives its backoff.
  - It notes that a credential-validation probe "still counts against the project's 10-requests/day quota".
  - It notes that a 429 at validation may mean "other tooling" exhausted the quota.
  - It states that repeated syncs are "the only way to accumulate history against this API".
  - Source: [PostHog microsoft_clarity.py](https://github.com/PostHog/posthog/blob/master/products/warehouse_sources/sources/microsoft_clarity/microsoft_clarity.py)

### Inferences
- **The quota is shared per project.** Every token, the MCP server in token mode, PostHog syncs and ad-hoc curl calls draw from the same 10 per day. The skill should budget 1–3 calls, record its own call count, and never retry on 429.
- **Run one `numOfDays=1` snapshot per day at a fixed UTC time.** Persisting it (for example `clarity/YYYY-MM-DD.json`) builds the time series. A numOfDays=1 window is "last 24 h from call time", not a calendar day, so a consistent schedule matters for comparability.
- **Recover a missed day with numOfDays=2 or 3.** It returns an aggregate over the window, not per-day rows, so the missing day cannot be separated out exactly. Mark that day as a gap.
- **The 1,000-row cap bites on high-cardinality breakdowns.** URL or 3-dimension cross products get truncated silently, so prefer single dimensions.

### Gaps
- Microsoft does not document when the daily quota resets. UTC midnight is likely but unconfirmed. The MCP server surfaces a `retry-after` header on 429 when present ([clarity-mcp-server projects/service.ts](https://github.com/microsoft/clarity-mcp-server/blob/main/src/projects/service.ts)), and that header could reveal the reset time.
- It is unconfirmed whether each metric block or each dimension row counts toward the 1,000-row cap.

## Newer Clarity APIs and features (2025–2026)

### Takeaway
The official MCP server (`@microsoft/clarity-mcp-server`) reached v3.0.0 on 2026-11-16.
- It now defaults to OAuth sign-in and is deprecating Data Export token auth.
- It talks to a separate, undocumented `https://clarity.microsoft.com/mcp/*` POST API. That API covers natural-language dashboard queries, session-recording lists (up to 250), AI Visibility (citations, bot activity, topic insights) and docs search.
- No public REST APIs exist for heatmap export, funnels, Copilot insights or a session list outside that MCP channel.
- The client-side JS API (identify/set/event/upgrade/consentv2) is for instrumentation only, not data retrieval.

### Cited Findings
- **Releases:** npm `@microsoft/clarity-mcp-server` versions are 1.0.0 (2025-04-30), 1.0.5 (2025-06-12), 2.0.0 (2025-09-14), 2.0.1 (2025-10-28) and 3.0.0 (2026-11-16). — [npm registry](https://www.npmjs.com/package/@microsoft/clarity-mcp-server). Verified via `npm view` on 2026-11-19.
- **Repo:** MIT license, about 144 stars, last push 2026-11-17. Recent commits are "Add AI Visibility capabilities" and "support-oauth" (PR #33). — [GitHub microsoft/clarity-mcp-server](https://github.com/microsoft/clarity-mcp-server)
- **v3 auth:**
  - Requires a Clarity account with admin or member access to at least one project.
  - Sign-in is a browser OAuth flow with a localhost callback.
  - "Data Export API token authentication for the MCP server is being deprecated." Migration means removing `--clarity_api_token` and `CLARITY_API_TOKEN`.
  - Source: [clarity-mcp-server README](https://github.com/microsoft/clarity-mcp-server/blob/main/README.md)
  - OAuth endpoints are `https://clarity.microsoft.com/oauth/authorize`, `/oauth/token` and `/oauth/revoke`, with public client id `clarity-mcp-client`. — [src/config.ts](https://github.com/microsoft/clarity-mcp-server/blob/main/src/config.ts)
- **Backend endpoints:** the server calls `https://clarity.microsoft.com/mcp{path}` with JSON POST. Paths:
  - `/dashboard/query` (natural-language analytics)
  - `/recordings/sample`
  - `/documentation/query`
  - `/projects/list`
  - `/citations/{overview,queries,topics,pages,trends/metrics,trends/items}`
  - `/bot-activity/{overview,crawlers,paths,distribution,trends/metrics,trends/items,trends/crawlers,scrape-to-referral,cdn-providers}`
  - `/topic-insights/{constraints,list,report,status,create,regenerate,delete}`
  - In legacy token mode the same endpoints take `Authorization: Bearer <Data Export token>`.
  - Sources: [src/features/*/tools.ts](https://github.com/microsoft/clarity-mcp-server/tree/main/src/features), [src/mcp/client.ts](https://github.com/microsoft/clarity-mcp-server/blob/main/src/mcp/client.ts)
- **MCP rate limit:** a 429 from the MCP API is reported as "The daily Clarity MCP request limit was reached for this project". Microsoft does not document the number. — [src/projects/service.ts](https://github.com/microsoft/clarity-mcp-server/blob/main/src/projects/service.ts)
- **Tools (v3):**
  - `query-analytics-dashboard` takes a natural-language query. It covers users, sessions, pages, devices, geography, smart events, Core Web Vitals (LCP/FID/CLS), JS errors, quickbacks, dead/rage clicks and session duration. Arbitrary time ranges are possible, e.g. "last 7 days" or "January 2024".
  - `list-session-recordings`
  - The AI Visibility tools: citations (verified domain required), bot activity (connected CDN required) and topic insights.
  - `query-documentation-resources`
  - Sources: [README](https://github.com/microsoft/clarity-mcp-server/blob/main/README.md), [analytics/instructions.ts](https://github.com/microsoft/clarity-mcp-server/blob/main/src/features/analytics/instructions.ts)
- **Recording list details:**
  - Sample count defaults to 100, max 250.
  - The date filter is required, in UTC ISO 8601; the default window is the last 2 days.
  - Filters include URL, device, browser, OS, country, city and smart events (a list of auto events such as Purchase, ContactUs, SubmitForm, SignUp, Login and OutboundClick).
  - Sources: [recordings/schemas.ts](https://github.com/microsoft/clarity-mcp-server/blob/main/src/features/recordings/schemas.ts), [recordings/tools.ts](https://github.com/microsoft/clarity-mcp-server/blob/main/src/features/recordings/tools.ts)
- **Other MCP row caps:** citation and bot-activity list tools cap at 100 rows with skip/limit paging and at most 5 trend values. — [citations/schemas.ts](https://github.com/microsoft/clarity-mcp-server/blob/main/src/features/citations/schemas.ts), [bot-activity/schemas.ts](https://github.com/microsoft/clarity-mcp-server/blob/main/src/features/bot-activity/schemas.ts)
- **Claude connector:** a Microsoft Clarity connector is listed in Claude's directory, published by Microsoft and added October 2025. It exposes list-session-recordings, query-documentation-data and query-analytics-data. — [Claude connectors: Microsoft Clarity](https://claude.com/connectors/microsoft-clarity)
- **Client JS API:**
  - `window.clarity("identify", custom-id, [custom-session-id], [custom-page-id], [friendly-name])`
  - `window.clarity("set", key, value|[values])`, with no limit on custom tags
  - `window.clarity("event", name)`, where custom events appear alongside Smart events in Filters, Dashboard and Recordings
  - `window.clarity("upgrade", reason)`, which prioritizes recording
  - HTML attributes `data-clarity-mask` and `data-clarity-unmask`
  - Clarity keeps up to 100,000 recordings per project per day and samples beyond that.
  - The Clarity ID is the only client "key".
  - Source: [Clarity client API](https://learn.microsoft.com/en-us/clarity/setup-and-installation/clarity-api)

### Inferences
- **The MCP `/dashboard/query` endpoint is richer than the export API.** It offers arbitrary date ranges (including 7 days and more), Web Vitals and smart events. However, it is natural-language in and free-form out, undocumented, and now aimed at interactive OAuth. That makes it a poor fit for a deterministic, unattended daily cron.
- **OAuth on a headless cron needs a refresh-token store, and the deprecation is a risk.** Driving the MCP from a headless cron would require persisting the refresh token. Using it with a Data Export token works today, but Microsoft is deprecating that path.
- **Custom `clarity('event')` calls are worth adding on key flows.** If the site's code adds them (e.g. signup or login success), the MCP dashboard query and recording filters can surface them. The export API does not list events as a metric.

### Gaps
- I found no official REST documentation for `clarity.microsoft.com/mcp/*`, and its daily quota is not published.
- I found no API for heatmap export, funnels, Copilot or "insights" summaries, or full session or event-level export. Clarity's GA4 integration pushes data into the GA4 UI. I did not find documentation of it as a data-access path in this research.

## Consent requirements and effect on data

### Takeaway
Since 2025-10-31, Clarity requires a consent signal for visits from the EEA, UK and CH.
- **Without one:** Clarity runs cookieless with a unique ID per page view. Sessions do not stitch across pages, and recordings, heatmaps and funnels may be limited or unavailable.
- **Effect on metrics:** EEA, UK and CH traffic will look like many single-page "sessions". Users and pages per session become unreliable for that segment.

### Cited Findings
- "Starting October 31, 2025, Clarity begins enforcing consent signal requirements for page visits originating from the European Economic Area (EEA), United Kingdom (UK), and Switzerland (CH)." — [Consent API v2](https://learn.microsoft.com/en-us/clarity/setup-and-installation/clarity-consent-api-v2)
- **Syntax:** `window.clarity('consentv2', {ad_Storage: "granted|denied", analytics_Storage: "granted|denied"})`. Both parameters are required.
  - The v1 `clarity('consent')` call "is planned for deprecation and should no longer be used".
  - `clarity('consent', false)` erases cookies.
  - Source: [Consent API v2](https://learn.microsoft.com/en-us/clarity/setup-and-installation/clarity-consent-api-v2)
- **Without consent:** "If consent is not granted, Clarity assigns a unique ID per page view and does not use cookies to persist session data."
  - Rejection deletes existing cookies, ends the session, and restarts tracking in no-consent mode.
  - Granting consent "enables session tracking across multiple pages".
  - Source: [Consent API v2](https://learn.microsoft.com/en-us/clarity/setup-and-installation/clarity-consent-api-v2)
- **Feature impact:** Clarity won't place cookies without a consent signal, and "session recordings, heatmaps, and funnel tracking may be limited, incomplete, or unavailable".
  - Consent mode is "automatically enabled" for EEA/UK/CH users, but owners should verify the setting per project.
  - Supported signal routes are the Consent API, supported CMPs, platform integrations, and Google Consent Mode.
  - Source: [Clarity blog: Cookie Consent Update](https://clarity.microsoft.com/blog/clarity-cookie-consent-update/)
- **Source conflict:** the blog says Clarity "won't collect analytics data" without consent, while the API doc describes no-consent mode with limited tracking. — [Clarity blog](https://clarity.microsoft.com/blog/clarity-cookie-consent-update/) vs [Consent API v2](https://learn.microsoft.com/en-us/clarity/setup-and-installation/clarity-consent-api-v2)
- **Google Consent Mode:** Clarity honors GCM signals (ad_storage, analytics_storage). Consent defaults to denied until updated and is valid for up to 9 months. — [Consent management](https://learn.microsoft.com/en-us/clarity/setup-and-installation/consent-management) (via search summary; not fetched in full)

### Inferences
- **Compare week over week, not across the 2025-10-31 boundary.** A sudden drop in pages per session or users, or a rise in sessions, for European traffic after that date is likely a consent artifact, not a site regression.
- **The site should call consentv2 (or GCM) from its CMP.** The health check could flag low pages per session from EEA countries as a "consent signal missing" heuristic.

### Gaps
- Microsoft does not quantify how no-consent page-view-level IDs affect the export API's `distinctUserCount` and `totalSessionCount`.

## Existing CLIs, packages, and tools wrapping the export API

### Takeaway
- No official CLI or SDK exists for the export API.
- The official MCP server is the only Microsoft tool, and it now steers away from the export token.
- Third-party options are thin wrappers of mixed maturity. Notable ones are the PyPI `clarity-api` (Knuckles-Team, 17 releases, latest 2026-11-16), PostHog's warehouse source, and Pipedream and Nango integrations.
- The API surface is tiny (one GET), so wrappers add little.

### Cited Findings
- **`@microsoft/clarity-mcp-server` 3.0.0** is official and MIT-licensed. It is an MCP server, not a CLI, and needs Node ≥16. — [npm](https://www.npmjs.com/package/@microsoft/clarity-mcp-server), [README](https://github.com/microsoft/clarity-mcp-server/blob/main/README.md)
- **PyPI `clarity-api` 3.4.0** (latest upload 2026-11-16, 17 releases) describes itself as "Microsoft Clarity API + MCP Server + A2A Server", "a typed, action-routed connector for the Microsoft Clarity Data Export API". It is built on `scion-sdk` and FastMCP, from the Knuckles-Team GitHub org. — [PyPI clarity-api](https://pypi.org/project/clarity-api/)
- **PostHog** ships a Microsoft Clarity warehouse source that calls `project-live-insights` and appends snapshot rows per sync. — [PostHog source](https://github.com/PostHog/posthog/tree/master/products/warehouse_sources/sources/microsoft_clarity)
- **Pipedream and Nango:** Pipedream has a `microsoft_clarity` app component, and Nango documents a Microsoft Clarity integration. — [Pipedream component](https://github.com/PipedreamHQ/pipedream/blob/master/components/microsoft_clarity/microsoft_clarity.app.mjs), [Nango docs](https://github.com/NangoHQ/nango/blob/master/docs/api-integrations/microsoft-clarity.mdx)
- **Another MCP server:** a third-party `@urdigital/mcp-server-clarity` MCP server also exists under a similar name. — [mcpservers.org listing](https://mcpservers.org/vi/servers/github-com-urdigitalau-mcp-integrations-tree-main-packages-clarity)
- **Packages that are not export clients:** `@microsoft/clarity`, `clarity-js` and `react-microsoft-clarity` are client-side tracking libraries. — npm search, 2026-11-19 ([npm @microsoft/clarity](https://www.npmjs.com/package/@microsoft/clarity))

### Inferences
- The third-party Python package pulls in a framework (scion-sdk, FastMCP, A2A), which is heavy for one GET. PostHog and Pipedream are platform-bound.

### Gaps
- I did not assess `clarity-api`'s GitHub stars or test coverage; its README badges were not resolvable from PyPI metadata.

## Recommendation: self-implement vs depend on MCP or third-party

### Takeaway
Self-implement a small stdlib Python script, using `urllib.request` and `json`, against `project-live-insights`. Do not depend on the MCP server or third-party packages for the daily check.

### Cited Findings
- The API is a single GET with a Bearer token and three optional query params. The official doc's own Python sample is about 10 lines. — [Data Export API](https://learn.microsoft.com/en-us/clarity/setup-and-installation/clarity-data-export-api)
- MCP token auth is being deprecated in favour of interactive browser OAuth. — [clarity-mcp-server README](https://github.com/microsoft/clarity-mcp-server/blob/main/README.md)
- The quota is 10 per project per day and is shared. — [Data Export API](https://learn.microsoft.com/en-us/clarity/setup-and-installation/clarity-data-export-api)

### Inferences
Suggested design:
1. **Configuration.** Read `CLARITY_API_TOKEN`, one token per project, from env or the secrets file.
2. **Daily calls.** Make one call with `numOfDays=1` and no dimension. Optionally make a second call with `dimension1=URL` for per-page friction. That is at most 2 of the 10 daily calls.
3. **Storage and history.** Write raw JSON to a dated snapshot file in UTC. Build the time series from stored snapshots, because the API cannot backfill.
4. **Parsing.** Normalize with case-insensitive keys and int coercion of string counts. Ignore unknown metric blocks.
5. **Errors and quota.**
   - On 429, do not retry; record it as "quota exhausted (shared with other tools?)".
   - On 401, report that the token expired or was revoked: regenerate it in Settings > Data Export, which requires a project admin.
   - On 403, report that the token belongs to the wrong project.
   - Keep a local call counter per UTC day, and refuse to exceed a budget of about 3 calls.
6. **Health signals.** Report sessions versus the 7-day median, the bot session share, rage, dead, error-click and script-error percentages versus baseline, quickback percentage, scroll depth and active time.
   - Flag known biases: the 24 h window is rolling, not a calendar day; EEA consent no-cookie mode deflates pages per session.
7. **Optional, manual only.** The MCP server (OAuth) is still useful for interactive drill-down: recordings with JS errors, Web Vitals, 7-day or longer ranges, and AI-crawler activity. Keep it out of the automated path.

### Gaps
- None material for the recommendation. Validate field casing and the Country dimension string with one live call during implementation.
