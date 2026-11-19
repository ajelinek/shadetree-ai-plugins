# Bing Webmaster Tools API and IndexNow (as of 2026-11-19)

## Auth options and endpoints (API key vs OAuth 2.0; JSON vs XML)

### Takeaway
Two auth methods, both covering the same API: one per-user API key passed as the `apikey` query parameter (simplest for a headless daily script), or OAuth 2.0 bearer tokens (scopes `webmaster.read` / `webmaster.manage`). The live service is a WCF service at `https://ssl.bing.com/webmaster/api.svc/{json|pox}/{Method}`. JSON is the practical choice.

### Cited Findings
- Microsoft lists two access methods, "OAuth 2.0 [Recommended]" and "API Key". The API key is generated under BWT Settings > API Access > Generate API Key, and "Only one API key can be generated per user." — [Getting Access](https://learn.microsoft.com/en-us/bingwebmaster/getting-access)
- The key is per user, not per site, so one key works for all of that user's verified sites. Deleting the key and generating a new one breaks every app tied to the old key. — [Getting Access](https://learn.microsoft.com/en-us/bingwebmaster/getting-access)
- API-key request form: `GET https://ssl.bing.com/webmaster/api.svc/json/GetQueryStats?siteUrl=http://example.com&apikey=...`. The XML variant uses `/webmaster/api.svc/pox/...` ("plain old XML", not SOAP envelopes) with `Content-Type: application/xml`. — [GetQueryStats reference](https://learn.microsoft.com/en-us/dotnet/api/microsoft.bing.webmaster.api.interfaces.iwebmasterapi.getquerystats?view=bing-webmaster-dotnet)
- POST methods take a JSON body with `Content-Type: application/json; charset=utf-8`, e.g. `POST /webmaster/api.svc/json/SubmitUrlbatch?apikey=...` with body `{"siteUrl":..., "urlList":[...]}`. The response is `{"d":null}`. — [SubmitUrlBatch reference](https://learn.microsoft.com/en-us/dotnet/api/microsoft.bing.webmaster.api.interfaces.iwebmasterapi.submiturlbatch?view=bing-webmaster-dotnet)
- OAuth: register a client (Client Name + Redirect URI) under Settings > API Access > OAuth Client to get a client ID and secret. The flow is authorization code: `GET https://www.bing.com/webmasters/oauth/authorize?response_type=code&client_id=..&redirect_uri=..&scope=webmaster.manage`, then `POST https://www.bing.com/webmasters/oauth/token` (form-encoded). The code is valid for 5 minutes. — [OAuth 2.0 doc (updated 2026-08-07)](https://learn.microsoft.com/en-us/bingwebmaster/oauth2)
- Token response: `access_token`, `expires_in` (sample 3599 s, about 1 hour), `refresh_token`, `token_type: Bearer`. "Refresh tokens are valid until the user revokes access." The API is called with an `Authorization: Bearer <token>` header. The doc's example uses host `www.bing.com/webmaster/api.svc/json/SubmitUrl`. — [OAuth 2.0 doc](https://learn.microsoft.com/en-us/bingwebmaster/oauth2)
- Scopes: `Webmaster.read` (read-only) and `Webmaster.manage` (read and write). — [OAuth 2.0 doc](https://learn.microsoft.com/en-us/bingwebmaster/oauth2)
- Doc inconsistency: the refresh-token parameter table says `grant_type` = `authorization_code`, while the sample request uses `grant_type=refresh_token` and posts to `/webmasters/token`, not `/webmasters/oauth/token`. — [OAuth 2.0 doc](https://learn.microsoft.com/en-us/bingwebmaster/oauth2)
- Observed live behavior (probe on 2026-11-19): `GET https://ssl.bing.com/webmaster/api.svc/json/GetUserSites` with a bad or missing key returns HTTP 400 with body `{"ErrorCode":3,"Message":"ERROR!!! InvalidApiKey"}`. — direct probe of [ssl.bing.com endpoint](https://ssl.bing.com/webmaster/api.svc/json/GetUserSites)
- The .NET reference types (`ApiFault` FaultContract, `ServiceContract` namespace `http://schemas.datacontract.org/2004/07/Microsoft.Bing.Webmaster.Api`) confirm this is a WCF service. The interface docs were last updated 2023-11-14. — [IWebmasterApi](https://learn.microsoft.com/en-us/dotnet/api/microsoft.bing.webmaster.api.interfaces.iwebmasterapi?view=bing-webmaster-dotnet)

### Inferences
- For a daily unattended skill, the API key is far simpler: no redirect URI, no token store, no refresh. OAuth only matters for multi-tenant apps acting for other users. Store the key in an env var and never log full request URLs, because the key is in the query string.
- Use the `json` path. Callers must unwrap the top-level `"d"` (WCF "wrapped" response) and ignore the `__type` fields.
- Treat HTTP 400 with `ErrorCode` in the body as the error shape, and surface `ErrorCode`/`Message`.

### Gaps
- No current official doc found for a true SOAP (`/soap`) endpoint or a WSDL URL. Only `json` and `pox` are documented in samples. The bare `https://ssl.bing.com/webmaster/api.svc` returned 404 on probe.
- Full `ErrorCode` enumeration not retrieved (the `ApiErrorCode` enum page exists in the .NET reference but was not fetched).
- Not verified whether OAuth bearer calls also work on `ssl.bing.com`, or only on `www.bing.com` as in the doc example.

## Relevant methods and response shapes

### Takeaway
All the core health-check data is available via simple GETs with `siteUrl`: traffic (`GetRankAndTrafficStats`, `GetQueryStats`, `GetPageStats`, `GetQueryPageStats`, `GetPageQueryStats`, `GetQueryTrafficStats`), crawl (`GetCrawlStats`, `GetCrawlIssues`), index (`GetUrlInfo`, `GetUrlTrafficInfo`, `GetChildrenUrlInfo`), sitemaps (`GetFeeds`, `GetFeedDetails`), links (`GetLinkCounts`, `GetUrlLinks`), keywords (`GetKeyword`, `GetKeywordStats`, `GetRelatedKeywords`), sites (`GetUserSites`), and quotas. Most traffic methods take no date parameters and return whatever window Bing serves.

### Cited Findings
- Full method list on IWebmasterApi, including: GetUserSites; GetQueryStats ("traffic statistics for top queries"); GetPageStats ("top pages"); GetQueryPageStats(siteUrl, query); GetPageQueryStats(siteUrl, page); GetQueryPageDetailStats(siteUrl, query, page); GetQueryTrafficStats(siteUrl, query); GetRankAndTrafficStats(siteUrl); GetCrawlStats; GetCrawlIssues; GetCrawlSettings/SaveCrawlSettings; GetUrlInfo(siteUrl, url); GetUrlTrafficInfo; GetChildrenUrlInfo(siteUrl, url, page, FilterProperties); GetChildrenUrlTrafficInfo; GetFeeds; GetFeedDetails; SubmitFeed; RemoveFeed; GetLinkCounts(siteUrl, page); GetUrlLinks(siteUrl, link, page); GetKeyword(q, country, language, start, end); GetKeywordStats(q, country, language); GetRelatedKeywords(...); FetchUrl/GetFetchedUrls/GetFetchedUrlDetails; SubmitUrl; SubmitUrlBatch; GetUrlSubmissionQuota; SubmitContent; GetContentSubmissionQuota; GetBlockedUrls/AddBlockedUrl/RemoveBlockedUrl; GetQueryParameters; GetSiteMoves/SubmitSiteMove; GetSiteRoles/AddSiteRoles; AddSite/VerifySite/RemoveSite. — [IWebmasterApi](https://learn.microsoft.com/en-us/dotnet/api/microsoft.bing.webmaster.api.interfaces.iwebmasterapi?view=bing-webmaster-dotnet)
- Marked **Obsolete**: GetDeepLink, GetDeepLinkAlgoUrls, UpdateDeepLink. — [IWebmasterApi](https://learn.microsoft.com/en-us/dotnet/api/microsoft.bing.webmaster.api.interfaces.iwebmasterapi?view=bing-webmaster-dotnet)
- GetQueryStats JSON row: `{"__type":"QueryStats:#Microsoft.Bing.Webmaster.Api","AvgClickPosition":18,"AvgImpressionPosition":17,"Clicks":15,"Date":"/Date(1316156400000-0700)/","Impressions":100,"Query":"query"}`, wrapped in `{"d":[...]}`. Remark: "The data will be updated every week." — [GetQueryStats](https://learn.microsoft.com/en-us/dotnet/api/microsoft.bing.webmaster.api.interfaces.iwebmasterapi.getquerystats?view=bing-webmaster-dotnet)
- GetRankAndTrafficStats JSON row: `{"Clicks":15,"Date":"/Date(...)/","Impressions":100}`. Remark: "The data will be updated every day. The traffic data includes Impressions and Clicks from all verticals i.e. Web, Chat, News, Images, Videos and Knowledge Panel from March 24th, 2023 onwards." (Note: the doc's XML sample mistakenly shows a GetQueryTrafficStats URL.) — [GetRankAndTrafficStats](https://learn.microsoft.com/en-us/dotnet/api/microsoft.bing.webmaster.api.interfaces.iwebmasterapi.getrankandtrafficstats?view=bing-webmaster-dotnet)
- GetCrawlStats returns "List of crawl statistics for the last 6 months". Row fields: AllOtherCodes, BlockedByRobotsTxt, Code2xx, Code301, Code302, Code4xx, Code5xx, ContainsMalware, CrawlErrors, CrawledPages, Date, InIndex, InLinks. Remark: "updated every day." — [GetCrawlStats](https://learn.microsoft.com/en-us/dotnet/api/microsoft.bing.webmaster.api.interfaces.iwebmasterapi.getcrawlstats?view=bing-webmaster-dotnet)
- GetUrlInfo(siteUrl, url) returns a single object: AnchorCount, DiscoveryDate, DocumentSize, HttpStatus, IsPage, LastCrawledDate, TotalChildUrlCount, Url. The `domain:` prefix gets domain-level info (e.g. `domain:bing.com`). This is index metadata, not a Google-style "URL Inspection" verdict (no indexed/not-indexed reason field). — [GetUrlInfo](https://learn.microsoft.com/en-us/dotnet/api/microsoft.bing.webmaster.api.interfaces.iwebmasterapi.geturlinfo?view=bing-webmaster-dotnet)
- SubmitUrlBatch: max 500 URLs per batch "unless it exceeds the available quota". Call GetUrlSubmissionQuota first. — [SubmitUrlBatch](https://learn.microsoft.com/en-us/dotnet/api/microsoft.bing.webmaster.api.interfaces.iwebmasterapi.submiturlbatch?view=bing-webmaster-dotnet)
- GetUrlSubmissionQuota returns `DailyQuota` and `MonthlyQuota` fields (third-party method list derived from the WSDL; one forum post shows DailyQuota 10000). — [search-console-mcp BING_API_METHODS.md](https://glama.ai/mcp/servers/@saurabhsharma2u/search-console-mcp/blob/a95175bed5f62a794e106e5d170e09bfcbbf987c/BING_API_METHODS.md); [WordPress forum](https://wordpress.org/support/?p=15131300)

### Inferences
- A minimal daily-health call set: GetUserSites (validate site access), GetRankAndTrafficStats (daily clicks and impressions trend), GetQueryStats + GetPageStats (top queries and pages, weekly buckets), GetCrawlStats (daily crawl codes, InIndex), GetCrawlIssues, GetFeeds (sitemap status), and optionally GetUrlInfo for a short list of key URLs. That is about 7 calls per site per day.
- `siteUrl` must exactly match the site as registered in BWT (scheme and trailing slash). Normalize it from the GetUserSites output instead of user input.

### Gaps
- Exact field shapes for GetPageStats, GetCrawlIssues (expected: Url, HttpCode, Issues flags enum, InLinks), GetFeeds (expected: Url, Type, Status, Submitted, LastCrawled, UrlCount), and GetLinkCounts (expected: paged `Links` with Url/Count, TotalPages) were not fetched in this pass. Confirm them from each method's Learn page before coding parsers.
- No documented pagination or row cap for GetQueryStats/GetPageStats ("top" queries/pages). The row limit is undocumented.
- No documented device, country, or search-type filters on these API methods, even though the UI gained device and country filters in 2025.

## Data granularity, history and lag; date format

### Takeaway
Site-level clicks and impressions (GetRankAndTrafficStats) and crawl stats are daily rows, updated daily. Query and page stats are documented as updated weekly, so expect weekly-bucketed rows. Dates use the WCF `/Date(ms±hhmm)/` format. The UI has 24 months of Search Performance history. The API window is not documented and may be shorter (crawl stats: last 6 months).

### Cited Findings
- Query stats: "The data will be updated every week." — [GetQueryStats](https://learn.microsoft.com/en-us/dotnet/api/microsoft.bing.webmaster.api.interfaces.iwebmasterapi.getquerystats?view=bing-webmaster-dotnet)
- Rank-and-traffic stats: "updated every day". They cover all verticals (Web, Chat, News, Images, Videos, Knowledge Panel) from 2023-03-24 onward. — [GetRankAndTrafficStats](https://learn.microsoft.com/en-us/dotnet/api/microsoft.bing.webmaster.api.interfaces.iwebmasterapi.getrankandtrafficstats?view=bing-webmaster-dotnet)
- Crawl stats: last 6 months, updated daily. — [GetCrawlStats](https://learn.microsoft.com/en-us/dotnet/api/microsoft.bing.webmaster.api.interfaces.iwebmasterapi.getcrawlstats?view=bing-webmaster-dotnet)
- JSON date format is `"/Date(1316156400000-0700)/"`, while XML uses ISO-8601 `2011-09-16T00:00:00-07:00` for the same value. — [GetQueryStats](https://learn.microsoft.com/en-us/dotnet/api/microsoft.bing.webmaster.api.interfaces.iwebmasterapi.getquerystats?view=bing-webmaster-dotnet)
- UI Search Performance history went from 6 to 16 months in October 2024. — [Bing blog Oct 2024](https://blogs.bing.com/webmaster/October-2024/Bing-Webmaster-Tools-Extends-Search-Performance-Data-to-16-Months)
- In August 2025 it went to 24 months, with country and device filters and keyword trendlines added. — [Search Engine Land](https://searchengineland.com/bing-webmaster-tools-now-with-24-months-of-data-filters-by-country-and-device-and-keyword-trendlines-460413); [SER](https://www.seroundtable.com/bing-webmaster-tools-gets-24-months-39906.html)
- Crawl and indexing history in the UI accumulates over time rather than being backfilled. — [Bing blog Oct 2024](https://blogs.bing.com/webmaster/October-2024/Bing-Webmaster-Tools-Extends-Search-Performance-Data-to-16-Months)

### Inferences
- Parse `/Date(ms±hhmm)/` with a regex: `ms` is milliseconds since the Unix epoch in UTC (WCF convention), and the offset only annotates the original local zone. In the sample, 1316156400000 = 2011-09-16T07:00Z = 2011-09-16T00:00-07:00, consistent with the XML. Convert to a date by applying the offset, so you get the Pacific-time calendar day Bing intends.
- Because query and page data are weekly, a daily health check should diff GetRankAndTrafficStats (daily) for anomaly detection, and only compare query and page data week over week. Do not alarm on unchanged query rows between days.
- Expect a lag of at least a day or two on daily series. Compare against the latest complete day present in the response, not "yesterday".

### Gaps
- No official statement found on the exact data lag (hours or days) or on how far back GetRankAndTrafficStats/GetQueryStats return via API. The 24-month figure is for the UI. Improvado claims "16 months via API", but that is unverified and likely outdated ([Improvado](https://improvado.io/integrations/bing-webmaster-tools)).
- Week-boundary convention for weekly rows (week start or week end date) is not documented.

## New in 2025–2026: AI Performance / Copilot citations, MCP servers, API changes

### Takeaway
BWT launched an "AI Performance" report (public preview, 2026-02-10) with Copilot and Bing AI citation metrics. As of the latest sources (October–November 2026) it has **no official public API**. There is no official Microsoft BWT MCP server. Several community MCP servers wrap the classic API. The classic API surface itself appears unchanged since 2023.

### Cited Findings
- AI Performance public preview, announced 2026-02-10. It covers Microsoft Copilot, AI summaries in Bing, and select partner integrations. Metrics: Total Citations, Average Cited Pages (per day), Grounding queries (sampled), page-level citation activity, and visibility trends over time. The announcement mentions no API. — [Bing blog Feb 2026](https://blogs.bing.com/webmaster/February-2026/Introducing-AI-Performance-in-Bing-Webmaster-Tools-Public-Preview)
- On Microsoft Q&A (2026-02-19), the accepted answer from a community volunteer, not Microsoft staff, was "not right now". — [Microsoft Q&A](https://learn.microsoft.com/en-us/answers/questions/5780844/bing-webmaster-tools-ai-performance-report-is-ther)
- Third-party reports say Fabrice Canel (Bing) put API access on the backlog with no date, and that the API reference still had no AI Performance methods as of October 2026. Export is CSV/Excel from the UI. — [SER](https://www.seroundtable.com/bing-webmaster-tools-ai-performance-report-40911.html); [Similarweb](https://aisearch.similarweb.com/blog/bing-ai-performance-tool/); [tryhikoo guide](https://www.tryhikoo.com/en/blog/guides/bing-webmaster-tools-ai-performance-complete-guide-2026/) (secondary sources, not verified against Microsoft)
- A community skill, `rebelytics/bing-wmt-ai-grounding-export` (updated 2026-11-16), extracts AI Performance data "via the report's own authenticated JSON API". It does this by driving a browser that is signed in to bing.com/webmasters/aiperformance, i.e. an undocumented internal UI API, not a public one. — [GitHub README](https://github.com/rebelytics/bing-wmt-ai-grounding-export)
- The IWebmasterApi reference was last updated 2023-11-14. No new methods are listed. — [IWebmasterApi](https://learn.microsoft.com/en-us/dotnet/api/microsoft.bing.webmaster.api.interfaces.iwebmasterapi?view=bing-webmaster-dotnet)
- The OAuth doc was touched 2026-08-07, with no new scopes. — [OAuth 2.0 doc](https://learn.microsoft.com/en-us/bingwebmaster/oauth2)
- Community MCP servers found: `zizzfizzix/mcp-server-bwt` (Python, MIT, PyPI 0.2.0 released 2026-09-25, 8 stars, uses the `BING_WEBMASTER_API_KEY` env var); `ncosentino/bing-webmaster-mcp` (2 stars, updated 2026-09-22); `mgcrea/mcp-bing-webmaster` and `Semust-com/bing-webmaster-mcp` (0 stars, Nov 2026); and Composio's hosted toolkit. A listed `Multivariate-AI-Inc/bing-webmaster-mcp-server` repo returned 404 on GitHub. — [PyPI mcp-server-bwt](https://pypi.org/p/mcp-server-bwt); [GitHub zizzfizzix](https://github.com/zizzfizzix/mcp-server-bwt); [Composio](https://composio.dev/toolkits/bing_webmaster_tools/framework/crew-ai); GitHub search via `gh` on 2026-11-19
- November 2025 note on the Bing blog: IndexNow is now the recommended primary real-time submission method. The Adaptive URL Submission API "remains supported for advanced use cases". — [Bing blog June 2019 (updated note)](https://blogs.bing.com/webmaster/june-2019/bingbot-Series-Introducing-Batch-mode-for-Adaptive-URL-submission-API) (reported via search summary, not fetched directly)

### Inferences
- The skill should not depend on AI Performance data via API. At most, it could ingest a user-supplied CSV export. Scraping the internal UI API needs a signed-in browser session, is fragile, and is likely outside the API terms.
- Treat SubmitUrl/SubmitUrlBatch as legacy-supported and prefer IndexNow for submissions.

### Gaps
- No primary Microsoft statement confirming the AI Performance API timeline. No official Microsoft MCP server found.
- Could not verify whether the AI Performance preview has graduated to GA by November 2026.

## Quotas and rate limits

### Takeaway
URL submission is quota-bound: an adaptive daily quota of up to 10,000 URLs per site, at most 500 per batch, queryable via GetUrlSubmissionQuota. General read-call rate limits are not publicly documented, so build in backoff.

### Cited Findings
- Batch max 500 URLs, bounded by available quota. — [SubmitUrlBatch](https://learn.microsoft.com/en-us/dotnet/api/microsoft.bing.webmaster.api.interfaces.iwebmasterapi.submiturlbatch?view=bing-webmaster-dotnet)
- 10,000 URLs/day, 500 per batch (2019 batch-mode post). — [Bing blog June 2019](https://blogs.bing.com/webmaster/june-2019/bingbot-Series-Introducing-Batch-mode-for-Adaptive-URL-submission-API)
- The quota is adaptive. It depends on verified site age in BWT, site impressions, and other signals, and is allocated at the domain level. — [SEJ](https://www.searchenginejournal.com/bing-allows-site-owners-to-submit-up-to-10000-urls-per-day/290801); [Bing blog Jan 2020](https://blogs.bing.com/webmaster/january-2020/Bing-partners-with-the-ecosystem-to-drive-fresh-signals)
- The 2019 launch said "no monthly quotas", yet the API still returns a `MonthlyQuota` field, possibly a legacy field. — [Seven Forums repost](https://www.sevenforums.com/threads/content-indexed-fast-by-submitting-up-to-10-000-urls-per-day-to-bing.418256/); [WSDL-derived list](https://glama.ai/mcp/servers/@saurabhsharma2u/search-console-mcp/blob/a95175bed5f62a794e106e5d170e09bfcbbf987c/BING_API_METHODS.md)
- The merj Python client defaults to client-side throttling of `rate_limit_calls=10` per `rate_limit_period=1` s, with exponential backoff on `RateLimitError`. These are the library's defaults, not a documented Bing limit. — [merj/bing-webmaster-tools README](https://github.com/merj/bing-webmaster-tools)
- The rebelytics skill describes the (separate) AI Performance UI API as quota-limited and paces its requests. — [rebelytics README](https://github.com/rebelytics/bing-wmt-ai-grounding-export)

### Inferences
- About 7 read calls per site per day is far below any plausible limit. Add simple retry with backoff on HTTP 429/5xx and on throttling `ErrorCode`s.

### Gaps
- No official published rate limit for read methods. The content submission (SubmitContent) quota values were not found (only that GetContentSubmissionQuota exists).

## IndexNow

### Takeaway
IndexNow is a simple, key-authenticated ping protocol. Host `{key}.txt` at the site root, then GET a single URL or POST up to 10,000 URLs as JSON to any participating engine (or `api.indexnow.org`). Engines share submissions with each other. As of November 2026 the official participants are Bing, Yandex, Seznam, Naver, Yep, Internet Archive and Amazonbot. Google does not participate. You can verify submissions in BWT's IndexNow Insights report.

### Cited Findings
- GET form: `https://<searchengine>/indexnow?url=<url-escaped>&key=<key>`. POST form: `/indexnow` with `Content-Type: application/json; charset=utf-8` and body `{"host","key","keyLocation"(optional),"urlList":[...]}`. — [IndexNow docs](https://www.indexnow.org/documentation)
- Key: 8–128 characters from `a-z A-Z 0-9 -`. Key file: a UTF-8 `{key}.txt` at the root containing the key (recommended), or anywhere on the same host with `keyLocation`. A non-root key file only authorizes URLs under its own path. — [IndexNow docs](https://www.indexnow.org/documentation)
- Batch limit: up to 10,000 URLs per POST, and http and https URLs may be mixed. — [IndexNow docs](https://www.indexnow.org/documentation)
- Response codes: 200 OK (submitted); 202 Accepted (received, key validation pending); 400 (bad format); 403 (key not valid or not found in file); 422 (URLs don't belong to the host, or key/schema mismatch); 429 (too many requests, potential spam). — [IndexNow docs](https://www.indexnow.org/documentation)
- Official participant registry (`searchengines.json`, fetched 2026-11-19): bing, yandex, seznam, naver, yep, internetarchive, amazonbot. Endpoints from each meta.json: `https://www.bing.com/indexnow`, `https://search.seznam.cz/indexnow`, `https://searchadvisor.naver.com/indexnow`, `https://indexnow.yep.com/indexnow`, `https://indexnow.amazonbot.amazon/indexnow`. Bing's meta.json also lists a `logs` URL, `https://www.bing.com/indexnow/logs`. — [indexnow.org/searchengines.json](https://www.indexnow.org/searchengines.json); [Bing meta.json](https://www.bing.com/indexnow/meta.json)
- Bing provides IndexNow support to the Internet Archive. — [SER](https://www.seroundtable.com/microsoft-indexnow-support-internet-archive-41180.html)
- Google: said in 2021 that it would test the protocol. 2026 third-party sources say it still does not support IndexNow, and Google is absent from the official registry above. — [SER 2021](https://www.seroundtable.com/google-indexnow-32396.html); [Wikipedia](https://en.wikipedia.org/wiki/IndexNow); [indexnow.org/searchengines.json](https://www.indexnow.org/searchengines.json)
- Probe on 2026-11-19: `GET https://api.indexnow.org/indexnow?url=https://example.com/&key=<bogus>` returned HTTP 429 with JSON `{"errorCode":"TooManyRequests",...}`, i.e. the shared endpoint answers bad or unverified submissions with a 429 (spam guard). `https://api.indexnow.org/indexnow/meta.json` returned a "services aren't available" HTML page. — direct probe of [api.indexnow.org](https://api.indexnow.org/indexnow)
- Verification in BWT: the IndexNow Insights report (launched March 2024) lists the latest 1,000 submitted URLs with index status, first-indexed date, and a "submitted late" flag, plus drill-downs and export. A 200 response only means the notification was accepted, not that the URL was indexed. — [Bing blog Mar 2024](https://blogs.bing.com/webmaster/March-2024/Optimize-your-Impact-with-IndexNow-Insights); [Search Engine Land](https://searchengineland.com/bing-webmaster-tools-gains-new-indexnow-insights-top-seo-insights-report-438100); [Microsoft Tech Community thread](https://techcommunity.microsoft.com/discussions/bing/rank-math-indexnow-returns-success-but-bing-doesnt-reflect-url-submissions/4532990)

### Inferences
- For the health check, IndexNow is a write action (submit changed URLs after deploy), not a data source. The read-side check is "is the key file reachable and does it contain the key", which is a cheap probe the daily check can run (GET `https://site/{key}.txt`, compare the body).
- Submit to one engine only (e.g. `www.bing.com/indexnow` or `api.indexnow.org`), since engines share submissions. Do not fan out to all of them.
- Treat 429 as "back off / check key", not as transient.

### Gaps
- No API exists to read IndexNow Insights. It is UI-only, and no IWebmasterApi method covers it.
- No published per-day IndexNow URL cap found beyond 10,000 per request and 429 throttling.

## Existing CLIs / packages / GitHub tools

### Takeaway
The only reasonably mature wrapper is `merj/bing-webmaster-tools` (PyPI `bing-webmaster-tools` 1.2.0, async/aiohttp, Python 3.10+, about 21 stars). It is still maintained (dependency and security commits in September 2026, push in November 2026), but its last release was April 2025. Everything else is a young community MCP server or CLI with few stars. There is no official Microsoft SDK besides the old .NET interface docs, and no relevant npm package.

### Cited Findings
- `bing-webmaster-tools` on PyPI: latest 1.2.0 (uploaded 2025-04-26); releases 1.0.1–1.2.0. Repo `merj/bing-webmaster-tools`: 21 stars, not archived, last push 2026-11-16, recent commits "drop Python 3.9 and update dependencies to resolve security alerts" (2026-09-17). Features: async on aiohttp, built-in retry and rate limiting, domain-organized services, Python ≥3.10, Poetry. — [PyPI JSON](https://pypi.org/pypi/bing-webmaster-tools/json); [GitHub](https://github.com/merj/bing-webmaster-tools)
- `mcp-server-bwt` 0.2.0 (2026-09-25), 8 stars, MIT, runs via `uvx`. — [PyPI](https://pypi.org/p/mcp-server-bwt); [GitHub](https://github.com/zizzfizzix/mcp-server-bwt)
- Other tools (all 0–2 stars, created or updated in Sept–Nov 2026): `siliconvalley-setup/bing-webmaster-cli` ("Unofficial CLI for the Bing Webmaster Tools JSON API"), `ncosentino/bing-webmaster-mcp`, `mgcrea/mcp-bing-webmaster`, `Semust-com/bing-webmaster-mcp`, `erayendes/mowteng-mcp` (GSC + BWT + Yandex + IndexNow). — GitHub search via `gh search repos "bing webmaster"` on 2026-11-19, e.g. [bing-webmaster-cli](https://github.com/siliconvalley-setup/bing-webmaster-cli)
- npm: no `bing-webmaster-tools` or `bing-webmaster-api` package exists. `indexnow` 0.1.0 was last modified 2022-05-05 (stale). — [npm registry indexnow](https://registry.npmjs.org/indexnow)

### Inferences
- The merj library adds aiohttp, Pydantic-style models and Poetry tooling. That is a heavy dependency for roughly 7 GET calls and a date-regex parse.

### Gaps
- Did not audit the merj library's coverage of every method or how well it parses `/Date()/`.

## Recommendation: self-implement stdlib vs third-party

### Takeaway
Self-implement a small stdlib Python script (`urllib.request` + `json` + `re`). The API is a handful of unauthenticated-style GETs with the key in the query string, a uniform `{"d": ...}` envelope, and one date format. No third-party package is mature enough to justify the dependency, and the API surface has been frozen since 2023.

### Cited Findings
- JSON GET with `apikey` + `siteUrl` query params, `{"d":[...]}` envelope, `/Date(ms±hhmm)/` dates. — [GetQueryStats](https://learn.microsoft.com/en-us/dotnet/api/microsoft.bing.webmaster.api.interfaces.iwebmasterapi.getquerystats?view=bing-webmaster-dotnet)
- Error shape: HTTP 400 `{"ErrorCode":3,"Message":"ERROR!!! InvalidApiKey"}`. — probe of [ssl.bing.com](https://ssl.bing.com/webmaster/api.svc/json/GetUserSites)
- The best existing wrapper's last release was April 2025, with about 21 stars. — [PyPI](https://pypi.org/pypi/bing-webmaster-tools/json)
- The interface has not changed since 2023-11-14. — [IWebmasterApi](https://learn.microsoft.com/en-us/dotnet/api/microsoft.bing.webmaster.api.interfaces.iwebmasterapi?view=bing-webmaster-dotnet)

### Inferences
- Suggested design:
  - **Auth:** `BING_WEBMASTER_API_KEY` env var, with the API-key method only.
  - **Base URL:** `https://ssl.bing.com/webmaster/api.svc/json/`.
  - **Helper:** `call(method, **params)` returns `resp["d"]`, with retry and backoff on 429/5xx.
  - **Dates:** a `parse_wcf_date()` that applies the offset.
  - **Site resolution:** resolve `siteUrl` from GetUserSites.
  - **Data pulled:** daily series from GetRankAndTrafficStats and GetCrawlStats, weekly rows from GetQueryStats and GetPageStats, a list from GetCrawlIssues, and sitemap state from GetFeeds.
  - **IndexNow:** an optional submit helper (POST to `api.indexnow.org` or `www.bing.com/indexnow`, max 10,000 URLs) plus a key-file reachability probe.
  - **Redaction:** mask `apikey` in any logged URL.
- Keep AI Performance out of scope for API automation. At most, accept a user-exported CSV.

### Gaps
- Response shapes for GetPageStats, GetCrawlIssues, GetFeeds and GetLinkCounts still need to be confirmed against a live key or each Learn method page before finalizing parsers.
