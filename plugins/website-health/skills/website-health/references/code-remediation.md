# Code remediation

Turns a confirmed anomaly or probe finding into a fix a coding agent can
apply.

## Steps

1. **Confirm real.** Layer 1 of [analysis-rules.md](analysis-rules.md). Stop
   at "unconfirmed" if the period is provisional.
2. **Localize.** Layers 2–3: which dimension and pages.
3. **Correlate.** `correlate(site, day, source)`. Pass the detecting source
   so the window widens for lagging sources (gsc/bing +72h, ga4/clarity
   +24h, crux +28 days). Candidates are ranked closest-before-the-anomaly
   first; deployments outrank workflow runs, PRs and commits at equal times.
4. **Inspect diffs** of the top candidates: `gh api repos/{repo}/commits/{sha}`
   or `gh pr diff {n}`. If the repo is checked out locally, read the files.
   Use the suspect-file table to prioritize.
5. **Hypothesis with confidence** (below). Never claim a mechanism the diff
   doesn't show.
6. **Output** each finding with the template. Severity P0–P3.
7. **After the fix ships:** `probe_site` + `run_pagespeed` immediately;
   GA4/Clarity next day; GSC/Bing after 3 days; CrUX over the following
   weeks. For changed or new URLs, offer `indexnow_submit` (confirm first).

## Suspect files

| Signal | Look at |
|---|---|
| `firebase_auth.signups`, GA4 `signupEvents` gap | auth/signup routes and components, Firebase init/config, post-signup redirects, GA4 event call |
| `ga4.keyEvents` | CTA components, checkout flow, event-binding ids/classes, tag manager/gtag snippet, consent banner |
| `gsc.*` / `bing.*` clicks, impressions, position | `<head>` meta, canonical, robots meta, `robots.txt`, sitemap config, JSON-LD, route renames/deletions, redirects (`firebase.json` / `_redirects`) |
| probe `noindex`, `canonical_changed`, `structured_data_removed`, `title_changed` | the layout or SEO component rendering `<head>` (e.g. `src/layouts/*.astro`, an SEO/Meta component) |
| probe `security_header_removed`, `redirect_added`, `http_not_redirected` | `firebase.json` `headers`/`redirects`, CDN config, middleware |
| probe `sitemap_shrank`, `sitemap_broken_urls` | sitemap integration config, content collection filters, deleted pages |
| probe `page_down`, `content_marker_missing` | the route file, build config, data fetch on that page |
| `crux.*`, PSI `newlyFailing` audits | images (size, `loading`, dimensions → CLS), fonts (`font-display`, preload), new or heavy scripts, hydration directives, third-party tags |
| `clarity.rageClickPct` / `deadClickPct` / `errorClickPct` on a page | the interactive component on that page: click handlers, disabled states, hydration of the island |
| `clarity.scriptErrorPct` | scripts and islands on the affected pages |
| `cloud_monitoring.responses5xx`, `uptimeCheckPassed` down | functions/SSR handlers, rewrites to functions, env/config changes |

## Confidence

- **High:** timing, changed file, and localized dimension all line up.
- **Medium:** two of the three line up, or any `qualityFlags` on the period.
- **Low:** timing only.

## Severity

- **P0:** confirmed regression, high-confidence cause, high impact (site down,
  noindex on a key page, checkout/signups broken, blocklisted, Safe Browsing).
- **P1:** confirmed high-impact regression, medium-confidence cause.
- **P2:** lower-impact regression, or a high-confidence cause on a moderate
  metric.
- **P3:** growth suggestion; nothing is broken.

## Output template

```
Metric: <metric> <direction> on <period> (<actual> vs baseline <baseline>, Δ<delta>)
Evidence: <sources that agree, in lag order>
Cause: <file>:<line> - <what changed> (<PR #/sha>)
Fix: <patch snippet or precise instruction>
Severity: P0-P3
Confidence: High/Medium/Low - <what aligned>
Verify: <which tool, when>
```

## Growth mode

When nothing is broken:

- **GSC:** `get_breakdown(site, "gsc.impressions", <latest final day>)` and
  `gsc.clicks` for pages and queries. Look for high impressions, low CTR at
  position 3–10. Likely fixes: title or description, FAQ or other JSON-LD,
  better internal links.
- **Bing:** pages and queries ranking on Bing but weak on Google, or the
  reverse.
- **CrUX/PSI:** "needs improvement" vitals, with the top failing audits.
- **Clarity:** pages with high excessive-scroll or quickback rates; content
  isn't answering the visit.
- **GA4 `aiReferralSessions`:** which pages AI assistants send people to.
  Strengthen those pages.

Always P3, same template, with "Cause" describing the opportunity.

## Worked example

`ga4.keyEvents` regression on 2026-07-06: 26 vs baseline 42, Δ −0.38,
critical, no flags. `topContributors`: `page=/pricing` 30 → 4. Clarity
`page=/pricing` `deadClickPct` 2 → 19. Probe clean. `correlate(site,
"2026-07-06", "ga4")`: PR #482 "Refactor pricing CTA markup", merged 9h
before. Diff: `src/components/PricingCta.astro` dropped
`id="pricing-upgrade-cta"`, which the GTM trigger keys on.

```
Metric: ga4.keyEvents regression on 2026-07-06 (26 vs 42, Δ-0.38)
Evidence: Clarity dead clicks on /pricing up 2%→19% (same window), GA4 key events
  on /pricing 30→4, other pages flat; probe clean
Cause: src/components/PricingCta.astro:14 - id="pricing-upgrade-cta" removed (PR #482)
Fix: restore the id: <button id="pricing-upgrade-cta" class="btn-primary">Upgrade</button>
Severity: P0
Confidence: High - timing (9h), file (the CTA on the affected page), dimension (/pricing only)
Verify: ga4_realtime after deploy; detect_anomalies tomorrow
```
