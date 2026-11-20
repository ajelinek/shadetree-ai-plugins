# Analysis rules

## What `detect_anomalies` does

For each metric in `anomalyThresholds` with stored data, it picks the latest
**finalized** period of the metric's grain (or the one at or before
`period`), builds a baseline from the prior `baselineDays` finalized periods
of the **same grain**, and applies the method:

| Method | Rule | Default use |
|---|---|---|
| `zscore` | (actual − mean) / sample stdev ≥ warn/critical | volumes: sessions, clicks, impressions, 5xx, errors |
| `percentChange` | (actual − mean) / mean ≥ warn/critical | key events, signups, revenue, CrUX p75 |
| `absoluteDelta` | actual − mean ≥ warn/critical | GSC position, Clarity friction %, CLS |

Minimum baseline points: 7 daily, 3 weekly, 5 Clarity snapshots. Fewer
points means the metric is `skipped`, not healthy.

`direction` is already corrected for metrics where lower is better
(position, friction %, CWV p75, 4xx/5xx, failed charges, errors, TTFB). Each
anomaly carries `qualityFlags` for that period and `topContributors`, the
per-dimension rows (page, query, channel, provider, monitor) that moved
most since the previous period.

`severityDraft` (warn/critical) is a starting point. The P0–P3 call comes
from the framework below and the confidence rules in
[code-remediation.md](code-remediation.md).

## Source lag order

Sources see a regression at different speeds. When several agree in this
order, that sequence is the strongest evidence a claim can have:

1. **probe**: minutes
2. **cloud_monitoring**: hours, daily rows
3. **clarity**: rolling 24h
4. **ga4**: ~12h, revised for 24–48h, late hits for up to 7 days
5. **gsc, bing**: 2–3 days (`correlate` widens its look-back by 72h)
6. **crux**: 28-day rolling window, so a deploy shows gradually over weeks

A GSC drop with a clean probe and flat GA4 organic sessions is suspicious.
Check the GSC day isn't still provisional.

## The 5-layer root-cause framework

### Layer 1: Is it real?

- Provisional or flagged? Report "unconfirmed, re-check after <date>".
- Platform effects that are not regressions:
  - AI Overviews and AI Mode impressions are folded into GSC `web` totals.
    Rising impressions with flat clicks (CTR down) may be AI surfaces, not a
    snippet regression. Long conversational queries appearing are AI Mode
    follow-ups.
  - Clarity: since 2025-10-31, EEA/UK/CH visitors without a consent signal
    get a new ID per page view. Pages per session falls and session counts
    rise for those visitors with no deploy involved.
  - Bing query and page stats are weekly buckets; a "drop" mid-week is just
    an incomplete bucket.
  - CrUX "insufficient data" means low Chrome traffic, not an outage.
- Seasonality: compare the same weekday in prior weeks with
  `get_timeseries`.

### Layer 2: Localize by dimension

Use `topContributors`, then `get_breakdown` for channel, page, query or
provider. Concentrated in one dimension → narrower cause; go to layer 3. Even
across all dimensions → likely external (layer 5) or tracking-wide (layer 4).

### Layer 3: Page level

Which pages carry the movement? Cross-check the same page in GA4
(`page=` dims), GSC (`page=`), Clarity (`page=` friction) and PSI. A few
pages carrying most of the drop → strong code-change candidate.

### Layer 4: Technical

- `probe_site`: page_down, noindex, canonical changed, content marker
  missing, robots disallow, sitemap shrank or broken URLs, security headers
  removed, TTFB regression.
- `inspect_urls` for affected pages: verdict, coverage state, Google vs user
  canonical, rich-result errors. `bing_url_info` for Bing.
- Tracking: did the GA4 tag or key-event trigger break? Compare GA4
  `signupEvents` with Firebase `signups`; a gap over 20% that opens suddenly
  is an instrumentation break, not fewer signups.
- `run_pagespeed` on affected URLs: `newlyFailing` audits since last run.

A technical fault found → go to code-remediation step 4 with the mechanism
known.

### Layer 5: External

Search algorithm updates around the date, a referrer that stopped sending,
an outage at a provider (check status pages only now, when an anomaly
points there), seasonality. External cause → state it with confidence; no
code fix. Nothing found anywhere → correlate anyway at Low confidence.
