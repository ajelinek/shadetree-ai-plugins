# Daily health check

## Workflow

1. `check_setup`. Proceed with whatever is ready; list not-configured
   optional sources once at the end, not as failures.
2. `health_report(site)`. It runs every ready source, upserts history,
   detects anomalies and gathers findings. The first run has no baseline, so
   say so and suggest `collect(site, backfill_days=90)` to seed GA4, GSC and
   the other backfillable sources. Clarity can't be backfilled.
3. For each regression, decide using
   [analysis-rules.md](analysis-rules.md): unconfirmed (provisional,
   flagged), external, or code-caused. Call `correlate` only for the
   plausible code-caused ones, then follow
   [code-remediation.md](code-remediation.md).
4. Critical probe findings (`page_down`, `noindex`, `robots_disallow_all`,
   `tls_invalid`, `content_marker_missing`, `dns_failure`,
   `blocklisted`, `safe_browsing`) are P0 candidates on their own. They need
   no baseline. Correlate them with the most recent deploy.
5. If `reminders` says an audit is due (or after a deploy), run `audit_site` and add a
   short "Site audit" block: counts by severity, new issues, resolved issues, and the AI
   access verdict. Details: [audit-checklist.md](audit-checklist.md).
6. Write the report below. Include `reminders` verbatim.

## Report template

```
# Website health: <site> (<url>), <date>

Overall: 🔴 Regression | 🟡 Needs attention | 🟢 Healthy
Sources: <ready sources> · Data through: GA4 <date>, GSC <date>, Bing <date>, Clarity <window>

## Needs action
- P0 <one line> - cause/next step - confidence
- P1 ...

## Site checks (live probe)
Status, TLS days left, sitemap URLs (Δ), key-page changes, security headers

## Metrics
| Metric | Latest final | Baseline | Δ | Note |
| GA4 sessions / key events | | | | |
| GSC clicks / impressions / position | | | | |
| Bing clicks / impressions | | | | |
| Clarity rage / dead / script-error % | | | | |
| CrUX LCP / INP / CLS (p75, phone) | | | | good / needs improvement / poor |
| PageSpeed performance / LCP / page weight (mobile) | | | | weekly; `psi.*` |
| Signups (Firebase) | | | | |
| <optional: Cloud Monitoring 5xx, uptime checks> | | | | |

## Watch (unconfirmed or low confidence)
- <metric> - provisional until <date> / thresholded / Clarity gap

## Improvements
- <metric> up <Δ> - note what changed if a deploy explains it

## Reminders
- <from health_report>

Not configured: <optional sources>, set up with doctor + configure_site.
```

Keep it short when everything is healthy: overall line, metrics table, and
"no action needed".
