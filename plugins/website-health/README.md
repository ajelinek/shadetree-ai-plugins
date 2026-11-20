# website-health

Cross-source website health checks for Claude: GA4, Google Search Console,
Bing Webmaster Tools, Microsoft Clarity, CrUX/PageSpeed Insights, a live-site
probe, Firebase Auth signups, Safe Browsing and DNS blocklists, plus optional
UptimeRobot, Cloud Monitoring, Cloudflare, Stripe and Sentry. Regressions are
correlated with GitHub deploys, PRs and commits so Claude can point at the
change that caused them and propose a fix.

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
- There's no built-in scheduler: data is collected when you run a check.
  Every source except Clarity backfills on the next run.
- Bing's AI Performance report and Search Console's generative-AI report
  have no API; the daily report reminds you monthly to check them.
