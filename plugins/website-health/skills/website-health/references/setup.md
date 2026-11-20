# Setup

Three parts: credentials (doctor), grants in the accounts that own the data,
and site config. Only the live probe and blocklists work with none of it.

## 1. Credentials: `doctor`

The user runs the `doctor_command` from `check_setup` in their own terminal.
Doctor walks every credential below. Enter skips one; a stored one can be
kept, validated, replaced or deleted. `--only <key or source>` limits it to
one. Values go only to the OS keychain under
`shadetree-ai-plugins:website-health`.

| Keychain key | Sources | Where the user gets it |
|---|---|---|
| `google-service-account` (JSON file) | ga4, gsc, firebase_auth, cloud_monitoring | Cloud Console → IAM & Admin → Service Accounts → create one → Keys → Add key → JSON. Doctor asks for the file path and offers to delete the file after storing it. |
| `google-api-key` | crux, psi (optional), safebrowsing | Cloud Console → APIs & Services → Credentials → Create credentials → API key. Restrict it to Chrome UX Report API, PageSpeed Insights API and Safe Browsing API. |
| `bing-api-key` | bing | bing.com/webmasters → Settings (gear) → API Access → API Key. |
| `clarity-token.<site>` | clarity | clarity.microsoft.com → project → Settings → Data Export → Generate new API token. Project admins only. Doctor only lists this once the site has `clarityProjectId`. |

**Browser help.** If you're helping in the browser, navigate only as far as
the page that shows the key. The user copies it into doctor. Never read a key
off the screen into chat.

PageSpeed (`psi`) works without a key but Google's shared keyless quota is usually
exhausted (HTTP 429). Store the key for reliable performance trends. `audit_site` and the
probe need no credentials at all.

### Cloud project setup for the service account

In the Cloud project that owns the service account, enable: Google Analytics
Data API, Google Analytics Admin API, Google Search Console API, Identity
Toolkit API (Firebase Auth) and Cloud Monitoring API. The API key's project
also needs Chrome UX Report API, PageSpeed Insights API and Safe Browsing API.

If the project sits under a Google Cloud organization created after May 2024,
service-account key creation is blocked by default
(`iam.disableServiceAccountKeyCreation`). A project with no organization isn't
affected; otherwise an org admin must allow it for that project.

## 2. Grants in the account that owns the data

The data usually lives in a different Google account from the one that
created the service account. That's fine: sign in to the **owning** account
and grant the service account's email (`check_setup` shows it as
`serviceAccountEmail`):

- **GA4:** Admin → Property access management → add the email → Viewer.
- **Search Console:** Settings → Users and permissions → Add user → Full.
- **Firebase Auth:** Google Cloud IAM on the Firebase project → grant
  *Firebase Authentication Viewer*. Enable Identity Toolkit API there too.
- **Cloud Monitoring (Firebase Hosting / uptime checks):** IAM on that
  project → *Monitoring Viewer*.

Microsoft works the same way:

- **Clarity:** the token belongs to the project, not the signed-in person.
  An admin of the project in the owning account generates it, or that
  account adds the user as a project admin.
- **Bing:** the key covers every site its user can see. Generate it in the
  owning account, or have that account add the user under Settings → Users.

A 403 in `collect` results carries a `fix` line naming the missing grant.

## 3. Site config

`discover_properties` → `configure_site(name, settings)`. Fields:

| Setting | Example | Needed for |
|---|---|---|
| `url` | `https://example.com` | everything (required) |
| `timezone` | `America/New_York` | day bucketing |
| `ga4PropertyId` | `123456789` | ga4 |
| `ga4SignupEvent` | `sign_up` | GA4 signup event count |
| `gscSiteUrl` | `sc-domain:example.com` or `https://example.com/` | gsc (must match exactly) |
| `bingSiteUrl` | `https://example.com/` | bing |
| `clarityProjectId` | from the Clarity URL | clarity |
| `firebaseProjectId` | `my-app` | firebase_auth |
| `githubRepos` | `["org/site"]` | correlate (needs `gh auth login`) |
| `keyPaths` | `["/", "/pricing", "/signup"]` | probe, PSI, URL inspection |
| `contentMarkers` | `{"/pricing": "Start free trial"}` | probe (text that must appear) |
| `cruxUrls` | `["/pricing"]` | URL-level CrUX (often insufficient traffic) |
| `indexnowKey` | 8–128 chars, file at `/<key>.txt` | indexnow |
| `cloudMonitoringProjectId` + `cloudMonitoringQueries` | `["uptime", "hosting"]` | cloud_monitoring |
| `safeBrowsing`, `blocklists` | `true` | on by default |
| `anomalyThresholds` | `{"gsc.clicks": {...}}` | override defaults |

The `hosting` preset expects a log-based metric for Firebase Hosting
responses with a `status` label, which needs Cloud Logging linked to Hosting.
If `collect` warns "no time series matched", give a custom query with the
real metric type.
