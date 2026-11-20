"""Source registry, in collection order (fast no-auth checks first)."""

from . import (
    bing,
    blocklists,
    clarity,
    cloud_monitoring,
    cloudflare,
    crux,
    firebase_auth,
    ga4,
    gsc,
    indexnow,
    probe,
    safebrowsing,
    sentry,
    stripe,
    uptime,
)

REGISTRY = {m.NAME: m for m in (
    probe, blocklists, safebrowsing, indexnow, ga4, gsc, firebase_auth, crux, clarity, bing,
    cloud_monitoring, uptime, cloudflare, stripe, sentry)}
