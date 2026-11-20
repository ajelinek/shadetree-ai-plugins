"""Credential manifest and keychain access for every source.

Values live only in the OS keychain (service ``shadetree-ai-plugins:website-health``).
They are never tool arguments, tool results, env vars, or files.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from shadetree_ai_plugins_common.secrets import SecretStoreError, get_secret

NAMESPACE = "website-health"


@dataclass(frozen=True)
class Credential:
    key: str
    label: str
    sources: tuple[str, ...]
    where: str
    kind: str = "secret"  # "secret" (hidden prompt) or "file" (JSON file path)
    per_site: bool = False

    def keychain_key(self, site: str | None = None) -> str:
        return f"{self.key}.{site}" if self.per_site and site else self.key


CREDENTIALS: tuple[Credential, ...] = (
    Credential(
        "google-service-account", "Google service-account key (JSON file)",
        ("ga4", "gsc", "firebase_auth", "cloud_monitoring"),
        "Cloud Console > IAM & Admin > Service Accounts > (account) > Keys > Add key > JSON. "
        "Then grant its email: GA4 Viewer, Search Console user, Firebase Authentication "
        "Viewer + Monitoring Viewer on the Firebase project.",
        kind="file"),
    Credential(
        "google-api-key", "Google API key (CrUX, PageSpeed Insights, Safe Browsing)",
        ("crux", "psi", "safebrowsing"),
        "Cloud Console > APIs & Services > Credentials > Create credentials > API key; "
        "restrict it to the Chrome UX Report, PageSpeed Insights and Safe Browsing APIs."),
    Credential(
        "bing-api-key", "Bing Webmaster Tools API key", ("bing",),
        "bing.com/webmasters > Settings (gear) > API Access > API Key."),
    Credential(
        "clarity-token", "Microsoft Clarity Data Export token", ("clarity",),
        "clarity.microsoft.com > project > Settings > Data Export > Generate new API token "
        "(project admin only).", per_site=True),
)

BY_KEY = {c.key: c for c in CREDENTIALS}
# Sources that work without their credential (a key only raises quota or adds history).
OPTIONAL_SOURCES = frozenset({"psi"})
BY_SOURCE = {source: c for c in CREDENTIALS for source in c.sources}


def read(key: str, site: str | None = None) -> str | None:
    """Return a stored credential or None. Raises SecretStoreError if the store fails."""
    cred = BY_KEY[key]
    return get_secret(NAMESPACE, cred.keychain_key(site))


def read_json(key: str) -> dict | None:
    value = read(key)
    if not value:
        return None
    try:
        data = json.loads(value)
    except ValueError:
        return None
    return data if isinstance(data, dict) else None


def status(key: str, site: str | None = None) -> str:
    """'stored', 'missing', or 'keychain_error' — never the value."""
    try:
        return "stored" if read(key, site) else "missing"
    except SecretStoreError:
        return "keychain_error"
