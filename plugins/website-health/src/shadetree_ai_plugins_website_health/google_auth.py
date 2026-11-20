"""Service-account access tokens, minted in memory from the keychain-stored key."""

from __future__ import annotations

import threading
import time

from google.auth import crypt, jwt

from . import credentials, http

SCOPES = {
    "ga4": "https://www.googleapis.com/auth/analytics.readonly",
    "gsc": "https://www.googleapis.com/auth/webmasters.readonly",
    "firebase_auth": "https://www.googleapis.com/auth/cloud-platform",
    "cloud_monitoring": "https://www.googleapis.com/auth/monitoring.read",
}
TOKEN_URI = "https://oauth2.googleapis.com/token"

_cache: dict[str, tuple[str, float]] = {}
_lock = threading.Lock()


class GoogleAuthError(RuntimeError):
    pass


def service_account_email() -> str | None:
    info = credentials.read_json("google-service-account")
    return info.get("client_email") if info else None


def token(source: str) -> str:
    """Return a bearer token for ``source``'s scope; cached until 5 min before expiry."""
    scope = SCOPES[source]
    with _lock:
        cached = _cache.get(scope)
        if cached and cached[1] - 300 > time.time():
            return cached[0]
        info = credentials.read_json("google-service-account")
        if not info:
            raise GoogleAuthError("setup_required: google-service-account is not stored.")
        if info.get("type") != "service_account" or not info.get("private_key"):
            raise GoogleAuthError("The stored Google credential is not a service-account key.")
        try:
            signer = crypt.RSASigner.from_service_account_info(info)
        except (ValueError, KeyError):
            raise GoogleAuthError("The stored service-account private key is unreadable.") from None
        now = int(time.time())
        assertion = jwt.encode(signer, {
            "iss": info["client_email"], "scope": scope, "aud": info.get("token_uri", TOKEN_URI),
            "iat": now, "exp": now + 3600,
        })
        try:
            resp = http.request("POST", info.get("token_uri", TOKEN_URI), form={
                "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                "assertion": assertion.decode() if isinstance(assertion, bytes) else assertion,
            })
        except http.HttpError as exc:
            raise GoogleAuthError(f"Google token exchange failed ({exc}). The key may be "
                                  "deleted or disabled; create a new one.") from None
        access = resp.data["access_token"]
        _cache[scope] = (access, now + int(resp.data.get("expires_in", 3600)))
        return access


def headers(source: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token(source)}"}


def clear_cache() -> None:
    with _lock:
        _cache.clear()
