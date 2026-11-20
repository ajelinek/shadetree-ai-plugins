"""Small stdlib HTTP client shared by every source.

Secrets travel in headers or bodies wherever the API allows. Where an API
insists on a query-string key (Bing, CrUX, PSI, Safe Browsing), callers pass
it via ``secret_params`` so it is redacted from every error message.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any

USER_AGENT = "shadetree-website-health/0.1 (+https://github.com/ajelinek/shadetree-ai-plugins)"
DEFAULT_TIMEOUT = 30


class HttpError(RuntimeError):
    """A non-2xx response or transport failure, with secrets already redacted."""

    def __init__(self, message: str, status: int | None = None, body: Any = None):
        super().__init__(message)
        self.status = status
        self.body = body


@dataclass
class Response:
    status: int
    headers: dict[str, str]
    data: Any


def _redact(text: str, secrets: list[str]) -> str:
    for secret in secrets:
        if secret:
            text = text.replace(secret, "***").replace(urllib.parse.quote(secret, safe=""), "***")
    return text


def build_url(url: str, params: dict[str, Any] | None) -> str:
    if not params:
        return url
    pairs: list[tuple[str, str]] = []
    for key, value in params.items():
        if value is None:
            continue
        for item in value if isinstance(value, (list, tuple)) else [value]:
            pairs.append((key, str(item)))
    sep = "&" if "?" in url else "?"
    return f"{url}{sep}{urllib.parse.urlencode(pairs)}"


def request(
    method: str,
    url: str,
    *,
    params: dict[str, Any] | None = None,
    secret_params: dict[str, str] | None = None,
    headers: dict[str, str] | None = None,
    json_body: Any = None,
    form: dict[str, Any] | None = None,
    timeout: float = DEFAULT_TIMEOUT,
    retries: int = 0,
    expect_json: bool = True,
) -> Response:
    """Send one request. ``retries`` applies only to 429/5xx/transport errors."""
    secrets = list((secret_params or {}).values())
    for value in (headers or {}).values():
        if value.lower().startswith("bearer "):
            secrets.append(value[7:])
    full_url = build_url(url, {**(params or {}), **(secret_params or {})})
    body: bytes | None = None
    all_headers = {"User-Agent": USER_AGENT, "Accept": "application/json", **(headers or {})}
    if json_body is not None:
        body = json.dumps(json_body).encode()
        all_headers["Content-Type"] = "application/json"
    elif form is not None:
        body = urllib.parse.urlencode(form).encode()
        all_headers["Content-Type"] = "application/x-www-form-urlencoded"
        secrets.extend(str(v) for k, v in form.items() if "key" in k.lower())
    attempt = 0
    while True:
        attempt += 1
        req = urllib.request.Request(full_url, data=body, headers=all_headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                raw = resp.read()
                hdrs = {k.lower(): v for k, v in resp.headers.items()}
                return Response(resp.status, hdrs, _decode(raw, expect_json))
        except urllib.error.HTTPError as exc:
            raw = exc.read()
            data = _decode(raw, True, strict=False)
            retryable = exc.code == 429 or exc.code >= 500
            if retryable and attempt <= retries:
                time.sleep(min(2**attempt, 10))
                continue
            detail = _error_detail(data) or exc.reason
            message = _redact(f"HTTP {exc.code}: {detail}", secrets)
            raise HttpError(message, exc.code, data) from None
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            if attempt <= retries:
                time.sleep(min(2**attempt, 10))
                continue
            reason = getattr(exc, "reason", exc)
            raise HttpError(_redact(f"Network error: {reason}", secrets)) from None


def _decode(raw: bytes, expect_json: bool, strict: bool = True) -> Any:
    if not expect_json:
        return raw.decode("utf-8", errors="replace")
    if not raw:
        return None
    try:
        return json.loads(raw)
    except ValueError:
        if strict:
            raise HttpError("Response was not valid JSON.") from None
        return raw.decode("utf-8", errors="replace")[:500]


def _error_detail(data: Any) -> str | None:
    if isinstance(data, dict):
        err = data.get("error")
        if isinstance(err, dict):
            return str(err.get("message") or err.get("status") or err)
        for key in ("message", "Message", "error_description", "detail", "error"):
            if data.get(key):
                return str(data[key])
        errors = data.get("errors")
        if isinstance(errors, list) and errors:
            first = errors[0]
            return str(first.get("message") if isinstance(first, dict) else first)
    if isinstance(data, str):
        return data[:300]
    return None
