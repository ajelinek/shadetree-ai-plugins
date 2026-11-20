"""Local MCP workflow boundary. Judgment stays in the bundled skill."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from fastmcp import FastMCP
from shadetree_ai_plugins_common.secrets import SecretStoreError, get_secret

from . import _dns, blocklists, headers, registration
from . import reputation as _reputation
from .audit import guard_secret, run_audit, validate_inputs
from .dns_auth import audit_dns, domain_from_arg, normalize_email, validate_selectors
from .reputation import check_reputation

NAMESPACE = "email-domain-reputation"
CREDENTIAL_KEY = "abstractapi-api-key"
READ_ONLY = {"readOnlyHint": True, "destructiveHint": False,
             "idempotentHint": False, "openWorldHint": True}

mcp = FastMCP(
    "shadetree-ai-plugins-email-domain-reputation",
    instructions=(
        "audit_client_domain is the primary client email-domain health audit: it needs the "
        "AbstractAPI key and the client's email address, and works best when the user pastes "
        "the original headers of a message the client sent (raw_headers). audit_domain is a "
        "keyless DNS-only audit of a domain. investigate_email triages one inbound address. "
        "For troubleshooting a single symptom without a key: analyze_headers parses a pasted "
        "message locally (why it bounced, went to spam, or failed DMARC), check_blocklists "
        "checks a domain and its sending IPs on DNSBLs, check_registration reads RDAP expiry "
        "and holds. Stop on setup/API failures (setup_required, reputation_unavailable) of "
        "audit_client_domain or investigate_email; do not silently substitute other tools' "
        "findings for a full audit. Never ask for or accept API keys in chat; check_setup "
        "returns a local terminal command. Apply the bundled skill's evidence-led rubric; "
        "report evidence and fixes, not trust verdicts. Results cannot authenticate a "
        "particular message."
    ),
)


def _setup_command() -> str:
    root = Path(__file__).resolve().parents[2]
    # JSON/text command is shown to the user; it is never executed by this server.
    return (f'uv run --project "{root}" --locked python '
            "-m shadetree_ai_plugins_email_domain_reputation credentials set")


def _get_api_key() -> str | None:
    try:
        return get_secret(NAMESPACE, CREDENTIAL_KEY) or None
    except SecretStoreError:
        return None


@mcp.tool(annotations={**READ_ONLY, "idempotentHint": True, "openWorldHint": False})
def check_setup() -> dict:
    """Report keychain readiness without a network request or exposing the key.

    A stored key is not proof of API access or remaining credits. Show the local
    setup_command to the user; never execute an interactive key prompt in a tool.
    """
    try:
        configured = bool(get_secret(NAMESPACE, CREDENTIAL_KEY))
        error = None if configured else "API key not configured."
    except SecretStoreError as exc:
        configured, error = False, str(exc)
    return {"ready": configured, "configured": configured, "error": error,
            "setup_command": _setup_command(), "api_access_verified": False}


@mcp.tool(annotations=READ_ONLY)
def investigate_email(email: str, selectors: list[str] | None = None) -> dict:
    """Investigate one address: AbstractAPI reputation then SPF/DMARC/MX/DKIM.

    Sends the address to AbstractAPI and the domain to the machine's DNS resolver.
    Uses one metered API request, no automatic retry, history or bulk mode. A key
    and working API access are required; failure returns no DNS-only assessment.
    Optional selectors (at most 20) are probed in addition to the 29 built-in
    common DKIM selectors.
    """
    try:
        email = normalize_email(email)
        validate_selectors(selectors)
    except ValueError as exc:
        return {"ok": False, "error": "invalid_input", "detail": str(exc)}
    key = _get_api_key()
    if not key:
        return {"ok": False, "error": "setup_required", "setup_command": _setup_command()}
    reputation = check_reputation(email, key)
    if not reputation["source"]["ok"]:
        return {"ok": False, "error": "reputation_unavailable", **reputation}
    return {"ok": True, "email": email, "domain": domain_from_arg(email),
            "checked_at": datetime.now(UTC).isoformat(), **reputation,
            "dns": audit_dns(email, selectors=selectors)}


@mcp.tool(annotations=READ_ONLY)
def audit_domain(target: str, selectors: list[str] | None = None) -> dict:
    """Inspect public mail DNS for a domain (or an address's domain), without an API key.

    Use only for explicit DNS-only audits, not as a fallback for a failed email
    investigation or client audit. No DNS modifications. Evaluates MX, SPF
    (recursive include/redirect expansion with lookup counting), DMARC (with
    organizational-domain inheritance), DKIM by guessing common selectors plus any
    given (absence is not proof DKIM is missing), MTA-STS, TLS-RPT, BIMI and a
    DNSSEC signal. No blocklists, registration or message-header analysis; use
    audit_client_domain for those.
    """
    try:
        report = audit_dns(target, selectors=selectors)
    except ValueError as exc:
        return {"ok": False, "error": "invalid_input", "detail": str(exc)}
    return {"ok": True, "checked_at": datetime.now(UTC).isoformat(), "dns": report}


@mcp.tool(annotations=READ_ONLY)
def audit_client_domain(target: str, raw_headers: str | None = None,
                        selectors: list[str] | None = None,
                        sending_ips: list[str] | None = None) -> dict:
    """Full health audit of a client's sending domain, from one of its email addresses.

    Runs AbstractAPI reputation for the address plus DNS authentication (SPF, DMARC,
    DKIM, MX, MTA-STS, TLS-RPT, BIMI, DNSSEC), DNS blocklists for the domain and its
    self-hosted sending IPs, RDAP registration, and cross-checks. raw_headers is the
    pasted original source (or header block, at most 256 KB) of a message the client
    sent, as received; its DKIM selectors and sending IP feed the DNS and blocklist
    checks. sending_ips adds known sending IPs; selectors adds known DKIM selectors.
    Requires the API key and a working API. The reputation call runs first; setup or
    API failure returns no partial audit and makes no DNS, blocklist or RDAP request.
    The reputation section contains breach data; do not persist it.
    """
    try:
        if "@" not in target:
            raise ValueError("Provide one of the client's email addresses; use audit_domain "
                             "for a keyless DNS-only audit of a bare domain.")
        inputs = validate_inputs(target, raw_headers=raw_headers, selectors=selectors,
                                 sending_ips=sending_ips)
    except ValueError as exc:
        return {"ok": False, "error": "invalid_input", "detail": str(exc)}
    key = _get_api_key()
    if not key:
        return {"ok": False, "error": "setup_required", "setup_command": _setup_command()}
    # Reputation first: if the API call fails, nothing else (DNS, DNSBL, RDAP,
    # MTA-STS) is sent anywhere.
    reputation, _ = guard_secret(key, _reputation.check_reputation, inputs["target"], key)
    if not reputation or not reputation["source"]["ok"]:
        reputation = reputation or {"signals": {}, "source": {
            "ok": False, "error": "unexpected_error",
            "detail": "The reputation check failed unexpectedly; no assessment made."}}
        return {"ok": False, "error": "reputation_unavailable", **reputation}
    audit = run_audit(target, raw_headers=raw_headers, selectors=selectors,
                      sending_ips=sending_ips, reputation_result=reputation)
    return {"ok": True, **audit}


@mcp.tool(annotations={**READ_ONLY, "idempotentHint": True, "openWorldHint": False})
def analyze_headers(raw_headers: str) -> dict:
    """Parse a pasted received message (full source or header block, at most 256 KB).

    Local only: no API key and no network request. Returns the receiving provider's
    SPF/DKIM/DMARC/ARC/compauth results, From/Return-Path/DKIM d= alignment
    (relaxed), the Received chain and likely sending IP, List-Unsubscribe and
    one-click, and spam-filter headers (Microsoft BCL/SCL). Never returns the body,
    Subject or unsubscribe URLs. Use it to explain why one message bounced, landed in
    spam or failed DMARC, or whether a received message was spoofed. A copy from the
    sender's Sent folder has no receiver results.
    """
    try:
        report = headers.analyze_headers(raw_headers)
    except ValueError as exc:
        return {"ok": False, "error": "invalid_input", "detail": str(exc)}
    return {"ok": True, "checked_at": datetime.now(UTC).isoformat(), "headers": report}


@mcp.tool(annotations=READ_ONLY)
def check_blocklists(target: str, sending_ips: list[str] | None = None,
                     resolver: str | None = None) -> dict:
    """Check a domain (or an address's domain) and its sending IPs on DNS blocklists.

    No API key. Domain lists: Spamhaus DBL, SURBL, URIBL. IP lists: Spamhaus ZEN,
    Barracuda, SpamCop, PSBL. IPs come from sending_ips (at most 20) plus the
    domain's own SPF ip4/ip6/a/mx terms, each with PTR and forward-confirmed rDNS.
    Each zone is canary-tested: through a refused or public resolver its results are
    unknown (listed null), never clean. resolver is an optional resolver IP (a local
    or ISP resolver) to re-check through; the default is the machine's resolver.
    """
    try:
        if resolver is not None and not _dns.is_valid_resolver(resolver):
            raise ValueError("resolver must be an IP address.")
        report = blocklists.build_output(target, sending_ips or (), resolver)
    except ValueError as exc:
        return {"ok": False, "error": "invalid_input", "detail": str(exc)}
    return {"ok": True, "checked_at": datetime.now(UTC).isoformat(), "blocklists": report}


@mcp.tool(annotations=READ_ONLY)
def check_registration(target: str) -> dict:
    """Read the RDAP registration of a domain's organizational domain via rdap.org.

    No API key. Returns registrar, created/expires, days_until_expiry, EPP statuses
    with on_hold / pending_delete / transfer_locked flags, nameservers and the DNSSEC
    delegation. Use it when a domain's mail or website stopped resolving, or to
    check renewal risk. source.error not_found_or_no_rdap means unregistered or no
    RDAP service (common for ccTLDs): check the registry's WHOIS instead.
    """
    try:
        report = registration.build_output(target)
    except ValueError as exc:
        return {"ok": False, "error": "invalid_input", "detail": str(exc)}
    return {"ok": True, "checked_at": datetime.now(UTC).isoformat(), **report}
