"""Interactive credential setup: walk every credential, store in the keychain, validate.

Run in your own terminal (never through Claude's shell tool):

    uv run --project <plugin dir> --locked python -m shadetree_ai_plugins_website_health doctor
    ... doctor --only bing-api-key        # one credential
    ... doctor --no-validate              # skip the live checks

Values are read with hidden prompts (or, for the service-account key, from a file
path) and are never echoed, logged, or passed as arguments.
"""

from __future__ import annotations

import argparse
import getpass
import sys
import warnings
from collections.abc import Callable
from pathlib import Path

from shadetree_ai_plugins_common.secret_setup import read_json_credential
from shadetree_ai_plugins_common.secrets import (
    SecretStoreError,
    delete_secret,
    get_secret,
    set_secret,
)

from . import config, credentials, google_auth, http
from .credentials import NAMESPACE, Credential
from .sources import bing, crux, ga4, gsc


def _clean(value: str) -> bool:
    return bool(value) and value.isascii() and not any(ord(c) <= 32 or ord(c) == 127
                                                       for c in value)


def validate_google_sa(_: str, sites: dict) -> str:
    google_auth.clear_cache()
    props = {p["ga4PropertyId"] for p in ga4.discover()}
    gsc_sites = {s["gscSiteUrl"] for s in gsc.discover()}
    email = google_auth.service_account_email()
    lines = [f"{email}: sees {len(props)} GA4 properties, {len(gsc_sites)} Search Console sites"]
    for name, site in sites.items():
        if site.get("ga4PropertyId") and site["ga4PropertyId"] not in props:
            lines.append(f"  ! {name}: GA4 property {site['ga4PropertyId']} not visible - add "
                         f"{email} as Viewer in GA4 Admin > Property access management")
        if site.get("gscSiteUrl") and site["gscSiteUrl"] not in gsc_sites:
            lines.append(f"  ! {name}: {site['gscSiteUrl']} not visible - add {email} in Search "
                         "Console > Settings > Users and permissions")
    return "\n".join(lines)


def validate_api_key(value: str, sites: dict) -> str:
    http.request("POST", f"{crux.BASE}:queryRecord", secret_params={"key": value},
                 json_body={"origin": "https://developer.chrome.com"})
    return "CrUX query succeeded (also enable PageSpeed Insights + Safe Browsing APIs)"


def validate_bing(value: str, sites: dict) -> str:
    found = {(s.get("Url") or "").rstrip("/") for s in (bing.call("GetUserSites", value) or [])}
    lines = [f"key sees {len(found)} site(s)"]
    for name, site in sites.items():
        if site.get("bingSiteUrl") and site["bingSiteUrl"].rstrip("/") not in found:
            lines.append(f"  ! {name}: {site['bingSiteUrl']} not in this key's sites - add the "
                         "key's user in Bing Webmaster Tools > Settings > Users")
    return "\n".join(lines)


def validate_clarity(value: str, sites: dict) -> str:
    if value.count(".") != 2:
        raise http.HttpError("That doesn't look like a Clarity token (expected a JWT).")
    return "format ok (not called: every call uses 1 of Clarity's 10 daily requests)"


VALIDATORS: dict[str, Callable[[str, dict], str]] = {
    "google-service-account": validate_google_sa,
    "google-api-key": validate_api_key,
    "bing-api-key": validate_bing,
    "clarity-token": validate_clarity,
}


def items(sites: dict, only: str | None) -> list[tuple[Credential, str | None]]:
    out: list[tuple[Credential, str | None]] = []
    for cred in credentials.CREDENTIALS:
        if cred.per_site:
            names = [n for n, s in sites.items() if s.get("clarityProjectId")] or []
            out += [(cred, n) for n in names]
            if not names and (only in (None, cred.key)):
                print(f"- {cred.label}: no site has clarityProjectId yet; configure a site "
                      "first (configure_site), then rerun doctor.")
        else:
            out.append((cred, None))
    if only:
        out = [(c, s) for c, s in out if only in (c.key, c.keychain_key(s), *c.sources)]
    return out


def prompt_value(cred: Credential) -> tuple[str | None, Path | None]:
    """Return (value, file to delete after a verified save)."""
    if cred.kind == "file":
        raw = input("  Path to the downloaded JSON key (Enter to skip): ").strip()
        if not raw:
            return None, None
        path = Path(raw).expanduser()
        value = read_json_credential(path)
        if '"service_account"' not in value:
            raise ValueError("That JSON file is not a service-account key.")
        delete = input(f"  Delete {path} after storing it? Type yes: ") == "yes"
        return value, path if delete else None
    with warnings.catch_warnings():
        warnings.simplefilter("error", getpass.GetPassWarning)
        value = getpass.getpass("  Paste value (hidden, Enter to skip): ").strip()
        if not value:
            return None, None
        if getpass.getpass("  Paste again to confirm (hidden): ").strip() != value:
            raise ValueError("Values didn't match.")
    if not _clean(value):
        raise ValueError("Values must contain no spaces or control characters.")
    return value, None


def run_item(cred: Credential, site: str | None, sites: dict, validate: bool) -> str:
    key = cred.keychain_key(site)
    label = cred.label + (f" [{site}]" if site else "")
    existing = get_secret(NAMESPACE, key)
    print(f"\n{label}\n  status: {'stored' if existing else 'missing'}"
          f"   used by: {', '.join(cred.sources)}")
    if existing:
        choice = input("  [Enter] keep  [v] validate  [r] replace  [d] delete: ").strip().lower()
        if choice == "d":
            if input("  Remove it? Type yes: ") == "yes":
                delete_secret(NAMESPACE, key)
                return f"{label}: deleted"
            return f"{label}: kept"
        if choice == "v":
            return f"{label}: " + check(cred, existing, sites)
        if choice != "r":
            return f"{label}: kept"
    print(f"  where: {cred.where}")
    try:
        value, delete_path = prompt_value(cred)
    except ValueError as exc:
        return f"{label}: not saved ({exc})"
    if not value:
        return f"{label}: skipped" if not existing else f"{label}: kept"
    set_secret(NAMESPACE, key, value)
    if get_secret(NAMESPACE, key) != value:
        raise SecretStoreError("Credential storage could not be verified.")
    if delete_path:
        delete_path.unlink(missing_ok=True)
    result = f"{label}: saved to keychain"
    if validate:
        result += "; " + check(cred, value, sites)
    return result


def check(cred: Credential, value: str, sites: dict) -> str:
    try:
        return "valid - " + VALIDATORS[cred.key](value, sites)
    except (http.HttpError, google_auth.GoogleAuthError) as exc:
        return f"FAILED - {exc}"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="doctor", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--only", help="One credential key or source name")
    parser.add_argument("--no-validate", action="store_true", help="Skip live validation")
    args = parser.parse_args(argv)
    if not sys.stdin.isatty():
        print("Run doctor yourself in an interactive terminal.", file=sys.stderr)
        return 1
    try:
        sites = config.load()["sites"]
    except config.ConfigError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    todo = items(sites, args.only)
    if not todo:
        print("Nothing matched --only.", file=sys.stderr)
        return 1
    print("website-health doctor - credentials go to the OS keychain only.")
    print(f"Sites configured: {', '.join(sites) or 'none yet'}")
    results = []
    try:
        for cred, site in todo:
            results.append(run_item(cred, site, sites, not args.no_validate))
    except (KeyboardInterrupt, EOFError):
        print("\nStopped; credentials saved so far are kept.")
    except SecretStoreError as exc:
        print(f"\nKeychain error: {exc}", file=sys.stderr)
        return 1
    print("\nSummary")
    for line in results:
        print(f"  {line}")
    return 0
