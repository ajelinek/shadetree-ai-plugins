"""Shared domain-name helpers.

normalize_domain / normalize_email / domain_from_arg / validate_selectors are
strict validators for user input and raise ValueError. bare_domain is the
lenient normalizer for header- and record-derived values and never raises.

org_domain() approximates the DMARC "organizational domain" without the full
Public Suffix List: it keeps the last two labels, or the last three when the
last two form a known multi-part public suffix (co.uk, com.au, ...). Not a
PSL replacement. org_domain_is_approximate() flags results under a two-letter
country-code TLD, where unlisted second-level registries can make it wrong.
"""

from __future__ import annotations

import re

LABEL_RE = re.compile(r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?")
LOCAL_RE = re.compile(r"[a-zA-Z0-9!#$%&'*+/=?^_`{|}~.-]+")
# Hostname shape: LDH labels of 1-63 chars, at least two labels.
DOMAIN_RE = re.compile(
    r"^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
    r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$"
)
MAX_USER_SELECTORS = 20
MAX_SELECTOR_LENGTH = 128

MULTI_PART_SUFFIXES = frozenset({
    "co.uk", "org.uk", "ac.uk", "gov.uk", "ltd.uk", "plc.uk", "me.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.nz", "org.nz", "net.nz",
    "co.jp", "ne.jp", "or.jp",
    "com.br", "com.mx", "com.ar", "com.co",
    "co.za", "co.in", "co.il", "co.kr",
    "com.sg", "com.hk", "com.tw", "com.cn", "com.tr",
    # Europe
    "com.pl", "net.pl", "org.pl", "co.at", "or.at", "gv.at", "co.hu",
    "com.es", "org.es", "com.gr", "com.cy", "com.mt", "com.ro", "com.hr",
    "com.ua", "net.ua", "org.ua", "co.rs", "org.rs",
    "com.ru", "net.ru", "org.ru",
    # Asia / Pacific
    "co.th", "in.th", "com.my", "com.vn", "com.ph", "co.id", "or.id",
    "net.in", "org.in", "com.np", "com.bd", "com.lk", "com.pk", "com.kh", "com.mm",
    "ac.jp", "go.jp", "gr.jp", "ad.jp", "lg.jp",
    "ac.nz", "asn.au", "id.au",
    # Middle East
    "org.il", "ac.il", "com.sa", "com.qa", "com.kw", "com.om", "com.bh",
    "com.jo", "com.lb",
    # Africa
    "org.za", "ac.za", "gov.za", "com.ng", "com.eg", "co.ke", "co.tz", "co.ug", "com.gh",
    # Americas
    "org.br", "net.br", "gob.mx", "org.mx", "net.mx",
    "com.pe", "com.ve", "co.ve", "com.ec", "com.uy", "co.cr", "com.do", "com.gt",
    "com.pa", "com.py", "com.bo", "com.sv", "com.ni", "com.hn",
})


def normalize_domain(value: str) -> str:
    """Strict: an IDNA-encoded, lower-case FQDN, or ValueError."""
    if not value or any(char.isspace() or ord(char) < 32 for char in value):
        raise ValueError("Provide a domain name without spaces, URLs, or paths.")
    try:
        domain = value.encode("idna").decode("ascii").lower()
    except UnicodeError:
        raise ValueError("Invalid internationalized domain name.") from None
    if len(domain) > 253 or "." not in domain or not all(
        LABEL_RE.fullmatch(label) for label in domain.split(".")
    ):
        raise ValueError("Provide a valid fully qualified domain name, not a URL or IP address.")
    if all(label.isdigit() for label in domain.split(".")):
        raise ValueError("Provide a domain name, not an IP address.")
    return domain


def normalize_email(value: str) -> str:
    """Strict: one ordinary unquoted address with a normalized domain, or ValueError."""
    if value.count("@") != 1:
        raise ValueError("Provide one email address, without a display name or message text.")
    local, domain = value.split("@")
    if not LOCAL_RE.fullmatch(local) or len(local) > 64 or local.startswith(".") or (
        local.endswith(".") or ".." in local
    ):
        raise ValueError("Unsupported email format; provide one ordinary, unquoted email address.")
    email = f"{local}@{normalize_domain(domain)}"
    if len(email) > 254:
        raise ValueError("Email address is too long.")
    return email


def domain_from_arg(value: str) -> str:
    """The domain of an email address or bare domain (strict)."""
    return normalize_email(value).rsplit("@", 1)[1] if "@" in value else normalize_domain(value)


def is_valid_selector(selector) -> bool:
    """A DKIM selector: dot-separated DNS labels, at most 128 characters."""
    return (isinstance(selector, str) and bool(selector)
            and len(selector) <= MAX_SELECTOR_LENGTH
            and all(LABEL_RE.fullmatch(label) for label in selector.split(".")))


def validate_selectors(selectors: list[str] | None) -> list[str]:
    """At most 20 user-supplied DKIM selectors (DNS labels); returns them
    lower-cased and de-duplicated. The built-in list is added by dns_auth."""
    if selectors is not None and (len(selectors) > MAX_USER_SELECTORS or any(
        not is_valid_selector(selector) for selector in selectors
    )):
        raise ValueError(
            "Supply at most 20 DKIM selector names (DNS labels, at most 128 characters)."
        )
    return list(dict.fromkeys(selector.lower() for selector in selectors or ()))


def bare_domain(value) -> str:
    """Lenient: lower-case, strip whitespace/trailing dot, drop any local part."""
    value = (value or "").strip().lower().rstrip(".")
    if "@" in value:
        value = value.rsplit("@", 1)[-1]
    return value


def is_valid_domain(domain) -> bool:
    return bool(DOMAIN_RE.match(domain or ""))


def org_domain(domain) -> str:
    labels = bare_domain(domain).split(".")
    if len(labels) <= 2:
        return ".".join(labels)
    if ".".join(labels[-2:]) in MULTI_PART_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def org_domain_is_approximate(domain) -> bool:
    """True when org_domain() may be wrong: the TLD is a two-letter ccTLD."""
    tld = bare_domain(domain).rsplit(".", 1)[-1]
    return len(tld) == 2 and tld.isalpha()


def aligned(domain_a, domain_b, mode: str = "r") -> bool:
    """DMARC identifier alignment: strict = exact match, relaxed = same org domain."""
    a, b = bare_domain(domain_a), bare_domain(domain_b)
    if not a or not b:
        return False
    if mode == "s":
        return a == b
    return org_domain(a) == org_domain(b)
