"""Small helpers shared by the check modules."""


def add_error(errors: dict, section: str, message: str) -> None:
    """Append `message` to errors[section], joining repeats with "; "."""
    errors[section] = f"{errors[section]}; {message}" if errors.get(section) else message


def mechanism_target(mechanism: dict, domain: str) -> str:
    """Domain an SPF a/mx/exists/include mechanism looks up (CIDR suffix
    removed). `mechanism` is an entry from dns_auth.parse_spf_terms."""
    value = mechanism["value"]
    if mechanism["name"] in ("a", "mx"):
        if not value or "/" in mechanism["term"].split(":", 1)[0]:
            return domain
        value = value.split("/", 1)[0]
    return (value or domain).lower().rstrip(".")
