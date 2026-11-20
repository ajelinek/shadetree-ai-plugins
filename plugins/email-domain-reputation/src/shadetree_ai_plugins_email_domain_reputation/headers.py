"""Parse the headers of a test message that a client domain sent to a mailbox
you control, and report what the RECEIVING provider concluded (SPF / DKIM /
DMARC / ARC / compauth), alignment against the From domain, the sending IP,
unsubscribe headers, and spam-filter headers.

DNS (dns_auth) shows what a domain publishes; only a received message shows
what passed and whether it aligned. Use the full source saved from the
recipient mailbox (Gmail "Show original"; Outlook "View message source").
Headers copied from the SENDER's Sent folder have no Authentication-Results.

Parse and normalize only -- no pass/fail verdict or severity is computed here.
The message body is never parsed into the output, and the Subject and the
List-Unsubscribe URLs are never echoed.

API:
    analyze_headers(raw)  validate pasted text (str, non-empty, at most 256 KB as
                          UTF-8, at least one recognizable header field) and
                          return build_output(); raises ValueError otherwise.
                          Accepts headers-only text or a full message, LF or
                          CRLF, with leading blank lines or a common indent.
    parse_message(data)   bytes or str -> Message (headers only), or None when
                          no recognizable header field is present.
    build_output(msg)     -> dict described below.

Output keys:
    from                       {address, domain, org_domain}
    return_path                {address, domain}   (top-most Return-Path)
    message_id_domain          domain part of Message-ID
    subject_present            bool
    authentication_results     every Authentication-Results header, top-most
                               first: {authserv_id, spf: {result,
                               smtp_mailfrom, client_ip}, dkim: [{result,
                               header_d, header_i, header_s}], dmarc:
                               {result, policy, action, header_from}, arc,
                               compauth: {result, reason}}; absent methods
                               are null / []
    arc_authentication_results same shape plus "instance" (ARC i=)
    received_spf               top-most Received-SPF: {result, client_ip}
    receiver_verdict           summary of the top-most Authentication-Results
                               (the receiving provider's): {authserv_id, spf,
                               dkim (pass if any dkim=pass), dmarc, compauth};
                               null when there is none
    dkim_signatures            per DKIM-Signature header: {d, s, a, i,
                               h_includes_from, aligned_relaxed,
                               aligned_strict, receiver_result}; alignment is
                               vs the From domain, receiver_result is the
                               matching dkim= result in receiver_verdict's
                               header (null if not found)
    selectors                  s= of signatures whose d= is relaxed-aligned
                               with From (look them up under that d=):
                               lower-cased, valid DNS labels only, at most
                               the first 20 distinct (the rest are dropped
                               with an invalid_dkim_selector /
                               too_many_dkim_selectors warning)
    alignment                  {spf_domain, spf_aligned, spf_pass_aligned,
                               dkim_aligned, dkim_aligned_domains}: SPF uses
                               the receiver's smtp.mailfrom, falling back to
                               Return-Path; *_pass_aligned / dkim_aligned
                               require a receiver pass (null when there is no
                               Authentication-Results to say so). All RELAXED
                               alignment -- the domain's DMARC adkim/aspf may
                               be strict (build_alignment takes the modes)
    received_chain             Received hops top-down: {from_host, from_ip,
                               by_host, timestamp (ISO 8601 or null)}
    sending_ip / sending_host / sending_ip_source
                               best-effort public IP that handed the message
                               to the receiver (see below)
    list_unsubscribe           {present, mailto, https, one_click}
    list_id_present            bool -- a List-Id header exists
    list_id_domain             the id inside List-Id's angle brackets,
                               lower-cased, or null
    spam_headers               only the headers present: x_spam_status,
                               x_spam_score, x_spam_flag, x_microsoft_antispam
                               {bcl}, x_forefront_antispam_report {SFV, SCL,
                               CAT, IPV, SFTY, CIP, CTRY, PTR, H},
                               x_ms_exchange_organization_scl
    warnings                   parse issues, "code: explanation" strings

sending_ip heuristic, first source that yields a public IP wins:
    1. received_spf     -- client-ip= in the top-most Received-SPF
    2. authentication_results -- the IP in the receiver's spf= comment
    3. forefront_cip    -- CIP: in X-Forefront-Antispam-Report (Microsoft)
    4. received_chain   -- the run of hops from the top whose by_host shares
                           the org domain of the top-most named by_host (a bare
                           "by <IP>" hop counts as internal); the bottom-most of
                           that run is where the message entered, and its
                           from_ip (or the next public from_ip below) is used
    5. x_originating_ip / x_sender_ip -- last, often the end user's client IP
    Private, loopback, link-local, and CGNAT addresses are skipped.
    sending_host is the from_host of the Received hop with that from_ip.
"""

from __future__ import annotations

import email.message
import email.parser
import email.policy
import email.utils
import ipaddress
import re
import textwrap

from ._domain import MAX_USER_SELECTORS, aligned, bare_domain, is_valid_selector, org_domain

MAX_HEADER_BYTES = 256 * 1024
MAX_HEADER_SELECTORS = MAX_USER_SELECTORS

# Any of these makes the input a message header block rather than random text.
KNOWN_HEADERS = (
    "from", "received", "authentication-results", "dkim-signature",
    "return-path", "message-id", "arc-authentication-results",
)

FOREFRONT_KEYS = ("SFV", "SCL", "CAT", "IPV", "SFTY", "CIP", "CTRY", "PTR", "H")

# ipaddress.is_private / is_global also treat the documentation ranges
# (192.0.2/24, 198.51.100/24, 203.0.113/24, 2001:db8::/32) as non-public,
# which would hide every IP in example headers -- so list the ranges that
# genuinely never identify a sender on the internet instead.
NON_PUBLIC_NETWORKS = tuple(ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10",
    "127.0.0.0/8", "169.254.0.0/16", "0.0.0.0/8",
    "::1/128", "fc00::/7", "fe80::/10", "::/128",
))

IP_CANDIDATE_RE = re.compile(
    r"(?<![\w.:-])(\d{1,3}(?:\.\d{1,3}){3}|[0-9A-Fa-f]{0,4}:[0-9A-Fa-f:.]*[0-9A-Fa-f])(?![\w.:-])"
)


# --- small helpers ---------------------------------------------------------

def unfold(value):
    """Join folded header lines and collapse whitespace."""
    return " ".join(str(value).split())


def header_values(msg, name):
    return [unfold(v) for v in (msg.get_all(name) or [])]


def first_header(msg, name):
    values = header_values(msg, name)
    return values[0] if values else None


def parse_ip(text):
    try:
        return ipaddress.ip_address((text or "").strip().strip("[]"))
    except ValueError:
        return None


def is_public_ip(ip):
    return ip is not None and not any(ip in net for net in NON_PUBLIC_NETWORKS
                                      if net.version == ip.version)


def find_ips(text):
    """Valid IP addresses appearing in free text, in order."""
    text = re.sub(r"(?i)ipv6:", "", text or "")
    return [ip for ip in (parse_ip(m) for m in IP_CANDIDATE_RE.findall(text)) if ip]


def first_public_ip(text):
    return next((ip for ip in find_ips(text) if is_public_ip(ip)), None)


def address_domain(value):
    """(address, domain) from an address header value; Nones when absent."""
    if value is None:
        return None, None
    _, addr = email.utils.parseaddr(value)
    addr = addr.strip().lower() or None
    domain = bare_domain(addr) if addr and "@" in addr else None
    return addr, domain or None


# --- Authentication-Results ------------------------------------------------

def split_outside_comments(value, sep=";"):
    """Split on `sep` except inside (comments) or "quoted strings"."""
    parts, buf, depth, quoted = [], [], 0, False
    for ch in value:
        if ch == '"' and depth == 0:
            quoted = not quoted
        elif not quoted and ch == "(":
            depth += 1
        elif not quoted and ch == ")" and depth:
            depth -= 1
        if ch == sep and depth == 0 and not quoted:
            parts.append("".join(buf).strip())
            buf = []
        else:
            buf.append(ch)
    parts.append("".join(buf).strip())
    return [p for p in parts if p]


def strip_comments(text):
    """Return (text without comments, [comment texts]).

    One linear pass: each balanced "(...)" (innermost first, in closing order)
    becomes a space; an unbalanced parenthesis stays as text."""
    comments, out, opens = [], [], []
    for ch in text:
        if ch == "(":
            opens.append(len(out))
            out.append(ch)
        elif ch == ")" and opens:
            start = opens.pop()
            comments.append("".join(out[start + 1:]).strip())
            del out[start:]
            out.append(" ")
        else:
            out.append(ch)
    return " ".join("".join(out).split()), comments


def parse_method(segment):
    """'dkim=pass (c) header.d=x' -> (method, result, props, comments)."""
    text, comments = strip_comments(segment)
    tokens = text.split()
    if not tokens or "=" not in tokens[0]:
        return None
    method, _, result = tokens[0].partition("=")
    props = {}
    for token in tokens[1:]:
        key, eq, val = token.partition("=")
        if eq:
            props[key.lower()] = val.strip('"')
    return method.lower(), result.lower(), props, comments


def parse_auth_results(value, arc=False):
    segments = split_outside_comments(value)
    parsed = {}
    if arc:
        parsed["instance"] = None
        if segments and re.fullmatch(r"i\s*=\s*\d+", segments[0]):
            parsed["instance"] = int(segments.pop(0).split("=")[1])
    parsed.update({"authserv_id": None, "spf": None, "dkim": [], "dmarc": None,
                   "arc": None, "compauth": None})
    if segments and "=" not in strip_comments(segments[0])[0].split(" ")[0]:
        parsed["authserv_id"] = strip_comments(segments.pop(0))[0].split(" ")[0].lower() or None

    for segment in segments:
        method = parse_method(segment)
        if method is None:
            continue  # e.g. "none"
        name, result, props, comments = method
        if name == "spf" and parsed["spf"] is None:
            comment_text = " ".join(comments)
            ip = first_public_ip(comment_text) or next(iter(find_ips(comment_text)), None)
            parsed["spf"] = {"result": result, "smtp_mailfrom": props.get("smtp.mailfrom"),
                             "client_ip": str(ip) if ip else None}
        elif name == "dkim":
            parsed["dkim"].append({"result": result, "header_d": props.get("header.d"),
                                   "header_i": props.get("header.i"),
                                   "header_s": props.get("header.s")})
        elif name == "dmarc" and parsed["dmarc"] is None:
            policy = props.get("policy.published-domain-policy")
            if policy is None:
                match = re.search(r"(?i)\bp=(\w+)", " ".join(comments))
                policy = match.group(1) if match else None
            parsed["dmarc"] = {"result": result, "policy": policy.lower() if policy else None,
                               "action": props.get("action"),
                               "header_from": props.get("header.from")}
        elif name == "arc" and parsed["arc"] is None:
            parsed["arc"] = result
        elif name == "compauth" and parsed["compauth"] is None:
            parsed["compauth"] = {"result": result, "reason": props.get("reason")}
    return parsed


def dkim_entry_domain(entry):
    return bare_domain(entry.get("header_d") or entry.get("header_i") or "") or None


def receiver_verdict(auth_results):
    if not auth_results:
        return None
    top = auth_results[0]
    dkim_results = [d["result"] for d in top["dkim"]]
    dkim = "pass" if "pass" in dkim_results else (dkim_results[0] if dkim_results else None)
    return {
        "authserv_id": top["authserv_id"],
        "spf": top["spf"]["result"] if top["spf"] else None,
        "dkim": dkim,
        "dmarc": top["dmarc"]["result"] if top["dmarc"] else None,
        "compauth": top["compauth"]["result"] if top["compauth"] else None,
    }


def parse_received_spf(value):
    if value is None:
        return None
    match = re.search(r"(?i)client-ip=([0-9A-Fa-f:.]+)", value)
    ip = parse_ip(match.group(1).rstrip(".")) if match else None
    return {"result": value.split()[0].lower(), "client_ip": str(ip) if ip else None}


# --- DKIM-Signature --------------------------------------------------------

def parse_tag_list(value):
    tags = {}
    for part in value.split(";"):
        key, eq, val = part.partition("=")
        if eq:
            tags[key.strip().lower()] = "".join(val.split())
    return tags


def parse_dkim_signatures(values, from_domain, verdict_dkim):
    signatures = []
    for value in values:
        tags = parse_tag_list(value)
        d = bare_domain(tags.get("d")) or None
        s = tags.get("s") or None
        signed = [h.strip().lower() for h in tags.get("h", "").split(":") if h.strip()]
        receiver_result = None
        for entry in verdict_dkim:
            same_selector = entry.get("header_s") in (None, s)
            if d and dkim_entry_domain(entry) == d and same_selector:
                receiver_result = entry["result"]
                break
        signatures.append({
            "d": d, "s": s, "a": tags.get("a"), "i": tags.get("i"),
            "h_includes_from": "from" in signed,
            "aligned_relaxed": aligned(d, from_domain, "r"),
            "aligned_strict": aligned(d, from_domain, "s"),
            "receiver_result": receiver_result,
        })
    return signatures


def build_alignment(from_domain, return_path_domain, auth_results, aspf="r", adkim="r"):
    """Alignment vs From; aspf / adkim are DMARC modes ("r" relaxed, "s" strict)."""
    top = auth_results[0] if auth_results else None
    spf = top["spf"] if top else None
    spf_domain = bare_domain(spf["smtp_mailfrom"]) if spf and spf.get("smtp_mailfrom") else None
    spf_domain = spf_domain or return_path_domain
    spf_aligned = aligned(spf_domain, from_domain, aspf)
    dkim_domains = []
    if top:
        for entry in top["dkim"]:
            domain = dkim_entry_domain(entry)
            if entry["result"] == "pass" and aligned(domain, from_domain, adkim) \
                    and domain not in dkim_domains:
                dkim_domains.append(domain)
    return {
        "spf_domain": spf_domain,
        "spf_aligned": spf_aligned,
        "spf_pass_aligned": (spf_aligned and spf["result"] == "pass") if spf else None,
        "dkim_aligned": bool(dkim_domains) if top else None,
        "dkim_aligned_domains": dkim_domains,
    }


# --- Received chain / sending IP -------------------------------------------

def parse_received(value):
    body, _, date_part = value.rpartition(";")
    if not body:
        body, date_part = value, ""
    timestamp = None
    try:
        timestamp = email.utils.parsedate_to_datetime(date_part.strip()).isoformat()
    except (TypeError, ValueError, IndexError):
        pass
    from_host = from_ip = None
    by_match = re.search(r"(?i)(?:^|\s)by\s+(\S+)", body)
    from_match = re.match(r"(?i)\s*from\s+(\S+)", body)
    if from_match:
        from_host = from_match.group(1).rstrip(".").lower()
        end = by_match.start() if by_match and by_match.start() > from_match.end() else len(body)
        clause = body[from_match.end():end]
        ips = find_ips(clause) or find_ips(from_host)
        public = [ip for ip in ips if is_public_ip(ip)]
        chosen = public[0] if public else (ips[0] if ips else None)
        from_ip = str(chosen) if chosen else None
    by_host = by_match.group(1).rstrip(".").lower() if by_match else None
    return {"from_host": from_host, "from_ip": from_ip, "by_host": by_host, "timestamp": timestamp}


def chain_entry_ip(chain):
    # Gmail's top hops are "by <IPv6>" -- internal, but no org domain to compare.
    def receiver_hop(hop, org):
        by = hop["by_host"]
        return bool(by) and (parse_ip(by) is not None or org_domain(by) == org)

    receiver_org = next((org_domain(hop["by_host"]) for hop in chain
                         if hop["by_host"] and parse_ip(hop["by_host"]) is None), None)
    if not receiver_org or not receiver_hop(chain[0], receiver_org):
        return None
    entry = 0
    while entry + 1 < len(chain) and receiver_hop(chain[entry + 1], receiver_org):
        entry += 1
    for hop in chain[entry:]:
        if is_public_ip(parse_ip(hop["from_ip"])):
            return hop["from_ip"]
    return None


def find_sending_ip(msg, received_spf, auth_results, forefront, chain):
    candidates = [
        ("received_spf", received_spf["client_ip"] if received_spf else None),
        ("authentication_results",
         auth_results[0]["spf"]["client_ip"] if auth_results and auth_results[0]["spf"] else None),
        ("forefront_cip", (forefront or {}).get("CIP")),
        ("received_chain", chain_entry_ip(chain)),
        ("x_originating_ip", first_header(msg, "X-Originating-IP")),
        ("x_sender_ip", first_header(msg, "X-Sender-IP")),
    ]
    for source, raw in candidates:
        ip = first_public_ip(raw) if raw else None
        if ip:
            host = next((hop["from_host"] for hop in chain if hop["from_ip"] == str(ip)), None)
            return str(ip), host, source
    return None, None, None


# --- List-Unsubscribe / spam headers ---------------------------------------

def parse_list_unsubscribe(msg):
    value = (first_header(msg, "List-Unsubscribe") or "").lower()
    post = (first_header(msg, "List-Unsubscribe-Post") or "").lower()
    return {
        "present": bool(value),
        "mailto": "<mailto:" in value,
        "https": "<https:" in value,
        "one_click": "list-unsubscribe=one-click" in post.replace(" ", ""),
    }


def parse_list_id(msg):
    """-> (present, id inside the angle brackets or None)."""
    value = first_header(msg, "List-Id")
    if value is None:
        return False, None
    match = re.search(r"<([^<>\s]+)>", value)
    return True, bare_domain(match.group(1)) if match else None


def parse_colon_pairs(value):
    pairs = {}
    for part in value.split(";"):
        key, sep, val = part.partition(":")
        if sep and key.strip():
            pairs[key.strip().upper()] = val.strip()
    return pairs


def as_int(value):
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return value


def parse_spam_headers(msg):
    spam = {}
    for name in ("X-Spam-Status", "X-Spam-Score", "X-Spam-Flag"):
        value = first_header(msg, name)
        if value is not None:
            spam[name.lower().replace("-", "_")] = value
    antispam = first_header(msg, "X-Microsoft-Antispam")
    if antispam is not None:
        spam["x_microsoft_antispam"] = {"bcl": as_int(parse_colon_pairs(antispam).get("BCL"))}
    forefront = first_header(msg, "X-Forefront-Antispam-Report")
    if forefront is not None:
        pairs = parse_colon_pairs(forefront)
        spam["x_forefront_antispam_report"] = {
            k: (as_int(pairs[k]) if k == "SCL" else pairs[k]) for k in FOREFRONT_KEYS if k in pairs
        }
    scl = first_header(msg, "X-MS-Exchange-Organization-SCL")
    if scl is not None:
        spam["x_ms_exchange_organization_scl"] = as_int(scl)
    return spam


# --- assembly --------------------------------------------------------------

def parse_message(data: bytes | str) -> email.message.Message | None:
    """Headers-only parse; None when no recognizable header field is present."""
    if isinstance(data, bytes):
        msg = email.parser.BytesParser(policy=email.policy.compat32).parsebytes(
            data.lstrip(b" \t\r\n"), headersonly=True)
    else:
        text = textwrap.dedent(data.replace("\r\n", "\n").replace("\r", "\n")).lstrip()
        msg = email.parser.Parser(policy=email.policy.compat32).parsestr(text, headersonly=True)
    if not any(msg.get(name) is not None for name in KNOWN_HEADERS):
        return None
    return msg


def header_selectors(signatures):
    """-> (selectors, warnings): the first MAX_HEADER_SELECTORS distinct,
    lower-cased s= values of relaxed-aligned signatures that are valid DNS
    labels; invalid and overflow selectors are dropped with a warning."""
    selectors, invalid, extra = [], 0, set()
    for sig in signatures:
        selector = sig["s"]
        if not sig["aligned_relaxed"] or not selector:
            continue
        if not is_valid_selector(selector):
            invalid += 1
            continue
        selector = selector.lower()
        if selector in selectors:
            continue
        if len(selectors) < MAX_HEADER_SELECTORS:
            selectors.append(selector)
        else:
            extra.add(selector)
    warnings = []
    if invalid:
        warnings.append(f"invalid_dkim_selector: {invalid} aligned DKIM selector(s) are not "
                        "valid DNS labels and were not checked")
    if extra:
        warnings.append(f"too_many_dkim_selectors: {len(extra)} more aligned DKIM selector(s) "
                        f"beyond the first {MAX_HEADER_SELECTORS} were not checked")
    return selectors, warnings


def build_output(msg: email.message.Message) -> dict:
    warnings = []
    from_values = header_values(msg, "From")
    if len(from_values) > 1:
        warnings.append("multiple_from: more than one From header; the first is used")
    from_addr, from_domain = address_domain(from_values[0] if from_values else None)
    if not from_domain:
        warnings.append("no_from_domain: no parseable From address; alignment can't be computed")
    rp_addr, rp_domain = address_domain(first_header(msg, "Return-Path"))
    _, mid_domain = address_domain(first_header(msg, "Message-ID"))

    auth_results = [parse_auth_results(v) for v in header_values(msg, "Authentication-Results")]
    if not auth_results:
        warnings.append("no_authentication_results: the receiver's verdict is missing -- the "
                        "headers may have been copied from the sender's Sent folder, or "
                        "truncated; use the copy saved from the recipient mailbox")
    arc_results = [parse_auth_results(v, arc=True)
                   for v in header_values(msg, "ARC-Authentication-Results")]
    received_spf = parse_received_spf(first_header(msg, "Received-SPF"))
    verdict = receiver_verdict(auth_results)

    dkim_values = header_values(msg, "DKIM-Signature")
    if not dkim_values:
        warnings.append("no_dkim_signature: the message carries no DKIM-Signature header")
    signatures = parse_dkim_signatures(dkim_values, from_domain,
                                       auth_results[0]["dkim"] if auth_results else [])
    selectors, selector_warnings = header_selectors(signatures)
    warnings += selector_warnings

    chain = [parse_received(v) for v in header_values(msg, "Received")]
    if not chain:
        warnings.append("no_received_headers: no Received headers; "
                        "sending IP relies on other headers")
    spam = parse_spam_headers(msg)
    sending_ip, sending_host, ip_source = find_sending_ip(
        msg, received_spf, auth_results, spam.get("x_forefront_antispam_report"), chain)
    if not sending_ip:
        warnings.append("no_sending_ip: no public sending IP found in the headers")

    list_id_present, list_id_domain = parse_list_id(msg)
    return {
        "from": {"address": from_addr, "domain": from_domain,
                 "org_domain": org_domain(from_domain) if from_domain else None},
        "return_path": {"address": rp_addr, "domain": rp_domain},
        "message_id_domain": mid_domain,
        "subject_present": msg.get("Subject") is not None,
        "authentication_results": auth_results,
        "arc_authentication_results": arc_results,
        "received_spf": received_spf,
        "receiver_verdict": verdict,
        "dkim_signatures": signatures,
        "selectors": selectors,
        "alignment": build_alignment(from_domain, rp_domain, auth_results),
        "received_chain": chain,
        "sending_ip": sending_ip,
        "sending_host": sending_host,
        "sending_ip_source": ip_source,
        "list_unsubscribe": parse_list_unsubscribe(msg),
        "list_id_present": list_id_present,
        "list_id_domain": list_id_domain,
        "spam_headers": spam,
        "warnings": warnings,
    }


def analyze_headers(raw: str) -> dict:
    """Validate pasted message headers (or a full message) and return build_output()."""
    if not isinstance(raw, str):
        raise ValueError("Provide the message headers as text.")
    if not raw.strip():
        raise ValueError("The message headers are empty.")
    if len(raw.encode("utf-8", "surrogatepass")) > MAX_HEADER_BYTES:
        raise ValueError("The message headers exceed 256 KB; paste only the header block.")
    msg = parse_message(raw)
    if msg is None:
        raise ValueError("No recognizable message headers (From, Received, "
                         "Authentication-Results, ...) were found.")
    return build_output(msg)
