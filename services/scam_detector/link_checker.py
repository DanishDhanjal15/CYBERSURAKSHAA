"""
services/scam_detector/link_checker.py
--------------------------------------
Extracts URLs from a message and checks domain age using python-whois.
A domain younger than 6 months is considered high-risk (newly registered
scam domains are a classic red flag in financial fraud).
"""

import ipaddress
import re
import datetime
import socket
import threading
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
from typing import Tuple
from urllib.parse import urlparse

try:
    import whois
except ImportError:
    whois = None  # Graceful degradation if library not installed

try:
    import requests
except ImportError:
    requests = None


# Regex pattern to extract URLs (http / https / bare domains)
URL_PATTERN = re.compile(
    r"(https?://[^\s]+|www\.[^\s]+|\b[a-zA-Z0-9\-]+\.[a-zA-Z]{2,}(?:/[^\s]*)?)",
    re.IGNORECASE,
)

# The bare-domain branch of URL_PATTERN also matches ordinary prose written
# without a space after a full stop — "Invest now.Guaranteed returns" yields
# "now.Guaranteed". Each such phantom domain used to cost a redirect probe plus
# a WHOIS query, so a single message could block the worker for minutes.
# Requiring a plausible TLD removes nearly all of them.
KNOWN_TLDS = {
    "com", "net", "org", "in", "co", "io", "me", "app", "dev", "ai", "xyz",
    "info", "biz", "club", "online", "site", "shop", "store", "live", "link",
    "top", "vip", "win", "bet", "cash", "fund", "money", "trade", "capital",
    "tk", "ml", "ga", "cf", "gq", "ru", "cn", "uk", "us", "eu", "pk", "bd",
    "lk", "np", "ae", "sg", "my", "id", "ph", "edu", "gov", "int", "pro",
}

# Hard limits so one message can never fan out into an unbounded number of
# outbound network calls.
MAX_URLS_CHECKED = 5
RESOLVE_TIMEOUT_SECONDS = 5
WHOIS_TIMEOUT_SECONDS = 6

# Threshold in days for "newly registered" domain risk
DOMAIN_AGE_THRESHOLD_DAYS = 180  # 6 months

# Risk score added when a new domain is detected
NEW_DOMAIN_RISK_SCORE = 60

# Domain-age answers change on the order of days, so caching them removes
# almost all repeat WHOIS traffic.
_age_cache: dict[str, int | None] = {}
_age_cache_lock = threading.Lock()

# Long-lived pool used to bound WHOIS calls, which python-whois offers no
# timeout for. Daemon threads so a stuck lookup cannot keep the process alive.
_whois_pool = ThreadPoolExecutor(
    max_workers=4, thread_name_prefix="whois"
)


def _host_of(url: str) -> str:
    """Bare hostname for a URL that may or may not carry a scheme."""
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", url):
        url = "http://" + url
    return (urlparse(url).hostname or "").strip().lower()


def _looks_like_domain(candidate: str) -> bool:
    """True when the candidate ends in a plausible TLD."""
    host = _host_of(candidate)
    if not host or "." not in host:
        return False
    return host.rsplit(".", 1)[-1] in KNOWN_TLDS


def _extract_urls(text: str) -> list[str]:
    """
    Return a deduplicated, bounded list of plausible URLs found in the text.

    Order is preserved (set() previously randomised it, so which links got
    checked varied run to run) and the list is capped so a link-stuffed
    message cannot trigger unbounded outbound requests.
    """
    seen: dict[str, None] = {}
    for match in URL_PATTERN.findall(text):
        if _looks_like_domain(match):
            seen.setdefault(match, None)
    return list(seen)[:MAX_URLS_CHECKED]


def _is_public_host(host: str) -> bool:
    """False for hosts that resolve to private, loopback or reserved space."""
    if not host:
        return False
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return False
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_reserved or ip.is_multicast or ip.is_unspecified):
            return False
    return True


def _resolve_url(url: str) -> str:
    """
    Follow redirects to get the ultimate destination URL (e.g. unshorten bit.ly).

    Every hop is checked against _is_public_host first. Following redirects
    blindly turned this into a server-side request forgery primitive: the
    message author chose the address, and the server fetched it.
    """
    if not url.startswith("http"):
        url = "http://" + url
    if requests is None:
        return url
    if not _is_public_host(_host_of(url)):
        return url
    try:
        res = requests.head(
            url, allow_redirects=False, timeout=RESOLVE_TIMEOUT_SECONDS
        )
        hops = 0
        while (res.is_redirect or res.is_permanent_redirect) and hops < 5:
            nxt = requests.compat.urljoin(url, res.headers.get("Location", ""))
            if not _is_public_host(_host_of(nxt)):
                return url
            url = nxt
            hops += 1
            res = requests.head(
                url, allow_redirects=False, timeout=RESOLVE_TIMEOUT_SECONDS
            )
        return url
    except Exception:
        return url


def _whois_creation_date(domain: str):
    """Raw WHOIS call — always invoked through a timeout in the caller."""
    return whois.whois(domain).creation_date


def _get_domain_age_days(domain: str) -> int | None:
    """
    Query WHOIS data for the domain and return its age in days.
    Returns None if the lookup fails or data is unavailable.

    python-whois talks to port 43 and exposes no timeout of its own, so a
    slow or unresponsive registrar could hang the request thread indefinitely.
    The call is therefore run in a worker with a hard deadline, and answers
    are cached.
    """
    if whois is None:
        return None

    with _age_cache_lock:
        if domain in _age_cache:
            return _age_cache[domain]

    age: int | None = None
    try:
        # Deliberately NOT a `with` block: ThreadPoolExecutor.__exit__ calls
        # shutdown(wait=True), which blocks until the worker finishes — so a
        # hung WHOIS call would still pin the request thread even after
        # .result() had already timed out, defeating the whole point. The
        # module-level executor is never shut down; an abandoned worker is left
        # to finish on its own while the request moves on.
        creation = _whois_pool.submit(_whois_creation_date, domain).result(
            timeout=WHOIS_TIMEOUT_SECONDS
        )
        if isinstance(creation, list):
            creation = creation[0] if creation else None
        if isinstance(creation, datetime.datetime):
            if creation.tzinfo is not None:
                creation = creation.astimezone(datetime.timezone.utc).replace(tzinfo=None)
            age = (datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None) - creation).days
        elif isinstance(creation, datetime.date):
            age = (datetime.date.today() - creation).days
    except (FutureTimeout, OSError, Exception):
        # Registrar unreachable, rate-limited, unsupported TLD, malformed
        # response — an unverifiable domain must not break the analysis.
        age = None

    with _age_cache_lock:
        _age_cache[domain] = age
    return age


def check_links(text: str) -> Tuple[int, list[str]]:
    """
    Analyse all URLs inside `text` for domain-age risk.

    Returns:
        link_risk  : Integer risk score contribution (0–60).
        reasons    : Human-readable list of findings.
    """
    urls = _extract_urls(text)
    if not urls:
        return 0, []

    link_risk = 0
    reasons: list[str] = []

    for url in urls:
        resolved_url = _resolve_url(url)
        # Normalise to a bare hostname. The old string surgery left ports,
        # credentials and "www." attached, which WHOIS could not resolve.
        domain = _host_of(resolved_url)
        if domain.startswith("www."):
            domain = domain[4:]
        if not domain:
            continue

        age_days = _get_domain_age_days(domain)

        if age_days is None:
            # Could not verify — mildly suspicious but don't penalize score
            reasons.append(
                f"⚠️ Could not verify domain age for '{domain}' (Lookup failed or unsupported TLD)."
            )
        elif age_days < DOMAIN_AGE_THRESHOLD_DAYS:
            reasons.append(
                f"🚨 Domain '{domain}' is newly registered "
                f"({age_days} days old — under 6 months). "
                "Scam sites frequently use fresh domains."
            )
            link_risk = max(link_risk, NEW_DOMAIN_RISK_SCORE)
        else:
            reasons.append(
                f"✅ Domain '{domain}' has been registered for {age_days} days — OK."
            )

    return link_risk, reasons
