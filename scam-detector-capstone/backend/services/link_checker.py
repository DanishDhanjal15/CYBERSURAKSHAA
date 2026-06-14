"""
link_checker.py
---------------
Extracts URLs from a message and checks domain age using python-whois.
A domain younger than 6 months is considered high-risk (newly registered scam domains
are a classic red flag in financial fraud).
"""

import re
import datetime
from typing import Tuple

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

# Threshold in days for "newly registered" domain risk
DOMAIN_AGE_THRESHOLD_DAYS = 180  # 6 months

# Risk score added when a new domain is detected
NEW_DOMAIN_RISK_SCORE = 60


def _extract_urls(text: str) -> list[str]:
    """Return a deduplicated list of URLs found in the text."""
    return list(set(URL_PATTERN.findall(text)))

def _resolve_url(url: str) -> str:
    """Follow redirects to get the ultimate destination URL (e.g. unshorten bit.ly)."""
    if not url.startswith("http"):
        url = "http://" + url
    if requests is None:
        return url
    try:
        res = requests.head(url, allow_redirects=True, timeout=5)
        return res.url
    except Exception:
        return url


def _get_domain_age_days(domain: str) -> int | None:
    """
    Query WHOIS data for the domain and return its age in days.
    Returns None if the lookup fails or data is unavailable.
    """
    if whois is None:
        return None
    try:
        w = whois.whois(domain)
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        if creation is None:
            return None
        if isinstance(creation, datetime.datetime):
            age = (datetime.datetime.utcnow() - creation).days
        else:
            # creation_date can be a date object
            age = (datetime.date.today() - creation).days
        return age
    except Exception:
        return None


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
        # Normalise: strip protocol and path to get bare domain
        domain = re.sub(r"https?://", "", resolved_url).split("/")[0].strip()

        age_days = _get_domain_age_days(domain)

        if age_days is None:
            # Could not verify — treat as mildly suspicious but DO NOT penalize score as it's a system error
            reasons.append(
                f"⚠️  Could not verify domain age for '{domain}' (Lookup failed or unsupported TLD)."
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
