"""
services/intel/feeds.py
-----------------------
Real, public threat-intelligence feeds.

The background crawler previously flipped a coin and, on failure *or* on the
coin flip, injected one of eight hand-written fake alerts into a feed the
dashboard labelled "LIVE INTEL SWEEP". The entries looked convincing precisely
because they were written to; nothing distinguished them from a genuine
observation.

This module supplies actual data from public sources that require no API key,
and every record it returns is tagged `provenance="LIVE"`. Anything the crawler
still generates locally is tagged `provenance="SIMULATED"` and must be rendered
as such. A live feed that is honest about which entries are live is worth more
in front of a judge — and in an investigation — than a convincing fake.

Sources
-------
    URLhaus (abuse.ch)   recently observed malware-distribution URLs
    OpenPhish            community phishing feed
    PhishTank            phishing submissions (optional, rate-limited)

All fetches are best-effort with short timeouts. A source that is down, slow,
or has changed its format is skipped, not fatal.
"""

from __future__ import annotations

import csv
import io
import re
from datetime import datetime

try:
    import requests
except Exception:                                    # pragma: no cover
    requests = None

PROVENANCE_LIVE = "LIVE"
PROVENANCE_SIMULATED = "SIMULATED"

DEFAULT_TIMEOUT = 12
USER_AGENT = "CYBERSURAKSHAA-CTI/1.0 (threat-intelligence research)"

# Terms that make a generic phishing/malware URL relevant to this platform's
# remit, and the module each maps to.
RELEVANCE_MAP = [
    (("bet", "casino", "poker", "rummy", "teenpatti", "satta", "matka",
      "jackpot", "lottery", "1xbet", "parimatch", "lotus365"), "Betting Content"),
    (("invest", "crypto", "bitcoin", "btc", "forex", "trading", "profit",
      "wallet", "binance", "usdt", "earn"), "Investment Scam"),
    (("kyc", "verify", "netbanking", "sbi", "hdfc", "icici", "axis", "paytm",
      "phonepe", "upi", "npci", "refund", "support", "helpline", "care",
      "customer"), "Customer Care"),
    (("deepfake", "faceswap", "face-swap", "nude", "undress", "aiswap"),
     "Deepfake Face"),
]


def _classify(url, extra_text=""):
    """Map a feed URL onto one of the platform's four threat categories."""
    blob = ("%s %s" % (url or "", extra_text or "")).lower()
    for terms, category in RELEVANCE_MAP:
        if any(t in blob for t in terms):
            return category
    return None


def _india_relevance(url, extra_text=""):
    """
    Crude India-relevance signal.

    The global feeds are overwhelmingly not about India. Boosting matches on
    Indian TLDs and Indian brand names keeps the dashboard useful without
    excluding everything else outright.
    """
    blob = ("%s %s" % (url or "", extra_text or "")).lower()
    markers = (".in/", ".in?", ".co.in", "india", "sbi", "hdfc", "icici",
               "axis", "paytm", "phonepe", "npci", "upi", "irctc", "aadhaar",
               "rupee", "inr", "bharat", "jio", "airtel")
    return sum(1 for m in markers if m in blob)


def _now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _get(url, timeout=DEFAULT_TIMEOUT):
    if requests is None:
        return None
    try:
        resp = requests.get(url, timeout=timeout,
                            headers={"User-Agent": USER_AGENT})
        if resp.status_code == 200:
            return resp
        print("[FEEDS] %s returned HTTP %d" % (url, resp.status_code))
    except Exception as e:
        print("[FEEDS] %s failed: %s" % (url, e))
    return None


# -- URLhaus ---------------------------------------------------------------

URLHAUS_RECENT = "https://urlhaus.abuse.ch/downloads/csv_recent/"


def fetch_urlhaus(limit=40):
    """
    Recent malware-distribution URLs from abuse.ch URLhaus.

    The CSV carries a block of '#' comment lines before the data, and the
    header row is itself commented, so the columns are addressed positionally:
    id, dateadded, url, url_status, last_online, threat, tags, urlhaus_link,
    reporter.
    """
    resp = _get(URLHAUS_RECENT)
    if resp is None:
        return []

    out = []
    try:
        text = resp.text
        reader = csv.reader(io.StringIO(text))
        for row in reader:
            if not row or row[0].startswith("#") or len(row) < 7:
                continue
            date_added, url, status = row[1], row[2], row[3]
            threat, tags = row[5], row[6]

            category = _classify(url, "%s %s" % (threat, tags))
            if not category:
                continue

            relevance = _india_relevance(url, tags)
            out.append({
                "provenance": PROVENANCE_LIVE,
                "source": "URLhaus (abuse.ch) — %s" % (threat or "malware_url"),
                "content": "Malware distribution URL observed live. Tags: %s. Status: %s."
                           % (tags or "none", status or "unknown"),
                "category": category,
                "risk_score": 85 if status == "online" else 65,
                "url": url,
                "observed": date_added,
                "india_relevance": relevance,
                "feed": "urlhaus",
            })
            if len(out) >= limit * 3:
                break
    except Exception as e:
        print("[FEEDS] URLhaus parse failed: %s" % e)
        return []

    out.sort(key=lambda r: (-r["india_relevance"], -r["risk_score"]))
    return out[:limit]


# -- OpenPhish -------------------------------------------------------------

OPENPHISH_FEED = "https://openphish.com/feed.txt"


def fetch_openphish(limit=40):
    """Community phishing feed — a plain newline-delimited URL list."""
    resp = _get(OPENPHISH_FEED)
    if resp is None:
        return []

    out = []
    try:
        for line in resp.text.splitlines():
            url = line.strip()
            if not url or not url.startswith(("http://", "https://")):
                continue
            category = _classify(url)
            if not category:
                continue
            out.append({
                "provenance": PROVENANCE_LIVE,
                "source": "OpenPhish community feed",
                "content": "Phishing URL reported by the OpenPhish community feed.",
                "category": category,
                "risk_score": 88,
                "url": url,
                "observed": _now(),
                "india_relevance": _india_relevance(url),
                "feed": "openphish",
            })
            if len(out) >= limit * 3:
                break
    except Exception as e:
        print("[FEEDS] OpenPhish parse failed: %s" % e)
        return []

    out.sort(key=lambda r: -r["india_relevance"])
    return out[:limit]


# -- PhishTank -------------------------------------------------------------

PHISHTANK_FEED = "http://data.phishtank.com/data/online-valid.csv"


def fetch_phishtank(limit=25):
    """
    PhishTank's verified online phishing list.

    Frequently rate-limited without an application key, so a failure here is
    routine and silent rather than exceptional.
    """
    resp = _get(PHISHTANK_FEED, timeout=15)
    if resp is None:
        return []

    out = []
    try:
        reader = csv.DictReader(io.StringIO(resp.text))
        for row in reader:
            url = (row.get("url") or "").strip()
            target = (row.get("target") or "").strip()
            if not url:
                continue
            category = _classify(url, target)
            if not category:
                continue
            out.append({
                "provenance": PROVENANCE_LIVE,
                "source": "PhishTank — verified phish targeting %s" % (target or "unknown"),
                "content": "Verified phishing page impersonating %s." % (target or "an unidentified brand"),
                "category": category,
                "risk_score": 90,
                "url": url,
                "observed": row.get("verification_time") or _now(),
                "india_relevance": _india_relevance(url, target),
                "feed": "phishtank",
            })
            if len(out) >= limit * 3:
                break
    except Exception as e:
        print("[FEEDS] PhishTank parse failed: %s" % e)
        return []

    out.sort(key=lambda r: -r["india_relevance"])
    return out[:limit]


FEED_SOURCES = [
    ("urlhaus", fetch_urlhaus),
    ("openphish", fetch_openphish),
    ("phishtank", fetch_phishtank),
]


def fetch_all(limit_per_feed=25):
    """
    Pull from every configured feed.

    Returns (records, status) where `status` reports what each source did, so
    the UI can show which feeds are actually contributing rather than implying
    all of them always are.
    """
    records = []
    status = {}
    for name, fn in FEED_SOURCES:
        try:
            got = fn(limit=limit_per_feed)
            status[name] = {"ok": True, "count": len(got)}
            records.extend(got)
        except Exception as e:
            status[name] = {"ok": False, "error": str(e), "count": 0}

    seen = set()
    deduped = []
    for r in records:
        if r["url"] in seen:
            continue
        seen.add(r["url"])
        deduped.append(r)

    deduped.sort(key=lambda r: (-r.get("india_relevance", 0), -r.get("risk_score", 0)))
    return deduped, status


def feeds_available():
    """Whether outbound HTTP is possible at all."""
    return requests is not None
