"""
services/intel/lookalike.py
---------------------------
Lookalike / typosquat domain generation and live checking.

Phishing against Indian banks and payment brands is overwhelmingly delivered
from a domain registered days earlier that reads almost like the real one:
sbi-verify.top, paytrn.in, phonepe-refund.xyz. Waiting for a citizen to report
one of those means acting after the money has moved.

This module works the other way round: given a brand's real domain it generates
the permutation space an attacker draws from, then checks which of those
permutations actually resolve. A domain that exists, resolves, and was
registered last week is a lead before anyone has been defrauded.

The generator is deliberately stdlib-only and offline; resolution is a separate,
optional step so the permutation set can be produced and reviewed without any
network traffic at all.
"""

from __future__ import annotations

import re
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

# Characters that read alike in a browser address bar at a glance.
HOMOGLYPHS = {
    "a": ["4", "@", "à", "á", "â"],
    "b": ["6", "8", "lb"],
    "c": ["(", "e"],
    "d": ["cl", "b"],
    "e": ["3", "a"],
    "g": ["9", "q"],
    "i": ["1", "l", "!"],
    "l": ["1", "i", "I"],
    "m": ["rn", "nn"],
    "n": ["m", "r"],
    "o": ["0", "q"],
    "q": ["g", "9"],
    "r": ["n"],
    "s": ["5", "$", "z"],
    "t": ["7", "+"],
    "u": ["v", "µ"],
    "v": ["u", "w"],
    "w": ["vv", "v"],
    "y": ["v", "j"],
    "z": ["2", "s"],
    "0": ["o"],
    "1": ["l", "i"],
    "5": ["s"],
}

# Words attackers append to a brand to manufacture a plausible pretext.
SCAM_AFFIXES = [
    "verify", "verification", "secure", "security", "login", "signin",
    "update", "kyc", "kyc-update", "support", "help", "helpline", "care",
    "customercare", "refund", "reward", "offer", "bonus", "wallet",
    "netbanking", "online", "account", "alert", "block", "unblock",
    "recovery", "official", "app", "in", "india",
]

# TLDs disproportionately represented in Indian phishing infrastructure --
# cheap, loosely policed, and rarely used by legitimate Indian institutions.
SUSPICIOUS_TLDS = [
    "top", "xyz", "online", "site", "club", "icu", "cyou", "buzz",
    "info", "biz", "live", "shop", "store", "website", "space", "fun",
    "cc", "co", "net", "org", "com", "in",
]

# Sensible default watchlist for the Indian financial threat surface.
DEFAULT_WATCHLIST = [
    "sbi.co.in", "hdfcbank.com", "icicibank.com", "axisbank.com",
    "pnbindia.in", "bankofbaroda.in", "kotak.com", "unionbankofindia.co.in",
    "paytm.com", "phonepe.com", "npci.org.in", "onlinesbi.sbi",
    "irctc.co.in", "epfindia.gov.in", "incometax.gov.in", "uidai.gov.in",
]

_LABEL_OK = re.compile(r"^[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?$")


def _split_domain(domain):
    """Split into (name, tld) where tld may be multi-label (co.in)."""
    domain = (domain or "").lower().strip().strip(".")
    parts = domain.split(".")
    if len(parts) < 2:
        return domain, ""
    second_level = {"co", "org", "net", "gov", "ac", "edu", "res", "nic", "firm", "gen", "ind"}
    if len(parts) >= 3 and parts[-2] in second_level and len(parts[-1]) == 2:
        return ".".join(parts[:-3]) or parts[-3], ".".join(parts[-2:])
    return ".".join(parts[:-1]), parts[-1]


def _valid_label(label):
    return bool(label) and len(label) <= 63 and bool(_LABEL_OK.match(label))


# -- Permutation strategies ------------------------------------------------

def _omission(name):
    return {name[:i] + name[i + 1:] for i in range(len(name)) if len(name) > 2}


def _repetition(name):
    return {name[:i] + name[i] + name[i:] for i in range(len(name))}


def _transposition(name):
    return {
        name[:i] + name[i + 1] + name[i] + name[i + 2:]
        for i in range(len(name) - 1) if name[i] != name[i + 1]
    }


def _replacement(name):
    """Adjacent-key substitutions -- the classic fat-finger typo."""
    keyboard = {
        "q": "wa", "w": "qes", "e": "wrd", "r": "etf", "t": "ryg", "y": "tuh",
        "u": "yij", "i": "uok", "o": "ipl", "p": "ol", "a": "qsz", "s": "awdx",
        "d": "serfc", "f": "drtgv", "g": "ftyhb", "h": "gyujn", "j": "huikm",
        "k": "jiol", "l": "kop", "z": "asx", "x": "zsdc", "c": "xdfv",
        "v": "cfgb", "b": "vghn", "n": "bhjm", "m": "njk",
    }
    out = set()
    for i, ch in enumerate(name):
        for sub in keyboard.get(ch, ""):
            out.add(name[:i] + sub + name[i + 1:])
    return out


def _homoglyph(name):
    out = set()
    for i, ch in enumerate(name):
        for sub in HOMOGLYPHS.get(ch, []):
            candidate = name[:i] + sub + name[i + 1:]
            # ASCII-only: an IDN homoglyph is a real attack but cannot be
            # resolved or reported through the same channels, so it is out of
            # scope here rather than silently producing unusable candidates.
            if candidate.isascii():
                out.add(candidate)
    return out


def _insertion(name):
    out = set()
    for i in range(1, len(name)):
        out.add(name[:i] + "-" + name[i:])
    return out


def _affix(name):
    out = set()
    for word in SCAM_AFFIXES:
        out.add("%s-%s" % (name, word))
        out.add("%s%s" % (name, word))
        out.add("%s-%s" % (word, name))
    return out


_STRATEGIES = [
    ("omission", _omission),
    ("repetition", _repetition),
    ("transposition", _transposition),
    ("replacement", _replacement),
    ("homoglyph", _homoglyph),
    ("hyphenation", _insertion),
    ("affix", _affix),
]


def generate(domain, tlds=None, include_affixes=True, max_results=600):
    """
    Generate the lookalike permutation space for `domain`.

    Returns a list of {"domain", "strategy"} dicts, excluding the original.
    Bounded by `max_results` -- the affix strategy alone crosses a thousand
    candidates on a long brand name, and a list that size is neither reviewable
    by an analyst nor resolvable within a request.
    """
    name, tld = _split_domain(domain)
    if not name:
        return []

    tld_list = tlds if tlds is not None else ([tld] + SUSPICIOUS_TLDS[:10] if tld else SUSPICIOUS_TLDS)
    seen = {}

    for strategy_name, fn in _STRATEGIES:
        if strategy_name == "affix" and not include_affixes:
            continue
        try:
            variants = fn(name)
        except Exception:
            continue
        for variant in variants:
            if not _valid_label(variant) or variant == name:
                continue
            # Same-name-different-TLD is itself a strategy, applied to the
            # original name as well as to every misspelling.
            for t in tld_list:
                candidate = "%s.%s" % (variant, t)
                if candidate == domain or candidate in seen:
                    continue
                seen[candidate] = strategy_name
                if len(seen) >= max_results:
                    break
            if len(seen) >= max_results:
                break
        if len(seen) >= max_results:
            break

    # The unmodified brand on a different TLD is the single most common real
    # attack, so it is added explicitly rather than left to chance.
    for t in tld_list:
        candidate = "%s.%s" % (name, t)
        if candidate != domain and candidate not in seen:
            seen[candidate] = "tld-swap"

    return [{"domain": d, "strategy": s} for d, s in sorted(seen.items())]


# -- Live checking ---------------------------------------------------------

def resolve(domain, timeout=3.0):
    """Resolve one domain. Returns a dict; never raises."""
    original_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        infos = socket.getaddrinfo(domain, None)
        ips = sorted({i[4][0] for i in infos})
        return {"domain": domain, "resolves": True, "ips": ips}
    except socket.gaierror:
        return {"domain": domain, "resolves": False, "ips": []}
    except Exception as e:
        return {"domain": domain, "resolves": False, "ips": [], "error": str(e)}
    finally:
        socket.setdefaulttimeout(original_timeout)


def check_live(candidates, max_workers=16, limit=200, timeout=3.0):
    """
    Resolve a batch of candidates concurrently, returning only those that exist.

    DNS resolution is I/O-bound and independent per name, so a small thread pool
    turns a multi-minute serial sweep into a few seconds. `limit` bounds how
    many are attempted in one call -- an unbounded sweep over a full permutation
    set is a lot of outbound DNS from one request and looks like reconnaissance
    to the resolver.
    """
    names = []
    for c in candidates[:limit]:
        names.append(c["domain"] if isinstance(c, dict) else c)

    strategy_of = {
        (c["domain"] if isinstance(c, dict) else c): (c.get("strategy") if isinstance(c, dict) else None)
        for c in candidates[:limit]
    }

    live = []
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(resolve, n, timeout): n for n in names}
        for fut in as_completed(futures):
            try:
                result = fut.result()
            except Exception:
                continue
            if result.get("resolves"):
                result["strategy"] = strategy_of.get(result["domain"])
                live.append(result)

    live.sort(key=lambda r: r["domain"])
    return live


def scan_brand(domain, tlds=None, resolve_limit=150, include_affixes=True):
    """
    Full sweep for one brand: generate, resolve, and summarise.

    Returns the candidate set alongside the subset that actually exists. A
    resolving lookalike is a lead, not a finding -- plenty of them are
    defensive registrations by the brand itself, which is why the response
    reports both numbers rather than presenting every hit as a threat.
    """
    candidates = generate(domain, tlds=tlds, include_affixes=include_affixes)
    live = check_live(candidates, limit=resolve_limit)
    return {
        "brand_domain": domain,
        "generated": len(candidates),
        "checked": min(len(candidates), resolve_limit),
        "live": live,
        "live_count": len(live),
        "candidates": candidates,
        "note": (
            "A resolving lookalike is a lead, not a confirmed threat -- brands "
            "defensively register many of these themselves. Confirm ownership "
            "via WHOIS and inspect the served content before acting."
        ),
    }
