"""
services/intel/indicators.py
----------------------------
Extraction of atomic threat indicators from free text.

Every detector already sees text — OCR output, a pasted message, a crawler
snippet, a call transcript. Until now each one pulled out the single field it
cared about and discarded the rest. This module extracts *all* of them in one
pass and returns them in a uniform shape, so the entity graph can link a phone
number seen in a betting poster to the same number seen in a customer-care
screenshot three weeks earlier.

Design notes
------------
- Stdlib only. No network, no models. This runs on every request and has to be
  testable without any of the ML stack installed.
- Every extractor is *conservative*. A false indicator is worse than a missing
  one here: indicators become graph nodes, graph nodes become campaign
  evidence, and campaign evidence ends up in a legal notice. Where a pattern is
  ambiguous the extractor declines.
- `normalized` is the identity used for graph joins; `raw` is preserved for
  display so an analyst can see what was actually on the poster.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field, asdict
from typing import Iterable


# -- Indicator kinds -------------------------------------------------------
# Plain strings rather than an Enum so they round-trip through JSON and SQLite
# without a converter.
KIND_PHONE = "phone"
KIND_UPI = "upi"
KIND_DOMAIN = "domain"
KIND_URL = "url"
KIND_IP = "ip"
KIND_EMAIL = "email"
KIND_TELEGRAM = "telegram"
KIND_WHATSAPP = "whatsapp"
KIND_BANK_ACCT = "bank_account"
KIND_IFSC = "ifsc"
KIND_CRYPTO = "crypto_wallet"
KIND_APK_CERT = "apk_cert"
KIND_IMAGE_HASH = "image_phash"
KIND_FILE_HASH = "file_sha256"

ALL_KINDS = (
    KIND_PHONE, KIND_UPI, KIND_DOMAIN, KIND_URL, KIND_IP, KIND_EMAIL,
    KIND_TELEGRAM, KIND_WHATSAPP, KIND_BANK_ACCT, KIND_IFSC, KIND_CRYPTO,
    KIND_APK_CERT, KIND_IMAGE_HASH, KIND_FILE_HASH,
)

# Human labels for the UI and for generated legal notices.
KIND_LABELS = {
    KIND_PHONE: "Telephone number",
    KIND_UPI: "UPI virtual payment address",
    KIND_DOMAIN: "Domain name",
    KIND_URL: "URL",
    KIND_IP: "IP address",
    KIND_EMAIL: "Email address",
    KIND_TELEGRAM: "Telegram handle / channel",
    KIND_WHATSAPP: "WhatsApp group invite",
    KIND_BANK_ACCT: "Bank account number",
    KIND_IFSC: "IFSC code",
    KIND_CRYPTO: "Cryptocurrency wallet",
    KIND_APK_CERT: "APK signing certificate",
    KIND_IMAGE_HASH: "Perceptual image hash",
    KIND_FILE_HASH: "File SHA-256",
}

# Which authority a given indicator kind is actionable against. Drives the
# enforcement action pack -- see services/intel/actions.py.
KIND_AUTHORITY = {
    KIND_PHONE: "DoT / TRAI (Sanchar Saathi)",
    KIND_UPI: "NPCI / sponsor bank",
    KIND_BANK_ACCT: "Bank nodal officer / I4C",
    KIND_IFSC: "Bank nodal officer / I4C",
    KIND_DOMAIN: "MeitY / domain registrar",
    KIND_URL: "MeitY / hosting intermediary",
    KIND_IP: "Hosting provider / CERT-In",
    KIND_TELEGRAM: "Telegram platform abuse",
    KIND_WHATSAPP: "Meta platform abuse",
    KIND_CRYPTO: "FIU-IND / exchange compliance",
}


@dataclass
class Indicator:
    """One extracted indicator."""

    kind: str
    raw: str                 # exactly as it appeared, for display / evidence
    normalized: str          # canonical join key for the graph
    confidence: float = 1.0  # 0..1 -- how sure the extractor is
    context: str = ""        # surrounding snippet, for the analyst
    meta: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)

    @property
    def key(self) -> tuple:
        return (self.kind, self.normalized)


# -- Phone numbers ---------------------------------------------------------
# Indian mobile (10 digits starting 6-9, optional +91/0 prefix), toll-free
# 1800/1860 blocks, short codes (121, 198, 1930) and landlines with an STD code.
#
# Deliberately anchored on non-digit boundaries: without that, a 16-digit card
# number yields a "phone" from its middle ten digits.
_PHONE_PATTERNS = [
    # Contiguous 10-digit mobile, optionally +91 / 0 prefixed.
    (re.compile(r"(?<!\d)(?:\+?91[\s\-.]?|0)?([6-9]\d{9})(?!\d)"), 0.95, "mobile"),
    # Mobile printed with internal separators. Posters and OCR output almost
    # always break the number up -- "98765-43210", "987 654 3210" -- and a
    # contiguous-only pattern silently missed every one of them.
    (re.compile(r"(?<!\d)(?:\+?91[\s\-.]?|0)?([6-9]\d{4}[\s\-.]\d{5})(?!\d)"), 0.95, "mobile"),
    (re.compile(r"(?<!\d)(?:\+?91[\s\-.]?|0)?([6-9]\d{2}[\s\-.]\d{3}[\s\-.]\d{4})(?!\d)"), 0.95, "mobile"),
    (re.compile(r"(?<!\d)(?:\+?91[\s\-.]?|0)?([6-9]\d{3}[\s\-.]\d{6})(?!\d)"), 0.90, "mobile"),
    (re.compile(r"(?<!\d)(1(?:800|860)[\s\-.]?\d{2,4}[\s\-.]?\d{3,4}(?:[\s\-.]?\d{1,4})?)(?!\d)"), 0.90, "tollfree"),
    (re.compile(r"(?<!\d)(0\d{2,4}[\s\-.]\d{6,8})(?!\d)"), 0.75, "landline"),
    (re.compile(r"(?<!\d)(121|198|1930|155260)(?!\d)"), 0.60, "shortcode"),
]

# Sequences that look like phone numbers but are not.
_PHONE_BLOCKLIST = re.compile(r"^(?:0{6,}|1{6,}|1234567890|9{10})$")

# Characters that can appear *inside* a printed number.
_RUN_CHARS = set("0123456789 -. ")


def _digits(value):
    return re.sub(r"\D", "", value or "")


def _digit_run_length(text, start, end):
    """
    Count the digits in the whole separator-joined run containing [start:end).

    Separator-tolerant mobile patterns will happily match ten digits out of the
    middle of a card number or an Aadhaar number. Looking at the run the match
    sits inside is what distinguishes "98765-43210" (a phone) from
    "9876 5432 1098 7654" (not one).
    """
    lo = start
    while lo > 0 and text[lo - 1] in _RUN_CHARS:
        lo -= 1
    hi = end
    while hi < len(text) and text[hi] in _RUN_CHARS:
        hi += 1
    return len(_digits(text[lo:hi]))


def extract_phones(text):
    """Extract Indian telephone numbers, most-specific pattern first."""
    if not text:
        return []
    found = {}
    for pattern, conf, subtype in _PHONE_PATTERNS:
        for m in pattern.finditer(text):
            raw = m.group(0).strip()
            norm = _digits(m.group(1))
            # Strip a leading country code so +919876543210 and 9876543210
            # collapse onto one graph node.
            if len(norm) == 12 and norm.startswith("91"):
                norm = norm[2:]
            if not norm or _PHONE_BLOCKLIST.match(norm):
                continue

            # Reject a ten-digit slice taken out of a longer grouped number.
            # 13 leaves room for a +91 prefix plus the ten digits; a 16-digit
            # card or a 12-digit Aadhaar run lands above it.
            run = _digit_run_length(text, m.start(), m.end())
            if run > 13:
                continue
            eff_conf = conf
            if run == 12 and not _digits(raw).startswith("91"):
                # Twelve digits with no country code is the Aadhaar shape.
                # Report it, but well below the threshold that would let it
                # drive a verdict or a blocking request on its own.
                eff_conf = min(conf, 0.45)

            # A 10-digit mobile already captured must not be re-added as a
            # lower-confidence landline fragment.
            if norm in found and found[norm].confidence >= eff_conf:
                continue
            found[norm] = Indicator(
                kind=KIND_PHONE, raw=raw, normalized=norm, confidence=eff_conf,
                context=_context(text, m.start(), m.end()),
                meta={"subtype": subtype},
            )
    return list(found.values())


# -- UPI virtual payment addresses -----------------------------------------
# The single most actionable indicator in Indian financial fraud, and the one
# the platform previously discarded entirely.
UPI_PSP_HANDLES = {
    # Bank-issued
    "oksbi", "okhdfcbank", "okicici", "okaxis", "okbizaxis",
    "ybl", "ibl", "axl", "axisb", "axisbank", "hdfcbank", "icici", "sbi",
    "kotak", "kmbl", "yesbank", "yesg", "idfcbank", "idfcfirst", "indus",
    "indianbank", "uco", "unionbank", "uboi", "cnrb", "canara", "barodampay",
    "bandhan", "cbin", "citi", "csbpay", "dbs", "dlb", "equitas", "fbl",
    "federal", "finobank", "hsbc", "jkb", "jsb", "karb", "karnataka",
    "kbl", "kvb", "lvb", "mahb", "obc", "pnb", "psb", "rbl", "sc", "scb",
    "sib", "tjsb", "utbi", "vijb", "yesbankltd",
    # PSP / TPAP
    "paytm", "ptyes", "ptsbi", "ptaxis", "pthdfc", "ptufc",
    "apl", "yapl", "abfspay", "airtel", "airtelpaymentsbank",
    "freecharge", "jupiteraxis", "naviaxis", "mbk", "myicici",
    "pockets", "rmhdfc", "slice", "slcaxis", "superyes", "timecosmos",
    "waaxis", "wahdfcbank", "waicici", "wasbi", "yescred", "yesfam",
    "cred", "gpay", "googlepay", "phonepe", "bharatpe", "mobikwik",
    "amazonpay", "apay", "razorpay", "payzapp", "fam", "jio", "jiopay",
}

# Distinguishing a VPA from an email address is entirely a matter of what
# follows the handle:
#   (?![\w\-])        the handle must end -- "help@sbi-verification-login.com"
#                     stops at the hyphen, so it is an email host, not "help@sbi"
#   (?!\.[a-zA-Z0-9]) a dot followed by more label is a domain, so "a@gmail.com"
#                     is excluded -- but a sentence-ending "pay to x@ybl." is not
#
# The second lookahead has to allow a trailing period: excluding '.' outright
# dropped every VPA that happened to end a sentence, which is most of them in
# real scam copy.
_UPI_RE = re.compile(
    r"(?<![\w.@-])([a-zA-Z0-9](?:[a-zA-Z0-9._\-]{1,63}))@([a-zA-Z]{2,32})(?![\w\-])(?!\.[a-zA-Z0-9])"
)


def extract_upi(text):
    """
    Extract UPI VPAs.

    A VPA and an email address are lexically similar, so the PSP handle is
    checked against the known-handle set. An unrecognised handle is still
    reported at reduced confidence -- new PSP handles appear faster than any
    hardcoded list is updated -- while anything shaped like a domain is
    excluded by the pattern's lookaheads before it gets here.
    """
    if not text:
        return []
    found = {}
    for m in _UPI_RE.finditer(text):
        local, handle = m.group(1), m.group(2)
        full = (local + "@" + handle).lower()
        known = handle.lower() in UPI_PSP_HANDLES
        conf = 0.95 if known else 0.5
        if full in found and found[full].confidence >= conf:
            continue
        found[full] = Indicator(
            kind=KIND_UPI, raw=m.group(0), normalized=full, confidence=conf,
            context=_context(text, m.start(), m.end()),
            meta={"psp": handle.lower(), "psp_known": known},
        )
    return list(found.values())


# -- Email -----------------------------------------------------------------
_EMAIL_RE = re.compile(r"(?<![\w.])([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})(?![\w])")


def extract_emails(text):
    if not text:
        return []
    out = {}
    for m in _EMAIL_RE.finditer(text):
        norm = m.group(1).lower()
        out[norm] = Indicator(
            kind=KIND_EMAIL, raw=m.group(1), normalized=norm,
            confidence=0.9, context=_context(text, m.start(), m.end()),
        )
    return list(out.values())


# -- URLs, domains, IPs ----------------------------------------------------
_URL_RE = re.compile(
    r"""(?xi)
    \b
    (?:(?P<scheme>https?)://)?
    (?P<host>
        (?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+
        (?P<tld>[a-z]{2,24})
    )
    (?P<port>:\d{2,5})?
    (?P<path>/[^\s<>"'()\[\]]*)?
    """
)

_IPV4_RE = re.compile(
    r"(?<!\d)((?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})(?!\d)"
)

_NOISE_HOSTS = {"e.g", "i.e", "etc.in", "vs.in", "no.in"}

# Extensions that a bare (schemeless) match would misread as a hostname.
_FILE_EXT_TLDS = {
    "jpg", "jpeg", "png", "gif", "webp", "pdf", "doc", "docx",
    "mp4", "mp3", "zip", "exe", "txt", "csv", "html", "php", "js",
}

# Public infrastructure that is never itself the threat. Extracting these
# produces graph hubs that connect every unrelated campaign to every other.
DOMAIN_STOPLIST = {
    "google.com", "www.google.com", "youtube.com", "www.youtube.com",
    "facebook.com", "instagram.com", "twitter.com", "x.com", "linkedin.com",
    "wikipedia.org", "amazon.in", "amazon.com", "flipkart.com",
    "gov.in", "nic.in", "rbi.org.in", "sebi.gov.in", "cybercrime.gov.in",
    "trai.gov.in", "meity.gov.in", "cert-in.org.in", "sancharsaathi.gov.in",
    "github.com", "microsoft.com", "apple.com", "cloudflare.com",
    # Messaging platforms. The channel handle or invite code is the indicator;
    # the platform host itself is shared by every campaign that uses it and
    # would otherwise become a hub joining unrelated operators together.
    "t.me", "telegram.me", "telegram.org", "whatsapp.com", "wa.me",
    # URL shorteners -- the destination matters, not the shortener.
    "bit.ly", "t.co", "goo.gl", "tinyurl.com", "cutt.ly", "is.gd",
    "rb.gy", "shorturl.at", "rebrand.ly", "ow.ly",
}


def _registrable(host):
    """
    Reduce a hostname to something close to its registrable domain.

    A full public-suffix list would add a dependency for no practical gain
    here; the two-label / three-label heuristic covers .in, .co.in, .gov.in,
    .org.in and the common gTLDs, which is the entire realistic input space.
    """
    host = host.lower().strip(".")
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    second_level = {
        "co", "org", "net", "gov", "ac", "edu", "res", "mil", "nic",
        "firm", "gen", "ind",
    }
    if len(parts) >= 3 and parts[-2] in second_level and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def extract_urls_and_domains(text):
    """Extract URLs and their registrable domains as separate linked indicators."""
    if not text:
        return []
    out = {}
    for m in _URL_RE.finditer(text):
        host = (m.group("host") or "").lower().rstrip(".")
        if not host or host in _NOISE_HOSTS:
            continue
        # A bare "something.jpg" is a filename, not a host.
        if m.group("tld").lower() in _FILE_EXT_TLDS and not m.group("scheme"):
            continue

        domain = _registrable(host)
        full = m.group(0).strip().rstrip(".,;:!?)")
        scheme = m.group("scheme") or "http"
        low = full.lower()
        url_norm = low if low.startswith(("http://", "https://")) else scheme + "://" + low

        if domain not in DOMAIN_STOPLIST:
            key = (KIND_DOMAIN, domain)
            if key not in out:
                out[key] = Indicator(
                    kind=KIND_DOMAIN, raw=host, normalized=domain, confidence=0.9,
                    context=_context(text, m.start(), m.end()),
                    meta={"hostname": host},
                )
        # The URL itself is worth keeping even for a stoplisted domain when it
        # carries a path (a Telegram invite, a Play Store listing).
        if m.group("path") or m.group("scheme"):
            key = (KIND_URL, url_norm)
            if key not in out:
                out[key] = Indicator(
                    kind=KIND_URL, raw=full, normalized=url_norm,
                    confidence=0.9, context=_context(text, m.start(), m.end()),
                    meta={"domain": domain},
                )
    return list(out.values())


def extract_ips(text):
    if not text:
        return []
    out = {}
    for m in _IPV4_RE.finditer(text):
        ip = m.group(1)
        # A version string ("2.6.1.0") is not an IP; require one octet above 9.
        if all(int(p) < 10 for p in ip.split(".")):
            continue
        out[ip] = Indicator(
            kind=KIND_IP, raw=ip, normalized=ip, confidence=0.7,
            context=_context(text, m.start(), m.end()),
        )
    return list(out.values())


# -- Messaging handles -----------------------------------------------------
_TELEGRAM_RE = re.compile(
    r"(?i)(?:(?:https?://)?t\.me/(?:joinchat/)?([a-zA-Z0-9_+\-]{4,64})"
    r"|(?<![\w@])@([a-zA-Z][a-zA-Z0-9_]{4,31})(?![\w.]))"
)
_WHATSAPP_RE = re.compile(r"(?i)(?:https?://)?chat\.whatsapp\.com/(?:invite/)?([a-zA-Z0-9]{6,40})")


def extract_messaging(text):
    """Telegram channels/handles and WhatsApp group invites."""
    if not text:
        return []
    out = {}
    for m in _WHATSAPP_RE.finditer(text):
        code = m.group(1)
        out[(KIND_WHATSAPP, code)] = Indicator(
            kind=KIND_WHATSAPP, raw=m.group(0), normalized=code, confidence=0.95,
            context=_context(text, m.start(), m.end()),
            meta={"invite_url": "https://chat.whatsapp.com/" + code},
        )
    for m in _TELEGRAM_RE.finditer(text):
        handle = (m.group(1) or m.group(2) or "").lstrip("@").lower()
        if not handle:
            continue
        # A bare @handle is much weaker evidence than a t.me/ link.
        via_link = m.group(1) is not None
        conf = 0.9 if via_link else 0.55
        key = (KIND_TELEGRAM, handle)
        if key in out and out[key].confidence >= conf:
            continue
        out[key] = Indicator(
            kind=KIND_TELEGRAM, raw=m.group(0), normalized=handle, confidence=conf,
            context=_context(text, m.start(), m.end()),
            meta={"via_link": via_link, "url": "https://t.me/" + handle},
        )
    return list(out.values())


# -- Banking ---------------------------------------------------------------
# IFSC: 4 alpha (bank) + '0' + 6 alnum (branch). The fixed '0' is what makes
# this safe to extract without surrounding context.
_IFSC_RE = re.compile(r"(?<![A-Z0-9])([A-Z]{4}0[A-Z0-9]{6})(?![A-Z0-9])")

# Account numbers are 9-18 digits, but a bare digit run is far too ambiguous --
# only extract when an explicit cue word appears nearby.
#
# The gap between cue and digits is deliberately tiny. A 24-character window
# let "Your SBI account is blocked. Call 98765-43210" match, turning the scam's
# callback number into a phantom bank account -- which would then have gone
# into a freeze request against an account that does not exist. An account
# number follows its label almost immediately ("A/c No: 3829...", "a/c
# 3829..."), so anything further away is a different fact in the same sentence.
_ACCT_CUE = re.compile(
    r"(?i)\b(?:a/?c|acct|account|beneficiary|khata)\b"
    r"\s*(?:no\.?|number|num|#)?\s*[:\-]?\s{0,2}"
    r"(\d[\d\s\-]{7,22}\d)"
)

# Longer-range cues, where the phrasing itself names a transfer destination
# and an intervening clause is normal.
_ACCT_CUE_WIDE = re.compile(
    r"(?i)\b(?:transfer\s+to|deposit\s+(?:to|in|into)|credit\s+to|remit\s+to)\b"
    r"[^0-9]{0,20}(\d[\d\s\-]{7,22}\d)"
)


def extract_banking(text):
    if not text:
        return []
    out = {}
    for m in _IFSC_RE.finditer(text.upper()):
        code = m.group(1)
        out[(KIND_IFSC, code)] = Indicator(
            kind=KIND_IFSC, raw=code, normalized=code, confidence=0.95,
            context=_context(text, m.start(), m.end()),
            meta={"bank_code": code[:4]},
        )
    for pattern, conf in ((_ACCT_CUE, 0.8), (_ACCT_CUE_WIDE, 0.7)):
        for m in pattern.finditer(text):
            norm = _digits(m.group(1))
            if not (9 <= len(norm) <= 18):
                continue
            key = (KIND_BANK_ACCT, norm)
            if key in out and out[key].confidence >= conf:
                continue
            out[key] = Indicator(
                kind=KIND_BANK_ACCT, raw=m.group(1).strip(), normalized=norm,
                confidence=conf, context=_context(text, m.start(), m.end()),
            )
    return list(out.values())


# -- Crypto wallets --------------------------------------------------------
_CRYPTO_PATTERNS = [
    (re.compile(r"(?<![\w])(0x[a-fA-F0-9]{40})(?![\w])"), "ETH/EVM", 0.95),
    (re.compile(r"(?<![\w])(bc1[a-z0-9]{25,62})(?![\w])"), "BTC (bech32)", 0.95),
    (re.compile(r"(?<![\w])([13][a-km-zA-HJ-NP-Z1-9]{25,34})(?![\w])"), "BTC (legacy)", 0.7),
    (re.compile(r"(?<![\w])(T[A-Za-z1-9]{33})(?![\w])"), "TRON (USDT-TRC20)", 0.85),
]


def extract_crypto(text):
    if not text:
        return []
    out = {}
    for pattern, chain, conf in _CRYPTO_PATTERNS:
        for m in pattern.finditer(text):
            addr = m.group(1)
            if addr in out and out[addr].confidence >= conf:
                continue
            out[addr] = Indicator(
                kind=KIND_CRYPTO, raw=addr, normalized=addr, confidence=conf,
                context=_context(text, m.start(), m.end()),
                meta={"chain": chain},
            )
    return list(out.values())


# -- Helpers ---------------------------------------------------------------
def _context(text, start, end, window=40):
    """A short snippet around a match, for analyst review in the case file."""
    lo = max(0, start - window)
    hi = min(len(text), end + window)
    snippet = text[lo:hi].replace("\n", " ").strip()
    return ("..." if lo > 0 else "") + snippet + ("..." if hi < len(text) else "")


_EXTRACTORS = (
    extract_phones,
    extract_upi,
    extract_emails,
    extract_urls_and_domains,
    extract_ips,
    extract_messaging,
    extract_banking,
    extract_crypto,
)


def extract_all(text, min_confidence=0.5):
    """
    Run every extractor over `text` and return the deduplicated union.

    Sorted by (kind, -confidence) so callers that truncate keep the strongest
    evidence of each kind.
    """
    if not text:
        return []
    seen = {}
    for fn in _EXTRACTORS:
        try:
            for ind in fn(text):
                if ind.confidence < min_confidence:
                    continue
                prev = seen.get(ind.key)
                if prev is None or ind.confidence > prev.confidence:
                    seen[ind.key] = ind
        except Exception:
            # One misbehaving pattern must not lose the other extractors'
            # output -- indicator extraction is best-effort enrichment, not a
            # correctness-critical path.
            continue

    _deconflict(seen)
    return sorted(seen.values(), key=lambda i: (i.kind, -i.confidence, i.normalized))


def _deconflict(seen):
    """
    Resolve indicators that claim the same underlying value under two kinds.

    A ten-digit string starting 6-9 is an Indian mobile number. Indian bank
    accounts are effectively never that shape, so when both extractors claim
    the same digits the phone wins and the account is dropped -- otherwise the
    action pack raises a freeze request against an account number that is
    really the scammer's callback line.
    """
    phones = {k[1] for k in seen if k[0] == KIND_PHONE}
    for value in list(phones):
        key = (KIND_BANK_ACCT, value)
        if key not in seen:
            continue
        if len(value) == 10 and value[0] in "6789":
            del seen[key]


def summarise(indicators):
    """Group normalised values by kind -- the shape stored on a scan row."""
    out = {}
    for ind in indicators:
        out.setdefault(ind.kind, []).append(ind.normalized)
    return out


def actionable(indicators):
    """
    Filter to the indicators an enforcement action can actually be raised
    against, strongest first. Used to build the action pack.
    """
    items = [i for i in indicators if i.kind in KIND_AUTHORITY]
    return sorted(items, key=lambda i: -i.confidence)
