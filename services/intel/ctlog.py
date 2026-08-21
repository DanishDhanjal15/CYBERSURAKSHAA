"""
services/intel/ctlog.py
-----------------------
Certificate Transparency monitoring — catching phishing infrastructure at
issuance rather than after a victim reports it.

Why this exists
===============
`services/intel/lookalike.py` works backwards. It enumerates the permutation
space around a brand — omissions, transpositions, homoglyphs — and DNS-probes
the results hoping to hit one that exists. That finds what it thought to guess,
and the permutation space around a single brand is effectively unbounded.

Certificate Transparency inverts the problem. Every publicly-trusted TLS
certificate issued anywhere is published to append-only public logs, because
browsers refuse certificates that are not. That makes CT a near-complete
register of *every domain someone bothered to provision HTTPS for* — and a
phishing kit needs HTTPS, because a browser warning kills the campaign before
it starts.

So instead of guessing, we read the register and look for brand collisions.
The practical consequence: `sbi-verify-kyc.com` shows up here when its
certificate is issued, which is typically hours-to-days *before* the first
message goes out. A registrar notice at that point costs the operator the
domain before it has touched a single citizen.

What a hit does and does not mean
=================================
A CT match is a **lead, never a verdict**. Certificate issuance says somebody
provisioned HTTPS for a name resembling a brand. Legitimate reasons exist:
regional subsidiaries, marketing microsites, security researchers, defensive
registrations by the brand itself. Every observation therefore carries a score
and its reasons, and nothing here classifies anything as malicious on its own.

Two coverage limits, stated because they bound what this can claim:

* Not every phishing domain appears. A campaign served over plain HTTP, or
  behind a compromised legitimate host, or on a subdomain of a service whose
  wildcard certificate was issued long ago, is invisible here.
* Not every appearance is phishing, per the paragraph above.

Two sources, answering two different questions
==============================================
**crt.sh** supports substring search across all logged certificates, which is
the only way to *discover* a name nobody knew to look for — `sbi-verify-kyc.com`
has no relationship to `sbi.co.in` that a by-domain query would ever surface.
This is the discovery source, and it has no substitute.

**Cert Spotter** (SSLMate) queries a domain and its subdomains. It cannot find
typosquats, so it is not a fallback for the above. It answers the other CT
question: *what certificates exist inside the brand's own namespace, and did
an unexpected authority issue one?* A certificate for `sbi.co.in` from a CA the
organisation does not use is a mis-issuance or a compromise, and that is worth
knowing regardless of any phishing campaign.

Both are third-party services run as public goods — slow, rate-limited, and
periodically down. crt.sh in particular returns 502 under load with some
regularity.

**Source outages are surfaced, never swallowed.** A monitor that reports "no
new observations" when its data source is unreachable is worse than no monitor:
it converts an outage into a false all-clear. `source_health()` reports the
last successful contact per source, and the UI is expected to say the discovery
feed is degraded rather than implying a quiet day.
"""

from __future__ import annotations

import json
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta

from services.intel.db import get_db_connection
from services.intel.lookalike import (
    DEFAULT_WATCHLIST, SCAM_AFFIXES, SUSPICIOUS_TLDS, _split_domain,
)

CRTSH_URL = "https://crt.sh/?q={query}&output=json&exclude=expired"

# Cert Spotter: by-domain, includes subdomains. Free tier needs no key at low
# volume. Used for namespace monitoring, NOT as a crt.sh fallback -- it cannot
# do the substring search that typosquat discovery depends on.
CERTSPOTTER_URL = ("https://api.certspotter.com/v1/issuances"
                   "?domain={domain}&include_subdomains=true"
                   "&expand=dns_names&expand=issuer")
CERTSPOTTER_TIMEOUT = 30

# crt.sh 502s under load often enough that a single failure means nothing.
CRTSH_RETRIES = 2
CRTSH_RETRY_BACKOFF = 4.0

# crt.sh is a free community service. These are deliberately conservative:
# a monitoring tool that hammers a public good until it is rate-limited has
# broken its own data source.
CRTSH_TIMEOUT = 45
CRTSH_DELAY_BETWEEN_BRANDS = 3.0
POLL_INTERVAL_SECONDS = 1800          # 30 minutes
MAX_RESULTS_PER_BRAND = 400

USER_AGENT = "CYBERSURAKSHAA-CT-Monitor/1.0 (threat intelligence; contact via deployment operator)"

# Certificate-name characters that are never part of a hostname we care about.
_WILDCARD = re.compile(r"^\*\.")
_HOSTNAME_OK = re.compile(r"^[a-z0-9.\-*]+$")

# Scoring weights. Kept as named constants because these are judgement calls,
# not measurements, and a reader deserves to see the whole scale at once.
W_BRAND_EXACT_LABEL = 45      # a label IS the brand token ("sbi" in sbi-kyc.com)
W_BRAND_NEAR_LABEL = 35       # a label is one edit from it ("sb1", "sbl")
W_BRAND_SUBSTRING = 25        # brand appears inside a longer label
W_SCAM_AFFIX = 25             # "verify", "kyc", "login", "secure"...
W_SUSPICIOUS_TLD = 15         # .top, .xyz, .icu...
W_MANY_HYPHENS = 10           # sbi-online-secure-login.com
W_DIGIT_SUBSTITUTION = 10     # 0 for o, 1 for l
W_WILDCARD_CERT = 5           # *.something -- cheap bulk provisioning
W_FREE_CA = 10                # Let's Encrypt / ZeroSSL: free and instant

SCORE_REPORT_THRESHOLD = 50   # below this an observation is stored, not alerted
SCORE_INGEST_THRESHOLD = 60   # below this it does not enter the entity graph

# Certificate authorities that issue free, instant, domain-validated
# certificates. Not remotely an accusation -- they are the backbone of a
# secure web -- but "free and instant" is a real signal in combination with a
# brand collision, because phishing infrastructure is disposable.
FREE_CA_MARKERS = ("let's encrypt", "lets encrypt", "zerossl", "buypass", "google trust services")


def _now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


# ── Schema ────────────────────────────────────────────────────────────────

def init_ctlog_db():
    """Create the CT observation tables. Idempotent."""
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS ct_observations (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            domain       TEXT NOT NULL,
            brand        TEXT NOT NULL,
            score        INTEGER NOT NULL DEFAULT 0,
            reasons      TEXT,
            issuer       TEXT,
            cert_id      TEXT,
            not_before   TEXT,
            not_after    TEXT,
            source       TEXT NOT NULL,
            resolves     INTEGER,
            resolved_ips TEXT,
            entity_id    INTEGER,
            reviewed     INTEGER NOT NULL DEFAULT 0,
            verdict      TEXT,
            first_seen   TEXT NOT NULL,
            last_seen    TEXT NOT NULL,
            UNIQUE(domain, brand)
        )
    """)
    cur.execute("CREATE INDEX IF NOT EXISTS idx_ct_score ON ct_observations(score DESC)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_ct_seen ON ct_observations(first_seen DESC)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_ct_brand ON ct_observations(brand)")

    # Per-brand poll bookkeeping, so a restart does not re-alert on every
    # certificate ever issued.
    cur.execute("""
        CREATE TABLE IF NOT EXISTS ct_watch (
            brand        TEXT PRIMARY KEY,
            added_at     TEXT NOT NULL,
            last_polled  TEXT,
            last_status  TEXT,
            certs_seen   INTEGER NOT NULL DEFAULT 0,
            hits         INTEGER NOT NULL DEFAULT 0,
            active       INTEGER NOT NULL DEFAULT 1
        )
    """)
    conn.commit()
    conn.close()

    init_namespace_db()


def seed_watchlist(domains=None):
    """Register the default brand watchlist. Idempotent."""
    conn = get_db_connection()
    try:
        for d in (domains or DEFAULT_WATCHLIST):
            conn.execute("""
                INSERT INTO ct_watch (brand, added_at, active) VALUES (?, ?, 1)
                ON CONFLICT(brand) DO NOTHING
            """, (d.lower().strip(), _now()))
        conn.commit()
    finally:
        conn.close()


def watchlist(active_only=True):
    conn = get_db_connection()
    sql = "SELECT * FROM ct_watch"
    if active_only:
        sql += " WHERE active = 1"
    sql += " ORDER BY brand"
    rows = [dict(r) for r in conn.execute(sql).fetchall()]
    conn.close()
    return rows


def add_brand(domain):
    conn = get_db_connection()
    try:
        conn.execute("""
            INSERT INTO ct_watch (brand, added_at, active) VALUES (?, ?, 1)
            ON CONFLICT(brand) DO UPDATE SET active = 1
        """, (domain.lower().strip(), _now()))
        conn.commit()
    finally:
        conn.close()


def remove_brand(domain):
    conn = get_db_connection()
    try:
        conn.execute("UPDATE ct_watch SET active = 0 WHERE brand = ?",
                     (domain.lower().strip(),))
        conn.commit()
    finally:
        conn.close()


# ── Matching ──────────────────────────────────────────────────────────────

def _levenshtein(a, b, max_distance=2):
    """
    Edit distance, abandoned once it provably exceeds `max_distance`.

    Typosquats are one or two edits from the brand; anything further is a
    different word. Bounding the computation matters because this runs against
    every label of every certificate in a poll cycle.
    """
    if abs(len(a) - len(b)) > max_distance:
        return max_distance + 1
    if a == b:
        return 0

    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        current = [i]
        for j, cb in enumerate(b, 1):
            current.append(min(
                previous[j] + 1,        # deletion
                current[j - 1] + 1,     # insertion
                previous[j - 1] + (ca != cb),   # substitution
            ))
        if min(current) > max_distance:
            return max_distance + 1
        previous = current
    return previous[-1]


def brand_tokens(brand_domain):
    """
    The identifying part of a brand domain.

    `sbi.co.in` -> {"sbi"}; `hdfcbank.com` -> {"hdfcbank", "hdfc"}. The split
    matters because operators register both `hdfcbank-kyc.com` and
    `hdfc-secure.com`, and only one of those contains the full name.
    """
    name, _tld = _split_domain(brand_domain)
    tokens = {name}
    # Split a compound name on the well-known suffixes Indian institutions use.
    for suffix in ("bank", "india", "pay", "cards", "life", "finance"):
        if name.endswith(suffix) and len(name) > len(suffix) + 2:
            tokens.add(name[: -len(suffix)])
    return {t for t in tokens if len(t) >= 3}


# Domains a watched brand genuinely operates besides its primary one.
#
# Without this, every routine certificate renewal on State Bank's real
# net-banking domain fires an alert -- `onlinesbi.sbi` scores 55 against
# `sbi.co.in` on the name alone, because it is *supposed* to look like SBI.
# An alert stream that cries wolf on the brand's own infrastructure is one
# nobody reads.
#
# Deliberately conservative and hand-verified. A wrong entry here suppresses a
# real phishing domain, which is far worse than an extra alert, so anything
# uncertain is left out.
BRAND_ALIASES = {
    "sbi.co.in": ["onlinesbi.sbi", "onlinesbi.com", "sbi.bank.in", "yonosbi.com",
                  "sbicard.com", "bank.sbi", "sbiepay.sbi"],
    "hdfcbank.com": ["hdfcbank.co.in", "hdfcsec.com", "hdfclife.com",
                     "payzapp.in", "smartbuy.hdfcbank.com"],
    "icicibank.com": ["icicibank.co.in", "icicidirect.com", "icicilombard.com",
                      "icicipruamc.com", "imobile.icicibank.com"],
    "axisbank.com": ["axisbank.co.in", "axisdirect.in", "freecharge.in"],
    "kotak.com": ["kotak.co.in", "kotaksecurities.com", "kotak811.com"],
    "paytm.com": ["paytm.in", "paytmbank.com", "paytmmoney.com", "paytmmall.com"],
    "phonepe.com": ["phonepe.in"],
    "pnbindia.in": ["pnbindia.com", "netpnb.com"],
    "bankofbaroda.in": ["bankofbaroda.com", "bobibanking.com"],
    "unionbankofindia.co.in": ["unionbankonline.co.in"],
    "npci.org.in": ["npci.org", "bhimupi.org.in"],
    "irctc.co.in": ["irctc.com", "irctctourism.com"],
    "uidai.gov.in": ["myaadhaar.uidai.gov.in", "resident.uidai.gov.in"],
    "incometax.gov.in": ["incometaxindia.gov.in", "incometaxindiaefiling.gov.in"],
    "epfindia.gov.in": ["unifiedportal-mem.epfindia.gov.in", "passbook.epfindia.gov.in"],
    "onlinesbi.sbi": ["sbi.co.in", "onlinesbi.com", "bank.sbi"],
}


def _own_domain(host, brand_domain):
    """
    True when `host` belongs to the brand rather than resembling it.

    Covers the primary domain, any subdomain of it, and the brand's other
    registered domains from BRAND_ALIASES.
    """
    host = host.lstrip("*.")
    owned = [brand_domain] + BRAND_ALIASES.get(brand_domain, [])
    for own in owned:
        if host == own or host.endswith("." + own):
            return True
    return False


def score_domain(host, brand_domain, issuer=None):
    """
    Score one certificate name against one brand.

    Returns (score, reasons). A score of 0 means no brand collision at all --
    the overwhelmingly common case, since most certificates have nothing to do
    with any watched brand.
    """
    host = (host or "").lower().strip()
    if not host or not _HOSTNAME_OK.match(host):
        return 0, []

    is_wildcard = bool(_WILDCARD.match(host))
    bare = _WILDCARD.sub("", host)

    if _own_domain(bare, brand_domain):
        return 0, []     # the brand's own certificate renewals

    name, tld = _split_domain(bare)
    labels = [l for l in bare.split(".") if l]
    # Longest first, and sorted so the result does not depend on set ordering.
    # `hdfcbank` must be tried before its stem `hdfc`, or a domain containing
    # the full brand name scores as though it only contained the stem.
    tokens = sorted(brand_tokens(brand_domain), key=lambda t: (-len(t), t))

    score = 0
    reasons = []
    matched_brand = False

    # Brand collision: strongest match wins, and it is counted once. A domain
    # naming the brand twice is not twice as suspicious.
    for label in labels:
        if matched_brand:
            break
        # Hyphens and underscores are word separators in a domain, so
        # "sbi-verify-kyc" contains the standalone word "sbi".
        parts = [p for p in re.split(r"[-_]", label) if p]
        for token in tokens:
            if label == token:
                score += W_BRAND_EXACT_LABEL
                reasons.append("A domain label is exactly the brand name %r" % token)
                matched_brand = True
                break
            if token in parts:
                score += W_BRAND_EXACT_LABEL
                reasons.append("A hyphen-separated part is exactly the brand name %r" % token)
                matched_brand = True
                break
            if len(label) <= len(token) + 2 and _levenshtein(label, token, 1) <= 1:
                score += W_BRAND_NEAR_LABEL
                reasons.append("Label %r is one character from the brand name %r" % (label, token))
                matched_brand = True
                break
            # The near-match has to run against the parts as well, or
            # `sb1-netbanking.com` -- digit-for-letter on the brand itself,
            # one of the most common squats there is -- scores zero, because
            # the whole label is far too long to be one edit from "sbi".
            near = next((p for p in parts
                         if len(p) <= len(token) + 2 and _levenshtein(p, token, 1) <= 1), None)
            if near:
                score += W_BRAND_NEAR_LABEL
                reasons.append("Domain part %r is one character from the brand name %r"
                               % (near, token))
                matched_brand = True
                break
            # Substring match. A four-character token is distinctive enough to
            # match anywhere in the label; a three-character one is not -- but
            # `sbi` is a real brand, and `sbibank.com` / `mysbi.net` are
            # textbook squats that a length floor alone scores at zero. So a
            # short token still counts when it sits at a word boundary, which
            # is where a brand name goes and where random collisions do not.
            if token in label and (len(token) >= 4
                                   or label.startswith(token)
                                   or label.endswith(token)):
                score += W_BRAND_SUBSTRING
                reasons.append("The brand name %r appears inside label %r" % (token, label))
                matched_brand = True
                break

    if not matched_brand:
        return 0, []

    # Scam vocabulary. This is what separates a typo from a lure.
    affixes_found = [a for a in SCAM_AFFIXES
                     if re.search(r"(?:^|[-_.])%s(?:$|[-_.])" % re.escape(a), bare)]
    if affixes_found:
        score += W_SCAM_AFFIX
        reasons.append("Contains phishing vocabulary: %s" % ", ".join(sorted(affixes_found)[:4]))

    if tld in SUSPICIOUS_TLDS and tld not in ("in", "com", "co.in", "org", "net"):
        score += W_SUSPICIOUS_TLD
        reasons.append("Registered under .%s, over-represented in Indian phishing" % tld)

    if name.count("-") >= 2:
        score += W_MANY_HYPHENS
        reasons.append("Multiple hyphens — the shape of a keyword-stuffed lure")

    if re.search(r"[a-z][01][a-z]|[a-z][a-z][01]", name):
        score += W_DIGIT_SUBSTITUTION
        reasons.append("Digit-for-letter substitution in the name")

    if is_wildcard:
        score += W_WILDCARD_CERT
        reasons.append("Wildcard certificate — one issuance covers unlimited subdomains")

    if issuer and any(m in issuer.lower() for m in FREE_CA_MARKERS):
        score += W_FREE_CA
        reasons.append("Free, instantly-issued certificate (%s) — disposable infrastructure"
                       % issuer.split(",")[0][:48])

    return min(score, 100), reasons


# ── crt.sh polling ────────────────────────────────────────────────────────

# Last-contact bookkeeping per source. The distinction this protects is the
# whole point: "the feed is up and found nothing" and "the feed is down" look
# identical in a result list and mean opposite things.
_source_health = {
    "crt.sh": {"ok": None, "last_success": None, "last_error": None, "detail": None},
    "certspotter": {"ok": None, "last_success": None, "last_error": None, "detail": None},
}
_health_lock = threading.Lock()


def _mark_source(name, ok, detail=None):
    with _health_lock:
        h = _source_health.setdefault(
            name, {"ok": None, "last_success": None, "last_error": None, "detail": None})
        h["ok"] = ok
        h["detail"] = detail
        if ok:
            h["last_success"] = _now()
        else:
            h["last_error"] = _now()


def source_health():
    """
    Per-source availability, for the UI to render honestly.

    `discovery_degraded` is the field that matters: when crt.sh is unreachable,
    no amount of empty result list means "nothing new was issued".
    """
    with _health_lock:
        snapshot = {k: dict(v) for k, v in _source_health.items()}
    crtsh = snapshot.get("crt.sh", {})
    state = crtsh.get("ok")

    # Three states, not two. "Never contacted" is not "reachable" -- reporting
    # it as reachable would be the same false all-clear this function exists to
    # prevent, just one step earlier.
    if state is False:
        note = ("Typosquat discovery depends on crt.sh substring search, and it "
                "is currently unreachable. An empty result list right now means "
                "the feed is down — not that no lookalike certificates were "
                "issued.")
    elif state is None:
        note = ("The discovery feed has not been contacted yet in this process, "
                "so the observations below are whatever was already stored. "
                "Nothing here reflects the current state of certificate "
                "issuance until a poll runs.")
    else:
        note = "Discovery feed reachable."

    return {
        "sources": snapshot,
        "discovery_degraded": state is not True,
        "discovery_state": ("ok" if state is True
                            else "down" if state is False else "unknown"),
        "note": note,
    }


def _fetch_crtsh(query):
    """
    One crt.sh query, with retries. Returns a list of records, or None.

    None and [] are deliberately different: [] means the service answered and
    had nothing, None means we did not get an answer and must not treat the
    absence of hits as evidence of absence. Every caller has to respect that
    distinction or the monitor becomes a false all-clear generator.
    """
    url = CRTSH_URL.format(query=urllib.parse.quote(query))
    last_detail = None

    for attempt in range(CRTSH_RETRIES + 1):
        req = urllib.request.Request(url, headers={
            "User-Agent": USER_AGENT,
            "Accept": "application/json",
        })
        try:
            with urllib.request.urlopen(req, timeout=CRTSH_TIMEOUT) as resp:
                body = resp.read().decode("utf-8", "replace")
            if not body.strip():
                _mark_source("crt.sh", True)
                return []
            records = json.loads(body)
            _mark_source("crt.sh", True)
            return records
        except urllib.error.HTTPError as e:
            # 502/503 from crt.sh means overloaded, not "no results". Retrying
            # is worthwhile; treating it as empty would be a lie.
            last_detail = "HTTP %s" % e.code
        except json.JSONDecodeError:
            last_detail = "non-JSON response (rate-limited or error page)"
        except Exception as e:
            last_detail = str(e)[:120]

        if attempt < CRTSH_RETRIES:
            time.sleep(CRTSH_RETRY_BACKOFF * (attempt + 1))

    print("[CT] crt.sh unreachable for %r: %s" % (query, last_detail))
    _mark_source("crt.sh", False, last_detail)
    return None


def _fetch_certspotter(domain):
    """
    Certificates issued inside one domain's namespace, via Cert Spotter.

    Returns a list of issuance records, or None if the service did not answer.
    """
    url = CERTSPOTTER_URL.format(domain=urllib.parse.quote(domain))
    req = urllib.request.Request(url, headers={
        "User-Agent": USER_AGENT,
        "Accept": "application/json",
    })
    try:
        with urllib.request.urlopen(req, timeout=CERTSPOTTER_TIMEOUT) as resp:
            records = json.loads(resp.read().decode("utf-8", "replace"))
        _mark_source("certspotter", True)
        return records
    except urllib.error.HTTPError as e:
        detail = "HTTP %s%s" % (e.code, " (rate limit)" if e.code == 429 else "")
        print("[CT] certspotter %s for %s" % (detail, domain))
        _mark_source("certspotter", False, detail)
        return None
    except Exception as e:
        print("[CT] certspotter failed for %s: %s" % (domain, e))
        _mark_source("certspotter", False, str(e)[:120])
        return None


def _names_from_record(record):
    """Every hostname a certificate covers: the CN plus all SANs."""
    names = set()
    cn = (record.get("common_name") or "").strip().lower()
    if cn:
        names.add(cn)
    for line in (record.get("name_value") or "").split("\n"):
        line = line.strip().lower()
        if line:
            names.add(line)
    return names


def poll_brand(brand, since_hours=None, ingest=True):
    """
    Poll crt.sh for one brand and record anything that collides with it.

    `since_hours` limits to recently-issued certificates. Left as None on a
    brand's first poll so the existing landscape is captured once, then set on
    subsequent polls so each cycle only looks at what is new.
    """
    brand = brand.lower().strip()
    tokens = sorted(brand_tokens(brand), key=len, reverse=True)
    if not tokens:
        return {"brand": brand, "error": "no usable brand token", "observations": []}

    seen_records = 0
    observations = []
    cutoff = None
    if since_hours:
        cutoff = datetime.now() - timedelta(hours=since_hours)

    reachable = False
    for token in tokens[:2]:      # the full name and, if present, its stem
        records = _fetch_crtsh("%%%s%%" % token)
        if records is None:
            continue
        reachable = True
        seen_records += len(records)

        for record in records[:MAX_RESULTS_PER_BRAND]:
            if cutoff:
                stamp = record.get("entry_timestamp") or record.get("not_before") or ""
                try:
                    issued = datetime.fromisoformat(stamp.replace("Z", "").split(".")[0])
                    if issued < cutoff:
                        continue
                except (ValueError, AttributeError):
                    pass    # unparseable timestamp: keep it rather than drop it

            issuer = record.get("issuer_name") or ""
            for host in _names_from_record(record):
                score, reasons = score_domain(host, brand, issuer)
                if score <= 0:
                    continue
                observations.append({
                    "domain": _WILDCARD.sub("", host),
                    "brand": brand,
                    "score": score,
                    "reasons": reasons,
                    "issuer": issuer[:200],
                    "cert_id": str(record.get("id") or ""),
                    "not_before": record.get("not_before"),
                    "not_after": record.get("not_after"),
                    "source": "crt.sh",
                })
        time.sleep(CRTSH_DELAY_BETWEEN_BRANDS)

    if not reachable:
        _record_poll(brand, "unreachable", 0, 0)
        return {"brand": brand, "error": "crt.sh unreachable", "observations": []}

    stored = _store_observations(observations, ingest=ingest)
    _record_poll(brand, "ok", seen_records, len(stored))
    return {
        "brand": brand,
        "certificates_examined": seen_records,
        "matches": len(observations),
        "new": len(stored),
        "observations": stored,
    }


def _record_poll(brand, status, certs, hits):
    conn = get_db_connection()
    try:
        conn.execute("""
            UPDATE ct_watch
            SET last_polled = ?, last_status = ?,
                certs_seen = certs_seen + ?, hits = hits + ?
            WHERE brand = ?
        """, (_now(), status, int(certs), int(hits), brand))
        conn.commit()
    finally:
        conn.close()


def _store_observations(observations, ingest=True):
    """
    Persist observations, returning only the ones not seen before.

    Re-observing a domain updates `last_seen` and keeps the higher score, but
    does not re-alert. A certificate renewal on a domain already known is not
    news.
    """
    if not observations:
        return []

    # Deduplicate within the batch first: one certificate's SAN list routinely
    # contains the same name several times across records.
    best = {}
    for obs in observations:
        key = (obs["domain"], obs["brand"])
        if key not in best or obs["score"] > best[key]["score"]:
            best[key] = obs

    fresh = []
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        for obs in best.values():
            cur.execute("SELECT id, score FROM ct_observations WHERE domain = ? AND brand = ?",
                        (obs["domain"], obs["brand"]))
            existing = cur.fetchone()
            if existing:
                cur.execute("""
                    UPDATE ct_observations
                    SET last_seen = ?, score = MAX(score, ?)
                    WHERE id = ?
                """, (_now(), obs["score"], existing["id"]))
                continue

            cur.execute("""
                INSERT INTO ct_observations
                    (domain, brand, score, reasons, issuer, cert_id,
                     not_before, not_after, source, first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (obs["domain"], obs["brand"], obs["score"],
                  json.dumps(obs["reasons"]), obs["issuer"], obs["cert_id"],
                  obs.get("not_before"), obs.get("not_after"), obs["source"],
                  _now(), _now()))
            obs["id"] = cur.lastrowid
            fresh.append(obs)
        conn.commit()
    finally:
        conn.close()

    if ingest:
        for obs in fresh:
            if obs["score"] >= SCORE_INGEST_THRESHOLD:
                _ingest_observation(obs)

    return fresh


def _ingest_observation(obs):
    """
    Put a high-scoring observation into the entity graph.

    Only above SCORE_INGEST_THRESHOLD. A weak brand collision is worth
    recording for an analyst to look at, but putting it in the graph would let
    every unrelated site containing "sbi" become a node and drown the thing
    the graph is for.
    """
    try:
        from services.intel import graph
        conn = graph.get_db_connection()
        try:
            eid = graph.upsert_entity(
                conn, "domain", obs["domain"],
                risk=obs["score"],
                confidence=0.6,     # issuance is a lead, not a determination
                meta={"source": "certificate_transparency",
                      "brand": obs["brand"],
                      "issuer": obs["issuer"]},
            )
            graph.record_sighting(
                conn, eid, module="CT Monitor",
                verdict="LOOKALIKE_ISSUED", score=obs["score"],
                context="Certificate issued for a name colliding with %s" % obs["brand"],
                source="ctlog",
            )
            conn.commit()
        finally:
            conn.close()

        conn = get_db_connection()
        conn.execute("UPDATE ct_observations SET entity_id = ? WHERE id = ?",
                     (eid, obs["id"]))
        conn.commit()
        conn.close()
        obs["entity_id"] = eid
    except Exception as e:
        print("[CT] graph ingestion failed for %s: %s" % (obs["domain"], e))



# ── Namespace monitoring (Cert Spotter) ──────────────────────────────────
#
# The other question CT answers. Rather than "who registered a name like ours",
# this asks "what certificates exist inside our own namespace, and did anyone
# unexpected issue one".
#
# Two things it catches that typosquat discovery never will:
#
#   * Mis-issuance. A certificate for the brand's real domain from a CA the
#     organisation does not use is either a CA failure or a compromise. It is
#     the original reason Certificate Transparency exists.
#   * Forgotten subdomains. `test-payments.bank.example` with a live
#     certificate is attack surface the security team may not know it has.
#
# Neither is a phishing finding, and neither is scored on the phishing scale.
# They are recorded separately so an analyst is not asked to triage a bank's
# own staging host as though it were a scam.

def init_namespace_db():
    """Table for certificates observed inside a watched brand's namespace."""
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS ct_namespace (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            brand        TEXT NOT NULL,
            hostname     TEXT NOT NULL,
            issuer       TEXT,
            cert_id      TEXT,
            not_before   TEXT,
            unexpected_ca INTEGER NOT NULL DEFAULT 0,
            first_seen   TEXT NOT NULL,
            last_seen    TEXT NOT NULL,
            UNIQUE(brand, hostname, issuer)
        )
    """)
    cur.execute("CREATE INDEX IF NOT EXISTS idx_ns_brand ON ct_namespace(brand)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_ns_unexpected ON ct_namespace(unexpected_ca)")
    conn.commit()
    conn.close()


def _ca_name(issuer):
    """The organisation from an issuer string, which is what identifies a CA."""
    if isinstance(issuer, dict):
        issuer = issuer.get("name") or ""
    for part in str(issuer or "").split(","):
        part = part.strip()
        if part.upper().startswith("O="):
            return part[2:].strip().strip('"')
    return str(issuer or "")[:80]


def poll_namespace(brand):
    """
    Enumerate certificates inside one brand's own namespace.

    The first poll establishes which CAs the brand legitimately uses; later
    polls flag anything issued by a CA outside that set. Learning the baseline
    rather than hardcoding it matters because every organisation's CA mix is
    different, and a hardcoded list would flag a routine vendor change as a
    compromise.
    """
    brand = brand.lower().strip()
    records = _fetch_certspotter(brand)
    if records is None:
        return {"brand": brand, "error": "certspotter unreachable", "hosts": 0}

    conn = get_db_connection()
    try:
        known_cas = {
            r["issuer"] for r in conn.execute(
                "SELECT DISTINCT issuer FROM ct_namespace WHERE brand = ?", (brand,)
            ).fetchall() if r["issuer"]
        }
        baseline_exists = bool(known_cas)

        new_hosts, unexpected = 0, []
        cur = conn.cursor()
        for rec in records:
            issuer = _ca_name(rec.get("issuer"))
            # On the very first poll everything is new, so nothing can be
            # "unexpected" -- flagging it all would be pure noise.
            is_unexpected = bool(baseline_exists and issuer and issuer not in known_cas)

            for host in (rec.get("dns_names") or []):
                host = str(host).lower().lstrip("*.")
                # ON CONFLICT ... DO UPDATE reports rowcount 1 for both an
                # insert and an update, so counting rowcount would report every
                # re-poll as a fresh discovery. Check first instead.
                existed = cur.execute(
                    "SELECT 1 FROM ct_namespace WHERE brand = ? AND hostname = ? AND issuer = ?",
                    (brand, host, issuer)).fetchone()
                cur.execute("""
                    INSERT INTO ct_namespace
                        (brand, hostname, issuer, cert_id, not_before,
                         unexpected_ca, first_seen, last_seen)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(brand, hostname, issuer) DO UPDATE SET last_seen = excluded.last_seen
                """, (brand, host, issuer, str(rec.get("id") or ""),
                      rec.get("not_before"), 1 if is_unexpected else 0, _now(), _now()))
                if not existed:
                    new_hosts += 1
                if is_unexpected:
                    unexpected.append({"hostname": host, "issuer": issuer})
        conn.commit()
    finally:
        conn.close()

    if unexpected:
        print("[CT] %d certificate(s) inside %s issued by a previously unseen CA."
              % (len(unexpected), brand))

    return {
        "brand": brand,
        "certificates": len(records),
        "new_hosts": new_hosts,
        "unexpected_ca": unexpected,
        "baseline_established": baseline_exists,
    }


def namespace_findings(brand=None, unexpected_only=False, limit=100):
    sql = "SELECT * FROM ct_namespace WHERE 1=1"
    params = []
    if brand:
        sql += " AND brand = ?"
        params.append(brand)
    if unexpected_only:
        sql += " AND unexpected_ca = 1"
    sql += " ORDER BY first_seen DESC LIMIT ?"
    params.append(int(limit))

    conn = get_db_connection()
    rows = [dict(r) for r in conn.execute(sql, params).fetchall()]
    conn.close()
    return rows

# ── Live resolution ───────────────────────────────────────────────────────

def resolve_observations(limit=40, only_unresolved=True):
    """
    DNS-resolve stored observations.

    A certificate exists for every one of these by definition. Whether the name
    also *resolves* separates "registered and provisioned, campaign pending"
    from "live right now" — which is the difference between a registrar notice
    and an urgent takedown.
    """
    from services.intel.lookalike import check_live

    sql = "SELECT id, domain FROM ct_observations"
    if only_unresolved:
        sql += " WHERE resolves IS NULL"
    sql += " ORDER BY score DESC, id DESC LIMIT ?"

    conn = get_db_connection()
    rows = [dict(r) for r in conn.execute(sql, (int(limit),)).fetchall()]
    conn.close()
    if not rows:
        return {"checked": 0, "live": 0}

    by_domain = {r["domain"]: r["id"] for r in rows}
    live = check_live(list(by_domain.keys()), limit=len(by_domain))
    live_map = {r["domain"]: r for r in live}

    conn = get_db_connection()
    try:
        for domain, obs_id in by_domain.items():
            hit = live_map.get(domain)
            conn.execute("""
                UPDATE ct_observations SET resolves = ?, resolved_ips = ?, last_seen = ?
                WHERE id = ?
            """, (1 if hit else 0,
                  json.dumps(hit["ips"]) if hit else None,
                  _now(), obs_id))
        conn.commit()
    finally:
        conn.close()

    return {"checked": len(by_domain), "live": len(live_map)}


# ── Queries ───────────────────────────────────────────────────────────────

def recent_observations(limit=60, min_score=0, brand=None, resolving_only=False):
    sql = "SELECT * FROM ct_observations WHERE score >= ?"
    params = [int(min_score)]
    if brand:
        sql += " AND brand = ?"
        params.append(brand)
    if resolving_only:
        sql += " AND resolves = 1"
    sql += " ORDER BY first_seen DESC, score DESC LIMIT ?"
    params.append(int(limit))

    conn = get_db_connection()
    rows = []
    for r in conn.execute(sql, params).fetchall():
        d = dict(r)
        try:
            d["reasons"] = json.loads(d["reasons"] or "[]")
        except (ValueError, TypeError):
            d["reasons"] = []
        try:
            d["resolved_ips"] = json.loads(d["resolved_ips"] or "[]")
        except (ValueError, TypeError):
            d["resolved_ips"] = []
        rows.append(d)
    conn.close()
    return rows


def stats():
    conn = get_db_connection()
    cur = conn.cursor()
    total = cur.execute("SELECT COUNT(*) AS n FROM ct_observations").fetchone()["n"]
    actionable = cur.execute("SELECT COUNT(*) AS n FROM ct_observations WHERE score >= ?",
                             (SCORE_REPORT_THRESHOLD,)).fetchone()["n"]
    live = cur.execute("SELECT COUNT(*) AS n FROM ct_observations WHERE resolves = 1").fetchone()["n"]
    today = cur.execute(
        "SELECT COUNT(*) AS n FROM ct_observations WHERE first_seen >= date('now')").fetchone()["n"]
    brands = cur.execute("SELECT COUNT(*) AS n FROM ct_watch WHERE active = 1").fetchone()["n"]
    last = cur.execute(
        "SELECT MAX(last_polled) AS t, SUM(certs_seen) AS c FROM ct_watch").fetchone()
    conn.close()
    return {
        "observations": total,
        "actionable": actionable,
        "resolving": live,
        "today": today,
        "brands_watched": brands,
        "last_poll": last["t"],
        "certificates_examined": last["c"] or 0,
        "report_threshold": SCORE_REPORT_THRESHOLD,
        "health": source_health(),
        "note": (
            "Certificate issuance is a lead, not a verdict. A brand collision "
            "means somebody provisioned HTTPS for a confusingly similar name — "
            "which has legitimate explanations, including defensive "
            "registration by the brand itself."
        ),
    }


def mark_reviewed(observation_id, verdict):
    """Analyst adjudication: PHISHING, LEGITIMATE, or UNCLEAR."""
    verdict = (verdict or "").upper().strip()
    if verdict not in ("PHISHING", "LEGITIMATE", "UNCLEAR"):
        return False, "verdict must be PHISHING, LEGITIMATE or UNCLEAR"
    conn = get_db_connection()
    try:
        cur = conn.execute(
            "UPDATE ct_observations SET reviewed = 1, verdict = ? WHERE id = ?",
            (verdict, int(observation_id)))
        conn.commit()
        return cur.rowcount > 0, None
    finally:
        conn.close()


# ── Background poller ─────────────────────────────────────────────────────

_poller_thread = None
_poller_stop = threading.Event()
_poller_state = {"running": False, "last_cycle": None, "cycles": 0, "last_error": None}


def poll_cycle(since_hours=None, ingest=True):
    """One pass over every active brand."""
    results = []
    for entry in watchlist():
        if _poller_stop.is_set():
            break
        # A brand polled before looks only at what is new; a brand's first
        # poll captures the existing landscape once.
        hours = since_hours if entry.get("last_polled") else None
        try:
            result = poll_brand(entry["brand"], since_hours=hours, ingest=ingest)
            # Namespace monitoring runs regardless of whether discovery
            # succeeded -- the two sources fail independently, and losing one
            # must not silently disable the other.
            try:
                result["namespace"] = poll_namespace(entry["brand"])
            except Exception as e:
                result["namespace"] = {"error": str(e)}
            results.append(result)
        except Exception as e:
            print("[CT] brand %s failed: %s" % (entry["brand"], e))
            results.append({"brand": entry["brand"], "error": str(e)})
    return results


def _poller_loop(interval):
    while not _poller_stop.is_set():
        try:
            results = poll_cycle(since_hours=interval / 3600.0 * 2)
            new = sum(r.get("new", 0) for r in results)
            _poller_state["last_cycle"] = _now()
            _poller_state["cycles"] += 1
            _poller_state["last_error"] = None
            if new:
                print("[CT] %d new certificate observation(s) across %d brand(s)."
                      % (new, len(results)))
        except Exception as e:
            _poller_state["last_error"] = str(e)
            print("[CT] poll cycle failed: %s" % e)
        # Interruptible wait, so shutdown does not block for the full interval.
        _poller_stop.wait(interval)
    _poller_state["running"] = False


def start_poller(interval=POLL_INTERVAL_SECONDS):
    """
    Start the background poller.

    Daemon thread: a monitoring loop must never be the reason a process refuses
    to exit. Runs once per process, so with several gunicorn workers only the
    first to call this does the polling -- which is correct, since crt.sh does
    not need four copies of the same query.
    """
    global _poller_thread
    if _poller_thread and _poller_thread.is_alive():
        return False
    _poller_stop.clear()
    _poller_state["running"] = True
    _poller_thread = threading.Thread(target=_poller_loop, args=(interval,),
                                      daemon=True, name="ct-monitor")
    _poller_thread.start()
    print("[CT] Certificate Transparency monitor started (interval %ds)." % interval)
    return True


def stop_poller():
    _poller_stop.set()
    _poller_state["running"] = False


def poller_status():
    return dict(_poller_state,
                thread_alive=bool(_poller_thread and _poller_thread.is_alive()))
