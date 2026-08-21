"""
blueprints/geo_intel.py
-----------------------
Cyber Threat Geo-Intelligence Map for CYBERSURAKSHAA.

Enriches scan registry data with geo-location:
  - Phone numbers  → Indian telecom circle (state lat/lng)
  - Domain / URL   → IP geolocation via ip-api.com (free, no key needed)
  - Fallback       → Random jitter around national centroid for unlocatable threats

Exposes:
  GET  /geo/            → Map page
  GET  /geo/api/map-data  → JSON threat marker list
  GET  /geo/api/stats     → JSON summary stats for sidebar
"""

from __future__ import annotations
import re
import json
import random
import threading
from flask import Blueprint, jsonify, render_template, session
from blueprints.auth import login_required
from extensions import limiter, POLLING_RATE_LIMIT

bp = Blueprint('geo_intel', __name__, url_prefix='/geo')

# ── India Telecom Circle → approximate centroid coordinates ──────
# Keyed by the 2-digit prefix of the 10-digit mobile number (after +91).
#
# A 2-digit prefix genuinely does not identify a telecom circle — "98" is
# issued in Maharashtra, Delhi, Gujarat and Punjab alike. Written as a flat
# dict literal, the repeated keys silently collapsed to whichever entry came
# last, so most of the table below was dead: every 98xxxxxxxx number plotted
# in Punjab, every 94xxxxxxxx in Kerala, and so on.
#
# Each prefix now maps to the list of circles that use it, and _phone_to_geo
# picks one deterministically from the remaining digits — so a given number
# always lands in the same place instead of hopping around between refreshes.
TELECOM_CIRCLES: dict[str, list[dict]] = {
    "98": [
        {"state": "Maharashtra",   "lat": 19.076, "lng": 72.877},
        {"state": "Delhi NCR",     "lat": 28.704, "lng": 77.102},
        {"state": "Gujarat",       "lat": 23.020, "lng": 72.571},
        {"state": "Punjab",        "lat": 30.900, "lng": 75.857},
    ],
    "99": [
        {"state": "Maharashtra",   "lat": 18.520, "lng": 73.856},
        {"state": "Delhi NCR",     "lat": 28.535, "lng": 77.391},
    ],
    "94": [
        {"state": "Uttar Pradesh", "lat": 25.317, "lng": 83.010},
        {"state": "Kerala",        "lat": 10.850, "lng": 76.271},
    ],
    "86": [
        {"state": "Haryana",       "lat": 28.017, "lng": 76.384},
        {"state": "Assam",         "lat": 26.144, "lng": 91.736},
    ],
    "70": [{"state": "Maharashtra",    "lat": 21.145, "lng": 79.088}],
    "91": [{"state": "Maharashtra",    "lat": 19.997, "lng": 73.790}],
    "81": [{"state": "Delhi NCR",      "lat": 28.450, "lng": 77.050}],
    "95": [{"state": "Uttar Pradesh",  "lat": 26.846, "lng": 80.946}],
    "97": [{"state": "Uttar Pradesh",  "lat": 27.176, "lng": 78.008}],
    "96": [{"state": "Karnataka",      "lat": 12.971, "lng": 77.594}],
    "80": [{"state": "Karnataka",      "lat": 15.317, "lng": 75.714}],
    "90": [{"state": "Tamil Nadu",     "lat": 13.082, "lng": 80.270}],
    "89": [{"state": "Tamil Nadu",     "lat": 10.789, "lng": 78.701}],
    "87": [{"state": "Gujarat",        "lat": 21.170, "lng": 72.831}],
    "93": [{"state": "West Bengal",    "lat": 22.572, "lng": 88.363}],
    "84": [{"state": "West Bengal",    "lat": 23.541, "lng": 87.305}],
    "92": [{"state": "Rajasthan",      "lat": 26.912, "lng": 75.787}],
    "82": [{"state": "Rajasthan",      "lat": 24.879, "lng": 74.628}],
    "77": [{"state": "Madhya Pradesh", "lat": 23.259, "lng": 77.412}],
    "78": [{"state": "Madhya Pradesh", "lat": 22.719, "lng": 75.857}],
    "79": [{"state": "Telangana",      "lat": 17.385, "lng": 78.486}],
    "85": [{"state": "Andhra Pradesh", "lat": 16.506, "lng": 80.648}],
    "74": [{"state": "Bihar",          "lat": 25.594, "lng": 85.137}],
    "83": [{"state": "Bihar",          "lat": 26.120, "lng": 85.367}],
    "76": [{"state": "Odisha",         "lat": 20.296, "lng": 85.824}],
}

# Comprehensive mapping: first 4 digits of 10-digit number → state
PHONE_PREFIX_MAP: dict[str, dict] = {
    # --- Airtel ---
    "9810": {"state": "Delhi NCR",      "lat": 28.704, "lng": 77.102},
    "9811": {"state": "Delhi NCR",      "lat": 28.635, "lng": 77.224},
    "9820": {"state": "Maharashtra",    "lat": 19.076, "lng": 72.877},
    "9821": {"state": "Maharashtra",    "lat": 18.520, "lng": 73.856},
    "9830": {"state": "West Bengal",    "lat": 22.572, "lng": 88.363},
    "9831": {"state": "West Bengal",    "lat": 22.700, "lng": 88.450},
    "9840": {"state": "Tamil Nadu",     "lat": 13.082, "lng": 80.270},
    "9841": {"state": "Tamil Nadu",     "lat": 11.127, "lng": 78.656},
    "9850": {"state": "Maharashtra",    "lat": 20.000, "lng": 73.790},
    "9860": {"state": "Maharashtra",    "lat": 17.688, "lng": 74.005},
    "9870": {"state": "Delhi NCR",      "lat": 28.450, "lng": 77.050},
    "9880": {"state": "Karnataka",      "lat": 12.971, "lng": 77.594},
    "9886": {"state": "Karnataka",      "lat": 15.317, "lng": 75.714},
    "9890": {"state": "Maharashtra",    "lat": 21.145, "lng": 79.088},
    "9900": {"state": "Karnataka",      "lat": 12.971, "lng": 77.594},
    "9910": {"state": "Delhi NCR",      "lat": 28.704, "lng": 77.102},
    "9920": {"state": "Maharashtra",    "lat": 19.076, "lng": 72.877},
    "9930": {"state": "Maharashtra",    "lat": 19.076, "lng": 72.877},
    "9940": {"state": "Tamil Nadu",     "lat": 13.082, "lng": 80.270},
    "9950": {"state": "Rajasthan",      "lat": 26.912, "lng": 75.787},
    "9960": {"state": "Maharashtra",    "lat": 18.520, "lng": 73.856},
    "9970": {"state": "Maharashtra",    "lat": 19.076, "lng": 72.877},
    "9980": {"state": "Karnataka",      "lat": 12.971, "lng": 77.594},
    "9990": {"state": "Delhi NCR",      "lat": 28.704, "lng": 77.102},
    # --- Jio ---
    "7000": {"state": "Madhya Pradesh", "lat": 23.259, "lng": 77.412},
    "7001": {"state": "West Bengal",    "lat": 22.572, "lng": 88.363},
    "7005": {"state": "Himachal Pradesh","lat": 31.104, "lng": 77.173},
    "7006": {"state": "Jammu & Kashmir","lat": 33.777, "lng": 76.575},
    "7007": {"state": "Uttar Pradesh",  "lat": 26.846, "lng": 80.946},
    "7008": {"state": "Odisha",         "lat": 20.296, "lng": 85.824},
    "7009": {"state": "Punjab",         "lat": 30.900, "lng": 75.857},
    "7010": {"state": "Tamil Nadu",     "lat": 13.082, "lng": 80.270},
    "7011": {"state": "Delhi NCR",      "lat": 28.704, "lng": 77.102},
    "7012": {"state": "Kerala",         "lat": 10.850, "lng": 76.271},
    "7013": {"state": "Telangana",      "lat": 17.385, "lng": 78.486},
    "7014": {"state": "Rajasthan",      "lat": 26.912, "lng": 75.787},
    "7015": {"state": "Haryana",        "lat": 28.017, "lng": 76.384},
    "7016": {"state": "Gujarat",        "lat": 23.020, "lng": 72.571},
    "7017": {"state": "Uttar Pradesh",  "lat": 27.176, "lng": 78.008},
    "7018": {"state": "Bihar",          "lat": 25.594, "lng": 85.137},
    "7019": {"state": "Karnataka",      "lat": 12.971, "lng": 77.594},
    "7020": {"state": "Maharashtra",    "lat": 19.076, "lng": 72.877},
    "8000": {"state": "Rajasthan",      "lat": 24.879, "lng": 74.628},
    "8001": {"state": "West Bengal",    "lat": 22.572, "lng": 88.363},
    "8006": {"state": "Uttar Pradesh",  "lat": 25.317, "lng": 83.010},
    "8008": {"state": "Andhra Pradesh", "lat": 16.506, "lng": 80.648},
    "8009": {"state": "Karnataka",      "lat": 12.971, "lng": 77.594},
    "8010": {"state": "Delhi NCR",      "lat": 28.704, "lng": 77.102},
    "8087": {"state": "Maharashtra",    "lat": 19.076, "lng": 72.877},
    "8088": {"state": "Karnataka",      "lat": 12.971, "lng": 77.594},
    "8089": {"state": "Kerala",         "lat": 10.850, "lng": 76.271},
    "6000": {"state": "Assam",          "lat": 26.144, "lng": 91.736},
    "6001": {"state": "Assam",          "lat": 26.144, "lng": 91.736},
    "6002": {"state": "Meghalaya",      "lat": 25.467, "lng": 91.366},
    "6003": {"state": "Tripura",        "lat": 23.940, "lng": 91.988},
    "6005": {"state": "Manipur",        "lat": 24.817, "lng": 93.936},
    "6006": {"state": "Nagaland",       "lat": 26.158, "lng": 94.562},
    "6009": {"state": "Arunachal Pradesh","lat": 27.100, "lng": 93.617},
}

# Module color coding
MODULE_COLORS = {
    "Investment Scam": "#10b981",
    "Betting Content": "#ef4444",
    "Deepfake Face":   "#a855f7",
    "Customer Care":   "#06b6d4",
}

# India centroid (fallback for unresolvable locations)
INDIA_CENTER = {"lat": 20.593, "lng": 78.962}

# ── Helpers ──────────────────────────────────────────────────────

# What a coordinate on this map actually means.
#
# Every marker is drawn as a pin, and a pin reads as "the threat is here".
# None of these coordinates carry that meaning, and the difference matters
# because an investigator acting on a pin would be acting on nothing. Each
# marker therefore carries a `precision` string stating what was actually
# resolved, and the UI shows it in the popup.
PRECISION = {
    "phone_circle": "Telecom circle (~300 km). Derived from the number's issuing "
                    "circle, not from the handset. It does not indicate where the "
                    "caller is, or was.",
    "ip_city":      "Hosting city from IP geolocation (~25 km, often wrong). This "
                    "is where the server is registered, not where the operator is.",
    "unlocated":    "Not geolocated. Placed at a metro centroid so the artefact "
                    "appears on the map at all. Position carries no information.",
    "simulated":    "Demonstration data. This marker was not observed.",
}


def _jitter(lat: float, lng: float, radius: float = 1.2) -> tuple[float, float]:
    """
    Add a small random offset so co-located markers don't stack perfectly.

    Note that this spreads markers *within* the uncertainty of the underlying
    estimate -- a telecom circle is hundreds of kilometres across -- so it
    costs no real accuracy. It does make the map look more precise than it is,
    which is why every marker carries an explicit `precision` field.
    """
    return (
        lat + random.uniform(-radius, radius),
        lng + random.uniform(-radius, radius),
    )


def _extract_phones(text: str) -> list[str]:
    """Extract Indian mobile numbers from any text string."""
    raw = re.findall(r'(?:\+91|0)?[6-9]\d{9}', re.sub(r'[\s\-\(\)]', '', text))
    cleaned = []
    for num in raw:
        num = re.sub(r'^\+91|^0', '', num)
        if len(num) == 10:
            cleaned.append(num)
    return list(set(cleaned))


def _extract_domains(text: str) -> list[str]:
    """Extract bare domain names from a text string."""
    matches = re.findall(
        r'(?:https?://)?(?:www\.)?([a-zA-Z0-9\-]+\.[a-zA-Z]{2,})',
        text,
    )
    return list(set(m.lower() for m in matches if len(m) > 4))


def _phone_to_geo(number: str) -> dict | None:
    """Map a 10-digit Indian mobile number to a geo coordinate via prefix table."""
    prefix4 = number[:4]
    if prefix4 in PHONE_PREFIX_MAP:
        info = PHONE_PREFIX_MAP[prefix4]
        lat, lng = _jitter(info["lat"], info["lng"], 0.6)
        return {"state": info["state"], "lat": lat, "lng": lng}

    # 2-digit fallback. The prefix maps to several possible circles; choose one
    # from the number's own digits so the same number always resolves to the
    # same circle rather than jumping around on every request.
    prefix2 = number[:2]
    circles = TELECOM_CIRCLES.get(prefix2)
    if circles:
        try:
            selector = int(number[2:6])
        except ValueError:
            selector = 0
        info = circles[selector % len(circles)]
        lat, lng = _jitter(info["lat"], info["lng"], 0.8)
        return {"state": info["state"], "lat": lat, "lng": lng}
    return None


def _domain_to_geo(domain: str) -> dict | None:
    """
    Geolocate a domain's IP using ip-api.com (free, no key, 45 req/min limit).
    Returns geo dict or None on failure.
    """
    try:
        import requests
        # Skip common safe domains
        skip = {"google.com", "youtube.com", "facebook.com", "instagram.com",
                 "twitter.com", "whatsapp.com", "amazon.com", "localhost"}
        if domain in skip:
            return None
        resp = requests.get(
            f"http://ip-api.com/json/{domain}",
            timeout=4,
            params={"fields": "status,country,regionName,city,lat,lon,isp,org"},
        )
        if resp.status_code == 200:
            data = resp.json()
            if data.get("status") == "success" and data.get("lat"):
                return {
                    "state": data.get("city") or data.get("regionName") or data.get("country"),
                    "country": data.get("country"),
                    "isp": data.get("isp"),
                    "lat": data["lat"],
                    "lng": data["lon"],
                }
    except Exception:
        pass
    return None


# Simple in-memory cache for domain geo lookups to avoid hammering ip-api.com
_domain_geo_cache: dict[str, dict | None] = {}
_domain_geo_lock = threading.Lock()

# Cap on entries kept, so the cache cannot grow without bound in a long-lived
# worker process.
_MAX_GEO_CACHE_ENTRIES = 2000

# Cap on *new* lookups performed while serving a single request. The map
# endpoint iterates up to 250 rows; with a cold cache that was up to 250
# sequential HTTP calls at 4s each plus a sleep between them, far past the
# 120s gunicorn timeout — the worker was killed and, with a single worker
# configured, the whole app went down with it. Rows beyond the cap fall back
# to the deterministic city placement, which is what happens for unresolvable
# domains anyway.
MAX_DOMAIN_LOOKUPS_PER_REQUEST = 12


def _cached_domain_geo(domain: str, budget: list | None = None) -> dict | None:
    """
    Geo for a domain, served from cache when possible.

    `budget` is a single-element list used as a mutable counter for the
    current request; when it is exhausted only cached answers are returned and
    no new network call is made.
    """
    with _domain_geo_lock:
        if domain in _domain_geo_cache:
            return _domain_geo_cache[domain]

    if budget is not None:
        if budget[0] <= 0:
            return None
        budget[0] -= 1

    geo = _domain_to_geo(domain)

    with _domain_geo_lock:
        if len(_domain_geo_cache) >= _MAX_GEO_CACHE_ENTRIES:
            _domain_geo_cache.clear()
        _domain_geo_cache[domain] = geo
    return geo


def _build_markers_from_scans(scans: list[dict], budget: list | None = None) -> list[dict]:
    """
    Convert scan registry rows into geo markers for the map.
    Each marker has: lat, lng, module, verdict, score, label, source_type
    """
    markers = []
    seen_locations: set[tuple[float, float]] = set()

    for scan in scans:
        module    = scan.get("module", "Unknown")
        verdict   = scan.get("verdict", "UNKNOWN")
        score     = scan.get("score", 0)
        summary   = scan.get("input_summary", "")
        timestamp = scan.get("timestamp", "")
        indicators = scan.get("indicators") or {}
        if isinstance(indicators, str):
            try:
                indicators = json.loads(indicators)
            except Exception:
                indicators = {}

        color = MODULE_COLORS.get(module, "#64748b")

        # ── 1. Try extracting phone numbers ────────────────────
        phone_candidates = _extract_phones(summary)
        phone_val = (indicators.get("detected_phone") or "").strip()
        if phone_val:
            phone_candidates.insert(0, re.sub(r'[^\d]', '', phone_val))

        phone_placed = False
        for phone in phone_candidates:
            phone = re.sub(r'[^\d]', '', phone)
            if len(phone) == 10:
                geo = _phone_to_geo(phone)
                if geo:
                    lat, lng = geo["lat"], geo["lng"]
                    markers.append({
                        "lat": lat, "lng": lng,
                        "module": module, "verdict": verdict,
                        "score": score, "color": color,
                        "label": f"📱 {phone}",
                        "state": geo["state"],
                        "source_type": "phone",
                        "precision": PRECISION["phone_circle"],
                        "simulated": False,
                        "timestamp": timestamp,
                        "summary": summary[:120],
                    })
                    phone_placed = True
                    break

        # ── 2. Try extracting domain / URL ─────────────────────
        domain_placed = False
        domain_candidates = _extract_domains(summary)

        for domain in domain_candidates[:2]:  # Limit API calls
            geo = _cached_domain_geo(domain, budget)
            if geo:
                lat, lng = _jitter(geo["lat"], geo["lng"], 0.3)
                markers.append({
                    "lat": lat, "lng": lng,
                    "module": module, "verdict": verdict,
                    "score": score, "color": color,
                    "label": f"🌐 {domain}",
                    "state": geo.get("state", geo.get("country", "Unknown")),
                    "country": geo.get("country", "India"),
                    "isp": geo.get("isp", ""),
                    "source_type": "domain",
                    "precision": PRECISION["ip_city"],
                    "simulated": False,
                    "timestamp": timestamp,
                    "summary": summary[:120],
                })
                domain_placed = True
                break

        # ── 3. Fallback — place on India map with module jitter ─
        if not phone_placed and not domain_placed:
            # Use verdict-based regional bias for variety
            fallback_regions = [
                {"lat": 28.704, "lng": 77.102, "state": "Delhi NCR"},
                {"lat": 19.076, "lng": 72.877, "state": "Mumbai"},
                {"lat": 12.971, "lng": 77.594, "state": "Bengaluru"},
                {"lat": 13.082, "lng": 80.270, "state": "Chennai"},
                {"lat": 22.572, "lng": 88.363, "state": "Kolkata"},
                {"lat": 17.385, "lng": 78.486, "state": "Hyderabad"},
                {"lat": 23.020, "lng": 72.571, "state": "Ahmedabad"},
                {"lat": 26.912, "lng": 75.787, "state": "Jaipur"},
            ]
            region = random.choice(fallback_regions)
            lat, lng = _jitter(region["lat"], region["lng"], 1.5)
            markers.append({
                "lat": lat, "lng": lng,
                "module": module, "verdict": verdict,
                "score": score, "color": color,
                "label": f"⚠️ {module}",
                "state": region["state"],
                "source_type": "scan",
                "precision": PRECISION["unlocated"],
                "simulated": False,
                "timestamp": timestamp,
                "summary": summary[:120],
            })

    return markers


def _build_demo_markers() -> list[dict]:
    """
    Demonstration markers, used only when the platform holds no real data.

    These exist so the map renders something on a fresh install. Every one is
    flagged `simulated: True` and labelled [DEMO] in the UI, and the API
    response carries `source: "demo"` so the front end can banner the whole
    map. Presenting these as observations would be the single most damaging
    thing this file could do.
    """
    demo_threats = [
        # Investment scams (green markers)
        {"module": "Investment Scam", "verdict": "SCAM", "score": 92, "phone": "9820123456", "summary": "Guaranteed 30% monthly returns crypto group"},
        {"module": "Investment Scam", "verdict": "SCAM", "score": 87, "phone": "9910654321", "summary": "Bitcoin doubling scheme via Telegram"},
        {"module": "Investment Scam", "verdict": "SUSPICIOUS", "score": 55, "phone": "7012789012", "summary": "Forex trading signal provider"},
        {"module": "Investment Scam", "verdict": "SCAM", "score": 78, "phone": "9840345678", "summary": "Ponzi scheme investment club"},
        {"module": "Investment Scam", "verdict": "SCAM", "score": 95, "phone": "9880901234", "summary": "Risk-free passive income opportunity"},
        # Betting content (red markers)
        {"module": "Betting Content", "verdict": "BETTING", "score": 97, "phone": "9830567890", "summary": "IPL betting tips Instagram post"},
        {"module": "Betting Content", "verdict": "BETTING", "score": 88, "phone": "7001234567", "summary": "Online cricket betting advertisement"},
        {"module": "Betting Content", "verdict": "SUSPICIOUS", "score": 61, "phone": "8010456789", "summary": "Fantasy sports promotion"},
        {"module": "Betting Content", "verdict": "BETTING", "score": 94, "phone": "9950678901", "summary": "Rummy & poker casino app"},
        # Customer Care scams (cyan markers)
        {"module": "Customer Care", "verdict": "DANGER", "score": 89, "phone": "9870234567", "summary": "Fake SBI helpline number in ad"},
        {"module": "Customer Care", "verdict": "DANGER", "score": 82, "phone": "9960789012", "summary": "Impersonating HDFC Bank support"},
        {"module": "Customer Care", "verdict": "SUSPICIOUS", "score": 58, "phone": "9990345678", "summary": "Unknown customer care number"},
        {"module": "Customer Care", "verdict": "DANGER", "score": 91, "phone": "8089012345", "summary": "Fake Amazon refund helpline"},
        # Deepfake (purple markers)
        {"module": "Deepfake Face", "verdict": "FAKE", "score": 94, "domain": "fakenews-india.xyz", "summary": "Deepfake video of PM endorsing crypto"},
        {"module": "Deepfake Face", "verdict": "FAKE", "score": 79, "domain": "viralvideo-bd.net", "summary": "Synthetic face in investment ad"},
        {"module": "Deepfake Face", "verdict": "FAKE", "score": 88, "domain": "scamcelebrity.tk", "summary": "Deepfake celebrity endorsement"},
    ]

    markers = []
    for t in demo_threats:
        color = MODULE_COLORS.get(t["module"], "#64748b")
        geo = None

        if "phone" in t:
            geo = _phone_to_geo(t["phone"])

        if geo:
            lat, lng = _jitter(geo["lat"], geo["lng"], 0.5)
            state = geo["state"]
        else:
            # Random Indian city fallback
            cities = [
                (28.704, 77.102, "Delhi NCR"), (19.076, 72.877, "Mumbai"),
                (12.971, 77.594, "Bengaluru"), (13.082, 80.270, "Chennai"),
                (22.572, 88.363, "Kolkata"),   (17.385, 78.486, "Hyderabad"),
                (23.020, 72.571, "Ahmedabad"), (26.912, 75.787, "Jaipur"),
                (25.594, 85.137, "Patna"),     (26.846, 80.946, "Lucknow"),
                (10.850, 76.271, "Kochi"),     (23.259, 77.412, "Bhopal"),
            ]
            city = random.choice(cities)
            lat, lng = _jitter(city[0], city[1], 0.8)
            state = city[2]

        markers.append({
            "lat": lat, "lng": lng,
            "module": t["module"],
            "verdict": t["verdict"],
            "score": t["score"],
            "color": color,
            "label": f"[DEMO] {t.get('phone', t.get('domain', 'Threat'))}",
            "state": state,
            "source_type": "phone" if "phone" in t else "domain",
            "precision": PRECISION["simulated"],
            "simulated": True,
            # No timestamp. A fabricated one would read as an observation time
            # and there was no observation.
            "timestamp": None,
            "summary": t["summary"],
        })

    return markers


# ── Routes ────────────────────────────────────────────────────────

@bp.route('/')
@login_required
def index():
    return render_template('geo_intel/index.html', active_page='geo')


def _marker_from_alert(alert: dict, budget: list | None = None) -> dict | None:
    """
    Convert a crawler alert row into a geo marker.
    Tries domain geo from the URL, falls back to deterministic city by id.
    """
    category_map = {
        "Investment Scam": ("Investment Scam", "#10b981"),
        "Betting Content": ("Betting Content", "#ef4444"),
        "Customer Care":   ("Customer Care",   "#06b6d4"),
        "Deepfake Face":   ("Deepfake Face",   "#a855f7"),
    }
    module, color = category_map.get(
        alert.get("category", ""),
        ("Unknown", "#64748b")
    )

    url     = alert.get("url", "")
    content = alert.get("content", "")
    score   = int(alert.get("risk_score", 50))
    ts      = alert.get("timestamp", "")
    summary = (content or url)[:120]

    # 1. Try domain geo from the URL
    domains = _extract_domains(url)
    for domain in domains[:1]:
        # Skip government/major domains
        safe_tlds = {".gov.in", ".nic.in", "sbi.co.in", "rbi.org.in"}
        if any(s in domain for s in safe_tlds):
            break
        geo = _cached_domain_geo(domain, budget)
        if geo:
            lat, lng = _jitter(geo["lat"], geo["lng"], 0.4)
            return {
                "lat": lat, "lng": lng,
                "module": module, "verdict": "ALERT",
                "score": score, "color": color,
                "label": f"🌐 {domain}",
                "state": geo.get("state", "Unknown"),
                "country": geo.get("country", "India"),
                "isp": geo.get("isp", ""),
                "source_type": "domain",
                "precision": PRECISION["ip_city"],
                "simulated": False,
                "timestamp": ts,
                "summary": summary,
            }

    # 2. Try phone from content
    phones = _extract_phones(content)
    for phone in phones[:1]:
        geo = _phone_to_geo(phone)
        if geo:
            lat, lng = _jitter(geo["lat"], geo["lng"], 0.5)
            return {
                "lat": lat, "lng": lng,
                "module": module, "verdict": "ALERT",
                "score": score, "color": color,
                "label": f"📱 {phone}",
                "state": geo["state"],
                "source_type": "phone",
                "precision": PRECISION["phone_circle"],
                "simulated": False,
                "timestamp": ts,
                "summary": summary,
            }

    # 3. Deterministic fallback: use alert ID to pick a consistent city
    CITIES = [
        (28.704, 77.102, "Delhi NCR"),     (19.076, 72.877, "Mumbai"),
        (12.971, 77.594, "Bengaluru"),     (13.082, 80.270, "Chennai"),
        (22.572, 88.363, "Kolkata"),       (17.385, 78.486, "Hyderabad"),
        (23.020, 72.571, "Ahmedabad"),     (26.912, 75.787, "Jaipur"),
        (25.594, 85.137, "Patna"),         (26.846, 80.946, "Lucknow"),
        (10.850, 76.271, "Kochi"),         (23.259, 77.412, "Bhopal"),
        (30.900, 75.857, "Ludhiana"),      (21.145, 79.088, "Nagpur"),
        (11.127, 78.656, "Coimbatore"),    (26.144, 91.736, "Guwahati"),
    ]
    aid   = int(alert.get("id", 0))
    city  = CITIES[aid % len(CITIES)]
    # Add small deterministic jitter based on id
    lat   = city[0] + (aid % 17 - 8) * 0.12
    lng   = city[1] + (aid % 13 - 6) * 0.15
    return {
        "lat": lat, "lng": lng,
        "module": module, "verdict": "ALERT",
        "score": score, "color": color,
        "label": f"⚠️ {alert.get('source', module)[:30]}",
        "state": city[2],
        "source_type": "scan",
        "precision": PRECISION["unlocated"],
        "simulated": False,
        "timestamp": ts,
        "summary": summary,
    }


def _marker_from_scan(scan: dict, budget: list | None = None) -> dict | None:
    """Convert a user scan row into a geo marker."""
    module    = scan.get("module", "Unknown")
    verdict   = scan.get("verdict", "UNKNOWN")
    score     = int(scan.get("score", 0))
    summary   = scan.get("input_summary", "")[:120]
    timestamp = scan.get("timestamp", "")
    color     = MODULE_COLORS.get(module, "#64748b")

    indicators = scan.get("indicators") or {}
    if isinstance(indicators, str):
        try:
            indicators = json.loads(indicators)
        except Exception:
            indicators = {}

    # 1. Phone from indicators or summary
    phone_val = re.sub(r"[^\d]", "", str(indicators.get("detected_phone", "")))
    phones    = ([phone_val] if len(phone_val) == 10 else []) + _extract_phones(summary)
    for phone in phones[:1]:
        geo = _phone_to_geo(phone)
        if geo:
            lat, lng = _jitter(geo["lat"], geo["lng"], 0.5)
            return {
                "lat": lat, "lng": lng,
                "module": module, "verdict": verdict,
                "score": score, "color": color,
                "label": f"📱 {phone}",
                "state": geo["state"],
                "source_type": "phone",
                "precision": PRECISION["phone_circle"],
                "simulated": False,
                "timestamp": timestamp,
                "summary": summary,
            }

    # 2. Domain from indicators or summary
    domain_val = str(indicators.get("detected_domain", "") or indicators.get("url", ""))
    domains    = _extract_domains(domain_val) + _extract_domains(summary)
    for domain in domains[:1]:
        geo = _cached_domain_geo(domain, budget)
        if geo:
            lat, lng = _jitter(geo["lat"], geo["lng"], 0.4)
            return {
                "lat": lat, "lng": lng,
                "module": module, "verdict": verdict,
                "score": score, "color": color,
                "label": f"🌐 {domain}",
                "state": geo.get("state", "Unknown"),
                "country": geo.get("country", "India"),
                "isp": geo.get("isp", ""),
                "source_type": "domain",
                "precision": PRECISION["ip_city"],
                "simulated": False,
                "timestamp": timestamp,
                "summary": summary,
            }

    # 3. Deterministic city based on scan id
    CITIES = [
        (28.704, 77.102, "Delhi NCR"),     (19.076, 72.877, "Mumbai"),
        (12.971, 77.594, "Bengaluru"),     (13.082, 80.270, "Chennai"),
        (22.572, 88.363, "Kolkata"),       (17.385, 78.486, "Hyderabad"),
        (23.020, 72.571, "Ahmedabad"),     (26.912, 75.787, "Jaipur"),
        (25.594, 85.137, "Patna"),         (26.846, 80.946, "Lucknow"),
        (10.850, 76.271, "Kochi"),         (23.259, 77.412, "Bhopal"),
        (30.900, 75.857, "Ludhiana"),      (21.145, 79.088, "Nagpur"),
    ]
    sid  = int(scan.get("id", 0))
    city = CITIES[sid % len(CITIES)]
    lat  = city[0] + (sid % 19 - 9) * 0.10
    lng  = city[1] + (sid % 11 - 5) * 0.13
    return {
        "lat": lat, "lng": lng,
        "module": module, "verdict": verdict,
        "score": score, "color": color,
        "label": f"⚠️ {module} Scan",
        "state": city[2],
        "source_type": "scan",
        "precision": PRECISION["unlocated"],
        "simulated": False,
        "timestamp": timestamp,
        "summary": summary,
    }


@bp.route('/api/map-data')
@limiter.limit(POLLING_RATE_LIMIT)
@login_required
def api_map_data():
    """
    Return geo-enriched threat markers as JSON.
    Pulls from BOTH the scans table (user submissions) AND the alerts table
    (live crawler feed) to always show real data, never hardcoded demo.
    """
    from services.auth_db import get_db_connection

    markers = []

    # Standard users see only their own scans. This query had no user filter,
    # so any logged-in user could read every other user's scan summaries —
    # phone numbers, scam message text, verdicts — straight off this endpoint.
    user_id = session.get('user_id')
    is_admin = session.get('user_role') == 'admin'

    # Shared budget of new (uncached) geo lookups for this request.
    budget = [MAX_DOMAIN_LOOKUPS_PER_REQUEST]

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # ── Pull from scans table ──────────────────────────────
        if is_admin:
            cursor.execute("""
                SELECT id, timestamp, module, input_summary, verdict, score, indicators
                FROM scans ORDER BY id DESC LIMIT 150
            """)
        else:
            cursor.execute("""
                SELECT id, timestamp, module, input_summary, verdict, score, indicators
                FROM scans WHERE user_id = ? ORDER BY id DESC LIMIT 150
            """, (user_id,))
        for row in cursor.fetchall():
            d = dict(row)
            try:
                d["indicators"] = json.loads(d["indicators"]) if d.get("indicators") else {}
            except Exception:
                d["indicators"] = {}
            m = _marker_from_scan(d, budget)
            if m:
                markers.append(m)

        # ── Pull from alerts table (crawler feed) ──────────────
        cursor.execute("""
            SELECT id, timestamp, source, content, category, risk_score, url
            FROM alerts ORDER BY id DESC LIMIT 100
        """)
        for row in cursor.fetchall():
            m = _marker_from_alert(dict(row), budget)
            if m:
                markers.append(m)

        conn.close()

        source = "live" if markers else "demo"
        if not markers:
            markers = _build_demo_markers()

        return jsonify({"markers": markers, "source": source, "count": len(markers)})

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"markers": _build_demo_markers(), "source": "demo", "error": str(e)})


@bp.route('/api/stats')
@limiter.limit(POLLING_RATE_LIMIT)
@login_required
def api_stats():
    """Return summary stats combining both scans + alerts tables."""
    from services.auth_db import get_db_connection

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Scan-side figures are scoped to the caller unless they are an admin,
        # matching /geo/api/map-data — otherwise the sidebar counts leaked the
        # size and composition of everyone else's scan history.
        user_id = session.get('user_id')
        is_admin = session.get('user_role') == 'admin'
        scan_filter = "" if is_admin else " WHERE user_id = ?"
        scan_params: tuple = () if is_admin else (user_id,)

        def _and(clause: str) -> str:
            """Append a condition, respecting whether a WHERE already exists."""
            return (" AND " if scan_filter else " WHERE ") + clause

        # Total from both tables
        cursor.execute(f"SELECT COUNT(*) FROM scans{scan_filter}", scan_params)
        scan_count = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM alerts WHERE status = 'ACTIVE'")
        alert_count = cursor.fetchone()[0]

        total = scan_count + alert_count

        # High risk
        cursor.execute(
            f"SELECT COUNT(*) FROM scans{scan_filter}" + _and("""(
                   LOWER(verdict) LIKE '%scam%'
                OR LOWER(verdict) LIKE '%betting%'
                OR LOWER(verdict) LIKE '%fake%'
                OR LOWER(verdict) LIKE '%danger%'
            )"""),
            scan_params
        )
        hr_scans = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM alerts WHERE risk_score >= 70")
        hr_alerts = cursor.fetchone()[0]

        high_risk = hr_scans + hr_alerts

        # Module breakdown — merge scans + alerts
        cursor.execute(
            f"SELECT module, COUNT(*) as cnt FROM scans{scan_filter} GROUP BY module",
            scan_params
        )
        scan_modules = {r[0]: r[1] for r in cursor.fetchall()}

        cursor.execute("SELECT category, COUNT(*) as cnt FROM alerts GROUP BY category")
        alert_modules = {r[0]: r[1] for r in cursor.fetchall()}

        # Merge
        all_modules: dict[str, int] = {}
        for m, c in {**scan_modules}.items():
            all_modules[m] = all_modules.get(m, 0) + c
        for m, c in alert_modules.items():
            all_modules[m] = all_modules.get(m, 0) + c

        by_module = [
            {"module": m, "count": c}
            for m, c in sorted(all_modules.items(), key=lambda x: -x[1])
        ]

        # Today
        cursor.execute(
            f"SELECT COUNT(*) FROM scans{scan_filter}"
            + _and("timestamp >= datetime('now', '-1 day')"),
            scan_params
        )
        today_scans = cursor.fetchone()[0]

        cursor.execute("""
            SELECT COUNT(*) FROM alerts
            WHERE timestamp >= datetime('now', '-1 day')
        """)
        today_alerts = cursor.fetchone()[0]

        conn.close()

        return jsonify({
            "total_scans": total,
            "scan_count": scan_count,
            "alert_count": alert_count,
            "high_risk": high_risk,
            "today": today_scans + today_alerts,
            "by_module": by_module,
            "is_demo": total == 0,
        })

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({
            "total_scans": 0, "high_risk": 0, "today": 0,
            "by_module": [], "is_demo": True,
        })

