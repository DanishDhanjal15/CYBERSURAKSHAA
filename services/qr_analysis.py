"""
services/qr_analysis.py
-----------------------
QR code decoding and payment-fraud heuristics.

UPI QR stickers are the cheapest scam delivery mechanism in India: a printed
square pasted over a shop's real code, a "pay ₹5 to receive your refund"
collect request, a parking-fine QR on a windscreen. The payload is tiny and
fully structured (upi://pay?pa=...), which makes it one of the few places in
this suite where rule-based analysis is the *right* tool rather than a
fallback: every field has a defined meaning and the abuse patterns are
documented by NPCI advisories.

Decoding uses OpenCV's QRCodeDetector, imported lazily so this module can be
imported (and its pure-text analysis unit-tested) on a machine without the
vision stack.

Scoring is heuristic and NOT a calibrated probability. Results go through
services/intel/calibration.assess() so the UI receives the same band structure
(SAFE / UNSURE / THREAT) every other module reports, with `calibrated: false`
stated honestly.
"""

from __future__ import annotations

import re
from urllib.parse import urlsplit, parse_qs, unquote

# ── Reference data ─────────────────────────────────────────────────────────

# Official PSP handles NPCI has allocated. A VPA on an unrecognised handle is
# not automatically fraud (the list grows), but combined with other signals it
# stops a made-up "@sbibank" handle passing as State Bank.
KNOWN_UPI_HANDLES = {
    "ybl", "ibl", "axl", "apl", "yapl", "rapl",          # PhonePe / Amazon Pay
    "paytm", "ptyes", "ptaxis", "pthdfc", "ptsbi",       # Paytm
    "okaxis", "oksbi", "okhdfcbank", "okicici", "okbizaxis",  # Google Pay
    "upi", "sbi", "hdfcbank", "icici", "axisbank", "kotak",
    "aubank", "barodampay", "boi", "cbin", "cnrb", "csbpay", "dbs",
    "federal", "fbl", "idbi", "idfcbank", "indianbank", "indus", "iob",
    "jkb", "karb", "kbl", "mahb", "obc", "psb", "rbl", "sib", "uco",
    "unionbank", "united", "utbi", "yesbank", "ubi", "pnb", "airtel",
    "freecharge", "mobikwik", "jupiteraxis", "niyoicici", "slice", "tapicici",
    "waaxis", "wahdfcbank", "waicici", "wasbi",           # WhatsApp Pay
    "naviaxis", "shriramhdfcbank", "superyes", "timecosmos", "seyes",
}

# Words in a VPA's local part that legitimate merchants essentially never use
# but refund/verification scams rely on. Matched on the folded form so
# "refund1", "ref-und" and "refund.desk" all hit.
SUSPICIOUS_VPA_WORDS = (
    "refund", "cashback", "verify", "verification", "kyc", "support",
    "helpdesk", "helpline", "customercare", "custcare", "care", "officer",
    "official", "lottery", "lucky", "winner", "prize", "claim", "reward",
    "gift", "bonus", "insurance", "police", "cyber", "govt", "government",
    "tax", "fine", "penalty", "challan", "blocked", "unblock", "update",
)

# Institutions scammers put in the payee-name field. A *name* is free text —
# nothing in UPI verifies it — so "SBI REFUND DESK" costs an attacker nothing.
IMPERSONATION_NAMES = (
    "sbi", "state bank", "rbi", "reserve bank", "hdfc", "icici", "axis",
    "punjab national", "pnb", "income tax", "customs", "police", "cyber cell",
    "telecom", "trai", "kbc", "lottery", "electricity", "discom", "gas agency",
    "epfo", "provident fund", "uidai", "aadhaar", "npci", "government",
    "ministry", "court", "challan", "traffic",
)

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "rb.gy",
    "shorturl.at", "tiny.cc", "s.id", "rebrand.ly", "ow.ly", "buff.ly",
}

# Same character confusions the betting OCR matcher folds.
_FOLD = str.maketrans({
    "0": "o", "1": "i", "l": "i", "|": "i", "!": "i",
    "5": "s", "8": "b", "2": "z", "$": "s", "@": "a",
    "-": "", "_": "", ".": "",
})


def _fold(s: str) -> str:
    return (s or "").lower().translate(_FOLD)


# ── Decoding ───────────────────────────────────────────────────────────────

def decode_qr(image_bytes: bytes) -> list[str]:
    """
    Return every distinct QR payload found in the image.

    Uses a multi-engine, multi-preprocessing fallback pipeline so that
    decorated QR codes (e.g. BHIM/UPI codes with a PhonePe or GPay logo
    embedded in the centre) are reliably decoded. OpenCV's built-in detector
    alone fails on these because the logo occludes the central data modules.

    Strategy order (fastest / most reliable first):
      1. pyzbar on the original image
      2. pyzbar on preprocessed variants (grayscale, thresholded, sharpened,
         upscaled, contrast-enhanced, inverted) — handles colour QR codes and
         dark backgrounds
      3. OpenCV WeChatQRCode detector (best OpenCV option for logo-in-QR)
      4. OpenCV detectAndDecodeMulti (catches multiple codes)
      5. OpenCV detectAndDecode (single-code fallback)

    Raises RuntimeError if OpenCV is unavailable.
    Raises ValueError if the bytes cannot be decoded as an image.
    Returns [] when the image has no decodable QR code.
    """
    try:
        import cv2
        import numpy as np
    except ImportError as exc:
        raise RuntimeError(
            "QR decoding requires OpenCV. Run: pip install opencv-python"
        ) from exc

    arr = np.frombuffer(image_bytes, dtype=np.uint8)
    img = cv2.imdecode(arr, cv2.IMREAD_COLOR)
    if img is None:
        raise ValueError("Could not decode the uploaded file as an image.")

    payloads: list[str] = []

    # ── Strategy 1 & 2: pyzbar (handles logo-embedded QR codes best) ────────
    try:
        from pyzbar import pyzbar
        from PIL import Image, ImageFilter, ImageEnhance
        import io

        def _pyzbar_scan(pil_img):
            results = pyzbar.decode(pil_img)
            return [r.data.decode("utf-8", errors="replace") for r in results if r.data]

        # Original image
        pil_orig = Image.open(io.BytesIO(image_bytes)).convert("RGB")
        payloads = _pyzbar_scan(pil_orig)

        if not payloads:
            # Build a set of preprocessed variants for stubborn codes
            variants = []

            # Grayscale
            gray_pil = pil_orig.convert("L")
            variants.append(gray_pil)

            # Sharpened (logo area softens edges)
            variants.append(pil_orig.filter(ImageFilter.SHARPEN))
            variants.append(pil_orig.filter(ImageFilter.UnsharpMask(radius=2, percent=180)))

            # High contrast grayscale (Otsu-like threshold via PIL)
            gray_np = np.array(gray_pil)
            _, th = cv2.threshold(gray_np, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
            variants.append(Image.fromarray(th))

            # Upscaled (low-res screenshots)
            w, h = pil_orig.size
            if max(w, h) < 800:
                variants.append(pil_orig.resize((w * 2, h * 2), Image.LANCZOS))

            # Contrast-enhanced
            variants.append(ImageEnhance.Contrast(pil_orig).enhance(2.0))
            variants.append(ImageEnhance.Sharpness(pil_orig).enhance(3.0))

            # Inverted (white-on-black QR codes)
            variants.append(Image.fromarray(255 - np.array(pil_orig)))

            for variant in variants:
                found = _pyzbar_scan(variant)
                if found:
                    payloads = found
                    break

    except ImportError:
        pass  # pyzbar not installed — fall through to OpenCV strategies
    except Exception:
        pass  # Any pyzbar decode error — fall through

    # ── Strategy 3: OpenCV WeChatQRCode (best for logo-in-QR) ───────────────
    if not payloads:
        try:
            wechat = cv2.wechat_qrcode_WeChatQRCode()
            texts, _ = wechat.detectAndDecode(img)
            payloads = [t for t in texts if t]
        except (AttributeError, cv2.error):
            pass  # WeChatQRCode may not be compiled in all cv2 builds

    # ── Strategy 4 & 5: OpenCV standard detectors ───────────────────────────
    if not payloads:
        detector = cv2.QRCodeDetector()
        try:
            ok, texts, _pts, _codes = detector.detectAndDecodeMulti(img)
            if ok:
                payloads = [t for t in texts if t]
        except cv2.error:
            pass

    if not payloads:
        # Try on grayscale + adaptive threshold for very dark/light images
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        detector = cv2.QRCodeDetector()
        for proc in (
            gray,
            cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)[1],
            cv2.adaptiveThreshold(gray, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C,
                                  cv2.THRESH_BINARY, 11, 2),
            cv2.resize(gray, (gray.shape[1] * 2, gray.shape[0] * 2)),
        ):
            try:
                text, _pts, _code = detector.detectAndDecode(proc)
                if text:
                    payloads = [text]
                    break
            except cv2.error:
                continue

    # ── Deduplicate preserving order ─────────────────────────────────────────
    seen: set[str] = set()
    unique: list[str] = []
    for p in payloads:
        if p and p not in seen:
            seen.add(p)
            unique.append(p)

    # ── Fallback: OCR-based UPI extraction from image text ───────────────────
    # Even when the QR itself fails to decode, the VPA is often printed as
    # plain text below the code (e.g. "UPI ID: rewardbonus@okhdfcbank").
    # Extract it so the analyst pipeline still produces a meaningful result.
    if not unique:
        unique = _extract_upi_from_text(img)

    return unique


def _extract_upi_from_text(img) -> list[str]:
    """
    Last-resort OCR fallback: read all text from the image and extract
    any UPI VPA printed as plain text (e.g. "UPI ID: rewardbonus@okhdfcbank").

    This is the critical path for AI-generated / decorative QR images where
    the QR pattern is visual-only and no QR library can decode it. The UPI ID
    is almost always printed below the QR code on scam banners.

    Uses PaddleOCR (already installed in this project). Falls back gracefully
    if PaddleOCR is unavailable.
    """
    try:
        import cv2

        ok, buf = cv2.imencode(".png", img)
        if not ok:
            return []
        img_bytes = buf.tobytes()

        # ── OCR via the betting module's shared extractor ───────────────────
        # Reuses the PaddleOCR singleton the app has already loaded, instead
        # of constructing a second instance (a full extra copy of the model in
        # RAM) with constructor arguments the installed paddleocr version does
        # not even accept.
        all_text = ""
        try:
            from blueprints.betting import _get_ocr
            all_text = _get_ocr().extract(image_bytes=img_bytes).extracted_text
        except Exception:
            pass

        # ── Regex: find UPI VPA patterns ────────────────────────────────────
        # Pattern: anything@something (covers rewardbonus@okhdfcbank, etc.)
        vpa_pattern = re.compile(
            r'\b([a-z0-9][a-z0-9.\-_]{1,60}@[a-z][a-z0-9]{1,30})\b', re.I
        )
        vpas = vpa_pattern.findall(all_text)

        if vpas:
            # Deduplicate and clean
            seen_v: set[str] = set()
            results = []
            for v in vpas:
                v_clean = v.strip().lower()
                if v_clean not in seen_v:
                    seen_v.add(v_clean)
                    # Also try to extract payee name and amount from OCR text
                    name_match = re.search(
                        r'(?:name|payee)[:\s]+([A-Za-z ]+)', all_text, re.I)
                    amt_match = re.search(
                        r'(?:₹|rs\.?|inr|amount)[:\s]*([0-9,]+(?:\.[0-9]{1,2})?)',
                        all_text, re.I)
                    pn = (name_match.group(1).strip() if name_match else "Unknown")
                    am = (amt_match.group(1).replace(",", "") if amt_match else "")
                    uri = f"upi://pay?pa={v_clean}&pn={pn}&ocr=1"
                    if am:
                        uri += f"&am={am}"
                    results.append(uri)
            return results

        # A bare "@handle" with no local part is deliberately NOT turned into
        # a fabricated "unknown@handle" VPA: that string would be extracted as
        # an indicator, ingested into the entity graph, and reported as if it
        # had been observed. An indicator that was never on the poster must
        # never enter the evidence trail.

    except Exception:
        pass

    return []



# ── UPI payload parsing ────────────────────────────────────────────────────

_VPA_RE = re.compile(r"^[a-z0-9][a-z0-9.\-_]{1,255}@[a-z][a-z0-9]{1,63}$", re.I)


def parse_upi(payload: str) -> dict | None:
    """Parse a upi:// URI into its fields; None if this is not a UPI URI."""
    if not payload.lower().startswith("upi://"):
        return None
    split = urlsplit(payload)
    params = {k: unquote(v[0]) for k, v in parse_qs(split.query).items() if v}
    return {
        "intent": (split.netloc or split.path.lstrip("/")).lower(),  # pay / collect
        "vpa": params.get("pa", "").strip().lower(),
        "payee_name": params.get("pn", "").strip(),
        "amount": params.get("am", "").strip(),
        "note": params.get("tn", "").strip(),
        "merchant_code": params.get("mc", "").strip(),
        "raw_params": params,
    }


# ── Analysis ───────────────────────────────────────────────────────────────

def _analyze_upi(upi: dict) -> tuple[int, list[str], dict]:
    score = 0
    reasons: list[str] = []
    vpa = upi["vpa"]
    details = {"type": "upi", **{k: upi[k] for k in
                                 ("intent", "vpa", "payee_name", "amount", "note",
                                  "merchant_code")}}

    if not vpa or not _VPA_RE.match(vpa):
        score += 35
        reasons.append("The QR claims to be a UPI payment but carries no valid "
                       "payment address — a malformed code is itself a red flag.")
        return score, reasons, details

    local, _, handle = vpa.rpartition("@")

    if handle not in KNOWN_UPI_HANDLES:
        score += 25
        reasons.append("The UPI handle '@%s' is not an NPCI-allocated PSP handle. "
                       "Genuine bank VPAs end in a recognised handle such as "
                       "@ybl, @oksbi or @paytm." % handle)

    folded_local = _fold(local)
    hits = sorted({w for w in SUSPICIOUS_VPA_WORDS if w in folded_local})
    if hits:
        score += min(40, 20 + 10 * (len(hits) - 1))
        reasons.append("The payment address contains %s — vocabulary refund and "
                       "verification scams use, and merchants do not (%s)."
                       % (", ".join("'%s'" % h for h in hits), vpa))

    name_l = upi["payee_name"].lower()
    imp = sorted({n for n in IMPERSONATION_NAMES if n in name_l})
    if imp:
        score += 25
        reasons.append("The payee name '%s' invokes %s. UPI does not verify the "
                       "name field — anyone can type an institution's name into it."
                       % (upi["payee_name"], ", ".join("'%s'" % i for i in imp)))

    if upi["intent"] == "collect":
        score += 20
        reasons.append("This is a COLLECT request: scanning it asks YOU to "
                       "approve paying them. Receiving money never requires "
                       "approving a collect request or entering your PIN.")

    if upi["amount"]:
        score += 10
        reasons.append("The QR pre-fills an amount of ₹%s. A payment code that "
                       "chooses its own amount deserves a second look at who "
                       "the payee is." % upi["amount"])

    note_l = _fold(upi["note"])
    note_hits = sorted({w for w in SUSPICIOUS_VPA_WORDS if w in note_l})
    if note_hits:
        score += 10
        reasons.append("The transaction note carries scam vocabulary (%s)."
                       % ", ".join("'%s'" % h for h in note_hits))

    if not reasons:
        reasons.append("The payment address is well-formed, on a recognised PSP "
                       "handle, and free of refund/verification vocabulary.")

    return min(score, 100), reasons, details


def _analyze_url(payload: str) -> tuple[int, list[str], dict]:
    score = 0
    reasons: list[str] = []
    split = urlsplit(payload if "://" in payload else "http://" + payload)
    host = (split.hostname or "").lower()
    details = {"type": "url", "url": payload, "domain": host}

    if split.scheme == "http":
        score += 15
        reasons.append("The link is plain HTTP — anything entered on it travels "
                       "unencrypted.")

    if host in URL_SHORTENERS:
        score += 30
        reasons.append("The QR hides its destination behind the URL shortener "
                       "%s. A payment or login QR has no honest reason to "
                       "conceal where it leads." % host)

    try:
        from services.intel.lookalike import SUSPICIOUS_TLDS, DEFAULT_WATCHLIST
        tld = host.rsplit(".", 1)[-1] if "." in host else ""
        if tld in SUSPICIOUS_TLDS[:8]:   # the cheap, loosely-policed tail
            score += 20
            reasons.append("The domain uses .%s — a TLD heavily represented in "
                           "Indian phishing infrastructure and rarely used by "
                           "legitimate institutions." % tld)

        folded_host = _fold(host)
        for official in DEFAULT_WATCHLIST:
            brand = official.split(".")[0]
            if len(brand) >= 3 and brand in folded_host and host != official \
                    and not host.endswith("." + official):
                score += 35
                reasons.append("The domain imitates '%s' but is not the official "
                               "domain (%s)." % (brand, official))
                break
    except Exception:
        pass

    if not reasons:
        reasons.append("No structural red flags in the link itself. That does "
                       "not vouch for the page it opens.")

    return min(score, 100), reasons, details


def _analyze_text(payload: str) -> tuple[int, list[str], dict]:
    from services.intel.multilingual import score_hinglish
    score, reasons = score_hinglish(payload)
    if not reasons:
        reasons = ["No scam patterns detected in the encoded text."]
    return score, list(reasons), {"type": "text", "text": payload[:500]}


def analyze_payload(payload: str) -> dict:
    """
    Analyse one decoded QR payload. Pure text — no network, no vision.

    Returns {type, score, reasons, details, indicators, known_entity}.
    """
    from services.intel.indicators import extract_all, KIND_LABELS, KIND_AUTHORITY

    upi = parse_upi(payload)
    if upi:
        score, reasons, details = _analyze_upi(upi)
    elif re.match(r"^(https?://|www\.)", payload, re.I):
        score, reasons, details = _analyze_url(payload)
    else:
        score, reasons, details = _analyze_text(payload)

    indicators = extract_all(payload)

    # Cross-reference against the entity graph: has any prior scan — a betting
    # poster, a customer-care screenshot — already surfaced this identifier?
    known = None
    try:
        from services.intel import graph
        for ind in indicators:
            ent = graph.get_entity(ind.kind, ind.normalized)
            # Only count entities that previously scored as a threat
            # (risk_max >= 40). Clean scans also ingest their indicators, so
            # bare existence in the graph proves nothing — and without this
            # gate a rescan of any clean artefact inflated its own score.
            if ent and (ent.get("risk_max") or 0) >= 40:
                sightings = max(1, ent.get("sightings") or 1)
                known = {
                    "kind": ind.kind,
                    "value": ind.normalized,
                    "sightings": sightings,
                }
                score = min(100, score + 30)
                reasons.insert(0,
                    "⚠ This %s has already appeared in %d prior flagged "
                    "artefact(s) analysed by this platform."
                    % (KIND_LABELS.get(ind.kind, ind.kind).lower(), sightings))
                break
    except Exception:
        pass   # graph unavailable must not fail the scan

    return {
        "payload": payload,
        "score": score,
        "reasons": reasons,
        "details": details,
        "known_entity": known,
        "indicators": [
            {
                "kind": i.kind,
                "label": KIND_LABELS.get(i.kind, i.kind),
                "value": i.normalized,
                "report_to": KIND_AUTHORITY.get(i.kind),
            }
            for i in indicators
        ],
    }


def analyze_image(image_bytes: bytes) -> dict:
    """Decode and analyse every QR in an image."""
    payloads = decode_qr(image_bytes)
    results = [analyze_payload(p) for p in payloads]
    return {
        "qr_count": len(payloads),
        "results": results,
        "max_score": max((r["score"] for r in results), default=0),
    }
