"""
services/nfc_analysis.py
------------------------
Threat analysis logic for Near Field Communication (NFC) NDEF records.

NFC tags are a rising delivery vector for proximity scams (smart posters in public transit,
fake retail tags, or parking payment cards). This service parses NDEF payloads (URI, Text,
Smart Poster), correlates them with existing threat indicators in the graph, and scores
them using the suite's custom heuristics.
"""

from __future__ import annotations

import re
from urllib.parse import urlsplit, parse_qs, unquote
from services.intel import calibration

# Reuse the same suspect handle/word lists from QR analysis to ensure consistent rules
from services.qr_analysis import (
    KNOWN_UPI_HANDLES,
    SUSPICIOUS_VPA_WORDS,
    IMPERSONATION_NAMES,
    URL_SHORTENERS,
    _fold,
    parse_upi,
)

# Broad categories of NFC NDEF types
RECORD_WELL_KNOWN = "well-known"
RECORD_MIME = "mime"
RECORD_URI = "uri"
RECORD_TEXT = "text"


def parse_ndef_record(record_type: str, data: str) -> dict:
    """
    Parse a single client-supplied NDEF record and return a structured dictionary.
    """
    record_type = record_type.lower()
    
    # 1. Check if the payload is a URI / URL
    if record_type in ("url", "uri") or data.lower().startswith(("http://", "https://", "tel:", "sms:", "upi:", "mailto:")):
        return _parse_uri_record(data)
        
    # 2. Otherwise treat it as a text record
    return {
        "type": "text",
        "content": data,
        "summary": data[:200]
    }


def _parse_uri_record(uri: str) -> dict:
    """Parse common URI schemes used in NFC tags (Web, Phone, SMS, UPI)."""
    uri_lower = uri.lower()
    
    if uri_lower.startswith("upi://"):
        upi_parsed = parse_upi(uri)
        return {
            "type": "upi",
            "uri": uri,
            "upi": upi_parsed or {},
            "summary": f"UPI Address: {upi_parsed.get('vpa', 'Unknown')}" if upi_parsed else "UPI Intent"
        }
        
    elif uri_lower.startswith("tel:"):
        phone = uri[4:].split("?")[0] # strip any params
        return {
            "type": "phone",
            "uri": uri,
            "phone": phone,
            "summary": f"Telephone number: {phone}"
        }
        
    elif uri_lower.startswith("sms:"):
        # Format: sms:+919876543210?body=hello
        parts = uri[4:].split("?")
        phone = parts[0]
        body = ""
        if len(parts) > 1:
            params = parse_qs(parts[1])
            body = unquote(params.get("body", [""])[0])
        return {
            "type": "sms",
            "uri": uri,
            "phone": phone,
            "body": body,
            "summary": f"SMS to {phone} (body: {body[:30]})"
        }
        
    elif uri_lower.startswith(("http://", "https://")):
        return {
            "type": "url",
            "uri": uri,
            "summary": uri
        }
        
    return {
        "type": "uri_generic",
        "uri": uri,
        "summary": uri
    }


def _analyze_uri(uri_data: dict) -> tuple[int, list[str], dict]:
    """Analyze structured URI records for phishing, spoofing, or auto-dial fraud."""
    score = 0
    reasons: list[str] = []
    details = {"type": uri_data["type"], "uri": uri_data["uri"]}
    
    uri_type = uri_data["type"]
    uri_str = uri_data["uri"]

    if uri_type == "url":
        split = urlsplit(uri_str)
        host = (split.hostname or "").lower()
        details["domain"] = host
        
        if split.scheme == "http":
            score += 15
            reasons.append("The link uses plain unencrypted HTTP. Tap-and-visit scams often use HTTP for simple phishing landing pages.")

        if host in URL_SHORTENERS:
            score += 30
            reasons.append(f"The link is masked behind shortener '{host}'. This prevents users from seeing the destination prior to tapping.")

        try:
            from services.intel.lookalike import SUSPICIOUS_TLDS, DEFAULT_WATCHLIST
            tld = host.rsplit(".", 1)[-1] if "." in host else ""
            # Only the cheap, loosely-policed head of the list (top, xyz,
            # online, ...). The full SUSPICIOUS_TLDS ends in com/org/in for the
            # lookalike *generator*; treating those as suspicious here flagged
            # every ordinary website on earth (+25 for wikipedia.org).
            if tld in SUSPICIOUS_TLDS[:8]:
                score += 25
                reasons.append(f"The domain uses a suspicious TLD '.{tld}', commonly associated with hosting malicious setups.")

            # Lookalike checks
            folded_host = _fold(host)
            for official in DEFAULT_WATCHLIST:
                brand = official.split(".")[0]
                if len(brand) >= 3 and brand in folded_host and host != official and not host.endswith("." + official):
                    score += 40
                    reasons.append(f"Lookalike Domain: Host '{host}' imitates official brand '{brand}' ({official}).")
                    break
        except Exception:
            pass

    elif uri_type == "phone":
        phone = uri_data["phone"]
        details["phone"] = phone
        
        # Check if the number is in the customer care threat database
        try:
            from cc_database import lookup_indicator
            intel = lookup_indicator(phone)
            if intel:
                reports = intel.get("reports", 0)
                score += min(100, 50 + reports * 10)
                reasons.append(f"🚨 This support number is flagged in the customer care database with {reports} scam report(s).")
        except Exception:
            pass
            
        if not reasons:
            reasons.append("NFC tags prompting auto-dialing must be handled with care. Ensure you trust the physical source of the tag.")
            score += 15

    elif uri_type == "sms":
        phone = uri_data["phone"]
        body = uri_data["body"]
        details["phone"] = phone
        details["body"] = body
        
        score += 30
        reasons.append("Auto-sending SMS payload. Tap-and-send triggers can send premium rate messages or confirm account registrations without user consent.")
        
        body_lower = body.lower()
        threat_words = ["block", "suspend", "confirm", "verify", "pay", "money", "code", "otp"]
        hits = [w for w in threat_words if w in body_lower]
        if hits:
            score += 25
            reasons.append(f"SMS body contains security/urgency keywords ({', '.join(hits)}). This matches standard card/sim swapping scam templates.")

    elif uri_type == "upi":
        upi = uri_data["upi"]
        vpa = upi.get("vpa", "")
        details["upi"] = upi
        
        if not vpa:
            score += 35
            reasons.append("The UPI payload contains no valid virtual payment address (VPA).")
        else:
            local, _, handle = vpa.rpartition("@")
            if handle not in KNOWN_UPI_HANDLES:
                score += 25
                reasons.append(f"Unrecognized UPI handle '@{handle}'. Real handles belong to authorized banks (e.g., @ybl, @oksbi).")
                
            folded_local = _fold(local)
            vpa_hits = sorted({w for w in SUSPICIOUS_VPA_WORDS if w in folded_local})
            if vpa_hits:
                score += 35
                reasons.append(f"Payment address contains scam keywords: {', '.join(vpa_hits)}.")
                
            if upi.get("intent") == "collect":
                score += 30
                reasons.append("NFC UPI COLLECT Request: Tapping this triggers a collect prompt to transfer money FROM your account.")

    return min(score, 100), reasons, details


def _analyze_text(content: str) -> tuple[int, list[str], dict]:
    """Scan plain text in NFC tags for scam language and Hinglish patterns."""
    from services.intel.multilingual import score_hinglish
    score, reasons = score_hinglish(content)
    
    details = {"type": "text", "text": content[:500]}
    if not reasons:
        reasons = ["No obvious multilingual scam keywords detected in plain text NDEF payload."]
        
    # Check for spaced out words or general obfuscation
    if re.search(r'\b[a-zA-Z]\s+[a-zA-Z]\s+[a-zA-Z]\b', content):
        score += 25
        reasons.append("Detected obfuscated lettering spacing (e.g. 'H E L P'), a typical tactic used to bypass automated text filters.")
        
    return min(score, 100), list(reasons), details


def analyze_ndef_record(record_type: str, data: str) -> dict:
    """
    Main entry point for analyzing a decoded NDEF record.
    Returns: {payload, type, score, reasons, details, known_entity, indicators}
    """
    from services.intel.indicators import extract_all, KIND_LABELS, KIND_AUTHORITY

    # 1. Parse record
    parsed = parse_ndef_record(record_type, data)
    
    # 2. Perform score/reason analysis
    if parsed["type"] in ("url", "phone", "sms", "upi", "uri_generic"):
        score, reasons, details = _analyze_uri(parsed)
    else:
        score, reasons, details = _analyze_text(parsed["content"])

    # 3. Indicator extraction and Graph lookups
    indicators = extract_all(data)
    known = None
    
    try:
        from services.intel import graph
        for ind in indicators:
            ent = graph.get_entity(ind.kind, ind.normalized)
            # Gate on risk, not mere existence: every analyst scan — including
            # a CLEAN one — ingests its indicators, so "exists in the graph"
            # only means "was scanned before". Without this gate, scanning
            # wikipedia.org twice made it SUSPICIOUS (+35 for being its own
            # previous sighting). The reason text promises "prior FLAGGED
            # artefacts", so the entity must actually have scored as one.
            if ent and (ent.get("risk_max") or 0) >= 40:
                sightings = max(1, ent.get("sightings") or 1)
                known = {
                    "kind": ind.kind,
                    "value": ind.normalized,
                    "sightings": sightings,
                }
                score = min(100, score + 35)
                reasons.insert(0, f"⚠ Found indicator ({KIND_LABELS.get(ind.kind, ind.kind)}) with {sightings} previous sighting(s) in other investigations.")
                break
    except Exception:
        pass

    return {
        "record_type": record_type,
        "raw_data": data,
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


def analyze_nfc_tag(records: list[dict]) -> dict:
    """
    Analyze all NDEF records extracted from a single NFC tag scan.
    """
    results = [analyze_ndef_record(r.get("recordType", "text"), r.get("data", "")) for r in records]
    max_score = max((r["score"] for r in results), default=0)
    
    # Calibrate risk band
    assessment = calibration.assess(max_score, module="nfc_scan")
    
    return {
        "record_count": len(records),
        "results": results,
        "max_score": max_score,
        "assessment": assessment
    }
