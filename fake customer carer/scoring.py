def calculate_risk_score(brand, phone_info, official_contact, is_threat_intel, reports):
    """
    Calculate the Risk Score (0-100) and identify the detection reasons.
    Returns (risk_score, severity, reasons, recommendation)
    """
    risk_score = 0
    reasons = []
    
    # 1. No phone number detected
    if not phone_info:
        # If a recognized brand was found in an image but OCR found no number,
        # this could mean OCR missed a number on a colored/styled background.
        # A customer care poster for a known brand with no detectable number is suspicious.
        if brand and brand != "Unknown":
            return (
                40,
                "Suspicious",
                [
                    f"Brand Detected: {brand} — This appears to be a '{brand}' customer care poster.",
                    "WARNING: No phone number was detected in the image. This may mean the number is printed on a colored/styled background that OCR struggled to read.",
                    "A customer care poster using a known brand without a verifiable number is a common scam pattern. Verify with the official website before calling any number shown in this image."
                ],
                f"CAUTION: '{brand}' branding was detected but no phone number could be verified. If this image contains a phone number, please verify it on {brand}'s official website before calling."
            )
        # Truly no brand, no phone — genuinely unclear/safe
        return 0, "Safe", ["No phone number detected in the text/image."], "No customer care details detected. Double-check your input."

    detected_phone = phone_info.get('normalized', '')
    original_phone = phone_info.get('original', '')
    
    reasons.append(f"Phone Number Detected: {original_phone} ({phone_info.get('type')})")

    # 2. Brand Detection analysis
    if brand == "Unknown":
        reasons.append("No official brand detected in association with the number.")
        if is_threat_intel:
            risk_score += 60
            reasons.append(f"Threat Intelligence Alert: This number has been reported as a scam {reports} time(s).")
        else:
            risk_score += 15
            reasons.append("Unverified phone number detected without brand context.")
    else:
        reasons.append(f"Brand Detected: {brand}")
        
        # Check against official database
        if official_contact:
            off_phone_norm = "".join(filter(str.isdigit, official_contact.get('official_phone', '')))
            det_phone_norm = "".join(filter(str.isdigit, detected_phone))
            
            # Compare numbers
            if off_phone_norm == det_phone_norm:
                risk_score += 5
                reasons.append(f"Verified Match: The number matches the official customer care number for {brand}.")
            else:
                risk_score += 75
                reasons.append(f"CRITICAL MISMATCH: The number is claiming to represent {brand}, but does NOT match their official support number ({official_contact.get('official_phone')}).")
        else:
            # Brand is known but has no official contact in our DB (unlikely with our seeds, but possible)
            risk_score += 35
            reasons.append(f"Brand '{brand}' is recognized, but no official customer care record was found in the database.")

    # 3. Threat Intel Modifier
    if is_threat_intel:
        # Boost risk score
        risk_score += 20
        # Add incremental score for multiple reports
        risk_score += min(reports * 5, 20)
        # Avoid duplicate reasons if already added under Unknown brand
        if f"Threat Intelligence Alert: This number has been reported as a scam {reports} time(s)." not in reasons:
            reasons.append(f"Known Threat Indicator: This number is flagged in our database with {reports} scam report(s).")

    # Clamp Risk Score to 0-100
    risk_score = min(max(risk_score, 0), 100)

    # Determine Severity
    if risk_score <= 30:
        severity = "Safe"
        recommendation = f"This number appears to be SAFE. It matches official contact records for {brand}." if brand != "Unknown" else "No suspicious indicators found. Verify details independently before dialing."
    elif risk_score <= 60:
        severity = "Suspicious"
        recommendation = "EXERCISE CAUTION. This number cannot be fully verified. Do not share personal details, OTPs, or passwords."
    elif risk_score <= 80:
        severity = "High Risk"
        recommendation = "HIGH RISK. Strong mismatch or threat indicators detected. Avoid dialing this number unless verified via official websites."
    else:
        severity = "Critical"
        recommendation = "CRITICAL THREAT. This is a confirmed or highly probable customer care scam. DO NOT CALL THIS NUMBER under any circumstances."

    return risk_score, severity, reasons, recommendation


def calculate_confidence_score(ocr_conf, brand_conf, phone_found, verified_against_db, threat_intel_matched, is_image=True):
    """
    Calculate the Confidence Score (0-100) for the threat assessment.
    """
    if not phone_found:
        return 0.0

    # Normalization parameters (all variables between 0 and 100)
    ocr_val = float(ocr_conf) if ocr_conf is not None else 100.0
    brand_val = float(brand_conf)
    phone_val = 100.0 if phone_found else 0.0
    verif_val = 100.0 if verified_against_db else 50.0
    threat_val = 100.0 if threat_intel_matched else 80.0

    if is_image:
        # Weighted Average with OCR
        weights = {
            'ocr': 0.20,
            'brand': 0.30,
            'phone': 0.15,
            'verification': 0.20,
            'threat': 0.15
        }
        confidence = (
            (ocr_val * weights['ocr']) +
            (brand_val * weights['brand']) +
            (phone_val * weights['phone']) +
            (verif_val * weights['verification']) +
            (threat_val * weights['threat'])
        )
    else:
        # Weighted Average without OCR
        weights = {
            'brand': 0.40,
            'phone': 0.20,
            'verification': 0.20,
            'threat': 0.20
        }
        confidence = (
            (brand_val * weights['brand']) +
            (phone_val * weights['phone']) +
            (verif_val * weights['verification']) +
            (threat_val * weights['threat'])
        )

    return round(min(max(confidence, 0.0), 100.0), 1)

if __name__ == "__main__":
    # Test scoring
    print("Testing scoring systems:")
    risk, sev, reasons, rec = calculate_risk_score(
        brand="Amazon",
        phone_info={'normalized': '9876543210', 'original': '9876543210', 'type': 'Mobile'},
        official_contact={'brand': 'Amazon', 'official_phone': '1800-3000-9009', 'official_website': 'amazon.in'},
        is_threat_intel=True,
        reports=2
    )
    print(f"Risk: {risk}, Severity: {sev}, Reasons: {reasons}, Recommendation: {rec}")
    
    conf = calculate_confidence_score(
        ocr_conf=95.0,
        brand_conf=95.0,
        phone_found=True,
        verified_against_db=True,
        threat_intel_matched=True,
        is_image=True
    )
    print(f"Confidence: {conf}")
