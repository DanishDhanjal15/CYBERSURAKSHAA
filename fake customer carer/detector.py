import re
import os
import sys

# Lazy-loaded PaddleOCR and spaCy instances
_ocr_instance = None
_nlp_instance = None

def get_ocr():
    """Lazy-load and initialize PaddleOCR."""
    global _ocr_instance
    if _ocr_instance is None:
        print("[SHIELD] Initializing PaddleOCR (this may take a few seconds)...")
        try:
            import os
            import logging
            # Bypasses model connectivity checks which fail when offline/behind proxies
            os.environ['PADDLE_PDX_DISABLE_MODEL_SOURCE_CHECK'] = 'True'
            os.environ['DISABLE_AUTO_LOGGING_CONFIG'] = '1'
            # Allow duplicate OpenMP libs (common on Windows with multiple ML packages)
            os.environ['KMP_DUPLICATE_LIB_OK'] = 'TRUE'
            logging.getLogger("ppocr").setLevel(logging.WARNING)

            from paddleocr import PaddleOCR
            # BUG FIX #1: Removed use_textline_orientation=True - it loads 3 extra heavy
            # orientation models (PP-LCNet_x1_0_doc_ori, UVDoc, PP-LCNet_x1_0_textline_ori)
            # and the server-grade PP-OCRv5_server_det detection model, causing 330+ second
            # inference times. Without it, PaddleOCR uses a fast mobile detection pipeline.
            # cpu_threads=1 prevents OpenMP multi-thread deadlock on Windows.
            _ocr_instance = PaddleOCR(lang='en', enable_mkldnn=False, cpu_threads=4)
            print("[SHIELD] PaddleOCR initialized successfully.")
        except Exception as e:
            print(f"[SHIELD ERROR] Failed to initialize PaddleOCR: {e}", file=sys.stderr)
            _ocr_instance = False  # Mark as failed to avoid retrying
    return _ocr_instance

def get_nlp():
    """Lazy-load and initialize spaCy NLP."""
    global _nlp_instance
    if _nlp_instance is None:
        print("[SHIELD] Initializing spaCy NLP...")
        try:
            import spacy
            try:
                _nlp_instance = spacy.load("en_core_web_sm")
            except OSError:
                # Fallback if shortcut link is broken
                import en_core_web_sm
                _nlp_instance = en_core_web_sm.load()
            print("[SHIELD] spaCy NLP initialized successfully.")
        except Exception as e:
            print(f"[SHIELD ERROR] Failed to initialize spaCy NLP: {e}", file=sys.stderr)
            _nlp_instance = False
    return _nlp_instance

# Maximum dimension for OCR input image. Larger images slow OCR significantly.
# At 640px OCR still reads text clearly and inference is 3-4x faster than 1024px.
_OCR_MAX_DIM = 640

def _resize_image_for_ocr(image_path):
    """
    Resize large images to speed up OCR while preserving aspect ratio.
    Returns a path to the (possibly resized) image.
    """
    try:
        from PIL import Image
        img = Image.open(image_path)
        w, h = img.size
        if max(w, h) <= _OCR_MAX_DIM:
            return image_path  # No resize needed
        # Calculate new dimensions preserving aspect ratio
        scale = _OCR_MAX_DIM / max(w, h)
        new_w, new_h = int(w * scale), int(h * scale)
        img_resized = img.resize((new_w, new_h), Image.LANCZOS)
        # Save to a temp file alongside the original
        base, ext = os.path.splitext(image_path)
        temp_path = base + '_ocr_tmp' + ext
        img_resized.save(temp_path)
        print(f"[SHIELD] Resized image from {w}x{h} to {new_w}x{new_h} for OCR.")
        return temp_path
    except Exception as e:
        print(f"[SHIELD WARNING] Could not resize image: {e}", file=sys.stderr)
        return image_path

def extract_text_from_image(image_path):
    """
    Run PaddleOCR on an image file.
    Returns (extracted_text, average_confidence)
    """
    ocr = get_ocr()
    if not ocr:
        return "", 0.0

    # Resize large images first to drastically reduce OCR inference time
    ocr_image_path = _resize_image_for_ocr(image_path)
    temp_created = (ocr_image_path != image_path)

    try:
        # BUG FIX #2: Use predict() - ocr.ocr() is deprecated in PaddleOCR 3.x
        result = list(ocr.predict(ocr_image_path))

        if not result:
            return "", 0.0

        lines = []
        confidences = []

        for res_item in result:
            if res_item is None:
                continue

            # BUG FIX #3: PaddleOCR 3.x returns a dict directly (not wrapped in a list).
            # The dict has 'rec_texts' and 'rec_scores' keys.
            if isinstance(res_item, dict):
                rec_texts = res_item.get('rec_texts', [])
                rec_scores = res_item.get('rec_scores', [])
                for text, conf in zip(rec_texts, rec_scores):
                    if text and text.strip():
                        lines.append(text.strip())
                        confidences.append(float(conf))

            # Handle dict-like objects (OCRResult) with attribute/key access
            elif hasattr(res_item, 'keys'):
                try:
                    rec_texts = res_item['rec_texts'] if 'rec_texts' in res_item else getattr(res_item, 'rec_texts', [])
                    rec_scores = res_item['rec_scores'] if 'rec_scores' in res_item else getattr(res_item, 'rec_scores', [])
                    for text, conf in zip(rec_texts, rec_scores):
                        if text and text.strip():
                            lines.append(text.strip())
                            confidences.append(float(conf))
                except Exception:
                    pass

            # Legacy fallback: old-style list result [[box, (text, conf)], ...]
            elif isinstance(res_item, list):
                for block in res_item:
                    if block and len(block) > 1:
                        try:
                            text = block[1][0]
                            conf = float(block[1][1])
                            if text and text.strip():
                                lines.append(text.strip())
                                confidences.append(conf)
                        except (IndexError, TypeError):
                            pass

        full_text = "\n".join(lines)
        avg_confidence = (sum(confidences) / len(confidences)) * 100 if confidences else 0.0
        print(f"[SHIELD] OCR extracted {len(lines)} text lines, avg confidence: {avg_confidence:.1f}%")
        return full_text, avg_confidence
    except Exception as e:
        print(f"[SHIELD ERROR] OCR processing failed: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc(file=sys.stderr)
        return "", 0.0
    finally:
        # Clean up temp resized image if we created one
        if temp_created and os.path.exists(ocr_image_path):
            try:
                os.remove(ocr_image_path)
            except Exception:
                pass

def extract_phone_numbers(text):
    """
    Extract mobile and toll-free numbers from text using regular expressions.
    Returns a list of dicts: [{'original': '...', 'normalized': '...', 'type': 'mobile/toll-free'}]

    Handles common OCR failure modes:
    - Fragments on separate lines:  "+91 / 93218 / 76543" each on its own line
    - Stray noise digits from icons: "3 76543" where "3" is a misread phone-icon graphic
    Three text variants are tried in order; the first match wins via deduplication.
    """
    if not text:
        return []

    # ── Pass 1: Collapse newlines → spaces so multi-line fragments reunite ──────
    p1 = re.sub(r'[\r\n]+', ' ', text)
    p1 = re.sub(r' {2,}', ' ', p1)

    # ── Pass 2: Digit-glued — remove ALL whitespace between digit/+ clusters ────
    #   "+91 93218 3 76543" → "+9193218376543"  (useful for clean numbers)
    p2 = re.sub(r'(?<=\d)\s+(?=\d)', '', p1)
    p2 = re.sub(r'(?<=\+)\s+(?=\d)', '', p2)

    # ── Pass 3: Stray-digit strip THEN collapse ──────────────────────────────────
    #   Strip 1-2 digit orphan tokens that sit between two larger digit groups.
    #   MUST run on p1 (spaces preserved) so "93218 3 76543" → "93218 76543".
    #   THEN collapse to join: "+91 93218 76543" → "+9193218 76543" → matched.
    #   Example: "+91 93218 3 76543" → strip "3 " → "+91 93218 76543"
    #            → collapse → "+9193218 76543" → mobile match → "9321876543" ✓
    p3 = re.sub(r'(?<!\d)\b\d{1,2}\b\s+(?=\d{5}\b)', '', p1)  # strip orphan
    p3 = re.sub(r'(?<=\d)\s+(?=\d)', '', p3)                   # then collapse
    p3 = re.sub(r'(?<=\+)\s+(?=\d)', '', p3)

    detected = []
    seen_normalized = set()

    def _add_phone(original, norm, phone_type):
        """Deduplicate and append detected phone."""
        if norm and norm not in seen_normalized:
            seen_normalized.add(norm)
            detected.append({'original': original.strip(), 'normalized': norm, 'type': phone_type})

    toll_free_pat = r'\b18[06]0[ -]?\d{2,4}[ -]?\d{4}\b'
    mobile_pat    = r'(?:\+?91|0)?[ -]?[6-9]\d{4}[ -]?\d{5}\b'
    generic_10    = r'\b\d{10}\b'

    for search_text in [p1, p2, p3]:
        for match in re.finditer(toll_free_pat, search_text):
            num_str = match.group()
            norm = "".join(filter(str.isdigit, num_str))
            _add_phone(num_str, norm, 'Toll-Free')

        for match in re.finditer(mobile_pat, search_text):
            num_str = match.group()
            norm = "".join(filter(str.isdigit, num_str))
            if len(norm) > 10:
                norm = norm[-10:]  # Keep last 10 digits (strips country code)
            if len(norm) == 10:
                _add_phone(num_str, norm, 'Mobile')

        for match in re.finditer(generic_10, search_text):
            num_str = match.group()
            norm = num_str
            num_type = 'Mobile' if norm[0] in '6789' else 'Phone'
            _add_phone(num_str, norm, num_type)

    return detected


def detect_brand(text):
    """
    Detect organization brand in text using spacy NER + keyword matching.
    Returns (brand_name, detection_method, confidence_score)
    """
    if not text:
        return "Unknown", "None", 0.0

    # Brand catalog with exact aliases for keyword scanning
    brand_catalog = {
        "Amazon": ["amazon", "amzn"],
        "Flipkart": ["flipkart", "fk"],
        "SBI": ["sbi", "state bank of india", "state bank"],
        "HDFC Bank": ["hdfc", "hdfc bank"],
        "ICICI Bank": ["icici", "icici bank"],
        "Axis Bank": ["axis", "axis bank"],
        "Airtel": ["airtel", "bharti airtel"],
        "Jio": ["jio", "reliance jio"],
        "Paytm": ["paytm"],
        "PhonePe": ["phonepe", "phone pe"]
    }

    text_lower = text.lower()
    
    # 1. First, check direct Keyword Matching (highly reliable for specific set)
    keyword_matches = {}
    for brand, aliases in brand_catalog.items():
        for alias in aliases:
            # Match word boundaries or distinct phrases
            pattern = r'\b' + re.escape(alias) + r'\b'
            if re.search(pattern, text_lower):
                # Score based on exact name vs alias match
                score = 95.0 if alias == brand.lower() else 85.0
                keyword_matches[brand] = max(keyword_matches.get(brand, 0.0), score)

    # 2. Check spaCy Named Entity Recognition
    nlp = get_nlp()
    spacy_matches = {}
    if nlp:
        try:
            doc = nlp(text)
            for ent in doc.ents:
                if ent.label_ == "ORG":
                    ent_text = ent.text.strip().lower()
                    # Check if the extracted ORG entity matches any brand or alias
                    for brand, aliases in brand_catalog.items():
                        if brand.lower() in ent_text or any(alias in ent_text for alias in aliases):
                            spacy_matches[brand] = 95.0
        except Exception as e:
            print(f"[SHIELD WARNING] spaCy brand detection exception: {e}", file=sys.stderr)

    # Combine detections: SpaCy matches are given higher confidence
    combined = {}
    for brand, score in keyword_matches.items():
        combined[brand] = score
    for brand, score in spacy_matches.items():
        # If spaCy detected it, boost the score or mark it
        combined[brand] = max(combined.get(brand, 0.0), score + 5.0)

    # Find the best brand match
    if combined:
        best_brand = max(combined, key=combined.get)
        method = "NLP + Keyword" if (best_brand in spacy_matches and best_brand in keyword_matches) else (
            "NLP Entity" if best_brand in spacy_matches else "Keyword Match"
        )
        conf_score = min(combined[best_brand], 100.0)
        return best_brand, method, conf_score

    return "Unknown", "None", 20.0

if __name__ == "__main__":
    # Quick Test
    test_text = "Call AMAZON CUSTOMER CARE at 1800-3000-9009 or mobile 9876543210 immediately."
    print("Testing Brand detection:")
    print(detect_brand(test_text))
    print("Testing Phone number extraction:")
    print(extract_phone_numbers(test_text))
