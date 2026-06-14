"""
services/scam_detector/nlp_analyzer.py
--------------------------------------
Keyword-based NLP threat scorer for investment scam detection.
Scans input text for urgency signals and known scam phrases.

Supports two ML engines when model files are available:
  Engine A: TF-IDF + XGBoost (fast, explainable)
  Engine B: XLM-RoBERTa (deep semantic, multilingual)

Falls back to keyword matching when models are unavailable.
"""

from __future__ import annotations
import re
import os
import pickle
from typing import Tuple

# ── Model Paths ──────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SAVED_MODELS_DIR = os.path.join(BASE_DIR, "scam-detector-capstone", "saved_models")

VECTORIZER_PATH = os.path.join(SAVED_MODELS_DIR, "tfidf_vectorizer.pkl")
MODEL_PATH = os.path.join(SAVED_MODELS_DIR, "xgboost_fraud_model.pkl")
ROBERTA_PATH = os.path.join(SAVED_MODELS_DIR, "xlm_roberta_scam_model")

# ── Lazy-loaded Engine A (XGBoost) ───────────────────────────
vectorizer = None
xgb_model = None

try:
    if os.path.exists(VECTORIZER_PATH) and os.path.exists(MODEL_PATH):
        with open(VECTORIZER_PATH, "rb") as f:
            vectorizer = pickle.load(f)
        with open(MODEL_PATH, "rb") as f:
            import warnings
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                xgb_model = pickle.load(f)
        print("[OK] Successfully loaded Engine A (XGBoost) models.")
    else:
        print("[Warning] Engine A models not found. Will fallback to keyword matcher.")
except Exception as e:
    print(f"[Error] Error loading Engine A: {e}")

# ── Lazy-loaded Engine B (XLM-RoBERTa) ──────────────────────
roberta_tokenizer = None
roberta_model = None
device = None

try:
    import torch
    from transformers import AutoTokenizer, AutoModelForSequenceClassification

    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')

    has_local_weights = os.path.exists(ROBERTA_PATH) and any(
        os.path.exists(os.path.join(ROBERTA_PATH, f))
        for f in ["model.safetensors", "pytorch_model.bin", "pytorch_model.pt", "model.ckpt"]
    )

    if has_local_weights:
        roberta_tokenizer = AutoTokenizer.from_pretrained(ROBERTA_PATH)
        roberta_model = AutoModelForSequenceClassification.from_pretrained(ROBERTA_PATH)
        roberta_model.to(device)
        print(f"[OK] Successfully loaded local Engine B (XLM-RoBERTa) on {device.type.upper()}.")
    else:
        hf_model_id = "nahiar/spam-detection-xlm-roberta-v1"
        print(f"[Info] Local weights not found. Loading Engine B from HF Hub: {hf_model_id}...")
        roberta_tokenizer = AutoTokenizer.from_pretrained(hf_model_id)
        roberta_model = AutoModelForSequenceClassification.from_pretrained(hf_model_id)
        roberta_model.to(device)
        print(f"[OK] Successfully loaded Engine B from HF Hub on {device.type.upper()}.")
except ImportError:
    print("[Warning] 'transformers' or 'torch' library not installed. Engine B inactive.")
except Exception as e:
    print(f"[Error] Error loading Engine B: {e}")

# ── Scam / urgency keyword bank ─────────────────────────────
# Each entry is (regex_pattern, weight, human_readable_label)
SCAM_KEYWORDS: list[tuple[str, int, str]] = [
    # High-confidence scam phrases (weight 25)
    (r"guaranteed\s+(?:[^.!?]{0,30}\s+)?(returns?|profit|income|payout|interest|gain)", 25, "Guaranteed returns promise"),
    (r"double\s+(?:[^.!?]{0,30}\s+)?(money|investment|capital|funds|returns?)", 25, "Double your money claim"),
    (r"triple\s+(?:[^.!?]{0,30}\s+)?(money|investment|capital|funds|returns?)", 25, "Triple your investment claim"),
    (r"risk[- ]?free\s+(?:[^.!?]{0,30}\s+)?(investment|returns?|profit|trade|opportunity)", 25, "Risk-free investment claim"),
    (r"ponzi|pyramid\s+scheme", 25, "Ponzi/pyramid scheme reference"),
    (r"get\s+rich\s+quick", 25, "Get rich quick language"),
    # Medium-confidence phrases (weight 15)
    (r"\d+\s*%\s*(daily|weekly|monthly|annual|yearly)?\s*(returns?|profit|interest|income|yield)", 15,
     "Unrealistic percentage returns"),
    (r"no\s+risk|zero\s+risk", 15, "No risk claim"),
    (r"exclusive\s+(offer|opportunity|deal|club)", 15, "Exclusive offer language"),
    (r"join\s+(our\s+)?(group|channel|team|whatsapp|telegram)\s+(now|today)", 15,
     "Invite to private group/channel"),
    (r"withdraw\s+(anytime|instantly|daily|immediately)", 15, "Instant withdrawal claim"),
    # Urgency / pressure tactics (weight 12)
    (r"\burgent\b", 12, "Urgency language"),
    (r"limited\s+time\s+(offer|opportunity|deal|slots?)", 12, "Limited time pressure"),
    (r"act\s+now", 12, "Act now pressure"),
    (r"don'?t\s+miss\s+(out|this)", 12, "FOMO language"),
    (r"slots?\s+(are\s+)?(filling|limited)", 12, "Artificial scarcity"),
    # Crypto / fintech misuse (weight 10)
    (r"\bcrypto\b|\bbitcoin\b|\bethereum\b|\busdt\b|\bnft\b", 10,
     "Crypto/digital asset mention"),
    (r"forex|binary\s+options?", 10, "Forex/binary options mention"),
    (r"trading\s+(bot|signal|platform)", 10, "Automated trading claim"),
    # Social channel lures (weight 8)
    (r"whatsapp\s+(group|link)|telegram\s+(group|channel|bot|link)", 8,
     "WhatsApp/Telegram group lure"),
    (r"click\s+(here|the\s+link|below|this\s+link)", 8, "Suspicious link CTA"),
    (r"refer\s+(friends?|others?|family)", 8, "Referral/recruitment language"),
    # Generic investment bait (weight 5)
    (r"\binvestment\b", 5, "Investment mention"),
    (r"\bpassive\s+income\b", 5, "Passive income mention"),
    (r"\bwealth\b|\bmillionaire\b", 5, "Wealth/millionaire promise"),
]

MAX_POSSIBLE_SCORE = 100


def analyze_text(text: str) -> Tuple[int, int, list[str], dict[str, bool]]:
    """
    Scan `text` using the trained XGBoost model (if loaded),
    falling back to keyword analysis if the model is missing.

    Returns:
        engine_a_score : Integer 0–100 (higher = more suspicious).
        engine_b_score : Integer 0–100.
        reasons        : List of human-readable matched signals.
        engine_status  : Dict tracking if ML models successfully loaded/ran.
    """
    reasons: list[str] = []
    engine_a_score = 0
    engine_b_score = 0

    engine_status = {
        "engine_a_online": vectorizer is not None and xgb_model is not None,
        "engine_b_online": roberta_tokenizer is not None and roberta_model is not None and device is not None
    }

    # 1. Baseline Keyword Check (always calculated as a safety net)
    text_lower = text.lower()
    keyword_score = 0
    keyword_reasons = []
    seen_labels: set[str] = set()

    for pattern, weight, label in SCAM_KEYWORDS:
        if re.search(pattern, text_lower) and label not in seen_labels:
            keyword_score += weight
            seen_labels.add(label)
            keyword_reasons.append(f"🔴 Detected high-risk phrasing: {label}")

    keyword_score = min(keyword_score, MAX_POSSIBLE_SCORE)

    # 2. Primary Engine A Analysis (XGBoost)
    if engine_status["engine_a_online"]:
        try:
            X = vectorizer.transform([text])
            prob = xgb_model.predict_proba(X)[0][1]
            ml_score = int(prob * 100)
            
            # Combine the ML score and the keyword score (take the max)
            engine_a_score = max(ml_score, keyword_score)
            
            reasons.append(f"🤖 Engine A (XGBoost) detected ML fraud probability of {ml_score}%")
            if keyword_reasons:
                reasons.extend(keyword_reasons)
        except Exception as e:
            print(f"Engine A Inference error: {e}")
            engine_status["engine_a_online"] = False

    if not engine_status["engine_a_online"]:
        # Fallback: keyword rule-based scoring only
        engine_a_score = keyword_score
        reasons.extend(keyword_reasons)

    # 3. Secondary Engine B Analysis (XLM-RoBERTa)
    if engine_status["engine_b_online"]:
        try:
            import torch
            inputs = roberta_tokenizer(
                text, padding="max_length", truncation=True,
                max_length=128, return_tensors="pt"
            )
            inputs = {k: v.to(device) for k, v in inputs.items()}

            with torch.no_grad():
                logits = roberta_model(**inputs).logits
            probs = torch.softmax(logits, dim=-1)
            scam_prob = probs[0][1].item()
            engine_b_score = int(scam_prob * 100)
            reasons.append(
                f"🧠 Engine B (XLM-RoBERTa) deep semantic fraud probability of {engine_b_score}%"
            )
        except Exception as e:
            print(f"Engine B Inference error: {e}")
            engine_status["engine_b_online"] = False
            engine_b_score = 0
    else:
        engine_b_score = 0

    return engine_a_score, engine_b_score, reasons, engine_status
