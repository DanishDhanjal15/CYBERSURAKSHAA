"""
models/text_classifier.py
-------------------------
Betting text classifier.

Baseline: TF-IDF vectorizer + Logistic Regression (no GPU required).
Optional:  HuggingFace BERT (enabled via USE_BERT=true env variable).

The classifier detects gambling-related language including:
  betting, gambling, sportsbook, odds, jackpot, casino, stake, 1xbet,
  bet365, parimatch, melbet, dafabet, fixed match, telegram group, etc.

If no pre-trained model file is found the classifier falls back to
keyword-only scoring so the system is always functional.
"""

from __future__ import annotations

import os
import pickle
import re
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np
from loguru import logger

# ---------------------------------------------------------------------------
# Keyword dictionary — curated list of betting-related terms
# (used both for fallback scoring and as training signal)
# ---------------------------------------------------------------------------
BETTING_KEYWORDS: list[str] = [
    # Core gambling terms
    "bet", "betting", "gamble", "gambling", "wager", "wagering",
    "sportsbook", "bookmaker", "bookie",
    # Outcomes & odds
    "odds", "handicap", "accumulator", "parlay", "over under",
    "spread", "moneyline", "live betting", "in-play",
    # Casino
    "casino", "jackpot", "slot", "roulette", "blackjack", "poker",
    "baccarat", "spin", "chips", "house edge",
    # Brands
    "1xbet", "bet365", "parimatch", "stake", "dafabet", "melbet",
    "betway", "william hill", "unibet", "betfair", "pinnacle",
    "draftkings", "fanduel", "bovada",
    # Scam / promo patterns
    "fixed match", "sure win", "guaranteed win", "tipster",
    "vip tips", "paid tips", "free tips", "win daily",
    "telegram group", "whatsapp group", "dm for tips",
    # Promotions
    "free bet", "welcome bonus", "deposit bonus", "cashback",
    "promo code", "no deposit", "rollover", "wagering requirement",
    # Crypto gambling
    "crypto casino", "bitcoin bet", "eth gambling",
]

# ---------------------------------------------------------------------------
# Model file path
# ---------------------------------------------------------------------------
MODEL_DIR = Path(__file__).parent / "saved"
TFIDF_MODEL_PATH = MODEL_DIR / "tfidf_classifier.pkl"


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------
@dataclass
class TextClassificationResult:
    """Output from the text classifier."""

    betting_probability: float
    matched_keywords: list[str] = field(default_factory=list)
    method: str = "keyword"  # "keyword" | "tfidf" | "bert"

    def to_dict(self) -> dict:
        return {
            "betting_probability": round(self.betting_probability, 4),
            "matched_keywords": self.matched_keywords,
            "method": self.method,
        }


# ---------------------------------------------------------------------------
# Classifier
# ---------------------------------------------------------------------------
class TextClassifier:
    """
    Multi-strategy betting text classifier.

    Strategy selection (in priority order):
      1. BERT   — if USE_BERT=true AND transformers is installed
      2. TF-IDF — if a trained model file exists at ``models/saved/tfidf_classifier.pkl``
      3. Keyword — always available as a reliable fallback

    Usage::

        clf = TextClassifier()
        result = clf.classify("1xbet bonus offer 100% deposit match")
        print(result.betting_probability)  # e.g. 0.97
        print(result.matched_keywords)     # ["1xbet", "deposit bonus"]
    """

    def __init__(self) -> None:
        self._use_bert: bool = os.getenv("USE_BERT", "false").lower() == "true"
        self._tfidf_pipeline = None
        self._bert_pipeline = None
        self._load_models()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def classify(self, text: str) -> TextClassificationResult:
        """
        Classify the given text.

        Parameters
        ----------
        text : str
            Extracted text from the image (from OCR).

        Returns
        -------
        TextClassificationResult
        """
        if not text or not text.strip():
            return TextClassificationResult(betting_probability=0.0)

        cleaned = self._clean(text)
        keywords = self._match_keywords(cleaned)

        # BERT takes priority if available
        if self._bert_pipeline is not None:
            return self._classify_bert(cleaned, keywords)

        # TF-IDF second
        if self._tfidf_pipeline is not None:
            return self._classify_tfidf(cleaned, keywords)

        # Keyword-only fallback
        return self._classify_keywords(cleaned, keywords)

    # ------------------------------------------------------------------
    # Model loading
    # ------------------------------------------------------------------

    def _load_models(self) -> None:
        """Attempt to load BERT and/or TF-IDF models."""
        if self._use_bert:
            self._load_bert()

        if TFIDF_MODEL_PATH.exists():
            self._load_tfidf()
        else:
            logger.warning(
                f"No TF-IDF model found at {TFIDF_MODEL_PATH}. "
                "Using keyword-only fallback. Run train_text_classifier.py to train."
            )

    def _load_tfidf(self) -> None:
        try:
            with open(TFIDF_MODEL_PATH, "rb") as f:
                self._tfidf_pipeline = pickle.load(f)
            # Quick sanity check — run a dummy prediction to catch sklearn
            # version-mismatch errors (e.g. removed 'multi_class' attribute)
            # at load time rather than at inference time.
            self._tfidf_pipeline.predict_proba(["test"])
            logger.info("TF-IDF classifier loaded.")
        except Exception as exc:
            logger.error(
                f"Failed to load TF-IDF model: {exc}. "
                "This usually happens when the model was trained with a "
                "different scikit-learn version. Re-run "
                "'python train_text_classifier.py' to rebuild the model."
            )
            self._tfidf_pipeline = None

    def _load_bert(self) -> None:
        try:
            from transformers import pipeline  # type: ignore[import-untyped]

            logger.info("Loading BERT classifier (this may take a while)…")
            self._bert_pipeline = pipeline(
                "text-classification",
                model="distilbert-base-uncased",
                return_all_scores=True,
            )
            logger.info("BERT classifier loaded.")
        except ImportError:
            logger.warning(
                "USE_BERT=true but transformers/torch not installed. "
                "Falling back to TF-IDF / keyword."
            )

    # ------------------------------------------------------------------
    # Classification strategies
    # ------------------------------------------------------------------

    def _classify_keywords(self, text: str, keywords: list[str]) -> TextClassificationResult:
        """Keyword density scoring — always available."""
        if not keywords:
            return TextClassificationResult(
                betting_probability=0.0, matched_keywords=[], method="keyword"
            )
        # Each keyword hit adds weight; cap at 1.0
        base_prob = min(1.0, len(keywords) * 0.20 + 0.30)
        return TextClassificationResult(
            betting_probability=round(base_prob, 4),
            matched_keywords=keywords,
            method="keyword",
        )

    def _classify_tfidf(self, text: str, keywords: list[str]) -> TextClassificationResult:
        """Use the trained sklearn pipeline to get a probability."""
        try:
            prob = float(self._tfidf_pipeline.predict_proba([text])[0][1])
            return TextClassificationResult(
                betting_probability=prob,
                matched_keywords=keywords,
                method="tfidf",
            )
        except Exception as exc:
            logger.error(f"TF-IDF inference failed: {exc}. Falling back to keyword.")
            return self._classify_keywords(text, keywords)

    def _classify_bert(self, text: str, keywords: list[str]) -> TextClassificationResult:
        """Use BERT pipeline (fine-tuned on sentiment → adapt to betting context)."""
        try:
            # Truncate to avoid token limits
            truncated = text[:512]
            scores = self._bert_pipeline(truncated)[0]
            if isinstance(scores, dict):
                scores = [scores]
            # Map POSITIVE label → higher probability (simplified heuristic)
            prob_map = {s["label"]: s["score"] for s in scores}
            betting_prob = prob_map.get("POSITIVE", prob_map.get("LABEL_1", 0.0))
            # Blend with keyword signal
            keyword_boost = min(0.3, len(keywords) * 0.05)
            final_prob = min(1.0, betting_prob * 0.7 + keyword_boost)
            return TextClassificationResult(
                betting_probability=round(final_prob, 4),
                matched_keywords=keywords,
                method="bert",
            )
        except Exception as exc:
            logger.error(f"BERT inference failed: {exc}. Falling back to TF-IDF.")
            return self._classify_tfidf(text, keywords)

    # ------------------------------------------------------------------
    # Utilities
    # ------------------------------------------------------------------

    @staticmethod
    def _clean(text: str) -> str:
        """Lowercase and normalise whitespace."""
        text = text.lower()
        text = re.sub(r"[^\w\s]", " ", text)
        text = re.sub(r"\s+", " ", text).strip()
        return text

    @staticmethod
    def _match_keywords(text: str) -> list[str]:
        """Return all betting keywords found in the text."""
        found: list[str] = []
        for kw in BETTING_KEYWORDS:
            if kw.lower() in text:
                found.append(kw)
        return list(dict.fromkeys(found))  # deduplicate, preserve order
