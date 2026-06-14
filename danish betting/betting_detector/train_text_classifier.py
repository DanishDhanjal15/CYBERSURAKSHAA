"""
train_text_classifier.py
------------------------
Train the TF-IDF + Logistic Regression text classifier.

Usage
-----
    python train_text_classifier.py
    python train_text_classifier.py --data datasets/text_labels.csv --output models/saved/tfidf_classifier.pkl

CSV format expected (if using custom data):
    text,label
    "1xbet bonus offer 100%",1
    "Beautiful sunset photo",0

If no CSV is provided, a synthetic dataset is auto-generated from the
keyword dictionary and common safe phrases.
"""

from __future__ import annotations

import argparse
import pickle
import random
import sys
from pathlib import Path

# Ensure the betting_detector package root is on the path
sys.path.insert(0, str(Path(__file__).parent))

import numpy as np
import pandas as pd
from loguru import logger
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report
from sklearn.model_selection import cross_val_score, train_test_split
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer

from models.text_classifier import BETTING_KEYWORDS

# ---------------------------------------------------------------------------
# Synthetic dataset generation
# ---------------------------------------------------------------------------
SAFE_PHRASES = [
    "beautiful sunset at the beach",
    "homemade pasta recipe",
    "morning workout motivation",
    "coffee shop vibes",
    "throwback thursday with friends",
    "new book recommendation",
    "weekend hiking trip",
    "food photography tips",
    "travel diary",
    "selfie with my dog",
    "art exhibition opening",
    "yoga session",
    "city skyline at night",
    "family dinner",
    "birthday celebration",
    "new outfit of the day",
    "plant based meal prep",
    "music festival highlights",
    "gym progress update",
    "learning guitar",
]

BETTING_PHRASES = [
    "win big today with our 1xbet promo code",
    "bet365 free bet welcome bonus",
    "best betting tips guaranteed win",
    "parimatch jackpot weekend offer",
    "fixed match 100% sure win dm me",
    "casino bonus no deposit required",
    "join our vip telegram betting group",
    "stake sports betting odds today",
    "dafabet live betting get bonus",
    "best football odds sportsbook",
    "roulette spin win casino chips",
    "daily betting tips telegram channel",
    "melbet promo code free spins",
    "online gambling crypto bitcoin",
    "football accumulator tips today",
    "over under odds prediction service",
    "bankroll management betting strategy",
    "arbitrage betting guaranteed profit",
    "free tips whatsapp group winners",
    "cashback offer wagering requirement rollover",
]


def generate_synthetic_dataset(n_samples: int = 2000) -> pd.DataFrame:
    """Generate a balanced synthetic training dataset."""
    records = []

    # Positive samples (betting)
    for _ in range(n_samples // 2):
        # Randomly combine keywords and phrases
        parts = []
        parts.append(random.choice(BETTING_PHRASES))
        # Add 1-3 random keywords
        parts.extend(random.sample(BETTING_KEYWORDS, k=random.randint(1, 3)))
        text = " ".join(parts)
        records.append({"text": text, "label": 1})

    # Negative samples (safe)
    for _ in range(n_samples // 2):
        parts = [random.choice(SAFE_PHRASES)]
        # Occasionally add safe words to make it harder
        extra = random.choice(["photo", "life", "love", "nature", "happy", "friends"])
        parts.append(extra)
        records.append({"text": " ".join(parts), "label": 0})

    df = pd.DataFrame(records)
    return df.sample(frac=1, random_state=42).reset_index(drop=True)


# ---------------------------------------------------------------------------
# Training
# ---------------------------------------------------------------------------
def train(data_path: str | None = None, output_path: str | None = None) -> None:
    # Load or generate data
    if data_path and Path(data_path).exists():
        logger.info(f"Loading training data from {data_path}")
        df = pd.read_csv(data_path)
        assert "text" in df.columns and "label" in df.columns, \
            "CSV must have 'text' and 'label' columns."
    else:
        logger.info("No CSV provided — generating synthetic dataset (2000 samples)…")
        df = generate_synthetic_dataset(n_samples=2000)

    logger.info(f"Dataset: {len(df)} samples, {df['label'].sum()} positive")

    X = df["text"].astype(str).tolist()
    y = df["label"].tolist()

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # Build pipeline
    pipeline = Pipeline([
        ("tfidf", TfidfVectorizer(
            ngram_range=(1, 2),
            max_features=20_000,
            sublinear_tf=True,
            min_df=2,
        )),
        ("clf", LogisticRegression(
            C=1.0,
            max_iter=1000,
            class_weight="balanced",
            solver="lbfgs",
            random_state=42,
        )),
    ])

    logger.info("Training TF-IDF + Logistic Regression pipeline…")
    pipeline.fit(X_train, y_train)

    # Evaluate
    y_pred = pipeline.predict(X_test)
    report = classification_report(y_test, y_pred, target_names=["SAFE", "BETTING"])
    logger.info(f"\n{report}")

    cv_scores = cross_val_score(pipeline, X, y, cv=5, scoring="f1")
    logger.info(f"5-fold CV F1: {cv_scores.mean():.3f} ± {cv_scores.std():.3f}")

    # Save
    out_path = Path(output_path or "models/saved/tfidf_classifier.pkl")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "wb") as f:
        pickle.dump(pipeline, f)
    logger.info(f"Model saved to {out_path}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train the betting text classifier")
    parser.add_argument("--data", type=str, default=None, help="Path to labelled CSV file")
    parser.add_argument(
        "--output",
        type=str,
        default="models/saved/tfidf_classifier.pkl",
        help="Output path for the trained model",
    )
    args = parser.parse_args()
    train(data_path=args.data, output_path=args.output)
