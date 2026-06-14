"""
mock_xgboost.py
---------------
Mock XGBoost model for text-based scam classification.
Replace the stub implementation with a real trained model when ready.
"""

# TODO: Load trained XGBoost model here
# import xgboost as xgb
# import pickle
# model = xgb.XGBClassifier()
# model.load_model("models/xgboost_scam_detector.json")

# TODO: Load TF-IDF or FinBERT vectorizer used during training
# with open("models/tfidf_vectorizer.pkl", "rb") as f:
#     vectorizer = pickle.load(f)


def predict_proba(text: str) -> float:
    """
    Returns the probability (0.0 – 1.0) that the given text is a scam.

    MOCK IMPLEMENTATION — always returns 0.5 (neutral).
    Replace this function body with real model inference once trained weights
    are available.

    Args:
        text: Raw input string from the user message.

    Returns:
        float between 0.0 (definitely safe) and 1.0 (definitely scam).
    """
    # TODO: Vectorize the text using the trained TF-IDF / FinBERT vectorizer
    # features = vectorizer.transform([text])

    # TODO: Run inference on the XGBoost model
    # proba = model.predict_proba(features)[0][1]  # probability of class "scam"
    # return float(proba)

    # MOCK: Return neutral probability until real model is loaded
    return 0.5
