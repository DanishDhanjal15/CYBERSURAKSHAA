import pickle
import sys
import xgboost as xgb
import os

base_dir = os.path.dirname(os.path.abspath(__file__))
model_path = os.path.join(base_dir, "saved_models", "xgboost_fraud_model.pkl")
vec_path = os.path.join(base_dir, "saved_models", "tfidf_vectorizer.pkl")

print(f"Checking if files exist: {os.path.exists(model_path)}, {os.path.exists(vec_path)}")

try:
    with open(vec_path, "rb") as f:
        vectorizer = pickle.load(f)
        
    with open(model_path, "rb") as f:
        model = pickle.load(f)

    test_text = ["Your Binance account is about to be suspended. We detected suspicious activity. Please verify your identity immediately to protect your funds. Act fast! Visit: www.binance-secure-auth123.net"]
    X = vectorizer.transform(test_text)
    prob = model.predict_proba(X)[0][1]
    
    print(f"Prediction success! Probability of scam: {prob:.4f}")
    
except Exception as e:
    import traceback
    traceback.print_exc()
    sys.exit(1)
