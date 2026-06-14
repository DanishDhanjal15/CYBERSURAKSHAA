import os
base_dir = os.path.dirname(os.path.abspath(__file__))
ROBERTA_PATH = os.path.abspath(os.path.join(base_dir, "..", "saved_models", "xlm_roberta_scam_model"))
print("Path:", ROBERTA_PATH)
print("Exists:", os.path.exists(ROBERTA_PATH))

try:
    from transformers import AutoTokenizer, AutoModelForSequenceClassification
    print("Import successful")
    
    roberta_tokenizer = AutoTokenizer.from_pretrained(ROBERTA_PATH)
    roberta_model = AutoModelForSequenceClassification.from_pretrained(ROBERTA_PATH)
    print("✅ Successfully loaded Engine B")
    
except Exception as e:
    import traceback
    traceback.print_exc()
