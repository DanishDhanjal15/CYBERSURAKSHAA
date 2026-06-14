# 🏗️ ScamGuard AI: Architecture & Pipeline

This document details the underlying mechanics, data engineering, and mathematical models that power the ScamGuard AI threat detection pipeline.

---

## 1. The Multilingual Data Pipeline

The foundation of the models relies on high-quality, balanced datasets capable of representing global and regional financial threats.

### Base Dataset & Augmentation
* **Source:** The initial foundation was built using the UCI SMS Spam Collection.
* **Regional Translation:** To fulfill the SMA (Social Media Analytics) parameters for regional India, real-world scam texts were augmented, sliced, and translated into **Hindi** and **Marathi** using the `deep-translator` library.
* **Final Form:** The resulting dataset consists of 320 highly curated, perfectly balanced rows of multilingual text, ensuring no heavy class imbalance penalizes the minority languages during gradient descent.

---

## 2. Engine A: Ensemble Learning (XGBoost)

Engine A serves as the highly explainable, rapid-inference wing of the pipeline.

### Mathematical Mechanics
* **Feature Extraction (TF-IDF):** 
  Text is converted into numerical feature vectors using Term Frequency-Inverse Document Frequency. 
  * Parameters: `ngram_range=(1,2)`, `max_features=2500`. This allows the model to capture two-word urgency signatures (e.g., "act now", "double money") rather than just isolated words.
* **Algorithm (Gradient Boosting):**
  Uses the `XGBoost` Classifier.
  * Parameters: `n_estimators=150`, `max_depth=5`, `learning_rate=0.1`.
  * XGBoost builds an ensemble of shallow decision trees sequentially, with each new tree correcting the residual errors of the previous ones.
* **Performance:** Achieved **87.50%** accuracy on validation slices.

---

## 3. Engine B: Deep Learning (Transfer Learning)

Engine B provides the deep semantic understanding necessary to catch sophisticated, nuanced scams that bypass simple TF-IDF vectors, specifically in non-English contexts.

### Neural Mechanics
* **Base Model:** Meta's `XLM-RoBERTa`, a Transformer-based masked language model pre-trained on 2.5TB of filtered CommonCrawl data spanning 100 languages.
* **Tokenization:** Text is mapped to subword tokens. 
  * Parameters: `max_length=128`, `padding="max_length"`, `truncation=True`.
* **Fine-tuning (AAI):** 
  The classification head of XLM-R was fine-tuned for 4 epochs using the Hugging Face `Trainer` API and PyTorch. Loss gradients were optimized using AdamW.
* **Hardware Acceleration:** Training was executed on a Google Colab **Tesla T4**. Local inference is pushed to the GPU (`.to(device)`) utilizing an **RTX 2050** to minimize latency.
* **Performance:** Achieved **95.31%** accuracy on unseen test data.

---

## 4. Fusion Logic & The Traffic Light Metric

When a payload hits the `/api/analyze` endpoint, it undergoes the following computation to yield a final, actionable risk metric for the end-user.

### The Algorithm
The backend implements a weighted ensemble fusion:
```math
Final Score = (Engine B Output \times 0.70) + (Engine A Output \times 0.30)
```
Engine B holds a heavier weight ($70\%$) due to its superior accuracy ($95.31\%$) and its ability to natively understand Hindi and Marathi context, while Engine A ($30\%$) stabilizes the score against Transformer hallucinations on extremely short, keyword-dense texts.

### Thresholds
* 🔴 **RED (70-100): High Risk Scam.** Immediate block/warning recommended.
* 🟡 **YELLOW (40-69): Suspicious.** Contains anomalies but lacks definitive malicious intent.
* 🟢 **GREEN (0-39): Safe.** Normal conversational baseline.
