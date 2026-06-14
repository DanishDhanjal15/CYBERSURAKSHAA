# 🛡️ ScamGuard AI: Multilingual Fraud Detection Dashboard

[![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.111.0-009688.svg)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/React-18-61DAFB.svg)](https://reactjs.org/)
[![XGBoost](https://img.shields.io/badge/ML-XGBoost-F37626.svg)](https://xgboost.readthedocs.io/)
[![XLM-RoBERTa](https://img.shields.io/badge/NLP-XLM--RoBERTa-EE4C2C.svg)](https://huggingface.co/docs/transformers/model_doc/xlm-roberta)

**ScamGuard AI** is a state-of-the-art cybersecurity pipeline designed to detect financial scams, Ponzi schemes, and malicious forward-chains across multiple regional languages (English, Hindi, and Marathi). Built as a full-stack Capstone Project, it bridges the gap between traditional keyword filters and advanced deep learning threat analysis.

---

## 🎯 Syllabus Alignment

This project rigorously implements advanced concepts from the AIML curriculum:

| Topic | Implementation Detail |
| :--- | :--- |
| **AI FBA (Fraud Analytics)** | Algorithmic risk scoring based on urgency markers and financial phrasing. |
| **AAI: Ensemble Learning** | **Engine A** utilizes **XGBoost** for rapid, explainable feature classification. |
| **AAI: Transfer Learning** | **Engine B** fine-tunes Meta's **XLM-RoBERTa** for deep semantic understanding. |
| **SMA (Social Media Analytics)** | Mining unstructured WhatsApp/Telegram messages and URL infrastructure tracing. |

---

## 🧠 Architecture Overview

ScamGuard AI uses a **Dual-Engine Fusion** approach:
1.  **Engine A (XGBoost)**: TF-IDF based ensemble model optimized for English scam patterns (87.5% Accuracy).
2.  **Engine B (XLM-RoBERTa)**: Neural transformer model fine-tuned for multilingual context (95.3% Accuracy).
3.  **Link Checker**: Asynchronous WHOIS domain validation and URL unshortening (Redirect Tracing).

---

## 📸 Screenshots

![English Phishing Detection Graph](docs/images/english_scam.png)
*Figure: High-Risk English Phishing Detection and Domain Age Validation.*

![Hindi Scam Detection Graph](docs/images/hindi_scam.png)
*Figure: Multilingual Hindi Scam Detection utilizing Engine B Deep Learning.*

---

## 📥 Model Setup (Crucial)

To keep the repository lightweight, the large model files are hosted externally. Follow these steps to set up the engines:

1.  **Download Models**: [Open Google Drive Folder](https://drive.google.com/drive/folders/1LpS0nU8QT62_Fmsa_u57lcjAjiD1GT9Q?usp=drive_link)
2.  **Relocate Files**:
    *   Place `tfidf_vectorizer.pkl` and `xgboost_fraud_model.pkl` directly in `/saved_models/`.
    *   Download the contents of the `xlm_roberta_scam_model` folder and place them in `/saved_models/xlm_roberta_scam_model/`.
3.  **Ensure the structure looks like this**:
    ```text
    /saved_models/
    ├── tfidf_vectorizer.pkl
    ├── xgboost_fraud_model.pkl
    └── xlm_roberta_scam_model/
        ├── config.json
        ├── model.safetensors
        └── tokenizer.json
    ```

---

## 🚀 Getting Started

### 1. Backend (FastAPI)
```bash
cd backend
python -m venv venv
source venv/bin/activate  # venv\Scripts\activate on Windows
pip install -r requirements.txt
uvicorn main:app --reload
```

### 2. Frontend (React)
```bash
cd frontend
npm install
npm run dev
```

---

## 🔮 Future Scope
- **Model Quantization**: Exporting to ONNX for 10x faster inference on mobile.
- **Human-in-the-Loop**: PostgreSQL integration for user feedback loop.
- **API Scalability**: Dockerization and Kubernetes orchestration.

*Developed by Tanmay — Capstone Project 2024*
