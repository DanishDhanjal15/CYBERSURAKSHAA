# 🇮🇳 CYBERSURAKSHAA — National Threat Detection Suite

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Python Version](https://img.shields.io/badge/Python-3.9+-green.svg)](https://www.python.org/)
[![Flask Version](https://img.shields.io/badge/Flask-3.0+-orange.svg)](https://flask.palletsprojects.com/)
[![Government Secure Access Portal](https://img.shields.io/badge/Security-Government%20Access%20Portal-red.svg)](#)

An AI-powered Cyber Threat Intelligence (CTI) platform built for law enforcement agencies, security analysts, and corporate investigators. **CYBERSURAKSHAA** offers real-time analysis, detection, and mitigation of digital fraudulent content across four specialized threat domains, unified under a secure Role-Based Access Control (RBAC) portal.

---

## 🇮🇳 Tricolor National Secure Access
CYBERSURAKSHAA features an official government-style secure gateway inspired by **National Cyber Crime Portal**, **NIC Services**, and **CERT-In Internal Systems**. The landing authentication portal features a tricolor gradient theme, a spinning Ashoka Chakra background, and a secure glassmorphic credential interface.

---

## 🚀 Key Modules & AI Engines

### 1. 🎰 Illegal Betting Content Detector
Detects and analyzes gambling advertisements, illegal betting applications, and scam promotions on social media images or banners.
* **Core Technologies**: YOLOv8 Logo Detection, PaddleOCR Text Extraction, NLP Text Classifier.
* **Workflow**: Extracts raw text from images, uses YOLO to identify gambling logos (e.g. popular betting apps), and runs a TF-IDF text classification model to verify betting-related terminology.

### 2. 📹 Deepfake Face & Video Detector
Performs frame-by-frame analysis on digital media to determine whether facial features have been synthetically manipulated or swapped.
* **Core Technologies**: MTCNN Face Cropping, EfficientNet-B4 CNN classifier, PyTorch.
* **Workflow**: Decodes uploaded videos, crops facial areas using MTCNN, and routes individual frames through a deep CNN (EfficientNet-B4) trained to distinguish authentic videos from deepfakes.

### 3. 📞 Fake Customer Care Scam Detector
Identifies customer care fraud campaigns, phishing message scripts, and impersonation attempts targeting consumers.
* **Core Technologies**: PaddleOCR text scanner, spaCy Named Entity Recognition (NER) pipeline.
* **Workflow**: Scans SMS screenshots or banners, extracts phone numbers and company names using custom spaCy NER patterns, and flags scam campaigns against a local known-threat registry.

### 4. 📈 Investment Scam Detector (ScamGuard AI)
Evaluates financial portals, high-yield investment programs (HYIPs), and cryptocurrency deposit sites.
* **Core Technologies**: python-whois registry lookup, XLM-RoBERTa (NLP model), XGBoost Fraud Scorer.
* **Workflow**: Audits the target site's domain registration date/location using WHOIS (under-3-month domains are flagged as high risk) and processes investment copy to output a weighted fraud index.

---

## 📄 Automated CTI Threat Report Exporter
After completing a scan in any detection module, investigators can export a comprehensive **Cyber Threat Intelligence (CTI) Report**:
* **PDF Report**: A publication-grade ReportLab document featuring:
  * Official CYBERSURAKSHAA header branding with the Indian Flag and national emblems.
  * Technical scan metadata (module, file name, timestamp, SHA-256 target hash).
  * Extracted indicators (telephone numbers, websites, predictions) and severity risk scoring.
  * Vector stamp overlays denoting the threat classification (e.g., `VERIFIED SCAM`, `ILLEGAL BETTING`, `MANIPULATED / FAKE`, `FINANCIAL FRAUD`).
  * Official security recommendation text and verification signature block signed by lead threat investigator **Danish Dhanjal**.
* **HTML Report**: A standalone, beautifully styled responsive page mirroring the PDF report styling with embedded target media and custom CSS stamp designs.

---

## 🖥️ Live Incident Log Feed (SOC Dashboard)
The main homepage serves as a Live Cyber Security Operations Center (SOC) dashboard. Every scan transaction registers instantly in a centralized SQLite database. A live chronological logs grid at the bottom displays real-time threat events, risk indexes, and status controls (`🚨 FLAGGED FOR TAKEDOWN`, `⚠️ UNDER REVIEW`, or `✅ SAFE`).

---

## 🔒 Access Credentials (RBAC)

Access is strictly monitored using Role-Based Access Control (RBAC). The application is pre-seeded with two accounts:

| Username | Password | Role | Access Level |
| :--- | :--- | :--- | :--- |
| **admin** | `admin123` | **Admin** | Full system administration, global security logs audit, and user registry management |
| **user** | `user123` | **User** | General threat scan modules, CTI exports, and personal scan history |

---

## 📂 Project Architecture

```
CYBERSURAKSHAA/
│
├── app.py                          # Flask application root
├── requirements.txt                # Unified requirements
├── cybersurakshaa.db               # SQLite database (Users & Audit registry)
├── readmesugg.md                   # Implementation notes
├── yolov8n.pt                      # YOLOv8 weights (Object/Logo detection)
│
├── blueprints/                     # Blueprint routes
│   ├── auth.py                     # User session & authorization
│   ├── admin.py                    # Admin user management & logs audit
│   ├── betting.py                  # Illegal betting scan routes
│   ├── deepfake.py                 # Deepfake analyzer routes
│   ├── customer_care.py            # Customer support scam detector
│   └── investment.py               # Financial investment scam check
│
├── services/                       # Application Services
│   ├── auth_db.py                  # Database init, migrations & user CRUD
│   ├── report_generator.py         # CTI HTML/PDF PDF compilers (by Danish Dhanjal)
│   └── scam_detector/              # Shared scam detector helpers
│       ├── fraud_scorer.py
│       ├── link_checker.py
│       └── nlp_analyzer.py
│
├── templates/                      # Jinja2 Layout Templates
│   ├── auth/                       # login.html, register.html
│   ├── admin/                      # dashboard.html
│   ├── betting/                    # index.html
│   ├── deepfake/                   # index.html
│   ├── customer_care/              # index.html
│   ├── investment/                 # index.html
│   ├── base.html                   # Global layout
│   └── index.html                  # Landing SOC Dashboard
│
└── static/                         # Assets & Front-end Logic
    ├── css/style.css               # Main styling rules
    ├── js/main.js                  # Frontend controllers & AJAX triggers
    ├── logo.png                    # Brand logo
    └── uploads/                    # Target media uploads directory
        ├── .gitkeep
        └── scans/                  # Saved scanned media files (SHA-256 name)
```

---

## 🛠️ Installation & Setup

### Prerequisites
* **Python**: Python 3.9, 3.10, or 3.11 is recommended.
* **C++ Build Tools**: Required on Windows machines for compiling PaddlePaddle and spaCy dependencies. Make sure **Desktop development with C++** is installed via Visual Studio Installer.

### Step-by-Step Installation

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/DanishDhanjal15/CYBERSURAKSHAA.git
   cd CYBERSURAKSHAA
   ```

2. **Initialize a Virtual Environment**:
   ```bash
   python -m venv venv
   # On Windows:
   .\venv\Scripts\activate
   # On Linux/macOS:
   source venv/bin/activate
   ```

3. **Install Core Requirements**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Install Ultralytics (YOLOv8)**:
   ```bash
   pip install ultralytics
   ```

5. **Download spaCy Named Entity Model**:
   ```bash
   python -m spacy download en_core_web_sm
   ```

6. **Start the Web Application**:
   ```bash
   python app.py
   ```
   Open `http://127.0.0.1:5000` in your web browser.

---

## 🔍 How to Use CYBERSURAKSHAA

1. **Secure Sign In**: Connect using the tricolor secure portal using one of the pre-seeded users.
2. **Dashboard Overview**: Access the central SOC dashboard showing real-time statistics and global scan metrics.
3. **Execute Scans**:
   * **Deepfake Detection**: Upload files (mp4, png, jpg) to inspect digital media for face modification.
   * **Betting & Customer Care Scanning**: Upload screenshots to run OCR, object detection, and NER matching.
   * **Investment Analyzer**: Provide website URLs and site descriptions to run NLP checks and domain WHOIS lookups.
4. **Threat Intelligence Logs**: Review the results of your scans in the interactive log table at the bottom of the page.
5. **Download CTI Evidence Reports**: Inside the results panel or history drawer, click **"Export Official Threat Report"** to download the signed PDF or view the HTML report format.

---

## 🛡️ License & Institutional Branding
This project is licensed under the MIT License - see the LICENSE file for details.

*Disclaimer: CYBERSURAKSHAA is an AI-powered Threat Intelligence suite developed for cybersecurity analysis and digital evidence indexing. Automated predictions should be verified independently by qualified forensic experts prior to official legal prosecution.*
