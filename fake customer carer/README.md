# 🛡️ SHIELD // Fake Customer Care Detection Engine

SHIELD is a premium web application designed to detect and verify **Fake Customer Care numbers** commonly used in phishing scams, deceptive advertisements, search engine ads, and WhatsApp forwards. 

Using advanced text analysis, optical character recognition (OCR), natural language processing (NLP), and a localized threat intelligence network, SHIELD identifies whether a customer care phone number listed for a brand is authentic or a scam.

---

## 🚀 Key Features

* **Three Scanning Modalities:**
  * 📸 **Scan Image:** Drag and drop screenshots of ads, banners, or forwards.
  * 🔗 **Scan from URL:** Enter a direct image URL (useful for scanning online posters).
  * 📝 **Paste Text:** Input advertisement copy or SMS texts directly.
* **Text Extraction Pipeline (PaddleOCR):** Integrates the fast mobile OCR pipeline (optimized to prevent OpenMP deadlocks on Windows and bypass model source connectivity issues) with image resizing for ultra-fast scanning.
* **Brand Recognition (spaCy NLP):** Employs Named Entity Recognition (NER) and keyword-alias catalogues to identify which brand (e.g., Jio, Amazon, SBI) the advertisement claims to represent.
* **Official Database Verification:** Cross-references the detected number against a pre-seeded, trusted database of official customer support contacts.
* **Threat Intelligence Network:** Allows users to flag verified scam numbers, updating a local SQLite-backed reputation system to protect future scans.
* **Premium Cyberpunk/Cybersecurity UI:** Styled with a sleek, interactive dark theme featuring glassmorphism, responsive circular gauges, dynamic glows, and micro-animations.

---

## 🛠️ Technology Stack

* **Backend Framework:** Python & Flask
* **OCR Text Extraction:** PaddleOCR & PaddlePaddle (custom orientation models bypassed for high-speed local inference)
* **Natural Language Processing:** spaCy (`en_core_web_sm`)
* **Database Management:** SQLite3 (pre-seeded with major brand contacts)
* **Frontend Design:** HTML5, CSS3 (Vanilla Custom Theme), Bootstrap 5, FontAwesome Icons

---

## 📦 Installation & Setup

### Prerequisites
Make sure you have **Python 3.10+** installed on your system.

### 1. Clone the Repository
```bash
git clone https://github.com/DanishDhanjal15/Fake-customer-care-Detection.git
cd Fake-customer-care-Detection
```

### 2. Install Dependencies
Install all required packages from `requirements.txt`:
```bash
pip install -r requirements.txt
```

### 3. Download the spaCy Language Model
Download the English language model used for Named Entity Recognition (NER):
```bash
python -m spacy download en_core_web_sm
```

### 4. Run the Application
Start the Flask local development server:
```bash
python app.py
```
Open your browser and navigate to:
```
http://127.0.0.1:5000
```

---

## 🗃️ Database Structure
The application automatically initializes `shield.db` (SQLite) with two primary tables:
1. `official_contacts`: Houses official, verified contact numbers and website links for major brands (Amazon, Flipkart, HDFC, SBI, Jio, PhonePe, Paytm, etc.).
2. `indicators`: Acts as the local Threat Intelligence repository, tracking reported scam phone numbers, count of reports, and timestamps.

---

## 🛡️ License
Built for educational, local threat-mitigation, and offline safety operations.
