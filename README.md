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

## 🧠 The Intelligence Layer

The five detectors above answer *"is this artefact malicious?"*. The
intelligence layer answers the question enforcement actually needs: **who is
behind it, and who can act on that?**

Full design notes: **[`md/intelligence_layer.md`](md/intelligence_layer.md)**.

### 🕸️ Entity Graph & Campaign Clustering
Every scan now keeps the identifiers it extracts — the deposit UPI address, the
Telegram channel, the mule account, the signing certificate — instead of
rendering them once and discarding them. Fourteen indicator kinds are extracted
from OCR output, transcripts, page copy and APK strings, deduplicated across
modules, and linked into an entity graph with full provenance for every
sighting.

Union-find over that graph produces **campaigns**: thirty betting posters that
share one deposit UPI ID are one operator, and one notice naming that UPI ID
achieves more than thirty notices naming thirty images. Indicators seen in more
than forty artefacts (a quoted helpline, a national short code) are suppressed
as merge points, so a shared number cannot collapse every unrelated operation
into a single cluster. Near-duplicate creatives are matched by MinHash over
character shingles with digits and URLs folded, so the same script with a
swapped brand name and phone number still groups together.

Rendered as an interactive Cytoscape graph at `/intel/graph`, with cases,
campaigns and a lookalike-domain monitor alongside.

### ⚖️ Enforcement Action Packs
An indicator is only useful if it reaches the authority that can act on it. Each
kind routes to a real Indian channel — UPI addresses to **NPCI and the sponsor
bank**, phone numbers to **DoT via Sanchar Saathi / Chakshu**, domains to the
**registrar**, hosting to the **intermediary under IT Act s.79(3)(b)**, and
everything to **NCRP (cybercrime.gov.in / 1930)** — and the platform renders a
draft notice per channel with the evidence hash and verification URL embedded.

Where the correct abuse contact is not known, the field reads
`[RESOLVE: confirm current abuse contact before dispatch]`. **No recipient
address is ever invented**: a notice addressed to a plausible but fictional
mailbox looks actioned and reaches nobody. Every document is a draft requiring
an authorised officer's signature.

### 🔗 Tamper-Evident Evidence Chain
Every scan, report, takedown, case change and analyst correction is appended to
a hash chain where each entry commits to its predecessor:

```
entry_hash = SHA256( seq | timestamp | event | actor | payload_hash | prev_hash )
```

Editing any historical entry breaks every link after it, and verification
reports exactly where. **`/verify/<sha256>` is public and needs no account** —
a verification endpoint only the operator can call verifies nothing to anybody
outside the operator. It confirms existence, timestamp, module, verdict and
chain integrity, and discloses no scanned content, no user, and no extracted
personal data. Every generated PDF and HTML report carries a QR code pointing
at it.

This is tamper-*evidence*, not tamper-*prevention*, and the UI says so.
Publishing the chain head externally (`python manage.py chain-head`) is what
converts internal consistency into an external guarantee.

### 📊 Calibration, Abstention & the Analyst Feedback Loop
Detectors report a **band** — SAFE / INSUFFICIENT EVIDENCE / THREAT — alongside
an explicit `calibrated: true|false`. When false, the interface states plainly
that the percentage is a raw model score and not a probability. The abstention
band lets the system decline: *"score 52, not classifying, route to a human"*
beats a coin flip dressed as a verdict.

Analysts mark verdicts wrong from the results panel. A correction is one
person's opinion until a **different** analyst confirms it — enforced
server-side — and only then does it enter the confusion matrix at
`/intel/feedback` or the training export. Agreement rates are withheld until a
module has 30 confirmed reviews, and always carry the caveat that reviewers
look at borderline cases, so these are not population error rates.

Confirmed corrections become `(score, label)` pairs, which fit a real
calibrator — the path by which `calibrated: false` stops being true.

### 👁️ Explainability
The deepfake detector returns a **Grad-CAM heatmap** over the final
convolutional layer of EfficientNet-B4, for the face that scored highest, with
a note on how to read it: a heatmap on the jawline is consistent with a
face-swap artefact, a heatmap on the background or a watermark is a reason to
discard the result. Text modules highlight the exact spans that moved the
score.

*This replaced a "forensic diagnostics" panel whose five named sub-metrics were
generated in the browser from the single model score plus a random jitter. The
network computes none of those quantities, and the numbers changed between runs
on the same file. A CI step now greps for it so it cannot return.*

---

## 🔊 New Detection Modules

### 📞 Voice Scam Detector (`/voice/`)
Scores call recordings and transcripts for coercion-script structure — the
"digital arrest", fake-agency, KYC-expiry and OTP-harvesting patterns behind
most Indian voice fraud. Speech recognition via faster-whisper when installed;
without it the module still scores analyst-supplied transcripts and says so
rather than failing silently.

An acoustic screen (silence ratio, dynamic range, clipping) is reported for
context and **deliberately excluded from the verdict** — it has never been
validated against a labelled corpus of cloned speech, and an unvalidated
heuristic must not move a decision that leads to a blocking request.

### 📱 APK / Betting App Analyzer (`/apk/`)
Illegal betting reaches victims as sideloaded APKs, not web pages. Parses the
binary `AndroidManifest.xml` directly (stdlib only — no androguard required),
scores high-risk permissions by what they actually enable (`READ_SMS` is OTP
interception; `BIND_ACCESSIBILITY_SERVICE` is full UI automation), mines
embedded endpoints and gambling vocabulary from package strings, and extracts
the **signing certificate fingerprint** — which every reskinned clone of the
same app shares, so reporting it covers the family rather than one build.

### 🌐 Lookalike Domain Monitor (`/intel/lookalike`)
Generates the typosquat space around a brand domain — omissions,
transpositions, homoglyphs, keyboard slips, scam affixes, alternate TLDs — and
resolves them concurrently to find the ones that already exist, before a
citizen reports one. Ships with a watchlist of Indian bank and government
domains.

### 🗣️ Multilingual & Obfuscation Handling
The original keyword banks were English-only, which is a serious gap when most
Indian scam SMS traffic is Hinglish. Added: Devanagari→Latin transliteration
with correct virama and inherent-'a' handling, a Hinglish scam-phrase bank, and
deobfuscation of the standard evasions (`f-r-e-e`, `w1n`, `j@ckp0t`,
`B O N U S`). Every keyword match is attempted against all four
representations.

---

## 🔭 Watchtower — the lifecycle of an operation

Every other module answers *"is this artefact malicious?"*. These three answer
*"what is this operator doing over time?"* — and they compose into one arc:
**see it born, watch it die, catch it come back.** One surface at
`/watchtower`.

### Stage 1 · Appearing — Certificate Transparency

Every publicly-trusted TLS certificate is published to append-only public logs,
because browsers reject certificates that are not. A phishing kit *needs*
HTTPS — a browser warning kills the campaign before it starts — so those logs
are a near-complete register of every domain someone provisioned for the
purpose.

Which means `sbi-verify-kyc.com` shows up **at issuance**, typically hours to
days before the first message goes out. A registrar notice at that point costs
the operator the domain before it touches a single citizen.

Two sources answering two different questions — not fallbacks for each other:

* **crt.sh** does substring search across all logs. The only way to *discover*
  a name nobody knew to look for. No substitute exists.
* **Cert Spotter** queries a domain and its subdomains. It answers the other CT
  question: what exists inside the brand's own namespace, and did an unexpected
  authority issue one? That is mis-issuance or compromise — the original reason
  CT exists. *(Polling `hdfcbank.com` during development returned 283 real
  hostnames, including publicly-certificated UAT environments.)*

Scoring is a transparent weighted sum with named constants, guarded three ways:
a **brand-alias list** so State Bank's real `onlinesbi.sbi` does not fire an
alert on every renewal; **word-boundary matching** so short brand tokens like
`sbi` still catch `sbibank.com` without matching everything; and
**deterministic token ordering** so `hdfcbank` beats its own stem `hdfc`.

**A hit is a lead, never a verdict.** Defensive registration, regional
subsidiaries and researchers all produce brand collisions. Only observations
scoring ≥60 enter the entity graph.

**Outages are surfaced, never swallowed.** This is the module's most important
property: a monitor reporting "nothing new" when its feed is down converts an
outage into a false all-clear. Feed health has *three* states — reachable,
down, and never-contacted — and the UI banners the last two rather than showing
an empty list that reads as a quiet day. (crt.sh 502s under load regularly, so
this is not hypothetical.)

### Stage 2 · Disappearing — takedown outcome tracking

The platform generated notices and then never found out whether any of them
worked. It could describe its own activity but never its own effect.

Now every dispatched target is registered and re-probed on a schedule, giving
the one sentence no classifier can produce:

> *41 filed · 27 gone dark · median 3.2 days · registrar 71%, hosting 40%*

Three things keep those numbers honest:

* **A single failed probe is not a takedown.** Resolvers hiccup. `DEAD` needs
  three consecutive failures, and one success resets the counter — otherwise
  three unrelated blips over three weeks add up to a fictional success.
* **Unprobeable channels are excluded, not counted as failures.** No public
  endpoint reports whether a UPI handle was frozen, and probing payment rails
  to find out would be indistinguishable from abuse. They stay `UNKNOWN` until
  an analyst records the outcome. This matters: payment-rail freezes are the
  most effective enforcement available in India, so folding them into the
  denominator would make the best channel look like the worst.
* **Correlation, not causation.** Operators rotate infrastructure, hosts
  suspend for non-payment, registrations lapse. There is no control group, and
  every metric says so — *"66% of reported targets went dark"* is what was
  measured; *"66% success rate"* is a causal claim the data cannot support.

Filing is distinct from previewing: `POST .../actions/dispatch` starts the
clock, `GET .../actions` only renders drafts.

### Stage 3 · Returning — resurrection detection

Operators don't stop when you take them down. They rebuild — and what they
replace versus what they keep is dictated by cost:

| Cheap · replaced every time | Expensive · held as long as possible |
|---|---|
| Domains, hosting, SIMs, Telegram channels, artwork | UPI address and the mule account behind it (needs a new person with fresh KYC) · APK signing certificate (rotating it orphans every install) · crypto wallet (moving funds is visible) |

So the signature is precise: **new disposable infrastructure attached to a
durable anchor already seen.**

> *UPI `kingbet@okaxis` was quiet for 37 days, then reappeared alongside 3 new
> domains and 1 new Telegram channel. The infrastructure is new; the payment
> rail is not.*

That is an intelligence product, not a classifier output — the difference
between processing incidents and pursuing an operator. `churn_profile()` goes
further and names the bottleneck: *"the longest-lived indicator is the UPI
address, held 37 days while domains were replaced every few — that is where
this operation is least able to absorb pressure."*

Anchors seen in more than 25 artefacts are suppressed, because an aggregator
payment handle spread across dozens of unrelated artefacts is infrastructure,
not identity. **No alert here is an attribution** — shared hosting and resold
wallets produce the same signature — it is a reason to examine two clusters
together.

### Running the monitors

Off by default: they contact third-party services and re-probe reported
domains, which a developer should opt into rather than find in their egress
logs.

```bash
WATCHTOWER_MONITORS=1 python app.py
```

Or from the CLI:

```bash
python manage.py ct-poll --brand sbi.co.in
python manage.py ct-observations --min-score 60
python manage.py takedown-sweep
python manage.py takedown-report
python manage.py resurrections
python manage.py churn --anchor 42
```

---

## 📲 Citizen-Facing Channels

Scam messages arrive on WhatsApp and Telegram and the decision to pay is made
in minutes. A platform that requires the victim to open a browser, register an
account and upload a screenshot has already lost.

### Telegram Bot — `integrations/telegram_bot.py`
Forward any message to the bot and get back what patterns it matches, which
identifiers it contains, which authority each one should be reported to, and
what to do next. Standard library only — no `python-telegram-bot` dependency.

```bash
export TELEGRAM_BOT_TOKEN=...                        # from @BotFather
export CYBERSURAKSHAA_API_KEY=$(python manage.py create-api-key \
        --label "telegram bot" --channel telegram | grep -o '[A-Za-z0-9_-]\{40,\}')
python integrations/telegram_bot.py
```

It stores no chat IDs, usernames or any other personal data — a service that
helps scam victims must not itself become a database of scam victims.

### Chrome Extension — `integrations/chrome-extension/`
Select suspicious text on any page, right-click, **Check this text for scam
patterns**, and get an in-page panel with the verdict, the identifiers and the
advice. Manifest V3.

Load it unpacked via `chrome://extensions` → Developer mode → *Load unpacked*,
then set the server URL and API key in the extension's settings. **Nothing is
sent anywhere until you press the button** — no passive page scanning, no
keystroke observation, no background telemetry. The API key is entered by the
user and never bundled, because everything shipped inside an extension is
readable by everyone who installs it.

### Public API — `/api/v1/`
Key-authenticated (`X-API-Key`), rate-limited, self-describing at `/api/v1/`.

```bash
curl -X POST http://localhost:5000/api/v1/check \
     -H "X-API-Key: $CYBERSURAKSHAA_API_KEY" \
     -H "Content-Type: application/json" \
     -d '{"text": "Your KYC has expired, pay to scammer@okaxis to reactivate"}'
```

Submissions are **quarantined**, not ingested: anything the public can send is
attacker-controlled, and auto-ingesting it would let one person forge arbitrary
links between identifiers that the campaign clustering would then faithfully
report as a finding. An analyst promotes a submission with
`python manage.py promote-submission <id>`.

---

## 🩺 Operations

| Endpoint | Purpose |
| :--- | :--- |
| `GET /healthz` | Liveness — process is up, database reachable, per-model states |
| `GET /readyz` | Readiness — 503 until every model has finished warming up |
| `GET /api/impact` | Live counters, computed from the database only |

Both probes are `@limiter.exempt`: a probe behind a rate limit stops being a
probe — the limiter starts 429ing the orchestrator and the container is killed
while perfectly healthy.

**Dashboard counters are real.** The home page previously added invented
baselines to genuine counts. It now starts at zero on a fresh install with a
note explaining why, and every figure is a live database count.

**Feed provenance is explicit.** Threat-feed records carry `[LIVE]` or
`[SIMULATED]` provenance chips. Simulated fallback records use `.invalid` URLs,
are visually distinct, and never reach the entity graph.

**Geolocation precision is stated.** Every map marker carries a `precision`
field shown in its popup: a phone pin resolves to a *telecom circle* — hundreds
of kilometres wide, and the circle the number was issued in, not where the
handset is; a domain pin resolves to the *hosting* IP. Neither locates a
person, and the map says so rather than implying pinpoint accuracy.

### Operator CLI

```bash
python manage.py create-api-key --label "telegram bot" --channel telegram
python manage.py verify-chain            # re-walk the evidence chain
python manage.py chain-head              # publish this externally
python manage.py rebuild-campaigns
python manage.py fit-calibrator "Betting Content"
python manage.py submissions             # quarantined public submissions
python manage.py stats
```

---

## 🧪 Tests

```bash
pip install pytest
python -m pytest tests/ -v
```

**221 tests.** The intelligence layer is stdlib-only by design, so most of the
suite runs on a bare interpreter with no model weights, no GPU and no network —
which is what makes it fast enough to run on every push. Coverage includes
indicator extraction regressions (each named for the mistake it locks out),
graph invariants, hub suppression, **evidence-chain tamper detection** (the
tests edit the database behind the module's back and assert verification
notices), the feedback review gate, calibration convergence, binary AXML
parsing against a hand-built synthetic manifest, anonymous-access checks
against every route, and the lifecycle guarantees — a feed outage must not read
as a quiet day, a network blip must not read as a takedown, and a shared
payment handle must not read as one operator. Nothing in the suite touches the
network.

CI (`.github/workflows/ci.yml`) runs the stdlib suite on Python 3.10–3.12, the
full Flask suite once, `compileall` over every module, `node --check` on the
front-end, and a guard against the fabricated-data patterns that were removed.

---

## 📄 Automated CTI Threat Report Exporter
After completing a scan in any detection module, investigators can export a comprehensive **Cyber Threat Intelligence (CTI) Report**:
* **PDF Report**: A publication-grade ReportLab document featuring:
  * Official CYBERSURAKSHAA header branding with the Indian Flag and national emblems.
  * Technical scan metadata (module, file name, timestamp, SHA-256 target hash).
  * Extracted indicators (telephone numbers, websites, predictions) and severity risk scoring.
  * Vector stamp overlays denoting the threat classification (e.g., `VERIFIED SCAM`, `ILLEGAL BETTING`, `MANIPULATED / FAKE`, `FINANCIAL FRAUD`).
  * Official security recommendation text and a verification signature block naming the analyst who ran the scan.
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
│   ├── report_generator.py         # CTI HTML/PDF compilers
│   ├── threat_crawler.py           # Live feeds with explicit provenance
│   ├── takedown_generator.py
│   ├── scam_detector/              # Shared scam detector helpers
│   │   ├── fraud_scorer.py
│   │   ├── link_checker.py
│   │   └── nlp_analyzer.py
│   └── intel/                      # Intelligence layer — imports no Flask
│       ├── indicators.py           # 14 indicator kinds
│       ├── graph.py                # Entity graph + cases
│       ├── campaigns.py            # Union-find clustering, MinHash
│       ├── actions.py              # 7 Indian enforcement channels
│       ├── evidence.py             # Tamper-evident hash chain
│       ├── feedback.py             # Analyst review loop
│       ├── calibration.py          # Platt / histogram, ECE, abstention
│       ├── explain.py              # Grad-CAM, token attribution
│       ├── lookalike.py            # Typosquat generation + DNS
│       ├── multilingual.py         # Devanagari, Hinglish, deobfuscation
│       ├── voice.py                # Transcript scoring, acoustic screen
│       ├── apk.py                  # Binary AXML parser
│       ├── feeds.py                # URLhaus / OpenPhish / PhishTank
│       ├── ctlog.py                # Certificate Transparency monitoring
│       ├── takedown.py             # Enforcement outcome tracking
│       ├── resurrection.py         # Operators rebuilding after takedown
│       ├── ops.py                  # Warm-up, health, readiness, impact
│       └── db.py                   # One connection policy
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
├── static/                         # Assets & Front-end Logic
│   ├── css/style.css               # Main styling rules
│   ├── js/main.js                  # Frontend controllers & AJAX triggers
│   └── uploads/scans/              # Saved scanned media (SHA-256 filename)
│
├── manage.py                       # Operator CLI (keys, chain, calibration)
├── pytest.ini
├── tests/                          # 221 tests; stdlib-only where possible
│   ├── conftest.py                 # Temp-database fixture
│   ├── test_indicators.py          # Extraction regressions
│   ├── test_graph.py               # Graph invariants + hub suppression
│   ├── test_evidence.py            # Tamper detection
│   ├── test_feedback.py            # Review gate + calibration
│   ├── test_apk_voice_multilingual.py
│   ├── test_public_api.py
│   ├── test_watchtower.py          # CT scoring, probe rules, resurrections
│   └── test_app_routes.py          # Anonymous-access sweep
│
├── integrations/
│   ├── telegram_bot.py             # Citizen bot (stdlib only)
│   └── chrome-extension/           # Manifest V3 in-page checker
│
└── .github/workflows/ci.yml
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
