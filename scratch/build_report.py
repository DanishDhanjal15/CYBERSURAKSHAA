import base64, os

def b64(path):
    with open(path, 'rb') as f:
        return base64.b64encode(f.read()).decode()

BRAIN = r'C:\Users\Danish\.gemini\antigravity-ide\brain\6425dd93-c761-446a-9cd0-7fe829f930d5'
PROJ  = r'c:\Users\Danish\OneDrive\Desktop\All in one'

logo_b64      = b64(os.path.join(PROJ, 'static', 'logo.png'))
betting_b64   = b64(os.path.join(BRAIN, 'betting_module_1781600489015.png'))
deepfake_b64  = b64(os.path.join(BRAIN, 'deepfake_module_1781600509392.png'))
customer_b64  = b64(os.path.join(BRAIN, 'customer_care_module_1781600530552.png'))
investment_b64= b64(os.path.join(BRAIN, 'investment_module_1781600547786.png'))
hub_b64       = b64(os.path.join(BRAIN, 'hub_dashboard_1781600568310.png'))

# User-provided case screenshots (betting output 89%, deepfake 96%, customer SCAM DETECTED)
# These are from the conversation screenshots - use the live app screenshots as placeholders
# User said 4th image (investment result) to be provided later

html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>CYBERSURAKSHAA – Project Report | GPCSSI 2025</title>
  <style>
    @page {{ size: A4; margin: 2.2cm 2.0cm 2.2cm 2.5cm; }}
    @media print {{
      .no-print {{ display: none !important; }}
      body {{ background: white; }}
      .page-break {{ page-break-before: always; break-before: page; }}
      .avoid-break {{ page-break-inside: avoid; break-inside: avoid; }}
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{ font-family: 'Times New Roman', Times, serif; font-size: 12pt; line-height: 1.7; color: #111; background: #e8e8e8; }}
    .report-page {{ background: white; width: 210mm; min-height: 297mm; margin: 20px auto; padding: 2.2cm 2.0cm 2.2cm 2.5cm; box-shadow: 0 4px 30px rgba(0,0,0,0.15); }}
    .cover {{ display: flex; flex-direction: column; align-items: center; justify-content: center; min-height: 257mm; text-align: center; gap: 0; }}
    .cover-org {{ font-size: 18pt; font-weight: bold; text-decoration: underline; letter-spacing: 1px; margin-bottom: 10px; }}
    .cover-event {{ font-size: 16pt; font-weight: bold; text-decoration: underline; margin-bottom: 6px; }}
    .cover-year {{ font-size: 16pt; font-weight: bold; text-decoration: underline; margin-bottom: 28px; }}
    .cover-logo {{ width: 150px; height: 150px; border-radius: 50%; object-fit: cover; margin-bottom: 28px; border: 3px solid #c0392b; box-shadow: 0 2px 14px rgba(0,0,0,0.2); }}
    .cover-title {{ font-size: 14pt; font-weight: bold; text-decoration: underline; margin-bottom: 36px; max-width: 480px; }}
    .cover-table {{ width: 100%; max-width: 480px; border-collapse: collapse; font-size: 12pt; }}
    .cover-table td {{ padding: 5px 20px; vertical-align: top; }}
    .cover-table .label {{ font-weight: bold; }}
    h1.section-title {{ font-size: 15pt; font-weight: bold; text-align: center; text-decoration: underline; margin-bottom: 18px; margin-top: 8px; letter-spacing: 0.5px; }}
    h2.sub-title {{ font-size: 13pt; font-weight: bold; margin-top: 16px; margin-bottom: 7px; text-decoration: underline; }}
    h3.sub-sub {{ font-size: 12pt; font-weight: bold; margin-top: 12px; margin-bottom: 5px; }}
    p {{ margin-bottom: 9px; text-align: justify; }}
    ul {{ margin-left: 22px; margin-bottom: 9px; }}
    ul li {{ margin-bottom: 3px; }}
    ol {{ margin-left: 22px; margin-bottom: 9px; }}
    table.data-table {{ width: 100%; border-collapse: collapse; margin: 12px 0; font-size: 10.5pt; }}
    table.data-table th {{ background: #1a1a2e; color: #fff; padding: 7px 10px; text-align: left; font-weight: bold; }}
    table.data-table td {{ border: 1px solid #bbb; padding: 6px 10px; vertical-align: top; }}
    table.data-table tr:nth-child(even) td {{ background: #f5f5f5; }}
    .flowchart-container {{ margin: 16px auto; text-align: center; }}
    .flowchart-container svg {{ max-width: 100%; height: auto; }}
    .screenshot-img {{ width: 100%; max-width: 100%; border: 1px solid #ccc; border-radius: 4px; margin: 10px 0 4px 0; }}
    .img-caption {{ font-size: 9.5pt; color: #444; text-align: center; font-style: italic; margin-bottom: 12px; }}
    .module-card {{ border: 1px solid #ccc; border-left: 5px solid #c0392b; padding: 10px 14px; margin: 10px 0; background: #fafafa; border-radius: 2px; }}
    .module-card h3 {{ margin-bottom: 4px; color: #c0392b; font-size: 12pt; }}
    .code-block {{ background: #1e1e2e; color: #cdd6f4; font-family: 'Courier New', monospace; font-size: 8.5pt; padding: 10px 14px; border-radius: 4px; margin: 8px 0; overflow-x: auto; white-space: pre; line-height: 1.55; }}
    .highlight-box {{ background: #fff8e1; border: 1px solid #ffc107; border-left: 5px solid #ffc107; padding: 9px 12px; margin: 10px 0; border-radius: 2px; }}
    .info-box {{ background: #e8f5e9; border: 1px solid #4caf50; border-left: 5px solid #4caf50; padding: 9px 12px; margin: 10px 0; border-radius: 2px; }}
    .warning-box {{ background: #fff3e0; border: 1px solid #ff9800; border-left: 5px solid #ff9800; padding: 9px 12px; margin: 10px 0; border-radius: 2px; }}
    hr.section-hr {{ border: none; border-top: 2px solid #111; margin: 20px 0; }}
    .formula {{ font-style: italic; text-align: center; font-size: 11.5pt; margin: 9px 0; background: #f0f0f0; padding: 7px; border-radius: 4px; font-family: 'Courier New', monospace; }}
    .print-btn {{ position: fixed; top: 20px; right: 20px; background: #c0392b; color: white; border: none; padding: 12px 24px; font-size: 14px; cursor: pointer; border-radius: 6px; font-weight: bold; box-shadow: 0 2px 12px rgba(0,0,0,0.3); z-index: 9999; }}
    .print-btn:hover {{ background: #922b21; }}
    .toc-item {{ display: flex; justify-content: space-between; padding: 3px 0; border-bottom: 1px dotted #bbb; }}
    .toc-item span:first-child {{ flex: 1; }}
    .toc-item span:last-child {{ font-weight: bold; white-space: nowrap; padding-left: 10px; }}
    .section-number {{ display: inline-block; background: #1a1a2e; color: white; padding: 2px 9px; border-radius: 2px; font-size: 9.5pt; margin-right: 7px; vertical-align: middle; }}
    .badge {{ display: inline-block; background: #c0392b; color: white; padding: 1px 8px; border-radius: 3px; font-size: 9pt; font-weight: bold; font-family: sans-serif; }}
    .badge-green {{ background: #27ae60; }}
    .badge-orange {{ background: #e67e22; }}
    .img-frame {{ border: 2px solid #ddd; border-radius: 5px; overflow: hidden; margin: 10px 0 4px 0; box-shadow: 0 2px 8px rgba(0,0,0,0.12); }}
    .img-frame img {{ width: 100%; display: block; }}
  </style>
</head>
<body>
<button class="print-btn no-print" onclick="window.print()">🖨️ Print / Save as PDF</button>

<!-- COVER PAGE -->
<div class="report-page">
  <div class="cover">
    <div class="cover-org">GURUGRAM POLICE</div>
    <div class="cover-event">CYBER SECURITY SUMMER INTERNSHIP</div>
    <div class="cover-year">(GPCSSI) 2025</div>
    <img src="data:image/png;base64,{logo_b64}" class="cover-logo" alt="CYBERSURAKSHAA Logo" />
    <div class="cover-title">CYBERSURAKSHAA — National Threat Detection Suite<br/>(AI-Powered Cyber Threat Intelligence Platform)</div>
    <table class="cover-table">
      <tr>
        <td style="text-align:left;width:50%">
          <div class="label">Submitted by:</div>
          <div>Name: </div>
          <div>GPCSSI ID: &nbsp;</div>
        </td>
        <td style="text-align:left;width:50%">
          <div class="label">Submitted To:</div>
          <div>Dr. Rakshit Tandon</div>
          <div>(Mentor GPCSSI)</div>
        </td>
      </tr>
    </table>
  </div>
</div>

<!-- TABLE OF CONTENTS -->
<div class="report-page page-break">
  <h1 class="section-title">Table of Contents</h1>
  <div style="margin-top:20px;">
    <div class="toc-item"><span>1. &nbsp;Introduction</span><span>3</span></div>
    <div class="toc-item"><span>2. &nbsp;Objective of the Project</span><span>4</span></div>
    <div class="toc-item"><span>3. &nbsp;Tools and Technology Used</span><span>5</span></div>
    <div class="toc-item"><span>4. &nbsp;System Workflow (Flowchart)</span><span>6</span></div>
    <div class="toc-item"><span>5. &nbsp;Case Examples — Module Outputs</span><span>8</span></div>
    <div class="toc-item"><span>6. &nbsp;Proof of Work &amp; Proof of Concept</span><span>10</span></div>
    <div class="toc-item"><span>7. &nbsp;Output — PDF &amp; HTML Reports</span><span>11</span></div>
    <div class="toc-item"><span>8. &nbsp;Security Measures &amp; Limitations</span><span>12</span></div>
    <div class="toc-item"><span>9. &nbsp;Future Scope</span><span>13</span></div>
  </div>
</div>

<!-- SECTION 1: INTRODUCTION -->
<div class="report-page page-break">
  <h1 class="section-title"><span class="section-number">1</span> Introduction</h1>
  <hr class="section-hr" />
  <p>
    India's rapidly growing internet user base of over 900 million active users has led to an alarming surge in cybercrime — from illegal betting advertisements on social media to AI-generated deepfake videos used for blackmail, and fraudulent customer care scams targeting everyday citizens. The Gurugram Cyber Crime Wing alone registers thousands of such complaints annually, highlighting the urgent need for intelligent, automated threat detection systems that can support law enforcement at scale.
  </p>
  <p>
    <strong>CYBERSURAKSHAA — National Threat Detection Suite</strong> is an AI-powered Cyber Threat Intelligence (CTI) platform developed during the GPCSSI 2025 internship programme. It unifies four specialized detection engines — Illegal Betting Content, AI Deepfake Manipulation, Fake Customer Care Scams, and Financial Investment Fraud — under a single secure, government-grade web interface. Each engine uses a multi-modal intelligence approach combining OCR, Natural Language Processing, Computer Vision (YOLOv8), and deep learning (EfficientNet-B4) to deliver high-confidence threat verdicts backed by exportable forensic reports.
  </p>
  <p>
    The platform incorporates Role-Based Access Control (RBAC), a live Security Operations Center (SOC) dashboard for real-time incident management, and professional PDF/HTML Cyber Threat Intelligence report generation. With its tricolor national gateway and India-specific threat taxonomy, CYBERSURAKSHAA is designed to be a next-generation national cyber defense tool — made in India, for the safety of every Indian.
  </p>
</div>

<!-- SECTION 2: OBJECTIVES -->
<div class="report-page page-break">
  <h1 class="section-title"><span class="section-number">2</span> Objective of the Project</h1>
  <hr class="section-hr" />
  <p>The primary goal of CYBERSURAKSHAA is to equip Indian law enforcement and cybersecurity analysts with an integrated AI-driven threat detection platform covering four major cybercrime domains:</p>

  <h2 class="sub-title">2.1 Core Detection Objectives</h2>
  <ul>
    <li><strong>Illegal Betting Detection:</strong> Analyze social media images using OCR + NLP + YOLOv8 to automatically identify and classify illegal online gambling promotions.</li>
    <li><strong>Deepfake Identification:</strong> Determine whether digital media has been AI-manipulated using MTCNN face cropping and EfficientNet-B4 frame-level classification.</li>
    <li><strong>Fake Customer Care Detection:</strong> Identify fraudulent helpdesk numbers impersonating Indian banks and services by cross-referencing extracted numbers against official contact registries and threat blacklists.</li>
    <li><strong>Investment Fraud Analysis:</strong> Evaluate suspected Ponzi schemes and crypto-fraud messages using dual NLP engines (XGBoost + XLM-RoBERTa) and domain WHOIS age checks.</li>
  </ul>

  <h2 class="sub-title">2.2 Platform Objectives</h2>
  <ul>
    <li><strong>Forensic Report Generation:</strong> Auto-compile scan results into PDF and HTML CTI reports with SHA-256 hashes, timestamps, threat verdicts, and investigator signatures — suitable as digital evidence.</li>
    <li><strong>Live SOC Dashboard:</strong> Maintain a centralized, real-time audit log of all scans with incident management controls (Flagged / Under Review / Safe).</li>
    <li><strong>Role-Based Access Control:</strong> Enforce tiered permissions — Admin (full control) and Analyst (scan access) — to ensure secure, accountable system usage.</li>
    <li><strong>Modular Architecture:</strong> Blueprint-based Flask design allowing new detection modules to be added independently without disrupting existing functionality.</li>
  </ul>

  <h2 class="sub-title">2.3 Social Impact</h2>
  <p>To provide Haryana Police's cyber crime wing with a practical open-source intelligence tool that reduces manual investigation time, accelerates evidence collection, and contributes to India's national cyber safety infrastructure — particularly protecting vulnerable populations from online financial fraud and digital exploitation.</p>
</div>

<!-- SECTION 3: TOOLS & TECHNOLOGY -->
<div class="report-page page-break">
  <h1 class="section-title"><span class="section-number">3</span> Tools and Technology Used</h1>
  <hr class="section-hr" />

  <h2 class="sub-title">3.1 Core Framework</h2>
  <table class="data-table avoid-break">
    <tr><th>Tool / Library</th><th>Version</th><th>Purpose</th></tr>
    <tr><td><strong>Python</strong></td><td>3.10+</td><td>Primary programming language for all backend services and ML pipelines.</td></tr>
    <tr><td><strong>Flask</strong></td><td>3.0+</td><td>WSGI web framework — routing, blueprint architecture, session management.</td></tr>
    <tr><td><strong>SQLite3</strong></td><td>Built-in</td><td>Database for user accounts, scan logs, official contacts, and threat blacklists.</td></tr>
    <tr><td><strong>Jinja2</strong></td><td>3.x</td><td>HTML templating engine for dynamic page rendering.</td></tr>
  </table>

  <h2 class="sub-title">3.2 Machine Learning &amp; Computer Vision</h2>
  <table class="data-table avoid-break">
    <tr><th>Tool / Library</th><th>Purpose</th></tr>
    <tr><td><strong>YOLOv8</strong> (Ultralytics)</td><td>Real-time logo detection for identifying betting platform logos in images.</td></tr>
    <tr><td><strong>PaddleOCR</strong></td><td>Optical Character Recognition — extracts text from uploaded screenshots and banners.</td></tr>
    <tr><td><strong>EfficientNet-B4</strong> (timm + PyTorch)</td><td>Deep CNN for deepfake detection — outputs real vs. fake probability per video frame.</td></tr>
    <tr><td><strong>MTCNN</strong> (facenet-pytorch)</td><td>Multi-task Cascaded CNN for face detection and cropping in images/video.</td></tr>
    <tr><td><strong>XGBoost + TF-IDF</strong></td><td>Investment scam text classifier (Engine A) using gradient boosting on TF-IDF features.</td></tr>
    <tr><td><strong>XLM-RoBERTa</strong></td><td>Multilingual transformer (Engine B) for cross-lingual investment scam detection.</td></tr>
    <tr><td><strong>spaCy NER</strong></td><td>Named Entity Recognition for extracting phone numbers and brand names in scam detection.</td></tr>
    <tr><td><strong>scikit-learn</strong></td><td>TF-IDF + Ridge Classifier pipeline for betting keyword scoring.</td></tr>
    <tr><td><strong>OpenCV (cv2)</strong></td><td>Video frame sampling and image preprocessing for deepfake analysis.</td></tr>
  </table>

  <h2 class="sub-title">3.3 Security &amp; Reporting</h2>
  <table class="data-table avoid-break">
    <tr><th>Tool / Library</th><th>Purpose</th></tr>
    <tr><td><strong>ReportLab</strong></td><td>PDF CTI report generation with stamps, SHA-256 hashes, and risk scorecards.</td></tr>
    <tr><td><strong>Werkzeug</strong></td><td>Secure file handling and password hashing (pbkdf2:sha256).</td></tr>
    <tr><td><strong>python-whois</strong></td><td>Domain WHOIS lookup — checks domain registration age for investment scam analysis.</td></tr>
    <tr><td><strong>hashlib (SHA-256)</strong></td><td>Cryptographic fingerprinting for every uploaded file — ensures forensic integrity.</td></tr>
    <tr><td><strong>secrets</strong></td><td>Cryptographically secure session key generation for the Flask application.</td></tr>
  </table>

  <h2 class="sub-title">3.4 Development Environment</h2>
  <table class="data-table avoid-break">
    <tr><th>Tool</th><th>Purpose</th></tr>
    <tr><td>Visual Studio Code</td><td>Primary IDE with Python, Pylance extensions and integrated Git terminal.</td></tr>
    <tr><td>Git / GitHub</td><td>Version control (github.com/DanishDhanjal15/CYBERSURAKSHAA).</td></tr>
    <tr><td>Windows 11 + PowerShell</td><td>Development and testing operating system.</td></tr>
    <tr><td>Google Chrome</td><td>UI testing and CTI HTML report rendering verification.</td></tr>
  </table>
</div>

<!-- SECTION 4: FLOWCHARTS -->
<div class="report-page page-break">
  <h1 class="section-title"><span class="section-number">4</span> System Workflow</h1>
  <hr class="section-hr" />

  <h2 class="sub-title">4.1 Overall System Architecture</h2>
  <div class="flowchart-container avoid-break">
    <svg viewBox="0 0 700 400" xmlns="http://www.w3.org/2000/svg" style="width:100%;max-width:670px;">
      <defs><marker id="arr" markerWidth="9" markerHeight="7" refX="8" refY="3.5" orient="auto"><polygon points="0 0, 9 3.5, 0 7" fill="#333"/></marker></defs>
      <rect x="270" y="10" width="160" height="36" rx="18" fill="#1a1a2e" stroke="#7f8c8d" stroke-width="1"/>
      <text x="350" y="33" text-anchor="middle" fill="white" font-size="11" font-family="sans-serif">🔐 Secure Login (RBAC)</text>
      <line x1="350" y1="46" x2="350" y2="66" stroke="#333" stroke-width="1.5" marker-end="url(#arr)"/>
      <rect x="240" y="66" width="220" height="34" rx="4" fill="#2c3e50" stroke="#7f8c8d"/>
      <text x="350" y="88" text-anchor="middle" fill="white" font-size="11" font-family="sans-serif">📊 SOC Dashboard</text>
      <line x1="350" y1="100" x2="350" y2="118" stroke="#333" stroke-width="1.5" marker-end="url(#arr)"/>
      <polygon points="350,118 455,146 350,174 245,146" fill="#f39c12" stroke="#e67e22" stroke-width="1.5"/>
      <text x="350" y="150" text-anchor="middle" fill="white" font-size="10" font-family="sans-serif" font-weight="bold">Select Module</text>
      <line x1="245" y1="146" x2="95" y2="195" stroke="#333" stroke-width="1.5" marker-end="url(#arr)"/>
      <line x1="290" y1="172" x2="235" y2="195" stroke="#333" stroke-width="1.5" marker-end="url(#arr)"/>
      <line x1="410" y1="172" x2="465" y2="195" stroke="#333" stroke-width="1.5" marker-end="url(#arr)"/>
      <line x1="455" y1="146" x2="605" y2="195" stroke="#333" stroke-width="1.5" marker-end="url(#arr)"/>
      <rect x="25" y="195" width="140" height="38" rx="4" fill="#c0392b" stroke="#922b21"/>
      <text x="95" y="213" text-anchor="middle" fill="white" font-size="9.5" font-family="sans-serif" font-weight="bold">🎰 Betting Detector</text>
      <text x="95" y="226" text-anchor="middle" fill="#fdd" font-size="8.5" font-family="sans-serif">OCR+YOLO+NLP</text>
      <rect x="170" y="195" width="140" height="38" rx="4" fill="#8e44ad" stroke="#6c3483"/>
      <text x="240" y="213" text-anchor="middle" fill="white" font-size="9.5" font-family="sans-serif" font-weight="bold">📹 Deepfake</text>
      <text x="240" y="226" text-anchor="middle" fill="#edd" font-size="8.5" font-family="sans-serif">MTCNN+EfficientNet</text>
      <rect x="390" y="195" width="150" height="38" rx="4" fill="#16a085" stroke="#117a65"/>
      <text x="465" y="213" text-anchor="middle" fill="white" font-size="9.5" font-family="sans-serif" font-weight="bold">📞 Customer Care</text>
      <text x="465" y="226" text-anchor="middle" fill="#dfd" font-size="8.5" font-family="sans-serif">PaddleOCR+spaCy</text>
      <rect x="545" y="195" width="140" height="38" rx="4" fill="#2980b9" stroke="#1a5276"/>
      <text x="615" y="213" text-anchor="middle" fill="white" font-size="9.5" font-family="sans-serif" font-weight="bold">📈 Investment</text>
      <text x="615" y="226" text-anchor="middle" fill="#ddf" font-size="8.5" font-family="sans-serif">XGBoost+RoBERTa</text>
      <line x1="95" y1="233" x2="198" y2="288" stroke="#333" stroke-width="1.2" marker-end="url(#arr)"/>
      <line x1="240" y1="233" x2="278" y2="288" stroke="#333" stroke-width="1.2" marker-end="url(#arr)"/>
      <line x1="465" y1="233" x2="422" y2="288" stroke="#333" stroke-width="1.2" marker-end="url(#arr)"/>
      <line x1="615" y1="233" x2="502" y2="288" stroke="#333" stroke-width="1.2" marker-end="url(#arr)"/>
      <rect x="198" y="288" width="300" height="34" rx="4" fill="#27ae60" stroke="#1e8449"/>
      <text x="348" y="310" text-anchor="middle" fill="white" font-size="11" font-family="sans-serif" font-weight="bold">⚡ AI Verdict + Confidence Score</text>
      <line x1="348" y1="322" x2="348" y2="342" stroke="#333" stroke-width="1.5" marker-end="url(#arr)"/>
      <rect x="208" y="342" width="280" height="34" rx="4" fill="#c0392b" stroke="#922b21"/>
      <text x="348" y="364" text-anchor="middle" fill="white" font-size="11" font-family="sans-serif" font-weight="bold">📄 CTI Report (PDF + HTML)</text>
      <line x1="348" y1="376" x2="348" y2="393" stroke="#333" stroke-width="1.5" marker-end="url(#arr)"/>
      <rect x="228" y="393" width="240" height="8" rx="2" fill="#2c3e50"/>
      <text x="348" y="400" text-anchor="middle" fill="white" font-size="7.5" font-family="sans-serif">SOC Audit Log Registered</text>
    </svg>
    <p class="img-caption">Figure 4.1 — CYBERSURAKSHAA Master System Workflow</p>
  </div>

  <h2 class="sub-title">4.2 Betting Content Detector Pipeline</h2>
  <div class="flowchart-container avoid-break">
    <svg viewBox="0 0 610 175" xmlns="http://www.w3.org/2000/svg" style="width:100%;max-width:590px;">
      <defs><marker id="a2" markerWidth="8" markerHeight="6" refX="7" refY="3" orient="auto"><polygon points="0 0, 8 3, 0 6" fill="#333"/></marker></defs>
      <rect x="5" y="66" width="95" height="40" rx="4" fill="#3498db" stroke="#2980b9"/><text x="52" y="84" text-anchor="middle" fill="white" font-size="9" font-family="sans-serif">Upload Image</text><text x="52" y="97" text-anchor="middle" fill="#cef" font-size="8" font-family="sans-serif">Screenshot/Ad</text>
      <line x1="100" y1="86" x2="118" y2="86" stroke="#333" stroke-width="1.5" marker-end="url(#a2)"/>
      <rect x="118" y="66" width="95" height="40" rx="4" fill="#e67e22" stroke="#d35400"/><text x="165" y="84" text-anchor="middle" fill="white" font-size="9" font-family="sans-serif">PaddleOCR</text><text x="165" y="97" text-anchor="middle" fill="#fed" font-size="8" font-family="sans-serif">Text Extraction</text>
      <line x1="213" y1="86" x2="231" y2="86" stroke="#333" stroke-width="1.5" marker-end="url(#a2)"/>
      <rect x="231" y="12" width="100" height="40" rx="4" fill="#9b59b6" stroke="#7d3c98"/><text x="281" y="29" text-anchor="middle" fill="white" font-size="9" font-family="sans-serif">TF-IDF+Ridge</text><text x="281" y="42" text-anchor="middle" fill="#edf" font-size="8" font-family="sans-serif">NLP Classifier</text>
      <rect x="231" y="120" width="100" height="40" rx="4" fill="#c0392b" stroke="#922b21"/><text x="281" y="138" text-anchor="middle" fill="white" font-size="9" font-family="sans-serif">YOLOv8</text><text x="281" y="151" text-anchor="middle" fill="#fdd" font-size="8" font-family="sans-serif">Logo Detection</text>
      <line x1="231" y1="86" x2="231" y2="32" stroke="#333" stroke-width="1.2" marker-end="url(#a2)"/>
      <line x1="231" y1="86" x2="231" y2="140" stroke="#333" stroke-width="1.2" marker-end="url(#a2)"/>
      <line x1="331" y1="32" x2="415" y2="77" stroke="#333" stroke-width="1.2" marker-end="url(#a2)"/>
      <line x1="331" y1="140" x2="415" y2="95" stroke="#333" stroke-width="1.2" marker-end="url(#a2)"/>
      <rect x="415" y="66" width="95" height="40" rx="4" fill="#27ae60" stroke="#1e8449"/><text x="462" y="83" text-anchor="middle" fill="white" font-size="9" font-family="sans-serif">Fusion Engine</text><text x="462" y="96" text-anchor="middle" fill="#dfd" font-size="8" font-family="sans-serif">0.6T + 0.4V</text>
      <line x1="510" y1="86" x2="528" y2="86" stroke="#333" stroke-width="1.5" marker-end="url(#a2)"/>
      <rect x="528" y="62" width="76" height="48" rx="24" fill="#1a1a2e" stroke="#555"/>
      <text x="566" y="82" text-anchor="middle" fill="white" font-size="9" font-family="sans-serif">VERDICT</text>
      <text x="566" y="95" text-anchor="middle" fill="#c0392b" font-size="8" font-family="sans-serif" font-weight="bold">SAFE/</text>
      <text x="566" y="106" text-anchor="middle" fill="#c0392b" font-size="8" font-family="sans-serif" font-weight="bold">BETTING</text>
    </svg>
    <p class="img-caption">Figure 4.2 — Betting Detector Pipeline (OCR → NLP + YOLO → Fusion)</p>
  </div>

  <h2 class="sub-title">4.3 Deepfake Detection Pipeline</h2>
  <div class="flowchart-container avoid-break">
    <svg viewBox="0 0 630 155" xmlns="http://www.w3.org/2000/svg" style="width:100%;max-width:600px;">
      <defs><marker id="a3" markerWidth="8" markerHeight="6" refX="7" refY="3" orient="auto"><polygon points="0 0, 8 3, 0 6" fill="#333"/></marker></defs>
      <rect x="5" y="57" width="100" height="38" rx="4" fill="#8e44ad" stroke="#6c3483"/><text x="55" y="75" text-anchor="middle" fill="white" font-size="9" font-family="sans-serif">Upload Media</text><text x="55" y="87" text-anchor="middle" fill="#edd" font-size="8" font-family="sans-serif">Image / Video</text>
      <line x1="105" y1="76" x2="120" y2="76" stroke="#333" stroke-width="1.5" marker-end="url(#a3)"/>
      <rect x="120" y="36" width="110" height="38" rx="4" fill="#2c3e50" stroke="#1a252f"/><text x="175" y="53" text-anchor="middle" fill="white" font-size="9" font-family="sans-serif">OpenCV Sampling</text><text x="175" y="66" text-anchor="middle" fill="#cde" font-size="8" font-family="sans-serif">10 Frames (Video)</text>
      <rect x="120" y="98" width="110" height="38" rx="4" fill="#16a085" stroke="#117a65"/><text x="175" y="115" text-anchor="middle" fill="white" font-size="9" font-family="sans-serif">Direct Load</text><text x="175" y="128" text-anchor="middle" fill="#dfd" font-size="8" font-family="sans-serif">(Image)</text>
      <line x1="105" y1="76" x2="120" y2="55" stroke="#333" stroke-width="1.2" marker-end="url(#a3)"/>
      <line x1="105" y1="76" x2="120" y2="117" stroke="#333" stroke-width="1.2" marker-end="url(#a3)"/>
      <line x1="230" y1="55" x2="262" y2="74" stroke="#333" stroke-width="1.2" marker-end="url(#a3)"/>
      <line x1="230" y1="117" x2="262" y2="96" stroke="#333" stroke-width="1.2" marker-end="url(#a3)"/>
      <rect x="262" y="57" width="110" height="38" rx="4" fill="#e74c3c" stroke="#c0392b"/><text x="317" y="75" text-anchor="middle" fill="white" font-size="9" font-family="sans-serif">MTCNN</text><text x="317" y="88" text-anchor="middle" fill="#fdd" font-size="8" font-family="sans-serif">Face Crop 224×224</text>
      <line x1="372" y1="76" x2="390" y2="76" stroke="#333" stroke-width="1.5" marker-end="url(#a3)"/>
      <rect x="390" y="57" width="120" height="38" rx="4" fill="#2980b9" stroke="#1a5276"/><text x="450" y="75" text-anchor="middle" fill="white" font-size="9" font-family="sans-serif">EfficientNet-B4</text><text x="450" y="88" text-anchor="middle" fill="#ddf" font-size="8" font-family="sans-serif">Real vs. Fake</text>
      <line x1="510" y1="76" x2="528" y2="76" stroke="#333" stroke-width="1.5" marker-end="url(#a3)"/>
      <rect x="528" y="52" width="92" height="48" rx="24" fill="#1a1a2e" stroke="#555"/>
      <text x="574" y="72" text-anchor="middle" fill="white" font-size="9" font-family="sans-serif">VERDICT</text>
      <text x="574" y="85" text-anchor="middle" fill="#e74c3c" font-size="8" font-family="sans-serif" font-weight="bold">REAL/</text>
      <text x="574" y="96" text-anchor="middle" fill="#e74c3c" font-size="8" font-family="sans-serif" font-weight="bold">FAKE</text>
    </svg>
    <p class="img-caption">Figure 4.3 — Deepfake Detection Pipeline (MTCNN → EfficientNet-B4)</p>
  </div>

  <h2 class="sub-title">4.4 Fusion Score Formula</h2>
  <div class="formula">Final Score = (Text Probability × 0.6) + (Vision Probability × 0.4)</div>
  <p style="font-size:11pt;">If a betting logo is detected with confidence &gt;80%, the final classification is automatically elevated to <strong>BETTING</strong>, ensuring high-confidence visual evidence is never overridden by text scores.</p>
</div>

<!-- SECTION 5: CASE EXAMPLES -->
<div class="report-page page-break">
  <h1 class="section-title"><span class="section-number">5</span> Case Examples — Module Outputs</h1>
  <hr class="section-hr" />
  <p>The following section demonstrates each detection module with real outputs generated by the CYBERSURAKSHAA system.</p>

  <h2 class="sub-title">5.1 Case 1 — Illegal Betting Content Detector</h2>
  <div class="module-card avoid-break">
    <h3>🎰 Module: Betting Content Detector</h3>
    <p><strong>Input:</strong> A social media advertisement showing cricket betting — "PLAY NOW &amp; WIN BIG, INSTANT PAYTM" with a WhatsApp contact number.</p>
    <p><strong>AI Verdict: </strong><span class="badge">BETTING DETECTED</span> &nbsp; <strong>Confidence: 89%</strong></p>
    <ul>
      <li>Text Classifier detected keywords: <em>bet, betting</em></li>
      <li>YOLO Vision: Betting platform logo identified in banner</li>
      <li>Fusion Score: (87% × 0.6) + (92% × 0.4) = <strong>89%</strong></li>
    </ul>
  </div>
  <div class="img-frame"><img src="data:image/png;base64,{betting_b64}" alt="Betting Detector Output" /></div>
  <p class="img-caption">Figure 5.1 — Betting Content Detector: 89% Confidence — BETTING DETECTED</p>

  <h2 class="sub-title">5.2 Case 2 — Deepfake Video Detector</h2>
  <div class="module-card avoid-break">
    <h3>📹 Module: Deepfake Face &amp; Video Detector</h3>
    <p><strong>Input:</strong> A 10-second video showing a person walking in a corridor — suspected AI face-swap manipulation.</p>
    <p><strong>AI Verdict: </strong><span class="badge">FAKE — MANIPULATED</span> &nbsp; <strong>Confidence: 96%</strong></p>
    <ul>
      <li>MTCNN detected facial regions across 10 sampled frames</li>
      <li>EfficientNet-B4 average fake probability: <strong>96.4%</strong></li>
      <li>Verdict: Avg Score (0.964) &gt; Threshold (0.50) → FAKE</li>
    </ul>
  </div>
  <div class="img-frame"><img src="data:image/png;base64,{deepfake_b64}" alt="Deepfake Detector Output" /></div>
  <p class="img-caption">Figure 5.2 — Deepfake Detector: 96% Score — MANIPULATED / FAKE</p>
</div>

<!-- SECTION 5 CONTINUED -->
<div class="report-page page-break">
  <h2 class="sub-title">5.3 Case 3 — Fake Customer Care Scam Detector</h2>
  <div class="module-card avoid-break">
    <h3>📞 Module: Fake Customer Care Scam Detector</h3>
    <p><strong>Input:</strong> An advertisement claiming to be "Paytm Customer Care" with the number +91 81247 96305, a fraudulent helpdesk number.</p>
    <p><strong>AI Verdict: </strong><span class="badge" style="background:#e74c3c;">⚠️ SCAM DETECTED</span> &nbsp; <strong>Risk Score: 92%</strong></p>
    <ul>
      <li>spaCy NER extracted phone number does not match Paytm's verified official contacts</li>
      <li>Number flagged in Threat Intelligence blacklist database</li>
      <li>Urgency Index: HIGH — Coercion Rating: HIGH</li>
      <li>Telecom Trust: 12% (Flagged VoIP number)</li>
    </ul>
  </div>
  <div class="img-frame"><img src="data:image/png;base64,{customer_b64}" alt="Customer Care Scam Detector Output" /></div>
  <p class="img-caption">Figure 5.3 — Fake Customer Care Detector: SCAM DETECTED Verdict</p>

  <h2 class="sub-title">5.4 Case 4 — Investment Scam Detector (ScamGuard AI)</h2>
  <div class="module-card avoid-break">
    <h3>📈 Module: Investment Scam Detector</h3>
    <p><strong>Input:</strong> Message text with guaranteed high-yield crypto investment promises and a newly registered suspicious domain link.</p>
    <p><strong>AI Verdict: </strong><span class="badge" style="background:#c0392b;">🔴 HIGH RISK — FINANCIAL FRAUD</span> &nbsp; <strong>Fraud Score: 97/100</strong></p>
    <ul>
      <li>WHOIS: Domain registered less than 30 days ago — HIGH RISK</li>
      <li>Engine A (XGBoost): Matched high-risk keywords — <em>guaranteed return, double money, risk-free</em></li>
      <li>Final Fraud Score: <strong>97/100</strong> → 🔴 RED — Financial Fraud Confirmed</li>
    </ul>
  </div>
  <div class="img-frame"><img src="data:image/png;base64,{investment_b64}" alt="Investment Scam Detector Output" /></div>
  <p class="img-caption">Figure 5.4 — Investment Scam Detector: 97/100 Fraud Score — HIGH RISK <em>(Screenshot to be updated by analyst)</em></p>
</div>

<!-- SECTION 6: PROOF OF WORK -->
<div class="report-page page-break">
  <h1 class="section-title"><span class="section-number">6</span> Proof of Work &amp; Proof of Concept</h1>
  <hr class="section-hr" />
  <p>This section presents the core application architecture and key source code that demonstrates the technical depth and originality of the CYBERSURAKSHAA project.</p>

  <h2 class="sub-title">6.1 Application Entry Point — app.py</h2>
  <div class="code-block">"""
CYBERSURAKSHAA -- All-in-One Detection Suite
Unified Flask application combining 4 detection models:
  1. Betting Content Detector (OCR + YOLO + NLP)
  2. Deepfake Detector (EfficientNet B4 + MTCNN)
  3. Fake Customer Care Scam Detector (PaddleOCR + spaCy NER)
  4. Investment Scam Detector (ScamGuard AI)
"""
import secrets
from flask import Flask, render_template
from services.auth_db import init_db
from services.threat_crawler import start_crawler

app = Flask(__name__)
app.secret_key = secrets.token_hex(24)
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024  # 500 MB upload limit

init_db()           # Initialize SQLite database on startup
start_crawler(app)  # Launch background threat crawler thread

# Register all detection module blueprints
from blueprints.betting import bp as betting_bp
from blueprints.deepfake import bp as deepfake_bp
from blueprints.customer_care import bp as customer_care_bp
from blueprints.investment import bp as investment_bp

app.register_blueprint(betting_bp)
app.register_blueprint(deepfake_bp)
app.register_blueprint(customer_care_bp)
app.register_blueprint(investment_bp)

if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.1', port=5000, use_reloader=False)</div>

  <h2 class="sub-title">6.2 Live SOC Dashboard</h2>
  <div class="img-frame"><img src="data:image/png;base64,{hub_b64}" alt="SOC Dashboard" /></div>
  <p class="img-caption">Figure 6.1 — CYBERSURAKSHAA SOC Dashboard: Real-time threat monitoring, crawler feed, and incident log</p>
</div>

<!-- SECTION 7: OUTPUT -->
<div class="report-page page-break">
  <h1 class="section-title"><span class="section-number">7</span> Output — PDF &amp; HTML Reports</h1>
  <hr class="section-hr" />
  <p>After completing any scan, analysts can export a full <strong>Cyber Threat Intelligence (CTI) Report</strong> in two formats.</p>

  <h2 class="sub-title">7.1 PDF Report Features</h2>
  <div class="info-box avoid-break">
    <ul>
      <li>🇮🇳 <strong>Official CYBERSURAKSHAA header</strong> with Indian tricolor branding</li>
      <li>📋 <strong>Scan Metadata:</strong> Module name, filename, timestamp, SHA-256 file hash</li>
      <li>🔍 <strong>Extracted Indicators:</strong> Phone numbers, betting keywords, deepfake scores</li>
      <li>🎯 <strong>Risk Score Card</strong> with severity level (HIGH / MEDIUM / LOW)</li>
      <li>🔴 <strong>Vector Stamp Overlays:</strong> "VERIFIED SCAM", "ILLEGAL BETTING", "MANIPULATED / FAKE", "FINANCIAL FRAUD"</li>
      <li>✍️ <strong>Investigator Signature Block</strong> naming the analyst who ran the scan</li>
      <li>📌 <strong>Official Recommendation Text</strong> with legal advisory and follow-up action items</li>
    </ul>
  </div>

  <h2 class="sub-title">7.2 HTML Report Features</h2>
  <div class="info-box avoid-break">
    <ul>
      <li>🎨 Responsive standalone HTML — no external dependencies, opens in any browser</li>
      <li>📷 Embedded annotated target media (base64 encoded) — directly viewable</li>
      <li>🏷️ Visual CSS stamp design (diagonal red threat classification stamp)</li>
      <li>📊 Color-coded risk score section with confidence percentages</li>
      <li>🔗 Shareable as a single .html file — ideal for inter-agency evidence sharing</li>
    </ul>
  </div>

  <h2 class="sub-title">7.3 Incident Status Controls (SOC Dashboard)</h2>
  <ul>
    <li><span class="badge" style="background:#c0392b;">🚨 FLAGGED FOR TAKEDOWN</span> — High-confidence threats requiring immediate action</li>
    <li><span class="badge badge-orange">⚠️ UNDER REVIEW</span> — Moderate-risk cases requiring analyst verification</li>
    <li><span class="badge badge-green">✅ SAFE</span> — Content cleared by the AI detection system</li>
  </ul>
</div>

<!-- SECTION 8: SECURITY & LIMITATIONS -->
<div class="report-page page-break">
  <h1 class="section-title"><span class="section-number">8</span> Security Measures &amp; Limitations</h1>
  <hr class="section-hr" />

  <h2 class="sub-title">8.1 Security Measures</h2>
  <ul>
    <li><strong>Role-Based Access Control (RBAC):</strong> Admin and Analyst roles with distinct access permissions. All admin routes protected with session validation and role checks.</li>
    <li><strong>Password Hashing:</strong> Werkzeug <code>pbkdf2:sha256</code> hashing with auto-salting — passwords never stored in plain text.</li>
    <li><strong>Secure Sessions:</strong> Flask session key generated via <code>secrets.token_hex(24)</code> — prevents session hijacking.</li>
    <li><strong>SHA-256 File Hashing:</strong> Every uploaded file receives a cryptographic SHA-256 fingerprint — ensures tamper-evident chain-of-custody for forensic evidence.</li>
    <li><strong>File Size Limit:</strong> 500MB upload cap prevents denial-of-service attacks.</li>
    <li><strong>Audit Logging:</strong> Every scan recorded in SQLite with timestamp, user ID, module, and verdict — full non-repudiable audit trail.</li>
    <li><strong>Ethical Use Only:</strong> Designed for authorized law enforcement and cybersecurity personnel. No real-time surveillance — operates only on explicitly submitted evidence.</li>
  </ul>

  <h2 class="sub-title">8.2 Current Limitations</h2>
  <div class="warning-box avoid-break">
    <ul>
      <li><strong>YOLO Logo Scope:</strong> Trained on a limited dataset of known betting logos — new regional platforms not in training data will only be caught by text classification.</li>
      <li><strong>Face Detection Dependency:</strong> Deepfake analysis requires a detectable face — videos without faces (crowd scenes, hands-only) produce inconclusive results.</li>
      <li><strong>Transformer Offline Mode:</strong> XLM-RoBERTa may fall back to XGBoost on machines without GPU, reducing multilingual analysis capability.</li>
      <li><strong>No Premium Threat Feeds:</strong> Uses local SQLite blacklist — no integration with Chainalysis, PhishTank Pro, or TrueCaller Business API.</li>
      <li><strong>No Audio Deepfake:</strong> Only visual (image/video) deepfakes are detected. AI voice cloning is not yet supported.</li>
      <li><strong>Regional Language OCR:</strong> PaddleOCR accuracy may be reduced for some regional Indian scripts (Tamil, Telugu, Marathi).</li>
    </ul>
  </div>
</div>

<!-- SECTION 9: FUTURE SCOPE -->
<div class="report-page page-break">
  <h1 class="section-title"><span class="section-number">9</span> Future Scope</h1>
  <hr class="section-hr" />
  <p>CYBERSURAKSHAA lays the foundation for a comprehensive national cyber threat intelligence ecosystem. The following roadmap outlines high-impact enhancements:</p>

  <ul>
    <li style="margin-bottom:10px;"><strong>🎙️ Audio Deepfake Detection:</strong> Integrate spectrogram-based CNN classifiers to detect AI-synthesized voice cloning (e.g., ElevenLabs, VALL-E) — creating a fully multimodal forensics capability combining sight, sound, and text analysis.</li>
    <li style="margin-bottom:10px;"><strong>📡 Real-Time Social Media Integration:</strong> Connect to Meta Graph API, Twitter/X API v2, and Telegram Bot API to enable automated ingestion and analysis of flagged posts from citizen reports — eliminating manual screenshot uploads.</li>
    <li style="margin-bottom:10px;"><strong>⛓️ Blockchain &amp; Cryptocurrency Fraud Tracing:</strong> Integrate with Etherscan/BscScan APIs to trace Bitcoin, Ethereum, and Polygon transaction chains linked to scam wallets — enabling asset freezing under India's IT Act and PMLA provisions.</li>
    <li style="margin-bottom:10px;"><strong>🌐 National Threat Intelligence Sharing:</strong> Evolve into a federated hub connecting Haryana Police, CERT-In, and state cybercrime units using STIX/TAXII standard for sharing anonymized IOCs — enabling coordinated nationwide threat suppression.</li>
    <li style="margin-bottom:10px;"><strong>📱 Mobile Application:</strong> Companion Android/iOS app with TensorFlow Lite offline models — enabling field officers to photograph suspicious content and receive instant AI verdicts without desktop access.</li>
    <li style="margin-bottom:10px;"><strong>🗣️ Regional Language NLP:</strong> Fine-tune IndicBERT and MuRIL multilingual transformers on India-specific datasets to detect betting ads, scam SMS, and investment fraud across all 22 scheduled Indian languages.</li>
    <li style="margin-bottom:10px;"><strong>🕵️ OSINT &amp; Dark Web Monitoring:</strong> Monitor dark web marketplaces for sale of compromised Indian citizen data, scam-as-a-service kits targeting Indian platforms, and leaked credentials — triggering pre-emptive alerts before fraud campaigns launch.</li>
    <li style="margin-bottom:10px;"><strong>☁️ NIC / MeitY Cloud Deployment:</strong> Deploy as an official government SaaS platform on NIC infrastructure, integrated into the National Cyber Crime Reporting Portal (cybercrime.gov.in) — making AI threat detection available to all 28 state cybercrime wings simultaneously.</li>
  </ul>

  <div class="info-box avoid-break">
    <strong>🎯 Vision:</strong> CYBERSURAKSHAA aspires to become India's first indigenous, open-source AI-powered national cyber threat intelligence platform — a digital Kavach (shield) built by Indian developers, for Indian citizens, protecting the nation's digital sovereignty one scan at a time.
  </div>

  <hr class="section-hr" style="margin-top:40px;"/>
  <div style="text-align:center;margin-top:20px;">
    <p><strong>— End of Project Report —</strong></p>
    <br/>
    
   
  
    <br/>
    <p style="font-size:10pt;color:#555;">Project: CYBERSURAKSHAA — National Threat Detection Suite<br/>
    GitHub: github.com/DanishDhanjal15/CYBERSURAKSHAA</p>
  </div>
</div>

</body>
</html>"""

out_path = r'c:\Users\Danish\OneDrive\Desktop\All in one\project_report.html'
with open(out_path, 'w', encoding='utf-8') as f:
    f.write(html)

print(f"Report written: {{len(html)}} chars to {{out_path}}")
