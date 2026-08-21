# -*- coding: utf-8 -*-
import os, html as htmllib

PROJ = r'c:\Users\Danish\OneDrive\Desktop\All in one'

def load(key):
    path = os.path.join(PROJ, 'scratch', 'imgs', key + '.b64')
    with open(path, 'r') as f:
        return f.read().strip()

logo     = load('LOGO')
betting  = load('BETTING')
deepfake = load('DEEPFAKE')
customer = load('CUSTOMER')
invest   = load('INVEST')
hub      = load('HUB')

def img(b64, alt=''):
    return f'<div class="fr"><img src="data:image/png;base64,{b64}" alt="{alt}"/></div>'

CSS = '''
@page{size:A4;margin:2.2cm 2.0cm 2.2cm 2.5cm}
@media print{.no-print{display:none!important}body{background:white}.page-break{page-break-before:always;break-before:page}.avoid-break{page-break-inside:avoid;break-inside:avoid}}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Times New Roman',Times,serif;font-size:12pt;line-height:1.7;color:#111;background:#ddd}
.rp{background:white;width:210mm;min-height:297mm;margin:20px auto;padding:2.2cm 2.0cm 2.2cm 2.5cm;box-shadow:0 4px 30px rgba(0,0,0,.15)}
.cover{display:flex;flex-direction:column;align-items:center;justify-content:center;min-height:257mm;text-align:center}
.corg{font-size:18pt;font-weight:bold;text-decoration:underline;letter-spacing:1px;margin-bottom:10px}
.cevt{font-size:16pt;font-weight:bold;text-decoration:underline;margin-bottom:6px}
.cyr{font-size:16pt;font-weight:bold;text-decoration:underline;margin-bottom:28px}
.clogo{width:150px;height:150px;border-radius:50%;object-fit:cover;margin-bottom:28px;border:3px solid #c0392b;box-shadow:0 2px 14px rgba(0,0,0,.2)}
.ctit{font-size:14pt;font-weight:bold;text-decoration:underline;margin-bottom:36px;max-width:480px}
.ctbl{width:100%;max-width:480px;border-collapse:collapse;font-size:12pt}
.ctbl td{padding:5px 20px;vertical-align:top}
h1.st{font-size:15pt;font-weight:bold;text-align:center;text-decoration:underline;margin-bottom:18px;margin-top:8px}
h2.sb{font-size:13pt;font-weight:bold;margin-top:16px;margin-bottom:7px;text-decoration:underline}
p{margin-bottom:9px;text-align:justify}
ul{margin-left:22px;margin-bottom:9px}
ul li{margin-bottom:3px}
table.dt{width:100%;border-collapse:collapse;margin:12px 0;font-size:10.5pt}
table.dt th{background:#1a1a2e;color:#fff;padding:7px 10px;text-align:left;font-weight:bold}
table.dt td{border:1px solid #bbb;padding:6px 10px;vertical-align:top}
table.dt tr:nth-child(even) td{background:#f5f5f5}
.fc{margin:16px auto;text-align:center}
.fc svg{max-width:100%;height:auto}
.ic{font-size:9.5pt;color:#444;text-align:center;font-style:italic;margin-bottom:12px;margin-top:4px}
.mc{border:1px solid #ccc;border-left:5px solid #c0392b;padding:10px 14px;margin:10px 0;background:#fafafa;border-radius:2px}
.mc h3{margin-bottom:4px;color:#c0392b;font-size:12pt}
.cb{background:#1e1e2e;color:#cdd6f4;font-family:'Courier New',monospace;font-size:8.5pt;padding:10px 14px;border-radius:4px;margin:8px 0;white-space:pre;line-height:1.55;overflow-x:auto}
.ib{background:#e8f5e9;border:1px solid #4caf50;border-left:5px solid #4caf50;padding:9px 12px;margin:10px 0;border-radius:2px}
.wb{background:#fff3e0;border:1px solid #ff9800;border-left:5px solid #ff9800;padding:9px 12px;margin:10px 0;border-radius:2px}
hr.hr{border:none;border-top:2px solid #111;margin:20px 0}
.fm{font-style:italic;text-align:center;font-size:11.5pt;margin:9px 0;background:#f0f0f0;padding:7px;border-radius:4px;font-family:'Courier New',monospace}
.pb{position:fixed;top:20px;right:20px;background:#c0392b;color:white;border:none;padding:12px 24px;font-size:14px;cursor:pointer;border-radius:6px;font-weight:bold;box-shadow:0 2px 12px rgba(0,0,0,.3);z-index:9999}
.pb:hover{background:#922b21}
.tc{display:flex;justify-content:space-between;padding:3px 0;border-bottom:1px dotted #bbb}
.sn{display:inline-block;background:#1a1a2e;color:white;padding:2px 9px;border-radius:2px;font-size:9.5pt;margin-right:7px;vertical-align:middle}
.badge{display:inline-block;background:#c0392b;color:white;padding:1px 8px;border-radius:3px;font-size:9pt;font-weight:bold;font-family:sans-serif}
.bg{background:#27ae60}.bo{background:#e67e22}
.fr{border:2px solid #ddd;border-radius:5px;overflow:hidden;margin:10px 0 4px 0;box-shadow:0 2px 8px rgba(0,0,0,.12)}
.fr img{width:100%;display:block}
code{background:#f0f0f0;padding:1px 4px;border-radius:2px;font-size:9pt;font-family:'Courier New',monospace}
'''

APP_CODE = htmllib.escape(
    'import secrets\n'
    'from flask import Flask, render_template\n'
    'from services.auth_db import init_db\n'
    'from services.threat_crawler import start_crawler\n\n'
    'app = Flask(__name__)\n'
    "app.secret_key = secrets.token_hex(24)\n"
    "app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024  # 500 MB\n\n"
    'init_db()           # Initialize SQLite database on startup\n'
    'start_crawler(app)  # Launch background threat crawler thread\n\n'
    '# Register all detection module blueprints\n'
    'from blueprints.betting import bp as betting_bp\n'
    'from blueprints.deepfake import bp as deepfake_bp\n'
    'from blueprints.customer_care import bp as customer_care_bp\n'
    'from blueprints.investment import bp as investment_bp\n\n'
    'app.register_blueprint(betting_bp)\n'
    'app.register_blueprint(deepfake_bp)\n'
    'app.register_blueprint(customer_care_bp)\n'
    'app.register_blueprint(investment_bp)\n\n'
    "if __name__ == '__main__':\n"
    "    app.run(debug=True, host='127.0.0.1', port=5000, use_reloader=False)"
)

FLOW_MAIN = '''<svg viewBox="0 0 700 400" xmlns="http://www.w3.org/2000/svg" style="width:100%;max-width:670px">
<defs><marker id="arr" markerWidth="9" markerHeight="7" refX="8" refY="3.5" orient="auto"><polygon points="0 0, 9 3.5, 0 7" fill="#333"/></marker></defs>
<rect x="270" y="10" width="160" height="36" rx="18" fill="#1a1a2e"/><text x="350" y="33" text-anchor="middle" fill="white" font-size="11" font-family="sans-serif">Secure Login (RBAC)</text>
<line x1="350" y1="46" x2="350" y2="66" stroke="#333" stroke-width="1.5" marker-end="url(#arr)"/>
<rect x="240" y="66" width="220" height="34" rx="4" fill="#2c3e50"/><text x="350" y="88" text-anchor="middle" fill="white" font-size="11" font-family="sans-serif">SOC Dashboard</text>
<line x1="350" y1="100" x2="350" y2="118" stroke="#333" stroke-width="1.5" marker-end="url(#arr)"/>
<polygon points="350,118 455,146 350,174 245,146" fill="#f39c12" stroke="#e67e22" stroke-width="1.5"/>
<text x="350" y="150" text-anchor="middle" fill="white" font-size="10" font-family="sans-serif" font-weight="bold">Select Module</text>
<line x1="245" y1="146" x2="95" y2="195" stroke="#333" stroke-width="1.5" marker-end="url(#arr)"/>
<line x1="290" y1="172" x2="235" y2="195" stroke="#333" stroke-width="1.5" marker-end="url(#arr)"/>
<line x1="410" y1="172" x2="465" y2="195" stroke="#333" stroke-width="1.5" marker-end="url(#arr)"/>
<line x1="455" y1="146" x2="605" y2="195" stroke="#333" stroke-width="1.5" marker-end="url(#arr)"/>
<rect x="25" y="195" width="140" height="38" rx="4" fill="#c0392b"/>
<text x="95" y="213" text-anchor="middle" fill="white" font-size="9.5" font-family="sans-serif" font-weight="bold">Betting Detector</text>
<text x="95" y="226" text-anchor="middle" fill="#fdd" font-size="8.5" font-family="sans-serif">OCR+YOLO+NLP</text>
<rect x="170" y="195" width="140" height="38" rx="4" fill="#8e44ad"/>
<text x="240" y="213" text-anchor="middle" fill="white" font-size="9.5" font-family="sans-serif" font-weight="bold">Deepfake</text>
<text x="240" y="226" text-anchor="middle" fill="#edd" font-size="8.5" font-family="sans-serif">MTCNN+EfficientNet</text>
<rect x="390" y="195" width="150" height="38" rx="4" fill="#16a085"/>
<text x="465" y="213" text-anchor="middle" fill="white" font-size="9.5" font-family="sans-serif" font-weight="bold">Customer Care</text>
<text x="465" y="226" text-anchor="middle" fill="#dfd" font-size="8.5" font-family="sans-serif">PaddleOCR+spaCy</text>
<rect x="545" y="195" width="140" height="38" rx="4" fill="#2980b9"/>
<text x="615" y="213" text-anchor="middle" fill="white" font-size="9.5" font-family="sans-serif" font-weight="bold">Investment</text>
<text x="615" y="226" text-anchor="middle" fill="#ddf" font-size="8.5" font-family="sans-serif">XGBoost+RoBERTa</text>
<line x1="95" y1="233" x2="198" y2="288" stroke="#333" stroke-width="1.2" marker-end="url(#arr)"/>
<line x1="240" y1="233" x2="278" y2="288" stroke="#333" stroke-width="1.2" marker-end="url(#arr)"/>
<line x1="465" y1="233" x2="422" y2="288" stroke="#333" stroke-width="1.2" marker-end="url(#arr)"/>
<line x1="615" y1="233" x2="502" y2="288" stroke="#333" stroke-width="1.2" marker-end="url(#arr)"/>
<rect x="198" y="288" width="300" height="34" rx="4" fill="#27ae60"/>
<text x="348" y="310" text-anchor="middle" fill="white" font-size="11" font-family="sans-serif" font-weight="bold">AI Verdict + Confidence Score</text>
<line x1="348" y1="322" x2="348" y2="342" stroke="#333" stroke-width="1.5" marker-end="url(#arr)"/>
<rect x="208" y="342" width="280" height="34" rx="4" fill="#c0392b"/>
<text x="348" y="364" text-anchor="middle" fill="white" font-size="11" font-family="sans-serif" font-weight="bold">CTI Report (PDF + HTML)</text>
<line x1="348" y1="376" x2="348" y2="393" stroke="#333" stroke-width="1.5" marker-end="url(#arr)"/>
<rect x="228" y="393" width="240" height="8" rx="2" fill="#2c3e50"/>
<text x="348" y="400" text-anchor="middle" fill="white" font-size="7.5" font-family="sans-serif">SOC Audit Log Registered</text>
</svg>'''

FLOW_BET = '''<svg viewBox="0 0 610 175" xmlns="http://www.w3.org/2000/svg" style="width:100%;max-width:590px">
<defs><marker id="a2" markerWidth="8" markerHeight="6" refX="7" refY="3" orient="auto"><polygon points="0 0, 8 3, 0 6" fill="#333"/></marker></defs>
<rect x="5" y="66" width="95" height="40" rx="4" fill="#3498db"/><text x="52" y="84" text-anchor="middle" fill="white" font-size="9" font-family="sans-serif">Upload Image</text><text x="52" y="97" text-anchor="middle" fill="#cef" font-size="8" font-family="sans-serif">Screenshot/Ad</text>
<line x1="100" y1="86" x2="118" y2="86" stroke="#333" stroke-width="1.5" marker-end="url(#a2)"/>
<rect x="118" y="66" width="95" height="40" rx="4" fill="#e67e22"/><text x="165" y="84" text-anchor="middle" fill="white" font-size="9" font-family="sans-serif">PaddleOCR</text><text x="165" y="97" text-anchor="middle" fill="#fed" font-size="8" font-family="sans-serif">Text Extraction</text>
<line x1="213" y1="86" x2="231" y2="86" stroke="#333" stroke-width="1.5" marker-end="url(#a2)"/>
<rect x="231" y="12" width="100" height="40" rx="4" fill="#9b59b6"/><text x="281" y="29" text-anchor="middle" fill="white" font-size="9" font-family="sans-serif">TF-IDF+Ridge</text><text x="281" y="42" text-anchor="middle" fill="#edf" font-size="8" font-family="sans-serif">NLP Classifier</text>
<rect x="231" y="120" width="100" height="40" rx="4" fill="#c0392b"/><text x="281" y="138" text-anchor="middle" fill="white" font-size="9" font-family="sans-serif">YOLOv8</text><text x="281" y="151" text-anchor="middle" fill="#fdd" font-size="8" font-family="sans-serif">Logo Detection</text>
<line x1="231" y1="86" x2="231" y2="32" stroke="#333" stroke-width="1.2" marker-end="url(#a2)"/>
<line x1="231" y1="86" x2="231" y2="140" stroke="#333" stroke-width="1.2" marker-end="url(#a2)"/>
<line x1="331" y1="32" x2="415" y2="77" stroke="#333" stroke-width="1.2" marker-end="url(#a2)"/>
<line x1="331" y1="140" x2="415" y2="95" stroke="#333" stroke-width="1.2" marker-end="url(#a2)"/>
<rect x="415" y="66" width="95" height="40" rx="4" fill="#27ae60"/><text x="462" y="83" text-anchor="middle" fill="white" font-size="9" font-family="sans-serif">Fusion Engine</text><text x="462" y="96" text-anchor="middle" fill="#dfd" font-size="8" font-family="sans-serif">0.6T + 0.4V</text>
<line x1="510" y1="86" x2="528" y2="86" stroke="#333" stroke-width="1.5" marker-end="url(#a2)"/>
<rect x="528" y="62" width="76" height="48" rx="24" fill="#1a1a2e"/><text x="566" y="82" text-anchor="middle" fill="white" font-size="9" font-family="sans-serif">VERDICT</text><text x="566" y="95" text-anchor="middle" fill="#c0392b" font-size="8" font-family="sans-serif" font-weight="bold">SAFE/BETTING</text>
</svg>'''

FLOW_DF = '''<svg viewBox="0 0 630 155" xmlns="http://www.w3.org/2000/svg" style="width:100%;max-width:600px">
<defs><marker id="a3" markerWidth="8" markerHeight="6" refX="7" refY="3" orient="auto"><polygon points="0 0, 8 3, 0 6" fill="#333"/></marker></defs>
<rect x="5" y="57" width="100" height="38" rx="4" fill="#8e44ad"/><text x="55" y="75" text-anchor="middle" fill="white" font-size="9" font-family="sans-serif">Upload Media</text><text x="55" y="87" text-anchor="middle" fill="#edd" font-size="8" font-family="sans-serif">Image / Video</text>
<line x1="105" y1="76" x2="120" y2="76" stroke="#333" stroke-width="1.5" marker-end="url(#a3)"/>
<rect x="120" y="36" width="110" height="38" rx="4" fill="#2c3e50"/><text x="175" y="53" text-anchor="middle" fill="white" font-size="9" font-family="sans-serif">OpenCV Sampling</text><text x="175" y="66" text-anchor="middle" fill="#cde" font-size="8" font-family="sans-serif">10 Frames (Video)</text>
<rect x="120" y="98" width="110" height="38" rx="4" fill="#16a085"/><text x="175" y="115" text-anchor="middle" fill="white" font-size="9" font-family="sans-serif">Direct Load</text><text x="175" y="128" text-anchor="middle" fill="#dfd" font-size="8" font-family="sans-serif">(Image)</text>
<line x1="105" y1="76" x2="120" y2="55" stroke="#333" stroke-width="1.2" marker-end="url(#a3)"/>
<line x1="105" y1="76" x2="120" y2="117" stroke="#333" stroke-width="1.2" marker-end="url(#a3)"/>
<line x1="230" y1="55" x2="262" y2="74" stroke="#333" stroke-width="1.2" marker-end="url(#a3)"/>
<line x1="230" y1="117" x2="262" y2="96" stroke="#333" stroke-width="1.2" marker-end="url(#a3)"/>
<rect x="262" y="57" width="110" height="38" rx="4" fill="#e74c3c"/><text x="317" y="75" text-anchor="middle" fill="white" font-size="9" font-family="sans-serif">MTCNN</text><text x="317" y="88" text-anchor="middle" fill="#fdd" font-size="8" font-family="sans-serif">Face Crop 224x224</text>
<line x1="372" y1="76" x2="390" y2="76" stroke="#333" stroke-width="1.5" marker-end="url(#a3)"/>
<rect x="390" y="57" width="120" height="38" rx="4" fill="#2980b9"/><text x="450" y="75" text-anchor="middle" fill="white" font-size="9" font-family="sans-serif">EfficientNet-B4</text><text x="450" y="88" text-anchor="middle" fill="#ddf" font-size="8" font-family="sans-serif">Real vs. Fake</text>
<line x1="510" y1="76" x2="528" y2="76" stroke="#333" stroke-width="1.5" marker-end="url(#a3)"/>
<rect x="528" y="52" width="92" height="48" rx="24" fill="#1a1a2e"/><text x="574" y="72" text-anchor="middle" fill="white" font-size="9" font-family="sans-serif">VERDICT</text><text x="574" y="85" text-anchor="middle" fill="#e74c3c" font-size="8" font-family="sans-serif" font-weight="bold">REAL/FAKE</text>
</svg>'''

out_sections = []

# HEAD
out_sections.append(f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1.0"/>
<title>CYBERSURAKSHAA - Project Report | GPCSSI 2025</title>
<style>{CSS}</style>
</head>
<body>
<button class="pb no-print" onclick="window.print()">&#128424; Print / Save as PDF</button>''')

# COVER
out_sections.append(f'''
<div class="rp"><div class="cover">
<div class="corg">GURUGRAM POLICE</div>
<div class="cevt">CYBER SECURITY SUMMER INTERNSHIP</div>
<div class="cyr">(GPCSSI) 2025</div>
<img src="data:image/png;base64,{logo}" class="clogo" alt="Logo"/>
<div class="ctit">CYBERSURAKSHAA &mdash; National Threat Detection Suite<br/>(AI-Powered Cyber Threat Intelligence Platform)</div>
<table class="ctbl"><tr>
<td style="text-align:left;width:50%"><strong>Submitted by:</strong><br/>Name: <br/>GPCSSI ID: &nbsp;</td>
<td style="text-align:left;width:50%"><strong>Submitted To:</strong><br/>Dr. Rakshit Tandon<br/>(Mentor GPCSSI)</td>
</tr></table>
</div></div>''')

# TOC
toc_items = [
    ("1. Introduction", "3"), ("2. Objective of the Project", "4"),
    ("3. Tools and Technology Used", "5"), ("4. System Workflow (Flowchart)", "6"),
    ("5. Case Examples &mdash; Module Outputs", "8"), ("6. Proof of Work &amp; Proof of Concept", "10"),
    ("7. Output &mdash; PDF &amp; HTML Reports", "11"), ("8. Security Measures &amp; Limitations", "12"),
    ("9. Future Scope", "13"),
]
toc_html = ''.join(f'<div class="tc"><span>{t}</span><span>{p}</span></div>' for t, p in toc_items)
out_sections.append(f'<div class="rp page-break"><h1 class="st">Table of Contents</h1><div style="margin-top:20px">{toc_html}</div></div>')

# S1: INTRODUCTION
out_sections.append('''<div class="rp page-break">
<h1 class="st"><span class="sn">1</span> Introduction</h1>
<hr class="hr"/>
<p>India's rapidly growing internet user base of over 900 million active users has led to an alarming surge in cybercrime &mdash; from illegal betting advertisements on social media to AI-generated deepfake videos used for blackmail, and fraudulent customer care scams targeting everyday citizens. The Gurugram Cyber Crime Wing alone registers thousands of such complaints annually, highlighting the urgent need for intelligent, automated threat detection systems capable of supporting law enforcement at scale.</p>
<p><strong>CYBERSURAKSHAA &mdash; National Threat Detection Suite</strong> is an AI-powered Cyber Threat Intelligence (CTI) platform developed during the GPCSSI 2025 internship programme. It unifies four specialized detection engines &mdash; Illegal Betting Content, AI Deepfake Manipulation, Fake Customer Care Scams, and Financial Investment Fraud &mdash; under a single secure, government-grade web interface. Each engine uses a multi-modal intelligence approach combining OCR, Natural Language Processing, Computer Vision (YOLOv8), and deep learning (EfficientNet-B4) to deliver high-confidence threat verdicts backed by exportable forensic reports.</p>
<p>The platform incorporates Role-Based Access Control (RBAC), a live Security Operations Center (SOC) dashboard for real-time incident management, and professional PDF/HTML Cyber Threat Intelligence report generation with SHA-256 file integrity hashing. With its tricolor national gateway and India-specific threat taxonomy, CYBERSURAKSHAA is designed to be a next-generation national cyber defense tool &mdash; made in India, for the safety of every Indian citizen.</p>
</div>''')

# S2: OBJECTIVES
out_sections.append('''<div class="rp page-break">
<h1 class="st"><span class="sn">2</span> Objective of the Project</h1>
<hr class="hr"/>
<p>The primary goal of CYBERSURAKSHAA is to equip Indian law enforcement and cybersecurity analysts with an integrated AI-driven threat detection platform covering four major cybercrime domains:</p>
<h2 class="sb">2.1 Core Detection Objectives</h2>
<ul>
<li><strong>Illegal Betting Detection:</strong> Analyze social media images using OCR + NLP + YOLOv8 to automatically identify illegal online gambling promotions.</li>
<li><strong>Deepfake Identification:</strong> Determine whether digital media has been AI-manipulated using MTCNN face cropping and EfficientNet-B4 frame-level classification.</li>
<li><strong>Fake Customer Care Detection:</strong> Identify fraudulent helpdesk numbers impersonating Indian banks and services by cross-referencing against official contact registries and threat blacklists.</li>
<li><strong>Investment Fraud Analysis:</strong> Evaluate Ponzi schemes and crypto-fraud messages using dual NLP engines (XGBoost + XLM-RoBERTa) and domain WHOIS age checks.</li>
</ul>
<h2 class="sb">2.2 Platform Objectives</h2>
<ul>
<li><strong>Forensic Report Generation:</strong> Auto-compile scan results into PDF and HTML CTI reports with SHA-256 hashes, timestamps, and investigator signatures suitable as digital evidence.</li>
<li><strong>Live SOC Dashboard:</strong> Centralized real-time audit log with incident management controls (Flagged / Under Review / Safe).</li>
<li><strong>Role-Based Access Control:</strong> Admin and Analyst roles with tiered permissions for secure, accountable usage.</li>
<li><strong>Modular Architecture:</strong> Blueprint-based Flask design allowing independent addition of new detection modules.</li>
</ul>
<h2 class="sb">2.3 Social Impact</h2>
<p>To provide Haryana Police's cyber crime wing with a practical open-source intelligence tool that reduces manual investigation time, accelerates evidence collection, and contributes to India's national cyber safety infrastructure &mdash; particularly protecting vulnerable populations from online financial fraud and digital exploitation.</p>
</div>''')

# S3: TOOLS
out_sections.append('''<div class="rp page-break">
<h1 class="st"><span class="sn">3</span> Tools and Technology Used</h1>
<hr class="hr"/>
<h2 class="sb">3.1 Core Framework</h2>
<table class="dt avoid-break">
<tr><th>Tool / Library</th><th>Version</th><th>Purpose</th></tr>
<tr><td><strong>Python</strong></td><td>3.10+</td><td>Primary programming language for all backend services and ML pipelines.</td></tr>
<tr><td><strong>Flask</strong></td><td>3.0+</td><td>WSGI web framework &mdash; routing, blueprint architecture, session management.</td></tr>
<tr><td><strong>SQLite3</strong></td><td>Built-in</td><td>Database for user accounts, scan logs, official contacts, and threat blacklists.</td></tr>
<tr><td><strong>Jinja2</strong></td><td>3.x</td><td>HTML templating engine for dynamic page rendering.</td></tr>
</table>
<h2 class="sb">3.2 Machine Learning &amp; Computer Vision</h2>
<table class="dt avoid-break">
<tr><th>Tool / Library</th><th>Purpose</th></tr>
<tr><td><strong>YOLOv8</strong> (Ultralytics)</td><td>Real-time logo detection for identifying betting platform logos in images.</td></tr>
<tr><td><strong>PaddleOCR</strong></td><td>Optical Character Recognition &mdash; extracts text from uploaded screenshots and banners.</td></tr>
<tr><td><strong>EfficientNet-B4</strong> (timm + PyTorch)</td><td>Deep CNN for deepfake detection &mdash; outputs real vs. fake probability per video frame.</td></tr>
<tr><td><strong>MTCNN</strong> (facenet-pytorch)</td><td>Multi-task Cascaded CNN for face detection and 224x224 crop in images/video.</td></tr>
<tr><td><strong>XGBoost + TF-IDF</strong></td><td>Investment scam classifier (Engine A) using gradient boosting on TF-IDF features.</td></tr>
<tr><td><strong>XLM-RoBERTa</strong></td><td>Multilingual transformer (Engine B) for cross-lingual investment scam detection.</td></tr>
<tr><td><strong>spaCy NER</strong></td><td>Named Entity Recognition for extracting phone numbers and brand names.</td></tr>
<tr><td><strong>scikit-learn</strong></td><td>TF-IDF + Ridge Classifier pipeline for betting keyword scoring.</td></tr>
<tr><td><strong>OpenCV (cv2)</strong></td><td>Video frame sampling and image preprocessing for deepfake analysis.</td></tr>
</table>
<h2 class="sb">3.3 Security &amp; Reporting</h2>
<table class="dt avoid-break">
<tr><th>Tool / Library</th><th>Purpose</th></tr>
<tr><td><strong>ReportLab</strong></td><td>PDF CTI report generation with stamps, SHA-256 hashes, and risk scorecards.</td></tr>
<tr><td><strong>Werkzeug</strong></td><td>Secure file handling and password hashing (pbkdf2:sha256).</td></tr>
<tr><td><strong>python-whois</strong></td><td>Domain WHOIS lookup &mdash; checks domain registration age for investment scam analysis.</td></tr>
<tr><td><strong>hashlib (SHA-256)</strong></td><td>Cryptographic fingerprinting of every uploaded file for forensic integrity.</td></tr>
<tr><td><strong>secrets</strong></td><td>Cryptographically secure session key generation for Flask.</td></tr>
</table>
<h2 class="sb">3.4 Development Environment</h2>
<table class="dt avoid-break">
<tr><th>Tool</th><th>Purpose</th></tr>
<tr><td>Visual Studio Code</td><td>Primary IDE with Python, Pylance extensions and integrated Git terminal.</td></tr>
<tr><td>Git / GitHub</td><td>Version control (github.com/DanishDhanjal15/CYBERSURAKSHAA).</td></tr>
<tr><td>Windows 11 + PowerShell</td><td>Development and testing operating system.</td></tr>
<tr><td>Google Chrome</td><td>UI testing and CTI HTML report rendering verification.</td></tr>
</table>
</div>''')

# S4: FLOWCHARTS
out_sections.append(f'''<div class="rp page-break">
<h1 class="st"><span class="sn">4</span> System Workflow</h1>
<hr class="hr"/>
<h2 class="sb">4.1 Overall System Architecture</h2>
<div class="fc avoid-break">{FLOW_MAIN}<p class="ic">Figure 4.1 &mdash; CYBERSURAKSHAA Master System Workflow</p></div>
<h2 class="sb">4.2 Betting Content Detector Pipeline</h2>
<div class="fc avoid-break">{FLOW_BET}<p class="ic">Figure 4.2 &mdash; Betting Detector Pipeline (OCR + YOLO + NLP + Fusion)</p></div>
<h2 class="sb">4.3 Deepfake Detection Pipeline</h2>
<div class="fc avoid-break">{FLOW_DF}<p class="ic">Figure 4.3 &mdash; Deepfake Detection Pipeline (MTCNN + EfficientNet-B4)</p></div>
<h2 class="sb">4.4 Fusion Score Formula</h2>
<div class="fm">Final Score = (Text Probability x 0.6) + (Vision Probability x 0.4)</div>
<p>If a betting logo is detected with confidence &gt;80%, the final classification is automatically elevated to <strong>BETTING</strong>, ensuring high-confidence visual evidence is never overridden by text scores alone.</p>
</div>''')

# S5: CASE EXAMPLES (first 2)
out_sections.append(f'''<div class="rp page-break">
<h1 class="st"><span class="sn">5</span> Case Examples &mdash; Module Outputs</h1>
<hr class="hr"/>
<p>The following section demonstrates each detection module with real outputs generated by the live CYBERSURAKSHAA system.</p>
<h2 class="sb">5.1 Case 1 &mdash; Illegal Betting Content Detector</h2>
<div class="mc avoid-break">
<h3>&#127922; Module: Betting Content Detector</h3>
<p><strong>Input:</strong> A social media cricket betting advertisement &mdash; &quot;PLAY NOW &amp; WIN BIG, INSTANT PAYTM&quot; with a WhatsApp contact number.</p>
<p><strong>AI Verdict:</strong> <span class="badge">BETTING DETECTED</span> &nbsp; <strong>Confidence: 89%</strong></p>
<ul>
<li>Text Classifier detected keywords: <em>bet, betting</em></li>
<li>YOLO Vision: Betting platform logo identified in banner</li>
<li>Fusion Score: (87% x 0.6) + (92% x 0.4) = <strong>89%</strong></li>
</ul>
</div>
{img(betting, "Betting Detector Output")}
<p class="ic">Figure 5.1 &mdash; Betting Content Detector: 89% Confidence &mdash; BETTING DETECTED</p>
<h2 class="sb">5.2 Case 2 &mdash; Deepfake Video Detector</h2>
<div class="mc avoid-break">
<h3>&#128249; Module: Deepfake Face &amp; Video Detector</h3>
<p><strong>Input:</strong> A 10-second video showing a person walking in a corridor &mdash; suspected AI face-swap manipulation.</p>
<p><strong>AI Verdict:</strong> <span class="badge">FAKE &mdash; MANIPULATED</span> &nbsp; <strong>Confidence: 96%</strong></p>
<ul>
<li>MTCNN detected facial regions across 10 sampled frames</li>
<li>EfficientNet-B4 average fake probability: <strong>96.4%</strong></li>
<li>Avg Score (0.964) &gt; Threshold (0.50) &rarr; FAKE</li>
</ul>
</div>
{img(deepfake, "Deepfake Detector Output")}
<p class="ic">Figure 5.2 &mdash; Deepfake Detector: 96% Score &mdash; MANIPULATED / FAKE</p>
</div>''')

# S5 continued (cases 3 & 4)
out_sections.append(f'''<div class="rp page-break">
<h2 class="sb">5.3 Case 3 &mdash; Fake Customer Care Scam Detector</h2>
<div class="mc avoid-break">
<h3>&#128222; Module: Fake Customer Care Scam Detector</h3>
<p><strong>Input:</strong> An advertisement claiming to be &quot;Paytm Customer Care&quot; with number +91 81247 96305 &mdash; a fraudulent helpdesk number.</p>
<p><strong>AI Verdict:</strong> <span class="badge">SCAM DETECTED</span> &nbsp; <strong>Risk Score: 92%</strong></p>
<ul>
<li>Extracted number does not match Paytm's verified official contacts</li>
<li>Number flagged in Threat Intelligence blacklist database</li>
<li>Urgency Index: HIGH &mdash; Coercion Rating: HIGH</li>
<li>Telecom Trust: 12% (Flagged VoIP number)</li>
</ul>
</div>
{img(customer, "Customer Care Scam Detector Output")}
<p class="ic">Figure 5.3 &mdash; Fake Customer Care Detector: SCAM DETECTED Verdict</p>
<h2 class="sb">5.4 Case 4 &mdash; Investment Scam Detector (ScamGuard AI)</h2>
<div class="mc avoid-break">
<h3>&#128200; Module: Investment Scam Detector</h3>
<p><strong>Input:</strong> Message with guaranteed high-yield crypto investment promises and a newly registered suspicious domain link.</p>
<p><strong>AI Verdict:</strong> <span class="badge">HIGH RISK &mdash; FINANCIAL FRAUD</span> &nbsp; <strong>Fraud Score: 97/100</strong></p>
<ul>
<li>WHOIS: Domain registered &lt;30 days ago &mdash; HIGH RISK indicator</li>
<li>Engine A (XGBoost): Keywords matched &mdash; <em>guaranteed return, double money, risk-free</em></li>
<li>Final Fraud Score: <strong>97/100</strong> &rarr; Traffic Light: &#128308; RED</li>
</ul>
</div>
{img(invest, "Investment Scam Detector Output")}
<p class="ic">Figure 5.4 &mdash; Investment Scam Detector: 97/100 Fraud Score &mdash; HIGH RISK <em>(Screenshot to be updated with result output)</em></p>
</div>''')

# S6: PROOF OF WORK
out_sections.append(f'''<div class="rp page-break">
<h1 class="st"><span class="sn">6</span> Proof of Work &amp; Proof of Concept</h1>
<hr class="hr"/>
<p>This section presents the core application architecture and key source code demonstrating the technical depth and originality of the CYBERSURAKSHAA project.</p>
<h2 class="sb">6.1 Application Entry Point &mdash; app.py</h2>
<div class="cb">{APP_CODE}</div>
<h2 class="sb">6.2 Live SOC Dashboard</h2>
{img(hub, "SOC Dashboard")}
<p class="ic">Figure 6.1 &mdash; CYBERSURAKSHAA SOC Dashboard: Real-time threat monitoring, crawler feed, and incident log</p>
</div>''')

# S7: OUTPUT
out_sections.append('''<div class="rp page-break">
<h1 class="st"><span class="sn">7</span> Output &mdash; PDF &amp; HTML Reports</h1>
<hr class="hr"/>
<p>After completing any scan, analysts can export a full <strong>Cyber Threat Intelligence (CTI) Report</strong> in two formats.</p>
<h2 class="sb">7.1 PDF Report Features</h2>
<div class="ib avoid-break"><ul>
<li><strong>Official CYBERSURAKSHAA header</strong> with Indian tricolor branding and national emblem</li>
<li><strong>Scan Metadata:</strong> Module name, filename, timestamp, SHA-256 file hash</li>
<li><strong>Extracted Indicators:</strong> Phone numbers, betting keywords, deepfake frame scores</li>
<li><strong>Risk Score Card</strong> with severity level (HIGH / MEDIUM / LOW)</li>
<li><strong>Vector Stamp Overlays:</strong> "VERIFIED SCAM", "ILLEGAL BETTING", "MANIPULATED / FAKE", "FINANCIAL FRAUD"</li>
<li><strong>Investigator Signature Block</strong> naming the analyst who ran the scan</li>
<li><strong>Official Recommendation Text</strong> with legal advisory and follow-up action items</li>
</ul></div>
<h2 class="sb">7.2 HTML Report Features</h2>
<div class="ib avoid-break"><ul>
<li>Responsive standalone HTML &mdash; no external dependencies, opens in any browser</li>
<li>Embedded annotated target media (base64 encoded) &mdash; directly viewable</li>
<li>Visual CSS stamp design (diagonal red threat classification stamp)</li>
<li>Color-coded risk score section with confidence percentages</li>
<li>Shareable as a single .html file &mdash; ideal for inter-agency digital evidence sharing</li>
</ul></div>
<h2 class="sb">7.3 Incident Status Controls (SOC Dashboard)</h2>
<ul>
<li><span class="badge">&#128680; FLAGGED FOR TAKEDOWN</span> &mdash; High-confidence threats requiring immediate action</li>
<li><span class="badge bo">&#9888;&#65039; UNDER REVIEW</span> &mdash; Moderate-risk cases requiring analyst verification</li>
<li><span class="badge bg">&#9989; SAFE</span> &mdash; Content cleared by the AI detection system</li>
</ul>
</div>''')

# S8: SECURITY & LIMITATIONS
out_sections.append('''<div class="rp page-break">
<h1 class="st"><span class="sn">8</span> Security Measures &amp; Limitations</h1>
<hr class="hr"/>
<h2 class="sb">8.1 Security Measures</h2>
<ul>
<li><strong>Role-Based Access Control (RBAC):</strong> Admin and Analyst roles with distinct access permissions; all admin routes protected with session validation and role checks.</li>
<li><strong>Password Hashing:</strong> Werkzeug <code>pbkdf2:sha256</code> with auto-salting &mdash; passwords never stored in plain text.</li>
<li><strong>Secure Sessions:</strong> Flask session key generated via <code>secrets.token_hex(24)</code> &mdash; prevents session hijacking.</li>
<li><strong>SHA-256 File Hashing:</strong> Every uploaded file receives a cryptographic fingerprint ensuring tamper-evident forensic chain-of-custody.</li>
<li><strong>File Size Limit:</strong> 500MB upload cap prevents denial-of-service attacks via large file submissions.</li>
<li><strong>Audit Logging:</strong> Every scan recorded in SQLite with timestamp, user ID, module, and verdict &mdash; full non-repudiable audit trail.</li>
<li><strong>Ethical Use Only:</strong> Designed for authorized law enforcement personnel. No real-time surveillance &mdash; operates only on explicitly submitted evidence.</li>
</ul>
<h2 class="sb">8.2 Current Limitations</h2>
<div class="wb avoid-break"><ul>
<li><strong>YOLO Logo Scope:</strong> Trained on a limited dataset of known betting logos &mdash; new regional platforms will only be caught by text classification.</li>
<li><strong>Face Detection Dependency:</strong> Deepfake analysis requires a detectable face &mdash; videos without faces produce inconclusive results.</li>
<li><strong>Transformer Offline Mode:</strong> XLM-RoBERTa may fall back to XGBoost on machines without GPU, reducing multilingual analysis capability.</li>
<li><strong>No Premium Threat Feeds:</strong> Uses local SQLite blacklist &mdash; no Chainalysis, PhishTank Pro, or TrueCaller Business API integration.</li>
<li><strong>No Audio Deepfake:</strong> Only visual deepfakes detected; AI voice cloning is not yet supported.</li>
<li><strong>Regional Language OCR:</strong> PaddleOCR accuracy may be reduced for some regional Indian scripts.</li>
</ul></div>
</div>''')

# S9: FUTURE SCOPE
out_sections.append('''<div class="rp page-break">
<h1 class="st"><span class="sn">9</span> Future Scope</h1>
<hr class="hr"/>
<p>CYBERSURAKSHAA lays the foundation for a comprehensive national cyber threat intelligence ecosystem. The following roadmap outlines high-impact enhancements:</p>
<ul>
<li style="margin-bottom:9px"><strong>&#127897;&#65039; Audio Deepfake Detection:</strong> Integrate spectrogram-based CNN classifiers to detect AI-synthesized voice cloning &mdash; creating a fully multimodal forensics capability combining sight, sound, and text analysis.</li>
<li style="margin-bottom:9px"><strong>&#128225; Real-Time Social Media Integration:</strong> Connect to Meta Graph API, Twitter/X API, and Telegram Bot API for automated ingestion and analysis of flagged posts &mdash; eliminating manual screenshot uploads.</li>
<li style="margin-bottom:9px"><strong>Blockchain &amp; Cryptocurrency Fraud Tracing:</strong> Integrate Etherscan/BscScan APIs to trace scam wallet transactions &mdash; enabling asset freezing under India's IT Act and PMLA provisions.</li>
<li style="margin-bottom:9px"><strong>&#127760; National Threat Intelligence Sharing:</strong> Evolve into a federated hub connecting Haryana Police, CERT-In, and state cybercrime units using STIX/TAXII standard for sharing anonymized IOCs nationally.</li>
<li style="margin-bottom:9px"><strong>&#128241; Mobile Application:</strong> Companion Android/iOS app with TensorFlow Lite offline models enabling field officers to capture and analyze suspicious content on-the-spot.</li>
<li style="margin-bottom:9px"><strong>&#128483;&#65039; Regional Language NLP:</strong> Fine-tune IndicBERT and MuRIL transformers on India-specific cybercrime datasets to detect scams across all 22 scheduled Indian languages.</li>
<li style="margin-bottom:9px"><strong>&#128373;&#65039; OSINT &amp; Dark Web Monitoring:</strong> Monitor dark web marketplaces for compromised Indian citizen data, scam kits, and leaked credentials &mdash; triggering pre-emptive alerts before fraud campaigns launch.</li>
<li style="margin-bottom:9px"><strong>&#9729;&#65039; NIC / MeitY Cloud Deployment:</strong> Deploy as official government SaaS on NIC infrastructure integrated into cybercrime.gov.in &mdash; making AI threat detection available to all 28 state cybercrime wings simultaneously.</li>
</ul>
<div class="ib avoid-break"><strong>&#127919; Vision:</strong> CYBERSURAKSHAA aspires to become India's first indigenous, open-source AI-powered national cyber threat intelligence platform &mdash; a digital Kavach (shield) built by Indian developers, for Indian citizens, protecting the nation's digital sovereignty one scan at a time.</div>
<hr class="hr" style="margin-top:40px"/>
<div style="text-align:center;margin-top:20px">
<p><strong>&mdash; End of Project Report &mdash;</strong></p><br/>
<p>Submitted To: <strong>Dr. Rakshit Tandon</strong> (Mentor GPCSSI)</p>
<p>Programme: <strong>Gurugram Police Cyber Security Summer Internship (GPCSSI) 2025</strong></p><br/>
<p style="font-size:10pt;color:#555">Project: CYBERSURAKSHAA &mdash; National Threat Detection Suite<br/>GitHub: github.com/DanishDhanjal15/CYBERSURAKSHAA</p>
</div>
</div>
</body></html>''')

out_html = ''.join(out_sections)
out_path = r'c:\Users\Danish\OneDrive\Desktop\All in one\project_report.html'
with open(out_path, 'w', encoding='utf-8') as f:
    f.write(out_html)
print(f'Report written: {len(out_html):,} chars to {out_path}')
