import os
import io
import json
import shutil
from datetime import datetime
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, KeepTogether
from reportlab.platypus import Image as RLImage
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.graphics.shapes import Drawing, Circle, Rect, Group, Line, String

def save_scanned_media(file_hash, file_bytes=None, file_path=None):
    """
    Saves a copy of the scanned image/media to static/uploads/scans/
    permanently for CTI report embedding.
    """
    scans_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'static', 'uploads', 'scans')
    os.makedirs(scans_dir, exist_ok=True)
    
    target_path = os.path.join(scans_dir, f"{file_hash}.png")
    if os.path.exists(target_path):
        return target_path
        
    try:
        if file_bytes:
            with open(target_path, 'wb') as f:
                f.write(file_bytes)
        elif file_path and os.path.exists(file_path):
            shutil.copy(file_path, target_path)
    except Exception as e:
        print(f"[REPORT GEN] Failed to save copy of scanned media: {e}")
        
    return target_path

def draw_flag_logo(width, height):
    """Draws a circular emblem with the Indian tricolor and blue wheel."""
    d = Drawing(width, height)
    cx = width / 2
    cy = height / 2
    r = min(width, height) / 2
    
    # Outer dark navy circular boundary
    d.add(Circle(cx, cy, r, fillColor=colors.HexColor('#0B172A'), strokeColor=colors.HexColor('#F5B301'), strokeWidth=1))
    
    # Tricolor bands inside
    bw = r * 1.3
    bh = r * 0.22
    
    # Saffron
    d.add(Rect(cx - bw/2, cy + bh/2, bw, bh, fillColor=colors.HexColor('#FF9933'), strokeColor=None))
    # White
    d.add(Rect(cx - bw/2, cy - bh/2, bw, bh, fillColor=colors.HexColor('#FFFFFF'), strokeColor=None))
    # Green
    d.add(Rect(cx - bw/2, cy - bh*1.5, bw, bh, fillColor=colors.HexColor('#138808'), strokeColor=None))
    
    # Blue wheel (Ashoka Chakra)
    d.add(Circle(cx, cy, bh/2, fillColor=None, strokeColor=colors.HexColor('#06038D'), strokeWidth=0.8))
    # Draw simple spoke lines
    for i in range(12):
        from math import sin, cos, radians
        angle = radians(i * 30)
        x2 = cx + (bh/2) * cos(angle)
        y2 = cy + (bh/2) * sin(angle)
        d.add(Line(cx, cy, x2, y2, strokeColor=colors.HexColor('#06038D'), strokeWidth=0.5))
        
    return d

def draw_official_stamp(text, state_class, width=140, height=46):
    """Draws a rotated, double-bordered rubber-stamp graphic in the PDF."""
    d = Drawing(width, height)
    g = Group()
    g.translate(width/2, height/2)
    g.rotate(-6)
    
    # Determine color
    if state_class == 'danger':
        color = colors.HexColor('#B91C1C')
    elif state_class == 'warning':
        color = colors.HexColor('#D97706')
    else:
        color = colors.HexColor('#166534')
        
    # Double border stamp
    g.add(Rect(-width/2 + 3, -height/2 + 3, width - 6, height - 6, 
               fillColor=None, strokeColor=color, strokeWidth=2.2, rx=4, ry=4))
    g.add(Rect(-width/2 + 6, -height/2 + 6, width - 12, height - 12, 
               fillColor=None, strokeColor=color, strokeWidth=0.8, rx=2, ry=2))
    
    # Text strings
    g.add(String(0, 3, text, textAnchor='middle', fontName='Helvetica-Bold', fontSize=10, fillColor=color))
    g.add(String(0, -9, "CYBERSURAKSHAA CTI", textAnchor='middle', fontName='Helvetica-Bold', fontSize=5.5, fillColor=color))
    g.add(String(0, -17, "OFFICIAL VERIFICATION", textAnchor='middle', fontName='Helvetica', fontSize=4.5, fillColor=color))
    
    d.add(g)
    return d

def draw_page_decorations(canvas, doc):
    """Draws the top tricolor border and bottom footer on each PDF page."""
    canvas.saveState()
    page_width, page_height = doc.pagesize
    
    # Draw top tricolor strip
    strip_height = 6
    canvas.setFillColor(colors.HexColor('#FF9933'))
    canvas.rect(0, page_height - strip_height, page_width / 3, strip_height, fill=1, stroke=0)
    canvas.setFillColor(colors.HexColor('#FFFFFF'))
    canvas.rect(page_width / 3, page_height - strip_height, page_width / 3, strip_height, fill=1, stroke=0)
    canvas.setFillColor(colors.HexColor('#138808'))
    canvas.rect(2 * page_width / 3, page_height - strip_height, page_width / 3, strip_height, fill=1, stroke=0)
    
    # Draw bottom footer line
    canvas.setStrokeColor(colors.HexColor('#E5E7EB'))
    canvas.setLineWidth(1)
    canvas.line(36, 45, page_width - 36, 45)
    
    # Draw footer text
    canvas.setFont('Helvetica', 8)
    canvas.setFillColor(colors.HexColor('#6B7280'))
    canvas.drawString(36, 30, "CYBERSURAKSHAA CTI THREAT REPORT — NATIONAL SECURITY GATEWAY")
    canvas.drawRightString(page_width - 36, 30, "Page 1 — STRICTLY RESTRICTED ACCESS")
    canvas.restoreState()

def generate_pdf_report(scan):
    """
    Compiles a beautifully styled official PDF threat report using ReportLab.
    Returns bytes of the compiled PDF document.
    """
    buffer = io.BytesIO()
    
    # Setup document: Margins at 36pt (0.5 inch), Letter size
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        leftMargin=36,
        rightMargin=36,
        topMargin=54,
        bottomMargin=54
    )
    
    styles = getSampleStyleSheet()
    
    # Custom typography styling
    style_title_main = ParagraphStyle(
        'DocTitleMain',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=20,
        leading=24,
        textColor=colors.HexColor('#0B172A'),
        spaceAfter=2
    )
    
    style_title_sub = ParagraphStyle(
        'DocTitleSub',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=10,
        leading=12,
        textColor=colors.HexColor('#F5B301'),
        spaceAfter=4
    )
    
    style_desc = ParagraphStyle(
        'DocDesc',
        parent=styles['Normal'],
        fontName='Helvetica-Oblique',
        fontSize=8,
        leading=10,
        textColor=colors.HexColor('#4B5563')
    )
    
    style_section_title = ParagraphStyle(
        'SectionTitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=11,
        leading=13,
        textColor=colors.HexColor('#0B172A'),
        spaceBefore=10,
        spaceAfter=6,
        keepWithNext=True
    )
    
    style_body = ParagraphStyle(
        'Body',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9,
        leading=13,
        textColor=colors.HexColor('#1F2937')
    )
    
    style_body_bold = ParagraphStyle(
        'BodyBold',
        parent=style_body,
        fontName='Helvetica-Bold'
    )
    
    style_reasons_bullet = ParagraphStyle(
        'ReasonsBullet',
        parent=style_body,
        leftIndent=15,
        firstLineIndent=-10,
        spaceAfter=2
    )
    
    style_text_evidence = ParagraphStyle(
        'TextEvidence',
        parent=styles['Normal'],
        fontName='Courier',
        fontSize=8,
        leading=10.5,
        textColor=colors.HexColor('#374151'),
        backColor=colors.HexColor('#F3F4F6'),
        borderColor=colors.HexColor('#E5E7EB'),
        borderWidth=0.5,
        borderPadding=6,
        spaceAfter=2
    )

    story = []
    
    # ── Header Section (Logo + Titles) ──
    logo = draw_flag_logo(54, 54)
    
    header_text_cell = [
        Paragraph("CYBERSURAKSHAA", style_title_main),
        Paragraph("NATIONAL THREAT DETECTION SUITE", style_title_sub),
        Paragraph("AI-Powered Threat Intelligence Platform for Detection, Investigation, and Analysis of Fraudulent Digital Content", style_desc)
    ]
    
    header_table = Table([[logo, header_text_cell]], colWidths=[65, 475])
    header_table.setStyle(TableStyle([
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('ALIGN', (0,0), (0,0), 'CENTER'),
        ('LEFTPADDING', (1,0), (1,0), 6),
        ('BOTTOMPADDING', (0,0), (-1,-1), 8),
    ]))
    story.append(header_table)
    
    # Gold separator line
    sep_table = Table([[""]], colWidths=[540], rowHeights=[2])
    sep_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#F5B301')),
        ('TOPPADDING', (0,0), (-1,-1), 0),
        ('BOTTOMPADDING', (0,0), (-1,-1), 0),
    ]))
    story.append(sep_table)
    story.append(Spacer(1, 10))
    
    # Document Title
    style_doc_header = ParagraphStyle(
        'DocHeader',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=12,
        leading=15,
        alignment=1, # Center
        textColor=colors.HexColor('#0B172A'),
        spaceAfter=10
    )
    story.append(Paragraph("OFFICIAL CYBER THREAT INTELLIGENCE REPORT", style_doc_header))
    
    # ── Metadata Section ──
    scan_id = scan.get('id', 0)
    ref_id = f"CS-CTI-2026-{scan_id:04d}"
    timestamp = scan.get('timestamp', datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    module = scan.get('module', 'Unknown Module')
    input_sum = scan.get('input_summary', 'N/A')
    if len(input_sum) > 80:
        input_sum = input_sum[:77] + "..."
    file_hash = scan.get('file_hash', 'N/A')
    analyst = scan.get('username', 'system')
    
    metadata_data = [
        [Paragraph("Report Reference:", style_body_bold), Paragraph(ref_id, style_body),
         Paragraph("Scan Date/Time:", style_body_bold), Paragraph(timestamp, style_body)],
        [Paragraph("Detection Engine:", style_body_bold), Paragraph(module, style_body),
         Paragraph("Investigator Account:", style_body_bold), Paragraph(analyst, style_body)],
        [Paragraph("Target Title:", style_body_bold), Paragraph(input_sum, style_body),
         Paragraph("SHA-256 Hash:", style_body_bold), Paragraph(file_hash, style_body)]
    ]
    
    metadata_table = Table(metadata_data, colWidths=[105, 165, 110, 160])
    metadata_table.setStyle(TableStyle([
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#E5E7EB')),
        ('BACKGROUND', (0,0), (0,-1), colors.HexColor('#FAFAFA')),
        ('BACKGROUND', (2,0), (2,-1), colors.HexColor('#FAFAFA')),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('TOPPADDING', (0,0), (-1,-1), 5),
        ('BOTTOMPADDING', (0,0), (-1,-1), 5),
        ('LEFTPADDING', (0,0), (-1,-1), 8),
        ('RIGHTPADDING', (0,0), (-1,-1), 8),
    ]))
    story.append(metadata_table)
    story.append(Spacer(1, 10))
    
    # ── Verdict & Risk Banner ──
    verdict = scan.get('verdict', 'UNKNOWN')
    score = scan.get('score', 0)
    verdict_upper = verdict.upper()
    
    # Determine color theme based on severity
    if any(k in verdict_upper for k in ('BETTING', 'FAKE', 'SCAM', 'DANGER', 'RED', 'CRITICAL', 'HIGH')):
        state_class = 'danger'
        bg_color = colors.HexColor('#FEE2E2') # red
        text_color = colors.HexColor('#991B1B')
        border_color = colors.HexColor('#F87171')
        verdict_icon = "🚨 CRITICAL THREAT DETECTED"
    elif any(k in verdict_upper for k in ('SUSPICIOUS', 'WARN', 'YELLOW')):
        state_class = 'warning'
        bg_color = colors.HexColor('#FEF9C3') # yellow
        text_color = colors.HexColor('#854D0E')
        border_color = colors.HexColor('#FACC15')
        verdict_icon = "⚠️ WARNING — SUSPICIOUS SIGNAL"
    else:
        state_class = 'safe'
        bg_color = colors.HexColor('#DCFCE7') # green
        text_color = colors.HexColor('#166534')
        border_color = colors.HexColor('#4ADE80')
        verdict_icon = "✅ SECURE — SAFE CONTENT VERIFIED"
        
    style_verdict_banner = ParagraphStyle(
        'VerdictBanner',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=11,
        leading=13,
        alignment=1, # Center
        textColor=text_color
    )
    
    verdict_text = f"{verdict_icon} — {verdict.upper()} (RISK SCORE: {score}%)"
    verdict_table = Table([[Paragraph(verdict_text, style_verdict_banner)]], colWidths=[540], rowHeights=[28])
    verdict_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), bg_color),
        ('BOX', (0,0), (-1,-1), 1.5, border_color),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('TOPPADDING', (0,0), (-1,-1), 0),
        ('BOTTOMPADDING', (0,0), (-1,-1), 0),
    ]))
    story.append(verdict_table)
    story.append(Spacer(1, 10))

    # ── Scanned Evidence & Rubber Stamp Section ──
    story.append(Paragraph("Scanned Target Evidence & CTI Verification Stamp", style_section_title))
    
    # Determine the stamp label
    verdict_stamp_text = "VERIFIED SAFE"
    if state_class == 'danger':
        if "Betting" in module:
            verdict_stamp_text = "ILLEGAL BETTING"
        elif "Deepfake" in module:
            verdict_stamp_text = "MANIPULATED / FAKE"
        elif "Customer Care" in module:
            verdict_stamp_text = "VERIFIED SCAM"
        else:
            verdict_stamp_text = "FINANCIAL FRAUD"
    elif state_class == 'warning':
        if "Customer Care" in module:
            verdict_stamp_text = "SUSPICIOUS LINE"
        elif "Investment" in module:
            verdict_stamp_text = "SUSPICIOUS GROUP"
        else:
            verdict_stamp_text = "SUSPICIOUS"
    else:
        if "Deepfake" in module:
            verdict_stamp_text = "VERIFIED REAL"
        else:
            verdict_stamp_text = "VERIFIED SAFE"
            
    stamp_drawing = draw_official_stamp(verdict_stamp_text, state_class)
    
    # Try loading the saved image file
    image_flowable = None
    media_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'static', 'uploads', 'scans', f"{file_hash}.png")
    
    # For text modules, or fallback, we show a quote paragraph
    is_image_evidence = False
    if os.path.exists(media_path):
        try:
            image_flowable = RLImage(media_path, width=190, height=130)
            image_flowable.hAlign = 'CENTER'
            is_image_evidence = True
        except Exception:
            pass
            
    if is_image_evidence:
        # Image next to stamp
        evidence_table = Table([[image_flowable, stamp_drawing]], colWidths=[270, 270])
        evidence_table.setStyle(TableStyle([
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('ALIGN', (0,0), (0,0), 'CENTER'),
            ('ALIGN', (1,0), (1,0), 'CENTER'),
            ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor('#E5E7EB')),
            ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#FAFAFA')),
            ('TOPPADDING', (0,0), (-1,-1), 8),
            ('BOTTOMPADDING', (0,0), (-1,-1), 8),
        ]))
        story.append(evidence_table)
    else:
        # It's text, show text quote next to stamp
        full_text = scan.get('input_summary', '')
        if not full_text or full_text == 'N/A' or len(full_text) < 10:
            # Maybe the text is longer
            full_text = scan.get('reasons', ['No text extract recorded'])[0]
        # Trim text to prevent huge block
        if len(full_text) > 280:
            full_text = full_text[:277] + "..."
            
        text_p = Paragraph(f"RAW EVIDENCE ANALYSIS DUMP:<br/><br/><i>\"{full_text}\"</i>", style_text_evidence)
        evidence_table = Table([[text_p, stamp_drawing]], colWidths=[370, 170])
        evidence_table.setStyle(TableStyle([
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('ALIGN', (1,0), (1,0), 'CENTER'),
            ('LEFTPADDING', (0,0), (-1,-1), 2),
            ('RIGHTPADDING', (0,0), (-1,-1), 2),
        ]))
        story.append(evidence_table)
        
    story.append(Spacer(1, 10))
    
    # ── Extracted Indicators Section ──
    story.append(Paragraph("Forensic Indicators Registry", style_section_title))
    
    indicators = scan.get('indicators', {})
    if not isinstance(indicators, dict):
        indicators = {}
        
    # Standardize indicators display depending on module
    indicators_rows = []
    
    if "Betting" in module:
        indicators_rows = [
            [Paragraph("OCR Text Probability", style_body_bold), Paragraph(f"{indicators.get('text_probability', 0)}%", style_body)],
            [Paragraph("YOLO Object Detection Confidence", style_body_bold), Paragraph(f"{indicators.get('vision_probability', 0)}%", style_body)],
            [Paragraph("Detected Bounding Box Logos", style_body_bold), Paragraph(", ".join(indicators.get('detected_logos', [])) or "None", style_body)],
            [Paragraph("Extracted Betting Keyphrases", style_body_bold), Paragraph(", ".join(indicators.get('matched_keywords', [])) or "None", style_body)]
        ]
    elif "Deepfake" in module:
        indicators_rows = [
            [Paragraph("Synthetic Face Classification Probability", style_body_bold), Paragraph(f"{indicators.get('score', 0)}%", style_body)],
            [Paragraph("Total Sampled Frame Count", style_body_bold), Paragraph(str(indicators.get('frames', 0)), style_body)],
            [Paragraph("Frame Manipulation Analysis", style_body_bold), Paragraph("Artifact patterns detected on MTCNN localized facial regions." if verdict_upper == "FAKE" else "No anomalous facial inconsistencies observed.", style_body)]
        ]
    elif "Customer Care" in module:
        indicators_rows = [
            [Paragraph("Detected Phone Number", style_body_bold), Paragraph(indicators.get('detected_phone', 'None'), style_body)],
            [Paragraph("Impersonated Brand Entity", style_body_bold), Paragraph(indicators.get('brand', 'None'), style_body)],
            [Paragraph("Official Registered Database Phone", style_body_bold), Paragraph(indicators.get('official_phone', 'None'), style_body)],
            [Paragraph("Carrier Verification Classification", style_body_bold), Paragraph(indicators.get('telecom_label', 'N/A'), style_body)],
            [Paragraph("Linguistic Pressure Scores", style_body_bold), Paragraph(f"Urgency: {indicators.get('urgency_score', 0)}% | Coercion: {indicators.get('coercion_score', 0)}% | Anomaly: {indicators.get('anomaly_score', 0)}%", style_body)]
        ]
    else: # Investment
        indicators_rows = [
            [Paragraph("Engine A (XGBoost Classifier)", style_body_bold), Paragraph(f"Score: {indicators.get('engine_breakdown', {}).get('engine_a_xgboost', 0)}%", style_body)],
            [Paragraph("Engine B (RoBERTa Transformer)", style_body_bold), Paragraph(f"Score: {indicators.get('engine_breakdown', {}).get('engine_b_xlm_roberta', 0)}%", style_body)],
            [Paragraph("Security Analysis Level", style_body_bold), Paragraph(indicators.get('traffic_light', 'green').upper(), style_body)],
            [Paragraph("Link/Domain Intelligence Check", style_body_bold), Paragraph("Suspicious external domains / redirects identified." if any("link" in r.lower() for r in scan.get('reasons', [])) else "All scanned links resolved to clean standard structures.", style_body)]
        ]
        
    if not indicators_rows:
        indicators_rows = [[Paragraph("Indicators Found", style_body_bold), Paragraph("No structured forensic indicators recorded.", style_body)]]
        
    indicators_table = Table(indicators_rows, colWidths=[180, 360])
    indicators_table.setStyle(TableStyle([
        ('LINEBELOW', (0,0), (-1,-2), 0.5, colors.HexColor('#F3F4F6')),
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('TOPPADDING', (0,0), (-1,-1), 4),
        ('BOTTOMPADDING', (0,0), (-1,-1), 4),
    ]))
    story.append(indicators_table)
    story.append(Spacer(1, 10))
    
    # ── Analysis Findings ──
    story.append(Paragraph("Forensic Analysis Findings", style_section_title))
    reasons = scan.get('reasons', [])
    if not reasons:
        reasons = ["No specific anomaly indicators flagged. Content meets base standard compliance criteria."]
        
    for r in reasons:
        story.append(Paragraph(f"&bull;&nbsp; {r}", style_reasons_bullet))
    story.append(Spacer(1, 10))
    
    # ── Security Recommendation Box ──
    reco_text = scan.get('recommendation', 'RECOMMENDATION: Standard monitoring. No security compliance action required.')
    
    reco_cell = [
        Paragraph("SECURITY COMPLIANCE ACTION REQUIRED", style_body_bold),
        Spacer(1, 4),
        Paragraph(reco_text, style_body)
    ]
    reco_table = Table([[reco_cell]], colWidths=[540])
    reco_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#FAFAFA')),
        ('BOX', (0,0), (-1,-1), 1, colors.HexColor('#0B172A')),
        ('LINELEFT', (0,0), (-1,-1), 3, colors.HexColor('#0B172A')), # thick navy border
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('TOPPADDING', (0,0), (-1,-1), 7),
        ('BOTTOMPADDING', (0,0), (-1,-1), 7),
        ('LEFTPADDING', (0,0), (-1,-1), 10),
        ('RIGHTPADDING', (0,0), (-1,-1), 10),
    ]))
    
    # Keep the recommendation and signatures together so they don't break across pages awkwardly
    footer_elements = []
    footer_elements.append(reco_table)
    footer_elements.append(Spacer(1, 14))
    
    # ── Signature Block ──
    sig_data = [
        [Paragraph("Digitally Verified By:", style_body_bold), Paragraph("CTI Validation Authority Seal:", style_body_bold)],
        [Paragraph("<br/><br/><b>Danish Dhanjal</b><br/>Threat Analyst Command Office", style_body),
         Paragraph("<br/><b>VERIFIED GATEWAY SECURE</b><br/>CYBERSURAKSHAA Portal Cert", style_body)]
    ]
    sig_table = Table(sig_data, colWidths=[270, 270])
    sig_table.setStyle(TableStyle([
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('ALIGN', (1,0), (1,-1), 'RIGHT'),
        ('BOTTOMPADDING', (0,0), (-1,-1), 2),
    ]))
    footer_elements.append(sig_table)
    
    story.append(KeepTogether(footer_elements))
    
    # Build Document
    doc.build(story, onFirstPage=draw_page_decorations, onLaterPages=draw_page_decorations)
    
    pdf_data = buffer.getvalue()
    buffer.close()
    return pdf_data

def generate_html_report(scan):
    """
    Generates a beautifully styled standalone HTML threat report,
    replicating the design grid, colors, and structure of the official PDF.
    """
    scan_id = scan.get('id', 0)
    ref_id = f"CS-CTI-2026-{scan_id:04d}"
    timestamp = scan.get('timestamp', datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    module = scan.get('module', 'Unknown Module')
    input_sum = scan.get('input_summary', 'N/A')
    file_hash = scan.get('file_hash', 'N/A')
    analyst = scan.get('username', 'system')
    verdict = scan.get('verdict', 'UNKNOWN')
    score = scan.get('score', 0)
    reasons = scan.get('reasons', [])
    indicators = scan.get('indicators', {})
    if not isinstance(indicators, dict):
        indicators = {}
    recommendation = scan.get('recommendation', 'RECOMMENDATION: Standard monitoring. No security compliance action required.')
    
    verdict_upper = verdict.upper()
    
    # Determine HTML style tags depending on severity
    if any(k in verdict_upper for k in ('BETTING', 'FAKE', 'SCAM', 'DANGER', 'RED', 'CRITICAL', 'HIGH')):
        state_class = 'danger'
        verdict_icon = '🚨'
        verdict_title = 'CRITICAL THREAT DETECTED'
        if "Betting" in module:
            verdict_stamp_text = "ILLEGAL BETTING"
        elif "Deepfake" in module:
            verdict_stamp_text = "MANIPULATED / FAKE"
        elif "Customer Care" in module:
            verdict_stamp_text = "VERIFIED SCAM"
        else:
            verdict_stamp_text = "FINANCIAL FRAUD"
    elif any(k in verdict_upper for k in ('SUSPICIOUS', 'WARN', 'YELLOW')):
        state_class = 'warning'
        verdict_icon = '⚠️'
        verdict_title = 'WARNING — SUSPICIOUS SIGNAL'
        if "Customer Care" in module:
            verdict_stamp_text = "SUSPICIOUS LINE"
        elif "Investment" in module:
            verdict_stamp_text = "SUSPICIOUS GROUP"
        else:
            verdict_stamp_text = "SUSPICIOUS"
    else:
        state_class = 'safe'
        verdict_icon = '✅'
        verdict_title = 'SECURE — SAFE CONTENT VERIFIED'
        if "Deepfake" in module:
            verdict_stamp_text = "VERIFIED REAL"
        else:
            verdict_stamp_text = "VERIFIED SAFE"

    # Evidence layout
    image_url = f"/static/uploads/scans/{file_hash}.png"
    has_image = os.path.exists(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'static', 'uploads', 'scans', f"{file_hash}.png"))
    
    if has_image:
        evidence_html = f"""
        <div class="row align-items-center border rounded p-3 bg-light g-3">
          <div class="col-md-6 text-center">
            <img src="{image_url}" class="img-fluid rounded border shadow-sm" style="max-height: 220px;" alt="Scanned Media Evidence">
          </div>
          <div class="col-md-6 text-center">
            <div class="cti-stamp {state_class}">{verdict_stamp_text}</div>
          </div>
        </div>
        """
    else:
        full_text = scan.get('input_summary', '')
        if not full_text or full_text == 'N/A' or len(full_text) < 10:
            full_text = scan.get('reasons', ['No text extract recorded'])[0]
        evidence_html = f"""
        <div class="row align-items-center g-3">
          <div class="col-md-8">
            <div class="p-3 border rounded bg-light font-monospace" style="font-size: 0.8rem; white-space: pre-wrap; color: #374151;">RAW EVIDENCE ANALYSIS DUMP:<br><br>"{full_text}"</div>
          </div>
          <div class="col-md-4 text-center">
            <div class="cti-stamp {state_class}">{verdict_stamp_text}</div>
          </div>
        </div>
        """

    # Extracted indicators HTML table rows
    indicators_html = ""
    if "Betting" in module:
        indicators_html = f"""
        <tr><td><strong>OCR Text Probability</strong></td><td>{indicators.get('text_probability', 0)}%</td></tr>
        <tr><td><strong>YOLO Object Detection Confidence</strong></td><td>{indicators.get('vision_probability', 0)}%</td></tr>
        <tr><td><strong>Detected Bounding Box Logos</strong></td><td>{", ".join(indicators.get('detected_logos', [])) or "None"}</td></tr>
        <tr><td><strong>Extracted Betting Keyphrases</strong></td><td>{", ".join(indicators.get('matched_keywords', [])) or "None"}</td></tr>
        """
    elif "Deepfake" in module:
        indicators_html = f"""
        <tr><td><strong>Synthetic Face Classification Probability</strong></td><td>{indicators.get('score', 0)}%</td></tr>
        <tr><td><strong>Total Sampled Frame Count</strong></td><td>{indicators.get('frames', 0)}</td></tr>
        <tr><td><strong>Frame Manipulation Analysis</strong></td><td>{"Artifact patterns detected on MTCNN localized facial regions." if verdict_upper == "FAKE" else "No anomalous facial inconsistencies observed."}</td></tr>
        """
    elif "Customer Care" in module:
        indicators_html = f"""
        <tr><td><strong>Detected Phone Number</strong></td><td>{indicators.get('detected_phone', 'None')}</td></tr>
        <tr><td><strong>Impersonated Brand Entity</strong></td><td>{indicators.get('brand', 'None')}</td></tr>
        <tr><td><strong>Official Registered Database Phone</strong></td><td>{indicators.get('official_phone', 'None')}</td></tr>
        <tr><td><strong>Carrier Verification Classification</strong></td><td>{indicators.get('telecom_label', 'N/A')}</td></tr>
        <tr><td><strong>Linguistic Pressure Scores</strong></td><td>Urgency: {indicators.get('urgency_score', 0)}% | Coercion: {indicators.get('coercion_score', 0)}% | Anomaly: {indicators.get('anomaly_score', 0)}%</td></tr>
        """
    else: # Investment
        indicators_html = f"""
        <tr><td><strong>Engine A (XGBoost Classifier)</strong></td><td>{indicators.get('engine_breakdown', {}).get('engine_a_xgboost', 0)}%</td></tr>
        <tr><td><strong>Engine B (RoBERTa Transformer)</strong></td><td>{indicators.get('engine_breakdown', {}).get('engine_b_xlm_roberta', 0)}%</td></tr>
        <tr><td><strong>Security Analysis Level</strong></td><td>{indicators.get('traffic_light', 'green').upper()}</td></tr>
        <tr><td><strong>Link/Domain Intelligence Check</strong></td><td>{"Suspicious external domains / redirects identified." if any("link" in r.lower() for r in reasons) else "All scanned links resolved to clean standard structures."}</td></tr>
        """

    if not indicators_html:
        indicators_html = "<tr><td><strong>Indicators Found</strong></td><td>No structured forensic indicators recorded.</td></tr>"

    reasons_html = "".join([f"<li>{r}</li>" for r in reasons])

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Official CTI Report — {ref_id}</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
  <style>
    :root {{
      --primary-navy: #0B172A;
      --secondary-gold: #F5B301;
      --border-color: #E5E7EB;
      --gov-grey: #F9FAFB;
      --text-main: #1F2937;
    }}
    body {{
      font-family: 'Inter', system-ui, -apple-system, sans-serif;
      background-color: #F3F4F6;
      color: var(--text-main);
      padding: 40px 15px;
    }}
    .report-paper {{
      background-color: #ffffff;
      max-width: 800px;
      margin: 0 auto;
      border-radius: 8px;
      box-shadow: 0 4px 20px rgba(0,0,0,0.08);
      position: relative;
      overflow: hidden;
      border: 1px solid var(--border-color);
    }}
    /* Top Tricolor Border Line */
    .tricolor-strip {{
      height: 8px;
      display: flex;
      width: 100%;
    }}
    .tricolor-saffron {{ background-color: #FF9933; flex: 1; }}
    .tricolor-white {{ background-color: #FFFFFF; flex: 1; }}
    .tricolor-green {{ background-color: #138808; flex: 1; }}
    
    .report-padding {{
      padding: 40px 48px;
    }}
    
    /* Header Emblem & Titles */
    .report-header {{
      display: flex;
      align-items: center;
      gap: 24px;
      padding-bottom: 20px;
      border-bottom: 3px solid var(--secondary-gold);
      margin-bottom: 24px;
    }}
    .header-emblem {{
      width: 60px;
      height: 60px;
      background-color: var(--primary-navy);
      border: 2px solid var(--secondary-gold);
      border-radius: 50%;
      display: flex;
      align-items: center;
      justify-content: center;
      color: #ffffff;
      font-size: 1.8rem;
      flex-shrink: 0;
      box-shadow: 0 2px 8px rgba(11,23,42,0.15);
      position: relative;
      overflow: hidden;
    }}
    .header-emblem::before {{
      content: "";
      position: absolute;
      top: 0; left: 0; right: 0; height: 33.3%;
      background: #FF9933;
      opacity: 0.15;
    }}
    .header-emblem::after {{
      content: "";
      position: absolute;
      bottom: 0; left: 0; right: 0; height: 33.3%;
      background: #138808;
      opacity: 0.15;
    }}
    .header-titles h1 {{
      font-size: 1.6rem;
      font-weight: 800;
      color: var(--primary-navy);
      margin: 0;
      letter-spacing: 0.05em;
    }}
    .header-titles h2 {{
      font-size: 0.82rem;
      font-weight: 700;
      color: var(--secondary-gold);
      margin: 2px 0 4px 0;
      letter-spacing: 0.12em;
      text-transform: uppercase;
    }}
    .header-titles p {{
      font-size: 0.72rem;
      font-style: italic;
      color: #6B7280;
      margin: 0;
    }}
    
    .document-title {{
      font-size: 1.05rem;
      font-weight: 800;
      color: var(--primary-navy);
      text-align: center;
      letter-spacing: 0.08em;
      margin-bottom: 24px;
      text-transform: uppercase;
    }}
    
    /* Metadata grid */
    .metadata-table {{
      font-size: 0.85rem;
      margin-bottom: 24px;
    }}
    .metadata-table th {{
      background-color: var(--gov-grey);
      font-weight: 700;
      color: var(--primary-navy);
      width: 25%;
    }}
    
    /* Verdict Banners */
    .verdict-banner {{
      padding: 12px 18px;
      font-weight: 700;
      text-align: center;
      font-size: 0.95rem;
      border-radius: 4px;
      margin-bottom: 28px;
      border: 1px solid transparent;
    }}
    .verdict-banner.safe {{
      background-color: #DCFCE7;
      color: #15803D;
      border-color: #86EFAC;
    }}
    .verdict-banner.warning {{
      background-color: #FEF9C3;
      color: #854D0E;
      border-color: #FDE047;
    }}
    .verdict-banner.danger {{
      background-color: #FEE2E2;
      color: #991B1B;
      border-color: #FCA5A5;
    }}
    
    .section-title {{
      font-size: 0.95rem;
      font-weight: 800;
      color: var(--primary-navy);
      text-transform: uppercase;
      letter-spacing: 0.05em;
      border-bottom: 1.5px solid var(--primary-navy);
      padding-bottom: 6px;
      margin-bottom: 14px;
      margin-top: 24px;
    }}
    
    /* Stamp style overlay */
    .cti-stamp {{
      border: 4px double #B91C1C;
      color: #B91C1C;
      font-weight: 900;
      text-transform: uppercase;
      padding: 6px 16px;
      border-radius: 4px;
      transform: rotate(-6deg);
      display: inline-block;
      font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif;
      font-size: 1.05rem;
      letter-spacing: 0.05em;
      text-align: center;
      background-color: rgba(255,255,255,0.9);
      box-shadow: 0 4px 12px rgba(0,0,0,0.05);
    }}
    .cti-stamp.danger {{ border-color: #B91C1C; color: #B91C1C; }}
    .cti-stamp.warning {{ border-color: #D97706; color: #D97706; }}
    .cti-stamp.safe {{ border-color: #166534; color: #166534; }}
    
    /* Indicators Table */
    .indicators-table {{
      font-size: 0.85rem;
      margin-bottom: 28px;
    }}
    .indicators-table td {{
      padding: 8px 12px;
    }}
    
    /* Reasons List */
    .reasons-list {{
      font-size: 0.85rem;
      line-height: 1.6;
      padding-left: 20px;
      margin-bottom: 28px;
    }}
    .reasons-list li {{
      margin-bottom: 4px;
    }}
    
    /* Recommendation box */
    .recommendation-box {{
      background-color: var(--gov-grey);
      border: 1px solid var(--primary-navy);
      border-left: 4px solid var(--primary-navy);
      padding: 16px 20px;
      border-radius: 4px;
      margin-bottom: 36px;
    }}
    .recommendation-box h4 {{
      font-size: 0.82rem;
      font-weight: 800;
      color: var(--primary-navy);
      margin-bottom: 6px;
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }}
    .recommendation-box p {{
      font-size: 0.85rem;
      margin: 0;
      line-height: 1.5;
    }}
    
    /* Signature Block */
    .signature-row {{
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      font-size: 0.82rem;
      margin-top: 40px;
      padding-top: 20px;
      border-top: 1px dashed var(--border-color);
    }}
    .sig-line {{
      margin-top: 30px;
      padding-top: 6px;
      width: 200px;
      text-align: left;
    }}
    .validation-badge {{
      border: 2px double #06038D;
      color: #06038D;
      padding: 8px 16px;
      font-weight: 800;
      text-transform: uppercase;
      letter-spacing: 0.06em;
      font-size: 0.72rem;
      border-radius: 4px;
      text-align: center;
    }}
    
    .print-btn-row {{
      max-width: 800px;
      margin: 20px auto 0;
      text-align: right;
    }}
    
    @media print {{
      body {{
        background-color: #ffffff;
        padding: 0;
      }}
      .report-paper {{
        box-shadow: none;
        border: none;
      }}
      .print-btn-row {{
        display: none;
      }}
    }}
  </style>
</head>
<body>

  <div class="report-paper">
    <div class="tricolor-strip">
      <div class="tricolor-saffron"></div>
      <div class="tricolor-white"></div>
      <div class="tricolor-green"></div>
    </div>
    
    <div class="report-padding">
      
      <!-- Logo and branding header -->
      <div class="report-header">
        <div class="header-emblem">
          <i class="fa-solid fa-shield-halved"></i>
        </div>
        <div class="header-titles">
          <h1>CYBERSURAKSHAA</h1>
          <h2>National Threat Detection Suite</h2>
          <p>AI-Powered Threat Intelligence Platform for Detection, Investigation, and Analysis of Fraudulent Digital Content</p>
        </div>
      </div>
      
      <!-- Document header -->
      <div class="document-title">
        Official Cyber Threat Intelligence Report
      </div>
      
      <!-- Metadata block -->
      <table class="table table-bordered metadata-table">
        <tbody>
          <tr>
            <th>Report Reference</th>
            <td>{ref_id}</td>
            <th>Scan Date/Time</th>
            <td>{timestamp}</td>
          </tr>
          <tr>
            <th>Detection Engine</th>
            <td>{module}</td>
            <th>Investigator Account</th>
            <td>{analyst}</td>
          </tr>
          <tr>
            <th>Target Title</th>
            <td>{input_sum}</td>
            <th>SHA-256 Hash</th>
            <td style="font-family: 'JetBrains Mono', monospace; font-size: 0.75rem;">{file_hash}</td>
          </tr>
        </tbody>
      </table>
      
      <!-- Verdict Banner -->
      <div class="verdict-banner {state_class}">
        {verdict_icon} {verdict_title} &mdash; {verdict.upper()} (RISK SCORE: {score}%)
      </div>
      
      <!-- Scanned Target Evidence and Stamp -->
      <div class="section-title">Scanned Target Evidence &amp; Verification Stamp</div>
      <div class="mb-4">
        {evidence_html}
      </div>
      
      <!-- Forensic Indicators -->
      <div class="section-title">Forensic Indicators Registry</div>
      <table class="table table-striped indicators-table">
        <tbody>
          {indicators_html}
        </tbody>
      </table>
      
      <!-- Reasons list -->
      <div class="section-title">Forensic Analysis Findings</div>
      <ul class="reasons-list">
        {reasons_html}
      </ul>
      
      <!-- Recommendations box -->
      <div class="recommendation-box">
        <h4>Security Compliance Action Required</h4>
        <p>{recommendation}</p>
      </div>
      
      <!-- Footer Signature Block -->
      <div class="signature-row">
        <div>
          <strong>Digitally Verified By:</strong>
          <div class="sig-line">
            <strong>Danish Dhanjal</strong><br>
            Threat Analyst Command Office
          </div>
        </div>
        <div style="display: flex; flex-direction: column; align-items: flex-end;">
          <strong>Validation Seal:</strong>
          <div class="validation-badge mt-2">
            Verified Gateway Secure<br>
            CYBERSURAKSHAA CTI PORTAL
          </div>
        </div>
      </div>
      
    </div>
  </div>

  <div class="print-btn-row">
    <button class="btn btn-navy" style="background-color: var(--primary-navy); color: #fff; font-weight: 700; font-size: 0.85rem;" onclick="window.print()">
      <i class="fa-solid fa-print"></i> Print Report / Save PDF
    </button>
  </div>

</body>
</html>
"""
    return html_content
