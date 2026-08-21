import os
import io
import json
from datetime import datetime
from html import escape as _html_escape
from xml.sax.saxutils import escape as _xml_escape
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, KeepTogether
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.graphics.shapes import Drawing, Rect, Circle, Line, String, Group

def _rl(value):
    """
    Escape a value for use inside a ReportLab Paragraph.

    Paragraph parses its argument as mini-XML, so a scan summary containing an
    unclosed angle bracket or a malformed entity aborted the document build and
    the notice endpoint returned a 500. See services/report_generator._rl.
    """
    return _xml_escape('' if value is None else str(value))


def _h(value):
    """
    Escape a value for interpolation into the generated HTML notice.

    The notice is served as text/html and carries scan text the user submitted,
    so interpolating it raw let markup in a scan run as script in the browser
    of whoever opened the notice.
    """
    return _html_escape('' if value is None else str(value), quote=True)


def draw_takedown_flag_header(width, height):
    """Draws a saffron-white-green horizontal tricolor band at the top of the notice page."""
    d = Drawing(width, height)
    bw = width
    bh = height / 3
    # Saffron
    d.add(Rect(0, bh * 2, bw, bh, fillColor=colors.HexColor('#FF9933'), strokeColor=None))
    # White
    d.add(Rect(0, bh, bw, bh, fillColor=colors.HexColor('#FFFFFF'), strokeColor=None))
    # Green
    d.add(Rect(0, 0, bw, bh, fillColor=colors.HexColor('#138808'), strokeColor=None))
    return d

def draw_takedown_seal(text, width=150, height=50):
    """Draws a formal government digital seal for the takedown document."""
    d = Drawing(width, height)
    g = Group()
    g.translate(width/2, height/2)
    g.rotate(-3)
    
    color = colors.HexColor('#1E3A8A')  # Deep navy
    
    # Outer rectangular stamp border
    g.add(Rect(-width/2 + 2, -height/2 + 2, width - 4, height - 4, 
               fillColor=None, strokeColor=color, strokeWidth=1.5, rx=3, ry=3))
    g.add(Rect(-width/2 + 4, -height/2 + 4, width - 8, height - 8, 
               fillColor=None, strokeColor=color, strokeWidth=0.5, rx=1, ry=1))
    
    # Stamp content
    # This seal previously read "NCSCC DIGITAL COMPLIANCE / GOVERNMENT OF INDIA".
    # Nothing here is issued by any government body, and a stamp saying so on a
    # document intended to be sent to a real intermediary is an impersonation
    # of the state, not a design flourish.
    g.add(String(0, 4, text, textAnchor='middle', fontName='Helvetica-Bold', fontSize=8, fillColor=color))
    g.add(String(0, -6, "MACHINE-GENERATED DRAFT", textAnchor='middle', fontName='Helvetica-Bold', fontSize=5, fillColor=color))
    g.add(String(0, -14, "REQUIRES AUTHORISED SIGNATURE", textAnchor='middle', fontName='Helvetica', fontSize=4.5, fillColor=color))
    
    d.add(g)
    return d


def _verification_block(scan, style_body, style_body_bold):
    """
    Evidence hash, public verification URL and QR code.

    Anyone holding this document -- the recipient intermediary, a court, the
    person it concerns -- can confirm the hash corresponds to a real scan and
    that the audit chain around it is intact, without an account and without
    trusting the sender.
    """
    from services.intel import evidence

    file_hash = (scan.get('file_hash') or '').strip()
    base_url = os.environ.get('PUBLIC_BASE_URL', 'http://localhost:5000')
    verify_url = evidence.verification_url(base_url, file_hash) if file_hash else None

    left = Paragraph(
        "<b>Independent verification</b><br/><br/>"
        "Evidence hash (SHA-256):<br/>"
        "<font face='Courier' size='6'>%s</font><br/><br/>"
        "%s" % (
            _rl(file_hash or 'not recorded for this scan'),
            ("Verify at:<br/><font size='7'>%s</font>" % _rl(verify_url))
            if verify_url else
            "No evidence hash was recorded, so this document cannot be verified."
        ),
        style_body)

    qr = evidence.qr_drawing(verify_url, size=64) if verify_url else None
    row = [left, qr if qr is not None else Paragraph("", style_body)]

    table = Table([row], colWidths=[430, 92])
    table.setStyle(TableStyle([
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor('#CBD5E1')),
        ('LEFTPADDING', (0, 0), (-1, -1), 10),
        ('RIGHTPADDING', (0, 0), (-1, -1), 10),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
    ]))
    return table

def generate_takedown_pdf(scan):
    """
    Compiles a formal ReportLab PDF notice under Section 79(3)(b) of the IT Act, 2000.
    """
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=45,
        leftMargin=45,
        topMargin=40,
        bottomMargin=40
    )
    
    styles = getSampleStyleSheet()
    
    # Custom styles
    style_title = ParagraphStyle(
        'TakedownTitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=15,
        leading=18,
        textColor=colors.HexColor('#1E3A8A'),
        alignment=1, # Centered
    )
    
    style_subtitle = ParagraphStyle(
        'TakedownSub',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=9,
        leading=11,
        textColor=colors.HexColor('#475569'),
        alignment=1, # Centered
    )
    
    style_legal_header = ParagraphStyle(
        'LegalHeader',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=10,
        leading=13,
        textColor=colors.HexColor('#0F172A'),
    )

    style_meta_label = ParagraphStyle(
        'MetaLabel',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=9,
        leading=11,
        textColor=colors.HexColor('#1E3A8A'),
    )

    style_meta_val = ParagraphStyle(
        'MetaVal',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9,
        leading=11,
        textColor=colors.HexColor('#334155'),
    )
    
    style_body = ParagraphStyle(
        'TakedownBody',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9.5,
        leading=14,
        textColor=colors.HexColor('#0F172A'),
    )
    
    style_body_bold = ParagraphStyle(
        'TakedownBodyBold',
        parent=style_body,
        fontName='Helvetica-Bold',
    )
    
    story = []
    
    # 1. Tricolor Header bar
    tricolor = draw_takedown_flag_header(522, 6)
    story.append(tricolor)
    story.append(Spacer(1, 10))

    # 1b. Draft banner. services/intel/actions.py:426-430 already carries this
    # discipline for the equivalent document; this generator did not, and it
    # is the one that looks most like a government directive.
    draft_banner = Table(
        [[Paragraph(
            "<b>DRAFT &mdash; NOT A DISPATCHED COMMUNICATION.</b> Produced by an automated "
            "detection system. It has no legal force until reviewed, verified and signed by "
            "an authorised officer with the standing to issue it. Automated verdicts are "
            "investigative leads, not findings of fact.", style_body)]],
        colWidths=[522])
    draft_banner.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#FEF3C7')),
        ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#D97706')),
        ('LEFTPADDING', (0, 0), (-1, -1), 10),
        ('RIGHTPADDING', (0, 0), (-1, -1), 10),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
    ]))
    story.append(draft_banner)
    story.append(Spacer(1, 14))

    # 2. National Security Header
    # The letterhead used to read "NATIONAL CYBER RISK MITIGATION CENTRE" over
    # "MINISTRY OF ELECTRONICS & INFORMATION TECHNOLOGY (MeitY) - GOVT. OF
    # INDIA". No such centre exists and this software is not MeitY. A notice
    # carrying a ministry's name is a forged government communication the
    # moment somebody emails it to a hosting provider.
    story.append(Paragraph("CYBERSURAKSHAA THREAT DETECTION PLATFORM", style_title))
    story.append(Paragraph("AUTOMATED DRAFT — FOR ISSUE BY AN AUTHORISED OFFICER", style_subtitle))
    story.append(Spacer(1, 2))
    
    # Border line
    line_drawing = Drawing(522, 2)
    line_drawing.add(Line(0, 0, 522, 0, strokeColor=colors.HexColor('#CBD5E1'), strokeWidth=1))
    story.append(line_drawing)
    story.append(Spacer(1, 12))
    
    # 3. Reference and Date info block
    scan_id = scan.get('id') or 0
    # Was "NCSCC-MEITY/CTI-TDR/2026/NNNN" -- a fabricated ministry file number.
    ref_code = f"CS-TDR-DRAFT/{datetime.now().year}/{scan_id:04d}"
    date_str = scan.get('timestamp') or datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    info_data = [
        [Paragraph(f"<b>Ref No:</b> {_rl(ref_code)}", style_meta_val),
         Paragraph(f"<b>Date:</b> {_rl(date_str)}", style_meta_val)]
    ]
    info_table = Table(info_data, colWidths=[261, 261])
    info_table.setStyle(TableStyle([
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('ALIGN', (1,0), (1,0), 'RIGHT'),
        ('BOTTOMPADDING', (0,0), (-1,-1), 0),
        ('TOPPADDING', (0,0), (-1,-1), 0),
    ]))
    story.append(info_table)
    story.append(Spacer(1, 15))
    
    # 4. Target/Recipient line
    story.append(Paragraph("<b>TO:</b> THE NOMINATED COMPLIANCE OFFICER / DISCIPLINARY INTERMEDIARY AUTHORITY", style_legal_header))
    story.append(Paragraph("<b>SUBJECT:</b> DIRECTIVE FOR IMMEDIATE REMOVAL / BLOCKING OF UNLAWFUL DIGITAL CONTENT UNDER SECTION 79(3)(b) OF THE INFORMATION TECHNOLOGY ACT, 2000", style_legal_header))
    story.append(Spacer(1, 12))
    
    # 5. Formal opening statement
    story.append(Paragraph(
        "Whereas, the National Threat Detection Suite (CYBERSURAKSHAA Portal) has performed a digital forensic threat assessment "
        "on the digital content described below. The forensic system has flagged the target content as hosting, promoting, or "
        "facilitating unlawful digital activities in direct violation of local laws, regulatory guidelines, and national security directives.",
        style_body
    ))
    story.append(Spacer(1, 12))
    
    # 6. Technical Evidence Table
    # `or <default>` on every field: these columns are nullable, and a None
    # reaching .upper()/len() raised before any of the notice was rendered.
    verdict = str(scan.get('verdict') or 'SUSPICIOUS').upper()
    score = scan.get('score', 0)
    module_name = str(scan.get('module') or 'General').upper()
    file_hash = scan.get('file_hash') or 'N/A'
    input_text = str(scan.get('input_summary') or '')
    if len(input_text) > 100:
        input_text = input_text[:97] + "..."

    table_data = [
        [Paragraph("CTI Incident Category:", style_meta_label), Paragraph(f"Cyber Crime / {_rl(module_name)}", style_meta_val)],
        [Paragraph("Target URL / Identifier:", style_meta_label), Paragraph(_rl(input_text), style_meta_val)],
        [Paragraph("Forensic Risk Assessment:", style_meta_label), Paragraph(f"<b>{_rl(verdict)}</b> (Score: {_rl(score)}%)", style_meta_val)],
        [Paragraph("Cryptographic Fingerprint:", style_meta_label), Paragraph(f"<font face='Courier'>{_rl(file_hash)}</font>", style_meta_val)],
    ]
    meta_table = Table(table_data, colWidths=[160, 362])
    meta_table.setStyle(TableStyle([
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#F8FAFC')),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#E2E8F0')),
        ('TOPPADDING', (0,0), (-1,-1), 6),
        ('BOTTOMPADDING', (0,0), (-1,-1), 6),
        ('LEFTPADDING', (0,0), (-1,-1), 8),
        ('RIGHTPADDING', (0,0), (-1,-1), 8),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 14))
    
    # 7. Directive Text
    story.append(Paragraph(
        "<b>DIRECTIVE FOR INTERMEDIARIES:</b>", style_legal_header
    ))
    story.append(Paragraph(
        "In exercise of the powers conferred by Section 79(3)(b) of the Information Technology Act, 2000, read in conjunction with the "
        "Information Technology (Intermediary Guidelines and Digital Media Ethics Code) Rules, the intermediary is to be directed to "
        "<b>immediately disable access to, remove or block the hosting of the specified unlawful content</b> on its platform, servers, "
        "or networks.",
        style_body
    ))
    story.append(Spacer(1, 8))
    story.append(Paragraph(
        "Compliance is required within the statutory period of <b>thirty-six (36) hours</b> of receipt of a notice issued under this "
        "provision, failing which the safe harbour protection under Section 79(1) ceases to apply. Depending on the conduct established, "
        "the underlying offence may fall under the Bharatiya Nyaya Sanhita 2023 &mdash; s.318 (cheating), s.319 (cheating by personation) "
        "or s.336 (forgery) &mdash; read with the applicable provisions of the Information Technology Act, 2000.",
        style_body
    ))
    story.append(Spacer(1, 15))
    
    # 8. Signature and Seal
    seal = draw_takedown_seal("UNSIGNED DRAFT")

    # The issuing authority was hardcoded to "Lead Threat Investigator /
    # CYBERSURAKSHAA Command Office". Nobody by that title issued anything --
    # the block is now empty, because only a named officer can fill it.
    sig_data = [
        [Paragraph("<b>Status:</b>", style_body_bold),
         Paragraph("<b>To be completed by the issuing officer:</b>", style_body_bold)],
        [seal, Paragraph(
            "Name: ______________________________<br/><br/>"
            "Designation: ________________________<br/><br/>"
            "Organisation: _______________________<br/><br/>"
            "Signature &amp; date: ____________________", style_body)]
    ]
    sig_table = Table(sig_data, colWidths=[260, 262])
    sig_table.setStyle(TableStyle([
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('BOTTOMPADDING', (0,0), (-1,-1), 2),
        ('TOPPADDING', (0,0), (-1,-1), 2),
    ]))
    
    story.append(KeepTogether(sig_table))
    story.append(Spacer(1, 14))

    # Evidence verification. services/intel/evidence.py has provided qr_drawing()
    # and verification_url() since it was written, with no caller anywhere --
    # while templates/verify.html tells the reader to "scan the QR code on the
    # document". This closes that gap: the two halves were built to work
    # together and were never connected.
    story.append(_verification_block(scan, style_body, style_body_bold))

    doc.build(story)
    pdf_bytes = buffer.getvalue()
    buffer.close()
    return pdf_bytes

def generate_takedown_html(scan):
    """
    Generates a formal, printable HTML legal compliance notice.
    """
    scan_id = scan.get('id') or 0
    ref_code = f"CS-TDR-DRAFT/{datetime.now().year}/{scan_id:04d}"

    # Verification block. evidence.qr_svg() and verification_url() had no caller
    # anywhere, while templates/verify.html instructs the reader to scan a QR
    # code on the document. Wire them together.
    from services.intel import evidence
    file_hash = (scan.get('file_hash') or '').strip()
    base_url = os.environ.get('PUBLIC_BASE_URL', 'http://localhost:5000')
    verify_url = evidence.verification_url(base_url, file_hash) if file_hash else None
    if verify_url:
        verify_line = ('Verify at:<br><a href="%s">%s</a>'
                       % (_h(verify_url), _h(verify_url)))
        qr = evidence.qr_svg(verify_url, size=96)
        qr_html = '<div class="verify-qr">%s</div>' % qr if qr else ''
    else:
        verify_line = ('No evidence hash was recorded for this scan, so this '
                       'document cannot be independently verified.')
        qr_html = ''

    date_str = scan.get('timestamp') or datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    verdict = str(scan.get('verdict') or 'SUSPICIOUS').upper()
    score = scan.get('score', 0)
    module_name = str(scan.get('module') or 'General').upper()
    file_hash = scan.get('file_hash') or 'N/A'
    input_text = str(scan.get('input_summary') or '')
    
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>IT Act Section 79(3)(b) Blocking Notice - CS-TDR-{scan_id:04d}</title>
  <style>
    :root {{
      --primary-navy: #1E3A8A;
      --text-dark: #0F172A;
      --border-gray: #E2E8F0;
      --bg-slate: #F8FAFC;
    }}
    body {{
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      color: var(--text-dark);
      line-height: 1.5;
      padding: 40px;
      background-color: #f1f5f9;
      margin: 0;
    }}
    .legal-page {{
      background: #ffffff;
      max-width: 800px;
      margin: 0 auto;
      padding: 50px;
      box-shadow: 0 4px 6px -1px rgb(0 0 0 / 0.1), 0 2px 4px -2px rgb(0 0 0 / 0.1);
      border-radius: 4px;
      position: relative;
    }}
    .flag-bar {{
      height: 6px;
      width: 100%;
      background: linear-gradient(90deg, #FF9933 33.3%, #ffffff 33.3%, #ffffff 66.6%, #138808 66.6%);
      border: 1px solid var(--border-gray);
      margin-bottom: 25px;
    }}
    .header-title {{
      text-align: center;
      font-weight: 800;
      font-size: 1.35rem;
      color: var(--primary-navy);
      margin: 0 0 4px 0;
      letter-spacing: 0.5px;
    }}
    .header-sub {{
      text-align: center;
      font-weight: 700;
      font-size: 0.82rem;
      color: #475569;
      margin: 0;
      letter-spacing: 0.2px;
    }}
    .divider {{
      height: 1px;
      background-color: var(--border-gray);
      margin: 15px 0 20px 0;
    }}
    .meta-row {{
      display: flex;
      justify-content: space-between;
      font-size: 0.85rem;
      color: #334155;
      margin-bottom: 25px;
      font-weight: 500;
    }}
    .legal-title-section {{
      font-weight: 700;
      font-size: 0.88rem;
      margin-bottom: 15px;
    }}
    .meta-table {{
      width: 100%;
      border-collapse: collapse;
      margin-bottom: 25px;
      font-size: 0.85rem;
    }}
    .meta-table td {{
      padding: 10px 12px;
      border: 1px solid var(--border-gray);
    }}
    .meta-table tr td:first-child {{
      font-weight: 700;
      width: 30%;
      color: var(--primary-navy);
      background-color: var(--bg-slate);
    }}
    .meta-table code {{
      font-family: monospace;
      font-size: 0.9rem;
    }}
    .directive-box {{
      margin-bottom: 30px;
    }}
    .directive-box h4 {{
      color: var(--text-dark);
      margin: 0 0 8px 0;
      font-size: 0.9rem;
      font-weight: 700;
    }}
    .directive-box p {{
      font-size: 0.88rem;
      margin: 0 0 10px 0;
      text-align: justify;
    }}
    .sig-row {{
      display: flex;
      justify-content: space-between;
      margin-top: 40px;
      font-size: 0.88rem;
    }}
    .seal-box {{
      border: 2px solid var(--primary-navy);
      padding: 10px 15px;
      font-weight: 700;
      color: var(--primary-navy);
      font-size: 0.75rem;
      text-align: center;
      border-radius: 4px;
      transform: rotate(-3deg);
      max-width: 180px;
    }}
    .seal-sub {{
      font-size: 0.55rem;
      font-weight: 400;
    }}
    .draft-banner {{
      background-color: #FEF3C7;
      border: 1px solid #D97706;
      border-radius: 4px;
      padding: 12px 16px;
      margin-bottom: 18px;
      font-size: 0.82rem;
      line-height: 1.6;
      color: #78350F;
    }}
    .verify-box {{
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      gap: 18px;
      border: 1px solid #CBD5E1;
      border-radius: 4px;
      padding: 14px 16px;
      margin-top: 22px;
      font-size: 0.8rem;
    }}
    .verify-qr svg {{ width: 96px; height: 96px; }}
    .print-actions {{
      max-width: 800px;
      margin: 20px auto 0 auto;
      text-align: right;
    }}
    .btn {{
      padding: 8px 16px;
      font-weight: 700;
      border: none;
      border-radius: 4px;
      cursor: pointer;
      font-size: 0.82rem;
    }}
    .btn-navy {{
      background-color: var(--primary-navy);
      color: #fff;
    }}
    @media print {{
      body {{
        background-color: #fff;
        padding: 0;
      }}
      .legal-page {{
        box-shadow: none;
        padding: 0;
      }}
      .print-actions {{
        display: none;
      }}
    }}
  </style>
</head>
<body>

  <div class="legal-page">
    <div class="flag-bar"></div>
    <div class="draft-banner">
      <strong>DRAFT &mdash; NOT A DISPATCHED COMMUNICATION.</strong>
      Produced by an automated detection system. It has no legal force until reviewed,
      verified and signed by an authorised officer with the standing to issue it.
      Automated verdicts are investigative leads, not findings of fact.
    </div>
    <div class="header-title">CYBERSURAKSHAA THREAT DETECTION PLATFORM</div>
    <div class="header-sub">AUTOMATED DRAFT — FOR ISSUE BY AN AUTHORISED OFFICER</div>
    <div class="divider"></div>

    <div class="meta-row">
      <div><strong>Ref No:</strong> {_h(ref_code)}</div>
      <div><strong>Date:</strong> {_h(date_str)}</div>
    </div>

    <div class="legal-title-section">
      <strong>TO:</strong> THE NOMINATED COMPLIANCE OFFICER / DISCIPLINARY INTERMEDIARY AUTHORITY<br>
      <strong>SUBJECT:</strong> DIRECTIVE FOR IMMEDIATE REMOVAL / BLOCKING OF UNLAWFUL DIGITAL CONTENT UNDER SECTION 79(3)(b) OF THE INFORMATION TECHNOLOGY ACT, 2000
    </div>

    <p style="font-size: 0.88rem; text-align: justify;">
      Whereas, the National Threat Detection Suite (CYBERSURAKSHAA Portal) has performed a digital forensic threat assessment 
      on the digital content described below. The forensic system has flagged the target content as hosting, promoting, or 
      facilitating unlawful digital activities in direct violation of local laws, regulatory guidelines, and national security directives.
    </p>

    <table class="meta-table">
      <tr>
        <td>CTI Incident Category:</td>
        <td>Cyber Crime / {_h(module_name)}</td>
      </tr>
      <tr>
        <td>Target URL / Identifier:</td>
        <td>{_h(input_text)}</td>
      </tr>
      <tr>
        <td>Forensic Risk Assessment:</td>
        <td><strong>{_h(verdict)}</strong> (Score: {_h(score)}%)</td>
      </tr>
      <tr>
        <td>Cryptographic Fingerprint:</td>
        <td><code>{_h(file_hash)}</code></td>
      </tr>
    </table>

    <div class="directive-box">
      <h4>DIRECTIVE FOR INTERMEDIARIES:</h4>
      <p>
        In exercise of the powers conferred by Section 79(3)(b) of the Information Technology Act, 2000, read in conjunction with the 
        Information Technology (Intermediary Guidelines and Digital Media Ethics Code) Rules, you are hereby directed to <strong>immediately disable 
        access to, remove or block the hosting of the specified unlawful content</strong> on your platform, servers, or networks.
      </p>
      <p>
        Compliance is required within the statutory period of <strong>thirty-six (36) hours</strong> of receipt of a notice issued
        under this provision, failing which the safe harbour protection under Section 79(1) ceases to apply. Depending on the
        conduct established, the underlying offence may fall under the Bharatiya Nyaya Sanhita 2023 &mdash; s.318 (cheating),
        s.319 (cheating by personation) or s.336 (forgery) &mdash; read with the applicable provisions of the
        Information Technology Act, 2000.
      </p>
    </div>

    <div class="sig-row">
      <div>
        <strong>Status:</strong>
        <div class="seal-box" style="margin-top: 10px;">
          UNSIGNED DRAFT<br>
          <span class="seal-sub">MACHINE-GENERATED<br>REQUIRES AUTHORISED SIGNATURE</span>
        </div>
      </div>
      <div style="text-align: right; margin-top: 20px;">
        <strong>To be completed by the issuing officer:</strong><br><br>
        Name: ______________________________<br><br>
        Designation: ________________________<br><br>
        Organisation: _______________________<br><br>
        Signature &amp; date: ____________________
      </div>
    </div>

    <div class="verify-box">
      <div>
        <strong>Independent verification</strong><br><br>
        Evidence hash (SHA-256):<br>
        <code style="font-size:0.68rem; word-break:break-all;">{_h(file_hash) or 'not recorded for this scan'}</code><br><br>
        {verify_line}
      </div>
      {qr_html}
    </div>

  </div>

  <div class="print-actions">
    <button class="btn btn-navy" onclick="window.print()">
      Print Compliance Notice
    </button>
  </div>

</body>
</html>
"""
    return html_content
