"""
services/certificate_generator.py
---------------------------------
Renders the section 63(4) certificate as a document.

Structure follows the Schedule to the Bharatiya Sakshya Adhiniyam 2023:
Part A completed by the party producing the record, Part B by an expert, with
the hash of the electronic record and the algorithm named in both.

The content comes from `services/intel/certificate.build_certificate()`; this
file only lays it out. Both signature blocks are rendered blank — see that
module's docstring for why the platform does not and cannot sign.
"""

from __future__ import annotations

import io
import os
from datetime import datetime

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Table,
                                TableStyle, KeepTogether, PageBreak)

from services.intel import certificate as cert_module
from services.intel import evidence

INK = colors.HexColor("#0F172A")
MUTED = colors.HexColor("#64748B")
RULE = colors.HexColor("#CBD5E1")
WARN_BG = colors.HexColor("#FEF3C7")
WARN_EDGE = colors.HexColor("#D97706")


def _esc(value):
    """
    Escape for a ReportLab Paragraph, which parses its argument as mini-XML.

    Scan summaries contain user-supplied text; an unescaped '&' or '<' raises
    at build time and takes the whole document with it.
    """
    return (str(value if value is not None else "")
            .replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))


def _styles():
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle("t", parent=base["Normal"], fontName="Helvetica-Bold",
                                fontSize=13, leading=17, alignment=1, textColor=INK),
        "subtitle": ParagraphStyle("st", parent=base["Normal"], fontName="Helvetica",
                                   fontSize=8.5, leading=12, alignment=1, textColor=MUTED),
        "part": ParagraphStyle("p", parent=base["Normal"], fontName="Helvetica-Bold",
                               fontSize=10.5, leading=14, textColor=INK,
                               spaceBefore=10, spaceAfter=4),
        "body": ParagraphStyle("b", parent=base["Normal"], fontName="Helvetica",
                               fontSize=8.6, leading=12.4, textColor=INK),
        "small": ParagraphStyle("s", parent=base["Normal"], fontName="Helvetica",
                                fontSize=7.6, leading=10.6, textColor=MUTED),
        "mono": ParagraphStyle("m", parent=base["Normal"], fontName="Courier",
                               fontSize=7.2, leading=9.6, textColor=INK),
    }


def _kv_table(rows, styles, widths=(150, 340)):
    data = [[Paragraph("<b>%s</b>" % _esc(k), styles["body"]),
             Paragraph(_esc(v) if not isinstance(v, str) or "<" not in v else v,
                       styles["body"])]
            for k, v in rows]
    table = Table(data, colWidths=list(widths))
    table.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LINEBELOW", (0, 0), (-1, -2), 0.25, RULE),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    return table


def _signature_block(title, statement, styles):
    """
    A blank attestation block.

    s.63(4) requires signature by the person in charge of the device *and* by
    an expert. Neither can be the software, so both are rendered empty with
    the statement the signatory is adopting printed above them.
    """
    body = [
        Paragraph("<b>%s</b>" % _esc(title), styles["part"]),
        Paragraph(statement, styles["body"]),
        Spacer(1, 10),
        _kv_table([
            ("Name", "_________________________________________"),
            ("Designation", "_________________________________________"),
            ("Organisation", "_________________________________________"),
            ("Place", "_________________________________________"),
            ("Date", "_________________________________________"),
            ("Signature", "_________________________________________"),
        ], styles, widths=(110, 380)),
    ]
    return KeepTogether(body)


def generate_certificate_pdf(scan_id, base_url=None, artefact_path=None):
    """
    Render the certificate. Returns PDF bytes, or None if the scan is unknown.

    Renders even when `is_certifiable()` would refuse — the refusal reasons are
    printed on the face of the document. An officer who asks for a certificate
    that cannot honestly be issued should be shown *why*, in the form they
    asked for, not handed a bare error.
    """
    data = cert_module.build_certificate(scan_id, base_url=base_url,
                                         artefact_path=artefact_path)
    if not data:
        return None

    styles = _styles()
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4,
                            leftMargin=48, rightMargin=48,
                            topMargin=44, bottomMargin=44,
                            title="Certificate under s.63(4) BSA 2023")
    story = []

    # ── Draft banner ────────────────────────────────────────────────────
    banner = Table([[Paragraph(
        "<b>UNSIGNED DRAFT.</b> This document has been prepared automatically "
        "from system records. It is not a certificate until completed and "
        "signed as section 63(4) requires. It is placed before a certifying "
        "person so that the facts stated may be adopted or corrected — the "
        "software makes no attestation of its own.", styles["body"])]],
        colWidths=[500])
    banner.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), WARN_BG),
        ("BOX", (0, 0), (-1, -1), 1, WARN_EDGE),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ("RIGHTPADDING", (0, 0), (-1, -1), 10),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))
    story += [banner, Spacer(1, 14)]

    story += [
        Paragraph("CERTIFICATE UNDER SECTION 63(4)", styles["title"]),
        Paragraph("BHARATIYA SAKSHYA ADHINIYAM, 2023", styles["title"]),
        Spacer(1, 3),
        Paragraph(_esc(data["statute"]["note"]), styles["subtitle"]),
        Spacer(1, 12),
        _kv_table([("Reference", data["reference"]),
                   ("Prepared at", data["generated_at"])], styles),
        Spacer(1, 6),
        Paragraph(_esc(data["statute"]["signatories_required"]), styles["small"]),
        Spacer(1, 12),
    ]

    # ── Part A ──────────────────────────────────────────────────────────
    record = data["record"]
    story.append(Paragraph("PART A — TO BE FILLED BY THE PARTY", styles["part"]))
    story.append(Paragraph(
        "Particulars of the electronic record and the manner of its production, "
        "per section 63(4)(a) and (b).", styles["small"]))
    story.append(Spacer(1, 6))

    recheck = record["hash_recheck"]
    if recheck.get("checked"):
        recheck_text = ("Recomputed at the time of this document and it "
                        "<b>matches</b>." if recheck.get("matches") else
                        "<b>Recomputed and it DOES NOT MATCH</b> the recorded "
                        "value. This record must not be relied upon until the "
                        "discrepancy is explained.")
    else:
        recheck_text = _esc(recheck.get("reason"))

    story.append(_kv_table([
        ("Record identifier", "Scan #%s" % record["scan_id"]),
        ("Description", record["description"]),
        ("Produced at", record["produced_at"]),
        ("Produced by module", record["module"]),
        ("Submitted through account", record["submitted_by"]),
        ("Automated classification", "%s (score %s)" % (record["verdict"], record["score"])),
        ("Hash algorithm", record["hash_algorithm"]),
    ], styles))
    story.append(Spacer(1, 4))
    story.append(Paragraph("<b>Hash of the electronic record</b>", styles["body"]))
    story.append(Paragraph(_esc(record["hash"] or "NOT RECORDED"), styles["mono"]))
    story.append(Paragraph(recheck_text, styles["small"]))
    story.append(Spacer(1, 8))

    story.append(Paragraph("<b>Manner of production</b>", styles["body"]))
    story.append(Paragraph(_esc(record["manner_of_production"]), styles["body"]))
    story.append(Spacer(1, 10))

    device = data["device"]
    story.append(Paragraph("<b>Particulars of the device — s.63(4)(b)</b>", styles["body"]))
    story.append(_kv_table([
        ("Host", device["host"]),
        ("Operating system", device["operating_system"]),
        ("Architecture", device["architecture"]),
        ("Runtime", device["runtime"]),
        ("Application", device["application"]),
        ("Record store", device["database"]),
        ("Time zone", device["timezone"]),
    ], styles))

    # ── s.63(2) conditions ──────────────────────────────────────────────
    story.append(PageBreak())
    story.append(Paragraph("CONDITIONS UNDER SECTION 63(2)", styles["part"]))
    story.append(Paragraph(
        "The four conditions are set out verbatim. Beneath each is what the "
        "system can evidence in support of it. The certifying person adopts or "
        "corrects these statements; the software asserts none of them.",
        styles["small"]))
    story.append(Spacer(1, 8))

    for condition in data["conditions"]:
        block = [
            Paragraph("<b>(%s) %s</b>" % (condition["clause"], _esc(condition["heading"])),
                      styles["body"]),
            Paragraph("<i>%s</i>" % _esc(condition["text"]), styles["small"]),
            Spacer(1, 3),
            Paragraph("<b>Evidenced by:</b> %s" % _esc(condition["system_evidence"]),
                      styles["body"]),
            Spacer(1, 10),
        ]
        story.append(KeepTogether(block))

    # ── Custody ─────────────────────────────────────────────────────────
    story.append(Paragraph("CHAIN OF CUSTODY", styles["part"]))
    custody = data["custody"]
    if custody:
        rows = [[Paragraph("<b>Seq</b>", styles["small"]),
                 Paragraph("<b>Recorded at</b>", styles["small"]),
                 Paragraph("<b>Event</b>", styles["small"]),
                 Paragraph("<b>Actor</b>", styles["small"])]]
        rows += [[Paragraph("#%s" % e["seq"], styles["small"]),
                  Paragraph(_esc(e["timestamp"]), styles["small"]),
                  Paragraph(_esc((e["event"] or "").replace("_", " ")), styles["small"]),
                  Paragraph(_esc(e["actor"] or "system"), styles["small"])]
                 for e in custody]
        table = Table(rows, colWidths=[40, 120, 200, 140])
        table.setStyle(TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LINEBELOW", (0, 0), (-1, 0), 0.6, RULE),
            ("LINEBELOW", (0, 1), (-1, -2), 0.25, RULE),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]))
        story.append(table)
    else:
        story.append(Paragraph(
            "No audit-chain entry references this record, so no chain of "
            "custody can be exhibited.", styles["body"]))

    chain = data["chain"]
    story.append(Spacer(1, 8))
    story.append(Paragraph(
        ("Audit chain verified across %s entries at the time of preparation; "
         "each entry's stored hash matches a recomputation over its own "
         "contents and its predecessor's." % chain["entries_verified"])
        if chain["valid"] else
        ("<b>AUDIT CHAIN VERIFICATION FAILED</b> at sequence %s (%s). This "
         "certificate should not be issued until that is resolved."
         % (_esc(chain["broken_at"]), _esc(chain["reason"]))),
        styles["body"]))
    story.append(Paragraph("Chain head: %s" % _esc(chain["head"]), styles["mono"]))

    if data["verification_url"]:
        story.append(Spacer(1, 8))
        qr = evidence.qr_drawing(data["verification_url"], size=68)
        verify_cell = Paragraph(
            "<b>Independent verification</b><br/>Any holder of this document "
            "may confirm the record exists and that the chain around it is "
            "intact, without an account and without trusting the sender:<br/>"
            "<font size='7'>%s</font>" % _esc(data["verification_url"]),
            styles["body"])
        story.append(Table([[verify_cell, qr if qr is not None else ""]],
                           colWidths=[420, 80],
                           style=TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP")])))

    # ── Part B and signatures ───────────────────────────────────────────
    story.append(PageBreak())
    story.append(_signature_block(
        "PART A — DECLARATION BY THE PARTY",
        "I state that I have read and understood section 63 of the Bharatiya "
        "Sakshya Adhiniyam 2023; that I am the person in charge of the computer "
        "or communication device described above, or of the management of the "
        "relevant activities; and that the particulars stated in Part A are "
        "true to the best of my knowledge and belief.",
        styles))

    story.append(Spacer(1, 18))
    story.append(_signature_block(
        "PART B — DECLARATION BY THE EXPERT",
        "I state that I have examined the electronic record and the system "
        "described above; that the hash value stated in Part A corresponds to "
        "the record produced; and that the matters set out under section 63(2) "
        "are as stated.",
        styles))

    # ── Limits ──────────────────────────────────────────────────────────
    story.append(Spacer(1, 16))
    story.append(Paragraph("WHAT THIS DOCUMENT DOES NOT ESTABLISH", styles["part"]))
    for limit in data["limits"]:
        story.append(Paragraph("&bull; %s" % _esc(limit), styles["small"]))
        story.append(Spacer(1, 3))

    doc.build(story, onFirstPage=_footer, onLaterPages=_footer)
    pdf = buffer.getvalue()
    buffer.close()
    return pdf


def _footer(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(MUTED)
    canvas.drawString(48, 26, "Draft certificate under s.63(4), Bharatiya Sakshya Adhiniyam 2023 — unsigned")
    canvas.drawRightString(A4[0] - 48, 26, "Page %d" % canvas.getPageNumber())
    canvas.restoreState()
