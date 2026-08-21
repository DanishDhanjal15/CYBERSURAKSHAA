"""
services/intel/actions.py
-------------------------
The enforcement action pack.

The platform already produced an IT Act s.79(3)(b) blocking notice
(services/takedown_generator.py). That covers exactly one channel -- the
hosting intermediary -- and leaves the indicators that a cyber cell can most
effectively act on completely unused: the mule UPI address, the SIM behind the
number, the Telegram channel, the registrar.

This module maps each extracted indicator to the authority that can actually
act on it and renders the corresponding submission. Detection becomes
enforcement.

Channels
--------
    NCRP        National Cyber Crime Reporting Portal complaint bundle
    SANCHAR     DoT / TRAI number-blocking request (Sanchar Saathi / CEIR)
    BANK        Bank / PSP account and VPA freeze request routed via I4C
    REGISTRAR   Domain registrar abuse report
    HOSTING     Hosting provider / CERT-In abuse report
    PLATFORM    Telegram / Meta / Google Play content report
    IT_ACT      the existing s.79(3)(b) blocking notice

Accuracy discipline
-------------------
Every generated document is a *draft for an authorised officer to review and
sign*, and says so on its face. Recipient addresses that depend on the specific
registrar, bank or host are emitted as explicit [RESOLVE] placeholders rather
than guessed -- a legal notice sent to a fabricated address is worse than one
that was never generated. Only channels with a single, publicly documented
national entry point (NCRP, 1930, Sanchar Saathi) are pre-filled.
"""

from __future__ import annotations

import json
from datetime import datetime
from html import escape as _h

from services.intel.indicators import (
    KIND_PHONE, KIND_UPI, KIND_BANK_ACCT, KIND_IFSC, KIND_DOMAIN, KIND_URL,
    KIND_IP, KIND_TELEGRAM, KIND_WHATSAPP, KIND_CRYPTO, KIND_APK_CERT,
    KIND_LABELS,
)

# Channel identifiers
CH_NCRP = "NCRP"
CH_SANCHAR = "SANCHAR"
CH_BANK = "BANK"
CH_REGISTRAR = "REGISTRAR"
CH_HOSTING = "HOSTING"
CH_PLATFORM = "PLATFORM"
CH_IT_ACT = "IT_ACT"

PLACEHOLDER = "[RESOLVE: confirm current abuse contact before dispatch]"

# Publicly documented national entry points. These are stable, single-address
# channels -- anything registrar- or bank-specific is left as a placeholder.
NATIONAL_CHANNELS = {
    CH_NCRP: {
        "authority": "Indian Cyber Crime Coordination Centre (I4C), MHA",
        "portal": "https://cybercrime.gov.in",
        "helpline": "1930",
        "note": "File through the portal; this document is the supporting annexure.",
    },
    CH_SANCHAR: {
        "authority": "Department of Telecommunications (DoT)",
        "portal": "https://sancharsaathi.gov.in",
        "note": "Submit under the Chakshu / suspected-fraud-communication facility.",
    },
}

# Which channels each indicator kind can drive.
KIND_CHANNELS = {
    KIND_PHONE: [CH_SANCHAR, CH_NCRP],
    KIND_UPI: [CH_BANK, CH_NCRP],
    KIND_BANK_ACCT: [CH_BANK, CH_NCRP],
    KIND_IFSC: [CH_BANK],
    KIND_DOMAIN: [CH_REGISTRAR, CH_IT_ACT],
    KIND_URL: [CH_IT_ACT, CH_HOSTING],
    KIND_IP: [CH_HOSTING],
    KIND_TELEGRAM: [CH_PLATFORM],
    KIND_WHATSAPP: [CH_PLATFORM],
    KIND_CRYPTO: [CH_NCRP],
    KIND_APK_CERT: [CH_PLATFORM],
}

PLATFORM_ROUTES = {
    KIND_TELEGRAM: ("Telegram", "abuse@telegram.org / https://telegram.org/support"),
    KIND_WHATSAPP: ("Meta (WhatsApp)", "https://www.whatsapp.com/contact/ (report group)"),
    KIND_APK_CERT: ("Google Play", "https://support.google.com/googleplay/android-developer/"),
}


def _now_human():
    return datetime.now().strftime("%d %B %Y, %H:%M IST")


def _ref(prefix, seed):
    return "CS-%s-%s-%05d" % (prefix, datetime.now().strftime("%Y%m%d"), int(seed) % 100000)


# -- Channel builders ------------------------------------------------------

def _ncrp_action(indicators, context):
    """NCRP complaint annexure covering every financially actionable indicator."""
    relevant = [i for i in indicators
                if i["kind"] in (KIND_PHONE, KIND_UPI, KIND_BANK_ACCT, KIND_CRYPTO, KIND_URL, KIND_DOMAIN)]
    if not relevant:
        return None
    meta = NATIONAL_CHANNELS[CH_NCRP]
    return {
        "channel": CH_NCRP,
        "title": "NCRP complaint annexure",
        "authority": meta["authority"],
        "recipient": meta["portal"],
        "helpline": meta["helpline"],
        "urgency": "IMMEDIATE" if _has_money_trail(relevant) else "STANDARD",
        "indicators": relevant,
        "category": _ncrp_category(context),
        "instruction": (
            "Register the complaint at cybercrime.gov.in under the category above "
            "and attach this annexure. Where funds have already moved, call 1930 "
            "first -- the golden hour for a lien on the beneficiary account is the "
            "single largest determinant of recovery."
        ),
        "prefilled": True,
    }


def _has_money_trail(indicators):
    return any(i["kind"] in (KIND_UPI, KIND_BANK_ACCT, KIND_CRYPTO) for i in indicators)


def _ncrp_category(context):
    module = (context.get("module") or "").lower()
    if "invest" in module:
        return "Online Financial Fraud > Investment / Trading scam"
    if "care" in module or "custcare" in module:
        return "Online Financial Fraud > Vishing / Customer-care impersonation"
    if "bet" in module:
        return "Online Gambling / Betting"
    if "deepfake" in module or "voice" in module:
        return "Cyber Crime against Women & Children / Impersonation (s.66D IT Act)"
    return "Online Financial Fraud > Other"


def _sanchar_action(indicators, context):
    """DoT number-blocking request for every telephone indicator."""
    phones = [i for i in indicators if i["kind"] == KIND_PHONE]
    if not phones:
        return None
    meta = NATIONAL_CHANNELS[CH_SANCHAR]
    return {
        "channel": CH_SANCHAR,
        "title": "Suspected fraud communication report (number disconnection)",
        "authority": meta["authority"],
        "recipient": meta["portal"],
        "urgency": "HIGH",
        "indicators": phones,
        "instruction": (
            "Report each number through the Chakshu facility on Sanchar Saathi. "
            "Attach the scan evidence and the SHA-256 of the source artefact so "
            "the report is traceable to a specific piece of evidence."
        ),
        "prefilled": True,
    }


def _bank_action(indicators, context):
    """UPI / account freeze request. Routed via I4C rather than sent directly."""
    fin = [i for i in indicators if i["kind"] in (KIND_UPI, KIND_BANK_ACCT, KIND_IFSC)]
    if not fin:
        return None

    # The PSP handle identifies which bank sponsors the VPA, which is the one
    # piece of routing information that can be derived rather than guessed.
    psps = sorted({(i.get("meta") or {}).get("psp") for i in fin
                   if i["kind"] == KIND_UPI and (i.get("meta") or {}).get("psp")})
    ifsc_banks = sorted({i["normalized"][:4] for i in fin if i["kind"] == KIND_IFSC})

    return {
        "channel": CH_BANK,
        "title": "Beneficiary account / VPA freeze request",
        "authority": "Sponsor bank nodal officer, routed through I4C",
        "recipient": PLACEHOLDER,
        "urgency": "IMMEDIATE",
        "indicators": fin,
        "routing_hints": {
            "upi_psp_handles": psps,
            "ifsc_bank_codes": ifsc_banks,
        },
        "instruction": (
            "Identify the sponsor bank from the PSP handle / IFSC above and route "
            "the freeze request through the I4C ticket rather than contacting the "
            "branch directly. Request a lien, the beneficiary KYC, and the "
            "transaction trail for the preceding 72 hours."
        ),
        "prefilled": False,
    }


def _registrar_action(indicators, context):
    domains = [i for i in indicators if i["kind"] == KIND_DOMAIN]
    if not domains:
        return None
    return {
        "channel": CH_REGISTRAR,
        "title": "Domain registrar abuse report",
        "authority": "Sponsoring registrar (per WHOIS)",
        "recipient": PLACEHOLDER,
        "urgency": "HIGH",
        "indicators": domains,
        "instruction": (
            "Resolve the sponsoring registrar and its abuse contact from the "
            "current WHOIS record for each domain, then submit citing the ICANN "
            "Registrar Accreditation Agreement s.3.18 abuse-handling obligation. "
            "Include the registration date -- a domain days old carrying a bank's "
            "branding is the strongest single argument for immediate suspension."
        ),
        "prefilled": False,
    }


def _hosting_action(indicators, context):
    hosts = [i for i in indicators if i["kind"] in (KIND_IP, KIND_URL)]
    if not hosts:
        return None
    return {
        "channel": CH_HOSTING,
        "title": "Hosting provider abuse report",
        "authority": "Hosting provider / CERT-In",
        "recipient": PLACEHOLDER,
        "urgency": "STANDARD",
        "indicators": hosts,
        "instruction": (
            "Identify the hosting ASN for each address and submit to its abuse "
            "contact. Copy CERT-In where the content impersonates a regulated "
            "financial entity."
        ),
        "prefilled": False,
    }


def _platform_action(indicators, context):
    plat = [i for i in indicators if i["kind"] in PLATFORM_ROUTES]
    if not plat:
        return None
    routes = []
    for i in plat:
        name, contact = PLATFORM_ROUTES[i["kind"]]
        routes.append({"indicator": i["normalized"], "platform": name, "contact": contact})
    return {
        "channel": CH_PLATFORM,
        "title": "Platform content / channel report",
        "authority": "Hosting platform trust & safety",
        "recipient": "; ".join(sorted({r["platform"] for r in routes})),
        "urgency": "STANDARD",
        "indicators": plat,
        "routes": routes,
        "instruction": (
            "Report each channel or group through its platform reporting flow. "
            "Platform reports are the fastest channel available but carry no "
            "statutory force -- raise them in parallel with, never instead of, "
            "the s.79(3)(b) notice."
        ),
        "prefilled": True,
    }


def _it_act_action(indicators, context):
    web = [i for i in indicators if i["kind"] in (KIND_URL, KIND_DOMAIN)]
    if not web:
        return None
    return {
        "channel": CH_IT_ACT,
        "title": "IT Act s.79(3)(b) blocking notice",
        "authority": "MeitY / intermediary",
        "recipient": PLACEHOLDER,
        "urgency": "HIGH",
        "indicators": web,
        "instruction": (
            "Generate the signed notice from the scan record -- it carries the "
            "statutory language, the evidence hash and the 36-hour compliance "
            "clock. This action pack references it rather than duplicating it."
        ),
        "prefilled": True,
        "generator": "services/takedown_generator.py",
    }


_BUILDERS = (
    _ncrp_action,
    _sanchar_action,
    _bank_action,
    _registrar_action,
    _hosting_action,
    _platform_action,
    _it_act_action,
)

_URGENCY_ORDER = {"IMMEDIATE": 0, "HIGH": 1, "STANDARD": 2}


def build_action_pack(indicators, context=None):
    """
    Build every applicable enforcement action for a set of indicators.

    `indicators` is a list of dicts in the shape Indicator.to_dict() produces
    (so it works equally on freshly extracted indicators and on entity rows
    loaded back out of the graph).

    Returns {"actions": [...], "summary": {...}} sorted most urgent first.
    """
    context = context or {}
    norm = [_normalise_indicator(i) for i in (indicators or [])]
    norm = [i for i in norm if i]

    actions = []
    for build in _BUILDERS:
        try:
            action = build(norm, context)
        except Exception as e:
            print("[ACTIONS] builder %s failed: %s" % (getattr(build, "__name__", "?"), e))
            continue
        if action:
            action["ref"] = _ref(action["channel"][:4], context.get("scan_id") or len(actions) + 1)
            actions.append(action)

    actions.sort(key=lambda a: _URGENCY_ORDER.get(a.get("urgency"), 3))

    return {
        "actions": actions,
        "summary": {
            "total": len(actions),
            "immediate": sum(1 for a in actions if a.get("urgency") == "IMMEDIATE"),
            "channels": [a["channel"] for a in actions],
            "indicator_count": len(norm),
            "money_trail": _has_money_trail(norm),
            "requires_manual_recipient": [
                a["channel"] for a in actions if not a.get("prefilled")
            ],
        },
    }


def _normalise_indicator(i):
    """Accept Indicator, Indicator.to_dict(), or an entity row."""
    if i is None:
        return None
    if hasattr(i, "to_dict"):
        i = i.to_dict()
    if not isinstance(i, dict):
        return None
    kind = i.get("kind")
    value = i.get("normalized") or i.get("value")
    if not kind or not value:
        return None
    meta = i.get("meta")
    if isinstance(meta, str):
        try:
            meta = json.loads(meta)
        except Exception:
            meta = {}
    return {
        "kind": kind,
        "normalized": value,
        "raw": i.get("raw") or i.get("display") or value,
        "confidence": i.get("confidence", 1.0),
        "label": KIND_LABELS.get(kind, kind),
        "context": i.get("context", ""),
        "meta": meta or {},
    }


# -- Rendering -------------------------------------------------------------

def render_action_text(action, context=None):
    """Plain-text submission body -- copy-pasteable into a portal form."""
    context = context or {}
    lines = []
    lines.append("=" * 72)
    lines.append("CYBERSURAKSHAA -- ENFORCEMENT ACTION DRAFT")
    lines.append("=" * 72)
    lines.append("Reference      : %s" % action.get("ref", "-"))
    lines.append("Channel        : %s -- %s" % (action["channel"], action["title"]))
    lines.append("Authority      : %s" % action.get("authority", "-"))
    lines.append("Recipient      : %s" % action.get("recipient", PLACEHOLDER))
    lines.append("Urgency        : %s" % action.get("urgency", "STANDARD"))
    lines.append("Generated      : %s" % _now_human())
    if context.get("module"):
        lines.append("Source module  : %s" % context["module"])
    if context.get("verdict"):
        lines.append("Verdict        : %s (%s%%)" % (context["verdict"], context.get("score", "-")))
    if context.get("file_hash"):
        lines.append("Evidence hash  : SHA-256 %s" % context["file_hash"])
    lines.append("")
    lines.append("INDICATORS")
    lines.append("-" * 72)
    for i in action.get("indicators", []):
        lines.append("  %-28s %s" % (i["label"] + ":", i["normalized"]))
        if i.get("context"):
            lines.append("      seen in: %s" % i["context"][:100])
    if action.get("routing_hints"):
        lines.append("")
        lines.append("ROUTING HINTS")
        lines.append("-" * 72)
        for k, v in action["routing_hints"].items():
            if v:
                lines.append("  %-28s %s" % (k + ":", ", ".join(v)))
    if action.get("routes"):
        lines.append("")
        lines.append("PLATFORM ROUTES")
        lines.append("-" * 72)
        for r in action["routes"]:
            lines.append("  %-28s %s -- %s" % (r["indicator"], r["platform"], r["contact"]))
    lines.append("")
    lines.append("ACTION REQUIRED")
    lines.append("-" * 72)
    for chunk in _wrap(action.get("instruction", ""), 70):
        lines.append("  " + chunk)
    lines.append("")
    lines.append("-" * 72)
    lines.append("DRAFT -- NOT A DISPATCHED COMMUNICATION.")
    lines.append("Generated by an automated detection system. It must be reviewed,")
    lines.append("verified and signed by an authorised officer before submission.")
    lines.append("Automated verdicts are investigative leads, not findings of fact.")
    lines.append("=" * 72)
    return "\n".join(lines)


def _wrap(text, width):
    words = (text or "").split()
    if not words:
        return []
    out, line = [], words[0]
    for w in words[1:]:
        if len(line) + 1 + len(w) <= width:
            line += " " + w
        else:
            out.append(line)
            line = w
    out.append(line)
    return out


def render_pack_html(pack, context=None):
    """A single self-contained HTML page listing every action in the pack."""
    context = context or {}
    rows = []
    for a in pack["actions"]:
        ind_rows = "".join(
            "<tr><td class='k'>%s</td><td class='v'>%s</td></tr>"
            % (_h(i["label"]), _h(i["normalized"]))
            for i in a.get("indicators", [])
        )
        badge = {
            "IMMEDIATE": "background:#dc2626",
            "HIGH": "background:#f59e0b",
            "STANDARD": "background:#0ea5e9",
        }.get(a.get("urgency"), "background:#64748b")
        manual = "" if a.get("prefilled") else (
            "<p class='warn'>Recipient must be resolved manually before dispatch.</p>"
        )
        rows.append("""
        <section class="action">
          <header>
            <span class="badge" style="%s">%s</span>
            <h2>%s</h2>
            <code>%s</code>
          </header>
          <dl>
            <div><dt>Authority</dt><dd>%s</dd></div>
            <div><dt>Recipient</dt><dd>%s</dd></div>
          </dl>
          %s
          <table>%s</table>
          <p class="instruction">%s</p>
        </section>
        """ % (badge, _h(a.get("urgency", "")), _h(a["title"]), _h(a.get("ref", "")),
               _h(a.get("authority", "")), _h(a.get("recipient", "")),
               manual, ind_rows, _h(a.get("instruction", ""))))

    return """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Enforcement Action Pack — %s</title>
<style>
 *{box-sizing:border-box} body{margin:0;padding:32px;background:#0b1220;color:#e2e8f0;
   font-family:system-ui,-apple-system,'Segoe UI',sans-serif;line-height:1.6}
 .wrap{max-width:900px;margin:0 auto}
 h1{font-size:1.6rem;margin:0 0 4px} .sub{color:#94a3b8;margin:0 0 28px;font-size:.9rem}
 .action{background:#111c33;border:1px solid #1e293b;border-radius:12px;padding:20px;margin-bottom:18px}
 .action header{display:flex;align-items:center;gap:12px;flex-wrap:wrap;margin-bottom:12px}
 .action h2{font-size:1.05rem;margin:0;flex:1}
 .badge{color:#fff;font-size:.7rem;font-weight:700;padding:3px 9px;border-radius:999px;letter-spacing:.04em}
 code{background:#0b1220;padding:3px 8px;border-radius:6px;font-size:.75rem;color:#7dd3fc}
 dl{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin:0 0 12px}
 dt{color:#94a3b8;font-size:.72rem;text-transform:uppercase;letter-spacing:.05em}
 dd{margin:0;font-size:.9rem}
 table{width:100%%;border-collapse:collapse;margin:8px 0;font-size:.85rem}
 td{padding:6px 8px;border-bottom:1px solid #1e293b}
 td.k{color:#94a3b8;width:40%%} td.v{font-family:ui-monospace,monospace;color:#7dd3fc;word-break:break-all}
 .instruction{background:#0b1220;border-left:3px solid #38bdf8;padding:10px 14px;
   border-radius:0 8px 8px 0;font-size:.85rem;color:#cbd5e1}
 .warn{background:#3f1d1d;border-left:3px solid #ef4444;padding:8px 14px;
   border-radius:0 8px 8px 0;font-size:.8rem;color:#fca5a5;margin:8px 0}
 footer{margin-top:28px;padding:16px;border:1px dashed #475569;border-radius:10px;
   color:#94a3b8;font-size:.8rem}
 @media(max-width:640px){dl{grid-template-columns:1fr}body{padding:18px}}
</style></head><body><div class="wrap">
<h1>Enforcement Action Pack</h1>
<p class="sub">%d action(s) &middot; %d indicator(s) &middot; generated %s</p>
%s
<footer><strong>Draft documents.</strong> Every item above was produced by an
automated detection system from a single artefact. They are investigative
leads, not findings of fact, and must be reviewed, verified and signed by an
authorised officer before any submission or dispatch.</footer>
</div></body></html>""" % (
        _h(str(context.get("scan_id", ""))),
        pack["summary"]["total"], pack["summary"]["indicator_count"],
        _h(_now_human()), "".join(rows),
    )
