"""
services/intel/lending.py
-------------------------
Predatory lending apps, and the harassment that is their business model.

Why this is a distinct detector
===============================
`services/intel/apk.py` already parses a binary manifest, weights permissions
and mines package strings. It was built for betting apps, and it scores a
loan app as unremarkable — READ_SMS and READ_CONTACTS look like ordinary
over-permissioning rather than what they actually are here.

For a lending app they are the product. The extortion model works like this:
the app takes the borrower's entire contact list and photo gallery at install
time; a small sum is disbursed at a punitive rate over a very short tenure;
and on or before the due date the operator threatens to contact everybody the
borrower knows, and frequently does — sometimes attaching morphed images. The
loan is the pretext. The contact list is the collateral.

The regulatory hook that makes this checkable
=============================================
The **RBI Guidelines on Digital Lending (2 September 2022)** are unusually
specific, which turns a judgement call into an objective test:

* a Digital Lending App must **not access the borrower's contact list, media
  and files, or call logs** — camera, microphone and location only on one-time
  explicit consent for KYC;
* the app must **disclose upfront the name of the Regulated Entity** (bank or
  NBFC) on whose behalf it lends;
* a Key Fact Statement with the all-inclusive **Annual Percentage Rate** must
  be given before execution.

So an APK that presents itself as a lender and requests `READ_CONTACTS` is not
merely suspicious. It is asking for a permission the guidelines prohibit it
from using, and that is a finding rather than an inference.

On the whitelist
================
RBI publishes the registered NBFCs and a repository of the DLAs that regulated
entities operate. That list changes constantly and is not shipped here — a
stale whitelist would clear an app that has since been delisted, which is
worse than having none. `set_registered_entities()` loads one when a
deployment has a current copy; absent that, the module reports that it could
not check registration rather than implying the app is unregistered.
"""

from __future__ import annotations

import re

from services.intel import multilingual

# ── Is this a lending app at all? ────────────────────────────────────────
#
# Checked before anything else. The permission findings below only mean what
# they mean if the app is presenting itself as a lender; a messaging app
# reading contacts is doing its job.

LENDING_TERMS = (
    "loan", "lend", "credit", "borrow", "cash advance", "instant cash",
    "quick cash", "paisa", "rupee", "rupya", "emi", "repay", "repayment",
    "disburse", "disbursal", "tenure", "interest rate", "processing fee",
    "credit limit", "personal loan", "salary advance", "payday",
    "nbfc", "lender", "loan amount", "due date", "overdue", "default",
)

# Naming conventions these apps cluster around.
LENDING_NAME_HINTS = (
    "loan", "cash", "credit", "rupee", "rupya", "paisa", "money", "wallet",
    "lend", "borrow", "kredit", "coin", "gold", "instant", "quick", "fast",
)

# ── Permissions the RBI guidelines prohibit a DLA from using ─────────────
#
# Weight reflects the extortion capability each one confers, not generic
# privacy risk. Contacts and media are what the threat is *made of*.

PROHIBITED_PERMISSIONS = {
    "android.permission.READ_CONTACTS": (
        35, "Reads the borrower's entire contact list — the collateral in a "
            "contact-shaming operation, and expressly outside what the RBI "
            "Digital Lending Guidelines permit a lending app to access."),
    "android.permission.WRITE_CONTACTS": (
        20, "Modifies contacts. No lending function requires this."),
    "android.permission.READ_SMS": (
        30, "Reads SMS. Used to scrape bank balances and transaction alerts to "
            "size the loan, and to intercept OTPs."),
    "android.permission.RECEIVE_SMS": (25, "Receives SMS, enabling OTP interception."),
    "android.permission.READ_EXTERNAL_STORAGE": (
        30, "Reads the photo gallery — the source of the images used in morphed "
            "shaming material. Prohibited for a DLA."),
    "android.permission.READ_MEDIA_IMAGES": (
        30, "Reads gallery images. Prohibited for a DLA."),
    "android.permission.READ_CALL_LOG": (
        25, "Reads call history, prohibited for a DLA and useful only for "
            "identifying who matters to the borrower."),
    "android.permission.READ_PHONE_STATE": (
        10, "Reads device and subscriber identifiers."),
    "android.permission.GET_ACCOUNTS": (
        15, "Enumerates accounts configured on the device."),
}

# Permissions that are defensible for a lender with one-time KYC consent, so
# their presence is recorded without being scored as a violation.
KYC_PERMISSIONS = {
    "android.permission.CAMERA": "Permitted for one-time KYC capture with explicit consent.",
    "android.permission.ACCESS_FINE_LOCATION": "Permitted for one-time KYC with explicit consent.",
    "android.permission.RECORD_AUDIO": "Permitted only for a specific, consented purpose.",
}

# ── The harassment itself ────────────────────────────────────────────────
#
# Same (regex, weight, label) shape as the other banks in this codebase, so it
# concatenates with the Hinglish bank — see multilingual.py:176-177. These
# messages arrive overwhelmingly in Hinglish.

HARASSMENT_PATTERNS = [
    # Contact-list threats. The signature of the whole model.
    (r"(?i)\b(?:all|sabhi|saare)?\s*(?:your|aapke|tumhare)?\s*contacts?\s+"
     r"(?:will be|honge|ko)\s*(?:informed|inform|notified|message|pata chal)",
     35, "Threat to contact the borrower's entire address book"),
    (r"(?i)\bwe have (?:your|all your) (?:contact|phone ?book|contact list)",
     35, "States the operator holds the borrower's contact list"),
    (r"(?i)\b(?:inform|call|message|whatsapp)\s+(?:your\s+)?"
     r"(?:family|friends|relatives|parents|office|employer|colleagues|ghar\s*wale)",
     30, "Threat to contact family, employer or friends"),
    (r"(?i)\b(?:reference|emergency contact)s?\s+(?:will be|ko)\s*(?:called|call|inform)",
     25, "Threat to call the borrower's stated references"),

    # Image-based coercion.
    (r"(?i)\b(?:your\s+)?(?:photo|photograph|picture|image|tasveer)\s+"
     r"(?:will be|ko)\s*(?:sent|send|share|viral|bhej)",
     40, "Threat to circulate the borrower's photograph"),
    (r"(?i)\b(?:morph|edit|nude|obscene|nangi|ashleel)\w*\s+"
     r"(?:photo|image|picture|video)",
     45, "Reference to morphed or obscene imagery of the borrower"),

    # Public shaming.
    (r"(?i)\b(?:defaulter|fraudster|chor|thief|cheater)\b.{0,40}"
     r"(?:declare|announce|list|poster|group)",
     30, "Threat to publicly label the borrower a defaulter or thief"),
    (r"(?i)\b(?:group|whatsapp group)\s+(?:banaya|created|bana|will be made)"
     r".{0,40}(?:contact|friend|family)",
     30, "Threat to create a group containing the borrower's contacts"),

    # Fabricated legal process. These bodies do not work this way.
    (r"(?i)\b(?:arrest|giraftar|warrant|non[- ]bailable)\b",
     25, "Threat of arrest for a civil debt"),
    (r"(?i)\b(?:lok adalat|court|adalat|summons|legal notice|case file)\b.{0,30}"
     r"(?:issued|filed|dayar|bheja)",
     20, "Claim that legal process has been initiated"),
    (r"(?i)\b(?:cyber ?cell|police|thana|fir)\b.{0,30}"
     r"(?:complaint|shikayat|report|darj)",
     20, "Claim that a police complaint has been filed over a loan"),

    # Coercive framing.
    (r"(?i)\bpay\s+(?:within|in)\s+\d+\s*(?:hour|minute|hrs?|min)",
     20, "Demand for payment within hours"),
    (r"(?i)\b(?:last|final|aakhri)\s+(?:warning|chance|notice|mauka)",
     15, "Final-warning framing"),
    (r"(?i)\b(?:consequences|anjaam|bhugatna)\b",
     15, "Veiled threat of consequences"),
]

# Rate framing that signals a punitive product regardless of harassment.
PREDATORY_TERMS = [
    (r"(?i)\b(?:7|seven|14|fourteen)\s*(?:day|din)s?\s*(?:tenure|loan|repay)",
     15, "Very short tenure typical of a payday-style product"),
    (r"(?i)\bprocessing fee\b.{0,30}\b(?:2[5-9]|[3-9]\d)\s*%", 20,
     "Processing fee of a quarter or more of the principal"),
    (r"(?i)\bno\s+(?:documents?|kyc|paperwork|credit\s*(?:score|check))\s+"
     r"(?:required|needed|chahiye)",
     15, "Claims no documentation or credit check is required"),
    (r"(?i)\binstant\s+(?:approval|disbursal|loan|cash)\b", 10,
     "Instant-disbursal promise"),
]

MAX_SCORE = 100

# Registered entities, loaded by a deployment that has a current list.
_REGISTERED_ENTITIES = set()


def set_registered_entities(names):
    """
    Load the RBI-registered entity names a deployment holds.

    Deliberately not shipped with the code. RBI's register of NBFCs and the
    repository of regulated entities' lending apps both change constantly, and
    a stale whitelist would clear an app that has since been delisted — a
    worse failure than having no list at all.
    """
    global _REGISTERED_ENTITIES
    _REGISTERED_ENTITIES = {str(n).strip().lower() for n in (names or []) if str(n).strip()}
    return len(_REGISTERED_ENTITIES)


def registered_entity_count():
    return len(_REGISTERED_ENTITIES)


# ── Detection ────────────────────────────────────────────────────────────

def looks_like_lending(strings, package=None, app_label=None):
    """
    Whether the artefact presents itself as a lender.

    Everything else in this module is conditional on this: a messaging app
    reading contacts is doing its job, and scoring it as a predatory lender
    would be a false accusation.
    """
    haystack = " ".join(str(s).lower() for s in (strings or []))
    hits = sorted({t for t in LENDING_TERMS if t in haystack})

    name = "%s %s" % (package or "", app_label or "")
    name_hits = sorted({h for h in LENDING_NAME_HINTS if h in name.lower()})

    # Two independent vocabulary hits, or one plus a naming signal. A single
    # occurrence of "credit" is not a lending app.
    confident = len(hits) >= 2 or (hits and name_hits)
    return {
        "is_lending": bool(confident),
        "terms": hits[:12],
        "name_signals": name_hits,
        "reason": ("Presents as a lending application: %s" % ", ".join(hits[:6]))
                  if confident else
                  "Does not present as a lending application.",
    }


def check_registration(strings):
    """
    Whether a Regulated Entity is named, as the guidelines require.

    Three outcomes, kept distinct: named and on the loaded list; named but not
    on it; and no list loaded, in which case the honest answer is that
    registration could not be checked.
    """
    haystack = " ".join(str(s).lower() for s in (strings or []))

    # An RE must be disclosed upfront, so the name appears in the package.
    named = sorted({n for n in _REGISTERED_ENTITIES if n and n in haystack})

    mentions_nbfc = bool(re.search(r"(?i)\b(?:nbfc|non[- ]banking financial|"
                                   r"regulated entity|rbi[- ]registered)\b", haystack))

    if not _REGISTERED_ENTITIES:
        return {
            "checked": False,
            "named_entities": [],
            "mentions_regulation": mentions_nbfc,
            "note": ("No register of RBI-regulated entities is loaded on this "
                     "deployment, so registration could not be checked. This is "
                     "not evidence the operator is unregistered."),
        }

    return {
        "checked": True,
        "named_entities": named,
        "mentions_regulation": mentions_nbfc,
        "note": ("Names a regulated entity from the loaded register: %s"
                 % ", ".join(named)) if named else
                ("No entity from the loaded register is named in the package. "
                 "The RBI Digital Lending Guidelines require the lending "
                 "entity to be disclosed upfront."),
    }


def assess_permissions(permissions):
    """Score the permissions against what a DLA is permitted to access."""
    granted = set(permissions or [])
    violations, kyc = [], []
    score = 0

    for perm, (weight, why) in PROHIBITED_PERMISSIONS.items():
        if perm in granted:
            score += weight
            violations.append({"permission": perm, "weight": weight, "why": why})

    for perm, why in KYC_PERMISSIONS.items():
        if perm in granted:
            kyc.append({"permission": perm, "note": why})

    violations.sort(key=lambda v: -v["weight"])

    # The combination is the extortion kit, and is worse than its parts.
    has_contacts = "android.permission.READ_CONTACTS" in granted
    has_media = bool(granted & {"android.permission.READ_EXTERNAL_STORAGE",
                                "android.permission.READ_MEDIA_IMAGES"})
    if has_contacts and has_media:
        score += 20
        violations.append({
            "permission": "READ_CONTACTS + gallery access", "weight": 20,
            "why": ("Together these are the complete toolkit for contact "
                    "shaming: who the borrower knows, and pictures of the "
                    "borrower to send them."),
        })

    return {"score": min(score, MAX_SCORE), "violations": violations,
            "kyc_permissions": kyc}


def score_harassment(text):
    """
    Score a recovery message for coercion.

    Runs against every normalised form — these arrive in Hinglish far more
    often than in English, and `multilingual.normalise()` already produces the
    transliterated and deobfuscated variants.
    """
    if not text:
        return {"score": 0, "matched": [], "reasons": []}

    forms = multilingual.normalise(text)
    haystacks = {forms["canonical"].lower(), forms["deobfuscated"].lower(),
                 forms["transliterated"].lower(), forms["original"].lower()}

    score, matched, reasons = 0, [], []
    for pattern, weight, label in HARASSMENT_PATTERNS + PREDATORY_TERMS:
        if label in matched:
            continue
        for hay in haystacks:
            if re.search(pattern, hay):
                score += weight
                matched.append(label)
                reasons.append(label)
                break

    return {"score": min(score, MAX_SCORE), "matched": matched, "reasons": reasons}


def analyse_app(apk_result):
    """
    Assess an APK already parsed by `services/intel/apk.py`.

    Takes that module's output rather than re-parsing, so the binary manifest
    work is done once and this layer only adds the lending-specific judgement.
    """
    apk_result = apk_result or {}
    strings = list(apk_result.get("strings", []) or [])
    strings += [apk_result.get("package") or "", apk_result.get("app_label") or ""]
    strings += [t for t in (apk_result.get("betting_terms") or [])]

    lending = looks_like_lending(strings, apk_result.get("package"),
                                 apk_result.get("app_label"))
    if not lending["is_lending"]:
        return {
            "is_lending_app": False,
            "score": 0,
            "verdict": "NOT_A_LENDING_APP",
            "lending": lending,
            "note": ("Permission findings are not raised because this package "
                     "does not present as a lender. An application that reads "
                     "contacts for its own stated purpose is not doing what "
                     "this module looks for."),
        }

    permissions = assess_permissions(apk_result.get("permissions"))
    registration = check_registration(strings)

    score = permissions["score"]
    reasons = [v["why"] for v in permissions["violations"]]

    # Failing to name a lender is a guideline breach in its own right, but only
    # scored where a register was actually consulted.
    if registration["checked"] and not registration["named_entities"]:
        score += 20
        reasons.append("No RBI-regulated entity is named in the package, which "
                       "the Digital Lending Guidelines require to be disclosed "
                       "upfront.")

    score = min(score, MAX_SCORE)
    if score >= 70:
        verdict = "PREDATORY_LENDING"
    elif score >= 40:
        verdict = "SUSPICIOUS_LENDING"
    else:
        verdict = "LENDING_APP"

    return {
        "is_lending_app": True,
        "score": score,
        "verdict": verdict,
        "lending": lending,
        "permissions": permissions,
        "registration": registration,
        "reasons": reasons,
        "recommendation": _recommendation(verdict, permissions, registration),
        "basis": ("RBI Guidelines on Digital Lending, 2 September 2022: a "
                  "digital lending app must not access the borrower's contact "
                  "list, media and files, or call logs, and must disclose the "
                  "regulated entity on whose behalf it lends."),
    }


def _recommendation(verdict, permissions, registration):
    if verdict == "PREDATORY_LENDING":
        steps = [
            "Report the distribution URL and package to MeitY for blocking, "
            "and to the app store hosting it.",
            "Report to RBI's Sachet portal, which receives complaints about "
            "unauthorised lending, and to the state cyber cell.",
            "Where contact shaming has already occurred, the conduct may "
            "attract IT Act s.66E and s.67 alongside Bharatiya Nyaya Sanhita "
            "2023 s.351 (criminal intimidation) — for an officer to assess, "
            "not this system.",
        ]
        if permissions["violations"]:
            steps.insert(1, "The permission set is itself the evidence: it "
                            "records what the operator equipped itself to do "
                            "before any borrower defaulted.")
        return steps
    if verdict == "SUSPICIOUS_LENDING":
        return ["Verify whether the operator is a regulated entity or acts for "
                "one before treating the app as legitimate.",
                "Check whether a Key Fact Statement with the annual percentage "
                "rate is presented before the loan is executed."]
    return ["No prohibited permission was requested. Registration and the "
            "advertised rate should still be checked against RBI's register "
            "before the app is treated as safe."]


def victim_guidance():
    """
    What to tell somebody already being harassed.

    Separate from the detection because it is the part that helps a person,
    and because the advice is the same whatever the app scored.
    """
    return {
        "title": "If a lending app is threatening you",
        "points": [
            "Do not pay more to stop the threats. Payment does not end them; "
            "in this model it establishes that pressure works.",
            "A loan is a civil matter. Nobody can be arrested for defaulting, "
            "and a recovery agent claiming a warrant, a court case or a police "
            "complaint is almost always lying.",
            "Contacting your friends, family or employer about your debt is "
            "unlawful. So is any threat to circulate your photographs.",
            "Preserve everything: screenshots of the messages, the caller "
            "numbers, the app listing and its permission screen. Do not delete "
            "the app before capturing what it asked for.",
            "Report at cybercrime.gov.in and to your state cyber cell. Where "
            "obscene or morphed images are involved, say so explicitly — it "
            "changes which provisions apply.",
            "Complain to RBI through the Sachet portal if the lender is not a "
            "regulated entity, and to the app store that distributed it.",
        ],
        "note": ("This is general information about how these operations work, "
                 "not legal advice on any particular case."),
    }
