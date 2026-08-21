"""
services/intel/jobfraud.py
--------------------------
Employment fraud, and the one case where it is not fraud at all.

The rule the whole module rests on
==================================
**A genuine employer does not charge a candidate to be hired.** Not a
registration fee, not a security deposit, not a refundable kit charge, not a
"training fee adjusted against your first salary". Recruitment costs are borne
by the employer. Fee-charging placement agencies exist and are lawful, but they
are licensed, they contract with the *candidate* in writing beforehand, and
they do not appear unsolicited on WhatsApp.

That single rule decides most cases, and it decides them without needing to
know anything about the company. It is far more reliable than trying to tell a
real offer letter from a forged one, because the forgery is usually excellent —
the logo is lifted from the real site and the letter is a copy of a real one.

The case that is not fraud
==========================
A subset of "overseas data entry" and "customer support in Bangkok" offers are
not employment fraud. They are **trafficking**. Recruits are flown to Thailand
on a tourist visa, moved overland into scam compounds in Myanmar, Cambodia or
Laos, and held there to run the very frauds this platform detects — passports
taken, quotas enforced by beating. The Ministry of External Affairs and Indian
missions in the region have issued repeated advisories about it.

This matters here for one practical reason: the advice is completely different.
An advance-fee job scam costs the victim a few thousand rupees and the answer
is "do not pay". This costs them their liberty, the answer is "do not travel",
and once they have travelled it stops being a cybercrime matter and becomes a
consular one. Scoring it as ordinary job fraud would bury the only finding on
the page that matters, so it is ranked above everything else regardless of
score.

What this does not claim
========================
It cannot tell you a company is fake. It has no register of employers, and one
built from a web scrape would be worse than none — it would clear a fraudster
who registered a shell company and condemn a real small business that has no
web presence. It reports what the *approach* does, which is observable, and
leaves the identity of the employer to be verified by the reader against
sources this module deliberately does not pretend to have.
"""

from __future__ import annotations

import re

from services.intel import multilingual

# ── Finding kinds, most severe first ─────────────────────────────────────

K_TRAFFICKING = "TRAFFICKING_RISK"
K_ADVANCE_FEE = "ADVANCE_FEE"
K_CREDENTIAL = "CREDENTIAL_HARVEST"
K_FAKE_OFFER = "FAKE_OFFER"
K_TASK_BAIT = "TASK_SCAM_BAIT"
K_PRESSURE = "PRESSURE"

KIND_ORDER = [K_TRAFFICKING, K_ADVANCE_FEE, K_CREDENTIAL,
              K_FAKE_OFFER, K_TASK_BAIT, K_PRESSURE]

KIND_LABELS = {
    K_TRAFFICKING: "Possible trafficking recruitment, not ordinary job fraud",
    K_ADVANCE_FEE: "Candidate asked to pay",
    K_CREDENTIAL: "Identity or banking details sought before any offer",
    K_FAKE_OFFER: "Offer letter or employer identity does not hold up",
    K_TASK_BAIT: "Task-scam recruitment wearing a job advert",
    K_PRESSURE: "Pressure and secrecy applied to a hiring decision",
}

# ── Pattern bank ─────────────────────────────────────────────────────────
#
# (regex, weight, kind, label). Weights are deliberately uneven: paying money
# is close to dispositive, whereas "urgent hiring" is background noise in a
# real job market and scores accordingly.

PATTERNS = [
    # -- Trafficking recruitment -----------------------------------------
    # The tell is not the country. It is a package that would make no
    # commercial sense for the work described: an employer flying a stranger
    # abroad, on a tourist visa, for data entry.
    (r"(?i)\b(?:data entry|typing|customer (?:support|service)|telecall\w*|"
     r"crypto|forex)\b.{0,80}\b(?:thailand|bangkok|myanmar|burma|cambodia|"
     r"phnom penh|laos|vientiane|poipet|sihanoukville|myawaddy|mae sot|"
     r"golden triangle)\b",
     55, K_TRAFFICKING,
     "Low-skill role advertised in a region associated with scam compounds"),
    (r"(?i)\b(?:tourist|visit)\s+visa\b.{0,60}\b(?:job|work|joining|convert)",
     55, K_TRAFFICKING,
     "Travel on a tourist visa to take up work — no lawful employer arranges this"),
    (r"(?i)\b(?:ticket|flight|visa|travel)\s+(?:free|paid|arranged|sponsored)"
     r"\b.{0,60}\b(?:company|employer|hr|agent)\b",
     35, K_TRAFFICKING,
     "Employer offers to fly a stranger abroad before any verified contract"),
    (r"(?i)\b(?:passport|original documents?)\b.{0,50}\b(?:hand over|submit|"
     r"deposit|jama|keep|custody|company will hold)",
     50, K_TRAFFICKING,
     "Passport to be surrendered — the mechanism by which people are held"),
    (r"(?i)\b(?:no|without)\s+(?:experience|degree|english)\b.{0,60}"
     r"\b(?:salary|package)\b.{0,30}\b(?:\$|usd|lakh|1[0-9]{5,})",
     30, K_TRAFFICKING,
     "Salary far above the market rate for a role requiring no qualification"),

    # -- Advance fee ------------------------------------------------------
    (r"(?i)\b(?:registration|regis\w*|application|processing|joining|"
     r"onboarding)\s+(?:fee|charges?|amount|payment)\b",
     50, K_ADVANCE_FEE,
     "Registration or joining fee demanded from the candidate"),
    (r"(?i)\b(?:security|caution|refundable)\s+(?:deposit|amount|money)\b",
     50, K_ADVANCE_FEE,
     "Security deposit demanded — refundable deposits are not a hiring practice"),
    (r"(?i)\b(?:training|course|certification|kit|laptop|id card|uniform)\s+"
     r"(?:fee|charges?|cost)\b.{0,40}\b(?:pay|deposit|transfer|bhejo|jama)",
     45, K_ADVANCE_FEE,
     "Candidate to pay for training, equipment or an ID card"),
    (r"(?i)\b(?:adjust\w*|refund\w*|deduct\w*)\b.{0,40}\b(?:first|1st)\s+"
     r"(?:salary|month)",
     40, K_ADVANCE_FEE,
     "Fee said to be refunded from the first salary — the standard reassurance"),
    (r"(?i)\b(?:pay|deposit|transfer|send)\b.{0,25}\b(?:rs\.?|inr|₹)\s*"
     r"[\d,]{3,}.{0,40}\b(?:job|joining|position|seat|offer|interview)\b",
     45, K_ADVANCE_FEE,
     "A specific sum to be paid in connection with the job"),
    (r"(?i)\b(?:google\s*pay|gpay|phonepe|paytm|upi|qr\s*code)\b.{0,50}"
     r"\b(?:hr|recruiter|company|fee|joining)\b",
     35, K_ADVANCE_FEE,
     "Payment routed to a personal UPI handle rather than a company account"),

    # -- Credential and identity harvesting -------------------------------
    (r"(?i)\b(?:aadhaar|aadhar|pan card|pan number)\b.{0,60}"
     r"\b(?:before|for)\s+(?:the\s+)?(?:interview|shortlist\w*|registration)",
     40, K_CREDENTIAL,
     "Aadhaar or PAN demanded before any interview has taken place"),
    (r"(?i)\b(?:bank\s+(?:account|detail)|account number|ifsc|cancelled cheque)"
     r"\b.{0,60}\b(?:before|to\s+confirm|for\s+registration|to\s+proceed)",
     40, K_CREDENTIAL,
     "Bank details sought before an offer exists"),
    (r"(?i)\b(?:otp|one[- ]time password|cvv|atm pin|card number)\b",
     50, K_CREDENTIAL,
     "OTP, CVV or PIN requested — no employer has any use for these, ever"),
    (r"(?i)\b(?:selfie|photo|video)\s+(?:with|holding)\s+(?:your\s+)?"
     r"(?:aadhaar|aadhar|pan|id|passport)",
     45, K_CREDENTIAL,
     "Selfie holding an identity document — the input to opening a mule account"),
    (r"(?i)\b(?:anydesk|teamviewer|quick\s*support|screen\s*shar\w+|"
     r"remote\s+access)\b",
     50, K_CREDENTIAL,
     "Remote-access software requested during a hiring process"),

    # -- Fake offer / employer identity -----------------------------------
    (r"(?i)\boffer letter\b.{0,80}\b(?:@gmail|@yahoo|@outlook|@hotmail|"
     r"@rediffmail|@protonmail)\b",
     45, K_FAKE_OFFER,
     "Offer letter sent from a free mail account rather than a company domain"),
    (r"(?i)\b(?:hr|recruiter|manager)\b.{0,40}\b(?:@gmail|@yahoo|@outlook|"
     r"@hotmail|@rediffmail)\b",
     30, K_FAKE_OFFER,
     "Recruiter using a free mail account"),
    (r"(?i)\bselected\b.{0,60}\b(?:without|no)\s+(?:interview|test|"
     r"further process)",
     45, K_FAKE_OFFER,
     "Selection announced without any interview"),
    (r"(?i)\byour (?:resume|cv|profile) (?:was |has been )?"
     r"(?:shortlisted|selected|picked)\b.{0,60}\b(?:naukri|shine|indeed|"
     r"monster|linkedin|portal)\b",
     20, K_FAKE_OFFER,
     "Claims to have taken the CV from a job portal — trivially assertable"),
    (r"(?i)\b(?:interview|selection)\s+(?:will be|is)\s+(?:on|via|through|over)"
     r"\s+(?:whatsapp|telegram|chat|text)\b",
     35, K_FAKE_OFFER,
     "Interview conducted entirely by text message"),
    (r"(?i)\b(?:work from home|wfh)\b.{0,60}\b(?:no\s+(?:experience|skill|"
     r"qualification)|anyone can)\b.{0,60}\b(?:\d{4,}|lakh|salary)",
     25, K_FAKE_OFFER,
     "Work-from-home role with no requirements and a quoted salary"),

    # -- Task-scam recruitment --------------------------------------------
    # A job advert is often just the doorway to the task scam that
    # lifecycle.py classifies. Naming it here routes the reader there.
    (r"(?i)\b(?:like|rate|review|subscribe|watch)\s+(?:videos?|hotels?|"
     r"products?|links?)\b.{0,50}\b(?:earn|income|per day|daily|payment)",
     45, K_TASK_BAIT,
     "Paid-per-task work — the recruitment doorway of the task scam"),
    (r"(?i)\b(?:daily|roz|per day)\s+(?:income|earning|payout|kamai)\b.{0,25}"
     r"(?:rs\.?|inr|₹)?\s*[\d,]{3,}",
     35, K_TASK_BAIT,
     "A guaranteed daily income figure"),
    (r"(?i)\b(?:prepaid|advance)\s+task\b",
     45, K_TASK_BAIT,
     "The prepaid-task mechanic, in which the candidate funds the task"),
    (r"(?i)\b(?:telegram|whatsapp)\s+(?:group|channel)\b.{0,50}"
     r"\b(?:join|add)\b.{0,40}\b(?:work|task|job|earn)",
     25, K_TASK_BAIT,
     "Work coordinated through a group chat"),

    # -- Pressure and secrecy ---------------------------------------------
    (r"(?i)\b(?:only|last)\s+\d+\s+(?:seats?|posts?|vacanc\w+|slots?)\s+"
     r"(?:left|remaining|available)",
     20, K_PRESSURE,
     "Artificial scarcity applied to a vacancy"),
    (r"(?i)\b(?:confirm|pay|reply)\s+(?:within|in)\s+\d+\s*"
     r"(?:hours?|hrs?|minutes?|mins?)\b",
     25, K_PRESSURE,
     "A deadline measured in hours on a hiring decision"),
    (r"(?i)\b(?:do not|don'?t)\s+(?:tell|share|discuss)\b.{0,40}"
     r"\b(?:anyone|family|parents|friends)\b",
     35, K_PRESSURE,
     "Candidate told to keep the offer secret"),
    (r"(?i)\b(?:govt|government|railway|ssc|upsc|police|bank)\s+"
     r"(?:job|vacancy|post|recruitment)\b.{0,60}\b(?:guarantee\w*|confirm\w*|"
     r"fix|setting|direct)\b",
     45, K_PRESSURE,
     "A guaranteed government post — these are filled only by public examination"),
]

# Terms that say this text is about employment at all. Without one of these
# the module returns nothing rather than reading a bank phishing SMS as a bad
# job offer.
JOB_TERMS = (
    "job", "jobs", "vacancy", "vacancies", "hiring", "recruit", "recruitment",
    "employment", "offer letter", "appointment letter", "interview", "resume",
    "cv ", "candidate", "salary", "joining", "post ", "position", "career",
    "work from home", "wfh", "part time", "part-time", "internship", "intern",
    "naukri", "rozgar", "bharti", "bharati", "placement", "hr ", "employer",
)

# Above this the finding is stated plainly rather than hedged.
STRONG_SCORE = 60


def looks_like_a_job_offer(text):
    """
    Gate. Everything below is meaningless applied to text that is not about
    employment, and "security deposit" appears in plenty of honest contexts.
    """
    if not text:
        return False
    low = " %s " % text.lower()
    return any(term in low for term in JOB_TERMS)


def analyse(text):
    """
    Score an employment approach.

    Returns the kind of problem rather than a single number, because the
    kinds do not share a response. A trafficking finding is surfaced above
    everything else no matter what the arithmetic says — it is the only one
    where the cost of being late is not measured in money.
    """
    if not text or not text.strip():
        return _empty("No text was supplied.")

    if not looks_like_a_job_offer(text):
        return _empty(
            "This text does not read as an employment approach, so the "
            "employment rules were not applied to it. That is not a finding "
            "that it is safe — run it through the general scam checks.")

    forms = multilingual.normalise(text)
    haystacks = {forms["canonical"].lower(), forms["deobfuscated"].lower(),
                 forms["transliterated"].lower(), forms["original"].lower()}

    score = 0
    by_kind = {kind: [] for kind in KIND_ORDER}
    seen = set()

    for pattern, weight, kind, label in PATTERNS:
        if label in seen:
            continue
        for hay in haystacks:
            if re.search(pattern, hay):
                seen.add(label)
                score += weight
                by_kind[kind].append({"finding": label, "weight": weight})
                break

    score = min(score, 100)
    matched = {k: v for k, v in by_kind.items() if v}

    if not matched:
        return _empty(
            "Nothing in this text matched a known employment-fraud pattern. "
            "The absence of a pattern is not a clearance — a well-written "
            "approach that asks for nothing yet will match nothing yet.")

    # Trafficking outranks arithmetic. An approach can score modestly and
    # still be the most dangerous thing on the page.
    if matched.get(K_TRAFFICKING):
        primary = K_TRAFFICKING
        score = max(score, 70)
    else:
        primary = max(matched, key=lambda k: (sum(f["weight"] for f in matched[k]),
                                              -KIND_ORDER.index(k)))

    return {
        "is_employment_text": True,
        "score": score,
        "primary_kind": primary,
        "primary_label": KIND_LABELS[primary],
        "kinds": [{"kind": k, "label": KIND_LABELS[k], "findings": matched[k]}
                  for k in KIND_ORDER if k in matched],
        "findings": [f["finding"] for k in KIND_ORDER
                     for f in matched.get(k, [])],
        "verdict": _verdict(score, primary),
        "advice": advice_for(primary),
        "rule": THE_RULE,
        "limits": LIMITS,
    }


def _empty(reason):
    return {
        "is_employment_text": False, "score": 0, "primary_kind": None,
        "primary_label": None, "kinds": [], "findings": [],
        "verdict": "Not assessed", "advice": None,
        "rule": THE_RULE, "limits": LIMITS, "reason": reason,
    }


def _verdict(score, primary):
    if primary == K_TRAFFICKING:
        return ("Treat as a trafficking risk, not a job scam. Do not travel "
                "and do not surrender any document.")
    if score >= STRONG_SCORE:
        return "Consistent with employment fraud on more than one independent count."
    if score >= 30:
        return ("Carries recognised employment-fraud markers. Verify the "
                "employer independently before going further.")
    return "One weak marker. Not enough on its own to call it fraud."


THE_RULE = {
    "statement": "A genuine employer does not charge a candidate to be hired.",
    "detail": ("Registration fees, security deposits, training charges, kit "
               "or ID-card costs and 'refundable' amounts adjusted against a "
               "first salary are all the same thing. Recruitment costs sit "
               "with the employer. This one rule settles most cases without "
               "needing to know anything about the company."),
    "exception": ("Licensed placement agencies may lawfully charge a "
                  "candidate, but they contract in writing in advance and "
                  "they do not appear unsolicited on WhatsApp. If a fee is "
                  "being asked for, ask to see the licence and the written "
                  "agreement before anything is paid."),
}

LIMITS = [
    "This checks how the approach behaves, not whether the company exists. "
    "It holds no register of employers and does not claim one.",
    "A forged offer letter is usually an excellent forgery — the logo is "
    "taken from the real website. Do not try to judge the document; verify "
    "the sender against the company's own published contact details, found "
    "independently rather than from the letter.",
    "Patterns are in English and Hinglish. An approach in another language "
    "may score zero without being any safer.",
]


def advice_for(kind):
    """What to do, which differs completely by kind."""
    if kind == K_TRAFFICKING:
        return {
            "headline": "Do not travel. This is a liberty risk, not a money risk.",
            "urgency": "Before departure — afterwards the options narrow sharply.",
            "steps": [
                "No lawful employer flies an unknown candidate abroad on a "
                "tourist visa to start work. A tourist visa converted to work "
                "on arrival is not a shortcut; it is the method.",
                "Verify any overseas offer through the Indian mission in that "
                "country and through eMigrate before accepting anything. Check "
                "the recruiting agent is registered with the Ministry of "
                "External Affairs.",
                "Never surrender your passport to an employer or agent. In the "
                "compounds this is the first step and it is what makes leaving "
                "impossible.",
                "Tell somebody at home the exact address, the agent's name and "
                "number, and arrange a fixed check-in schedule before you fly.",
                "If a family member has already travelled and contact has "
                "changed character — messages that read as written by somebody "
                "else, requests for money, refusal to video call — contact the "
                "Indian Embassy in that country and the MEA immediately. This "
                "becomes a consular matter, not a cybercrime complaint.",
            ],
            "report_to": [
                "Ministry of External Affairs / the Indian mission in the "
                "destination country",
                "eMigrate (emigrate.gov.in) to check the recruiting agent",
                "Local police, for the recruitment offence committed in India",
                "National Cyber Crime Reporting Portal, cybercrime.gov.in, if "
                "money was also taken",
            ],
        }

    if kind == K_ADVANCE_FEE:
        return {
            "headline": "Pay nothing. The fee is the fraud.",
            "urgency": "If money has already gone, the next hour decides whether it can be held.",
            "steps": [
                "Stop at the fee. There is no version of a genuine hire that "
                "requires the candidate to transfer money first.",
                "Do not pay a second time to 'release' the first. The refund "
                "demand is the same fraud continued.",
                "If you have already paid, call 1930 immediately and report at "
                "cybercrime.gov.in. Tell your bank separately — that is what "
                "decides your liability, and it is a different step from the "
                "portal.",
                "Keep the chat, the UPI reference and the account or handle you "
                "paid into. The handle is what links this to other victims.",
            ],
            "report_to": ["1930", "cybercrime.gov.in", "your bank"],
        }

    if kind == K_CREDENTIAL:
        return {
            "headline": "Send no documents. This is about your identity, not a job.",
            "urgency": "Immediate if an OTP was shared or remote access granted.",
            "steps": [
                "An employer needs your documents after an offer, through a "
                "verified HR channel — never before an interview and never "
                "over a chat app.",
                "No employer ever needs an OTP, a CVV or a card PIN. A request "
                "for one is not a mistake or a formality.",
                "A selfie holding your Aadhaar is the input to opening a bank "
                "account in your name. Mule accounts opened this way leave the "
                "named person answering for the fraud run through them.",
                "If you granted remote access, disconnect the device from the "
                "network now, change passwords from a different device, and "
                "tell your bank.",
                "If documents have already gone, lock your Aadhaar biometrics "
                "on the UIDAI portal and watch your credit report for accounts "
                "you did not open.",
            ],
            "report_to": ["cybercrime.gov.in", "1930 if money moved",
                          "UIDAI, to lock Aadhaar biometrics"],
        }

    if kind == K_FAKE_OFFER:
        return {
            "headline": "Verify the employer independently before anything else.",
            "urgency": "Not time-critical unless money or documents have moved.",
            "steps": [
                "Find the company's number yourself — from its own website "
                "reached by search, not from any link or letter you were sent "
                "— and call the switchboard to ask whether the person exists.",
                "Check the sender's mail domain against the company's real "
                "one. A free mail account for an offer letter settles it.",
                "A selection with no interview is not good fortune.",
                "Report the posting to the job portal it claimed to come from. "
                "They act on these and it protects the next candidate.",
            ],
            "report_to": ["The job portal named", "cybercrime.gov.in if a fee "
                          "or documents were requested"],
        }

    if kind == K_TASK_BAIT:
        return {
            "headline": "This is a task scam recruiting, not an employer hiring.",
            "urgency": "Cheapest to leave now; the early payouts are real and are the hook.",
            "steps": [
                "Paid-per-like and paid-per-review work is the doorway to the "
                "task scam. The first small commissions are genuinely paid, "
                "out of what later victims deposit.",
                "The moment you are asked to fund a task yourself, the "
                "direction of money has reversed and it does not reverse back.",
                "Leave the group and deposit nothing. Keep the conversation as "
                "evidence of the method.",
            ],
            "report_to": ["cybercrime.gov.in", "1930 if a deposit was made"],
            "see_also": ("Run the conversation through the stage triage — it "
                         "will say how far along the script this has gone and "
                         "what is still recoverable."),
        }

    if kind == K_PRESSURE:
        return {
            "headline": "Slow it down. Urgency in hiring is manufactured.",
            "urgency": "Not time-critical.",
            "steps": [
                "No real vacancy expires in two hours, and no real employer "
                "asks you to keep an offer from your family.",
                "Government posts are filled only through published "
                "examinations and merit lists. Anyone offering a guaranteed "
                "or 'direct' government job is committing an offence, and "
                "paying them is money gone.",
                "Take a day. Verify the employer independently. An offer that "
                "cannot survive a day was never an offer.",
            ],
            "report_to": ["cybercrime.gov.in if a fee was requested"],
        }
    return None


def summarise(result):
    """One line for a list view."""
    if not result or not result.get("primary_kind"):
        return "No employment-fraud finding"
    return "%s (score %d)" % (result["primary_label"], result["score"])
