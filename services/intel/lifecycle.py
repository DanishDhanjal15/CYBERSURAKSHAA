"""
services/intel/lifecycle.py
---------------------------
Where in the script a victim currently is.

The distinction this draws
==========================
Every other detector in the platform answers "is this a scam". For the
long-form frauds — task scams, so-called pig butchering, romance and
matrimonial fraud — that answer is nearly useless on its own, because it is
the same answer at every stage of a confidence trick that runs for weeks.

What actually changes the advice is **which stage the victim is at**, because
the stages differ in what can still be done:

  1. **Contact.** An unsolicited approach. Nothing has been lost. Blocking
     ends it, and the whole thing costs nothing.
  2. **Grooming.** Rapport, or a small prepaid task that genuinely pays. The
     victim is usually *ahead* on money and reads that as proof the thing is
     real. This is the moment intervention is cheapest and least welcome.
  3. **Investment.** Larger sums, into a platform whose displayed balance is
     a number the operator controls. Money is gone from here on, though it
     does not look it.
  4. **Extraction.** Withdrawal blocked; "tax", "fee", "margin" or "unfreezing
     charge" demanded to release a balance that does not exist. Every rupee
     paid at this stage is paid to recover a fiction.
  5. **Recovery fraud.** A second operator, often the same one, approaches
     offering to get the money back for a fee.

A victim at stage 2 needs to be told the payouts are the hook. A victim at
stage 4 needs to be told the balance is not real and to stop paying — and
that their money moved weeks ago, so the golden hour is long gone and the
realistic action is evidence and reporting rather than a lien.

Confidence
==========
Stage is inferred from wording, and wording is what the operator controls.
Every result carries the evidence it relied on, and a stage inferred from a
single phrase is reported as low confidence rather than asserted. A wrong
stage produces confidently wrong advice, which is worse than none.
"""

from __future__ import annotations

import re

from services.intel import multilingual

# ── Stages ───────────────────────────────────────────────────────────────

S_CONTACT = "CONTACT"
S_GROOMING = "GROOMING"
S_INVESTMENT = "INVESTMENT"
S_EXTRACTION = "EXTRACTION"
S_RECOVERY_FRAUD = "RECOVERY_FRAUD"

STAGE_ORDER = [S_CONTACT, S_GROOMING, S_INVESTMENT, S_EXTRACTION, S_RECOVERY_FRAUD]

STAGE_LABELS = {
    S_CONTACT: "Initial contact",
    S_GROOMING: "Grooming — trust being built",
    S_INVESTMENT: "Investment — money going in",
    S_EXTRACTION: "Extraction — withdrawal blocked, fees demanded",
    S_RECOVERY_FRAUD: "Recovery fraud — second approach after the loss",
}

# Patterns per stage, in the (regex, weight, label) shape used throughout this
# codebase so the Hinglish bank concatenates cleanly.

STAGE_PATTERNS = {
    S_CONTACT: [
        (r"(?i)\b(?:sorry|sry)[,\s]+(?:wrong number|galat number)", 30,
         "Opens with the wrong-number pretext"),
        (r"(?i)\bis this\s+\w+\?.{0,40}\b(?:sorry|my mistake)", 25,
         "Manufactured misdial to start a conversation"),
        (r"(?i)\b(?:hi|hello|hey)\b.{0,30}\bi (?:got|found) your (?:number|contact|profile)",
         25, "Unexplained possession of the recipient's contact details"),
        (r"(?i)\b(?:part[- ]?time|online)\s+(?:job|work|task)\b.{0,40}"
         r"\b(?:home|ghar|mobile)\b", 25,
         "Unsolicited work-from-home offer"),
        (r"(?i)\b(?:daily|roz)\s+(?:income|earning|kamai)\s+\d", 20,
         "Advertises a daily income figure"),
        (r"(?i)\badd me on (?:whatsapp|telegram|wechat)\b", 20,
         "Immediate move to an encrypted channel"),
    ],

    S_GROOMING: [
        (r"(?i)\b(?:complete|karo|do)\s+(?:this|ye|small)?\s*"
         r"(?:task|job|review|like|rating)\b", 30,
         "Small task set as an entry step"),
        (r"(?i)\b(?:commission|payout|reward|bonus)\s+(?:credited|received|mila|aa gaya)",
         35, "A payout is said to have already landed"),
        (r"(?i)\b(?:prepaid|advance)\s+task\b", 30,
         "The prepaid-task mechanic"),
        (r"(?i)\byou (?:can|will) withdraw (?:anytime|immediately|turant)", 25,
         "Reassurance that withdrawal is unrestricted"),
        (r"(?i)\b(?:screenshot|proof)\s+(?:of|ka)\s+(?:payment|receipt|credit)", 20,
         "Payout screenshots used as social proof"),
        (r"(?i)\b(?:trust|bharosa|believe)\s+(?:me|us|karo)\b", 15,
         "Explicit appeal to trust"),
        (r"(?i)\b(?:mentor|guide|teacher|sir|madam)\s+(?:will|ne|ka)\s*"
         r"(?:help|guide|batayenge)", 20,
         "A mentor figure is introduced"),
    ],

    S_INVESTMENT: [
        (r"(?i)\b(?:deposit|invest|jama|lagao)\s+(?:more|aur|zyada|\d)", 30,
         "Prompt to deposit a larger amount"),
        (r"(?i)\b(?:vip|premium|gold|platinum)\s+(?:level|plan|package|group)\b", 25,
         "Tiered plans that require larger deposits"),
        (r"(?i)\b(?:profit|return|munafa)\s+(?:show|showing|dikh|balance)", 25,
         "Displayed profits used to justify further deposits"),
        (r"(?i)\b(?:portfolio|wallet|account)\s+balance\b.{0,30}\d", 20,
         "An in-platform balance is quoted"),
        (r"(?i)\b(?:usdt|tether|crypto|trading|forex|binary)\b.{0,40}"
         r"\b(?:deposit|invest|transfer)\b", 25,
         "Crypto or trading platform as the deposit destination"),
        (r"(?i)\b(?:limited|last)\s+(?:slot|seat|time)\b", 15,
         "Scarcity pressure applied to the deposit"),
    ],

    S_EXTRACTION: [
        (r"(?i)\b(?:withdraw|withdrawal|nikal)\w*\s+(?:is\s+)?"
         r"(?:blocked|frozen|failed|pending|rok|band)", 45,
         "Withdrawal blocked — the defining move of the extraction stage"),
        (r"(?i)\b(?:pay|deposit|jama)\s+.{0,25}\b(?:tax|tds|gst|income tax)\b.{0,30}"
         r"\b(?:withdraw|release|nikal)", 45,
         "Tax demanded before a withdrawal will be released"),
        (r"(?i)\b(?:unfreeze|unlock|activate|release)\s+(?:fee|charge|amount|balance)",
         45, "Fee demanded to unfreeze or release a balance"),
        (r"(?i)\b(?:margin|security|clearance|verification)\s+(?:deposit|fee|amount)"
         r".{0,40}\b(?:withdraw|release)", 40,
         "Margin or clearance deposit demanded against a withdrawal"),
        (r"(?i)\b(?:account|khata)\s+(?:frozen|blocked|suspend|band)\b.{0,40}"
         r"\b(?:pay|deposit|fee)", 40,
         "Account frozen with payment offered as the remedy"),
        (r"(?i)\b(?:one|final|last)\s+(?:more|aur)\s+(?:payment|deposit|transfer)",
         35, "The 'one more payment' pattern"),
        (r"(?i)\b(?:credit score|scoring|rating)\s+(?:low|kam)\b.{0,40}"
         r"\b(?:deposit|pay)", 30,
         "A fabricated internal score used to justify another payment"),
    ],

    S_RECOVERY_FRAUD: [
        (r"(?i)\b(?:recover|recovery|wapas|refund)\s+(?:your\s+)?"
         r"(?:money|funds|amount|paisa)\b.{0,40}\b(?:fee|charge|payment|percent)",
         45, "Offers to recover lost money for a fee"),
        (r"(?i)\b(?:we|i)\s+(?:can|will)\s+(?:get|recover|return)\s+"
         r"(?:your\s+)?(?:money|funds)\s+back", 40,
         "Unsolicited promise to return money already lost"),
        (r"(?i)\b(?:cyber|legal|recovery)\s+(?:expert|agency|team|lawyer)\b.{0,40}"
         r"\b(?:contact|hire|fee)", 30,
         "A recovery agency approaches the victim"),
        (r"(?i)\b(?:we|i)\s+(?:have|got)\s+your\s+(?:complaint|case|details)\b.{0,40}"
         r"\b(?:fee|charge|process)", 35,
         "Claims to hold the victim's existing complaint"),
    ],
}

# Signals that money has already gone, whatever stage the wording suggests.
MONEY_MOVED = re.compile(
    r"(?i)\b(?:transferred|paid|deposited|sent|bheja|kar diya|de diya)\b"
    r".{0,30}\b(?:rs\.?|inr|rupees?|₹|\d{3,})")

# Below this the stage is reported but flagged as thin.
LOW_CONFIDENCE_SCORE = 30


def classify(text, money_already_sent=None):
    """
    Infer which stage the conversation is at.

    `money_already_sent`, when the caller knows it, overrides an optimistic
    reading: wording that looks like grooming from somebody who has already
    transferred is at best the investment stage, and treating it as harmless
    would give exactly the wrong advice.
    """
    if not text or not text.strip():
        return _empty()

    forms = multilingual.normalise(text)
    haystacks = {forms["canonical"].lower(), forms["deobfuscated"].lower(),
                 forms["transliterated"].lower(), forms["original"].lower()}

    scores, evidence = {}, {}
    for stage, patterns in STAGE_PATTERNS.items():
        total, hits = 0, []
        for pattern, weight, label in patterns:
            if label in hits:
                continue
            for hay in haystacks:
                if re.search(pattern, hay):
                    total += weight
                    hits.append(label)
                    break
        scores[stage] = min(total, 100)
        evidence[stage] = hits

    detected = MONEY_MOVED.search(text) is not None
    money_moved = money_already_sent if money_already_sent is not None else detected

    ranked = sorted(scores.items(), key=lambda kv: -kv[1])
    top_stage, top_score = ranked[0]

    if top_score == 0:
        return _empty()

    # Money having moved sets a floor. The operator writes the reassuring
    # words; the transfer is the fact.
    if money_moved and STAGE_ORDER.index(top_stage) < STAGE_ORDER.index(S_INVESTMENT):
        top_stage = S_INVESTMENT
        top_score = max(top_score, scores[S_INVESTMENT], 40)
        evidence[S_INVESTMENT] = evidence.get(S_INVESTMENT, []) + [
            "Money is stated to have already been transferred, so the "
            "conversation is at least at the investment stage regardless of "
            "how the current message reads"]

    runner_up = ranked[1][1] if len(ranked) > 1 else 0
    confidence = _confidence(top_score, runner_up, len(evidence[top_stage]))

    return {
        "stage": top_stage,
        "stage_label": STAGE_LABELS[top_stage],
        "stage_index": STAGE_ORDER.index(top_stage) + 1,
        "stage_count": len(STAGE_ORDER),
        "score": top_score,
        "confidence": confidence,
        "evidence": evidence[top_stage],
        "all_scores": {s: scores[s] for s in STAGE_ORDER},
        "money_moved": money_moved,
        "advice": advice_for(top_stage, money_moved),
        "caveat": _caveat(confidence),
    }


def _empty():
    return {
        "stage": None, "stage_label": None, "stage_index": None,
        "stage_count": len(STAGE_ORDER), "score": 0, "confidence": "none",
        "evidence": [], "all_scores": {s: 0 for s in STAGE_ORDER},
        "money_moved": False, "advice": None,
        "caveat": ("No stage could be inferred from this text. That is not a "
                   "finding that the conversation is safe — it may simply be "
                   "an early or innocuous-looking message."),
    }


def _confidence(top, runner_up, hit_count):
    if top >= 60 and hit_count >= 2 and top - runner_up >= 20:
        return "high"
    if top >= LOW_CONFIDENCE_SCORE and hit_count >= 2:
        return "moderate"
    return "low"


def _caveat(confidence):
    if confidence == "low":
        return ("This stage rests on a single phrase. Wording is what the "
                "operator controls, so treat it as a hint and read the wider "
                "conversation before acting on it.")
    if confidence == "moderate":
        return ("Several indicators point at this stage, but adjacent stages "
                "scored comparably. Confirm against the conversation history.")
    return ("Multiple independent indicators, well separated from the next "
            "stage. Still an inference from wording, not an observation of "
            "what was actually paid.")


def advice_for(stage, money_moved=False):
    """
    What the person should do, given where they are.

    The point of the whole module. Advice that ignored the stage would tell a
    stage-4 victim to watch for warning signs they passed three weeks ago.
    """
    if stage == S_CONTACT:
        return {
            "headline": "Nothing has been lost. Block and stop here.",
            "steps": [
                "Do not reply. Any response, even a refusal, confirms the "
                "number is live and answered by a person.",
                "Block and report the account on the platform it came from.",
                "Report the number through Sanchar Saathi (Chakshu) so it can "
                "be considered for disconnection.",
            ],
            "cost_of_stopping": "Nothing.",
        }

    if stage == S_GROOMING:
        return {
            "headline": "The small payouts are the hook. Stop while you are ahead.",
            "steps": [
                "The early commissions are real, and they are paid out of the "
                "money later victims put in. They exist to make the larger "
                "deposit feel safe.",
                "Withdraw whatever balance is showing and deposit nothing "
                "further. If a withdrawal is refused, you are already at the "
                "next stage.",
                "Leave the group. The scripting relies on daily contact.",
                "Report the account and keep the conversation — it is evidence "
                "of the method even if you lose nothing.",
            ],
            "cost_of_stopping": ("Usually nothing, and sometimes a small gain. "
                                 "This is the cheapest point at which to walk "
                                 "away and the hardest to accept."),
        }

    if stage == S_INVESTMENT:
        return {
            "headline": "The balance on the screen is a number they control. Stop depositing.",
            "steps": [
                "The platform showing your profits is operated by the same "
                "people taking the deposits. The figure is not held anywhere.",
                "Deposit nothing further, whatever the displayed balance says "
                "you would forfeit.",
                "Report immediately at cybercrime.gov.in or on 1930. If any "
                "transfer was made within the last few hours, say so first — "
                "a recent transfer is the only one with a real chance of being "
                "held.",
                "Tell your bank as well as the portal. That is a separate step "
                "and it is what decides your liability.",
                "Preserve everything before leaving: the chat, the platform "
                "screens, the payment references.",
            ],
            "cost_of_stopping": ("Whatever has already gone in, most of which "
                                 "is unlikely to be recoverable. Continuing "
                                 "costs more."),
        }

    if stage == S_EXTRACTION:
        return {
            "headline": "There is no balance to release. Every further payment is lost.",
            "steps": [
                "No genuine platform requires a payment to release your own "
                "money. Tax, margin, clearance and unfreezing fees are all the "
                "same demand under different names.",
                "The displayed balance does not exist. Paying the fee does not "
                "produce it, and the demands continue as long as you pay.",
                "Stop paying now. This is the single decision that limits the "
                "loss.",
                "Report at cybercrime.gov.in and on 1930, and tell your bank.",
                "Preserve the chat, the platform screens and every payment "
                "reference before you are removed from the group.",
                "Expect a follow-up approach offering to recover the money. It "
                "is the same operation.",
            ],
            "cost_of_stopping": ("The money already paid is very unlikely to "
                                 "return. What stopping saves is everything "
                                 "not yet paid, which is usually more."),
        }

    if stage == S_RECOVERY_FRAUD:
        return {
            "headline": "This is a second fraud aimed at people who lost money in the first.",
            "steps": [
                "Nobody who contacts you unprompted can recover defrauded "
                "money, and no legitimate agency charges an advance fee to try.",
                "They know about your loss because they caused it or bought "
                "the list. That knowledge is not evidence they can help.",
                "Pay nothing. Share no bank detail, no OTP, no remote-access "
                "software.",
                "Recovery, where it happens at all, goes through the bank and "
                "the police on the complaint you already filed.",
                "Report this approach too — it is a separate offence and the "
                "numbers are worth having.",
            ],
            "cost_of_stopping": "Nothing further. Everything, if you engage.",
        }
    return None


def summarise(classification):
    """One line for a list view."""
    if not classification or not classification.get("stage"):
        return "Stage not determined"
    return "%s (%d of %d, %s confidence)" % (
        classification["stage_label"], classification["stage_index"],
        classification["stage_count"], classification["confidence"])
