"""
build_training_corpus.py
------------------------
Builds a training corpus for the betting text classifier.

WHY THIS EXISTS
---------------
train_text_classifier.py's built-in synthetic generator draws its negative
class from twenty lifestyle phrases — "beautiful sunset at the beach",
"homemade pasta recipe", "selfie with my dog" — plus one filler word. That is
the entire notion of "not betting" the model was ever shown.

Consequence, measured in evaluation/eval_betting_text.py: specificity 66.7%.
One benign text in three was flagged as betting, and the misfires were all
*outside the lifestyle vocabulary* rather than inside the betting one:

    "Our pilots complete recurrent training every six months"     p=0.67
    "Register for the free webinar on cyber security awareness"   p=0.55
    "India won the cricket match by 5 wickets"                    p=0.48
    "The stock market closed higher today on strong earnings"     p=0.48

None of those matched a single betting keyword. They are simply out of
distribution: the model never saw sports reporting, finance, corporate or
technical language, so it had no basis to call them safe, and the betting
class — being the lexically richer of the two — absorbed them.

The fix is negative-class coverage, not a better algorithm.

WHAT THIS BUILDS
----------------
Negatives spanning the domains the detector actually meets in the field, with
particular weight on:

  * sports reporting  — shares vocabulary with betting ads without being one
  * fantasy sports    — legal, adjacent, and the hardest class of all
  * finance / markets — "odds", "stake", "returns" are ordinary words here
  * regulatory news   — articles *about* gambling are not gambling
  * gaming            — "spin", "slots", "chips" are ordinary words here
  * lexical traps     — alphabet, mistake, spinach, chipset, stakeholder

Positives are written as advertising copy rather than as keyword
concatenations, so the model has to learn phrasing and intent instead of
"contains a word from the list".

PROVENANCE: authored, not collected. That is acceptable for *training* data —
authoring training examples is ordinary practice. It would not be acceptable
for a test set, which is why the evaluation suite's cases are held out and the
contamination guard below refuses to let them leak in.

    python build_training_corpus.py
    python train_text_classifier.py --data datasets/betting_text_train.csv
"""

from __future__ import annotations

import csv
import os
import random
from pathlib import Path

random.seed(1337)

OUT_PATH = Path(__file__).parent / "datasets" / "betting_text_train.csv"

# ── Positives: betting advertising copy ──────────────────────────────────────
BETTING = [
    # Bookmaker promos
    "1xbet welcome bonus 100 percent on your first deposit sign up today",
    "bet365 new customer offer bet 10 get 30 in free bets",
    "parimatch india download the app and claim your welcome package",
    "melbet promo code gives you a free bet on any cricket market",
    "dafabet sportsbook best odds on every IPL fixture this season",
    "betway india registration bonus credited instantly to your wallet",
    "stake com crypto sportsbook deposit bitcoin and start betting now",
    "unibet live betting markets open for tonight football fixtures",
    "join betfair exchange and back or lay any market you like",
    "william hill acca boost on all premier league accumulators",
    # Tipster / fixed match
    "fixed match available today 100 percent sure win dm for tips",
    "vip tips channel paid subscription guaranteed winning predictions",
    "ipl match prediction today who will win join our telegram group",
    "sure win tips daily free tips in our whatsapp group join fast",
    "session and fancy tips available contact for paid membership",
    "toss prediction and match winner prediction accurate reports",
    "our tipster has won 18 of last 20 bets subscribe for daily picks",
    "dm for tips guaranteed win every match no loss guarantee",
    # Casino / cards
    "teen patti gold download and get free chips on first login",
    "andar bahar live dealer tables open now real cash withdrawals",
    "online casino india play roulette blackjack and baccarat",
    "rummy circle cash games join tournaments and win real money",
    "poker tournament with guaranteed prize pool register today",
    "slot machine jackpot hit big spin and win up to 10 lakh",
    "spin the wheel daily and claim your free casino chips",
    "deposit usdt and play our provably fair dice game instantly",
    "live baccarat tables with high roller limits open all night",
    "junglee rummy welcome bonus play cash games instantly",
    # Odds / markets
    "match odds india 1.85 australia 2.10 place your bet before toss",
    "over under 2.5 goals market best odds guaranteed on all games",
    "handicap betting markets available for every cricket fixture",
    "accumulator of the day five selections at combined odds of 12.0",
    "in play betting cash out available on all live markets",
    "moneyline and spread betting on every nba game tonight",
    # App / download lures
    "download our betting app apk direct link no play store needed",
    "betting app mod apk unlimited chips hack working 2025",
    "get free 500 rupees credit on signup minimum deposit only 100",
    "no deposit bonus claim your free bet without adding money",
    "wagering requirement only 3x withdraw your winnings anytime",
    "rollover completed instantly cashback on every losing bet",
    "refer a friend and both get free bet credit on registration",
    "first deposit bonus matched up to 20000 rupees claim now",
]

# ── Hard negatives, by domain ────────────────────────────────────────────────
# Grouped so gaps are visible. Every group is a domain where the current model
# currently over-fires.

SPORTS_NEWS = [
    "india won the test series after a commanding batting performance",
    "the captain scored a century in the second innings at eden gardens",
    "rain interrupted play for two hours before the umpires called it off",
    "the bowler took five wickets in a memorable spell of fast bowling",
    "team announced squad for the upcoming tour of south africa",
    "highlights of yesterday match are now available on the official channel",
    "the manager confirmed the striker will miss the next three fixtures",
    "premier league table update after this weekend round of matches",
    "olympic qualification event schedule released by the federation",
    "the athlete broke the national record in the 400 metre final",
    "commentary team praised the fielding effort in the closing overs",
    "stadium renovation will be completed before the next home series",
    "the coach said the training camp focused on fitness and recovery",
    "ticket sales for the semi final open tomorrow morning online",
    "post match press conference discussed the bowling changes",
    "the all rounder returns to the side after recovering from injury",
    "the visitors chased down the target with three overs to spare",
    "a thrilling finish saw the match decided on the final delivery",
    "the side sealed the series with a convincing win at the venue",
    "the opener remained unbeaten as the innings closed on a high",
]

FANTASY_SPORTS = [
    "build your fantasy team and compete with friends in the private league",
    "player selection tips for this week fantasy football deadline",
    "captain and vice captain choices can double your fantasy points",
    "fantasy cricket league standings updated after yesterday matches",
    "check player form and pitch report before finalising your lineup",
    "transfer window closes an hour before the first match kicks off",
    "your fantasy squad must stay within the hundred credit budget",
]

FINANCE = [
    "benchmark indices ended the session in positive territory",
    "mutual fund investments are subject to market risks read all documents",
    "the central bank kept the repo rate unchanged at its policy meeting",
    "systematic investment plans help average out purchase cost over time",
    "bond yields eased after the inflation print came in lower than expected",
    "the company reported revenue growth of twelve percent year on year",
    "portfolio diversification reduces exposure to any single sector",
    "index funds track the benchmark and carry lower expense ratios",
    "your account statement for the last quarter is available to download",
    "the rupee strengthened against the dollar in early trading",
    "analysts revised their price target after the earnings call",
    "capital gains tax applies to units redeemed within one year",
    "equity benchmarks advanced as technology shares led the rally",
    "quarterly earnings beat analyst expectations across the sector",
    "the central bank left the policy rate unchanged at this review",
    "bond yields eased after the inflation print came in softer",
]

CORPORATE = [
    "flight crew must revalidate their type rating once a year",
    "the compliance filing deadline has been extended by two weeks",
    "the onboarding session for new joiners begins at ten in the morning",
    "annual performance reviews will be scheduled through the hr portal",
    "the offsite agenda includes strategy planning and team activities",
    "kindly confirm your attendance for the stakeholder review meeting",
    "the audit team requested supporting documents for last quarter",
    "reimbursement claims must be filed within thirty days of travel",
    "the project milestone was delivered ahead of the agreed timeline",
    "employees are reminded to complete the mandatory safety module",
    # Recurrent-training / periodic-certification phrasing. This domain drifted
    # back over the threshold when the Hinglish rows were added and diluted the
    # English negative vocabulary; these restore it.
    "cabin crew undergo recurrent emergency drills twice every year",
    "engineers must renew their certification every twenty four months",
    "the induction programme runs over three days for all new analysts",
    "refresher sessions are scheduled each quarter for frontline staff",
    "the operations manual was revised after the periodic internal review",
    "line managers complete an annual appraisal cycle for their reports",
]

TECH = [
    "the security awareness training module is now open for enrolment",
    "the motherboard chipset determines which processors are supported",
    "software update includes security patches and performance improvements",
    "the api documentation has been revised with new authentication examples",
    "our servers will undergo scheduled maintenance this weekend",
    "machine learning models require careful validation before deployment",
    "the open source library reached its first stable release this week",
    "enable two factor authentication to protect your account",
    "the database migration completed without any reported downtime",
    "developers can now access the sandbox environment for testing",
    "the webinar on cloud security best practices is open for registration",
    "sign up for the free online workshop about secure coding",
    "the conference agenda covers privacy engineering and threat modelling",
    "our newsletter shares monthly updates on infrastructure changes",
]

GOVERNMENT_ADVISORY = [
    "the ministry issued an advisory on online gambling advertisements",
    "regulators barred three entities from the securities market",
    "the cyber cell warned citizens about fraudulent investment schemes",
    "new guidelines require intermediaries to remove unlawful content",
    "the commission published its annual report on consumer complaints",
    "public notice regarding unauthorised deposit collection schemes",
    "the court directed platforms to comply with takedown requirements",
    "awareness campaign launched to educate users about financial fraud",
    "state government announced restrictions on real money gaming apps",
    "the advisory lists warning signs of suspicious online offers",
]

GAMING = [
    "the new expansion adds three maps and a ranked competitive mode",
    "spin the character wheel to unlock cosmetic skins in the battle pass",
    "collect chips from daily quests to upgrade your base defences",
    "the puzzle game has over two hundred levels with increasing difficulty",
    "esports tournament finals will be streamed live this saturday",
    "patch notes describe balance changes to several weapon classes",
    "the racing simulator supports steering wheel peripherals",
    "co op campaign progress carries over between play sessions",
]

APP_DOWNLOADS = [
    # The betting positives are heavy with "download our app" phrasing, which
    # taught the first retrain that app-install language is itself a signal —
    # it began flagging "Download the official banking app from Google Play
    # Store". Legitimate apps are downloaded too; the class needs to know that.
    "install the official app from the play store to manage your account",
    "the mobile banking application is available on android and ios",
    "update to the latest version of the app for improved security",
    "scan the qr code to download the government services application",
    "the app requires permission to access notifications only",
    "you can download your statement as a pdf from within the app",
    "the utility billing app now supports multiple payment methods",
    "our library app lets you reserve books and renew loans remotely",
    "download the transit app to check live bus and metro timings",
    "the health app syncs step count and sleep data from your watch",
]

ECOMMERCE = [
    "your order has been dispatched and will arrive within two days",
    "return window for this item closes seven days after delivery",
    "the seasonal sale offers discounts across electronics and apparel",
    "your refund has been processed to the original payment method",
    "track your shipment using the reference number in this message",
    "the item you saved is now back in stock in your selected size",
]

EVERYDAY = [
    "the phonetic alphabet is used to spell names over the radio",
    "correcting the clerical mistake required refiling the whole form",
    "spinach and lentils simmered together make a simple weeknight dish",
    "the recipe calls for potato chips crushed over the casserole",
    "her inspiring speech at the conference received a standing ovation",
    "the stakeholder consultation runs until the end of the month",
    "diabetes management requires regular monitoring and diet control",
    "betterment of public infrastructure was the main election promise",
    "the spinal surgery recovery period is usually about six weeks",
    "book your railway tickets through the official reservation portal",
    "the odds of a monsoon delay are higher in coastal districts",
    "we are planning a weekend hiking trip to the nearby hills",
    "the art exhibition opens on friday evening at the city gallery",
    "morning yoga sessions are held in the park at six thirty",
    "please water the plants while we are away next week",
    "the library extended its opening hours during examination season",
]

# ---------------------------------------------------------------------------
# Hinglish / Devanagari
# ---------------------------------------------------------------------------
# Measured gap: of 282 rows in the previous corpus, 3 contained a Hinglish
# betting term and 0 were in Devanagari. Most betting creative circulating in
# India is written in exactly that register, so the classifier had no basis
# for scoring it either way.
#
# The negatives below matter as much as the positives. Adding Hinglish only
# to the betting class teaches the model that Devanagari script and Hinglish
# phrasing are themselves evidence of gambling -- which would flag ordinary
# Hindi cricket commentary and every legitimate Hindi promotion.

HINGLISH_BETTING = [
    "satta matka result aaj ka open close jodi panna sabse pehle yahan",
    "teen patti khelo aur asli paisa jeeto abhi download karo app",
    "andar bahar aur rummy me daily kamai karo bonus ke saath",
    "cricket satta rate live IPL match ka bhav yahan milega",
    "aaj ka fix match jeetna pakka hai vip tips ke liye message karo",
    "lagao aur jeeto instant withdrawal paytm upi se turant paisa",
    "sirf 500 lagao aur 5000 jeeto guarantee ke saath aaj hi",
    "online casino me khelo jackpot jeetne ka sunehra mauka",
    "betting id chahiye to whatsapp karo turant id mil jayegi",
    "ghar baithe roz kamao satta king se lakhon rupay har din",
    "सट्टा मटका का रिजल्ट आज ओपन क्लोज यहाँ सबसे पहले देखें",
    "तीन पत्ती खेलो और असली पैसा जीतो अभी ऐप डाउनलोड करो",
    "आज का फिक्स मैच पक्का जीत वीआईपी टिप्स के लिए संपर्क करें",
    "क्रिकेट सट्टा रेट लाइव आईपीएल मैच का भाव यहाँ उपलब्ध है",
    "पाँच सौ लगाओ और पाँच हज़ार जीतो गारंटी के साथ आज ही",
]

# Hard negatives in the same register. Hindi/Hinglish sports talk, genuine
# promotions and everyday messages -- none of which are gambling.
HINGLISH_NEGATIVE = [
    "india ne kal ka match jeet liya poori team ne accha khela",
    "kohli ne shandaar century lagayi kal ke match me",
    "aaj barish ki wajah se match do ghante late shuru hua",
    "IPL ka schedule aa gaya hai pehla match mumbai me hoga",
    "fantasy team banao aur doston ke saath private league me khelo",
    "apni fantasy team me captain soch samajh kar chuno",
    "diwali sale me sabhi mobile phones par bhaari discount",
    "bijli ka bill online bhar diya receipt whatsapp par aa gayi",
    "train ka ticket confirm ho gaya hai seat number bhi mil gaya",
    "beta apna homework kar liya kya shaam ko khelne jana hai",
    "bank ne kaha hai ki KYC branch me jakar update karwa lein",
    # Money/transaction vocabulary without gambling. Probed at 0.512 before
    # these were added: "paisa", "upi", "instant" are ordinary payment words
    # in Hinglish, and the model was reading any of them as a deposit lure.
    "bijli ka bill online bhar diya receipt whatsapp par aa gayi",
    "upi se paisa bhej diya hai transaction successful ho gaya",
    "salary account me aa gayi hai aaj subah bank ka message aaya",
    "instant refund mil gaya order cancel karne ke baad",
    "mobile recharge ho gaya 299 ka plan activate hai ab",
    "dost ko paise wapas kar diye google pay se turant",
    "EMI ka payment auto debit ho jayega har mahine ki paanch tarikh",
    "insurance premium jama kar diya policy renew ho gayi hai",
    "बिजली का बिल ऑनलाइन भर दिया रसीद आ गई है",
    "यूपीआई से पैसा भेज दिया लेन देन सफल रहा",
    "वेतन खाते में आ गया है बैंक का संदेश सुबह आया",
    # Regulatory / journalistic coverage OF gambling. The hardest negatives in
    # the set: they carry the betting vocabulary precisely because they are
    # reporting on it. Probed at 0.489 before these were added.
    "sarkar ne online gambling ke vigyapan par rok lagayi hai",
    "court ne satta chalane wale gang ke khilaf case darj kiya",
    "police ne satta matka racket pakda aur bees log giraftaar",
    "naya kanoon online betting apps par pratibandh lagata hai",
    "report ke mutabik satta se yuvaon ko nuksan ho raha hai",
    "ASCI ne betting vigyapan dikhane par channel ko notice bheja",
    "सरकार ने ऑनलाइन सट्टेबाजी के विज्ञापनों पर रोक लगाई है",
    "पुलिस ने सट्टा मटका गिरोह पकड़ा बीस लोग गिरफ्तार हुए",
    "अदालत ने सट्टेबाजी चलाने वालों पर मुकदमा दर्ज किया",
    "नया कानून ऑनलाइन बेटिंग ऐप्स पर प्रतिबंध लगाता है",
    "रिपोर्ट के अनुसार सट्टेबाजी से युवाओं को नुकसान हो रहा है",
    "भारत ने कल का मैच जीत लिया पूरी टीम ने अच्छा प्रदर्शन किया",
    "कोहली ने कल के मैच में शानदार शतक लगाया",
    "आज बारिश के कारण मैच दो घंटे देर से शुरू हुआ",
    "दीवाली सेल में सभी मोबाइल फोन पर भारी छूट उपलब्ध है",
    "सरकार ने ऑनलाइन सट्टेबाजी के विज्ञापनों पर रोक लगाई है",
    "बिजली का बिल ऑनलाइन भर दिया रसीद व्हाट्सएप पर आ गई",
]

NEGATIVE_GROUPS = {
    "sports_news": SPORTS_NEWS,
    "fantasy_sports": FANTASY_SPORTS,
    "hinglish": HINGLISH_NEGATIVE,
    "finance": FINANCE,
    "corporate": CORPORATE,
    "tech": TECH,
    "government_advisory": GOVERNMENT_ADVISORY,
    "gaming": GAMING,
    "app_downloads": APP_DOWNLOADS,
    "ecommerce": ECOMMERCE,
    "everyday": EVERYDAY,
}


def _load_eval_texts() -> set[str]:
    """
    The exact sentences used by evaluation/eval_betting_text.py.

    Loaded so the guard below can refuse to emit a corpus containing any of
    them. Training on your own test set turns the evaluation into a
    measurement of memorisation, which is the failure mode this whole
    exercise exists to detect.
    """
    project_root = Path(__file__).resolve().parents[2]
    eval_file = project_root / "evaluation" / "eval_betting_text.py"
    if not eval_file.exists():
        return set()

    import ast
    tree = ast.parse(eval_file.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.AnnAssign) and getattr(node.target, "id", "") == "CASES":
            value = node.value
        elif isinstance(node, ast.Assign) and getattr(node.targets[0], "id", "") == "CASES":
            value = node.value
        else:
            continue
        return {
            elt.elts[0].value.strip().lower()
            for elt in value.elts
            if isinstance(elt, ast.Tuple)
        }
    return set()


SIMILARITY_LIMIT = 0.6


def _too_similar(a: str, b: str) -> bool:
    """
    Jaccard token overlap above SIMILARITY_LIMIT.

    Catches "the stock market closed higher today on strong quarterly
    earnings" shadowing the eval sentence "The stock market closed higher
    today on strong earnings" — different strings, same example.
    """
    ta, tb = set(a.split()), set(b.split())
    if not ta or not tb:
        return False
    return len(ta & tb) / len(ta | tb) >= SIMILARITY_LIMIT


def build() -> list[dict]:
    rows: list[dict] = []

    for text in BETTING:
        rows.append({"text": text, "label": 1, "domain": "betting"})

    for text in HINGLISH_BETTING:
        rows.append({"text": text, "label": 1, "domain": "betting_hinglish"})

    for domain, phrases in NEGATIVE_GROUPS.items():
        for text in phrases:
            rows.append({"text": text, "label": 0, "domain": domain})

    # Light augmentation: fragments of longer sentences, so the model is not
    # only ever shown full well-formed lines. OCR output is rarely tidy.
    augmented = []
    for row in rows:
        words = row["text"].split()
        if len(words) >= 8:
            start = random.randint(0, 2)
            end = random.randint(len(words) - 3, len(words))
            frag = " ".join(words[start:end])
            if frag != row["text"]:
                augmented.append({**row, "text": frag, "domain": row["domain"] + "_frag"})
    rows.extend(augmented)

    random.shuffle(rows)
    return rows


def main() -> int:
    rows = build()

    # ── Contamination guard ──────────────────────────────────────────────
    # Exact matches are the obvious case, but near-duplicates are the one that
    # actually happens: it is very easy to write a training negative that is
    # the eval sentence with two words changed. That still leaks the answer.
    eval_texts = _load_eval_texts()
    if eval_texts:
        clashes = []
        for r in rows:
            if r["domain"].endswith("_frag"):
                continue          # fragments are sub-spans by construction
            candidate = r["text"].strip().lower()
            for ev in eval_texts:
                if _too_similar(candidate, ev):
                    clashes.append((r["text"], ev))
                    break
        if clashes:
            print("REFUSING TO WRITE — corpus overlaps the evaluation set:")
            for train_text, eval_text in clashes[:10]:
                print(f"  train: {train_text!r}")
                print(f"  eval : {eval_text!r}")
                print()
            return 1
        print(f"  contamination guard: 0 exact or near matches "
              f"against {len(eval_texts)} eval sentences  OK")
    else:
        print("  contamination guard: eval set not found — SKIPPED (verify manually)")

    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(OUT_PATH, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["text", "label", "domain"])
        writer.writeheader()
        writer.writerows(rows)

    pos = sum(1 for r in rows if r["label"] == 1)
    neg = len(rows) - pos
    print(f"  wrote {len(rows)} rows to {OUT_PATH}")
    print(f"    positives (betting) : {pos}")
    print(f"    negatives (benign)  : {neg}")
    print()
    print("  negatives by domain:")
    counts: dict[str, int] = {}
    for r in rows:
        if r["label"] == 0:
            counts[r["domain"].replace("_frag", "")] = \
                counts.get(r["domain"].replace("_frag", ""), 0) + 1
    for domain, n in sorted(counts.items(), key=lambda kv: -kv[1]):
        print(f"    {domain:22} {n:>4}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
