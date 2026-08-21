"""
services/intel/multilingual.py
------------------------------
Hindi, Hinglish and obfuscation handling for the text detectors.

Every keyword bank in the platform is English-only -- SCAM_KEYWORDS in
services/scam_detector/nlp_analyzer.py, the urgency and coercion lists in
blueprints/customer_care.py -- and PaddleOCR is initialised with lang='en'.
Real Indian scam copy is not English. It is Hinglish ("aapka account block ho
gaya hai, turant call karein"), Devanagari, or deliberately obfuscated
("1nvestment", "p@ytm", "K Y C").

This module normalises all three into a form the existing English matchers can
score, and adds the Hindi/Hinglish signal vocabulary they were missing.

Everything here is stdlib-only and rule-based. Transliteration is lossy and
approximate by design: the goal is not readable English, it is a canonical
string that keyword matching can hit reliably.
"""

from __future__ import annotations

import re
import unicodedata

# -- Script detection ------------------------------------------------------

_DEVANAGARI = re.compile(r"[ऀ-ॿ]")
_LATIN = re.compile(r"[A-Za-z]")
_BENGALI = re.compile(r"[ঀ-৿]")
_TAMIL = re.compile(r"[஀-௿]")
_TELUGU = re.compile(r"[ఀ-౿]")
_GUJARATI = re.compile(r"[઀-૿]")
_GURMUKHI = re.compile(r"[਀-੿]")
_KANNADA = re.compile(r"[ಀ-೿]")
_MALAYALAM = re.compile(r"[ഀ-ൿ]")

_SCRIPTS = [
    ("devanagari", _DEVANAGARI), ("bengali", _BENGALI), ("tamil", _TAMIL),
    ("telugu", _TELUGU), ("gujarati", _GUJARATI), ("gurmukhi", _GURMUKHI),
    ("kannada", _KANNADA), ("malayalam", _MALAYALAM), ("latin", _LATIN),
]


def detect_scripts(text):
    """Return the set of scripts present, most frequent first."""
    if not text:
        return []
    counts = []
    for name, pattern in _SCRIPTS:
        n = len(pattern.findall(text))
        if n:
            counts.append((name, n))
    counts.sort(key=lambda kv: -kv[1])
    return [name for name, _ in counts]


def is_multilingual(text):
    """True when the text is not purely Latin script."""
    scripts = detect_scripts(text)
    return bool(scripts) and scripts != ["latin"]


# -- Devanagari transliteration -------------------------------------------
# A compact ITRANS-style mapping. Ordered longest-key-first at build time so
# conjuncts and vowel signs are consumed before their component characters.

_DEVA_MAP = {
    # Independent vowels
    "अ": "a", "आ": "aa", "इ": "i", "ई": "ii", "उ": "u", "ऊ": "uu",
    "ऋ": "ri", "ए": "e", "ऐ": "ai", "ओ": "o", "औ": "au",
    # Consonants (inherent 'a' added, stripped later where a virama follows)
    "क": "ka", "ख": "kha", "ग": "ga", "घ": "gha", "ङ": "nga",
    "च": "cha", "छ": "chha", "ज": "ja", "झ": "jha", "ञ": "nya",
    "ट": "ta", "ठ": "tha", "ड": "da", "ढ": "dha", "ण": "na",
    "त": "ta", "थ": "tha", "द": "da", "ध": "dha", "न": "na",
    "प": "pa", "फ": "pha", "ब": "ba", "भ": "bha", "म": "ma",
    "य": "ya", "र": "ra", "ल": "la", "व": "va", "श": "sha",
    "ष": "sha", "स": "sa", "ह": "ha", "ळ": "la",
    # Nukta forms common in loanwords
    "क़": "qa", "ख़": "kha", "ग़": "gha", "ज़": "za", "ड़": "ra",
    "ढ़": "rha", "फ़": "fa",
    # Dependent vowel signs
    "ा": "a", "ि": "i", "ी": "ii", "ु": "u", "ू": "uu", "ृ": "ri",
    "े": "e", "ै": "ai", "ो": "o", "ौ": "au",
    # Marks
    "ं": "n", "ः": "h", "ँ": "n", "्": "",
    # Digits
    "०": "0", "१": "1", "२": "2", "३": "3", "४": "4",
    "५": "5", "६": "6", "७": "7", "८": "8", "९": "9",
    "।": ".", "॥": ".",
}

_VIRAMA = "्"
_VOWEL_SIGNS = set("ािीुूृेैोौ")


def transliterate_devanagari(text):
    """
    Approximate Devanagari -> Latin transliteration.

    The inherent 'a' of a consonant is dropped when the next character is a
    virama or a dependent vowel sign, which is what makes "खाता" come out as
    "khaata" rather than "khaaataa". Exactness is not the goal -- matching
    "khata"/"khaata" against the keyword bank is.
    """
    if not text:
        return ""
    out = []
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        nxt = text[i + 1] if i + 1 < n else ""

        # Consume a nukta pair as one unit.
        pair = ch + nxt
        if pair in _DEVA_MAP:
            mapped = _DEVA_MAP[pair]
            i += 2
        elif ch in _DEVA_MAP:
            mapped = _DEVA_MAP[ch]
            i += 1
        else:
            out.append(ch)
            i += 1
            continue

        # Drop the inherent vowel when a virama or vowel sign follows.
        following = text[i] if i < n else ""
        if mapped.endswith("a") and len(mapped) > 1:
            if following == _VIRAMA or following in _VOWEL_SIGNS:
                mapped = mapped[:-1]
        out.append(mapped)

    return "".join(out)


# -- Obfuscation normalisation --------------------------------------------
# Scam copy routinely evades naive substring matching with leetspeak, inserted
# spaces and homoglyph punctuation: "1nvestment", "p@ytm", "K Y C", "g-u-a-r-a-n-t-e-e-d".

_LEET = {
    "0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t",
    "@": "a", "$": "s", "!": "i", "|": "i", "€": "e", "₹": "r",
}

_SPACED_LETTERS = re.compile(r"\b(?:[a-zA-Z][\s\-_.]){2,}[a-zA-Z]\b")
_REPEATED = re.compile(r"(.)\1{2,}")


def _collapse_spaced(match):
    return re.sub(r"[\s\-_.]", "", match.group(0))


def deobfuscate(text):
    """
    Undo the common evasions so keyword matching sees the underlying word.

    Applied in addition to -- never instead of -- matching against the raw
    text: collapsing "K Y C" to "kyc" is right, but collapsing every spaced
    capital sequence would also mangle legitimate text, so both forms are
    scored and the stronger signal wins.
    """
    if not text:
        return ""
    t = unicodedata.normalize("NFKC", text)
    t = _SPACED_LETTERS.sub(_collapse_spaced, t)
    t = "".join(_LEET.get(ch, ch) for ch in t)
    # "guaranteeeee" -> "guarantee"; cap runs at two so real doubles survive.
    t = _REPEATED.sub(lambda m: m.group(1) * 2, t)
    return t.lower()


# -- Hinglish / Hindi signal vocabulary ------------------------------------
# (pattern, weight, label) in the same shape as SCAM_KEYWORDS in
# services/scam_detector/nlp_analyzer.py, so the two banks can be concatenated.

HINGLISH_SCAM_KEYWORDS = [
    # Guaranteed-return / investment bait
    (r"paisa\s+(?:double|dugna)|dugna\s+paisa", 25, "Hinglish: double-your-money claim"),
    (r"guarantee(?:d)?\s+(?:return|munafa|profit)|pakka\s+munafa", 25, "Hinglish: guaranteed profit"),
    (r"bina\s+risk|risk\s+free\s+nivesh|koi\s+risk\s+nahi", 25, "Hinglish: no-risk claim"),
    (r"rozana\s+kamai|daily\s+kamai|ghar\s+baithe\s+kama", 15, "Hinglish: daily earnings claim"),
    (r"nivesh\s+kar|investment\s+kar[ae]", 8, "Hinglish: investment solicitation"),
    (r"lakhpati|karodpati|crorepati", 12, "Hinglish: instant-wealth promise"),

    # Urgency and fear
    (r"turant|abhi\s+kare?n|jaldi\s+kare?n|foran", 12, "Hinglish: urgency pressure"),
    (r"account\s+band\s+ho|khata\s+band|band\s+ho\s+jayega", 20, "Hinglish: account-closure threat"),
    (r"block\s+ho\s+(?:gaya|jayega)|blocked\s+ho", 20, "Hinglish: account-block threat"),
    (r"aakhri\s+(?:mauka|chance)|last\s+chance\s+hai", 12, "Hinglish: final-chance pressure"),
    (r"samay\s+seema|time\s+khatam\s+ho", 12, "Hinglish: deadline pressure"),

    # Authority impersonation / coercion
    (r"police\s+(?:case|complaint)\s+(?:hoga|ho\s+jayega)", 25, "Hinglish: police-action threat"),
    (r"giraftar|arrest\s+ho\s+jay", 25, "Hinglish: arrest threat"),
    (r"digital\s+arrest|ghar\s+me\s+hi\s+rahe", 25, "Hinglish: 'digital arrest' script"),
    (r"court\s+(?:ka\s+)?notice|adalat", 20, "Hinglish: court-notice threat"),
    (r"cbi|ed\s+officer|custom(?:s)?\s+(?:department|vibhag)", 20, "Hinglish: agency impersonation"),

    # KYC / verification lures
    (r"kyc\s+(?:update|complete|karva|expire)", 20, "Hinglish: KYC lure"),
    (r"verify\s+kare?n|verification\s+kar", 15, "Hinglish: verification demand"),
    (r"aadhaar\s+link|pan\s+link\s+kare", 15, "Hinglish: Aadhaar/PAN linking lure"),

    # Payment instructions
    (r"paise\s+bhej|payment\s+kare?n|transfer\s+kare?n", 15, "Hinglish: payment instruction"),
    (r"upi\s+(?:id|par)\s+bhej|scan\s+kare?n", 15, "Hinglish: UPI payment instruction"),
    (r"processing\s+fee|registration\s+fee\s+bhar", 20, "Hinglish: advance-fee demand"),
    (r"refund\s+ke\s+liye|paise\s+wapas", 15, "Hinglish: refund lure"),

    # Lottery / prize
    (r"lottery\s+(?:jeet|laga)|inaam\s+jeeta|prize\s+jeeta", 25, "Hinglish: lottery-win claim"),
    (r"lucky\s+draw\s+me\s+chuna|winner\s+chune\s+gaye", 20, "Hinglish: lucky-draw claim"),

    # Betting
    (r"satta|matka|teen\s+patti|rummy\s+khel", 20, "Hinglish: gambling reference"),
    (r"match\s+fix|pakki\s+khabar|sure\s+shot\s+tip", 20, "Hinglish: fixed-match claim"),

    # Channel lures
    (r"whatsapp\s+(?:par|pe)\s+(?:message|msg)|telegram\s+(?:par|pe)\s+jud", 8,
     "Hinglish: messaging-channel lure"),
    (r"link\s+(?:par|pe)\s+click|niche\s+diye\s+link", 8, "Hinglish: link CTA"),
]

# Devanagari source terms. Matched after transliteration, but listed here in
# native script for review by a Hindi-reading analyst.
DEVANAGARI_TERMS = {
    "खाता": "account", "बंद": "closed", "तुरंत": "immediately",
    "पैसा": "money", "दुगना": "double", "मुनाफा": "profit",
    "गारंटी": "guarantee", "निवेश": "investment", "इनाम": "prize",
    "लॉटरी": "lottery", "गिरफ्तार": "arrest", "पुलिस": "police",
    "अदालत": "court", "जल्दी": "quickly", "आखिरी": "last",
    "सत्यापन": "verification", "भुगतान": "payment", "शुल्क": "fee",
}


def normalise(text):
    """
    Produce the canonical matching form of `text`.

    Returns a dict with every representation, so a caller can score each and
    keep the strongest signal:

        original        as supplied
        transliterated  Devanagari folded into Latin
        deobfuscated    leetspeak / spacing evasions undone
        canonical       transliterated *and* deobfuscated -- the match target
        scripts         which scripts were detected
    """
    original = text or ""
    translit = transliterate_devanagari(original) if _DEVANAGARI.search(original) else original
    deobf = deobfuscate(original)
    canonical = deobfuscate(translit)
    return {
        "original": original,
        "transliterated": translit,
        "deobfuscated": deobf,
        "canonical": canonical,
        "scripts": detect_scripts(original),
        "multilingual": is_multilingual(original),
    }


def score_hinglish(text):
    """
    Score `text` against the Hinglish/Hindi bank.

    Returns (score, reasons) using the same 0-100 scale and the same reason
    formatting as the English keyword scorer, so the two combine without any
    special-casing at the call site.
    """
    forms = normalise(text)
    # Match against every representation: obfuscation and transliteration each
    # hide different terms, and a term found in any form is genuinely present.
    haystacks = {
        forms["canonical"].lower(),
        forms["deobfuscated"].lower(),
        forms["transliterated"].lower(),
        forms["original"].lower(),
    }

    score = 0
    reasons = []
    seen = set()
    for pattern, weight, label in HINGLISH_SCAM_KEYWORDS:
        if label in seen:
            continue
        for hay in haystacks:
            if re.search(pattern, hay):
                score += weight
                seen.add(label)
                reasons.append("Detected high-risk phrasing: %s" % label)
                break

    return min(score, 100), reasons


def enrich_keyword_bank(english_bank):
    """
    Concatenate the Hinglish bank onto an existing English one.

    Lets nlp_analyzer.SCAM_KEYWORDS gain Hindi coverage with a one-line change
    and no restructuring of its scoring loop.
    """
    return list(english_bank) + list(HINGLISH_SCAM_KEYWORDS)


def ocr_languages(text_hint=None):
    """
    Language codes to configure PaddleOCR with.

    PaddleOCR's 'devanagari' model covers Hindi and Marathi. Running both it and
    the English model and merging the output costs roughly twice the inference
    time, so the caller decides based on expected input; this returns the
    recommendation rather than imposing it.
    """
    if text_hint and _DEVANAGARI.search(text_hint):
        return ["devanagari", "en"]
    return ["en", "devanagari"]
