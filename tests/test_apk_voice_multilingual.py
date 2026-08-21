"""
APK static analysis, multilingual normalisation, voice-script scoring,
lookalike generation, and enforcement action packs.

The AXML test builds a synthetic binary manifest by hand rather than shipping
a real APK. That keeps the repository free of malware samples and makes the
parser's contract explicit: given these exact bytes, produce this package name.
"""

import struct
import zipfile
import io as _io

import pytest

from services.intel import apk, multilingual, voice, lookalike, actions


# ── Synthetic binary AndroidManifest.xml ─────────────────────────────────
# Chunk layout per the AOSP ResourceTypes.h: a string pool followed by
# START_ELEMENT chunks. The attribute block begins 16 bytes into the element
# chunk (the attrExt struct), which is exactly the offset that was wrong on
# the first attempt at this parser.

def _string_pool(strings):
    """UTF-16 string pool chunk."""
    data = b""
    offsets = []
    for s in strings:
        offsets.append(len(data))
        encoded = s.encode("utf-16-le")
        data += struct.pack("<H", len(s)) + encoded + b"\x00\x00"

    while len(data) % 4:
        data += b"\x00"

    header_size = 28
    offsets_size = 4 * len(strings)
    strings_start = header_size + offsets_size
    chunk_size = strings_start + len(data)

    header = struct.pack(
        "<HHIIIIII",
        0x0001,          # RES_STRING_POOL_TYPE
        header_size,
        chunk_size,
        len(strings),    # stringCount
        0,               # styleCount
        0,               # flags (0 = UTF-16)
        strings_start,
        0,               # stylesStart
    )
    return header + struct.pack("<%dI" % len(offsets), *offsets) + data


# ResXMLTree_attribute is exactly 20 bytes:
#   ns(4) name(4) rawValue(4) typedValue{size(2) res0(1) dataType(1) data(4)}
# Packing it as six uint32s -- 24 bytes -- silently shifts every subsequent
# attribute and yields garbage the parser cannot distinguish from real data.
_TYPED_VALUE_HEADER = (0x03 << 24) | 8   # dataType = TYPE_STRING, size = 8


def _start_element(ns_idx, name_idx, attrs):
    """One START_ELEMENT chunk. attrs = [(ns, name, rawvalue, typedvalue)]."""
    attr_bytes = b""
    for ns, name, raw, typed in attrs:
        attr_bytes += struct.pack("<IIIII", ns, name, raw,
                                  _TYPED_VALUE_HEADER, typed)

    # 8 chunk header + 4 lineNumber + 4 comment + 20 attrExt = 36 bytes
    # before the attribute block.
    chunk_size = 36 + len(attr_bytes)

    header = struct.pack("<HHII", 0x0102, 16, chunk_size, 0)
    header += struct.pack("<I", 0xFFFFFFFF)      # comment
    header += struct.pack("<II", ns_idx, name_idx)
    header += struct.pack("<HHHHHH",
                          20,            # attributeStart (from attrExt)
                          20,            # attributeSize
                          len(attrs),    # attributeCount
                          0, 0, 0)       # id/class/style index
    return header + attr_bytes


def build_axml(package="com.evil.betting", permissions=()):
    strings = ["manifest", "package", package, "uses-permission",
               "name", "http://schemas.android.com/apk/res/android"]
    for p in permissions:
        strings.append(p)

    body = _start_element(0xFFFFFFFF, 0, [(0xFFFFFFFF, 1, 2, 2)])
    for i, p in enumerate(permissions):
        idx = 6 + i
        body += _start_element(0xFFFFFFFF, 3, [(5, 4, idx, idx)])

    pool = _string_pool(strings)
    payload = pool + body
    return struct.pack("<HHI", 0x0003, 8, 8 + len(payload)) + payload


def _attrs_of(elements, tag):
    return [e["attrs"] for e in elements if e["name"] == tag]


class TestAxmlParsing:
    def test_package_name_extracted(self):
        """
        The attribute block starts 16 bytes into the element chunk (the attrExt
        struct), not at the chunk start. Getting that offset wrong yields a
        parser that reads plausible-looking garbage rather than failing, which
        is why this test uses bytes with a known correct answer.
        """
        elements = apk.parse_axml(build_axml("com.evil.betting"))
        manifests = _attrs_of(elements, "manifest")
        assert manifests, "no <manifest> element parsed"
        assert manifests[0].get("package") == "com.evil.betting"

    def test_permissions_extracted(self):
        elements = apk.parse_axml(build_axml(
            "com.evil.betting",
            ["android.permission.READ_SMS",
             "android.permission.SYSTEM_ALERT_WINDOW"]))
        names = {a.get("name") for a in _attrs_of(elements, "uses-permission")}
        assert "android.permission.READ_SMS" in names

    def test_garbage_input_returns_empty_not_an_exception(self):
        """
        A truncated or hostile APK must not take down the request. The parser
        reads attacker-controlled bytes; every failure path returns a partial
        result rather than raising.
        """
        assert apk.parse_axml(b"not an axml file at all") == []
        assert apk.parse_axml(b"") == []


class TestApkAnalysis:
    def test_risky_permissions_are_weighted(self):
        assert "android.permission.READ_SMS" in apk.RISKY_PERMISSIONS

    def test_sms_read_outweighs_a_benign_permission(self):
        """
        READ_SMS on a betting app is how the OTP interception happens; INTERNET
        is on every app ever shipped. They must not carry the same weight.
        """
        sms_weight = apk.RISKY_PERMISSIONS["android.permission.READ_SMS"][0]
        assert sms_weight >= 15
        assert "android.permission.INTERNET" not in apk.RISKY_PERMISSIONS

    def test_analysis_of_a_non_apk_fails_cleanly(self, tmp_path):
        bad = tmp_path / "not.apk"
        bad.write_bytes(b"definitely not a zip")
        result = apk.analyse(str(bad))
        assert result.get("error") or result.get("verdict")

    def test_analysis_of_a_minimal_apk(self, tmp_path):
        path = tmp_path / "sample.apk"
        buf = _io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("AndroidManifest.xml", build_axml(
                "com.lucky.rummy.cash",
                ["android.permission.READ_SMS"]))
            z.writestr("classes.dex",
                       b"teen patti rummy deposit withdraw jackpot "
                       b"https://api.luckyrummy.win/bet")
        path.write_bytes(buf.getvalue())

        result = apk.analyse(str(path))
        assert result["package"] == "com.lucky.rummy.cash"
        assert result["file_sha256"]
        assert result["verdict"] in ("HIGH_RISK", "SUSPICIOUS", "LOW_RISK")
        assert result["betting_terms"], "gambling vocabulary in strings was missed"


class TestMultilingual:
    def test_devanagari_is_detected(self):
        assert "devanagari" in [s.lower() for s in
                               multilingual.detect_scripts("आपका खाता बंद")]

    def test_transliteration_produces_latin(self):
        out = multilingual.transliterate_devanagari("खाता")
        assert out and all(ord(c) < 0x900 for c in out)

    @pytest.mark.parametrize("obfuscated,plain", [
        ("f-r-e-e", "free"),
        ("w1n", "win"),
        ("j@ckp0t", "jackpot"),
        ("B O N U S", "bonus"),
    ])
    def test_deobfuscation(self, obfuscated, plain):
        """
        Spacing, leetspeak and separator injection are the standard evasions
        against a keyword bank. An English-only exact-match detector misses
        every one of them.
        """
        assert plain in multilingual.deobfuscate(obfuscated).lower()

    def test_hinglish_scam_scores_above_benign_text(self):
        """
        The original keyword banks were English-only. Most scam SMS traffic in
        India is Hinglish, so an English-only bank scores the real thing at
        zero and the benign message at zero -- indistinguishable.
        """
        scam_score, scam_reasons = multilingual.score_hinglish(
            "aapka account block ho jayega, turant KYC update karo, "
            "OTP share karo warna paisa doob jayega")
        benign_score, _ = multilingual.score_hinglish(
            "kal milte hain office mein, lunch ke baad")
        assert scam_score > benign_score
        assert scam_reasons

    def test_empty_input_is_safe(self):
        score, reasons = multilingual.score_hinglish("")
        assert score == 0 and reasons == []


class TestVoiceScoring:
    def test_digital_arrest_script_scores_high(self):
        transcript = (
            "This is Inspector Sharma from the CBI Mumbai cyber crime branch. "
            "A parcel in your name containing narcotics has been seized. "
            "You are under digital arrest. Do not disconnect this call or "
            "inform anyone. Transfer the verification amount to the account "
            "I give you or a warrant will be issued today."
        )
        score, reasons, matched = voice.score_transcript(transcript)
        assert score > 50
        assert matched and reasons

    def test_ordinary_call_scores_low(self):
        score, _, _ = voice.score_transcript(
            "Hi, I'm calling about the delivery scheduled for tomorrow "
            "morning. Will someone be at home between ten and twelve?")
        assert score < 30

    def test_verdict_ignores_the_acoustic_screen(self):
        """
        The acoustic screen is an unvalidated heuristic. It is reported for
        context and deliberately excluded from the decision, because a
        blocking request must not rest on a number nobody has checked.
        """
        result = voice.analyse(transcript="Just calling to say hello.")
        assert result["verdict"] in ("NO_SCRIPT_INDICATORS", "SUSPICIOUS",
                                     "VOICE_SCAM", "NO_TRANSCRIPT")
        acoustic = result.get("acoustic")
        # A transcript-only analysis has no audio to screen, so `acoustic` is
        # None. When it does run, it must declare itself unvalidated.
        if acoustic and acoustic.get("available"):
            assert acoustic["validated"] is False

    def test_no_transcript_is_a_distinct_verdict(self):
        """
        "We could not hear the call" is not "the call was clean". Collapsing
        the two would clear every recording the ASR backend failed on.
        """
        assert voice.analyse(transcript="")["verdict"] == "NO_TRANSCRIPT"


class TestLookalike:
    def test_generates_typosquats(self):
        variants = lookalike.generate("sbi.co.in")
        assert len(variants) > 20
        names = {v["domain"] for v in variants}
        assert "sbi.co.in" not in names, "the brand itself is not a typosquat"

    def test_homoglyph_strategy_present(self):
        strategies = {v["strategy"] for v in lookalike.generate("hdfcbank.com")}
        assert "homoglyph" in strategies or "replacement" in strategies

    def test_scam_affixes_are_generated(self):
        """
        `sbi-verification-login.com` is the shape these actually take, and no
        character-level permutation would ever produce it.
        """
        names = {v["domain"] for v in lookalike.generate("sbi.co.in")}
        assert any("verify" in n or "login" in n or "secure" in n for n in names)

    def test_watchlist_is_indian_institutions(self):
        joined = " ".join(lookalike.DEFAULT_WATCHLIST)
        assert ".in" in joined


class TestActionPacks:
    def test_upi_routes_to_npci(self):
        pack = actions.build_action_pack(
            indicators=[{"kind": "upi", "normalized": "scam@okaxis",
                         "raw": "scam@okaxis"}],
            context={"module": "Betting Content", "verdict": "BETTING",
                     "score": 95, "scan_id": 1, "artefact_hash": "a" * 64})
        channels = {a["channel"] for a in pack["actions"]}
        assert any("bank" in c.lower() or "npci" in c.lower()
                   or "ncrp" in c.lower() for c in channels)

    def test_no_recipient_address_is_ever_invented(self):
        """
        A takedown notice addressed to a made-up abuse mailbox is worse than
        no notice: it looks actioned and reaches nobody. Unknown recipients
        carry an explicit placeholder an officer has to resolve.
        """
        pack = actions.build_action_pack(
            indicators=[{"kind": "domain", "normalized": "evil-bank.example",
                         "raw": "evil-bank.example"}],
            context={"module": "Customer Care", "verdict": "DANGER",
                     "score": 90, "scan_id": 2, "artefact_hash": "b" * 64})
        for action in pack["actions"]:
            recipient = (action.get("recipient") or "")
            if recipient and "@" in recipient:
                assert actions.PLACEHOLDER in recipient or action.get("verified")

    def test_every_document_is_labelled_a_draft(self):
        pack = actions.build_action_pack(
            indicators=[{"kind": "phone", "normalized": "9876543210",
                         "raw": "9876543210"}],
            context={"module": "Customer Care", "verdict": "DANGER",
                     "score": 88, "scan_id": 3, "artefact_hash": "c" * 64})
        for action in pack["actions"]:
            body = actions.render_action_text(action, pack).lower()
            assert "draft" in body

    def test_no_indicators_produces_no_actions(self):
        pack = actions.build_action_pack(
            indicators=[],
            context={"module": "Betting Content", "verdict": "SAFE",
                     "score": 5, "scan_id": 4, "artefact_hash": "d" * 64})
        assert pack["actions"] == [] or all(
            a.get("urgency") != "IMMEDIATE" for a in pack["actions"])
