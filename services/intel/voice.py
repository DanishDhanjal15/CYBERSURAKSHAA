"""
services/intel/voice.py
-----------------------
Voice-scam and synthetic-speech analysis.

The platform covers manipulated video and scam text but had no audio path at
all, which leaves out the dominant Indian fraud vector: the call. "Digital
arrest" scripts, fake CBI/ED officers, KYC-expiry vishing and cloned-voice
family emergencies are all delivered by voice, and none of the existing four
modules can look at a recording.

Pipeline
--------
    1. Transcribe          faster-whisper if available, else openai-whisper,
                           else accept an analyst-supplied transcript.
    2. Score the script    the existing keyword banks plus the Hinglish bank
                           plus a coercion-script model specific to voice fraud.
    3. Acoustic screen     heuristic synthetic-speech indicators computed from
                           the waveform with the stdlib `wave` module.
    4. Extract indicators  phones, UPI IDs and URLs spoken aloud feed straight
                           into the entity graph.

Honesty about the acoustic stage
--------------------------------
Step 3 is a *screen*, not a detector. It measures things that differ on
average between synthetic and natural speech -- silence structure, dynamic
range, clipping, spectral flatness proxies -- and it has not been validated
against a labelled corpus of cloned speech. It reports its own reliability as
LOW and never drives the verdict on its own. The transcript-based score is the
load-bearing signal, and it is the one that is actually defensible.
"""

from __future__ import annotations

import math
import os
import re
import wave

# `audioop` was removed from the standard library in Python 3.13 (PEP 594).
# It is used only by the acoustic screen, which is an explicitly non-decisive
# signal -- so its absence must degrade that one panel, not prevent the module
# from importing and take the whole voice blueprint (and with it the app) down
# on a newer interpreter.
try:
    import audioop
except ImportError:  # pragma: no cover - depends on interpreter version
    audioop = None

from services.intel import multilingual
from services.intel.indicators import extract_all

# Formats the transcription backends handle.
SUPPORTED_AUDIO = {".wav", ".mp3", ".m4a", ".ogg", ".opus", ".flac", ".aac", ".webm", ".mp4"}

# Waveform analysis reads PCM directly, so only WAV can be screened acoustically
# without an ffmpeg decode step.
PCM_READABLE = {".wav"}


# -- Voice-fraud script patterns -------------------------------------------
# These are specific to spoken fraud and do not appear in the text banks:
# a caller announcing an identity, issuing an instruction and forbidding
# consultation is the structural signature of a coercion script.

VOICE_SCRIPT_PATTERNS = [
    # Authority assertion
    (r"\b(?:i am|this is|speaking from|calling from)\s+(?:the\s+)?"
     r"(?:cbi|c\.?b\.?i|enforcement directorate|e\.?d\.?|narcotics|customs|"
     r"income tax|cyber crime|police|trai|tra i|delhi police|mumbai police)\b",
     30, "Caller asserts law-enforcement identity"),
    (r"\b(?:sub[- ]?inspector|inspector|officer|dcp|acp|constable)\s+\w+\s+(?:here|speaking|bol)",
     25, "Caller asserts police rank"),
    (r"\b(?:bank|branch)\s+manager\s+(?:speaking|here|bol)", 20,
     "Caller asserts bank-official identity"),

    # The digital-arrest structure
    (r"\bdigital\s+arrest\b", 35, "Explicit 'digital arrest' framing"),
    (r"\b(?:do not|don'?t|mat)\s+(?:disconnect|cut|hang up|end)\s+(?:the\s+)?call\b",
     30, "Instruction not to end the call"),
    (r"\b(?:do not|don'?t|mat)\s+(?:tell|inform|discuss with|talk to)\s+"
     r"(?:anyone|any one|family|police|your family)\b",
     30, "Instruction to conceal the call from others"),
    (r"\b(?:stay|remain|rahe|raho)\s+(?:on\s+(?:the\s+)?(?:line|video)|in\s+(?:the\s+)?room)\b",
     25, "Instruction to remain on the line"),
    (r"\bcamera\s+(?:on|chalu)|video\s+call\s+(?:par|on)\b", 20,
     "Demand to remain on video"),

    # Legal threat
    (r"\b(?:arrest|warrant|non[- ]?bailable|fir|f\.?i\.?r\.?|case\s+(?:file|register))\b",
     20, "Threat of arrest or legal proceedings"),
    (r"\b(?:money laundering|drugs?|narcotics?|illegal (?:parcel|package|item))\b",
     25, "Fabricated serious-offence allegation"),
    (r"\b(?:your\s+)?(?:aadhaar|aadhar|pan card)\s+(?:is\s+)?(?:linked|used|misused)\b",
     25, "Claim that identity documents were misused"),
    (r"\bparcel\s+(?:contains|me|has)\b", 20, "Fake parcel-interception pretext"),

    # Payment demand
    (r"\b(?:verification|security|clearance|processing|penalty)\s+(?:fee|charge|amount|deposit)\b",
     30, "Demand for an advance fee"),
    (r"\b(?:transfer|send|deposit|pay)\s+(?:the\s+)?(?:amount|money|funds?|rupees|rs)\b",
     25, "Instruction to transfer money"),
    (r"\brefundable\s+(?:amount|deposit|security)\b", 25,
     "'Refundable deposit' framing"),
    (r"\b(?:supreme court|rbi|reserve bank)\s+(?:account|verification)\b", 30,
     "Fake official-account framing"),

    # OTP / credential harvesting
    (r"\b(?:otp|one time password|pin|cvv|password)\b", 30,
     "Request for OTP or credentials"),
    (r"\b(?:share|tell|batao|bataiye|read out)\s+(?:me\s+)?(?:the\s+)?"
     r"(?:otp|code|number|pin)\b", 35, "Explicit request to read out a code"),
    (r"\b(?:screen[- ]?share|anydesk|teamviewer|quick\s?support|remote\s+access)\b",
     35, "Request to install remote-access software"),

    # Urgency
    (r"\b(?:within|in)\s+(?:the\s+next\s+)?\d+\s*(?:minutes?|hours?)\b", 15,
     "Explicit deadline pressure"),
    (r"\b(?:immediately|right now|abhi|turant|at once)\b", 12, "Urgency language"),
]

MAX_VOICE_SCORE = 100


def score_transcript(transcript):
    """
    Score a call transcript for coercion-script structure.

    Combines the voice-specific patterns above with the Hinglish bank, since
    almost all of these calls are conducted in Hindi or Hinglish.

    Returns (score, reasons, matched_labels).
    """
    if not transcript:
        return 0, [], []

    forms = multilingual.normalise(transcript)
    haystacks = {
        forms["canonical"].lower(),
        forms["deobfuscated"].lower(),
        forms["original"].lower(),
    }

    score = 0
    reasons = []
    matched = []
    for pattern, weight, label in VOICE_SCRIPT_PATTERNS:
        if label in matched:
            continue
        for hay in haystacks:
            if re.search(pattern, hay):
                score += weight
                matched.append(label)
                reasons.append("Voice-fraud script indicator: %s" % label)
                break

    hinglish_score, hinglish_reasons = multilingual.score_hinglish(transcript)
    # The Hinglish bank contributes at reduced weight: it was written for
    # written scam copy, and a spoken transcript legitimately contains more of
    # its softer terms ("turant", "payment") than a poster does.
    score += int(hinglish_score * 0.4)
    reasons.extend(hinglish_reasons)

    return min(score, MAX_VOICE_SCORE), reasons, matched


# -- Acoustic screening ----------------------------------------------------

def acoustic_screen(path):
    """
    Heuristic synthetic-speech indicators from a WAV file.

    Computes four cheap statistics that differ on average between natural and
    synthesised speech:

        silence_ratio       TTS output typically has unnaturally clean pauses
        dynamic_range_db    natural speech varies more in level
        clipping_ratio      re-encoded / concatenated audio clips more often
        zero_crossing_var   varies less in synthetic speech

    Returns a dict including an explicit `reliability` of "LOW" and a
    `validated: False` flag. These figures have never been checked against a
    labelled corpus of cloned speech; they are displayed to give an analyst
    something to look at, and they must not be presented as a deepfake verdict.
    """
    if audioop is None:
        return {"available": False,
                "reason": "acoustic screening needs the audioop module, "
                          "removed from the standard library in Python 3.13"}

    ext = os.path.splitext(path)[1].lower()
    if ext not in PCM_READABLE:
        return {
            "available": False,
            "reason": "Acoustic screening reads PCM directly and supports WAV only. "
                      "Convert the recording to WAV to enable it.",
            "validated": False,
        }

    try:
        with wave.open(path, "rb") as wf:
            channels = wf.getnchannels()
            width = wf.getsampwidth()
            rate = wf.getframerate()
            frames = wf.getnframes()
            if frames <= 0:
                return {"available": False, "reason": "Empty audio file.", "validated": False}
            raw = wf.readframes(min(frames, rate * 300))  # cap at 5 minutes

        if channels > 1:
            raw = audioop.tomono(raw, width, 0.5, 0.5)

        duration = frames / float(rate) if rate else 0.0
        peak = audioop.max(raw, width)
        rms_overall = audioop.rms(raw, width)
        max_possible = float(2 ** (8 * width - 1))

        # Window the signal to measure silence structure and level variation.
        window_samples = max(1, int(rate * 0.02))          # 20 ms
        window_bytes = window_samples * width
        rms_windows = []
        for i in range(0, len(raw) - window_bytes, window_bytes):
            chunk = raw[i:i + window_bytes]
            if chunk:
                rms_windows.append(audioop.rms(chunk, width))

        if not rms_windows:
            return {"available": False, "reason": "Audio too short to analyse.",
                    "validated": False}

        silence_floor = max(1.0, max_possible * 0.005)
        silent = sum(1 for r in rms_windows if r < silence_floor)
        silence_ratio = silent / float(len(rms_windows))

        voiced = [r for r in rms_windows if r >= silence_floor]
        if voiced:
            lo, hi = min(voiced), max(voiced)
            dynamic_range_db = 20.0 * math.log10(hi / lo) if lo > 0 else 0.0
        else:
            dynamic_range_db = 0.0

        clipping_ratio = 1.0 if peak >= max_possible - 1 else 0.0
        if peak > 0:
            near_peak = sum(1 for r in rms_windows if r > 0.95 * peak)
            clipping_ratio = near_peak / float(len(rms_windows))

        mean_rms = sum(rms_windows) / float(len(rms_windows))
        variance = sum((r - mean_rms) ** 2 for r in rms_windows) / float(len(rms_windows))
        level_cv = (math.sqrt(variance) / mean_rms) if mean_rms > 0 else 0.0

        # Combine into an advisory 0-100 figure. Weights are judgement, not fit.
        suspicion = 0
        notes = []
        if silence_ratio > 0.45:
            suspicion += 25
            notes.append("Unusually high proportion of near-digital silence (%.0f%%)"
                         % (silence_ratio * 100))
        if dynamic_range_db < 18:
            suspicion += 25
            notes.append("Compressed dynamic range (%.1f dB) — consistent with "
                         "synthesised or heavily processed speech" % dynamic_range_db)
        if level_cv < 0.45:
            suspicion += 20
            notes.append("Low level variation across the recording")
        if clipping_ratio > 0.02:
            suspicion += 15
            notes.append("Clipping present in %.1f%% of windows — re-encoded or "
                         "concatenated audio" % (clipping_ratio * 100))

        return {
            "available": True,
            "validated": False,
            "reliability": "LOW",
            "duration_seconds": round(duration, 2),
            "sample_rate": rate,
            "channels": channels,
            "silence_ratio": round(silence_ratio, 3),
            "dynamic_range_db": round(dynamic_range_db, 1),
            "level_variation": round(level_cv, 3),
            "clipping_ratio": round(clipping_ratio, 4),
            "rms": rms_overall,
            "suspicion_score": min(suspicion, 100),
            "notes": notes,
            "disclaimer": (
                "Heuristic screen only. These statistics have not been validated "
                "against a labelled corpus of synthetic speech and must not be "
                "reported as a deepfake determination. Treat as context for the "
                "transcript analysis, which is the load-bearing signal."
            ),
        }
    except wave.Error as e:
        return {"available": False, "reason": "Unreadable WAV file: %s" % e,
                "validated": False}
    except Exception as e:
        return {"available": False, "reason": str(e), "validated": False}


# -- Transcription ---------------------------------------------------------

_whisper_model = None
_whisper_backend = None


def _load_whisper(model_size=None):
    """
    Load a Whisper backend once, preferring faster-whisper.

    Both backends are optional. When neither is installed the caller falls back
    to an analyst-supplied transcript, which keeps the whole module usable on a
    machine with no ML stack -- including the demo laptop.
    """
    global _whisper_model, _whisper_backend
    if _whisper_model is not None:
        return _whisper_model, _whisper_backend

    size = model_size or os.environ.get("WHISPER_MODEL", "base")

    try:
        from faster_whisper import WhisperModel
        _whisper_model = WhisperModel(size, device="cpu", compute_type="int8")
        _whisper_backend = "faster-whisper"
        print("[VOICE] Loaded faster-whisper (%s)." % size)
        return _whisper_model, _whisper_backend
    except Exception as e:
        print("[VOICE] faster-whisper unavailable: %s" % e)

    try:
        import whisper
        _whisper_model = whisper.load_model(size)
        _whisper_backend = "openai-whisper"
        print("[VOICE] Loaded openai-whisper (%s)." % size)
        return _whisper_model, _whisper_backend
    except Exception as e:
        print("[VOICE] openai-whisper unavailable: %s" % e)

    return None, None


def transcribe(path, language=None):
    """
    Transcribe an audio file.

    Returns {"text", "language", "backend", "segments"} or
    {"available": False, "reason": ...} when no backend is installed.
    """
    model, backend = _load_whisper()
    if model is None:
        return {
            "available": False,
            "reason": ("No speech-recognition backend installed. Install "
                       "faster-whisper (pip install faster-whisper) or paste the "
                       "transcript manually to analyse the call script."),
        }

    try:
        if backend == "faster-whisper":
            segments, info = model.transcribe(path, language=language, beam_size=1)
            seg_list = [{"start": s.start, "end": s.end, "text": s.text} for s in segments]
            text = " ".join(s["text"].strip() for s in seg_list)
            return {
                "available": True, "text": text.strip(),
                "language": getattr(info, "language", language),
                "backend": backend, "segments": seg_list,
            }

        result = model.transcribe(path, language=language)
        return {
            "available": True,
            "text": (result.get("text") or "").strip(),
            "language": result.get("language", language),
            "backend": backend,
            "segments": [
                {"start": s.get("start"), "end": s.get("end"), "text": s.get("text")}
                for s in result.get("segments", [])
            ],
        }
    except Exception as e:
        return {"available": False, "reason": "Transcription failed: %s" % e}


# -- Orchestration ---------------------------------------------------------

def analyse(path=None, transcript=None, language=None):
    """
    Full voice-scam analysis.

    Either `path` (an audio file) or `transcript` (analyst-supplied text) is
    required. Supplying both skips transcription and uses the given text, which
    is what an analyst wants when the ASR output needs correcting.

    Returns a dict ready to hand back as JSON.
    """
    result = {
        "transcript": None,
        "transcription": None,
        "acoustic": None,
        "script_score": 0,
        "reasons": [],
        "matched_indicators": [],
        "indicators": [],
        "verdict": "UNKNOWN",
    }

    text = (transcript or "").strip()

    if not text and path:
        tr = transcribe(path, language=language)
        result["transcription"] = tr
        if tr.get("available"):
            text = tr.get("text", "")

    result["transcript"] = text

    if path:
        result["acoustic"] = acoustic_screen(path)

    if not text:
        result["verdict"] = "NO_TRANSCRIPT"
        result["reasons"] = [
            "No transcript available. Install a speech-recognition backend or "
            "paste the call transcript to analyse the script."
        ]
        return result

    score, reasons, matched = score_transcript(text)
    result["script_score"] = score
    result["reasons"] = reasons
    result["matched_indicators"] = matched
    result["indicators"] = [i.to_dict() for i in extract_all(text)]

    # The verdict comes from the transcript only. The acoustic screen is
    # reported alongside it but deliberately excluded from the decision --
    # an unvalidated heuristic must not move a verdict that leads to a
    # blocking request.
    if score >= 70:
        result["verdict"] = "VOICE_SCAM"
    elif score >= 35:
        result["verdict"] = "SUSPICIOUS"
    else:
        result["verdict"] = "NO_SCRIPT_INDICATORS"

    result["recommendation"] = _recommendation(result["verdict"], matched)
    return result


def _recommendation(verdict, matched):
    if verdict == "VOICE_SCAM":
        base = (
            "RECOMMENDATION: The transcript matches the structure of a coercion "
            "fraud script. Report the calling number through Sanchar Saathi "
            "(Chakshu) for disconnection and register a complaint at "
            "cybercrime.gov.in. If money has already been transferred, call 1930 "
            "immediately — a lien within the first hours is the largest single "
            "determinant of recovery."
        )
        if any("remote-access" in m for m in matched):
            base += (" The caller requested remote-access software; treat every "
                     "device involved as compromised and reset credentials.")
        if any("digital arrest" in m.lower() for m in matched):
            base += (" No Indian law-enforcement agency conducts arrests over a "
                     "video call. This is conclusive of the 'digital arrest' fraud.")
        return base
    if verdict == "SUSPICIOUS":
        return (
            "RECOMMENDATION: Some coercion-script indicators are present but the "
            "evidence is not conclusive. Verify the caller independently through "
            "the organisation's published number — never a number supplied by the "
            "caller — before taking any action they requested."
        )
    return (
        "RECOMMENDATION: No voice-fraud script indicators detected in the "
        "transcript. This does not certify the call as genuine; it means the "
        "specific coercion patterns this module checks for were absent."
    )
