"""
services/intel/apk.py
---------------------
Android package (APK) analysis for illegal betting and fraud apps.

Illegal betting in India is distributed as sideloaded APKs, not as web pages.
Mahadev-style operations ship dozens of reskinned builds -- different name,
different icon, different domain -- signed with the *same certificate*, because
re-signing breaks their update channel. That certificate fingerprint links
every clone to one operator, and no other module in the platform could see it.

What this extracts
------------------
    package name, version           from the binary AndroidManifest.xml
    requested permissions           ditto
    signing certificate fingerprint from META-INF/*.RSA|DSA|EC
    embedded URLs / UPI IDs / phones by scanning DEX and resource strings
    risk assessment                 permission profile + betting-term density

Dependencies
------------
androguard is used when installed. When it is not, a minimal binary-XML (AXML)
parser implemented here reads the manifest directly -- an APK is a ZIP and the
manifest is a well-documented chunked format, so the fallback is a real parser
rather than a degraded guess. That keeps the module working on a deployment
that cannot install androguard's dependency tree.
"""

from __future__ import annotations

import hashlib
import os
import re
import struct
import zipfile

from services.intel.indicators import (
    extract_all, Indicator, KIND_APK_CERT, KIND_DOMAIN, KIND_URL, KIND_UPI,
)

# -- Permissions that matter for fraud apps --------------------------------
# Weight reflects how much the permission enables fraud specifically, not how
# dangerous it is in general.
RISKY_PERMISSIONS = {
    "android.permission.READ_SMS": (25, "Reads SMS — enables OTP interception"),
    "android.permission.RECEIVE_SMS": (25, "Receives SMS — enables OTP interception"),
    "android.permission.SEND_SMS": (20, "Sends SMS — enables premium-rate abuse and spread"),
    "android.permission.READ_CONTACTS": (15, "Reads contacts — enables victim-list harvesting"),
    "android.permission.CALL_PHONE": (10, "Places calls without confirmation"),
    "android.permission.READ_CALL_LOG": (15, "Reads call history"),
    "android.permission.SYSTEM_ALERT_WINDOW": (25, "Draws over other apps — enables overlay credential theft"),
    "android.permission.BIND_ACCESSIBILITY_SERVICE": (30, "Accessibility service — enables full UI automation and keylogging"),
    "android.permission.REQUEST_INSTALL_PACKAGES": (20, "Installs further packages — dropper behaviour"),
    "android.permission.READ_EXTERNAL_STORAGE": (5, "Reads external storage"),
    "android.permission.WRITE_EXTERNAL_STORAGE": (5, "Writes external storage"),
    "android.permission.RECORD_AUDIO": (15, "Records audio"),
    "android.permission.CAMERA": (10, "Camera access"),
    "android.permission.ACCESS_FINE_LOCATION": (10, "Precise location"),
    "android.permission.QUERY_ALL_PACKAGES": (10, "Enumerates installed apps — targets banking apps"),
    "android.permission.DISABLE_KEYGUARD": (15, "Disables the lock screen"),
    "android.permission.RECEIVE_BOOT_COMPLETED": (5, "Starts on boot — persistence"),
}

# Terms whose presence in an APK's strings indicates gambling functionality.
BETTING_TERMS = [
    "teenpatti", "teen patti", "rummy", "andarbahar", "andar bahar", "jhandimunda",
    "dragontiger", "dragon tiger", "satta", "matka", "lottery", "casino",
    "roulette", "baccarat", "blackjack", "slots", "jackpot", "betting",
    "bet365", "parimatch", "1xbet", "melbet", "fairplay", "lotus365",
    "mahadev", "wager", "odds", "cricket betting", "ipl betting",
    "deposit bonus", "withdraw winnings", "recharge chips", "buy chips",
]

# Well-known legitimate signing authorities would be a useful allowlist, but a
# wrong entry here would clear a malicious app -- so there is no allowlist, and
# every certificate is reported neutrally as an identity, not as a verdict.


# -- Binary AndroidManifest.xml (AXML) parser ------------------------------

_CHUNK_STRING_POOL = 0x0001
_CHUNK_START_ELEMENT = 0x0102
_UTF8_FLAG = 1 << 8


def _parse_string_pool(data, offset):
    """
    Parse a RES_STRING_POOL_TYPE chunk.

    Returns (strings, next_offset). Handles both the UTF-8 and UTF-16 encodings
    that AXML uses depending on the build tool version.
    """
    chunk_type, header_size, chunk_size = struct.unpack_from("<HHI", data, offset)
    string_count, style_count, flags, strings_start, styles_start = struct.unpack_from(
        "<IIIII", data, offset + 8
    )

    is_utf8 = bool(flags & _UTF8_FLAG)
    offsets_at = offset + header_size
    data_at = offset + strings_start

    strings = []
    for i in range(string_count):
        try:
            str_offset = struct.unpack_from("<I", data, offsets_at + i * 4)[0]
            pos = data_at + str_offset
            if is_utf8:
                # Two varint-ish lengths (UTF-16 length, then byte length).
                n16 = data[pos]
                pos += 2 if (n16 & 0x80) else 1
                n8 = data[pos]
                if n8 & 0x80:
                    n8 = ((n8 & 0x7F) << 8) | data[pos + 1]
                    pos += 2
                else:
                    pos += 1
                strings.append(data[pos:pos + n8].decode("utf-8", errors="replace"))
            else:
                n = struct.unpack_from("<H", data, pos)[0]
                if n & 0x8000:
                    n = ((n & 0x7FFF) << 16) | struct.unpack_from("<H", data, pos + 2)[0]
                    pos += 4
                else:
                    pos += 2
                strings.append(data[pos:pos + n * 2].decode("utf-16-le", errors="replace"))
        except Exception:
            strings.append("")

    return strings, offset + chunk_size


def parse_axml(data):
    """
    Extract elements and attributes from a binary AndroidManifest.xml.

    Returns a list of {"name": tag, "attrs": {attr: value}}. Attribute values
    that are resource references or non-string types come back as the raw
    integer rendered as a string -- for permissions and the package name, which
    is what this module needs, the values are plain strings.
    """
    if len(data) < 8:
        return []

    # File header, then chunks.
    offset = 8
    strings = []
    elements = []

    while offset + 8 <= len(data):
        try:
            chunk_type, header_size, chunk_size = struct.unpack_from("<HHI", data, offset)
        except struct.error:
            break
        if chunk_size <= 0 or offset + chunk_size > len(data):
            break

        if chunk_type == _CHUNK_STRING_POOL:
            strings, _ = _parse_string_pool(data, offset)

        elif chunk_type == _CHUNK_START_ELEMENT:
            try:
                name_idx = struct.unpack_from("<I", data, offset + 20)[0]
                attr_start, attr_size, attr_count = struct.unpack_from("<HHH", data, offset + 24)
                tag = strings[name_idx] if 0 <= name_idx < len(strings) else "?"

                attrs = {}
                # attributeStart is measured from the start of the attrExt
                # struct, which begins 16 bytes into the chunk (8-byte chunk
                # header + lineNumber + comment) -- not from the chunk start.
                base = offset + 16 + attr_start
                for i in range(attr_count):
                    a = base + i * attr_size
                    a_name_idx = struct.unpack_from("<I", data, a + 4)[0]
                    a_raw_idx = struct.unpack_from("<i", data, a + 8)[0]
                    a_data = struct.unpack_from("<I", data, a + 16)[0]
                    a_name = strings[a_name_idx] if 0 <= a_name_idx < len(strings) else "?"
                    if 0 <= a_raw_idx < len(strings):
                        value = strings[a_raw_idx]
                    elif 0 <= a_data < len(strings):
                        value = strings[a_data]
                    else:
                        value = str(a_data)
                    attrs[a_name] = value
                elements.append({"name": tag, "attrs": attrs})
            except (struct.error, IndexError):
                pass

        offset += chunk_size

    return elements


# -- Certificate fingerprint ----------------------------------------------

def _signing_certificates(zf):
    """
    SHA-256 fingerprints of the signing certificates in META-INF.

    The fingerprint is taken over the raw PKCS#7 block. That is stable across
    reskins of the same app -- which is the property that links a family of
    clones -- without needing an ASN.1 parser to reach the embedded X.509.
    """
    out = []
    for name in zf.namelist():
        upper = name.upper()
        if upper.startswith("META-INF/") and upper.endswith((".RSA", ".DSA", ".EC")):
            try:
                blob = zf.read(name)
            except Exception:
                continue
            out.append({
                "file": name,
                "sha256": hashlib.sha256(blob).hexdigest(),
                "size": len(blob),
            })
    return out


# -- String mining ---------------------------------------------------------

_PRINTABLE = re.compile(rb"[\x20-\x7e]{6,}")


def _mine_strings(zf, max_bytes=24 * 1024 * 1024):
    """
    Pull printable strings out of DEX and resource blobs.

    Bounded: a large APK's classes.dex can be tens of megabytes and scanning
    all of it inside a request is not worth the latency. The cap is applied
    across files, largest-value files first.
    """
    targets = []
    for info in zf.infolist():
        n = info.filename.lower()
        if n.endswith(".dex") or n in ("resources.arsc",) or n.startswith("assets/"):
            targets.append(info)

    # DEX first: embedded endpoints are almost always there.
    targets.sort(key=lambda i: (0 if i.filename.lower().endswith(".dex") else 1, -i.file_size))

    collected = []
    budget = max_bytes
    for info in targets:
        if budget <= 0:
            break
        try:
            blob = zf.read(info.filename)[:budget]
        except Exception:
            continue
        budget -= len(blob)
        for m in _PRINTABLE.finditer(blob):
            try:
                collected.append(m.group(0).decode("ascii"))
            except Exception:
                continue

    return collected


def analyse(path):
    """
    Full APK analysis.

    Returns a dict ready to serve as JSON. Never raises on a malformed file --
    a corrupt or non-APK upload comes back as an error field.
    """
    if not os.path.exists(path):
        return {"error": "File not found."}

    result = {
        "file_sha256": None,
        "package": None,
        "version_name": None,
        "version_code": None,
        "permissions": [],
        "risky_permissions": [],
        "certificates": [],
        "betting_terms": [],
        "indicators": [],
        "risk_score": 0,
        "reasons": [],
        "parser": None,
    }

    try:
        with open(path, "rb") as f:
            result["file_sha256"] = hashlib.sha256(f.read()).hexdigest()
    except Exception as e:
        return {"error": "Could not read file: %s" % e}

    try:
        zf = zipfile.ZipFile(path)
    except zipfile.BadZipFile:
        return {"error": "Not a valid APK (the file is not a ZIP archive)."}

    try:
        names = set(zf.namelist())
        if "AndroidManifest.xml" not in names:
            return {"error": "Not a valid APK (no AndroidManifest.xml)."}

        # -- Manifest ---------------------------------------------------
        parsed = False
        try:
            from androguard.core.bytecodes.apk import APK  # type: ignore
            apk = APK(path)
            result["package"] = apk.get_package()
            result["version_name"] = apk.get_androidversion_name()
            result["version_code"] = apk.get_androidversion_code()
            result["permissions"] = sorted(apk.get_permissions())
            result["parser"] = "androguard"
            parsed = True
        except Exception:
            pass

        if not parsed:
            try:
                elements = parse_axml(zf.read("AndroidManifest.xml"))
                perms = set()
                for el in elements:
                    if el["name"] == "manifest":
                        result["package"] = el["attrs"].get("package") or result["package"]
                        result["version_name"] = el["attrs"].get("versionName")
                        result["version_code"] = el["attrs"].get("versionCode")
                    elif el["name"] == "uses-permission":
                        value = el["attrs"].get("name")
                        if value and value.startswith("android."):
                            perms.add(value)
                result["permissions"] = sorted(perms)
                result["parser"] = "builtin-axml"
            except Exception as e:
                result["parser"] = "failed"
                result["reasons"].append("Manifest could not be parsed: %s" % e)

        # -- Certificates -----------------------------------------------
        result["certificates"] = _signing_certificates(zf)

        # -- Strings ----------------------------------------------------
        strings = _mine_strings(zf)
        blob = "\n".join(strings)
        lowered = blob.lower()

        found_terms = sorted({t for t in BETTING_TERMS if t in lowered})
        result["betting_terms"] = found_terms

        # Retain a bounded sample of the mined strings so other analysers can
        # work from this parse rather than re-opening the archive. The lending
        # detector in services/intel/lending.py needs them to decide whether
        # the package even presents as a lender, which is what makes its
        # permission findings mean anything.
        result["strings"] = strings[:4000]

        # Indicator extraction over mined strings. Bounded, and restricted to
        # network- and payment-bearing kinds: a DEX contains a great deal of
        # digit noise that the phone extractor would otherwise mine for
        # spurious numbers.
        wanted = {KIND_DOMAIN, KIND_URL, KIND_UPI}
        indicators = [i for i in extract_all(blob[:400000]) if i.kind in wanted]
        for cert in result["certificates"]:
            indicators.append(Indicator(
                kind=KIND_APK_CERT, raw=cert["sha256"], normalized=cert["sha256"],
                confidence=1.0, context="Signing certificate %s" % cert["file"],
                meta={"file": cert["file"], "size": cert["size"]},
            ))
        result["indicators"] = [i.to_dict() for i in indicators]

    finally:
        zf.close()

    # -- Risk assessment ------------------------------------------------
    score = 0
    reasons = list(result["reasons"])

    for perm in result["permissions"]:
        if perm in RISKY_PERMISSIONS:
            weight, why = RISKY_PERMISSIONS[perm]
            score += weight
            result["risky_permissions"].append({"permission": perm, "weight": weight, "why": why})

    if found_terms:
        term_score = min(40, 10 + len(found_terms) * 5)
        score += term_score
        reasons.append(
            "Contains %d gambling-related term(s): %s"
            % (len(found_terms), ", ".join(found_terms[:8]))
        )

    # The OTP-interception combination is the signature of a banking dropper
    # and is worth more than its parts.
    perms = set(result["permissions"])
    if {"android.permission.READ_SMS", "android.permission.RECEIVE_SMS"} & perms and \
       "android.permission.BIND_ACCESSIBILITY_SERVICE" in perms:
        score += 20
        reasons.append(
            "Requests SMS access together with an accessibility service — the "
            "standard combination for automated OTP interception."
        )

    if not result["certificates"]:
        reasons.append(
            "No signing certificate found. The APK is unsigned or was repacked, "
            "so it cannot have been installed from Play Store."
        )
        score += 10

    result["risk_score"] = min(score, 100)
    result["reasons"] = reasons

    if result["risk_score"] >= 70:
        result["verdict"] = "HIGH_RISK"
    elif result["risk_score"] >= 35:
        result["verdict"] = "SUSPICIOUS"
    else:
        result["verdict"] = "LOW_RISK"

    # Lending assessment. Conditional on the package presenting as a lender,
    # so an ordinary app that reads contacts is not accused of anything.
    try:
        from services.intel import lending
        result["lending"] = lending.analyse_app(result)
        if result["lending"].get("is_lending_app"):
            # A predatory lender scores on its own scale; take the higher of
            # the two rather than averaging, because the two assessments are
            # about different things.
            result["risk_score"] = max(result["risk_score"],
                                       result["lending"]["score"])
            result["reasons"].extend(result["lending"].get("reasons", []))
    except Exception as e:
        print("[APK] lending assessment unavailable: %s" % e)

    result["recommendation"] = _recommendation(result)
    return result


def _recommendation(result):
    if result.get("verdict") == "HIGH_RISK":
        base = (
            "RECOMMENDATION: Package exhibits a high-risk profile. Report the "
            "signing certificate fingerprint to Google Play and to the hosting "
            "site's registrar — the fingerprint identifies every reskinned build "
            "from the same operator, so one report can cover an entire family of "
            "clones."
        )
        if result.get("betting_terms"):
            base += (
                " Gambling functionality was detected; where the operator is "
                "unlicensed, refer the distribution URL to MeitY for blocking "
                "under the IT Rules."
            )
        return base
    if result.get("verdict") == "SUSPICIOUS":
        return (
            "RECOMMENDATION: Some high-risk traits present but not conclusive. "
            "Review the permission list and the embedded endpoints before acting."
        )
    return (
        "RECOMMENDATION: No high-risk traits detected in the manifest or strings. "
        "Static analysis only — this does not certify the package as safe, since "
        "behaviour delivered at runtime is not visible to it."
    )
