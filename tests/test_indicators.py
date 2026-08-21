"""
Indicator extraction.

These are the regression tests for the extractor, and most of them exist
because the case they cover was wrong at some point during development. Each
one names the mistake it locks out, because a test whose failure message does
not explain what broke costs more than it saves.
"""

import pytest

from services.intel.indicators import extract_all, DOMAIN_STOPLIST


def kinds(text):
    return {i.kind for i in extract_all(text)}


def values(text, kind):
    return {i.normalized for i in extract_all(text) if i.kind == kind}


class TestPhones:
    def test_plain_mobile(self):
        assert "9876543210" in values("call me on 9876543210", "phone")

    def test_country_code(self):
        assert "9876543210" in values("call +91 9876543210 now", "phone")

    @pytest.mark.parametrize("written", [
        "+91 98765-43210",
        "+91 987-654-3210",
        "098765 43210",
        "+91 9876.543210",
    ])
    def test_separator_variants(self, written):
        """
        Scam creatives almost never print a bare ten-digit run. Before the
        separator-tolerant patterns existed, every hyphenated number on a
        poster was invisible to the extractor.
        """
        assert "9876543210" in values("helpline %s" % written, "phone")

    def test_card_number_is_not_a_phone(self):
        """
        A 16-digit card contains many valid-looking 10-digit substrings. The
        digit-run guard is what stops the extractor manufacturing a phone
        number out of the middle of a PAN.
        """
        assert not values("card 4532015112830366 expires 12/27", "phone")

    def test_aadhaar_is_not_a_phone(self):
        assert not values("aadhaar 9876 5432 1098 attached", "phone")

    def test_tollfree(self):
        assert values("dial 1800 209 4324 for support", "phone")


class TestUpi:
    def test_basic_vpa(self):
        assert "scamguy@okhdfcbank" in values("pay to scamguy@okhdfcbank", "upi")

    def test_vpa_at_end_of_sentence(self):
        """
        A trailing full stop is sentence punctuation, not a domain label. An
        over-eager fix for the email case below once rejected this.
        """
        assert "scamguy@okhdfcbank" in values("send it to scamguy@okhdfcbank.", "upi")

    def test_email_is_not_a_upi_id(self):
        """
        `help@sbi-verification-login.com` was being read as the VPA
        `help@sbi` — which would have put a fabricated payment address into an
        enforcement notice sent to NPCI.
        """
        text = "write to help@sbi-verification-login.com"
        assert "help@sbi" not in values(text, "upi")
        assert not values(text, "upi")

    def test_email_still_extracted_as_email(self):
        assert values("write to help@sbi-verification-login.com", "email")


class TestBankAccounts:
    def test_cued_account_number(self):
        assert values("transfer to account number 38472910556677", "bank_account")

    def test_phone_after_account_word_is_not_an_account(self):
        """
        "Your account is blocked. Call 98765-43210" produced the phone number
        as a bank account as well, because the account cue matched across the
        sentence boundary. Deconfliction is what removes the duplicate.
        """
        text = "Your account is blocked. Call 98765-43210 immediately"
        assert "9876543210" in values(text, "phone")
        assert "9876543210" not in values(text, "bank_account")

    def test_ifsc(self):
        assert "SBIN0001234" in values("IFSC SBIN0001234", "ifsc")


class TestDomains:
    def test_domain_extracted(self):
        assert "sbi-verification-login.com" in values(
            "visit sbi-verification-login.com", "domain")

    @pytest.mark.parametrize("host", ["t.me", "whatsapp.com", "wa.me", "bit.ly"])
    def test_platform_hosts_are_stoplisted(self, host):
        """
        Every scam message links to Telegram or WhatsApp. Treating those hosts
        as indicators turned them into graph hubs that connected every
        unrelated campaign into one component.
        """
        assert host in DOMAIN_STOPLIST
        assert host not in values("join https://%s/abc" % host, "domain")

    def test_telegram_handle_still_extracted(self):
        """The stoplist drops the host, not the channel — the channel is the
        identifier that actually belongs to the operator."""
        assert values("join https://t.me/sbi_kyc_help now", "telegram")


class TestEndToEnd:
    def test_full_scam_message(self, sample_scam_text):
        found = kinds(sample_scam_text)
        for expected in ("phone", "upi", "bank_account", "ifsc",
                         "domain", "telegram"):
            assert expected in found, "missing %s in %s" % (expected, sorted(found))

    def test_no_indicator_appears_twice(self, sample_scam_text):
        """Deduplication is on (kind, normalized) -- the graph join key. Two
        rows with the same key would double-count an operator's sightings."""
        seen = [i.key for i in extract_all(sample_scam_text)]
        assert len(seen) == len(set(seen))

    def test_every_indicator_carries_provenance(self, sample_scam_text):
        """`raw` is what the analyst sees quoted in a notice, `context` is what
        justifies it. An indicator with neither cannot be defended."""
        for i in extract_all(sample_scam_text):
            assert i.raw, "indicator %r has no raw form" % (i.key,)
            assert 0.0 < i.confidence <= 1.0
            assert i.to_dict()["kind"] == i.kind

    def test_empty_input(self):
        assert extract_all("") == []
        assert extract_all(None) == []
