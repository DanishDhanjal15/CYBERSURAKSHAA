"""
Phase 4 crime coverage: predatory lending and scam-stage classification.

Both of these produce *advice*, not just a score, so the tests care about the
advice being right for the situation. Telling somebody at the extraction stage
to watch for warning signs they passed three weeks ago is worse than saying
nothing, and accusing a messaging app of being a predatory lender because it
reads contacts is a false accusation.
"""

import pytest

from services.intel import lending, lifecycle


# ══════════════════════════════════════════════════════════════════════════
# Predatory lending
# ══════════════════════════════════════════════════════════════════════════

LOAN_STRINGS = ["instant loan approval", "repayment tenure", "processing fee",
                "credit limit", "disbursal to your bank account"]

CHAT_STRINGS = ["send message", "group chat", "sticker pack", "video call"]

EXTORTION_KIT = ["android.permission.READ_CONTACTS",
                 "android.permission.READ_SMS",
                 "android.permission.READ_EXTERNAL_STORAGE",
                 "android.permission.INTERNET"]


class TestIsItEvenALender:
    def test_a_loan_app_is_recognised(self):
        result = lending.looks_like_lending(LOAN_STRINGS, package="com.quick.rupee.loan")
        assert result["is_lending"] is True

    def test_a_messaging_app_is_not(self):
        """
        Everything else in the module is conditional on this. An app reading
        contacts for its own stated purpose is doing its job.
        """
        assert lending.looks_like_lending(CHAT_STRINGS, package="com.chat.app")["is_lending"] is False

    def test_one_stray_word_is_not_enough(self):
        """A single occurrence of 'credit' does not make something a lender."""
        assert lending.looks_like_lending(["credit card offers in our store"],
                                          package="com.shop.app")["is_lending"] is False

    def test_a_chat_app_with_the_extortion_kit_is_not_accused(self):
        result = lending.analyse_app({"package": "com.chat.app",
                                      "strings": CHAT_STRINGS,
                                      "permissions": EXTORTION_KIT})
        assert result["is_lending_app"] is False
        assert result["score"] == 0
        assert result["verdict"] == "NOT_A_LENDING_APP"
        assert "does not present as a lender" in result["note"]


class TestProhibitedPermissions:
    def test_contacts_on_a_lender_is_a_guideline_breach(self):
        """
        The RBI Digital Lending Guidelines expressly bar a DLA from accessing
        the contact list. This is a finding, not an inference.
        """
        result = lending.assess_permissions(["android.permission.READ_CONTACTS"])
        assert result["score"] >= 35
        why = result["violations"][0]["why"]
        assert "contact" in why.lower() and "RBI" in why

    def test_contacts_plus_gallery_scores_above_their_sum(self):
        """Together they are the complete contact-shaming toolkit."""
        contacts = lending.assess_permissions(["android.permission.READ_CONTACTS"])["score"]
        gallery = lending.assess_permissions(["android.permission.READ_EXTERNAL_STORAGE"])["score"]
        both = lending.assess_permissions(["android.permission.READ_CONTACTS",
                                           "android.permission.READ_EXTERNAL_STORAGE"])["score"]
        assert both > contacts + gallery

    def test_kyc_permissions_are_noted_not_scored(self):
        """Camera for one-time KYC is permitted with explicit consent."""
        result = lending.assess_permissions(["android.permission.CAMERA"])
        assert result["score"] == 0
        assert result["kyc_permissions"][0]["permission"] == "android.permission.CAMERA"

    def test_a_full_extortion_kit_reads_as_predatory(self):
        result = lending.analyse_app({"package": "com.quick.rupee.loan",
                                      "strings": LOAN_STRINGS,
                                      "permissions": EXTORTION_KIT})
        assert result["verdict"] == "PREDATORY_LENDING"
        assert result["score"] >= 70

    def test_a_clean_lender_is_not_condemned(self):
        result = lending.analyse_app({"package": "com.bank.lending",
                                      "strings": LOAN_STRINGS,
                                      "permissions": ["android.permission.INTERNET"]})
        assert result["verdict"] == "LENDING_APP"


class TestRegistrationCheck:
    def setup_method(self):
        lending.set_registered_entities([])

    def teardown_method(self):
        lending.set_registered_entities([])

    def test_with_no_register_loaded_it_says_so(self):
        """
        A stale whitelist would clear an app that has since been delisted, so
        none is shipped. Absence must not read as 'unregistered'.
        """
        result = lending.check_registration(LOAN_STRINGS)
        assert result["checked"] is False
        assert "not evidence the operator is unregistered" in result["note"]

    def test_no_score_is_added_when_registration_could_not_be_checked(self):
        unchecked = lending.analyse_app({"package": "com.quick.rupee.loan",
                                         "strings": LOAN_STRINGS,
                                         "permissions": ["android.permission.INTERNET"]})
        lending.set_registered_entities(["Some Registered NBFC Ltd"])
        checked = lending.analyse_app({"package": "com.quick.rupee.loan",
                                       "strings": LOAN_STRINGS,
                                       "permissions": ["android.permission.INTERNET"]})
        assert checked["score"] > unchecked["score"]

    def test_a_named_registered_entity_clears_the_disclosure_test(self):
        lending.set_registered_entities(["acme finance limited"])
        result = lending.check_registration(
            LOAN_STRINGS + ["Lending partner: Acme Finance Limited"])
        assert result["checked"] is True
        assert result["named_entities"] == ["acme finance limited"]


class TestHarassment:
    @pytest.mark.parametrize("message,expected", [
        ("All your contacts will be informed about your default",
         "contact"),
        ("We have your contact list and your photo will be sent to everyone",
         "photograph"),
        ("Pay within 2 hours or arrest warrant will be issued",
         "arrest"),
    ])
    def test_recognises_the_standard_threats(self, message, expected):
        result = lending.score_harassment(message)
        assert result["score"] > 0
        assert any(expected in label.lower() for label in result["matched"])

    def test_morphed_imagery_scores_highest(self):
        """
        The most serious variant, and the one that changes which offences
        apply.
        """
        result = lending.score_harassment(
            "Your nude photo will be sent to your family list")
        assert result["score"] >= 45

    def test_an_ordinary_reminder_is_not_harassment(self):
        result = lending.score_harassment(
            "Your EMI of Rs 2000 is due on the 5th. Please pay on time to "
            "avoid late charges.")
        assert result["score"] == 0

    def test_hinglish_threats_are_caught(self):
        """These arrive in Hinglish far more often than in English."""
        result = lending.score_harassment(
            "Aapke saare contacts ko inform kar denge, ghar wale ko bhi call karenge")
        assert result["score"] > 0

    def test_empty_text_scores_zero(self):
        assert lending.score_harassment("")["score"] == 0
        assert lending.score_harassment(None)["score"] == 0


class TestVictimGuidance:
    def test_says_a_debt_is_not_an_arrestable_matter(self):
        points = " ".join(lending.victim_guidance()["points"])
        assert "civil matter" in points
        assert "arrested" in points

    def test_says_paying_more_does_not_stop_it(self):
        assert "does not end them" in " ".join(lending.victim_guidance()["points"])

    def test_tells_them_to_capture_permissions_before_uninstalling(self):
        """The permission screen is evidence, and it disappears with the app."""
        points = " ".join(lending.victim_guidance()["points"])
        assert "Do not delete the app before capturing" in points


# ══════════════════════════════════════════════════════════════════════════
# Stage classification
# ══════════════════════════════════════════════════════════════════════════

class TestStageClassification:
    def test_wrong_number_opener_is_first_contact(self):
        result = lifecycle.classify("Sorry, wrong number! Is this Priya?")
        assert result["stage"] == lifecycle.S_CONTACT

    def test_paid_task_is_grooming(self):
        result = lifecycle.classify(
            "Complete this small task and your commission has been credited. "
            "You can withdraw anytime.")
        assert result["stage"] == lifecycle.S_GROOMING

    def test_blocked_withdrawal_is_extraction(self):
        """The defining move of the whole script."""
        result = lifecycle.classify(
            "Your withdrawal is blocked. Pay 15% income tax to release your "
            "balance of Rs 4,80,000.")
        assert result["stage"] == lifecycle.S_EXTRACTION
        assert result["confidence"] in ("moderate", "high")

    def test_unsolicited_refund_offer_is_recovery_fraud(self):
        result = lifecycle.classify(
            "We can recover your money back. Our recovery team charges only a "
            "small processing fee.")
        assert result["stage"] == lifecycle.S_RECOVERY_FRAUD

    def test_bigger_deposit_prompt_is_the_investment_stage(self):
        result = lifecycle.classify(
            "Upgrade to VIP level and deposit more. Your portfolio balance is "
            "showing 2,40,000 profit.")
        assert result["stage"] == lifecycle.S_INVESTMENT

    def test_unrecognised_text_returns_no_stage(self):
        result = lifecycle.classify("Are we still meeting at four?")
        assert result["stage"] is None
        assert "not a finding that the conversation is safe" in result["caveat"]

    def test_empty_input_is_handled(self):
        assert lifecycle.classify("")["stage"] is None
        assert lifecycle.classify(None)["stage"] is None


class TestStageEvidence:
    def test_a_single_phrase_is_low_confidence(self):
        """
        Wording is what the operator controls. One phrase is a hint, and
        asserting a stage from it produces confidently wrong advice.
        """
        result = lifecycle.classify("Add me on WhatsApp")
        assert result["confidence"] == "low"
        assert "single phrase" in result["caveat"]

    def test_several_indicators_raise_confidence(self):
        result = lifecycle.classify(
            "Your withdrawal is blocked. Pay the unfreeze fee. Account frozen "
            "until you deposit the clearance amount.")
        assert result["confidence"] == "high"
        assert len(result["evidence"]) >= 2

    def test_evidence_is_always_returned(self):
        result = lifecycle.classify("Complete this task, commission credited")
        assert result["evidence"]

    def test_all_stage_scores_are_exposed(self):
        """So a reader can see how close the runner-up was."""
        result = lifecycle.classify("Your withdrawal is blocked, pay tax to release")
        assert set(result["all_scores"]) == set(lifecycle.STAGE_ORDER)


class TestMoneyMovedOverride:
    def test_a_transfer_lifts_an_early_reading(self):
        """
        The operator writes the reassuring words; the transfer is the fact.
        Reading this as grooming would advise somebody they can still walk
        away for nothing.
        """
        result = lifecycle.classify(
            "Complete the task and trust me, commission credited. I already "
            "transferred Rs 50,000 as you asked.")
        assert lifecycle.STAGE_ORDER.index(result["stage"]) >= \
            lifecycle.STAGE_ORDER.index(lifecycle.S_INVESTMENT)
        assert result["money_moved"] is True

    def test_caller_knowledge_overrides_the_text(self):
        result = lifecycle.classify("Sorry wrong number, is this Priya?",
                                    money_already_sent=True)
        assert result["money_moved"] is True

    def test_it_never_drags_a_late_stage_backwards(self):
        result = lifecycle.classify(
            "Withdrawal blocked, pay the unfreeze fee to release your balance",
            money_already_sent=True)
        assert result["stage"] == lifecycle.S_EXTRACTION


class TestAdviceMatchesTheStage:
    def test_first_contact_costs_nothing_to_leave(self):
        advice = lifecycle.advice_for(lifecycle.S_CONTACT)
        assert advice["cost_of_stopping"] == "Nothing."

    def test_grooming_advice_names_the_payouts_as_the_hook(self):
        advice = lifecycle.advice_for(lifecycle.S_GROOMING)
        assert "hook" in advice["headline"].lower()
        assert "later victims" in " ".join(advice["steps"])

    def test_extraction_advice_says_stop_paying(self):
        """
        The single decision that limits the loss. Advice at this stage that
        talked about spotting warning signs would be three weeks too late.
        """
        advice = lifecycle.advice_for(lifecycle.S_EXTRACTION)
        assert "Stop paying now" in " ".join(advice["steps"])
        assert "no balance to release" in advice["headline"].lower()

    def test_extraction_warns_of_the_follow_up_approach(self):
        advice = lifecycle.advice_for(lifecycle.S_EXTRACTION)
        assert "same operation" in " ".join(advice["steps"])

    def test_investment_advice_prioritises_a_recent_transfer(self):
        """A transfer in the last hours is the only one with a real chance."""
        steps = " ".join(lifecycle.advice_for(lifecycle.S_INVESTMENT)["steps"])
        assert "last few hours" in steps and "1930" in steps

    def test_recovery_fraud_advice_says_pay_nothing(self):
        advice = lifecycle.advice_for(lifecycle.S_RECOVERY_FRAUD)
        assert "Pay nothing" in " ".join(advice["steps"])

    def test_every_stage_has_advice(self):
        for stage in lifecycle.STAGE_ORDER:
            advice = lifecycle.advice_for(stage)
            assert advice["headline"] and advice["steps"]
