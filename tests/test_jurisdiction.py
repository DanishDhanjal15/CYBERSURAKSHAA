"""
Jurisdiction routing.

The failure mode here is confident wrongness: naming a force that has no
territory over the case, or presenting a phone-prefix guess as a determination.
Most of these test that a weak signal stays labelled weak and that an unknown
stays unknown.
"""

import pytest

from services.intel import jurisdiction as jx


class TestDirectory:
    def test_all_thirty_six_are_present(self):
        """28 States plus 8 Union Territories. Police is a State subject."""
        s = jx.summary()
        assert s["states"] == 28
        assert s["union_territories"] == 8
        assert s["jurisdictions"] == 36

    def test_no_contact_is_pre_filled(self):
        """
        A wrong number for a state cyber cell sends a victim to a dead line
        during the hours that decide whether their money is recoverable.
        """
        for record in jx.all_jurisdictions():
            assert record["contact"] == jx.CONTACT_PLACEHOLDER
            assert record["contact_verified"] is False

    def test_national_channels_are_filled_in(self):
        """These are stable and universal, unlike the state contacts."""
        record = jx.get("MH")
        assert record["national"]["helpline"] == "1930"
        assert "cybercrime.gov.in" in record["national"]["portal"]

    def test_every_jurisdiction_has_a_region(self):
        assert all(r["region"] for r in jx.all_jurisdictions())
        assert set(jx.by_region()) == {"North", "South", "East", "West",
                                       "Central", "North East"}


class TestNormalisation:
    @pytest.mark.parametrize("given,expected", [
        ("MH", "MH"), ("mh", "MH"),
        ("Maharashtra", "MH"), ("MAHARASHTRA", "MH"),
        ("Mumbai", "MH"), ("Pune", "MH"),
        ("Delhi NCR", "DL"), ("Delhi", "DL"),
        ("Bengaluru", "KA"), ("Bangalore", "KA"),
    ])
    def test_accepts_what_the_platform_actually_produces(self, given, expected):
        """geo_intel emits names like 'Delhi NCR'; people type city names."""
        assert jx.normalise(given) == expected

    @pytest.mark.parametrize("old,current", [
        ("TG", "TS"),      # Telangana adopted TG alongside TS
        ("OR", "OD"),      # Orissa renamed Odisha
        ("DD", "DH"),      # merged into one UT in 2020
        ("UA", "UK"),
    ])
    def test_superseded_codes_still_resolve(self, old, current):
        assert jx.normalise(old) == current

    def test_unknown_is_none_not_a_guess(self):
        for junk in ("ZZ", "Atlantis", "", None, "12345"):
            assert jx.normalise(junk) is None

    def test_ambiguous_prefix_does_not_resolve(self):
        """
        'M' prefixes Maharashtra, Manipur, Meghalaya, Mizoram and Madhya
        Pradesh. Picking one would be inventing a jurisdiction.
        """
        assert jx.normalise("M") is None


class TestRouting:
    def test_a_stated_state_is_a_strong_signal(self):
        result = jx.route(stated_state="MH")
        assert result["primary"]["code"] == "MH"
        assert result["confidence"] == jx.STRONG
        assert result["rule"] == "complainant_state"

    def test_a_phone_prefix_is_only_weak(self):
        """
        Portability, roaming and VoIP all break the circle inference. It must
        never present as a determination.
        """
        result = jx.route(phone="9820123456")
        if result["primary"]:
            assert result["confidence"] == jx.WEAK
            assert "lead rather than a location" in result["reason"] \
                or "close to no evidence" in result["reason"]

    def test_a_stated_state_outranks_a_phone_guess(self):
        result = jx.route(stated_state="BR", phone="9820123456")
        assert result["primary"]["code"] == "BR"
        assert result["confidence"] == jx.STRONG

    def test_nothing_known_returns_none_and_says_why(self):
        result = jx.route()
        assert result["primary"] is None
        assert "No jurisdiction could be determined" in result["reason"]
        assert "which State or Union Territory" in result["reason"]

    def test_every_candidate_is_returned_not_just_the_winner(self):
        """
        Victim in Bihar, mule account in Maharashtra: both forces are involved
        and hiding one behind a single answer would be worse than useless.
        """
        result = jx.route(stated_state="BR", beneficiary_state="MH")
        codes = {c["jurisdiction"]["code"] for c in result["candidates"]}
        assert codes == {"BR", "MH"}
        assert result["multi_jurisdiction"] is True
        assert "three different States" in result["multi_jurisdiction_note"]

    def test_a_single_jurisdiction_is_not_flagged_as_multi(self):
        result = jx.route(stated_state="MH", beneficiary_state="Mumbai")
        assert result["multi_jurisdiction"] is False
        assert result["multi_jurisdiction_note"] is None

    def test_infrastructure_is_labelled_as_locating_a_server(self):
        result = jx.route(infrastructure_state="KA")
        assert "not a person" in result["reason"]

    def test_unknown_states_are_ignored_rather_than_routed_to(self):
        result = jx.route(stated_state="Atlantis")
        assert result["primary"] is None


class TestZeroFir:
    def test_cites_the_current_statute(self):
        """
        The CrPC was replaced by the BNSS on 1 July 2024. Citing the CrPC
        would be citing a repealed code.
        """
        guidance = jx.zero_fir_guidance()
        assert "Bharatiya Nagarik Suraksha Sanhita 2023" in guidance["basis"]
        assert "section 173" in guidance["basis"]

    def test_says_a_station_cannot_refuse(self):
        points = " ".join(jx.zero_fir_guidance()["points"])
        assert "cannot lawfully refuse" in points

    def test_tells_them_to_call_1930_in_parallel(self):
        """
        The FIR and the money are different problems. A lien is time-critical
        and does not wait on the FIR.
        """
        guidance = jx.zero_fir_guidance()
        assert "1930" in " ".join(guidance["points"])
        assert "not instead of it" in " ".join(guidance["points"])
        assert "1930" in guidance["urgency"]

    def test_routing_always_carries_it(self):
        """Including when no jurisdiction could be worked out — especially then."""
        assert jx.route()["zero_fir"]["title"]


class TestAggregation:
    def test_unattributed_reports_are_counted_not_hidden(self, temp_db):
        """
        The proportion with no usable state is what says how much to trust the
        rest of the breakdown.
        """
        from services.intel import harm
        harm.init_harm_db()
        harm.record_report(10_000, category="investment", state_code="MH")
        harm.record_report(5_000, category="investment", state_code="ZZ")

        result = jx.loss_by_jurisdiction()
        assert [r["code"] for r in result["rows"]] == ["MH"]
        assert result["unattributed"]["reports"] == 1
        assert "excluded from this breakdown" in result["note"]

    def test_ranked_by_money_not_report_count(self, temp_db):
        from services.intel import harm
        harm.init_harm_db()
        harm.record_report(500_000, category="investment", state_code="BR")
        for _ in range(4):
            harm.record_report(1_000, category="investment", state_code="MH")

        rows = jx.loss_by_jurisdiction()["rows"]
        assert rows[0]["code"] == "BR"

    def test_carries_the_where_harm_was_suffered_caveat(self, temp_db):
        from services.intel import harm
        harm.init_harm_db()
        result = jx.loss_by_jurisdiction()
        assert "where harm was suffered" in result["caveat"]
