"""
Entity graph and campaign clustering.

The graph is the piece that makes this a platform rather than five separate
detectors, so the properties tested here are the ones that would silently
destroy its usefulness: duplicate entities, direction-dependent edges,
unbounded neighbourhoods, and hub collapse.
"""

import pytest

from services.intel import graph, campaigns
from services.intel.db import get_db_connection


def upsert(kind, value, risk=0):
    """upsert_entity takes a live connection so a caller can batch a whole
    artefact into one transaction. Tests do one at a time."""
    conn = get_db_connection()
    try:
        eid = graph.upsert_entity(conn, kind, value, risk=risk)
        conn.commit()
        return eid
    finally:
        conn.close()


def link(a, b):
    conn = get_db_connection()
    try:
        graph.link_entities(conn, a, b)
        conn.commit()
    finally:
        conn.close()


class TestUpsert:
    def test_same_value_is_one_entity(self, temp_db):
        a = upsert("upi", "scammer@okaxis")
        b = upsert("upi", "scammer@okaxis")
        assert a == b

    def test_sightings_accumulate(self, temp_db):
        eid = upsert("phone", "9876543210")
        upsert("phone", "9876543210")
        upsert("phone", "9876543210")
        ent = graph.get_entity_by_id(eid)
        assert ent["sightings"] >= 3

    def test_different_kinds_are_different_entities(self, temp_db):
        """A phone number and a bank account can be the same digits. Keying on
        value alone would merge a mule account with a helpline."""
        a = upsert("phone", "9876543210")
        b = upsert("bank_account", "9876543210")
        assert a != b


class TestEdges:
    def test_edge_is_undirected(self, temp_db):
        """
        link(A,B) and link(B,A) must be one row. Two rows would double every
        co-occurrence weight and make the clustering thresholds meaningless.
        """
        a = upsert("upi", "x@okaxis")
        b = upsert("phone", "9812345670")
        link(a, b)
        link(b, a)

        nb = graph.neighbourhood(a, depth=1)
        edges = [e for e in nb["edges"]
                 if {e["source"], e["target"]} == {a, b}]
        assert len(edges) == 1

    def test_edge_weight_grows_with_repeat_sightings(self, temp_db):
        a = upsert("upi", "y@okaxis")
        b = upsert("phone", "9812345671")
        link(a, b)
        first = graph.neighbourhood(a, depth=1)["edges"][0]["weight"]
        link(a, b)
        second = graph.neighbourhood(a, depth=1)["edges"][0]["weight"]
        assert second > first


class TestIngest:
    def test_ingest_creates_linked_entities(self, temp_db, sample_scam_text):
        result = graph.ingest(sample_scam_text, module="Customer Care",
                              verdict="DANGER", score=88, source="test")
        assert result["entities"] >= 4
        assert result["indicators"]

    def test_ingest_caps_indicators(self, temp_db):
        """
        A single OCR dump of a spam wall can contain hundreds of numbers.
        Without the cap, one artefact would produce a fully-connected clique
        of that size -- O(n^2) edges, and a graph nobody can read.
        """
        text = " ".join("98%08d" % i for i in range(200))
        result = graph.ingest(text, module="Betting Content",
                              verdict="BETTING", score=90, source="test")
        assert result["entities"] <= graph.MAX_INDICATORS_PER_ARTEFACT

    def test_ingest_of_empty_text_is_a_noop(self, temp_db):
        result = graph.ingest("", module="X", verdict="SAFE", score=0)
        assert result["entities"] == 0


class TestNeighbourhood:
    def test_node_cap_is_enforced(self, temp_db):
        """An analyst opening a hub must not be handed ten thousand nodes; the
        response says it was truncated rather than pretending to be complete."""
        hub = upsert("phone", "9800000000")
        for i in range(60):
            leaf = upsert("upi", "leaf%d@okaxis" % i)
            link(hub, leaf)

        nb = graph.neighbourhood(hub, depth=2, max_nodes=20)
        assert len(nb["nodes"]) <= 20
        assert nb["truncated"] is True

    def test_no_dangling_edges(self, temp_db):
        """
        Every edge returned must have both endpoints in `nodes`. A renderer
        handed an edge to a missing node either throws or silently invents
        the node -- Cytoscape does the latter, which is worse.
        """
        hub = upsert("phone", "9800000001")
        for i in range(40):
            leaf = upsert("upi", "l%d@okaxis" % i)
            link(hub, leaf)

        nb = graph.neighbourhood(hub, depth=2, max_nodes=15)
        ids = {n["id"] for n in nb["nodes"]}
        for e in nb["edges"]:
            assert e["source"] in ids and e["target"] in ids


class TestCampaigns:
    def test_shared_upi_merges_two_artefacts(self, temp_db):
        graph.ingest("Deposit to boss@okaxis, call 9811111111",
                     module="Betting Content", verdict="BETTING", score=95)
        graph.ingest("Pay boss@okaxis then WhatsApp 9822222222",
                     module="Investment Scam", verdict="SCAM", score=91)

        result = campaigns.rebuild_campaigns()
        assert result["campaigns"] >= 1

        found = campaigns.list_campaigns()
        assert any(c["size"] >= 3 for c in found)

    def test_hub_does_not_collapse_unrelated_operations(self, temp_db):
        """
        The 1930 helpline appears in a great many scam messages -- often
        because the scammer quotes it to look official. Clustering through it
        would merge every unrelated campaign into a single component and make
        the whole feature useless. This is what HUB_DEGREE_LIMIT prevents.
        """
        shared = "1930"
        for i in range(campaigns.HUB_DEGREE_LIMIT + 10):
            graph.ingest(
                "Report fraud to %s. Deposit to op%d@okaxis" % (shared, i),
                module="Customer Care", verdict="DANGER", score=80)

        result = campaigns.rebuild_campaigns()
        assert result["hubs_suppressed"] >= 1
        # If the hub had merged everything, there would be exactly one
        # campaign containing nearly every entity.
        biggest = max((c["size"] for c in campaigns.list_campaigns()), default=0)
        assert biggest < result["total_entities"]

    def test_singletons_are_not_campaigns(self, temp_db):
        graph.ingest("lonely@okaxis", module="X", verdict="SCAM", score=50)
        result = campaigns.rebuild_campaigns()
        for c in campaigns.list_campaigns():
            assert c["size"] >= campaigns.MIN_CAMPAIGN_SIZE


class TestNearDuplicates:
    def test_same_script_different_numbers_matches(self, temp_db):
        """
        Operators reuse one script and swap the number and brand. Folding
        digits and URLs before shingling is what makes those two texts look
        like the same creative.
        """
        a = ("Dear customer your KYC has expired. Call 9811111111 to "
             "reactivate your account immediately or it will be blocked.")
        b = ("Dear customer your KYC has expired. Call 9899999999 to "
             "reactivate your account immediately or it will be blocked.")
        sig_a = campaigns.minhash(a)
        sig_b = campaigns.minhash(b)
        assert campaigns.signature_similarity(sig_a, sig_b) > 0.8

    def test_unrelated_texts_do_not_match(self, temp_db):
        a = "Dear customer your KYC has expired. Call 9811111111."
        b = "Win 50 lakh in the IPL jackpot, download our app now."
        sig_a = campaigns.minhash(a)
        sig_b = campaigns.minhash(b)
        assert campaigns.signature_similarity(sig_a, sig_b) < 0.4
