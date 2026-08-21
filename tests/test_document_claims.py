"""
Phase 0 — generated documents must not overstate.

Each test here is named for a specific claim the platform used to make and had
not earned. They exist because these documents can be sent to real
intermediaries, where an unearned claim is not a cosmetic problem.
"""
import pytest

SCAN = {
    'id': 7, 'timestamp': '2026-08-19 10:00:00', 'module': 'Betting Content',
    'verdict': 'BETTING', 'score': 95, 'input_summary': 'poster.png',
    'file_hash': 'c' * 64, 'reasons': ['gambling logo detected'],
    'username': 'officer_kumar', 'recommendation': 'Refer for blocking.',
}


@pytest.fixture
def takedown_html():
    from services.takedown_generator import generate_takedown_html
    return generate_takedown_html(SCAN)


@pytest.fixture
def report_html():
    from services.report_generator import generate_html_report
    return generate_html_report(SCAN)


class TestNoGovernmentImpersonation:
    @pytest.mark.parametrize("claim", [
        "MINISTRY OF ELECTRONICS",
        "GOVERNMENT OF INDIA",
        "NATIONAL CYBER RISK MITIGATION CENTRE",
        "NCSCC-MEITY",
    ])
    def test_notice_does_not_claim_to_be_a_ministry(self, takedown_html, claim):
        """
        The notice carried MeitY letterhead, a 'Government of India' seal and a
        ministry-style file number, with no disclaimer. Emailed to a hosting
        provider, that is a forged government communication.
        """
        assert claim not in takedown_html

    def test_notice_declares_itself_a_draft(self, takedown_html):
        assert "DRAFT" in takedown_html
        assert "NOT A DISPATCHED COMMUNICATION" in takedown_html

    def test_notice_leaves_the_issuing_officer_blank(self, takedown_html):
        assert "Lead Threat Investigator" not in takedown_html
        assert "Designation:" in takedown_html


class TestNoUnearnedAttestation:
    def test_report_names_the_analyst_who_ran_it(self, report_html):
        """
        The signatory used to be hardcoded to one person on every report,
        whoever actually ran the scan. Asserting the running analyst's name
        appears is what pins that down; the old hardcoded name is no longer
        named here because it no longer appears anywhere in the project.
        """
        assert "officer_kumar" in report_html

    def test_report_does_not_claim_a_digital_signature(self, report_html):
        """Nothing is cryptographically signed; the wording said otherwise."""
        assert "Digitally Verified" not in report_html


class TestVerificationIsReachable:
    def test_notice_prints_its_verification_url(self, takedown_html):
        """
        evidence.verification_url() and qr_svg() had no caller anywhere, while
        templates/verify.html tells the reader to scan a QR on the document.
        """
        assert "/verify/" + "c" * 64 in takedown_html

    def test_notice_prints_the_evidence_hash(self, takedown_html):
        assert "c" * 64 in takedown_html

    def test_a_scan_without_a_hash_says_so_rather_than_faking_one(self):
        from services.takedown_generator import generate_takedown_html
        html = generate_takedown_html(dict(SCAN, file_hash=None))
        assert "cannot be independently verified" in html


class TestStatutoryCurrency:
    def test_bns_is_cited_with_section_numbers(self, takedown_html):
        """IPC was replaced by the BNS in July 2024; a bare 'BNS' is not a citation."""
        assert "s.318" in takedown_html or "318" in takedown_html
        assert "Bharatiya Nyaya Sanhita" in takedown_html


class TestPdfRenders:
    def test_both_pdfs_still_build(self):
        from services.takedown_generator import generate_takedown_pdf
        from services.report_generator import generate_pdf_report
        assert len(generate_takedown_pdf(SCAN)) > 1000
        assert len(generate_pdf_report(SCAN)) > 1000
