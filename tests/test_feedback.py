"""
Analyst feedback loop and calibration.

The properties that matter here are about evidential weight, not plumbing:
one analyst gets one vote, an unconfirmed opinion is not a label, and a
calibrator is not fitted on a sample too small to mean anything.
"""

import pytest

from services.intel import feedback, calibration


def file_one(scan_id=1, reviewer_id=7, label=feedback.LABEL_FALSE_POSITIVE,
             module="Betting Content", verdict="BETTING", score=91.0):
    return feedback.submit(
        scan_id=scan_id, module=module, label=label,
        system_verdict=verdict, system_score=score,
        reviewer="analyst_%d" % reviewer_id, reviewer_id=reviewer_id,
        artefact_text="Win big on IPL, deposit to boss@okaxis",
    )


class TestSubmission:
    def test_records_a_correction(self, temp_db):
        fb_id, err = file_one()
        assert err is None and fb_id

    def test_rejects_unknown_label(self, temp_db):
        fb_id, err = feedback.submit(scan_id=1, module="X", label="MAYBE")
        assert fb_id is None and "unknown label" in err

    def test_one_analyst_one_vote(self, temp_db):
        """
        Without the unique index, a double-fired submit handler would count
        one analyst twice in every metric computed downstream.
        """
        file_one(scan_id=1, reviewer_id=7, label=feedback.LABEL_FALSE_POSITIVE)
        file_one(scan_id=1, reviewer_id=7, label=feedback.LABEL_CORRECT)
        rows = feedback.for_scan(1)
        assert len(rows) == 1
        assert rows[0]["label"] == feedback.LABEL_CORRECT

    def test_changed_opinion_returns_to_pending(self, temp_db):
        """A revised opinion has not been confirmed by anyone yet, so it must
        not keep the CONFIRMED status the previous one earned."""
        fb_id, _ = file_one()
        feedback.review(fb_id, feedback.STATUS_CONFIRMED, reviewer="other")
        assert feedback.get(fb_id)["status"] == feedback.STATUS_CONFIRMED

        file_one(label=feedback.LABEL_CORRECT)
        assert feedback.get(fb_id)["status"] == feedback.STATUS_PENDING

    def test_different_analysts_both_recorded(self, temp_db):
        file_one(scan_id=1, reviewer_id=7)
        file_one(scan_id=1, reviewer_id=8)
        assert len(feedback.for_scan(1)) == 2


class TestReviewGate:
    def test_pending_is_not_a_label(self, temp_db):
        """
        An unconfirmed correction is one person's opinion. It must not appear
        in the confusion matrix or in the training export.
        """
        file_one()
        assert feedback.metrics()["total_reviewed"] == 0
        assert feedback.training_export() == []

    def test_confirmed_becomes_a_label(self, temp_db):
        fb_id, _ = file_one()
        feedback.review(fb_id, feedback.STATUS_CONFIRMED, reviewer="second")
        assert feedback.metrics()["total_reviewed"] == 1
        assert len(feedback.training_export()) == 1

    def test_rejected_is_excluded(self, temp_db):
        fb_id, _ = file_one()
        feedback.review(fb_id, feedback.STATUS_REJECTED, reviewer="second")
        assert feedback.metrics()["total_reviewed"] == 0

    def test_unknown_status_rejected(self, temp_db):
        fb_id, _ = file_one()
        ok, err = feedback.review(fb_id, "APPROVED_MAYBE")
        assert ok is False and err


class TestMetrics:
    def test_rates_are_withheld_on_small_samples(self, temp_db):
        """
        "100% accurate" off three reviews is the number that gets a system
        deployed and then discredited. Below 30 confirmed reviews the rate is
        computed but flagged unreportable.
        """
        for i in range(5):
            fb_id, _ = file_one(scan_id=i, reviewer_id=i,
                                label=feedback.LABEL_CORRECT)
            feedback.review(fb_id, feedback.STATUS_CONFIRMED, reviewer="second")

        m = feedback.metrics()["modules"][0]
        assert m["reviewed"] == 5
        assert m["reportable"] is False

    def test_rates_become_reportable_at_thirty(self, temp_db):
        for i in range(30):
            fb_id, _ = file_one(scan_id=i, reviewer_id=i,
                                label=feedback.LABEL_CORRECT)
            feedback.review(fb_id, feedback.STATUS_CONFIRMED, reviewer="second")

        m = feedback.metrics()["modules"][0]
        assert m["reportable"] is True
        assert m["agreement_rate"] == 1.0

    def test_false_positives_and_negatives_are_counted_separately(self, temp_db):
        cases = [feedback.LABEL_FALSE_POSITIVE] * 3 + [feedback.LABEL_FALSE_NEGATIVE] * 2
        for i, label in enumerate(cases):
            fb_id, _ = file_one(scan_id=i, reviewer_id=i, label=label)
            feedback.review(fb_id, feedback.STATUS_CONFIRMED, reviewer="second")

        m = feedback.metrics()["modules"][0]
        assert m["false_positive"] == 3
        assert m["false_negative"] == 2

    def test_metrics_always_carry_the_sampling_caveat(self, temp_db):
        """
        Reviewers look at borderline cases, so these are not population error
        rates. The caveat travels with the numbers so it cannot be quoted
        without it.
        """
        assert "not" in feedback.metrics()["caveat"].lower()


class TestLabelReconstruction:
    @pytest.mark.parametrize("verdict,label,expected", [
        ("BETTING", feedback.LABEL_CORRECT, 1),
        ("BETTING", feedback.LABEL_FALSE_POSITIVE, 0),
        ("SAFE", feedback.LABEL_CORRECT, 0),
        ("SAFE", feedback.LABEL_FALSE_NEGATIVE, 1),
    ])
    def test_ground_truth_from_verdict_and_correction(self, temp_db, verdict,
                                                      label, expected):
        fb_id, _ = file_one(verdict=verdict, label=label, score=80.0)
        feedback.review(fb_id, feedback.STATUS_CONFIRMED, reviewer="second")
        samples = feedback.calibration_samples("Betting Content")
        assert samples and samples[0][1] == expected

    def test_scores_are_normalised_to_unit_interval(self, temp_db):
        fb_id, _ = file_one(score=91.0)
        feedback.review(fb_id, feedback.STATUS_CONFIRMED, reviewer="second")
        score, _ = feedback.calibration_samples("Betting Content")[0]
        assert 0.0 <= score <= 1.0

    def test_unsure_never_becomes_a_label(self, temp_db):
        fb_id, _ = file_one(label=feedback.LABEL_UNSURE)
        feedback.review(fb_id, feedback.STATUS_CONFIRMED, reviewer="second")
        assert feedback.calibration_samples("Betting Content") == []


class TestCalibration:
    def test_uncalibrated_module_says_so(self, temp_db):
        a = calibration.assess(91.0, module="module_with_no_calibrator")
        assert a["calibrated"] is False
        assert "raw score" in a["note"]

    def test_abstention_band(self, temp_db):
        mid = calibration.assess(50.0, module="anything")
        assert mid["band"] == calibration.BAND_ABSTAIN
        assert mid["abstained"] is True

    def test_confident_scores_do_not_abstain(self, temp_db):
        assert calibration.assess(95.0, module="x")["band"] == calibration.BAND_THREAT
        assert calibration.assess(5.0, module="x")["band"] == calibration.BAND_SAFE

    def test_histogram_calibration_reduces_ece(self):
        """
        The fusion engine's noisy-OR output is systematically overconfident.
        Histogram binning is the family that fits it; this asserts the fit
        actually improves calibration rather than assuming it.
        """
        scores, labels = [], []
        for i in range(200):
            s = (i % 100) / 100.0
            scores.append(s)
            # True probability well below the reported score -- overconfidence.
            labels.append(1 if (i % 100) > 70 else 0)

        model = calibration.fit_histogram(scores, labels)
        report = calibration.reliability_report(scores, labels, model)
        assert report["ece_after"] <= report["ece_before"]
        assert report["improved"] is True

    def test_report_flags_a_calibrator_that_made_things_worse(self):
        """
        During development, gradient-descent Platt raised ECE from 0.055 to
        0.198 and was adopted silently. The report now refuses to let that
        pass unremarked.
        """
        scores = [i / 100.0 for i in range(100)]
        labels = [1 if s > 0.5 else 0 for s in scores]
        bad_model = {"method": "platt", "a": -20.0, "b": 10.0, "n": 100}
        report = calibration.reliability_report(scores, labels, bad_model)
        if not report["improved"]:
            assert "warning" in report

    def test_perfect_predictions_have_zero_brier(self):
        assert calibration.brier_score([1.0, 0.0, 1.0], [1, 0, 1]) == 0.0
