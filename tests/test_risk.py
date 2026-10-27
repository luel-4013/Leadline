"""Risk scoring tests: triage state and CVE applicability must matter."""
from app.risk import compute_risk


class _Finding:
    def __init__(
        self,
        severity,
        finding_type="test",
        triage_status="open",
        is_false_positive=False,
        extra_data=None,
    ):
        self.severity = severity
        self.finding_type = finding_type
        self.triage_status = triage_status
        self.is_false_positive = is_false_positive
        self.extra_data = extra_data or {}


def test_open_high_finding_sets_high_risk():
    score, level = compute_risk([_Finding("high")])
    assert level == "high"
    assert 60 <= score <= 84


def test_false_positive_does_not_drive_risk():
    score, level = compute_risk([
        _Finding("critical", triage_status="false_positive"),
        _Finding("high", is_false_positive=True),
    ])
    assert (score, level) == (0, "minimal")


def test_unverified_cve_is_excluded_from_risk():
    score, level = compute_risk([
        _Finding(
            "critical",
            finding_type="cve_match",
            extra_data={"applicability_verified": False},
        )
    ])
    assert (score, level) == (0, "minimal")


def test_verified_cpe_cve_is_included_in_risk():
    score, level = compute_risk([
        _Finding(
            "critical",
            finding_type="cve_match",
            extra_data={"applicability_verified": True},
        )
    ])
    assert level == "critical"
    assert score >= 85
