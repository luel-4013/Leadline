"""Shared risk and severity calculations.

Both the report API and target history need the same numbers, so the logic
lives here instead of being duplicated (and silently diverging) in two
routers.
"""
from typing import Any, Dict, Iterable, Tuple


SEVERITIES = ("critical", "high", "medium", "low", "info")


def severity_counts(findings: Iterable[Any]) -> Dict[str, int]:
    counts = {severity: 0 for severity in SEVERITIES}
    for finding in findings:
        severity = getattr(finding, "severity", None)
        if severity in counts:
            counts[severity] += 1
    return counts


def compute_risk(findings: Iterable[Any]) -> Tuple[int, str]:
    """Overall risk score (0-100) and level.

    Derived from the highest severity present plus a volume modifier at that
    tier. Deliberately simple and explainable: severity tier sets the floor,
    additional findings at that tier or above nudge it up, capped so one
    score does not dominate purely by finding count.

    Unverified CVE candidates are excluded: an NVD keyword hit may not affect
    the observed version at all, so it must not push a scan into "critical".
    CPE version-range matches are included.
    """
    counts = {severity: 0 for severity in SEVERITIES}
    for finding in findings:
        # False positives are analyst decisions, not scanner output. Once a
        # finding is marked false_positive it should stop influencing risk.
        if getattr(finding, "is_false_positive", False):
            continue
        if getattr(finding, "triage_status", None) == "false_positive":
            continue
        if (
            getattr(finding, "finding_type", None) == "cve_match"
            and not (getattr(finding, "extra_data", None) or {}).get("applicability_verified")
        ):
            continue
        severity = getattr(finding, "severity", None)
        if severity in counts:
            counts[severity] += 1

    if counts["critical"] > 0:
        score = min(100, 85 + (counts["critical"] - 1) * 3)
        level = "critical"
    elif counts["high"] > 0:
        score = min(84, 60 + (counts["high"] - 1) * 3)
        level = "high"
    elif counts["medium"] > 0:
        score = min(59, 35 + (counts["medium"] - 1) * 2)
        level = "medium"
    elif counts["low"] > 0:
        score = min(34, 15 + (counts["low"] - 1))
        level = "low"
    else:
        score = 0
        level = "minimal"

    return score, level
