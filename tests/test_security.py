from lib.security import (
    summarize,
    weighted_risk,
    security_score,
    security_grade,
    risk_level,
    empty_summary,
)
from lib.vulnerability import Vulnerability


def test_security_summary():

    vulnerabilities = [
        Vulnerability(
            "CVE-2026-0001",
            severity="critical",
        ),
        Vulnerability(
            "CVE-2026-0002",
            severity="high",
        ),
        Vulnerability(
            "CVE-2026-0003",
            severity="medium",
        ),
    ]

    result = summarize(vulnerabilities)

    assert result["critical"] == 1
    assert result["high"] == 1
    assert result["medium"] == 1
    assert result["findings"] == 3
    assert result["unique_vulnerabilities"] == 3


def test_weighted_risk():

    summary = {
        "critical": 2,
        "high": 3,
        "medium": 4,
        "low": 5,
    }

    risk = weighted_risk(summary)

    assert risk == (
        2 * 10 +
        3 * 5 +
        4 * 2 +
        5
    )


def test_security_score():

    summary = {
        "critical": 2,
        "high": 3,
        "medium": 4,
        "low": 5,
    }

    score = security_score(summary)

    assert 0 <= score <= 100


def test_unique_vulnerabilities():

    vulnerabilities = [
        Vulnerability(
            "CVE-2026-0001",
            severity="critical",
        ),
        Vulnerability(
            "CVE-2026-0001",
            severity="high",
        ),
        Vulnerability(
            "CVE-2026-0003",
            severity="medium",
        ),
    ]

    result = summarize(vulnerabilities)

    assert result["unique_vulnerabilities"] == 2


def test_empty_summary():
    """
    This ensures your default dictionary does not accidentally change.
    """

    summary = empty_summary()

    assert summary["findings"] == 0
    assert summary["unique_vulnerabilities"] == 0
    assert summary["critical"] == 0
    assert summary["security_score"] == 0
    assert summary["grade"] == ""


def test_security_grade():
    """
    This verifies scoring classification.
    """

    assert security_grade(95) == "A"
    assert security_grade(85) == "B"
    assert security_grade(75) == "C"
    assert security_grade(65) == "D"
    assert security_grade(40) == "F"


def test_risk_level():
    """
    This verifies risk classification.
    """

    assert risk_level(95) == "LOW"
    assert risk_level(75) == "MODERATE"
    assert risk_level(55) == "HIGH"
    assert risk_level(25) == "CRITICAL"
