from lib.security import (
    summarize,
    weighted_risk,
    security_score
)


def test_security_summary():
    matches = [
        {
            "vulnerability": {
                "id": "CVE-001",
                "severity": "Critical"
            }
        },
        {
            "vulnerability": {
                "id": "CVE-002",
                "severity": "High"
            }
        },
        {
            "vulnerability": {
                "id": "CVE-003",
                "severity": "Medium"
            }
        }
    ]

    result = summarize(matches)

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

    matches = [
        {
            "vulnerability": {
                "id": "CVE-001",
                "severity": "Critical"
            }
        },
        {
            "vulnerability": {
                "id": "CVE-001",
                "severity": "High"
            }
        },
        {
            "vulnerability": {
                "id": "CVE-002",
                "severity": "Medium"
            }
        }
    ]

    result = summarize(matches)

    assert result["unique_vulnerabilities"] == 2
