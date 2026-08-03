from lib.security import summarize, security_score


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

    assert result["Critical"] == 1
    assert result["High"] == 1
    assert result["Medium"] == 1
    assert result["Findings"] == 3


def test_security_score():

    summary = {
        "Critical": 2,
        "High": 3,
        "Medium": 4,
        "Low": 5
    }

    score = security_score(summary)

    assert score == (
        2 * 10 +
        3 * 5 +
        4 * 2 +
        5
    )
