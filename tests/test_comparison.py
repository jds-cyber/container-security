from lib.comparison import compare_scores, compare_vulnerabilities, compare_severity


def test_compare_scores_improved():

    previous = {"security_score": 70}
    current = {"security_score": 90}

    result = compare_scores(previous, current)

    assert result["delta"] == 20
    assert result["trend"] == "Improved"


def test_compare_scores_regressed():

    previous = {"security_score": 82}
    current = {"security_score": 76}

    result = compare_scores(previous, current)

    assert result["delta"] == -6
    assert result["trend"] == "Regressed"


def test_compare_scores_no_change():

    previous = {"security_score": 99}
    current = {"security_score": 99}

    result = compare_scores(previous, current)

    assert result["delta"] == 0
    assert result["trend"] == "No Change"



def test_compare_vulnerabilities():

    previous = {
        "vulnerability_ids": [
            "CVE-2026-9538",
            "CVE-2026-9547",
            "CVE-2026-9669"
        ]
    }

    current = {
        "vulnerability_ids": [
            "CVE-2026-9547",
            "CVE-2026-9669",
            "CVE-2026-8932"
        ]
    }

    result = compare_vulnerabilities(previous, current)

    assert result["new"] == ["CVE-2026-8932"]
    assert result["fixed"] == ["CVE-2026-9538"]
    assert result["unchanged"] == [
        "CVE-2026-9547",
        "CVE-2026-9669"
    ]


def test_compare_severity():

    previous = {
        "critical": 5,
        "high": 10,
        "medium": 20,
        "low": 4,
        "negligible": 100,
        "unknown": 2,
    }

    current = {
        "critical": 7,
        "high": 8,
        "medium": 25,
        "low": 3,
        "negligible": 95,
        "unknown": 2,
    }

    result = compare_severity(previous, current)

    assert result["critical"]["previous"] == 5
    assert result["critical"]["current"] == 7
    assert result["critical"]["delta"] == 2

    assert result["high"]["delta"] == -2
    assert result["medium"]["delta"] == 5
    assert result["low"]["delta"] == -1
    assert result["negligible"]["delta"] == -5
    assert result["unknown"]["delta"] == 0
