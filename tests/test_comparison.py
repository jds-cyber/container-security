from lib.comparison import compare_scores, compare_vulnerabilities


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
