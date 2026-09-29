import pytest
from lib.comparison import (
    compare_scores,
    compare_vulnerabilities,
    compare_severity,
    compare_intelligence,
    compare_packages,
)


# ============================================================
# Security score comparison
# ============================================================

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


# ============================================================
# Vulnerability ID comparison
# ============================================================

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


# ============================================================
# Vulnerability ID validation
# ============================================================

def test_compare_vulnerabilities_rejects_invalid_previous_ids():

    previous = {
        "vulnerability_ids": [
            "CVE-2026-1234",
            None,
        ]
    }

    current = {
        "vulnerability_ids": [
            "CVE-2026-1234",
        ]
    }

    try:
        compare_vulnerabilities(previous, current)
        assert False, "Expected ValueError"
    except ValueError:
        pass


def test_compare_vulnerabilities_rejects_invalid_current_ids():

    previous = {
        "vulnerability_ids": [
            "CVE-2026-1234",
        ]
    }

    current = {
        "vulnerability_ids": [
            "",
        ]
    }

    try:
        compare_vulnerabilities(previous, current)
        assert False, "Expected ValueError"
    except ValueError:
        pass


def test_compare_vulnerabilities_rejects_non_list_ids():

    previous = {
        "vulnerability_ids": "CVE-2026-1234"
    }

    current = {
        "vulnerability_ids": [
            "CVE-2026-1234",
        ]
    }

    try:
        compare_vulnerabilities(previous, current)
        assert False, "Expected ValueError"
    except ValueError:
        pass


# ============================================================
# Severity comparison
# ============================================================

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


# ============================================================
# Intelligence comparison
# ============================================================

def test_compare_intelligence():

    previous = {
        "intelligence_summary": {
            "total": 10,
            "enriched": 6,
            "unenriched": 4,
            "cvss_available": 5,
            "cwe_available": 4,
            "high_cvss": 3,
            "high_epss": 2,
            "high_epss_percentile": 1,
            "affected_package": 2,
        }
    }

    current = {
        "intelligence_summary": {
            "total": 12,
            "enriched": 9,
            "unenriched": 3,
            "cvss_available": 8,
            "cwe_available": 7,
            "high_cvss": 4,
            "high_epss": 5,
            "high_epss_percentile": 3,
            "affected_package": 4,
        }
    }

    result = compare_intelligence(previous, current)

    assert result["enriched"]["previous"] == 6
    assert result["enriched"]["current"] == 9
    assert result["enriched"]["delta"] == 3

    assert result["unenriched"]["delta"] == -1
    assert result["cvss_available"]["delta"] == 3
    assert result["cwe_available"]["delta"] == 3
    assert result["high_cvss"]["delta"] == 1
    assert result["high_epss"]["delta"] == 3
    assert result["high_epss_percentile"]["delta"] == 2
    assert result["affected_package"]["delta"] == 2


# ============================================================
# Security score validation
# ============================================================

def test_compare_scores_rejects_invalid_previous_score():

    previous = {"security_score": "90"}
    current = {"security_score": 95}

    try:
        compare_scores(previous, current)
        assert False, "Expected ValueError"
    except ValueError:
        pass


def test_compare_scores_rejects_invalid_current_score():

    previous = {"security_score": 90}
    current = {"security_score": "95"}

    try:
        compare_scores(previous, current)
        assert False, "Expected ValueError"
    except ValueError:
        pass


def test_compare_scores_rejects_out_of_range_score():

    previous = {"security_score": 90}
    current = {"security_score": 101}

    try:
        compare_scores(previous, current)
        assert False, "Expected ValueError"
    except ValueError:
        pass


def test_compare_scores_rejects_negative_score():

    previous = {"security_score": -1}
    current = {"security_score": 90}

    try:
        compare_scores(previous, current)
        assert False, "Expected ValueError"
    except ValueError:
        pass


def test_compare_scores_rejects_missing_previous_score():

    previous = {}
    current = {"security_score": 90}

    try:
        compare_scores(previous, current)
        assert False, "Expected ValueError"
    except ValueError:
        pass


def test_compare_scores_rejects_missing_current_score():

    previous = {"security_score": 90}
    current = {}

    try:
        compare_scores(previous, current)
        assert False, "Expected ValueError"
    except ValueError:
        pass


# ============================================================
# Severity validation
# ============================================================

def test_compare_severity_rejects_invalid_count():

    previous = {
        "critical": "5",
    }

    current = {
        "critical": 6,
    }

    try:
        compare_severity(previous, current)
        assert False, "Expected ValueError"
    except ValueError:
        pass


def test_compare_severity_rejects_negative_count():

    previous = {
        "critical": -1,
    }

    current = {
        "critical": 6,
    }

    try:
        compare_severity(previous, current)
        assert False, "Expected ValueError"
    except ValueError:
        pass


# ============================================================
# Intelligence validation
# ============================================================

def test_compare_intelligence_handles_missing_summary():

    previous = {
        "security_score": 80,
    }

    current = {
        "security_score": 85,
    }

    result = compare_intelligence(previous, current)

    assert result["total"]["previous"] == 0
    assert result["total"]["current"] == 0
    assert result["enriched"]["previous"] == 0
    assert result["enriched"]["current"] == 0
    assert result["unenriched"]["previous"] == 0
    assert result["unenriched"]["current"] == 0


# ============================================================
# Package comparison
# ============================================================


def test_compare_packages_detects_added_packages():
    previous = {
        "packages": [
            {"name": "openssl", "version": "1.0"},
        ],
    }

    current = {
        "packages": [
            {"name": "openssl", "version": "1.0"},
            {"name": "curl", "version": "8.0"},
        ],
    }

    result = compare_packages(previous, current)

    assert result == {
        "added": [("curl", "8.0")],
        "removed": [],
        "unchanged": [("openssl", "1.0")],
    }


def test_compare_packages_detects_removed_packages():
    previous = {
        "packages": [
            {"name": "openssl", "version": "1.0"},
            {"name": "curl", "version": "8.0"},
        ],
    }

    current = {
        "packages": [
            {"name": "openssl", "version": "1.0"},
        ],
    }

    result = compare_packages(previous, current)

    assert result == {
        "added": [],
        "removed": [("curl", "8.0")],
        "unchanged": [("openssl", "1.0")],
    }


def test_compare_packages_normalizes_package_names():
    previous = {
        "packages": [
            {"name": " OpenSSL ", "version": "1.0"},
        ],
    }

    current = {
        "packages": [
            {"name": "openssl", "version": "1.0"},
        ],
    }

    result = compare_packages(previous, current)

    assert result == {
        "added": [],
        "removed": [],
        "unchanged": [("openssl", "1.0")],
    }


def test_compare_packages_rejects_invalid_package():
    previous = {
        "packages": [
            {"name": "openssl"},
        ],
    }

    current = {
        "packages": [],
    }

    with pytest.raises(
        ValueError,
        match="Invalid package version",
    ):
        compare_packages(previous, current)
