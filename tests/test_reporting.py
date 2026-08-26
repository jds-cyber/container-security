from lib.reporting import (
    generate_report,
    security_comparison,
    security_score_trend,
)
from lib.history import (
    load_history,
    save_history,
)


# ============================================================
# generate_report
# ============================================================

def test_generate_report(tmp_path):

    summary = {
        "findings": 3,
        "unique_vulnerabilities": 3,
        "critical": 1,
        "high": 1,
        "medium": 1,
        "low": 0,
        "negligible": 0,
        "unknown": 0,
        "weighted_risk": 17,
        "security_score": 85,
        "grade": "B",
    }

    output = tmp_path / "report.html"

    generate_report(
        summary,
        output,
        image_name="test-image",
        history_dir=tmp_path / "history",
    )

    assert output.exists()

    content = output.read_text()

    assert "Container Security Report" in content
    assert "test-image" in content
    assert "85" in content
    assert "B" in content
    assert "Scan Information" in content
    assert "Scan Timestamp" in content


def test_generate_report_displays_policy_failures(
    tmp_path,
):

    summary = {
        "findings": 3,
        "unique_vulnerabilities": 3,
        "critical": 1,
        "high": 1,
        "medium": 1,
        "low": 0,
        "negligible": 0,
        "unknown": 0,
        "weighted_risk": 17,
        "security_score": 85,
        "grade": "B",
        "risk_level": "HIGH",
        "policy_passed": False,
        "policy_failures": [
            "Critical vulnerabilities exceed limit.",
            "High vulnerabilities exceed limit.",
        ],
    }

    output = tmp_path / "report.html"

    generate_report(
        summary,
        output,
        image_name="test-image",
        history_dir=tmp_path / "history",
    )

    content = output.read_text()

    assert "Policy Failures" in content
    assert "Critical vulnerabilities exceed limit." in content
    assert "High vulnerabilities exceed limit." in content


def test_generate_report_policy_status_comes_from_summary(
    tmp_path,
):

    summary = {
        "findings": 0,
        "unique_vulnerabilities": 0,
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "negligible": 0,
        "unknown": 0,
        "weighted_risk": 0,
        "security_score": 100,
        "grade": "A",
        "risk_level": "LOW",
        "policy_passed": True,
        "policy_failures": [],
    }

    output = tmp_path / "report.html"

    generate_report(
        summary,
        output,
        image_name="test-image",
        history_dir=tmp_path / "history",
    )

    content = output.read_text()

    assert "Policy Status:" in content
    assert "PASS" in content


def test_generate_report_policy_failure_sets_status_to_fail(
    tmp_path,
):

    summary = {
        "findings": 1,
        "unique_vulnerabilities": 1,
        "critical": 1,
        "high": 0,
        "medium": 0,
        "low": 0,
        "negligible": 0,
        "unknown": 0,
        "weighted_risk": 10,
        "security_score": 90,
        "grade": "A",
        "risk_level": "MEDIUM",
        "policy_passed": False,
        "policy_failures": [
            "Critical vulnerabilities exceed limit."
        ],
    }

    output = tmp_path / "report.html"

    generate_report(
        summary,
        output,
        image_name="test-image",
        history_dir=tmp_path / "history",
    )

    content = output.read_text()

    assert "Policy Status:" in content
    assert "FAIL" in content
    assert "Critical vulnerabilities exceed limit." in content


def test_generate_report_missing_policy_status_defaults_to_fail(
    tmp_path,
):

    summary = {
        "findings": 0,
        "unique_vulnerabilities": 0,
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "negligible": 0,
        "unknown": 0,
        "weighted_risk": 0,
        "security_score": 100,
        "grade": "A",
        "risk_level": "LOW",
    }

    output = tmp_path / "report.html"

    generate_report(
        summary,
        output,
        image_name="test-image",
        history_dir=tmp_path / "history",
    )

    content = output.read_text()

    assert "Policy Status:" in content
    assert "FAIL" in content


def test_generate_report_displays_vulnerability_intelligence(
    tmp_path,
):

    summary = {
        "findings": 1,
        "unique_vulnerabilities": 1,
        "critical": 0,
        "high": 1,
        "medium": 0,
        "low": 0,
        "negligible": 0,
        "unknown": 0,
        "weighted_risk": 5,
        "security_score": 95,
        "grade": "A",
        "risk_level": "LOW",
        "vulnerabilities": [
            {
                "id": "CVE-2026-1234",
                "severity": "high",
                "package": "example",
                "installed_version": "1.0.0",
                "fixed_version": "1.0.1",
                "intelligence": {
                    "vulnerability_id": "CVE-2026-1234",
                    "description": (
                        "Test vulnerability intelligence."
                    ),
                    "cvss": {
                        "score": 8.1,
                        "vector": (
                            "CVSS:3.1/AV:N/AC:L/PR:N/"
                            "UI:N/S:U/C:H/I:H/A:H"
                        ),
                    },
                    "cwe": [
                        "CWE-787"
                    ],
                    "aliases": [
                        "GHSA-test"
                    ],
                    "references": [
                        "https://example.com/advisory"
                    ],
                },
            }
        ],
    }

    output = tmp_path / "report.html"

    generate_report(
        summary,
        output,
        image_name="test-image",
        history_dir=tmp_path / "history",
    )

    content = output.read_text()

    assert "Vulnerability Intelligence" in content
    assert "CVE-2026-1234" in content
    assert "Test vulnerability intelligence." in content
    assert "8.1" in content
    assert "CWE-787" in content
    assert "GHSA-test" in content
    assert "example" in content
    assert "1.0.0" in content
    assert "1.0.1" in content


def test_generate_report_handles_missing_vulnerability_intelligence(
    tmp_path,
):

    summary = {
        "findings": 1,
        "unique_vulnerabilities": 1,
        "critical": 0,
        "high": 1,
        "medium": 0,
        "low": 0,
        "negligible": 0,
        "unknown": 0,
        "weighted_risk": 5,
        "security_score": 95,
        "grade": "A",
        "risk_level": "LOW",
        "vulnerabilities": [
            {
                "id": "CVE-2026-1234",
                "severity": "high",
                "package": "example",
                "installed_version": "1.0.0",
                "fixed_version": None,
                "intelligence": None,
            }
        ],
    }

    output = tmp_path / "report.html"

    generate_report(
        summary,
        output,
        image_name="test-image",
        history_dir=tmp_path / "history",
    )

    content = output.read_text()

    assert "Vulnerability Intelligence" in content
    assert "CVE-2026-1234" in content
    assert (
        "No vulnerability intelligence available."
        in content
    )


def test_generate_report_displays_intelligence_summary(tmp_path):

    summary = {
        "findings": 2,
        "unique_vulnerabilities": 2,
        "critical": 0,
        "high": 1,
        "medium": 1,
        "low": 0,
        "negligible": 0,
        "unknown": 0,
        "weighted_risk": 7,
        "security_score": 93,
        "grade": "A",
        "risk_level": "LOW",
        "policy_passed": True,
        "policy_failures": [],
        "intelligence_summary": {
            "total": 2,
            "enriched": 1,
            "unenriched": 1,
            "cvss_available": 1,
            "cwe_available": 1,
        },
        "vulnerabilities": [],
    }

    output = tmp_path / "report.html"

    generate_report(
        summary,
        output,
        image_name="test-image",
        history_dir=tmp_path / "history",
    )

    content = output.read_text()

    assert "Vulnerability Intelligence Coverage" in content
    assert "Total Vulnerabilities" in content
    assert "Enriched" in content
    assert "Unenriched" in content
    assert "CVSS Available" in content
    assert "CWE Available" in content


# ============================================================
# security_comparison
# ============================================================

def test_security_comparison():

    previous = {
        "security_score": 70,
        "vulnerability_ids": [
            "CVE-2017-0144",
            "CVE-2021-44228",
        ],
    }

    current = {
        "security_score": 85,
        "vulnerability_ids": [
            "CVE-2014-0160",
            "CVE-2021-44228",
        ],
    }

    result = security_comparison(
        previous,
        current,
    )

    assert result["score"]["previous"] == 70
    assert result["score"]["current"] == 85
    assert result["score"]["delta"] == 15
    assert result["score"]["trend"] == "Improved"

    assert result["vulnerabilities"]["new"] == [
        "CVE-2014-0160"
    ]
    assert result["vulnerabilities"]["fixed"] == [
        "CVE-2017-0144"
    ]
    assert result["vulnerabilities"]["unchanged"] == [
        "CVE-2021-44228"
    ]


def test_security_comparison_without_previous_scan():

    current = {
        "security_score": 85,
        "vulnerability_ids": [
            "CVE-2024-1234",
        ],
    }

    result = security_comparison(
        None,
        current,
    )

    assert result is None


# ============================================================
# security_score_trend
# ============================================================

def test_security_score_trend_filters_by_image(
    tmp_path,
    monkeypatch,
):

    history = [
        {
            "scan": "2026-08-10",
            "security_score": 80,
            "image": "test-image:latest",
        },
        {
            "scan": "2026-08-11",
            "security_score": 90,
            "image": "test-image:latest",
        },
        {
            "scan": "2026-08-12",
            "security_score": 60,
            "image": "other-image:latest",
        },
    ]

    monkeypatch.setattr(
        "lib.reporting.load_history",
        lambda history_dir: history,
    )

    chart = security_score_trend(
        "test-image:latest"
    )

    assert chart
    assert "2026-08-10" in chart
    assert "2026-08-11" in chart
    assert "2026-08-12" not in chart


def test_security_score_trend_returns_empty_when_no_matching_image(
    monkeypatch,
):

    monkeypatch.setattr(
        "lib.reporting.load_history",
        lambda history_dir: [
            {
                "scan": "2026-08-10",
                "security_score": 80,
                "image": "other-image:latest",
            }
        ],
    )

    chart = security_score_trend(
        "test-image:latest"
    )

    assert chart == ""


def test_security_score_trend_uses_saved_history(
    tmp_path,
):

    save_history(
        {"security_score": 75},
        tmp_path,
        image_name="test-image:latest",
    )

    save_history(
        {"security_score": 85},
        tmp_path,
        image_name="test-image:latest",
    )

    history = load_history(tmp_path)

    assert len(history) == 2
    assert history[0]["security_score"] == 75
    assert history[1]["security_score"] == 85

    chart = security_score_trend(
        "test-image:latest",
        history_dir=tmp_path,
    )

    assert chart
    assert "Security Score Trend" in chart


def test_security_score_trend_uses_configured_history(
    tmp_path,
):

    configured_history = tmp_path / "configured"
    default_history = tmp_path / "default"

    save_history(
        {"security_score": 75},
        configured_history,
        image_name="test-image:latest",
    )

    save_history(
        {"security_score": 90},
        configured_history,
        image_name="test-image:latest",
    )

    save_history(
        {"security_score": 20},
        default_history,
        image_name="test-image:latest",
    )

    chart = security_score_trend(
        "test-image:latest",
        history_dir=configured_history,
    )

    assert chart
    assert "Security Score Trend" in chart
