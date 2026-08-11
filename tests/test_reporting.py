import json
from pathlib import Path
from lib.reporting import generate_report, security_comparison
from lib.trends import load_history


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
        image_name="test-image"
    )

    assert output.exists()

    content = output.read_text()

    assert "Container Security Report" in content
    assert "test-image" in content
    assert "85" in content
    assert "B" in content
    assert "Scan Information" in content
    assert "Scan Timestamp" in content


def test_load_history_includes_scan_name(tmp_path):

    history_dir = tmp_path / "history"
    history_dir.mkdir()

    report = {
        "security_score": 90,
        "grade": "A"
    }

    file = history_dir / "2026-08-05_scan.json"

    file.write_text(
        json.dumps(report)
    )

    history = load_history(history_dir)

    assert len(history) == 1
    assert history[0]["scan"] == "2026-08-05_scan"
    assert history[0]["security_score"] == 90


def test_security_comparison():

    previous = {
        "security_score": 70,
        "vulnerability_ids": [
            "CVE-2017-0144",
            "CVE-2021-44228"
        ]
    }

    current = {
        "security_score": 85,
        "vulnerability_ids": [
            "CVE-2014-0160",
            "CVE-2021-44228"
        ]
    }

    result = security_comparison(previous, current)

    assert result["score"]["previous"] == 70
    assert result["score"]["current"] == 85
    assert result["score"]["delta"] == 15
    assert result["score"]["trend"] == "Improved"

    assert result["vulnerabilities"]["new"] == ["CVE-2014-0160"]
    assert result["vulnerabilities"]["fixed"] == ["CVE-2017-0144"]
    assert result["vulnerabilities"]["unchanged"] == ["CVE-2021-44228"]


def test_security_comparison_without_previous_scan():

    current = {
        "security_score": 85,
        "vulnerability_ids": [
            "CVE-2024-1234"
        ]
    }
    result = security_comparison(None, current)

    assert result is None
