import os
import subprocess
import sys
import json 
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
REPORT_SCRIPT = ROOT / "scripts" / "report.py"


def test_report_requires_arguments():
    result = subprocess.run(
        [sys.executable, str(REPORT_SCRIPT)],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 1
    assert "Usage: report.py summary.json output.html image" in result.stdout


def test_report_rejects_empty_image():
    result = subprocess.run(
        [
            sys.executable,
            str(REPORT_SCRIPT),
            "summary.json",
            "output.html",
            "",
        ],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 1
    assert "Image name cannot be empty" in result.stdout


def test_report_generates_successfully(tmp_path):
    summary_file = tmp_path / "summary.json"
    output_file = tmp_path / "report.html"
    history_dir = tmp_path / "history"

    summary_file.write_text(
        """
{
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
    "vulnerability_ids": [
        "CVE-2021-44228"
    ]
}
"""
    )

    env = dict(os.environ)
    env["CONTAINER_SECURITY_HISTORY"] = str(history_dir)

    result = subprocess.run(
        [
            sys.executable,
            str(REPORT_SCRIPT),
            str(summary_file),
            str(output_file),
            "test-image:latest",
        ],
        capture_output=True,
        text=True,
        cwd=ROOT,
        env=env
    )

    assert result.returncode == 0
    assert output_file.exists()
    assert "Report generated:" in result.stdout


def test_report_contains_scan_metadata(tmp_path):
    summary_file = tmp_path / "summary.json"
    output_file = tmp_path / "report.html"
    history_dir = tmp_path / "history"

    summary_file.write_text(
        """
{
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
    "vulnerability_ids": [
        "CVE-2021-44228"
    ]
}
"""
    )

    env = dict(os.environ)
    env["CONTAINER_SECURITY_HISTORY"] = str(history_dir)

    result = subprocess.run(
        [
            sys.executable,
            str(REPORT_SCRIPT),
            str(summary_file),
            str(output_file),
            "test-image:latest",
        ],
        capture_output=True,
        text=True,
        cwd=ROOT,
        env=env,
    )

    assert result.returncode == 0

    content = output_file.read_text()

    assert "Scan ID:" in content
    assert "Scan Timestamp:" in content

    history_files = list(history_dir.glob("*.json"))

    assert len(history_files) == 1

    history = json.loads(history_files[0].read_text())

    assert history["image"] == "test-image:latest"
    assert history["scan_id"] in content
    assert history["scan_timestamp"] in content


def test_report_rejects_missing_summary_file(tmp_path):

    output_file = tmp_path / "report.html"

    result = subprocess.run(
        [
            sys.executable,
            str(REPORT_SCRIPT),
            str(tmp_path / "missing.json"),
            str(output_file),
            "test-image:latest",
        ],
        capture_output=True,
        text=True,
        cwd=ROOT,
    )

    assert result.returncode == 1
    assert "Summary file not found" in result.stdout


def test_report_rejects_invalid_json(tmp_path):

    summary_file = tmp_path / "summary.json"
    output_file = tmp_path / "report.html"

    summary_file.write_text(
        "{ invalid json"
    )

    result = subprocess.run(
        [
            sys.executable,
            str(REPORT_SCRIPT),
            str(summary_file),
            str(output_file),
            "test-image:latest",
        ],
        capture_output=True,
        text=True,
        cwd=ROOT,
    )

    assert result.returncode == 1
    assert "Invalid JSON summary" in result.stdout


def test_report_rejects_invalid_summary_structure(tmp_path):

    summary_file = tmp_path / "summary.json"
    output_file = tmp_path / "report.html"

    summary_file.write_text(
        json.dumps(["not", "a", "summary"])
    )

    result = subprocess.run(
        [
            sys.executable,
            str(REPORT_SCRIPT),
            str(summary_file),
            str(output_file),
            "test-image:latest",
        ],
        capture_output=True,
        text=True,
        cwd=ROOT,
    )

    assert result.returncode == 1
    assert "Invalid summary structure" in result.stdout


def test_report_rejects_empty_summary(tmp_path):

    summary_file = tmp_path / "summary.json"
    output_file = tmp_path / "report.html"

    summary_file.write_text("{}")

    result = subprocess.run(
        [
            sys.executable,
            str(REPORT_SCRIPT),
            str(summary_file),
            str(output_file),
            "test-image:latest",
        ],
        capture_output=True,
        text=True,
        cwd=ROOT,
    )

    assert result.returncode == 1
    assert "Invalid summary structure" in result.stdout


def test_report_uses_configured_history_for_trend(tmp_path):
    history_dir = tmp_path / "custom-history"
    history_dir.mkdir()

    first_summary = tmp_path / "first.json"
    first_output = tmp_path / "first.html"

    first_summary.write_text(
        json.dumps(
            {
                "findings": 1,
                "unique_vulnerabilities": 1,
                "critical": 0,
                "high": 1,
                "medium": 0,
                "low": 0,
                "negligible": 0,
                "unknown": 0,
                "weighted_risk": 5,
                "security_score": 75,
                "grade": "C",
                "vulnerability_ids": [
                    "CVE-2021-44228"
                ],
            }
        )
    )

    env = dict(os.environ)
    env["CONTAINER_SECURITY_HISTORY"] = str(history_dir)

    result = subprocess.run(
        [
            sys.executable,
            str(REPORT_SCRIPT),
            str(first_summary),
            str(first_output),
            "test-image:latest",
        ],
        capture_output=True,
        text=True,
        cwd=ROOT,
        env=env,
    )

    assert result.returncode == 0

    second_summary = tmp_path / "second.json"
    second_output = tmp_path / "second.html"

    second_summary.write_text(
        json.dumps(
            {
                "findings": 1,
                "unique_vulnerabilities": 1,
                "critical": 0,
                "high": 1,
                "medium": 0,
                "low": 0,
                "negligible": 0,
                "unknown": 0,
                "weighted_risk": 3,
                "security_score": 90,
                "grade": "A",
                "vulnerability_ids": [
                    "CVE-2021-44228"
                ],
            }
        )
    )

    result = subprocess.run(
        [
            sys.executable,
            str(REPORT_SCRIPT),
            str(second_summary),
            str(second_output),
            "test-image:latest",
        ],
        capture_output=True,
        text=True,
        cwd=ROOT,
        env=env,
    )

    assert result.returncode == 0
    assert second_output.exists()

    history_files = list(history_dir.glob("*.json"))

    assert len(history_files) == 2

    content = second_output.read_text()

    assert "Security Score Trend" in content


def test_report_includes_previous_scan_comparison(tmp_path):
    history_dir = tmp_path / "history"

    first_summary = tmp_path / "first.json"
    first_output = tmp_path / "first.html"

    first_summary.write_text(
        json.dumps(
            {
                "findings": 2,
                "unique_vulnerabilities": 2,
                "critical": 1,
                "high": 1,
                "medium": 0,
                "low": 0,
                "negligible": 0,
                "unknown": 0,
                "weighted_risk": 15,
                "security_score": 70,
                "grade": "C",
                "vulnerability_ids": [
                    "CVE-2021-44228",
                    "CVE-2024-12345",
                ],
            }
        )
    )

    env = dict(os.environ)
    env["CONTAINER_SECURITY_HISTORY"] = str(history_dir)

    result = subprocess.run(
        [
            sys.executable,
            str(REPORT_SCRIPT),
            str(first_summary),
            str(first_output),
            "test-image:latest",
        ],
        capture_output=True,
        text=True,
        cwd=ROOT,
        env=env,
    )

    assert result.returncode == 0

    second_summary = tmp_path / "second.json"
    second_output = tmp_path / "second.html"

    second_summary.write_text(
        json.dumps(
            {
                "findings": 1,
                "unique_vulnerabilities": 1,
                "critical": 0,
                "high": 1,
                "medium": 0,
                "low": 0,
                "negligible": 0,
                "unknown": 0,
                "weighted_risk": 5,
                "security_score": 90,
                "grade": "A",
                "vulnerability_ids": [
                    "CVE-2024-12345",
                ],
            }
        )
    )

    result = subprocess.run(
        [
            sys.executable,
            str(REPORT_SCRIPT),
            str(second_summary),
            str(second_output),
            "test-image:latest",
        ],
        capture_output=True,
        text=True,
        cwd=ROOT,
        env=env,
    )

    assert result.returncode == 0
    assert second_output.exists()

    content = second_output.read_text()

    assert "Security Comparison" in content
    assert "Previous Score:" in content
    assert "Current Score:" in content
    assert "70" in content
    assert "90" in content
    assert "Improved" in content
