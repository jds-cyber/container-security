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
