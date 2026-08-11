import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
SUMMARIZE_SCRIPT = ROOT / "scripts" / "summarize.py"


def write_report(path, critical=0, high=0, medium=0):
    report = {
        "matches": []
    }

    for severity, count in [
        ("Critical", critical),
        ("High", high),
        ("Medium", medium),
    ]:
        for _ in range(count):
            report["matches"].append(
                {
                    "vulnerability": {
                        "id": f"TEST-{severity}-{_}"
                    },
                    "matchDetails": [],
                    "vulnerability": {
                        "id": f"TEST-{severity}-{_}",
                        "severity": severity,
                    },
                }
            )

    path.write_text(json.dumps(report))


def test_summarize_exits_zero_when_policy_passes(tmp_path):
    report_file = tmp_path / "report.json"
    policy_file = tmp_path / "policy.yml"

    write_report(report_file, critical=0, high=2, medium=5)

    policy_file.write_text(
        """
policy:
  max_critical: 0
  max_high: 10
  max_medium: 100

fail_on:
  - Critical
  - High
  - Medium
"""
    )

    result = subprocess.run(
        [
            sys.executable,
            str(SUMMARIZE_SCRIPT),
            str(report_file),
            "--policy",
            str(policy_file),
        ],
        capture_output=True,
        text=True,
        cwd=ROOT,
    )

    assert result.returncode == 0
    assert "SECURITY POLICY PASSED" in result.stderr


def test_summarize_exits_one_when_policy_fails(tmp_path):
    report_file = tmp_path / "report.json"
    policy_file = tmp_path / "policy.yml"

    write_report(report_file, critical=1, high=2, medium=5)

    policy_file.write_text(
        """
policy:
  max_critical: 0
  max_high: 10
  max_medium: 100

fail_on:
  - Critical
  - High
  - Medium
"""
    )

    result = subprocess.run(
        [
            sys.executable,
            str(SUMMARIZE_SCRIPT),
            str(report_file),
            "--policy",
            str(policy_file),
        ],
        capture_output=True,
        text=True,
        cwd=ROOT,
    )

    assert result.returncode == 1
    assert "SECURITY POLICY FAILED" in result.stderr
    assert "Critical vulnerabilities exceed limit." in result.stderr


def test_summarize_fails_when_policy_file_is_missing(tmp_path):
    report_file = tmp_path / "report.json"
    missing_policy = tmp_path / "missing-policy.yml"

    write_report(report_file)

    result = subprocess.run(
        [
            sys.executable,
            str(SUMMARIZE_SCRIPT),
            str(report_file),
            "--policy",
            str(missing_policy),
        ],
        capture_output=True,
        text=True,
        cwd=ROOT,
    )

    assert result.returncode == 1
    assert "Policy file not found" in result.stderr


def test_summarize_fails_when_report_structure_is_invalid(tmp_path):
    report_file = tmp_path / "report.json"
    policy_file = tmp_path / "policy.yml"

    report_file.write_text(
        json.dumps({"invalid": []})
    )

    policy_file.write_text(
        """
policy:
  max_critical: 0
  max_high: 10
  max_medium: 100

fail_on:
  - Critical
"""
    )

    result = subprocess.run(
        [
            sys.executable,
            str(SUMMARIZE_SCRIPT),
            str(report_file),
            "--policy",
            str(policy_file),
        ],
        capture_output=True,
        text=True,
        cwd=ROOT,
    )

    assert result.returncode == 1
    assert "Invalid report structure" in result.stderr


def test_summarize_fails_when_policy_yaml_is_invalid(tmp_path):
    report_file = tmp_path / "report.json"
    policy_file = tmp_path / "policy.yml"

    write_report(report_file)

    policy_file.write_text(
        """
policy:
  max_critical: 0
  max_high: 10
  max_medium: 100

fail_on:
  - Critical
  - High
  - Medium
  invalid: [broken
"""
    )

    result = subprocess.run(
        [
            sys.executable,
            str(SUMMARIZE_SCRIPT),
            str(report_file),
            "--policy",
            str(policy_file),
        ],
        capture_output=True,
        text=True,
        cwd=ROOT,
    )

    assert result.returncode == 1
    assert "Invalid policy YAML" in result.stderr
