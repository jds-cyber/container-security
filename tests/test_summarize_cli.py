import json
import subprocess
import sys
from pathlib import Path
from lib.reporting import generate_report


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
                        "id": "CVE-2026-2034",
                        "severity": severity,
                    },
                    "matchDetails": [],
                },
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
            "--scanner",
            "grype",
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
            "--scanner",
            "grype",
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
            "--scanner",
            "grype",
            "--policy",
            str(missing_policy),
        ],
        capture_output=True,
        text=True,
        cwd=ROOT,
    )

    assert result.returncode == 1
    assert "Policy file not found" in result.stderr
    assert "Traceback" not in result.stderr


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
            "--scanner",
            "grype",
            "--policy",
            str(policy_file),
        ],
        capture_output=True,
        text=True,
        cwd=ROOT,
    )

    assert result.returncode == 1
    assert "Invalid Grype report structure" in result.stderr


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
            "--scanner",
            "grype",
            "--policy",
            str(policy_file),
        ],
        capture_output=True,
        text=True,
        cwd=ROOT,
    )

    assert result.returncode == 1
    assert "Invalid policy YAML" in result.stderr


def test_summarize_includes_policy_result_when_policy_passes(tmp_path):
    report_file = tmp_path / "report.json"
    policy_file = tmp_path / "policy.yml"

    write_report(
        report_file,
        critical=0,
        high=2,
        medium=5,
    )

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
            "--scanner",
            "grype",
            "--policy",
            str(policy_file),
        ],
        capture_output=True,
        text=True,
        cwd=ROOT,
    )

    assert result.returncode == 0

    summary = json.loads(result.stdout)

    assert summary["policy_passed"] is True
    assert summary["policy_failures"] == []


def test_summarize_includes_policy_result_when_policy_fails(tmp_path):
    report_file = tmp_path / "report.json"
    policy_file = tmp_path / "policy.yml"

    write_report(
        report_file,
        critical=1,
        high=2,
        medium=5,
    )

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
            "--scanner",
            "grype",
            "--policy",
            str(policy_file),
        ],
        capture_output=True,
        text=True,
        cwd=ROOT,
    )

    assert result.returncode == 1

    summary = json.loads(result.stdout)

    assert summary["policy_passed"] is False
    assert "Critical vulnerabilities exceed limit." in summary["policy_failures"]


def test_generate_report_policy_status_comes_from_summary(tmp_path):

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

        "policy_passed": False,
        "policy_failures": [
            "Test policy failure."
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

    assert "FAIL" in content
    assert "Test policy failure." in content


def test_summarize_accepts_scanner_argument(tmp_path):

    report_file = tmp_path / "report.json"

    write_report(
        report_file,
        critical=0,
        high=5,
        medium=5,
    )

    result = subprocess.run(
        [
            sys.executable,
            str(SUMMARIZE_SCRIPT),
            str(report_file),
            "--scanner",
            "grype",
        ],
        capture_output=True,
        text=True,
        cwd=ROOT,
    )

    assert result.returncode == 0


def test_summarize_rejects_unknown_scanner(tmp_path):

    report_file = tmp_path / "report.json"

    write_report(
        report_file,
        critical=0,
        high=0,
        medium=0,
    )

    result = subprocess.run(
        [
            sys.executable,
            str(SUMMARIZE_SCRIPT),
            str(report_file),
            "--scanner",
            "nessus"
        ],
        capture_output=True,
        text=True,
        cwd=ROOT,
    )

    assert result.returncode == 1
    assert "Unknown scanner: nessus" in result.stderr


def test_summarize_enriches_vulnerabilities_with_intelligence(tmp_path):
    report_file = tmp_path / "report.json"
    intelligence_file = tmp_path / "intelligence.json"
    policy_file = tmp_path / "policy.xml"

    report_file.write_text(
        json.dumps(
            {
                "matches": [
                    {
                        "vulnerability": {
                            "id": "CVE-2026-1234",
                            "severity": "High",
                        },
                        "artifact": {
                            "name": "example",
                            "version": "1.0.0",
                        },
                    }
                ]
            }
        )
    )

    intelligence_file.write_text(
        json.dumps(
            {
                "CVE-2026-1234": {
                    "vulnerability_id": "CVE-2026-1234",
                    "description": "Test vulnerability intelligence.",
                    "cvss": {
                        "version": "3.1",
                        "score": 8.1,
                        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                        "severity": "high",
                    },
                    "cwe": [
                        "CWE-787"
                    ],
                    "published": "2026-01-01T00:00:00",
                    "modified": "2026-08-01T00:00:00",
                    "references": [
                        "https://example.com/CVE-2026-1234"
                    ],
                }
            }
        )
    )

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
            "--scanner",
            "grype",
            "--intelligence",
            str(intelligence_file),
            "--policy",
            str(policy_file),
        ],
        capture_output=True,
        text=True,
        cwd=ROOT,
    )

    assert result.returncode == 0

    summary = json.loads(result.stdout)

    assert summary["findings"] == 1
    assert summary["unique_vulnerabilities"] == 1

    vulnerability = summary["vulnerabilities"][0]

    assert vulnerability["id"] == "CVE-2026-1234"
    assert vulnerability["severity"] == "high"

    assert vulnerability["intelligence"] is not None
    assert (
        vulnerability["intelligence"]["vulnerability_id"]
        == "CVE-2026-1234"
    )
    assert (
        vulnerability["intelligence"]["description"]
        == "Test vulnerability intelligence."
    )
    assert vulnerability["intelligence"]["cvss"]["score"] == 8.1
    assert vulnerability["intelligence"]["cwe"] == ["CWE-787"]


def test_summarize_leaves_intelligence_none_when_vulnerability_not_found(
    tmp_path,
):
    report_file = tmp_path / "report.json"
    intelligence_file = tmp_path / "intelligence.json"
    policy_file = tmp_path / "policy.yml"

    report_file.write_text(
        json.dumps(
            {
                "matches": [
                    {
                        "vulnerability": {
                            "id": "CVE-2026-1234",
                            "severity": "High",
                        },
                        "artifact": {
                            "name": "example",
                            "version": "1.0.0",
                        },
                    },
                    {
                        "vulnerability": {
                            "id": "CVE-2026-9999",
                            "severity": "Medium",
                        },
                        "artifact": {
                            "name": "example",
                            "version": "1.0.0",
                        },
                    },
                ]
            }
        )
    )

    intelligence_file.write_text(
        json.dumps(
            {
                "CVE-2026-1234": {
                    "vulnerability_id": "CVE-2026-1234",
                    "description": "Known vulnerability.",
                }
            }
        )
    )

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
            "--scanner",
            "grype",
            "--intelligence",
            str(intelligence_file),
            "--policy",
            str(policy_file),
        ],
        capture_output=True,
        text=True,
        cwd=ROOT,
    )

    assert result.returncode == 0

    summary = json.loads(result.stdout)

    vulnerabilities = {
        vulnerability["id"]: vulnerability
        for vulnerability in summary["vulnerabilities"]
    }

    assert vulnerabilities["CVE-2026-1234"]["intelligence"] is not None
    assert vulnerabilities["CVE-2026-9999"]["intelligence"] is None


def test_summarize_fails_when_intelligence_json_is_invalid(tmp_path):
    report_file = tmp_path / "report.json"
    intelligence_file = tmp_path / "intelligence.json"

    write_report(report_file)

    intelligence_file.write_text(
        '{"CVE-2026-1234": invalid}'
    )

    result = subprocess.run(
        [
            sys.executable,
            str(SUMMARIZE_SCRIPT),
            str(report_file),
            "--scanner",
            "grype",
            "--intelligence",
            str(intelligence_file),
        ],
        capture_output=True,
        text=True,
        cwd=ROOT,
    )

    assert result.returncode == 1
    assert "Invalid intelligence JSON" in result.stderr
    assert "Traceback" not in result.stderr


def test_summarize_fails_when_intelligence_file_is_missing(tmp_path):
    report_file = tmp_path / "report.json"
    intelligence_file = tmp_path / "missing-intelligence.json"

    write_report(report_file)

    result = subprocess.run(
        [
            sys.executable,
            str(SUMMARIZE_SCRIPT),
            str(report_file),
            "--scanner",
            "grype",
            "--intelligence",
            str(intelligence_file),
        ],
        capture_output=True,
        text=True,
        cwd=ROOT,
    )

    assert result.returncode == 1
    assert "Intelligence file not found" in result.stderr
    assert "Traceback" not in result.stderr
