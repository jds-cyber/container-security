from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
WORKFLOW = ROOT / ".github" / "workflows" / "security-scan.yml"


def test_workflow_displays_policy_failures():
    content = WORKFLOW.read_text()

    assert 'summary.get("policy_failures")' in content
    assert 'for failure in summary["policy_failures"]' in content
    assert "Policy Failures" in content


def test_workflow_preserves_policy_exit_status():
    content = WORKFLOW.read_text()

    assert 'summary_exit=' in content
    assert "Security policy failed." in content
    assert "Security policy passed." in content


def test_workflow_generates_report_after_policy_failure():
    content = WORKFLOW.read_text()

    assert "Generate HTML report" in content
    assert "if: always()" in content
    assert "./scripts/report.py" in content


def test_workflow_uploads_security_artifacts():
    content = WORKFLOW.read_text()

    assert "actions/upload-artifact@v4" in content
    assert "reports/latest/report.json" in content
    assert "reports/latest/summary.json" in content
    assert "reports/latest/report.html" in content
