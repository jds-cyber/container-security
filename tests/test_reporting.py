from pathlib import Path
from lib.reporting import generate_report

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
