import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
MAKEFILE = ROOT / "Makefile"


def test_makefile_defines_security_report():
    content = MAKEFILE.read_text()

    assert "security-report:" in content
    assert '$(MAKE) scan IMAGE="$(IMAGE)"' in content
    assert '$(MAKE) summarize REPORT="$(REPORT)"' in content
    assert '$(MAKE) report IMAGE="$(IMAGE)"' in content


def test_security_report_preserves_summary_exit_code():
    content = MAKEFILE.read_text()

    assert "set +e" in content
    assert "SUMMARY_EXIT=$$?" in content
    assert "exit $$SUMMARY_EXIT" in content


def test_summarize_target_does_not_ignore_policy_failure():
    content = MAKEFILE.read_text()

    lines = content.splitlines()

    summarize_line = next(
        line for line in lines
        if "$(MAKE) summarize REPORT=" in line
    )

    assert not summarize_line.lstrip().startswith("@-")


def test_security_report_preserves_report_exit_code():
    content = MAKEFILE.read_text()

    assert "REPORT_EXIT=$$?" in content
    assert "if [ $$REPORT_EXIT -ne 0 ]" in content
    assert "exit $$REPORT_EXIT" in content


def test_security_report_runs_report_after_summary_failure():
    content = MAKEFILE.read_text()

    lines = content.splitlines()

    summarize_index = next(
        i for i, line in enumerate(lines)
        if "$(MAKE) summarize REPORT=" in line
    )

    report_index = next(
        i for i, line in enumerate(lines)
        if "$(MAKE) report IMAGE=" in line
    )

    assert summarize_index < report_index
