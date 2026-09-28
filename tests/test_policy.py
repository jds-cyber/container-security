import pytest

from lib.policy import evaluate, load_policy


# ============================================================
# Policy evaluation
# ============================================================


def test_policy_failure():
    summary = {
        "critical": 1,
        "high": 5,
        "medium": 10,
    }

    policy = {
        "policy": {
            "max_critical": 0,
            "max_high": 10,
            "max_medium": 100,
        },
        "fail_on": [
            "Critical",
            "High",
            "Medium",
        ],
    }

    failures = evaluate(summary, policy)

    assert len(failures) == 1
    assert "Critical" in failures[0]


def test_policy_pass():
    summary = {
        "critical": 0,
        "high": 5,
        "medium": 10,
    }

    policy = {
        "policy": {
            "max_critical": 0,
            "max_high": 10,
            "max_medium": 100,
        },
    }

    failures = evaluate(summary, policy)

    assert failures == []


def test_policy_detects_security_violations():
    summary = {
        "critical": 2,
        "high": 20,
        "medium": 150,
    }

    policy = {
        "policy": {
            "max_critical": 0,
            "max_high": 10,
            "max_medium": 100,
        },
        "fail_on": [
            "Critical",
            "High",
            "Medium",
        ],
    }

    failures = evaluate(summary, policy)

    assert "Critical vulnerabilities exceed limit." in failures
    assert "High vulnerabilities exceed limit." in failures
    assert "Medium vulnerabilities exceed limit." in failures


def test_policy_respects_fail_on():
    summary = {
        "critical": 0,
        "high": 50,
        "medium": 200,
    }

    policy = {
        "policy": {
            "max_critical": 0,
            "max_high": 10,
            "max_medium": 100,
        },
        "fail_on": [
            "Critical",
        ],
    }

    failures = evaluate(summary, policy)

    assert failures == []


def test_policy_passes_at_exact_threshold():
    summary = {
        "critical": 0,
        "high": 10,
        "medium": 100,
    }

    policy = {
        "policy": {
            "max_critical": 0,
            "max_high": 10,
            "max_medium": 100,
        },
        "fail_on": [
            "Critical",
            "High",
            "Medium",
        ],
    }

    failures = evaluate(summary, policy)

    assert failures == []


def test_policy_fails_one_above_threshold():
    summary = {
        "critical": 0,
        "high": 11,
        "medium": 101,
    }

    policy = {
        "policy": {
            "max_critical": 0,
            "max_high": 10,
            "max_medium": 100,
        },
        "fail_on": [
            "Critical",
            "High",
            "Medium",
        ],
    }

    failures = evaluate(summary, policy)

    assert "High vulnerabilities exceed limit." in failures
    assert "Medium vulnerabilities exceed limit." in failures


def test_policy_defaults_missing_thresholds_to_zero():
    summary = {
        "critical": 0,
        "high": 1,
        "medium": 1,
    }

    policy = {
        "policy": {
            "max_critical": 0,
        },
        "fail_on": [
            "Critical",
            "High",
            "Medium",
        ],
    }

    failures = evaluate(summary, policy)

    assert "High vulnerabilities exceed limit." in failures
    assert "Medium vulnerabilities exceed limit." in failures
    assert "Critical vulnerabilities exceed limit." not in failures


def test_policy_allows_missing_threshold_when_severity_not_enforced():
    summary = {
        "critical": 0,
        "high": 50,
        "medium": 200,
    }

    policy = {
        "policy": {
            "max_critical": 0,
        },
        "fail_on": [
            "Critical",
        ],
    }

    failures = evaluate(summary, policy)

    assert failures == []


def test_policy_defaults_missing_fail_on_to_no_enforcement():
    summary = {
        "critical": 10,
        "high": 50,
        "medium": 200,
    }

    policy = {
        "policy": {
            "max_critical": 0,
            "max_high": 10,
            "max_medium": 100,
        },
    }

    failures = evaluate(summary, policy)

    assert failures == []


def test_policy_empty_fail_on_disables_enforcement():
    summary = {
        "critical": 10,
        "high": 50,
        "medium": 200,
    }

    policy = {
        "policy": {
            "max_critical": 0,
            "max_high": 10,
            "max_medium": 100,
        },
        "fail_on": [],
    }

    failures = evaluate(summary, policy)

    assert failures == []


def test_policy_supports_only_critical_threshold():
    summary = {
        "critical": 1,
        "high": 50,
        "medium": 200,
    }

    policy = {
        "policy": {
            "max_critical": 0,
        },
        "fail_on": [
            "Critical",
        ],
    }

    failures = evaluate(summary, policy)

    assert failures == [
        "Critical vulnerabilities exceed limit.",
    ]


def test_policy_missing_summary_severities_default_to_zero():
    summary = {}

    policy = {
        "policy": {
            "max_critical": 0,
            "max_high": 10,
            "max_medium": 100,
        },
        "fail_on": [
            "Critical",
            "High",
            "Medium",
        ],
    }

    failures = evaluate(summary, policy)

    assert failures == []


def test_policy_reports_all_failures_in_severity_order():
    summary = {
        "critical": 1,
        "high": 11,
        "medium": 101,
    }

    policy = {
        "policy": {
            "max_critical": 0,
            "max_high": 10,
            "max_medium": 100,
        },
        "fail_on": [
            "Medium",
            "Critical",
            "High",
        ],
    }

    failures = evaluate(summary, policy)

    assert failures == [
        "Critical vulnerabilities exceed limit.",
        "High vulnerabilities exceed limit.",
        "Medium vulnerabilities exceed limit.",
    ]


def test_policy_enforces_only_high():
    summary = {
        "critical": 10,
        "high": 11,
        "medium": 200,
    }

    policy = {
        "policy": {
            "max_critical": 0,
            "max_high": 10,
            "max_medium": 100,
        },
        "fail_on": [
            "High",
        ],
    }

    failures = evaluate(summary, policy)

    assert failures == [
        "High vulnerabilities exceed limit.",
    ]


def test_policy_enforces_only_medium():
    summary = {
        "critical": 10,
        "high": 20,
        "medium": 101,
    }

    policy = {
        "policy": {
            "max_critical": 0,
            "max_high": 10,
            "max_medium": 100,
        },
        "fail_on": [
            "Medium",
        ],
    }

    failures = evaluate(summary, policy)

    assert failures == [
        "Medium vulnerabilities exceed limit.",
    ]


def test_policy_does_not_fail_passing_severities():
    summary = {
        "critical": 0,
        "high": 10,
        "medium": 100,
    }

    policy = {
        "policy": {
            "max_critical": 0,
            "max_high": 10,
            "max_medium": 100,
        },
        "fail_on": [
            "Critical",
            "High",
            "Medium",
        ],
    }

    failures = evaluate(summary, policy)

    assert failures == []


def test_policy_handles_missing_summary_field_for_enforced_severity():
    summary = {
        "critical": 1,
    }

    policy = {
        "policy": {
            "max_critical": 0,
            "max_high": 10,
            "max_medium": 100,
        },
        "fail_on": [
            "Critical",
            "High",
            "Medium",
        ],
    }

    failures = evaluate(summary, policy)

    assert failures == [
        "Critical vulnerabilities exceed limit.",
    ]


def test_policy_enforces_only_critical():
    summary = {
        "critical": 1,
        "high": 50,
        "medium": 200,
    }

    policy = {
        "policy": {
            "max_critical": 0,
        },
        "fail_on": [
            "Critical",
        ],
    }

    failures = evaluate(summary, policy)

    assert failures == [
        "Critical vulnerabilities exceed limit.",
    ]


def test_policy_does_not_duplicate_failure_for_duplicate_fail_on():
    summary = {
        "critical": 1,
        "high": 0,
        "medium": 0,
    }

    policy = {
        "policy": {
            "max_critical": 0,
            "max_high": 10,
            "max_medium": 100,
        },
        "fail_on": [
            "Critical",
            "critical",
        ],
    }

    failures = evaluate(summary, policy)

    assert failures == [
        "Critical vulnerabilities exceed limit.",
    ]


# ============================================================
# Policy validation and loading
# ============================================================


def test_load_policy_rejects_missing_policy_section(tmp_path):
    policy_file = tmp_path / "policy.yml"

    policy_file.write_text(
        """
fail_on:
  - Critical
"""
    )

    with pytest.raises(
        ValueError,
        match="missing 'policy' section",
    ):
        load_policy(policy_file)


def test_load_policy_rejects_non_integer_threshold(tmp_path):
    policy_file = tmp_path / "policy.yml"

    policy_file.write_text(
        """
policy:
  max_critical: banana
  max_high: 10
  max_medium: 100

fail_on:
  - Critical
"""
    )

    with pytest.raises(
        ValueError,
        match="'max_critical' must be an integer",
    ):
        load_policy(policy_file)


def test_load_policy_rejects_negative_threshold(tmp_path):
    policy_file = tmp_path / "policy.yml"

    policy_file.write_text(
        """
policy:
  max_critical: -1
  max_high: 10
  max_medium: 100

fail_on:
  - Critical
"""
    )

    with pytest.raises(
        ValueError,
        match="'max_critical' cannot be negative",
    ):
        load_policy(policy_file)


def test_load_policy_rejects_invalid_fail_on(tmp_path):
    policy_file = tmp_path / "policy.yml"

    policy_file.write_text(
        """
policy:
  max_critical: 0
  max_high: 10
  max_medium: 100

fail_on: Critical
"""
    )

    with pytest.raises(
        ValueError,
        match="'fail_on' must be a list",
    ):
        load_policy(policy_file)


def test_load_policy_rejects_invalid_fail_on_severity(tmp_path):
    policy_file = tmp_path / "policy.yml"

    policy_file.write_text(
        """
policy:
  max_critical: 0
  max_high: 10
  max_medium: 100

fail_on:
  - Critical
  - Banana
"""
    )

    with pytest.raises(
        ValueError,
        match="'fail_on' contains invalid severity",
    ):
        load_policy(policy_file)


def test_load_policy_accepts_case_insensitive_fail_on_severities(tmp_path):
    policy_file = tmp_path / "policy.yml"

    policy_file.write_text(
        """
policy:
  max_critical: 0
  max_high: 10
  max_medium: 100

fail_on:
  - CRITICAL
  - high
  - MeDiUm
"""
    )

    policy = load_policy(policy_file)

    assert policy["fail_on"] == [
        "CRITICAL",
        "high",
        "MeDiUm",
    ]


def test_load_policy_rejects_non_string_fail_on_severity(tmp_path):
    policy_file = tmp_path / "policy.yml"

    policy_file.write_text(
        """
policy:
  max_critical: 0
  max_high: 10
  max_medium: 100

fail_on:
  - Critical
  - 123
"""
    )

    with pytest.raises(
        ValueError,
        match="'fail_on' contains invalid severity",
    ):
        load_policy(policy_file)


def test_load_policy_rejects_fail_on_severity_with_whitespace(tmp_path):
    policy_file = tmp_path / "policy.yml"

    policy_file.write_text(
        """
policy:
  max_critical: 0
  max_high: 10
  max_medium: 100

fail_on:
  - " Critical "
"""
    )

    with pytest.raises(
        ValueError,
        match="'fail_on' contains invalid severity",
    ):
        load_policy(policy_file)


def test_load_policy_defaults_missing_fail_on_to_empty_list(tmp_path):
    policy_file = tmp_path / "policy.yml"

    policy_file.write_text(
        """
policy:
  max_critical: 0
  max_high: 10
  max_medium: 100
"""
    )

    policy = load_policy(policy_file)

    assert policy["fail_on"] == []


def test_load_policy_rejects_unknown_policy_rule(tmp_path):
    policy_file = tmp_path / "policy.yml"

    policy_file.write_text(
        """
policy:
  max_critical: 0
  max_high: 10
  max_medium: 100
  max_low: 50

fail_on:
  - Critical
"""
    )

    with pytest.raises(
        ValueError,
        match="unknown policy rule",
    ):
        load_policy(policy_file)


# ============================================================
# Policy validation edge cases
# ============================================================


def test_policy_rejects_non_dict_summary():
    policy = {
        "policy": {
            "max_critical": 0,
            "max_high": 10,
            "max_medium": 100,
        },
        "fail_on": [
            "Critical",
            "High",
            "Medium",
        ],
    }

    with pytest.raises(
        ValueError,
        match="summary must be a mapping",
    ):
        evaluate([], policy)


def test_policy_rejects_non_integer_summary_severity():
    summary = {
        "critical": "1",
        "high": 5,
        "medium": 10,
    }

    policy = {
        "policy": {
            "max_critical": 0,
            "max_high": 10,
            "max_medium": 100,
        },
        "fail_on": [
            "Critical",
            "High",
            "Medium",
        ],
    }

    with pytest.raises(
        ValueError,
        match="'critical' must be an integer",
    ):
        evaluate(summary, policy)


def test_policy_rejects_negative_summary_severity():
    summary = {
        "critical": -1,
        "high": 5,
        "medium": 10,
    }

    policy = {
        "policy": {
            "max_critical": 0,
            "max_high": 10,
            "max_medium": 100,
        },
        "fail_on": [
            "Critical",
            "High",
            "Medium",
        ],
    }

    with pytest.raises(
        ValueError,
        match="'critical' cannot be negative",
    ):
        evaluate(summary, policy)


def test_policy_allows_empty_policy_rules():
    summary = {
        "critical": 10,
        "high": 50,
        "medium": 200,
    }

    policy = {
        "policy": {},
    }

    failures = evaluate(summary, policy)

    assert failures == []


# ============================================================
# Container security policy
# ============================================================


def test_policy_enforces_unfixed_vulnerabilities():
    summary = {
        "container_checks": {
            "unfixed_vulnerabilities": [
                {"vulnerability_id": "CVE-2026-0001"},
                {"vulnerability_id": "CVE-2026-0002"},
            ],
        },
    }

    policy = {
        "policy": {
            "max_unfixed_vulnerabilities": 1,
        },
        "fail_on": [
            "UnfixedVulnerabilities",
        ],
    }

    failures = evaluate(summary, policy)

    assert failures == [
        "Unfixed vulnerabilities exceed limit.",
    ]


def test_policy_enforces_high_cvss():
    summary = {
        "container_checks": {
            "high_cvss": [
                {"vulnerability_id": "CVE-2026-0001"},
                {"vulnerability_id": "CVE-2026-0002"},
            ],
        },
    }

    policy = {
        "policy": {
            "max_high_cvss": 1,
        },
        "fail_on": [
            "HighCVSS",
        ],
    }

    failures = evaluate(summary, policy)

    assert failures == [
        "High CVSS vulnerabilities exceed limit.",
    ]


def test_policy_enforces_high_epss():
    summary = {
        "container_checks": {
            "high_epss": [
                {"vulnerability_id": "CVE-2026-0001"},
                {"vulnerability_id": "CVE-2026-0002"},
            ],
        },
    }

    policy = {
        "policy": {
            "max_high_epss": 1,
        },
        "fail_on": [
            "HighEPSS",
        ],
    }

    failures = evaluate(summary, policy)

    assert failures == [
        "High EPSS vulnerabilities exceed limit.",
    ]


def test_policy_enforces_metadata_issues():
    summary = {
        "container_checks": {
            "metadata_completeness": [
                {"vulnerability_id": "CVE-2026-0001"},
                {"vulnerability_id": "CVE-2026-0002"},
            ],
        },
    }

    policy = {
        "policy": {
            "max_metadata_issues": 1,
        },
        "fail_on": [
            "Metadata",
        ],
    }

    failures = evaluate(summary, policy)

    assert failures == [
        "Metadata issues exceed limit.",
    ]


def test_policy_container_checks_pass_at_exact_threshold():
    summary = {
        "container_checks": {
            "unfixed_vulnerabilities": [{}],
            "high_cvss": [{}],
            "high_epss": [{}],
            "metadata_completeness": [{}],
        },
    }

    policy = {
        "policy": {
            "max_unfixed_vulnerabilities": 1,
            "max_high_cvss": 1,
            "max_high_epss": 1,
            "max_metadata_issues": 1,
        },
        "fail_on": [
            "UnfixedVulnerabilities",
            "HighCVSS",
            "HighEPSS",
            "Metadata",
        ],
    }

    failures = evaluate(summary, policy)

    assert failures == []


def test_policy_container_checks_fail_one_above_threshold():
    summary = {
        "container_checks": {
            "unfixed_vulnerabilities": [{}, {}],
            "high_cvss": [{}, {}],
            "high_epss": [{}, {}],
            "metadata_completeness": [{}, {}],
        },
    }

    policy = {
        "policy": {
            "max_unfixed_vulnerabilities": 1,
            "max_high_cvss": 1,
            "max_high_epss": 1,
            "max_metadata_issues": 1,
        },
        "fail_on": [
            "UnfixedVulnerabilities",
            "HighCVSS",
            "HighEPSS",
            "Metadata",
        ],
    }

    failures = evaluate(summary, policy)

    assert failures == [
        "Unfixed vulnerabilities exceed limit.",
        "High CVSS vulnerabilities exceed limit.",
        "High EPSS vulnerabilities exceed limit.",
        "Metadata issues exceed limit.",
    ]


def test_policy_container_checks_respect_fail_on():
    summary = {
        "container_checks": {
            "unfixed_vulnerabilities": [{}, {}],
            "high_cvss": [{}, {}],
            "high_epss": [{}, {}],
            "metadata_completeness": [{}, {}],
        },
    }

    policy = {
        "policy": {
            "max_unfixed_vulnerabilities": 1,
            "max_high_cvss": 1,
            "max_high_epss": 1,
            "max_metadata_issues": 1,
        },
        "fail_on": [
            "HighCVSS",
        ],
    }

    failures = evaluate(summary, policy)

    assert failures == [
        "High CVSS vulnerabilities exceed limit.",
    ]


def test_policy_container_checks_default_missing_thresholds_to_zero():
    summary = {
        "container_checks": {
            "unfixed_vulnerabilities": [{}],
            "high_cvss": [{}],
            "high_epss": [{}],
            "metadata_completeness": [{}],
        },
    }

    policy = {
        "policy": {},
        "fail_on": [
            "UnfixedVulnerabilities",
            "HighCVSS",
            "HighEPSS",
            "Metadata",
        ],
    }

    failures = evaluate(summary, policy)

    assert failures == [
        "Unfixed vulnerabilities exceed limit.",
        "High CVSS vulnerabilities exceed limit.",
        "High EPSS vulnerabilities exceed limit.",
        "Metadata issues exceed limit.",
    ]


def test_policy_container_checks_allow_missing_summary():
    summary = {}

    policy = {
        "policy": {
            "max_unfixed_vulnerabilities": 0,
            "max_high_cvss": 0,
            "max_high_epss": 0,
            "max_metadata_issues": 0,
        },
        "fail_on": [
            "UnfixedVulnerabilities",
            "HighCVSS",
            "HighEPSS",
            "Metadata",
        ],
    }

    failures = evaluate(summary, policy)

    assert failures == []


def test_policy_container_checks_accept_case_insensitive_fail_on():
    summary = {
        "container_checks": {
            "high_cvss": [{}],
        },
    }

    policy = {
        "policy": {
            "max_high_cvss": 0,
        },
        "fail_on": ["highcvss"],
    }

    failures = evaluate(summary, policy)

    assert failures == ["High CVSS vulnerabilities exceed limit."]
