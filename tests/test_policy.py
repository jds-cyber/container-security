import pytest

from lib.policy import evaluate, load_policy


def test_policy_failure():

    summary = {
        "critical": 1,
        "high": 5,
        "medium": 10
    }

    policy = {
        "policy": {
            "max_critical": 0,
            "max_high": 10,
            "max_medium": 100
        },
        "fail_on": [
            "Critical",
            "High",
            "Medium"
        ]
    }

    failures = evaluate(summary, policy)

    assert len(failures) == 1
    assert "Critical" in failures[0]


def test_policy_pass():

    summary = {
        "critical": 0,
        "high": 5,
        "medium": 10
    }

    policy = {
        "policy": {
            "max_critical": 0,
            "max_high": 10,
            "max_medium": 100
        }
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
            "Medium"
        ]
    }

    failures = evaluate(summary, policy)

    assert "Critical vulnerabilities exceed limit." in failures
    assert "High vulnerabilities exceed limit." in failures
    assert "Medium vulnerabilities exceed limit." in failures


def test_policy_respects_fail_on():

    summary = {
        "critical": 0,
        "high": 50,
        "medium": 200
    }

    policy = {
        "policy": {
            "max_critical": 0,
            "max_high": 10,
            "max_medium": 100
        },
        "fail_on": [
            "Critical",
        ]
    }

    failures = evaluate(summary, policy)

    assert failures == []


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
