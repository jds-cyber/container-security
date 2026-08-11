from lib.policy import evaluate


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
    from lib.policy import load_policy

    policy_file = tmp_path / "policy.yml"

    policy_file.write_text(
        """
fail_on:
  - Critical
"""
    )

    try:
        load_policy(policy_file)
        assert False, "Expected invalid policy configuration"
    except ValueError as exc:
        assert "missing 'policy' section" in str(exc)


def test_load_policy_rejects_non_integer_threshold(tmp_path):
    from lib.policy import load_policy

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

    try:
        load_policy(policy_file)
        assert False, "Expected invalid policy configuration"
    except ValueError as exc:
        assert "'max_critical' must be an integer" in str(exc)


def test_load_policy_rejects_negative_threshold(tmp_path):
    from lib.policy import load_policy

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

    try:
        load_policy(policy_file)
        assert False, "Expected invalid policy configuration"
    except ValueError as exc:
        assert "'max_critical' cannot be negative" in str(exc)


def test_load_policy_rejects_invalid_fail_on(tmp_path):
    from lib.policy import load_policy

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

    try:
        load_policy(policy_file)
        assert False, "Expected invalid policy configuration"
    except ValueError as exc:
        assert "'fail_on' must be a list" in str(exc)
