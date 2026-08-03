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
        "Critical": 0,
        "High": 5,
        "Medium": 10
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
