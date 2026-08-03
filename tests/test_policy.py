from lib.policy import evaluate


def test_policy_failure():

    summary = {
        "Critical": 1,
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