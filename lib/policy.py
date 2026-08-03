import yaml

def load_policy(path):
    with open(path, "r") as file:
        return yaml.safe_load(file)

def evaluate(summary, policy):
    failures = []

    rules = policy["policy"]

    fail_on = [
        severity.lower()
        for severity in policy.get("fail_on", [])
    ]

    if "critical" in fail_on:
        if summary.get("critical", 0) > rules.get("max_critical", 0):
            failures.append(
                f"Critical vulnerabilities exceed limit."
            )
    if "high" in fail_on:
        if summary.get("high", 0) > rules.get("max_high", 0):
            failures.append(
                f"High vulnerabilities exceed limit."
            )

    if "medium" in fail_on:
        if summary.get("medium", 0) > rules.get("max_medium", 0):
            failures.append(
                f"Medium vulnerabilities exceed limit."
            )

    return failures
