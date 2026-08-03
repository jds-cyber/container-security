import yaml

def load_policy(path):
    with open(path, "r") as file:
        return yaml.safe_load(file)

def evaluate(summary, policy):
    failures = []

    rules = policy["policy"]

    if summary.get("critical", 0) > rules.get("max_critical", 0):
        failures.append(
            f"Critical vulnerabilities exceed limit."
        )

    if summary.get("high", 0) > rules.get("max_high", 0):
        failures.append(
            f"High vulnerabilities exceed limit."
        )

    if summary.get("medium", 0) > rules.get("max_medium", 0):
        failures.append(
            f"Medium vulnerabilities exceed limit."
        )

    return failures
