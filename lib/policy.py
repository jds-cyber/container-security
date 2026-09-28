import yaml


def load_policy(path):
    try:
        with open(path, "r") as file:
            policy = yaml.safe_load(file)
    except FileNotFoundError:
        raise ValueError(f"Policy file not found: {path}")
    except yaml.YAMLError as exc:
        raise ValueError(f"Invalid policy YAML: {exc}")

    if not isinstance(policy, dict):
        raise ValueError("Invalid policy configuration")

    if "policy" not in policy:
        raise ValueError("Invalid policy configuration: missing 'policy' section")

    rules = policy["policy"]

    if not isinstance(rules, dict):
        raise ValueError("Invalid policy configuration: 'policy' must be a mapping")

    valid_rules = {
        "max_critical",
        "max_high",
        "max_medium",
        "max_unfixed_vulnerabilities",
        "max_high_cvss",
        "max_high_epss",
        "max_metadata_issues",
    }

    for key in rules:
        if key not in valid_rules:
            raise ValueError(
                f"Invalid policy configuration: unknown policy rule: {key}"
            )

    for key in valid_rules:
        if key in rules:
            value = rules[key]

            if not isinstance(value, int) or isinstance(value, bool):
                raise ValueError(
                    f"Invalid policy configuration: '{key}' must be an integer."
                )

            if value < 0:
                raise ValueError(
                    f"Invalid policy configuration: '{key}' cannot be negative."
                )

    if "fail_on" not in policy:
        policy["fail_on"] = []

    elif not isinstance(policy["fail_on"], list):
        raise ValueError(
            "Invalid policy configuration: 'fail_on' must be a list"
        )

    valid_fail_on = {
        "critical",
        "high",
        "medium",
        "unfixedvulnerabilities",
        "highcvss",
        "highepss",
        "metadata",
    }

    for severity in policy["fail_on"]:
        if not isinstance(severity, str):
            raise ValueError(
                "Invalid policy configuration: "
                "'fail_on' contains invalid severity"
            )

        if severity.lower() not in valid_fail_on:
            raise ValueError(
                "Invalid policy configuration: "
                f"'fail_on' contains invalid severity: {severity}"
            )

    return policy


def evaluate(summary, policy):
    if not isinstance(summary, dict):
        raise ValueError("Invalid summary configuration: summary must be a mapping.")

    for severity in ("critical", "high", "medium"):
        if severity in summary:
            value = summary[severity]

            if not isinstance(value, int) or isinstance(value, bool):
                raise ValueError(
                    f"Invalid summary configuration: "
                    f"'{severity}' must be an integer."
                )

            if value < 0:
                raise ValueError(
                    f"Invalid summary configuration: "
                    f"'{severity}' cannot be negative."
                )

    if not isinstance(policy, dict):
        raise ValueError("Invalid policy configuration")

    if "policy" not in policy:
        raise ValueError(
            "Invalid policy configuration: missing policy section."
        )

    rules = policy["policy"]

    if not isinstance(rules, dict):
        raise ValueError(
            "Invalid policy configuration: policy must be a mapping."
        )

    severity_rules = {
        "critical": "max_critical",
        "high": "max_high",
        "medium": "max_medium",
    }

    fail_on = [
        severity.lower()
        for severity in policy.get("fail_on", [])
    ]

    container_rules = {
        "UnfixedVulnerabilities": "unfixed_vulnerabilities",
        "HighCVSS": "high_cvss",
        "HighEPSS": "high_epss",
        "Metadata": "metadata_completeness",
    }

    failures = []

    for severity, rule in severity_rules.items():
        if severity not in fail_on:
            continue

        count = summary.get(severity, 0)
        limit = rules.get(rule, 0)

        if count > limit:
            failures.append(
                f"{severity.capitalize()} vulnerabilities exceed limit."
            )

    container_failure_messages = {
        "unfixed_vulnerabilities": "Unfixed vulnerabilities exceed limit.",
        "high_cvss": "High CVSS vulnerabilities exceed limit.",
        "high_epss": "High EPSS vulnerabilities exceed limit.",
        "metadata_completeness": "Metadata issues exceed limit.",
    }

    checks = summary.get("container_checks", {})

    for fail_on_name, check_name in container_rules.items():
        if fail_on_name.lower() not in fail_on:
            continue

        rule = {
            "unfixed_vulnerabilities": "max_unfixed_vulnerabilities",
            "high_cvss": "max_high_cvss",
            "high_epss": "max_high_epss",
            "metadata_completeness": "max_metadata_issues",
        }[check_name]

        if check_name not in checks:
            continue

        count = len(checks[check_name])
        limit = rules.get(rule, 0)

        if count > limit:
            failures.append(container_failure_messages[check_name])

    return failures
