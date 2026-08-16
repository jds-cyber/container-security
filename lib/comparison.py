SEVERITIES = (
    "critical",
    "high",
    "medium",
    "low",
    "negligible",
    "unknown",
)


def _validate_score(summary, field_name):
    """
    Validate a security score used for comparison.
    """

    if not isinstance(summary, dict):
        raise ValueError(
            f"Invalid comparison summary: expected dict"
        )

    if field_name not in summary:
        raise ValueError(
            f"Missing {field_name} in comparison summary"
        )

    score = summary[field_name]

    if (
        isinstance(score, bool)
        or not isinstance(score, (int, float))
        or score < 0
        or score > 100
    ):
        raise ValueError(
            f"Invalid {field_name} in comparison summary"
        )

    return score


def _validate_vulnerability_ids(summary):
    """
    Validate vulnerability identifiers used for comparison.
    """

    if not isinstance(summary, dict):
        raise ValueError(
            f"Invalid comparison summary: expected dict"
        )

    if "vulnerability_ids" not in summary:
        raise ValueError(
            f"Missing vulnerability_ids in comparison summary"
        )

    vulnerability_ids = summary["vulnerability_ids"]

    if not isinstance(vulnerability_ids, list):
        raise ValueError(
            "Invalid vulnerability_ids in comparison summary"
        )

    for vulnerability_id in vulnerability_ids:
        if (
            not isinstance(vulnerability_id, str)
            or not vulnerability_id.strip()
        ):
            raise ValueError(
                f"Invalid vulnerability_ids in comparison summary"
            )

    return vulnerability_ids


def _validate_severity_count(summary, severity):
    """
    Validate an individual severity count.

    Missing severity fields are treated as zero for compatibility with historical summaries that predate the field.
    """

    if not isinstance(summary, dict):
        raise ValueError(
            f"Invalid comparison summary: excepted dict"
        )

    if severity not in summary:
        return 0

    count = summary[severity]

    if (
        isinstance(count, bool)
        or not isinstance(count, int)
        or count < 0
    ):
        raise ValueError(
            f"Invalid {severity} count in comparison summary"
        )

    return count


def compare_scores(previous, current):
    """
    Compare two security scores.
    """

    previous_score = _validate_score(previous, "security_score")
    current_score = _validate_score(current, "security_score")

    delta = current_score - previous_score

    if delta > 0:
        trend = "Improved"
    elif delta < 0:
        trend = "Regressed"
    else:
        trend = "No Change"

    return {
        "previous": previous_score,
        "current": current_score,
        "delta": delta,
        "trend": trend,
    }


def compare_vulnerabilities(previous, current):
    """
    Compare vulnerability IDs between two scans.
    """

    previous_ids = set(_validate_vulnerability_ids(previous))
    current_ids = set(_validate_vulnerability_ids(current))

    return {
        "new": sorted(current_ids - previous_ids),
        "fixed": sorted(previous_ids - current_ids),
        "unchanged": sorted(previous_ids & current_ids)
    }


def compare_severity(previous, current):
    """
    Compare vulnerability severity counts between two scans.
    """

    comparison = {}

    for severity in SEVERITIES:
        previous_count = _validate_severity_count(previous, severity)
        current_count = _validate_severity_count(current, severity)

        comparison[severity] = {
            "previous": previous_count,
            "current": current_count,
            "delta": current_count - previous_count,
        }

    return comparison
