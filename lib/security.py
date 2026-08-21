from lib.vulnerability import Vulnerability


def empty_summary():
    """
    Create an empty vulnerability summary.
    """

    return {
        "findings": 0,
        "unique_vulnerabilities": 0,
        "vulnerability_ids": [],
        "vulnerabilities": [],
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "negligible": 0,
        "unknown": 0,
        "weighted_risk": 0,
        "security_score": 0,
        "grade": "",
        "risk_level": "",
    }


def summarize(vulnerabilities):
    """
    Extract vulnerability summary counts from normalized vulnerabilities.
    """

    summary = empty_summary()
    summary["findings"] = len(vulnerabilities)

    for vulnerability in vulnerabilities:

        summary["vulnerabilities"].append(
            vulnerability.to_dict()
        )

        summary["vulnerability_ids"].append(
            vulnerability.id
        )

        severity = vulnerability.severity

        if severity in (
            "critical",
            "high",
            "medium",
            "low",
            "negligible",
            "unknown",
        ):
            summary[severity] += 1
        else:
            summary["unknown"] += 1

    summary["vulnerability_ids"] = sorted(
        set(summary["vulnerability_ids"])
    )

    summary["unique_vulnerabilities"] = len(
        summary["vulnerability_ids"]
    )

    return summary


def weighted_risk(summary):
    """
    Calculate the weighted risk based on vulnerability severity.
    """

    return (
        summary.get("critical", 0) * 10
        + summary.get("high", 0) * 5
        + summary.get("medium", 0) * 2
        + summary.get("low", 0)
    )


def security_score(summary):
    """
    Convert the weighted risk into a normalized score (0–100).

    Higher score = better security.
    """

    risk = weighted_risk(summary)

    return round(100 / (1 + (risk / 100)))


def security_grade(score):
    """
    Convert a security score into a letter grade.
    """

    if score >= 90:
        return "A"
    elif score >= 80:
        return "B"
    elif score >= 70:
        return "C"
    elif score >= 60:
        return "D"
    else:
        return "F"


def risk_level(score):
    """
    Convert security score into a risk classification.

    High score = better security.
    """

    if score >= 90:
        return "LOW"
    elif score >= 70:
        return "MODERATE"
    elif score >= 50:
        return "HIGH"
    else:
        return "CRITICAL"
