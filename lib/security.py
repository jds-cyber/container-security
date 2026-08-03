def summarize(matches):
    """
    Extract vulnerability summary counts from Grype matches.
    """

    summary = {
    "Findings": len(matches),
    "Unique Vulnerabilities": len(
        set(
            match.get("vulnerability", {})
            .get("id")
            for match in matches
        )
    ),
    "Critical": 0,
    "High": 0,
    "Medium": 0,
    "Low": 0,
    "Negligible": 0,
    "Unknown": 0,
}

    for match in matches:
        severity = (
            match.get("vulnerability", {})
            .get("severity", "Unknown")
            .capitalize()
        )

        if severity in summary:
            summary[severity] += 1
        else:
            summary["Unknown"] += 1

    return summary


def security_score(summary):
    """
    Calculate a simple risk score.

    Higher score = higher risk.
    """

    score = (
        summary.get("Critical", 0) * 10 +
        summary.get("High", 0) * 5 +
        summary.get("Medium", 0) * 2 +
        summary.get("Low", 0)
    )

    return score