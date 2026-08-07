def compare_scores(previous, current):
    """
    Compare two security scores.
    """

    previous_score = previous.get("security_score", 0)
    current_score = current.get("security_score", 0)

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

    previous_ids = set(previous.get("vulnerability_ids", []))
    current_ids = set(current.get("vulnerability_ids", []))

    return {
        "new": sorted(current_ids - previous_ids),
        "fixed": sorted(previous_ids - current_ids),
        "unchanged": sorted(previous_ids & current_ids)
    }
