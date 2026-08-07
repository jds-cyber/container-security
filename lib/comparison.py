def compare_scores(previous, current):
    """
    Compare two security scores.
    """

    delta = current["security_score"] - previous["security_score"]

    if delta > 0:
        trend = "Improved"
    elif delta < 0:
        trend = "Regressed"
    else:
        trend = "No Change"

    return {
        "previous": previous["security_score"],
        "current": current["security_score"],
        "delta": delta,
        "trend": trend,
    }
