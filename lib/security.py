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
        "intelligence_summary": {
            "total": 0,
            "enriched": 0,
            "unenriched": 0,
            "cvss_available": 0,
            "cwe_available": 0,
            "high_cvss": 0,
            "high_epss": 0,
            "high_epss_percentile": 0,
            "affected_package": 0,
        },
    }


def intelligence_summary(vulnerabilities):
    """
    Summarize vulnerability intelligence coverage.
    """

    summary = {
        "total": len(vulnerabilities),
        "enriched": 0,
        "unenriched": 0,
        "cvss_available": 0,
        "cwe_available": 0,
        "high_cvss": 0,
        "high_epss": 0,
        "high_epss_percentile": 0,
        "affected_package": 0,
    }

    for vulnerability in vulnerabilities:
        intelligence = vulnerability.intelligence

        if intelligence is None:
            summary["unenriched"] += 1
            continue

        summary["enriched"] += 1

        if intelligence.cvss is not None:
            summary["cvss_available"] += 1

        if intelligence.cwe:
            summary["cwe_available"] += 1

        for indicator in intelligence.risk_indicators():
            if indicator in summary:
                summary[indicator] += 1

    return summary


def sbom_summary(correlation):
    """
    Summarize SBOM vulnerability correlation.
    """

    total = len(correlation)

    matched = sum(
        1
        for result in correlation
        if result.get("sbom_match") is True
    )

    return {
        "total": total,
        "matched": matched,
        "unmatched": total - matched,
    }


def summarize(vulnerabilities, sbom_correlation=None):
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

    summary["intelligence_summary"] = intelligence_summary(
        vulnerabilities
    )

    if sbom_correlation is not None:
        summary["sbom_summary"] = sbom_summary(
            sbom_correlation
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
