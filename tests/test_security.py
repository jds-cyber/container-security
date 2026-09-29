from lib.security import (
    sbom_summary,
    summarize,
    weighted_risk,
    security_score,
    security_grade,
    risk_level,
    empty_summary,
    intelligence_summary,
)
from lib.vulnerability import (
    Vulnerability,
    VulnerabilityIntelligence,
    CVSS,
    EPSS,
    AffectedPackage,
)


# ---------------------------------------------------------------------------
# summarize
# ---------------------------------------------------------------------------

def test_security_summary():

    vulnerabilities = [
        Vulnerability(
            "CVE-2026-0001",
            severity="critical",
        ),
        Vulnerability(
            "CVE-2026-0002",
            severity="high",
        ),
        Vulnerability(
            "CVE-2026-0003",
            severity="medium",
        ),
    ]

    result = summarize(vulnerabilities)

    assert result["critical"] == 1
    assert result["high"] == 1
    assert result["medium"] == 1
    assert result["findings"] == 3
    assert result["unique_vulnerabilities"] == 3


def test_unique_vulnerabilities():

    vulnerabilities = [
        Vulnerability(
            "CVE-2026-0001",
            severity="critical",
        ),
        Vulnerability(
            "CVE-2026-0001",
            severity="high",
        ),
        Vulnerability(
            "CVE-2026-0003",
            severity="medium",
        ),
    ]

    result = summarize(vulnerabilities)

    assert result["unique_vulnerabilities"] == 2


# ---------------------------------------------------------------------------
# intelligence_summary
# ---------------------------------------------------------------------------

def test_intelligence_summary_counts_enrichment():

    vulnerabilities = [
        Vulnerability(
            "CVE-2026-0001",
            severity="critical",
        ),
        Vulnerability(
            "CVE-2026-0002",
            severity="high",
        ),
        Vulnerability(
            "CVE-2026-0003",
            severity="medium",
        ),
    ]

    result = intelligence_summary(vulnerabilities)

    assert result["total"] == 3
    assert result["enriched"] == 0
    assert result["unenriched"] == 3
    assert result["cvss_available"] == 0
    assert result["cwe_available"] == 0


def test_intelligence_summary_counts_cvss_and_cwe():

    intelligence = VulnerabilityIntelligence(
        "CVE-2026-0001",
        description="Test vulnerability.",
        cvss=CVSS(
            version="3.1",
            score=8.1,
            vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            severity="high",
        ),
        epss=EPSS(
            score=0.8,
            percentile=0.95
        ),
        cwe=["CWE-787"],
        affected_packages=[
            AffectedPackage(
                ecosystem="PyPI",
                name="requests",
            ),
        ],
    )

    vulnerabilities = [
        Vulnerability(
            "CVE-2026-0001",
            severity="high",
            intelligence=intelligence,
        ),
        Vulnerability(
            "CVE-2026-0002",
            severity="medium",
        ),
    ]

    result = intelligence_summary(vulnerabilities)

    assert result["total"] == 2
    assert result["enriched"] == 1
    assert result["unenriched"] == 1
    assert result["cvss_available"] == 1
    assert result["cwe_available"] == 1
    assert result["high_cvss"] == 1
    assert result["high_epss"] == 1
    assert result["high_epss_percentile"] == 1
    assert result["affected_package"] == 1


def test_intelligence_summary_counts_enriched_without_cvss_or_cwe():

    intelligence = VulnerabilityIntelligence(
        "CVE-2026-0001",
        description="Test vulnerability.",
    )

    vulnerabilities = [
        Vulnerability(
            "CVE-2026-0001",
            severity="high",
            intelligence=intelligence,
        ),
    ]

    result = intelligence_summary(vulnerabilities)

    assert result["total"] == 1
    assert result["enriched"] == 1
    assert result["unenriched"] == 0
    assert result["cvss_available"] == 0
    assert result["cwe_available"] == 0


def test_intelligence_summary_counts_cwe_without_cvss():

    intelligence = VulnerabilityIntelligence(
        "CVE-2026-0001",
        description="Test vulnerability.",
        cwe=["CWE-79"],
    )

    vulnerabilities = [
        Vulnerability(
            "CVE-2026-0001",
            severity="high",
            intelligence=intelligence,
        ),
    ]

    result = intelligence_summary(vulnerabilities)

    assert result["total"] == 1
    assert result["enriched"] == 1
    assert result["unenriched"] == 0
    assert result["cvss_available"] == 0
    assert result["cwe_available"] == 1


def test_security_summary_includes_intelligence_summary():

    intelligence = VulnerabilityIntelligence(
        "CVE-2026-0001",
        description="Test vulnerability.",
        cvss=CVSS(
            version="3.1",
            score=8.1,
            vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            severity="high",
        ),
        cwe=["CWE-787"],
    )

    vulnerabilities = [
        Vulnerability(
            "CVE-2026-0001",
            severity="high",
            intelligence=intelligence,
        ),
        Vulnerability(
            "CVE-2026-0002",
            severity="medium",
        ),
    ]

    result = summarize(vulnerabilities)

    assert result["intelligence_summary"] == {
        "total": 2,
        "enriched": 1,
        "unenriched": 1,
        "cvss_available": 1,
        "cwe_available": 1,
        "high_cvss": 1,
        "high_epss": 0,
        "high_epss_percentile": 0,
        "affected_package": 0,
    }


# ---------------------------------------------------------------------------
# container_checks
# ---------------------------------------------------------------------------

def test_security_summary_includes_container_checks():

    vulnerabilities = [
        Vulnerability(
            "CVE-2026-0001",
            severity="high",
            package="openssl",
            installed_version="1.1.1",
            fixed_version=None,
            intelligence=VulnerabilityIntelligence(
                "CVE-2026-0001",
                cvss=CVSS(
                    version="3.1",
                    score=8.1,
                ),
                epss=EPSS(
                    score=0.8,
                    percentile=0.95,
                ),
            ),
        ),
        Vulnerability(
            "CVE-2026-0002",
            severity="medium",
            package=None,
            installed_version=None,
            fixed_version="2.0.0",
        ),
    ]

    result = summarize(vulnerabilities)

    assert result["container_checks"] == {
        "unfixed_vulnerabilities": [
            {
                "vulnerability_id": "CVE-2026-0001",
                "package": "openssl",
            }
        ],
        "high_cvss": [
            {
                "vulnerability_id": "CVE-2026-0001",
                "score": 8.1,
            }
        ],
        "high_epss": [
            {
                "vulnerability_id": "CVE-2026-0001",
                "score": 0.8,
                "percentile": 0.95,
            }
        ],
        "metadata_completeness": [
            {
                "vulnerability_id": "CVE-2026-0002",
                "missing": [
                    "package",
                    "installed_version",
                ],
            }
        ],
    }


# ---------------------------------------------------------------------------
# weighted_risk
# ---------------------------------------------------------------------------

def test_weighted_risk():

    summary = {
        "critical": 2,
        "high": 3,
        "medium": 4,
        "low": 5,
    }

    risk = weighted_risk(summary)

    assert risk == (
        2 * 10
        + 3 * 5
        + 4 * 2
        + 5
    )


# ---------------------------------------------------------------------------
# security_score
# ---------------------------------------------------------------------------

def test_security_score():

    summary = {
        "critical": 2,
        "high": 3,
        "medium": 4,
        "low": 5,
    }

    score = security_score(summary)

    assert 0 <= score <= 100


# ---------------------------------------------------------------------------
# empty_summary
# ---------------------------------------------------------------------------

def test_empty_summary():
    """
    Ensure the default summary dictionary does not accidentally change.
    """

    summary = empty_summary()

    assert summary["findings"] == 0
    assert summary["unique_vulnerabilities"] == 0
    assert summary["critical"] == 0
    assert summary["security_score"] == 0
    assert summary["grade"] == ""

    assert summary["intelligence_summary"]["total"] == 0
    assert summary["intelligence_summary"]["enriched"] == 0
    assert summary["intelligence_summary"]["unenriched"] == 0
    assert summary["intelligence_summary"]["cvss_available"] == 0
    assert summary["intelligence_summary"]["cwe_available"] == 0
    assert summary["intelligence_summary"]["high_cvss"] == 0
    assert summary["intelligence_summary"]["high_epss"] == 0
    assert summary["intelligence_summary"]["high_epss_percentile"] == 0
    assert summary["intelligence_summary"]["affected_package"] == 0


# ---------------------------------------------------------------------------
# security_grade
# ---------------------------------------------------------------------------

def test_security_grade():
    """
    Verify security score classification.
    """

    assert security_grade(95) == "A"
    assert security_grade(85) == "B"
    assert security_grade(75) == "C"
    assert security_grade(65) == "D"
    assert security_grade(40) == "F"


# ---------------------------------------------------------------------------
# risk_level
# ---------------------------------------------------------------------------

def test_risk_level():
    """
    Verify risk classification.
    """

    assert risk_level(95) == "LOW"
    assert risk_level(75) == "MODERATE"
    assert risk_level(55) == "HIGH"
    assert risk_level(25) == "CRITICAL"


# ============================================================
# SBOM Summary
# ============================================================

def test_sbom_summary_counts_correlation():
    correlation = [
        {
            "vulnerability_id": "CVE-2026-1234",
            "package": "openssl",
            "installed_version": "1.1.1",
            "sbom_match": True,
        },
        {
            "vulnerability_id": "CVE-2026-5678",
            "package": "curl",
            "installed_version": "8.0.0",
            "sbom_match": False,
        },
    ]

    summary = sbom_summary(correlation)

    assert summary == {
        "total": 2,
        "matched": 1,
        "unmatched": 1,
    }


def test_summarize_includes_sbom_summary_when_provided():
    vulnerability = Vulnerability(
        "CVE-2026-1234",
        severity="high",
        package="openssl",
        installed_version="1.1.1",
    )

    correlation = [
        {
            "vulnerability_id": "CVE-2026-1234",
            "package": "openssl",
            "installed_version": "1.1.1",
            "sbom_match": True,
        }
    ]

    summary = summarize(
        [vulnerability],
        sbom_correlation=correlation,
    )

    assert summary["sbom_summary"] == {
        "total": 1,
        "matched": 1,
        "unmatched": 0,
    }


def test_summarize_includes_packages_when_provided():
    vulnerabilities = []
    packages = [
        {
            "name": "openssl",
            "version": "3.0.2",
            "type": "deb",
            "purl": "pkg:deb/ubuntu/openssl@3.0.2",
        }
    ]

    summary = summarize(
        vulnerabilities,
        packages=packages,
    )

    assert summary["packages"] == packages
