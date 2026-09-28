import pytest

from lib.container_checks import (
    check_unfixed_vulnerabilities,
    check_high_cvss,
    check_high_epss,
    check_metadata_completeness,
)
from lib.vulnerability import (
    CVSS,
    EPSS,
    Vulnerability,
    VulnerabilityIntelligence,
)


# ============================================================
# Unfixed vulnerabilities
# ============================================================

def test_check_unfixed_vulnerabilities():
    vulnerabilities = [
        Vulnerability(
            "CVE-2024-1234",
            fixed_version=None,
        ),
        Vulnerability(
            "CVE-2024-5678",
            fixed_version="1.2.3",
        ),
    ]

    results = check_unfixed_vulnerabilities(vulnerabilities)

    assert results == [
        {
            "vulnerability_id": "CVE-2024-1234",
            "package": None,
        }
    ]


# ============================================================
# High CVSS
# ============================================================

def test_check_high_cvss():
    vulnerability = Vulnerability(
        "CVE-2024-1234",
        intelligence=VulnerabilityIntelligence(
            "CVE-2024-1234",
            cvss=CVSS("3.1", 9.8),
        ),
    )

    results = check_high_cvss([vulnerability])

    assert results == [
        {
            "vulnerability_id": "CVE-2024-1234",
            "score": 9.8,
        }
    ]


# ============================================================
# High EPSS
# ============================================================

def test_check_high_epss():
    vulnerability = Vulnerability(
        "CVE-2024-1234",
        intelligence=VulnerabilityIntelligence(
            "CVE-2024-1234",
            epss=EPSS(
                score=0.75,
                percentile=0.99,
            ),
        ),
    )

    results = check_high_epss([vulnerability])

    assert results == [
        {
            "vulnerability_id": "CVE-2024-1234",
            "score": 0.75,
            "percentile": 0.99,
        }
    ]


# ============================================================
# Metadata completeness
# ============================================================

def test_check_metadata_completeness():
    vulnerabilities = [
        Vulnerability(
            "CVE-2024-1234",
            package="openssl",
            installed_version="1.1.1",
        ),
        Vulnerability(
            "CVE-2024-5678",
        ),
    ]

    results = check_metadata_completeness(vulnerabilities)

    assert results == [
        {
            "vulnerability_id": "CVE-2024-5678",
            "missing": [
                "package",
                "installed_version",
            ],
        }
    ]
