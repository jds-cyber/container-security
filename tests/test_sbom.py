import json
from pathlib import Path

from lib.vulnerability import Vulnerability
from lib.sbom import (
    load_sbom,
    correlate_vulnerabilities,
)


ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "sbom.sh"
CONFIG = ROOT / "config" / "config.env"
CONFIG_EXAMPLE = ROOT / "config" / "config.env.example"


# ============================================================
# Configuration
# ============================================================

def test_config_defines_syft_image():
    content = CONFIG.read_text()

    assert "SYFT_IMAGE=registry.access.redhat.com/hi/syft:latest" in content


def test_example_config_defines_syft_image():
    content = CONFIG_EXAMPLE.read_text()

    assert "SYFT_IMAGE=registry.access.redhat.com/hi/syft:latest" in content


# ============================================================
# SBOM Script
# ============================================================

def test_sbom_script_exists_and_is_executable():
    assert SCRIPT.exists()
    assert SCRIPT.stat().st_mode & 0o111


def test_sbom_script_uses_syft():
    content = SCRIPT.read_text()

    assert 'source "$SCRIPT_DIR/common.sh"' in content
    assert '"$SYFT_IMAGE"' in content
    assert '"docker:$IMAGE"' in content
    assert "-o json" in content


def test_sbom_script_mounts_docker_socket():
    content = SCRIPT.read_text()

    assert "-v /var/run/docker.sock:/var/run/docker.sock" in content


def test_sbom_script_uses_corporate_certificate():
    content = SCRIPT.read_text()

    assert 'SSL_CERT_FILE=/tmp/corporate-ca.crt' in content
    assert ':/tmp/corporate-ca.crt:ro"' in content


def test_sbom_script_writes_to_sbom_directory():
    content = SCRIPT.read_text()

    assert '"$ROOT_DIR/$SBOM_DIR/$SCAN_ID"' in content
    assert '"$SBOM_SCAN_DIR/sbom.json"' in content


# ============================================================
# SBOM Correlation
# ============================================================

def test_load_sbom_returns_package_inventory(tmp_path):
    sbom = {
        "artifacts": [
            {
                "name": "openssl",
                "version": "1.1.1",
                "type": "rpm",
                "purl": "pkg:rpm/redhat/openssl@1.1.1",
            }
        ]
    }

    path = tmp_path / "sbom.json"
    path.write_text(json.dumps(sbom))

    packages = load_sbom(path)

    assert packages == [
        {
            "name": "openssl",
            "version": "1.1.1",
            "type": "rpm",
            "purl": "pkg:rpm/redhat/openssl@1.1.1",
        }
    ]


def test_correlate_vulnerability_with_sbom_package():
    vulnerabilities = [
        Vulnerability(
            "CVE-2026-1234",
            severity="high",
            package="openssl",
            installed_version="1.1.1",
        )
    ]

    packages = [
        {
            "name": "openssl",
            "version": "1.1.1",
            "type": "rpm",
            "purl": "pkg:rpm/redhat/openssl@1.1.1",
        }
    ]

    results = correlate_vulnerabilities(
        vulnerabilities,
        packages,
    )

    assert results[0]["vulnerability_id"] == "CVE-2026-1234"
    assert results[0]["package"] == "openssl"
    assert results[0]["installed_version"] == "1.1.1"
    assert results[0]["sbom_match"] is True


def test_correlate_vulnerability_without_sbom_package():
    vulnerabilities = [
        Vulnerability(
            "CVE-2026-1234",
            severity="high",
            package="openssl",
            installed_version="1.1.1",
        )
    ]

    packages = [
        {
            "name": "curl",
            "version": "8.0.0",
            "type": "rpm",
        }
    ]

    results = correlate_vulnerabilities(
        vulnerabilities,
        packages,
    )

    assert results[0]["sbom_match"] is False


def test_correlate_vulnerability_matches_package_name_case_insensitively():
    vulnerabilities = [
        Vulnerability(
            "CVE-2026-1234",
            severity="high",
            package="OpenSSL",
            installed_version="1.1.1",
        )
    ]

    packages = [
        {
            "name": "openssl",
            "version": "1.1.1",
            "type": "rpm",
        }
    ]

    results = correlate_vulnerabilities(
        vulnerabilities,
        packages,
    )

    assert results[0]["sbom_match"] is True


def test_correlate_vulnerability_without_package_does_not_match():
    vulnerabilities = [
        Vulnerability(
            "CVE-2026-1234",
            severity="high",
        )
    ]

    packages = [
        {
            "name": "openssl",
            "version": "1.1.1",
            "type": "rpm",
        }
    ]

    results = correlate_vulnerabilities(
        vulnerabilities,
        packages,
    )

    assert results[0]["sbom_match"] is False


def test_correlate_realistic_grype_vulnerability_with_sbom_package():
    vulnerabilities = [
        Vulnerability(
            "CVE-2026-1234",
            severity="high",
            package="OpenSSL",
            installed_version="1.1.1",
        )
    ]

    packages = [
        {
            "name": "openssl",
            "version": "1.1.1",
            "type": "rpm",
            "purl": "pkg:rpm/redhat/openssl@1.1.1",
        },
        {
            "name": "curl",
            "version": "8.0.0",
            "type": "rpm",
        },
    ]

    results = correlate_vulnerabilities(
        vulnerabilities,
        packages,
    )

    assert results[0]["vulnerability_id"] == "CVE-2026-1234"
    assert results[0]["package"] == "OpenSSL"
    assert results[0]["installed_version"] == "1.1.1"
    assert results[0]["sbom_match"] is True
