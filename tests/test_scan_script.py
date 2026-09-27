from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "scan.sh"


# ============================================================
# Scan Script
# ============================================================

def test_scan_script_exists_and_is_executable():
    assert SCRIPT.exists()
    assert SCRIPT.stat().st_mode & 0o111


def test_scan_script_uses_syft_image():
    content = SCRIPT.read_text()

    assert '"$SYFT_IMAGE"' in content


def test_scan_script_generates_sbom():
    content = SCRIPT.read_text()

    assert "SBOM_DIR" in content
    assert "syft" in content.lower()
    assert "-o json" in content


def test_scan_script_mounts_docker_socket_for_sbom():
    content = SCRIPT.read_text()

    assert "-v /var/run/docker.sock:/var/run/docker.sock" in content


def test_scan_script_uses_corporate_certificate_for_sbom():
    content = SCRIPT.read_text()

    assert "SSL_CERT_FILE=/tmp/corporate-ca.crt" in content
    assert "CERT_FILE" in content
