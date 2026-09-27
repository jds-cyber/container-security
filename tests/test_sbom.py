from pathlib import Path


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
