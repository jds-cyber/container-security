import json


def load_sbom(path):
    """
    Load a Syft SBOM and return its package inventory.
    """

    with open(path) as f:
        sbom = json.load(f)

    if not isinstance(sbom, dict):
        raise ValueError("Invalid SBOM structure")

    artifacts = sbom.get("artifacts", [])

    if not isinstance(artifacts, list):
        raise ValueError("Invalid SBOM artifacts")

    packages = []

    for artifact in artifacts:
        if not isinstance(artifact, dict):
            continue

        packages.append(
            {
                "name": artifact.get("name"),
                "version": artifact.get("version"),
                "type": artifact.get("type"),
                "purl": artifact.get("purl"),
            }
        )

    return packages


def correlate_vulnerabilities(vulnerabilities, packages):
    """
    Correlate normalized vulnerabilities with SBOM packages.
    """

    package_keys = {
        (
            package.get("name", "").strip().lower(),
            package.get("version"),
        )
        for package in packages
    }

    results = []

    for vulnerability in vulnerabilities:
        key = (
            (vulnerability.package or "").strip().lower(),
            vulnerability.installed_version,
        )

        results.append(
            {
                "vulnerability_id": vulnerability.id,
                "package": vulnerability.package,
                "installed_version": vulnerability.installed_version,
                "sbom_match": key in package_keys,
            }
        )

    return results
