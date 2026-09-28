from lib.vulnerability import Vulnerability


def check_unfixed_vulnerabilities(vulnerabilities):
    results = []

    for vulnerability in vulnerabilities:
        if vulnerability.fixed_version is None:
            results.append(
                {
                    "vulnerability_id": vulnerability.id,
                    "package": vulnerability.package,
                }
            )

    return results


def check_high_cvss(vulnerabilities):
    results = []

    for vulnerability in vulnerabilities:
        intelligence = vulnerability.intelligence

        if intelligence is None or intelligence.cvss is None:
            continue

        if intelligence.cvss.score >= 7.0:
            results.append(
                {
                    "vulnerability_id": vulnerability.id,
                    "score": intelligence.cvss.score,
                }
            )

    return results


def check_high_epss(vulnerabilities):
    results = []

    for vulnerability in vulnerabilities:
        intelligence = vulnerability.intelligence

        if intelligence is None or intelligence.epss is None:
            continue

        if intelligence.epss.score >= 0.5:
            results.append(
                {
                    "vulnerability_id": vulnerability.id,
                    "score": intelligence.epss.score,
                    "percentile": intelligence.epss.percentile,
                }
            )

    return results


def check_metadata_completeness(vulnerabilities):
    results = []

    for vulnerability in vulnerabilities:
        missing = []

        if not vulnerability.package:
            missing.append("package")

        if not vulnerability.installed_version:
            missing.append("installed_version")

        if missing:
            results.append(
                {
                    "vulnerability_id": vulnerability.id,
                    "missing": missing,
                }
            )

    return results
