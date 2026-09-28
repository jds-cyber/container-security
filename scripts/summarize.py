#!/usr/bin/env python3
import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from lib.intelligence import (
    enrich_vulnerabilities,
    RecordIntelligenceProvider,
    OSVIntelligenceProvider,
    EPSSIntelligenceProvider,
)
from lib.policy import load_policy, evaluate
from lib.security import (
    summarize,
    weighted_risk,
    security_score,
    security_grade,
    risk_level,
)
from lib.scanner import (
    create_default_registry,
    load_scan_report,
    parse_scan,
)
from lib.sbom import (
    load_sbom,
    correlate_vulnerabilities,
)


def load_intelligence_records(path):
    """
    Load vulnerability intelligence records from a JSON file.
    """

    try:
        with open(path) as f:
            records = json.load(f)

    except FileNotFoundError:
        raise FileNotFoundError(
            f"Intelligence file not found: {path}"
        )

    except json.JSONDecodeError as exc:
        raise ValueError(
            "Invalid intelligence JSON"
        ) from exc

    if not isinstance(records, dict):
        raise ValueError(
            "Invalid intelligence records structure"
        )

    return records


def main():
    parser = argparse.ArgumentParser(
        description="Summarize container security scan results",
    )

    parser.add_argument(
        "report",
        help="Path to scanner report",
    )

    parser.add_argument(
        "--scanner",
        required=True,
        help="Scanner name",
    )

    parser.add_argument(
        "--sbom",
        help="Path to Syft SBOM JSON",
    )

    parser.add_argument(
        "--policy",
        default="config/security_policy.yml",
        help="Path to security policy YAML",
    )

    parser.add_argument(
        "--intelligence",
        help="Path to vulnerability intelligence JSON",
    )

    parser.add_argument(
        "--osv",
        action="store_true",
        help="Retrieve vulnerability intelligence from OSV",
    )

    parser.add_argument(
        "--epss",
        action="store_true",
        help="Retrieve vulnerability intelligence from EPSS",
    )

    args = parser.parse_args()
    registry = create_default_registry()

    # Intelligence is optional

    intelligence_providers = []

    if args.intelligence and (args.osv or args.epss):
        parser.error(
            "--intelligence cannot be combined with "
            "--osv or --epss."
        )

    if args.intelligence:
        try:
            records = load_intelligence_records(
                Path(args.intelligence)
            )
            intelligence_providers.append(
                RecordIntelligenceProvider(
                    records=records
                )
            )

        except FileNotFoundError as exc:
            print(str(exc), file=sys.stderr)
            return 1

        except ValueError as exc:
            print(str(exc), file=sys.stderr)
            return 1

    if args.osv:
        intelligence_providers.append(
            OSVIntelligenceProvider()
        )

    if args.epss:
        intelligence_providers.append(
            EPSSIntelligenceProvider()
        )

    try:
        report = load_scan_report(
            registry,
            args.scanner,
            Path(args.report),
        )

        vulnerabilities = parse_scan(
            registry,
            args.scanner,
            report,
        )

        correlation = None

        if args.sbom:
            packages = load_sbom(
                Path(args.sbom)
            )

            correlation = correlate_vulnerabilities(
                vulnerabilities,
                packages,
            )

        if intelligence_providers:
            enrich_vulnerabilities(
                vulnerabilities,
                intelligence_providers,
            )

    except FileNotFoundError:
        print(
            f"Report not found: {args.report}",
            file=sys.stderr,
        )
        return 1

    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    summary = summarize(
        vulnerabilities=vulnerabilities,
        sbom_correlation=correlation,
    )

    summary["weighted_risk"] = weighted_risk(summary)
    summary["security_score"] = security_score(summary)
    summary["grade"] = security_grade(summary["security_score"])
    summary["risk_level"] = risk_level(summary["security_score"])

    try:
        policy = load_policy(args.policy)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    failures = evaluate(
        summary,
        policy,
    )

    summary["policy_failures"] = failures
    summary["policy_passed"] = not failures

    if failures:
        print(
            "***SECURITY POLICY FAILED***\n",
            file=sys.stderr,
        )

        for failure in failures:
            print(
                f"- {failure}",
                file=sys.stderr,
            )

    else:
        print(
            "***SECURITY POLICY PASSED***\n",
            file=sys.stderr
        )

    print(
        json.dumps(
            summary,
            indent=4,
        )
    )

    if failures:
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
