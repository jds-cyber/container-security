#!/usr/bin/env python3
import json
import sys
import argparse
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

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

parser = argparse.ArgumentParser(description="Summarize container security scan results")

parser.add_argument("report", help="Path to scanner report")
parser.add_argument(
    "--scanner",
    required=True,
    help="Scanner name"
)
parser.add_argument(
    "--policy",
    default="config/security_policy.yml",
    help="Path to security policy YAML")

args = parser.parse_args()

registry = create_default_registry()

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

except FileNotFoundError:
    print(f"Report not found: {args.report}")
    sys.exit(1)

except ValueError as exc:
    print(str(exc), file=sys.stderr)
    sys.exit(1)

summary = summarize(vulnerabilities=vulnerabilities)

summary["weighted_risk"] = weighted_risk(summary)
summary["security_score"] = security_score(summary)
summary["grade"] = security_grade(summary["security_score"])
summary["risk_level"] = risk_level(summary["security_score"])

try:
    policy = load_policy(args.policy)
except ValueError as exc:
    print(str(exc), file=sys.stderr)
    sys.exit(1)

failures = evaluate(summary, policy)

summary["policy_failures"] = failures
summary["policy_passed"] = not failures

if failures:
    print("***SECURITY POLICY FAILED***\n", file=sys.stderr)

    for failure in failures:
        print(f"- {failure}", file=sys.stderr)

else:
    print("***SECURITY POLICY PASSED***\n", file=sys.stderr)

print(json.dumps(summary, indent=4))

if failures:
    sys.exit(1)
