#!/usr/bin/env python3

import json
import sys
import argparse
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from lib.security import (
    summarize,
    weighted_risk,
    security_score,
    security_grade,
    risk_level,
)
from lib.policy import load_policy, evaluate

parser = argparse.ArgumentParser(description="Summarize container security scan results")

parser.add_argument("report", help="Path to Grype JSON report")
parser.add_argument(
    "--policy",
    default="config/security_policy.yml",
    help="Path to security policy YAML")

args = parser.parse_args()

try:
    with open(args.report) as f:
        report = json.load(f)

except FileNotFoundError:
    print(f"Report not found: {args.report}")
    sys.exit(1)

except json.JSONDecodeError:
    print("Invalid JSON report")
    sys.exit(1)

summary = summarize(report["matches"])

summary["weighted_risk"] = weighted_risk(summary)
summary["security_score"] = security_score(summary)
summary["grade"] = security_grade(summary["security_score"])
summary["risk_level"] = risk_level(summary["security_score"])

policy = load_policy(args.policy)

failures = evaluate(summary, policy)

if failures:
    print("***SECURITY POLICY FAILED***\n", file=sys.stderr)

    for failure in failures:
        print(f"- {failure}", file=sys.stderr)

else:
    print("***SECURITY POLICY PASSED***\n", file=sys.stderr)

print(json.dumps(summary, indent=4))

if failures:
    sys.exit(1)
