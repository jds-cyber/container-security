#!/usr/bin/env python3

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from lib.security import (
    summarize,
    weighted_risk,
    security_score,
    security_grade,
)
from lib.policy import load_policy, evaluate

if len(sys.argv) != 2:
    print("Usage: summarize.py report.json")
    sys.exit(1)

try:
    with open(sys.argv[1]) as f:
        report = json.load(f)

except FileNotFoundError:
    print(f"Report not found: {sys.argv[1]}")
    sys.exit(1)

except json.JSONDecodeError:
    print("Invalid JSON report")
    sys.exit(1)

summary = summarize(report["matches"])

summary["weighted_risk"] = weighted_risk(summary)
summary["security_score"] = security_score(summary)
summary["grade"] = security_grade(summary["security_score"])

policy = load_policy(
    "config/security_policy.yml"
)

failures = evaluate(summary, policy)

if failures:
    print("SECURITY POLICY FAILED", file=sys.stderr)

    for failure in failures:
        print(f"- {failure}", file=sys.stderr)

else:
    print("SECURITY POLICY PASSED", file=sys.stderr)

print(json.dumps(summary, indent=4))

if failures:
    sys.exit(1)
