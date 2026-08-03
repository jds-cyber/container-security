#!/usr/bin/env python3

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from lib.security import summarize, security_score
from lib.policy import load_policy, evaluate

if len(sys.argv) != 2:
    print("Usage: summarize.py report.json")
    sys.exit(1)

with open(sys.argv[1]) as f:
    report = json.load(f)

summary = summarize(report["matches"])
summary["Score"] = security_score(summary)

policy = load_policy(
    "config/security_policy.yml"
)

failures = evaluate(summary, policy)

if failures:
    print("SECURITY POLICY FAILED")

    for failure in failures:
        print(f"- {failure}")

    exit(1)

else:
    print("SECURITY POLICY PASSED")

print(json.dumps(summary, indent=4))
