#!/usr/bin/env python3

import json
import sys
from collections import Counter

if len(sys.argv) != 2:
    print("Usage: summarize.py <report.json>")
    sys.exit(1)

with open(sys.argv[1]) as f:
    report = json.load(f)

counts = Counter()

for match in report.get("matches", []):
    severity = (
        match.get("vulnerability", {})
        .get("severity", "Unknown")
        .capitalize()
    )
    counts[severity] += 1

order = [
    "Critical",
    "High",
    "Medium",
    "Low",
    "Negligible",
    "Unknown",
]

summary = {}

for sev in order:
    summary[sev] = counts.get(sev, 0)

print(json.dumps(summary, indent=4))
