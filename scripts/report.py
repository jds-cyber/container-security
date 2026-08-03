#!/usr/bin/env python3

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from lib.reporting import generate_report

if len(sys.argv) != 3:
    print(
        "Usage: report.py summary.json output.html"
    )
    sys.exit(1)

with open(sys.argv[1]) as f:
    summary = json.load(f)

generate_report(
    summary,
    sys.argv[2],
    image_name="pywinrm-ansible:dev"
)

print(
    f"Report generated: {sys.argv[2]}"
)
