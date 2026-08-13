#!/usr/bin/env python3
import json, sys, os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from lib.reporting import generate_report
from lib.history import previous_scan, save_history


if len(sys.argv) != 4:
    print("Usage: report.py summary.json output.html image")
    sys.exit(1)

image_name = sys.argv[3]

if not image_name.strip():
    print("Image name cannot be empty")
    sys.exit(1)

summary_path = Path(sys.argv[1])

try:
    with open(summary_path) as f:
        summary = json.load(f)

except FileNotFoundError:
    print(f"Summary file not found: {summary_path}")
    sys.exit(1)

except json.JSONDecodeError:
    print("Invalid JSON summary")
    sys.exit(1)

required_fields = {
    "findings",
    "unique_vulnerabilities",
    "critical",
    "high",
    "medium",
    "low",
    "negligible",
    "unknown",
    "weighted_risk",
    "security_score",
    "grade",
}

if not isinstance(summary, dict) or not required_fields.issubset(summary):
    print("Invalid summary structure")
    sys.exit(1)

history_dir = os.environ.get(
    "CONTAINER_SECURITY_HISTORY",
    "reports/history")

previous = previous_scan(
    history_dir,
    image_name
)

history_output = save_history(
    summary,
    history_dir,
    image_name=image_name
)

with open(history_output) as f:
    history_record = json.load(f)

generate_report(
    summary,
    sys.argv[2],
    image_name=image_name,
    previous_summary=previous,
    scan_id=history_record["scan_id"],
    scan_timestamp=history_record["scan_timestamp"]
)

print(f"Report generated: {sys.argv[2]}")
