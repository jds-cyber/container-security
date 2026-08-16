import json
from pathlib import Path
from datetime import datetime


SEVERITY_FIELDS = (
    "critical",
    "high",
    "medium",
    "low",
    "negligible",
    "unknown",
)

def _validate_history_summary(summary, file):
    """
    Validate the structure and types of a historical security summary.
    """
    required_metadata = {
        "image",
        "scan_id",
        "scan_timestamp",
    }

    if not required_metadata.issubset(summary):
        raise ValueError(
            f"Invalid history metadata: {file}"
        )

    image = summary["image"]
    scan_id = summary["scan_id"]
    scan_timestamp = summary["scan_timestamp"]

    if not isinstance(image, str) or not image.strip():
        raise ValueError(
            f"Invalid history image: {file}"
        )

    if not isinstance(scan_id, str) or not scan_id.strip():
        raise ValueError(
            f"Invalid history scan_id: {file}"
        )

    if scan_id != file.stem:
        raise ValueError(
            f"History scan_id does not match filename: {file}"
        )

    if not isinstance(scan_timestamp, str) or not scan_timestamp.strip():
        raise ValueError(
            f"Invalid history scan_timestamp: {file}"
        )

    try:
        datetime.fromisoformat(scan_timestamp)
    except ValueError:
        raise ValueError(
            f"Invalid history scan_timestamp: {file}"
        )

    if "security_score" in summary:
        score = summary["security_score"]

        if (
            isinstance(score, bool)
            or not isinstance(score, (int, float))
            or score < 0
            or score > 100
        ):
            raise ValueError(
                f"Invalid history security_score: {file}"
            )

    for severity in SEVERITY_FIELDS:
        if severity not in summary:
            continue

        count = summary[severity]

        if (
            isinstance(count, bool)
            or not isinstance(count, int)
            or count < 0
        ):
            raise ValueError(
                f"Invalid history {severity} count: {file}"
            )

    if "vulnerability_ids" in summary:
        vulnerability_ids = summary["vulnerability_ids"]

        if not isinstance(vulnerability_ids, list):
            raise ValueError(
                f"Invalid history vulnerability_ids: {file}"
            )

        for vulnerability_id in vulnerability_ids:
            if (
                not isinstance(vulnerability_id, str)
                or not vulnerability_id.strip()
            ):
                raise ValueError(
                    f"Invalid history vulnerability_ids: {file}"
                )


def save_history(summary, directory="reports/history", image_name="Unknown"):
    """
    Save a timestamped copy of the security summary.
    """
    path = Path(directory)
    path.mkdir(parents=True, exist_ok=True)

    scan_time = datetime.now()
    scan_id = scan_time.strftime("%Y-%m-%d_%H%M%S-%f")

    filename = scan_id + ".json"

    history_summary = dict(summary)
    history_summary["image"] = image_name
    history_summary["scan_id"] = scan_id
    history_summary["scan_timestamp"] = scan_time.isoformat()

    output = path / filename
    output.write_text(json.dumps(history_summary, indent=4))

    return output


def load_history(history_dir):
    """
    Load previous scan summaries.

    Include scan identifier from filename for trend reporting.
    """
    history_path = Path(history_dir)

    summaries = []

    for file in sorted(history_path.glob("*.json")):
        with open(file, "r") as f:
            summary = json.load(f)

        if not isinstance(summary, dict):
            raise ValueError(
                f"Invalid history summary structure: {file}"
            )

        _validate_history_summary(summary, file)

        summaries.append(
            {
                **summary,
                "scan": file.stem,
            }
        )

    return summaries


def previous_scan(history_dir, image_name):
    """
    Return the most recent previous scan for the specified image.
    """
    history = load_history(history_dir)

    matching = [
        summary
        for summary in history
        if summary.get("image") == image_name
    ]

    if not matching:
        return None

    return matching[-1]
