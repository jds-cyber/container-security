import json
from pathlib import Path
from datetime import datetime


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

        required_metadata = {
            "image",
            "scan_id",
            "scan_timestamp",
        }

        if not required_metadata.issubset(summary):
            raise ValueError(
                f"Invalid history metadata: {file}"
            )

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
