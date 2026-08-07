import json
from pathlib import Path
from datetime import datetime


def save_history(summary, directory="reports/history"):
    """
    Save a timestamped copy of the security summary.
    """
    path = Path(directory)
    path.mkdir(parents=True, exist_ok=True)

    filename = (datetime.now().strftime("%Y-%m-%d_%H%M%S") + ".json")

    output = path / filename
    output.write_text(json.dumps(summary, indent=4))

    return output


def load_history(history_dir):
    """
    Load previous scan summaries.
    """

    history_path = Path(history_dir)

    summaries = []

    for file in sorted(history_path.glob("*.json")):
        with open(file, "r") as f:
            summaries.append(json.load(f))

    return summaries


def previous_scan(history_dir):
    """
    Return the most recent previous scan.
    """

    history = load_history(history_dir)

    if len(history) < 2:
        return None

    return history[-2]
