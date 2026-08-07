from pathlib import Path
from datetime import datetime
import json


def save_history(summary, directory="reports/history"):
    """
    Save a timestamped copy of the security summary.
    """

    history_dir = Path(directory)
    history_dir.mkdir(parents=True, exist_ok=True)

    filename = (datetime.now().strftime("%Y-%m-%d-%H%M%S.json"))

    output = history_dir / filename
    output.write_text(json.dumps(summary, indent=4))

    return output
