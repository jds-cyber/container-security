from pathlib import Path
import json


def load_history(directory="reports/history"):
    """
    Load all historical security summaries.

    Include scan identifier from filename for trend reporting.
    """
    history = []

    for report_file in sorted(Path(directory).glob("*.json")):

        summary = json.loads(report_file.read_text())

        history.append(
            {
                "scan": report_file.stem,
                **summary
            }
        )

    return history
