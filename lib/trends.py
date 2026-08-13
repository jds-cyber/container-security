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

        if not isinstance(summary, dict):
            raise ValueError(
                f"Invalid history summary structure: {report_file}"
            )

        history.append(
            {
                "scan": report_file.stem,
                **summary
            }
        )

    return history
