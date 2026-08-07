from lib.history import save_history
import json


def test_save_history(tmp_path):
    summary = {
        "critical": 1,
        "security_score": 90
    }

    output = save_history(summary, directory=tmp_path)

    assert output.exists()

    data = json.loads(output.read_text())

    assert data["critical"] == 1
    assert data["security_score"] == 90
