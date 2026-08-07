from lib.history import save_history, load_history
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


def test_history_save_and_load(tmp_path):

    summary = {
        "security_score": 90,
        "vulnerability_ids": ["CVE-2021-44228"]
    }

    save_history(summary, tmp_path)

    history = load_history(tmp_path)

    assert len(history) == 1
    assert history[0]["security_score"] == 90
