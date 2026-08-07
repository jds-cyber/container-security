import json

from lib.trends import load_history


def test_load_history(tmp_path):

    report1 = { "security_score": 80 }
    report2 = { "security_score": 90 }

    (tmp_path / "1.json").write_text(json.dumps(report1))
    (tmp_path / "2.json").write_text(json.dumps(report2))

    history = load_history(tmp_path)

    assert len(history) == 2
    assert history[0]["security_score"] == 80
    assert history[1]["security_score"] == 90
