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


def test_load_history_includes_scan_name(tmp_path):

    history_dir = tmp_path / "history"
    history_dir.mkdir()

    report = {
        "security_score": 90,
        "grade": "A"
    }

    file = history_dir / "2026-08-05_scan.json"

    file.write_text(
        json.dumps(report)
    )

    history = load_history(history_dir)

    assert len(history) == 1
    assert history[0]["scan"] == "2026-08-05_scan"
    assert history[0]["security_score"] == 90


def test_load_history_rejects_invalid_json(tmp_path):

    file = tmp_path / "broken.json"
    file.write_text("{ invalid json")

    try:
        load_history(tmp_path)
        assert False, "Expected JSONDecodeError"
    except json.JSONDecodeError:
        pass


def test_load_history_rejects_non_dict_summary(tmp_path):

    file = tmp_path / "invalid.json"
    file.write_text(
        json.dumps(["not", "a", "summary"])
    )

    try:
        load_history(tmp_path)
        assert False, "Expected ValueError"
    except ValueError:
        pass
