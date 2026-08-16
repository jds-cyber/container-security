from lib.history import save_history, load_history, previous_scan
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


def test_previous_scan_same_image(tmp_path):
    summary = {
        "security_score": 90,
        "vulnerability_ids": ["CVE-2021-44228"]
    }

    save_history(summary, tmp_path, image_name="pihole/pihole:latest")
    summary["security_score"] = 95

    save_history(summary, tmp_path, image_name="pihole/pihole:latest")
    previous = previous_scan(tmp_path, "pihole/pihole:latest")

    assert previous is not None
    assert previous["security_score"] == 95
    assert previous["image"] == "pihole/pihole:latest"


def test_previous_scan_ignores_other_images(tmp_path):

    save_history(
        {"security_score": 70},
        tmp_path,
        image_name="other-image:latest",
    )

    save_history(
        {"security_score": 80},
        tmp_path,
        image_name="test-image:latest",
    )

    save_history(
        {"security_score": 90},
        tmp_path,
        image_name="test-image:latest",
    )

    previous = previous_scan(
        tmp_path,
        "test-image:latest",
    )

    assert previous is not None
    assert previous["security_score"] == 90
    assert previous["image"] == "test-image:latest"


def test_history_contains_scan_metadata(tmp_path):
    summary = {
        "security_score": 90
    }

    save_history(
        summary,
        tmp_path,
        image_name="test-image:latest",
    )

    history = load_history(tmp_path)

    assert history[0]["image"] == "test-image:latest"
    assert "scan_timestamp" in history[0]
    assert history[0]["scan_timestamp"]


def test_history_contains_scan_id(tmp_path):
    summary = {
        "security_score": 90
    }

    output = save_history(
        summary,
        tmp_path,
        image_name="test-image:latest",
    )

    data = json.loads(output.read_text())

    assert "scan_id" in data
    assert data["scan_id"] in output.name


def test_previous_scan_returns_none_when_no_history(tmp_path):

    previous = previous_scan(
        tmp_path,
        "test-image:latest",
    )

    assert previous is None


def test_previous_scan_returns_latest_with_one_scan(tmp_path):

    save_history(
        {"security_score": 90},
        tmp_path,
        image_name="test-image:latest",
    )

    previous = previous_scan(
        tmp_path,
        "test-image:latest",
    )

    assert previous is not None
    assert previous["security_score"] == 90


def test_load_history_empty_directory(tmp_path):

    history = load_history(tmp_path)

    assert history == []


def test_load_history_missing_directory(tmp_path):

    history_dir = tmp_path / "missing"
    history = load_history(history_dir)

    assert history == []


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


def test_load_history_uses_filename_for_scan_identifier(tmp_path):

    file = tmp_path / "2026-08-13_120000-000000.json"

    file.write_text(
        json.dumps(
            {
                "scan": "incorrect-scan-id",
                "image": "test-image:latest",
                "scan_id": "incorrect-scan-id",
                "scan_timestamp": "2026-08-13T12:00:00",
                "security_score": 90,
            }
        )
    )

    try:
        load_history(tmp_path)
        assert False, "Expected ValueError"
    except ValueError:
        pass


def test_load_history_rejects_missing_history_metadata(tmp_path):

    file = tmp_path / "2026-08-13_120000-000000.json"

    file.write_text(
        json.dumps(
            {
                "security_score": 90,
            }
        )
    )

    try:
        load_history(tmp_path)
        assert False, "Expected ValueError"
    except ValueError:
        pass


def test_load_history_rejects_invalid_image_type(tmp_path):
    file = tmp_path / "2026-08-13_120000-000000.json"

    file.write_text(
        json.dumps(
            {
                "image": 12345,
                "scan_id": "2026-08-13_120000-000000",
                "scan_timestamp": "2026-08-13T12:00:00",
                "security_score": 90,
            }
        )
    )

    try:
        load_history(tmp_path)
        assert False, "Expected ValueError"
    except ValueError:
        pass


def test_load_history_rejects_empty_image(tmp_path):
    file = tmp_path / "2026-08-13_120000-000000.json"

    file.write_text(
        json.dumps(
            {
                "image": "",
                "scan_id": "2026-08-13_120000-000000",
                "scan_timestamp": "2026-08-13T12:00:00",
                "security_score": 90,
            }
        )
    )

    try:
        load_history(tmp_path)
        assert False, "Expected ValueError"
    except ValueError:
        pass


def test_load_history_rejects_scan_id_mismatch(tmp_path):
    file = tmp_path / "2026-08-13_120000-000000.json"

    file.write_text(
        json.dumps(
            {
                "image": "test-image:latest",
                "scan_id": "different-scan-id",
                "scan_timestamp": "2026-08-13T12:00:00",
                "security_score": 90,
            }
        )
    )

    try:
        load_history(tmp_path)
        assert False, "Expected ValueError"
    except ValueError:
        pass


def test_load_history_rejects_invalid_scan_timestamp(tmp_path):
    file = tmp_path / "2026-08-13_120000-000000.json"

    file.write_text(
        json.dumps(
            {
                "image": "test-image:latest",
                "scan_id": "2026-08-13_120000-000000",
                "scan_timestamp": "not-a-timestamp",
                "security_score": 90,
            }
        )
    )

    try:
        load_history(tmp_path)
        assert False, "Expected ValueError"
    except ValueError:
        pass


def test_load_history_rejects_invalid_security_score(tmp_path):
    file = tmp_path / "2026-08-13_120000-000000.json"

    file.write_text(
        json.dumps(
            {
                "image": "test-image:latest",
                "scan_id": "2026-08-13_120000-000000",
                "scan_timestamp": "2026-08-13T12:00:00",
                "security_score": "90",
            }
        )
    )

    try:
        load_history(tmp_path)
        assert False, "Expected ValueError"
    except ValueError:
        pass


def test_load_history_rejects_invalid_severity_count(tmp_path):
    file = tmp_path / "2026-08-13_120000-000000.json"

    file.write_text(
        json.dumps(
            {
                "image": "test-image:latest",
                "scan_id": "2026-08-13_120000-000000",
                "scan_timestamp": "2026-08-13T12:00:00",
                "critical": -1,
                "security_score": 90,
            }
        )
    )

    try:
        load_history(tmp_path)
        assert False, "Expected ValueError"
    except ValueError:
        pass


def test_load_history_rejects_invalid_vulnerability_ids(tmp_path):
    file = tmp_path / "2026-08-13_120000-000000.json"

    file.write_text(
        json.dumps(
            {
                "image": "test-image:latest",
                "scan_id": "2026-08-13_120000-000000",
                "scan_timestamp": "2026-08-13T12:00:00",
                "vulnerability_ids": [
                    "CVE-2026-1234",
                    None,
                ],
                "security_score": 90,
            }
        )
    )

    try:
        load_history(tmp_path)
        assert False, "Expected ValueError"
    except ValueError:
        pass
