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
    assert previous["security_score"] == 90
    assert previous["image"] == "pihole/pihole:latest"


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
