
"""Automated tests for the Purple Team analyst CLI."""

from unittest.mock import patch

from triage_cli import (
    select_incident,
    collect_analyst_details,
    build_triage_record,
)

import json
import triage_cli

def sample_incidents():
    """Create isolated test incidents without using live evidence."""
    return [
        {
            "severity": "HIGH",
            "source_ip": "192.168.139.128",
            "target_ip": "192.168.139.129",
            "trigger_time": "2026-10-09T12:49:21-05:00",
            "backdoor_time": "2026-10-09T12:49:23-05:00",
        }
    ]


def test_select_valid_incident(capsys):
    """A valid selection returns the correct incident."""
    incidents = sample_incidents()

    with patch("builtins.input", return_value="1"):
        selected = select_incident(incidents)

    assert selected == incidents[0]

    output = capsys.readouterr().out
    assert "Selected Incident #1" in output


def test_reject_out_of_range_selection(capsys):
    """An unavailable incident number is rejected."""
    incidents = sample_incidents()

    with patch("builtins.input", return_value="2"):
        selected = select_incident(incidents)

    assert selected is None

    output = capsys.readouterr().out
    assert "incident number out of range" in output


def test_reject_nonnumeric_selection(capsys):
    """Nonnumeric input is rejected safely."""
    incidents = sample_incidents()

    with patch("builtins.input", return_value="abc"):
        selected = select_incident(incidents)

    assert selected is None

    output = capsys.readouterr().out
    assert "enter a whole number" in output


def test_empty_incident_list(capsys):
    """An empty incident list does not prompt for input."""
    with patch("builtins.input") as mock_input:
        selected = select_incident([])

    assert selected is None
    mock_input.assert_not_called()

    output = capsys.readouterr().out
    assert "No incidents available for selection." in output



def test_collect_valid_analyst_details():
    """Valid analyst information is collected correctly."""
    with patch(
        "builtins.input",
        side_effect=[
            "Blue Team Analyst",
            "Investigate",
            "Correlated trigger and backdoor alerts",
        ],
    ):
        details = collect_analyst_details()

    assert details == {
        "analyst": "Blue Team Analyst",
        "decision": "Investigate",
        "reason": "Correlated trigger and backdoor alerts",
    }


def test_reject_empty_analyst_name(capsys):
    """An empty analyst name is rejected."""
    with patch("builtins.input", return_value=""):
        details = collect_analyst_details()

    assert details is None
    assert "analyst cannot be empty" in capsys.readouterr().out


def test_reject_whitespace_decision(capsys):
    """A whitespace-only decision is rejected."""
    with patch(
        "builtins.input",
        side_effect=["Blue Team Analyst", "   "],
    ):
        details = collect_analyst_details()

    assert details is None
    assert "decision cannot be empty" in capsys.readouterr().out


def test_reject_whitespace_reason(capsys):
    """A whitespace-only justification is rejected."""
    with patch(
        "builtins.input",
        side_effect=["Blue Team Analyst", "Investigate", "   "],
    ):
        details = collect_analyst_details()

    assert details is None
    assert "reason cannot be empty" in capsys.readouterr().out


def sample_triage_incident():
    """Provide synthetic incident evidence for triage tests."""
    return {
        "source_ip": "192.0.2.10",
        "target_ip": "192.0.2.20",
        "trigger_sid": 1000001,
        "backdoor_sid": 1000002,
        "trigger_time": "2026-10-09T12:49:21-05:00",
        "backdoor_time": "2026-10-09T12:49:23-05:00",
    }


def test_build_valid_triage_record():
    """Build a TRIAGED record without granting approval."""
    incident = sample_triage_incident()
    details = {
        "analyst": "Blue Team Analyst",
        "decision": "Investigate",
        "reason": "Correlated trigger and backdoor alerts",
    }

    record = build_triage_record(incident, details)

    assert record["status"] == "TRIAGED"
    assert record["approved"] is False
    assert record["analyst"] == "Blue Team Analyst"
    assert record["decision"] == "Investigate"
    assert record["reason"] == "Correlated trigger and backdoor alerts"

    assert len(record["incident_id"]) == 64
    assert all(
        character in "0123456789abcdef"
        for character in record["incident_id"]
    )

    # Same evidence must generate the same incident ID.
    second_record = build_triage_record(incident, details)
    assert record["incident_id"] == second_record["incident_id"]


def test_build_triage_rejects_empty_analyst():
    """Reject records that lack analyst identification."""
    import pytest

    incident = sample_triage_incident()
    details = {
        "analyst": "   ",
        "decision": "Investigate",
        "reason": "Correlated alerts",
    }

    with pytest.raises(ValueError, match="analyst"):
        build_triage_record(incident, details)


def test_build_triage_rejects_empty_reason():
    """Reject triage decisions without justification."""
    import pytest

    incident = sample_triage_incident()
    details = {
        "analyst": "Blue Team Analyst",
        "decision": "Investigate",
        "reason": "   ",
    }

    with pytest.raises(ValueError, match="reason"):
        build_triage_record(incident, details)


def prepare_workflow_test(tmp_path, monkeypatch):
    """Create isolated incident evidence for workflow testing."""
    incident_file = tmp_path / "incidents.json"

    incident_file.write_text(
        json.dumps([sample_triage_incident()]),
        encoding="utf-8",
    )

    monkeypatch.setattr(
        triage_cli, "INCIDENT_FILE", incident_file
    )

    return incident_file


def test_main_saves_unapproved_record_and_preserves_evidence(
    tmp_path, monkeypatch, capsys
):
    """Persist triage without changing original incident evidence."""
    incident_file = prepare_workflow_test(
        tmp_path, monkeypatch
    )

    response_file = tmp_path / "response_records.json"

    monkeypatch.setattr(
        triage_cli, "RESPONSE_FILE",
        response_file, raising=False
    )

    original_evidence = incident_file.read_bytes()

    with patch(
        "builtins.input",
        side_effect=[
            "1",
            "Blue Team Analyst",
            "Investigate",
            "Correlated trigger and backdoor alerts",
        ],
    ):
        triage_cli.main()

    output = capsys.readouterr().out

    assert "TRIAGE RECORD SAVED" in output
    assert "Status: TRIAGED" in output
    assert "Approved: False" in output

    assert incident_file.read_bytes() == original_evidence

    records = json.loads(
        response_file.read_text(encoding="utf-8")
    )

    assert len(records) == 1
    assert records[0]["status"] == "TRIAGED"
    assert records[0]["approved"] is False

def test_main_stops_on_invalid_selection(
    tmp_path, monkeypatch, capsys
):
    """Invalid selection prevents analyst data collection."""
    prepare_workflow_test(tmp_path, monkeypatch)

    with patch(
        "builtins.input", return_value="99"
    ) as mock_input:
        triage_cli.main()

    output = capsys.readouterr().out

    assert "incident number out of range" in output
    assert "ANALYST TRIAGE DETAILS" not in output
    assert "TRIAGE RECORD CREATED IN MEMORY" not in output
    assert mock_input.call_count == 1
    assert not (tmp_path / "response_records.json").exists()


def test_main_stops_on_invalid_analyst_details(
    tmp_path, monkeypatch, capsys
):
    """Invalid analyst data prevents record construction."""
    prepare_workflow_test(tmp_path, monkeypatch)

    with patch(
        "builtins.input",
        side_effect=["1", "   "],
    ) as mock_input:
        triage_cli.main()

    output = capsys.readouterr().out

    assert "analyst cannot be empty" in output
    assert "TRIAGE RECORD CREATED IN MEMORY" not in output
    assert mock_input.call_count == 2
    assert not (tmp_path / "response_records.json").exists()



def test_main_persists_unapproved_record(
    tmp_path, monkeypatch
):
    """Persist triage without modifying original evidence."""
    incident_file = prepare_workflow_test(
        tmp_path, monkeypatch
    )

    response_file = tmp_path / "response_records.json"

    monkeypatch.setattr(
        triage_cli, "RESPONSE_FILE",
        response_file, raising=False
    )

    original_evidence = incident_file.read_bytes()

    with patch(
        "builtins.input",
        side_effect=[
            "1",
            "Blue Team Analyst",
            "Investigate",
            "Correlated trigger and backdoor alerts",
        ],
    ):
        triage_cli.main()

    assert incident_file.read_bytes() == original_evidence

    records = json.loads(
        response_file.read_text(encoding="utf-8")
    )

    assert len(records) == 1
    assert records[0]["status"] == "TRIAGED"
    assert records[0]["approved"] is False
    assert records[0]["analyst"] == "Blue Team Analyst"

def test_main_rejects_duplicate_without_changing_history(
    tmp_path, monkeypatch, capsys
):
    """Duplicate triage must not change saved response history."""
    prepare_workflow_test(tmp_path, monkeypatch)

    response_file = tmp_path / "response_records.json"

    monkeypatch.setattr(
        triage_cli, "RESPONSE_FILE",
        response_file
    )

    analyst_answers = [
        "1",
        "Blue Team Analyst",
        "Investigate",
        "Correlated trigger and backdoor alerts",
    ]

    with patch("builtins.input", side_effect=analyst_answers):
        triage_cli.main()

    original_history = response_file.read_bytes()
    capsys.readouterr()

    with patch("builtins.input", side_effect=analyst_answers):
        triage_cli.main()

    output = capsys.readouterr().out

    assert "TRIAGE RECORD NOT SAVED" in output
    assert "Response record already exists" in output
    assert "TRIAGE RECORD SAVED" not in output

    assert response_file.read_bytes() == original_history

    records = json.loads(
        response_file.read_text(encoding="utf-8")
    )

    assert len(records) == 1
    assert records[0]["approved"] is False

def test_main_rejects_corrupted_history_without_overwriting(
    tmp_path, monkeypatch, capsys
):
    """Corrupted history must remain untouched after a failed save."""
    incident_file = prepare_workflow_test(
        tmp_path, monkeypatch
    )

    response_file = tmp_path / "response_records.json"

    monkeypatch.setattr(
        triage_cli, "RESPONSE_FILE",
        response_file
    )

    response_file.write_text(
        '{"corrupted": ',
        encoding="utf-8"
    )

    original_history = response_file.read_bytes()
    original_evidence = incident_file.read_bytes()

    with patch(
        "builtins.input",
        side_effect=[
            "1",
            "Blue Team Analyst",
            "Investigate",
            "Correlated trigger and backdoor alerts",
        ],
    ):
        triage_cli.main()

    output = capsys.readouterr().out

    assert "TRIAGE RECORD NOT SAVED" in output
    assert "TRIAGE RECORD SAVED" not in output

    assert response_file.read_bytes() == original_history
    assert incident_file.read_bytes() == original_evidence

def test_main_handles_storage_failure_without_false_success(
    tmp_path, monkeypatch, capsys
):
    """Storage failure must never be reported as a successful save."""
    incident_file = prepare_workflow_test(
        tmp_path, monkeypatch
    )

    response_file = tmp_path / "response_records.json"

    monkeypatch.setattr(
        triage_cli, "RESPONSE_FILE",
        response_file
    )

    original_evidence = incident_file.read_bytes()

    def simulated_save_failure(file_path, record):
        raise OSError("Simulated storage failure")

    monkeypatch.setattr(
        triage_cli,
        "save_response_record",
        simulated_save_failure
    )

    with patch(
        "builtins.input",
        side_effect=[
            "1",
            "Blue Team Analyst",
            "Investigate",
            "Correlated trigger and backdoor alerts",
        ],
    ):
        triage_cli.main()

    output = capsys.readouterr().out

    assert "TRIAGE RECORD NOT SAVED" in output
    assert "Simulated storage failure" in output
    assert "TRIAGE RECORD SAVED" not in output

    assert incident_file.read_bytes() == original_evidence
    assert not response_file.exists()
