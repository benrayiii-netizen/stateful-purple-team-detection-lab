
"""Automated tests for the Purple Team analyst CLI."""

from unittest.mock import patch

from triage_cli import select_incident


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
