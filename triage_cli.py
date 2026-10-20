"""Purple Team analyst CLI for incident review and persistent triage."""

import json
from pathlib import Path
from response import create_triage_record, save_response_record

INCIDENT_FILE = Path(__file__).resolve().parent / "incidents.json"

RESPONSE_FILE = Path(__file__).resolve().parent / "response_records.json"

def load_incidents(file_path):
    """Load and validate the incident list structure."""
    with Path(file_path).open("r", encoding="utf-8") as file:
        incidents = json.load(file)

    if not isinstance(incidents, list):
        raise ValueError("Incident file must contain a JSON list")

    for index, incident in enumerate(incidents, start=1):
        if not isinstance(incident, dict):
            raise ValueError(
                f"Incident #{index} must be a JSON object"
            )

    return incidents


def list_incidents(incidents):
    """Display a numbered, read-only incident summary."""
    print("\nPURPLE TEAM — INCIDENT TRIAGE")
    print("=" * 40)

    if not incidents:
        print("No incidents available.")
        return

    for number, incident in enumerate(incidents, start=1):
        print(f"\nIncident #{number}")
        print(f"Severity: {incident.get('severity', 'UNKNOWN')}")
        print(f"Title: {incident.get('title', 'UNKNOWN')}")
        print(f"Source: {incident.get('source_ip', 'UNKNOWN')}")
        print(f"Target: {incident.get('target_ip', 'UNKNOWN')}")
        print(f"Trigger Time: {incident.get('trigger_time', 'UNKNOWN')}")
        print(f"Backdoor Time: {incident.get('backdoor_time', 'UNKNOWN')}")

    print(f"\nTotal incidents: {len(incidents)}")


def select_incident(incidents):
    """Prompt the analyst to select a valid incident."""
    if not incidents:
        print("No incidents available for selection.")
        return None

    choice = input(
        f"\nSelect incident (1-{len(incidents)}): "
    ).strip()

    if not choice.isdecimal():
        print("Invalid selection: enter a whole number.")
        return None

    number = int(choice)

    if not 1 <= number <= len(incidents):
        print("Invalid selection: incident number out of range.")
        return None

    selected = incidents[number - 1]

    print(f"\nSelected Incident #{number}")
    print(f"Severity: {selected.get('severity', 'UNKNOWN')}")
    print(f"Source: {selected.get('source_ip', 'UNKNOWN')}")
    print(f"Target: {selected.get('target_ip', 'UNKNOWN')}")
    print(f"Trigger Time: {selected.get('trigger_time', 'UNKNOWN')}")
    print(f"Backdoor Time: {selected.get('backdoor_time', 'UNKNOWN')}")

    return selected



def collect_analyst_details():
    """Collect analyst information without saving any records."""
    print("\nANALYST TRIAGE DETAILS")
    print("=" * 40)

    details = {}

    for field_name, prompt in (
        ("analyst", "Analyst name: "),
        ("decision", "Analyst decision: "),
        ("reason", "Reason / justification: "),
    ):
        value = input(prompt).strip()

        if not value:
            print(f"Invalid input: {field_name} cannot be empty.")
            return None

        details[field_name] = value

    return details



def build_triage_record(incident, details):
    """Build an unapproved triage record using the response engine."""
    return create_triage_record(
        incident,
        details["analyst"],
        details["decision"],
        details["reason"],
    )


def main():
    """Create and persist an unapproved analyst triage record."""
    incidents = load_incidents(INCIDENT_FILE)
    list_incidents(incidents)

    selected_incident = select_incident(incidents)

    if selected_incident is None:
        return

    details = collect_analyst_details()

    if details is None:
        return

    record = build_triage_record(selected_incident, details)

    try:
        save_response_record(RESPONSE_FILE, record)
    except (ValueError, OSError) as exc:
        print(f"\nTRIAGE RECORD NOT SAVED: {exc}")
        return

    print("\nTRIAGE RECORD SAVED")
    print("=" * 40)
    print(f"Incident ID: {record['incident_id']}")
    print(f"Status: {record['status']}")
    print(f"Analyst: {record['analyst']}")
    print(f"Decision: {record['decision']}")
    print(f"Reason: {record['reason']}")
    print(f"Approved: {record['approved']}")
    print("\nRecord saved to disk.")






if __name__ == "__main__":
    main()
