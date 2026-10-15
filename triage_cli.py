
"""Read-only incident listing for the Purple Team analyst CLI."""

import json
from pathlib import Path


INCIDENT_FILE = Path(__file__).resolve().parent / "incidents.json"


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





def main():
    """Display existing incidents without modifying evidence."""
    incidents = load_incidents(INCIDENT_FILE)
    list_incidents(incidents)
    select_incident(incidents)

if __name__ == "__main__":
    main()
