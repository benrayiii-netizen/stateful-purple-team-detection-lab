
import hashlib
import json


def generate_incident_id(incident):
    """Generate a stable SHA-256 identifier from incident evidence."""
    identifying_fields = {
        "source_ip": incident["source_ip"],
        "target_ip": incident["target_ip"],
        "trigger_sid": incident["trigger_sid"],
        "backdoor_sid": incident["backdoor_sid"],
        "trigger_time": incident["trigger_time"],
        "backdoor_time": incident["backdoor_time"],
    }

    canonical_data = json.dumps(
        identifying_fields,
        sort_keys=True,
        separators=(",", ":"),
    )

    return hashlib.sha256(
        canonical_data.encode("utf-8")
    ).hexdigest()


VALID_STATUSES = {
    "NEW",
    "TRIAGED",
    "CONTAINED",
    "CLOSED",
}


def validate_response_status(status):
    """Reject unsupported incident response statuses."""
    if not isinstance(status, str) or status not in VALID_STATUSES:
        raise ValueError(f"Invalid incident response status: {status!r}")

    return status



def create_triage_record(incident, analyst, decision, reason):
    """Create an unapproved analyst triage record in memory."""
    for field_name, value in {
        "analyst": analyst,
        "decision": decision,
        "reason": reason,
    }.items():
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{field_name} must be a non-empty string")

    return {
        "incident_id": generate_incident_id(incident),
        "status": validate_response_status("TRIAGED"),
        "analyst": analyst.strip(),
        "decision": decision.strip(),
        "reason": reason.strip(),
        "approved": False,
    }



from pathlib import Path


def load_response_records(file_path):
    """Load response history without modifying the source file."""
    path = Path(file_path)

    if not path.exists():
        return []

    with path.open("r", encoding="utf-8") as response_file:
        records = json.load(response_file)

    if not isinstance(records, list):
        raise ValueError("Response records must be a JSON list")

    return records



def validate_response_record(record):
    """Validate an unapproved analyst triage record."""
    if not isinstance(record, dict):
        raise ValueError("Response record must be a dictionary")

    required_fields = (
        "incident_id",
        "status",
        "analyst",
        "decision",
        "reason",
    )

    for field in required_fields:
        value = record.get(field)
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{field} must be a non-empty string")

    if len(record["incident_id"]) != 64 or any(
        char not in "0123456789abcdef"
        for char in record["incident_id"]
    ):
        raise ValueError("incident_id must be a SHA-256 hex digest")

    if validate_response_status(record["status"]) != "TRIAGED":
        raise ValueError("Only TRIAGED records are supported")

    if record.get("approved") is not False:
        raise ValueError("Triage records must be unapproved")

    return record



def check_duplicate_incident(records, new_record):
    """Reject a second triage record for the same incident."""
    incident_id = new_record["incident_id"]

    for existing_record in records:
        if existing_record["incident_id"] == incident_id:
            raise ValueError(
                f"Response record already exists for incident: {incident_id}"
            )

    return True



import os
import tempfile



def save_response_record(file_path, new_record):
    """Persist a validated triage record under an exclusive lock."""
    validate_response_record(new_record)

    path = Path(file_path)
    lock_path = path.with_name(path.name + ".lock")

    with lock_path.open("a+b") as lock_file:
        acquire_response_lock(lock_file)

        records = load_response_records(path)
        validate_response_history(records)
        check_duplicate_incident(records, new_record)

        updated_records = records + [new_record]
        temporary_path = None

        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                dir=path.parent,
                prefix=f".{path.name}.",
                suffix=".tmp",
                delete=False,
            ) as temporary_file:
                temporary_path = Path(temporary_file.name)
                json.dump(updated_records, temporary_file, indent=4)
                temporary_file.flush()
                os.fsync(temporary_file.fileno())

            os.replace(temporary_path, path)

        finally:
            if temporary_path is not None:
                temporary_path.unlink(missing_ok=True)

        return updated_records


def validate_response_history(records):
    """Reject malformed or duplicate incident response history."""
    if not isinstance(records, list):
        raise ValueError("Response history must be a list")

    seen_incident_ids = set()

    for record in records:
        validate_response_record(record)

        incident_id = record["incident_id"]

        if incident_id in seen_incident_ids:
            raise ValueError(
                f"Duplicate incident ID in response history: {incident_id}"
            )

        seen_incident_ids.add(incident_id)

    return records



import fcntl


def acquire_response_lock(lock_file):
    """Acquire an exclusive Linux advisory file lock."""
    fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
