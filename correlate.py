import json
import os
import time

from datetime import datetime
from pathlib import Path

def validate_config(config):
    required_keys = {
        "trigger_sid",
        "backdoor_sid",
        "correlation_window_seconds"
    }

    missing_keys = required_keys - config.keys()

    if missing_keys:
        raise ValueError(
            f"Missing required configuration keys: {sorted(missing_keys)}"
        )

    if not isinstance(config["trigger_sid"], int):
        raise ValueError("trigger_sid must be an integer")

    if not isinstance(config["backdoor_sid"], int):
        raise ValueError("backdoor_sid must be an integer")

    if not isinstance(config["correlation_window_seconds"], int):
        raise ValueError("correlation_window_seconds must be an integer")

    if config["correlation_window_seconds"] <= 0:
        raise ValueError("correlation_window_seconds must be greater than 0")

def process_event(
    event,
    pending_triggers,
    incidents,
    trigger_sid,
    backdoor_sid,
    correlation_window_seconds,
):

    alert = event.get("alert", {})
    sid = alert.get("signature_id")
    timestamp_value = event.get("timestamp")

    if sid is None or timestamp_value is None:
        return

    try:
        timestamp = datetime.fromisoformat(timestamp_value)
    except (TypeError, ValueError):
        return

    stale_keys = []

    for stored_key, stored_time in pending_triggers.items():
        age = timestamp - stored_time

        if age.total_seconds() > correlation_window_seconds:
            stale_keys.append(stored_key)

    for stale_key in stale_keys:
        del pending_triggers[stale_key]

    src_ip = event.get("src_ip")
    dest_ip = event.get("dest_ip")

    if src_ip is None or dest_ip is None:
        return

    key = (src_ip, dest_ip)

    if sid == trigger_sid:
        pending_triggers[key] = timestamp

    elif sid == backdoor_sid:
        if key not in pending_triggers:
            return

        delta = timestamp - pending_triggers[key]

        if 0 <= delta.total_seconds() <= correlation_window_seconds:
            incident = {
                "severity": "HIGH",
                "title": "Possible Successful vsftpd Backdoor Exploitation",
                "source_ip": src_ip,
                "target_ip": dest_ip,
                "trigger_sid": trigger_sid,
                "backdoor_sid": backdoor_sid,
                "elapsed_seconds": round(delta.total_seconds(), 1),
                "trigger_time": pending_triggers[key].isoformat(),
                "backdoor_time": timestamp.isoformat(),
            }

            new_incident = None

            if incident not in incidents:
                incidents.append(incident)
                new_incident = incident

            del pending_triggers[key]

            return new_incident

def main():
    EVE_FILE = "/var/log/suricata/eve.json"
    pending_triggers = {}
    BASE_DIR = Path(__file__).resolve().parent
    CONFIG_FILE = BASE_DIR / "config.json"
    INCIDENT_FILE = BASE_DIR / "incidents.json"
    try:
        with open(CONFIG_FILE, "r") as f:
            config = json.load(f)
    except FileNotFoundError:
        print(f"CONFIGURATION ERROR: {CONFIG_FILE} was not found")
        raise SystemExit(1)
    except json.JSONDecodeError:
        print(f"CONFIGURATION ERROR: {CONFIG_FILE} contains invalid JSON")
        raise SystemExit(1)

    try:
        validate_config(config)
    except ValueError as error:
        print(f"CONFIGURATION ERROR: {error}")
        raise SystemExit(1)

    TRIGGER_SID = config["trigger_sid"]
    BACKDOOR_SID = config["backdoor_sid"]
    CORRELATION_WINDOW_SECONDS = config["correlation_window_seconds"]
    CUSTOM_SIDS = {TRIGGER_SID, BACKDOOR_SID}

    try:
        with open(INCIDENT_FILE, "r") as f:
            incidents = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        incidents = []

    try:
        eve_stream = open(EVE_FILE, "r")
    except FileNotFoundError:
        print(f"TELEMETRY ERROR: {EVE_FILE} was not found")
        raise SystemExit(1)
    except PermissionError:
        print(f"TELEMETRY ERROR: permission denied reading {EVE_FILE}")
        raise SystemExit(1)

    with eve_stream as f:
        f.seek(0, 2)

        while True:
            try:
                current_inode = os.stat(EVE_FILE).st_ino
                open_inode = os.fstat(f.fileno()).st_ino
            except FileNotFoundError:
                time.sleep(0.5)
                continue

            if current_inode != open_inode:
                f.close()
                f = open(EVE_FILE, "r")
                f.seek(0, 2)

            line = f.readline()

            if not line:
                time.sleep(0.5)
                continue

            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue

            if event.get("event_type") != "alert":
                continue

            new_incident = process_event(
                event,
                pending_triggers,
                incidents,
                TRIGGER_SID,
                BACKDOOR_SID,
                CORRELATION_WINDOW_SECONDS,
            )

            if new_incident is not None:
                print("=" * 50)
                print("HIGH SECURITY INCIDENT")
                print(f"Source: {new_incident['source_ip']}")
                print(f"Target: {new_incident['target_ip']}")
                print(f"Elapsed: {new_incident['elapsed_seconds']} seconds")
                print("Confidence: HIGH")
                print("=" * 50)

                with open(INCIDENT_FILE, "w") as incident_file:
                    json.dump(incidents, incident_file, indent=4)

if __name__ == "__main__":
    main()
