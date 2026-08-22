import json

from datetime import datetime
from pathlib import Path

EVE_FILE = "/var/log/suricata/eve.json"
CUSTOM_SIDS = {1000001, 1000002}
CORRELATION_WINDOW_SECONDS = 300
pending_triggers = {}
BASE_DIR = Path(__file__).resolve().parent
INCIDENT_FILE = BASE_DIR / "incidents.json"
try:
    with open(INCIDENT_FILE, "r") as f:
        incidents = json.load(f)
except (FileNotFoundError, json.JSONDecodeError):
    incidents = []

with open(EVE_FILE, "r") as f:
    for line in f:
        event = json.loads(line)

        if event.get("event_type") != "alert":
            continue

        alert = event.get("alert", {})
        sid = alert.get("signature_id")
        timestamp = datetime.fromisoformat(event["timestamp"])
        stale_keys = []

        for stored_key, stored_time in pending_triggers.items():
            age = timestamp - stored_time

            if age.total_seconds() > CORRELATION_WINDOW_SECONDS:
                stale_keys.append(stored_key)

        for stale_key in stale_keys:
            del pending_triggers[stale_key]

        if sid not in CUSTOM_SIDS:
            continue

        key = (event.get("src_ip"), event.get("dest_ip"))

        if sid == 1000001:
            pending_triggers[key] = timestamp

        elif sid == 1000002:
            if key in pending_triggers:
               delta = timestamp - pending_triggers[key]

               if 0 <= delta.total_seconds() <= CORRELATION_WINDOW_SECONDS:
                   source_ip, dest_ip = key
                   elapsed_seconds = delta.total_seconds()

                   incident = {
                       "severity": "HIGH",
                       "title": "Possible Successful vsftpd Backdoor Exploitation",
                       "source_ip": source_ip,
                       "target_ip": dest_ip,
                       "trigger_sid": 1000001,
                       "backdoor_sid": 1000002,
                       "elapsed_seconds": round(elapsed_seconds, 1),
                       "trigger_time": pending_triggers[key].isoformat(),
                       "backdoor_time": timestamp.isoformat()
                   }

                   if incident not in incidents:
                       incidents.append(incident)

                   print("=" * 50)
                   print("HIGH SECURITY INCIDENT")
                   print("Possible Successful vsftpd Backdoor Exploitation")
                   print()
                   print(f"Source:       {source_ip}")
                   print(f"Target:       {dest_ip}")
                   print("Trigger SID:  1000001")
                   print("Backdoor SID: 1000002")
                   print(f"Elapsed:      {elapsed_seconds:.1f} seconds")
                   print("Confidence:   HIGH")
                   print("=" * 50)

                   del pending_triggers[key]        

with open(INCIDENT_FILE, "w") as f:
    json.dump(incidents, f, indent=4)
