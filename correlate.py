import json

from datetime import datetime
from pathlib import Path

EVE_FILE = "/var/log/suricata/eve.json"
pending_triggers = {}
BASE_DIR = Path(__file__).resolve().parent
CONFIG_FILE = BASE_DIR / "config.json"
INCIDENT_FILE = BASE_DIR / "incidents.json"
with open(CONFIG_FILE, "r") as f:
    config = json.load(f)
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
TRIGGER_SID = config["trigger_sid"]
BACKDOOR_SID = config["backdoor_sid"]
CORRELATION_WINDOW_SECONDS = config["correlation_window_seconds"]
CUSTOM_SIDS = {TRIGGER_SID, BACKDOOR_SID}
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
        if sid == TRIGGER_SID:
            pending_triggers[key] = timestamp
        
        elif sid == BACKDOOR_SID:
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
                       "trigger_sid": TRIGGER_SID,
                       "backdoor_sid": BACKDOOR_SID,
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
                   print(f"Trigger SID:  {TRIGGER_SID}")
                   print(f"Backdoor SID: {BACKDOOR_SID}")
                   print(f"Elapsed:      {elapsed_seconds:.1f} seconds")
                   print("Confidence:   HIGH")
                   print("=" * 50)

                   del pending_triggers[key]        

with open(INCIDENT_FILE, "w") as f:
    json.dump(incidents, f, indent=4)
