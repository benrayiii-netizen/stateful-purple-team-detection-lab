# Stateful Purple Team Detection & Correlation Lab

## Overview

A controlled Purple Team lab demonstrating network-based detection and stateful correlation of a known vsftpd 2.3.4 backdoor behavior.

The project uses Suricata custom detection rules to identify an FTP backdoor trigger and subsequent connection to the associated backdoor service. A Python correlation engine analyzes Suricata EVE JSON telemetry and escalates related events when they satisfy source, destination, event-order, and time-window requirements.

## Lab Environment

This project was developed and validated in an isolated virtual lab.

- Kali Linux — analyst, detection, and correlation system
- Metasploitable — intentionally vulnerable target
- Suricata 8.x — network intrusion detection engine
- Python 3 — event parsing and stateful correlation
- Nmap — network service validation
- Netcat — controlled network interaction
- VMware — virtualized lab environment

All testing was performed against systems within the isolated lab. The project focuses on defensive detection engineering, telemetry analysis, and incident correlation.

## Architecture

Network Traffic
→ Suricata
→ Custom Detection Rules
→ EVE JSON
→ Python Correlation Engine
→ High-Confidence Incident
→ Structured JSON Output

## Detection Logic

Two custom Suricata signatures are correlated:

- SID 1000001 — possible vsftpd backdoor trigger
- SID 1000002 — connection to the associated backdoor service

An incident is escalated only when:

1. Both events involve the same source and destination.
2. The trigger occurs before the follow-on connection.
3. The events occur within the configured 300-second correlation window.

## Correlation Rationale

A single detection event does not necessarily demonstrate successful exploitation.

SID 1000001 identifies traffic consistent with the known vsftpd backdoor trigger. On its own, this event represents evidence of an exploitation attempt but does not confirm that the associated backdoor service became accessible.

SID 1000002 identifies a subsequent connection to the associated backdoor service.

The correlation engine therefore increases confidence only when the following relationship is observed:

```text
SID 1000001 — Backdoor Trigger
        |
        | same source and target
        | correct chronological order
        | within 300 seconds
        v
SID 1000002 — Backdoor Connection
        |
        v
HIGH SECURITY INCIDENT

## Validation

V1 was tested against positive and negative scenarios:

| Test | Scenario | Expected Result | Result |
|---|---|---|---|
| 1 | Trigger only | No high-severity incident | PASS |
| 2 | Trigger followed by backdoor connection after 86.7 seconds | One high-severity incident | PASS |
| 3 | Trigger followed by backdoor connection after 360 seconds | No high-severity incident | PASS |

## Repository Structure

```text
purple_team/
├── correlate.py
├── README.md
├── rules/
│   └── lab_suricata.rules
├── tests/
│   └── test_outside_window.json
├── docs/
└── examples/

## Project Status

V1 detection and correlation logic validated in a controlled lab environment.
