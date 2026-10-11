# Security Incident Report — October 9, 2026

## 1. Executive Summary

On October 9, 2026, a controlled penetration test was conducted
against an intentionally vulnerable Metasploitable2 system.

Suricata detected an FTP backdoor trigger followed by a connection
to the associated backdoor service. The Python correlation engine
identified the matching source and target IP addresses and generated
a HIGH-severity security incident.

The two alerts occurred approximately 2.4 seconds apart, within
the configured 300-second correlation window.

The resulting incident was recorded in incidents.json.

## 2. Scope and Environment

Assessment Type: Authorized, isolated Purple Team laboratory test

Source System: Kali Linux
Source IP: 192.168.139.128

Target System: Metasploitable2
Target IP: 192.168.139.129

Detection Engine: Suricata 8.0.6
Correlation Engine: Python-based stateful event correlator

Relevant Service: FTP (TCP/21)
Associated Backdoor Port: TCP/6200

Vulnerability Under Test:
vsftpd 2.3.4 backdoored distribution (CVE-2011-2523)

This assessment was performed exclusively within a controlled
laboratory environment. No production systems were targeted.

## 3. Detection Timeline

Date: October 9, 2026
Timezone: Central Daylight Time (UTC-05:00)

12:49:21.287815
- Suricata detected an FTP backdoor trigger.
- Signature ID: 1000001
- Source: 192.168.139.128
- Destination: 192.168.139.129
- Detection: LAB Possible vsftpd backdoor trigger

12:49:23.665952
- Suricata detected a connection to the associated backdoor port.
- Signature ID: 1000002
- Source: 192.168.139.128
- Destination: 192.168.139.129
- Detection: LAB Connection to vsftpd backdoor shell

Correlation Result:
- Both alerts involved the same source and destination.
- The FTP trigger preceded the backdoor connection.
- Recorded elapsed time: 2.4 seconds.
- Configured correlation window: 300 seconds.
- Correlation outcome: HIGH-severity security incident.

The correlation engine recorded the incident in incidents.json.

## 4. Evidence and Validation

### 4.1 Suricata Detection Evidence

Suricata generated two relevant alerts:

- SID 1000001: FTP backdoor trigger detection
- SID 1000002: Connection to the associated backdoor service

Both alerts identified the same source and destination IP addresses.

The alerts were recorded in:
- /var/log/suricata/eve.json

### 4.2 Stateful Correlation Evidence

The Python correlator evaluated the alert sequence and
confirmed that the backdoor connection followed the FTP trigger
within the configured 300-second window.

The correlator generated a HIGH-severity incident.

Persistent incident evidence:
- /home/kali/purple_team/incidents.json

Recorded correlation interval:
- 2.4 seconds

### 4.3 Controlled Exploitation Validation

During the authorized laboratory exercise, the tester
independently observed successful access to the target's
backdoor shell.

The command `id` returned:

uid=0(root) gid=0(root)

This demonstrated root-level privileges within the
intentionally vulnerable laboratory target.

The root-access observation is separate from the
correlated Suricata alerts. The correlation record alone
does not establish the privilege level of the shell.

### 4.4 Evidence Limitations

- This was an isolated laboratory exercise.
- No production environment was compromised.
- The incident record establishes detection and correlation.
- Root-level access was observed during controlled validation.
- No claim is made that the correlation engine independently
  verified successful privilege escalation.
- No production containment or eradication actions are claimed.

## 5. Analyst Assessment and Response Actions

### 5.1 Analyst Assessment

The observed alert sequence is consistent with exploitation
of the vsftpd 2.3.4 backdoor in the controlled laboratory.

The HIGH severity classification is supported by:

- Detection of the FTP backdoor trigger (SID 1000001).
- Detection of the subsequent backdoor connection (SID 1000002).
- Matching source and destination IP addresses.
- A 2.4-second correlation interval within the 300-second window.
- Separate controlled validation demonstrating root-level access.

The available evidence supports successful exploitation
within the authorized laboratory environment.

### 5.2 Actions Performed

The following actions were performed during laboratory testing:

- Validated network connectivity between Kali and Metasploitable2.
- Executed controlled exploitation against the authorized target.
- Inspected Suricata EVE alerts and packet-capture evidence.
- Corrected and validated the FTP trigger detection signature.
- Verified generation of the HIGH-severity correlated incident.
- Confirmed persistence of the incident in incidents.json.
- Tested rejection of reverse-order alerts.
- Verified the Python correlator's telemetry-reading behavior.

These actions supported detection validation and evidence
collection. They do not constitute production containment
or eradication.

### 5.3 Recommended Production Response

If comparable activity were detected in a production
environment, recommended analyst actions would include:

- Validate the alerts and identify the affected asset.
- Escalate according to the organization's incident policy.
- Isolate the affected host when authorized and appropriate.
- Preserve relevant network, host, and authentication evidence.
- Investigate unauthorized access and potential persistence.
- Remove the compromised software and rebuild or remediate
  the affected system according to approved procedures.
- Verify recovery and monitor for additional suspicious activity.

These are recommendations only. They were not performed
as production response actions during this laboratory exercise.

## 6. Lessons Learned and Recommendations

### 6.1 Detection Engineering

The initial FTP trigger signature required correction
before reliable live detection was demonstrated.

The revised SID 1000001 uses FTP-aware inspection
keywords to identify the backdoor trigger.

The validated signature was preserved in the project's
rules/lab_suricata.rules file and committed to GitHub.

Lesson learned:
Detection signatures must be validated against actual
network telemetry rather than assumed to work because
they load successfully.

### 6.2 Stateful Correlation

The correlator successfully associated the FTP trigger
with a subsequent backdoor connection from the same
source to the same target.

The 300-second correlation window prevented unrelated
or excessively delayed events from qualifying.

Automated testing also verified that reverse-order
alerts do not generate a HIGH incident.

Lesson learned:
Event sequence, timing, and host relationships are
essential to reliable security correlation.

### 6.3 Telemetry Health Monitoring

The correlator uses a 60-second telemetry freshness
threshold and warning suppression logic.

During October 11 validation, intermittent stale
warnings were reproduced while Suricata continued
generating EVE telemetry.

Temporary diagnostic logging captured a warning
with the following measurements:

- Warning check: 08:11:54.904033 UTC
- Last telemetry consumed: 08:11:58.436257 UTC
- Calculated age: approximately -3.53 seconds
- Reader position: 6,871,778 bytes
- EVE file size: 6,871,778 bytes

The negative age caused the wall-clock-based
freshness check to classify recently consumed
telemetry as stale.

The underlying cause of the clock discrepancy
was not conclusively established. System clock
synchronization was enabled, and the time-service
and kernel journal checks provided no confirming
evidence of a clock adjustment.

Remediation:
The live telemetry monitor was changed to use
time.monotonic() for elapsed-time measurements.
Incident timestamps and correlation logic were
preserved.

Validation:
- 19 automated tests passed.
- A monotonic freshness regression test was added.
- Suricata generated EVE stats approximately
  every eight seconds.
- Blue ran without a reported stale warning
  during the final observation.
- The EVE reader position matched the file size
  at 10,024,323 bytes.

Lesson learned:
Telemetry health should be measured using a
monotonic elapsed-time clock rather than relying
on wall-clock subtraction. A running detection
service alone does not prove telemetry consumption.

### 6.4 Recommended Future Improvements

- Preserve reproducible detection rules and configuration.
- Expand automated testing for additional edge cases.
- Continue investigating intermittent telemetry warnings
  if they recur.
- Improve operational logging and evidence retention.
- Document analyst escalation and response procedures.
- Maintain clear separation between laboratory validation
  and production security operations.

## 7. Report Conclusion

The October 9, 2026 controlled laboratory exercise
demonstrated successful detection and correlation of
the tested vsftpd backdoor activity.

Suricata generated the relevant network alerts, and
the Python correlator produced a HIGH-severity incident
within the configured correlation window.

Separate controlled testing demonstrated root-level
access to the intentionally vulnerable target.

The exercise validated the primary detection workflow
while identifying opportunities for continued
operational improvement.

This report documents laboratory findings only.
It does not represent an actual production compromise
or customer incident.
