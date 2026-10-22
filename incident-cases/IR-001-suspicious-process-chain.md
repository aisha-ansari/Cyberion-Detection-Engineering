# IR-001: Suspicious Process Chain and Scheduled Task

## 1. Investigation Status

- Status: Preliminary analysis
- Data source: EVTX-ATTACK-SAMPLES
- Log file: `exec_persist_rundll32_mshta_scheduledtask_sysmon_1_3_11.evtx`
- Host recorded in logs: `IEWIN7`
- Account recorded in logs: `IEWIN7\IEUser`
- Evidence reviewed: Five Sysmon events
- Analysis date: 2026-10-22

## 2. Executive Summary

The reviewed events show a suspicious process chain involving `cmd.exe`, `rundll32.exe`, and `mshta.exe`. The logs also record a network connection associated with `mshta.exe` and execution of a command intended to create a scheduled task named `MSOFFICE_`.

This activity warrants further investigation because script-capable Windows utilities, remote URLs, and scheduled tasks can be abused during attacks.

The available five events do not independently confirm that the scheduled task was successfully created, that remote content was malicious, or that the host suffered a specific impact.

## 3. Evidence

### Event 1 — Process Creation

- Sysmon Event ID: 1
- Process: `cmd.exe`
- Process ID: 1532
- Command line: Contains a `rundll32.exe` invocation using JavaScript and a request to launch `mshta.exe` with a remote URL.
- Parent process: `cmd.exe`, PID 3548

### Event 2 — Process Creation

- Sysmon Event ID: 1
- Process: `rundll32.exe`
- Process ID: 2920
- Parent process: `cmd.exe`, PID 1532
- Observation: The command line contains the same unusual execution chain.

### Event 3 — Process Creation

- Sysmon Event ID: 1
- Process: `mshta.exe`
- Process ID: 2432
- Parent process: `rundll32.exe`, PID 2920
- URL in command line: `https://hotelesms.com/talsk.txt`

### Event 4 — Network Connection

- Sysmon Event ID: 3
- Process: `mshta.exe`, PID 2432
- Source IP: `10.0.2.15`
- Destination IP: `108.179.232.58`
- Destination port: `443`
- Protocol: TCP
- Observation: A connection was recorded for the same process ID as Event 3.

### Event 5 — Process Creation

- Sysmon Event ID: 1
- Process: `schtasks.exe`
- Process ID: 3772
- Parent process: `mshta.exe`, PID 2432
- Task name specified: `MSOFFICE_`
- Requested action: Launch `mshta.exe` with `https://hotelesms.com/Injection.txt`
- Observation: The command attempts to create a scheduled task. Successful creation and subsequent execution require corroboration.

## 4. Preliminary Timeline

The displayed timestamps suggest that the process and network events occurred close together. However, Event 4 has a discrepancy between its `Timestamp` and `UtcTime` values. Verify the timestamp fields and their interpretation before finalizing the timeline.

## 5. Preliminary Assessment

The combination of unusual command-line execution, a remote URL, a recorded network connection, and a scheduled-task creation command is suspicious.

Potential areas for further investigation:

- Remote content and domain reputation
- Scheduled-task creation and execution
- Related process and network activity
- Additional persistence or follow-on activity
- Relevant MITRE ATT&CK technique mappings

## 6. Limitations

- Only five events have been reviewed.
- The successful creation and later execution of the scheduled task have not been verified.
- The remote content has not been independently analyzed.
- The available evidence does not establish the full impact or root cause.
- Timestamp discrepancies require further examination.

## 7. Next Steps

1. Review additional events from the same EVTX file.
2. Correlate process IDs and process GUIDs with related events.
3. Investigate the scheduled task and its configured action.
4. Verify timestamp interpretation.
5. Map supported behaviors to MITRE ATT&CK.
6. Identify a detection opportunity and test it against the dataset.
