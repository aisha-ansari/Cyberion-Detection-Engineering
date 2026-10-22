# Sigma Detection Rule Test Results

## Rule 1: Suspicious Rundll32 JavaScript Execution

**Rule file:** `win_susp_rundll32_javascript.yml`

**Validation status:** Passed — 0 errors, 0 condition errors, 0 issues.

### Test Result

- **Events matched:** 1
- **Matched event number:** 2
- **Event type:** Sysmon Event ID 1 — Process Creation
- **Matched image:** `C:\Windows\System32\rundll32.exe`
- **Matching command-line indicators:** `javascript:` and `RunHTMLApplication`

### Assessment

The Python test script successfully matched one event in the selected EVTX sample. The command-line pattern is suspicious and warrants further investigation.

The result does not independently establish compromise or demonstrate that the rule has no false positives.

### False-Positive Review

**Review status:** Initial review; further testing required.

**Potential false positives:** Legitimate or authorized activity that uses `rundll32.exe` with a JavaScript-related command line.

**Potential detection gaps:** Suspicious uses of `rundll32.exe` that do not contain `javascript:` may not match this rule.

**Current assessment:** The rule matched one event in the selected EVTX sample. This is insufficient to measure its false-positive rate or detection coverage.

**Next action:** Test the rule against additional relevant log samples and, where available, benign process-creation logs.

---

## Rule 2: Suspicious Mshta Execution with Remote URL

**Rule file:** `win_susp_mshta_remote_url.yml`

**Validation status:** Passed — 0 errors, 0 condition errors, 0 issues.

### Test Result

- **Events matched:** 1
- **Matched event number:** 3
- **Event type:** Sysmon Event ID 1 — Process Creation
- **Matched image:** `C:\Windows\System32\mshta.exe`
- **URL observed:** `https://hotelesms.com/talsk.txt`

### Assessment

The Python test script successfully matched one event that satisfied both detection conditions. The observed execution pattern is suspicious and warrants further investigation.

The match does not independently establish that the remote content was malicious or that the system was compromised.

### False-Positive Review

**Review status:** Initial review; further testing required.

**Potential false positives:** Legitimate administrative or application activity using `mshta.exe` with a remote URL.

**Potential detection gaps:** Suspicious uses of `mshta.exe` without an HTTP or HTTPS URL in the command line may not match this rule.

**Current assessment:** The rule matched one event in the selected EVTX sample. This is insufficient to measure its false-positive rate or detection coverage.

**Next action:** Test the rule against additional relevant log samples and, where available, benign process-creation logs.

### Testing Method Limitation

The Python test script reproduces the detection logic for both rules. It does not execute the Sigma YAML rules through a SIEM or Sigma backend.