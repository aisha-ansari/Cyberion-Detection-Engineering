### False-Positive Review

**Review status:** Initial review; further testing required.

**Potential false positives:** Legitimate or authorized activity that uses `rundll32.exe` with a JavaScript-related command line.

**Potential detection gaps:** Suspicious uses of `rundll32.exe` that do not contain `javascript:` may not match this rule.

**Current assessment:** The rule matched one event in the selected EVTX sample. This is insufficient to measure its false-positive rate or detection coverage.

**Next action:** Test the rule against additional relevant log samples and, where available, benign process-creation logs.