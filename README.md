# DFIR Case Files

A reproducible digital forensics and incident response portfolio built around synthetic JSON Lines evidence. The Python analyzer normalizes an event timeline to UTC and emits traceable triage findings for an SSH failure burst, a subsequent same-source success, and a long high-entropy DNS label.

## Case 001 — Suspicious authentication and DNS activity

- **Evidence:** `cases/001-suspicious-auth-and-dns/events.jsonl`
- **Investigation report:** [incident-report.md](cases/001-suspicious-auth-and-dns/incident-report.md)
- **Analyzer:** `src/analyze_case.py`
- **Tests:** `tests/test_case_analysis.py`

The case contains SSH authentication, DNS, and a synthetic CloudTrail record. The incident report includes an event timeline, evidence IDs, confidence and severity assessments, alternative explanations, evidence gaps, and analyst follow-up steps.

All records are synthetic and use documentation-only IP addresses. No real user data, credentials, or packet capture is included.

## Run locally

Use Python 3.11 or newer. From the repository root:

```bash
python src/analyze_case.py cases/001-suspicious-auth-and-dns/events.jsonl
python -m unittest discover -s tests -v
```

The command prints JSON containing an ordered UTC timeline and findings. Each finding includes supporting event identifiers so reviewers can trace the result back to the supplied fixture.

## Detection logic

- **SSH burst:** at least five failed logins from one source IP within a rolling five-minute window.
- **Success after burst:** a same-source successful authentication within 15 minutes after the detected burst.
- **DNS heuristic:** first query label at least 32 characters long with Shannon entropy of at least 3.5 bits per character.

These heuristics are intentionally explainable and are only triage leads. A high-entropy label does not prove DNS tunnelling or exfiltration; an SSH failure burst does not prove compromise; and a shared IP does not prove two events came from the same actor. The CloudTrail record is assessed separately unless identity, session, and asset evidence supports correlation.

## Investigation method

1. Normalize and order timestamps; confirm clock and source integrity in a real case.
2. Trace every finding to its supporting event IDs.
3. Separate direct observations from interpretations and hypotheses.
4. State confidence, alternative explanations, and evidence gaps.
5. Recommend additional collection and authorized next steps without overstating what the data proves.

## Limitations

The dataset is synthetic and designed for repeatable tool behavior, not calibrated production thresholds. The analyzer does not acquire or preserve evidence, validate source authenticity, enrich IP/domain reputation, parse raw vendor logs, or perform containment. Real investigations should preserve originals, document chain of custody, correlate with endpoint/resolver/identity/cloud telemetry, and validate detections against the target environment.
