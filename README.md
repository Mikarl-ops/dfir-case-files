# DFIR Case Files

A reproducible digital forensics and incident response case built from synthetic JSON Lines evidence. The analysis script creates a normalized UTC timeline and flags an SSH failed-login burst, a subsequent same-source success, and a long high-entropy DNS label for analyst review.

## Case 001

The fictional case is in cases/001-suspicious-auth-and-dns. It contains authentication and DNS events with documentation-only IP addresses. No real user data, credentials, or packet capture is included.

Run the analysis and tests from the repository root:

    python src/analyze_case.py cases/001-suspicious-auth-and-dns/events.jsonl
    python -m unittest discover -s tests -v

The command prints a JSON document with an ordered timeline and findings. Each finding includes the supporting event identifiers so a reviewer can trace it back to the fixture.

## Method and limitations

The SSH rule flags at least five failed logins from one source within five minutes and notes a later successful login from that source. The DNS heuristic flags a first label that is at least 32 characters long with Shannon entropy of at least 3.5 bits per character. These are triage leads, not proof of compromise or exfiltration. A real investigation would add resolver context, endpoint identity, packet evidence, baseline comparison, and validated timestamps.

The dataset is synthetic and designed for repeatable tool behavior, not to represent a real incident or calibrated detection thresholds. Do not treat the report as evidence about a real person or system.
