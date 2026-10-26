# Case 001: Suspicious authentication and DNS activity

## Scope

This is a synthetic training case. The event file contains fictional SSH authentication, DNS, and CloudTrail records. The IPs come from documentation-only ranges. No raw packet capture or real account data is included.

## Observations

- Five SSH failures for admin from 203.0.113.70 occur between 02:00 and 02:02 UTC.
- A successful SSH authentication from the same source and user follows within 20 seconds.
- A DNS query from web-01 contains a long, high-entropy first label. The heuristic marks it for review.
- A separate synthetic CloudTrail ListBuckets event occurs later. The sample does not prove it is related to the SSH or DNS events.

## Assessment

The authentication sequence is consistent with a password-guessing attempt followed by a successful login. The DNS label is consistent with an encoded token or identifier and merits resolver and endpoint review. These signals alone do not prove that the host was compromised or that data was exfiltrated.

## Follow-up evidence to collect in a real investigation

1. Validate timestamps, time zones, host identity, and event integrity.
2. Review SSH daemon records, host process history, and account changes around the login.
3. Query resolver logs for the full DNS response, destination, frequency, and peer behavior.
4. Correlate the host with cloud audit activity using identity, session, and asset context.
5. Preserve original evidence and hashes before remediation.
