# Case 001: Suspicious authentication and DNS activity

**Case type:** Synthetic DFIR exercise  
**Assessment status:** Initial triage; not a confirmed incident  
**Overall priority:** Medium for investigation, based on the authentication sequence plus a separate DNS heuristic  
**Data handling:** All records are synthetic. IP addresses use documentation-only ranges; no real account data or packet capture is included.

## Executive summary

The supplied records show five failed SSH authentications for `admin` from `203.0.113.70` on `web-01` between **02:00:00 and 02:02:00 UTC on 24 October 2026**, followed by a successful SSH authentication from the same source and account at **02:02:20 UTC**. This sequence warrants investigation for password guessing followed by possible unauthorized access.

A DNS query at 02:05:00 UTC contains a long, high-entropy first label and is flagged by a simple heuristic. This may reflect encoded application data, a token, or benign generated content; the available event alone does not establish DNS tunnelling or exfiltration.

A synthetic CloudTrail `ListBuckets` event appears at 02:06:00 UTC for `demo-role`, with source `198.51.100.24`. The records do **not** establish a link between this API event and the SSH activity. Treat it as a separate lead until identity, session, asset, and network evidence support correlation.

## Scope and method

The analysis used `events.jsonl` and the local `src/analyze_case.py` evaluator. The evaluator normalizes recognized timestamps to UTC, orders events, groups SSH failures by source IP, and flags:
- At least five failed SSH authentications from one source within a rolling five-minute window.
- A successful SSH authentication from the same source within 15 minutes after the end of a qualifying failure burst.
- A DNS query whose first label is at least 32 characters and has Shannon entropy of at least 3.5 bits per character.

These are deterministic triage heuristics, not validated production detections. The report is limited to the supplied synthetic records; no endpoint, resolver, identity-provider, packet, or cloud-session evidence was available.

## Evidence timeline (UTC)

| Time | Event ID | Observed record | Interpretation |
| --- | --- | --- | --- |
| 02:00:00 | `auth-001` | SSH failure for `admin` from `203.0.113.70` to `web-01` | First event in the failure sequence |
| 02:00:30 | `auth-002` | Same source and user; SSH failure | Repeated failure |
| 02:01:00 | `auth-003` | Same source and user; SSH failure | Repeated failure |
| 02:01:30 | `auth-004` | Same source and user; SSH failure | Repeated failure |
| 02:02:00 | `auth-005` | Same source and user; fifth SSH failure | Meets the configured threshold |
| 02:02:20 | `auth-006` | SSH success for `admin` from the same source | Concerning temporal sequence; authorization is not established |
| 02:04:10 | `auth-007` | One SSH failure from `198.51.100.24` for `deploy` | Separate low-volume event; does not meet the burst threshold |
| 02:05:00 | `dns-001` | DNS query from `web-01` with a long encoded-looking label | Heuristic alert; query context and response are absent |
| 02:06:00 | `cloudtrail-001` | `ListBuckets` by `demo-role`, source `198.51.100.24` | Separate cloud audit lead; no demonstrated link to the SSH burst |

The timeline above is a human-readable summary of the fixture, not an independently verified forensic timeline. The input timestamps are accepted as supplied; source clock accuracy and log integrity have not been validated.

## Findings and confidence

### F-01 — SSH failure burst followed by success

**Severity:** Medium  
**Confidence:** High that the supplied records contain the sequence; low that the sequence alone proves compromise  
**Supporting evidence:** `auth-001` through `auth-006`

Five failed SSH attempts against `admin` occurred within two minutes, followed by a successful login 20 seconds after the final failure from the same source IP. This is consistent with password guessing followed by a successful authentication, but can also result from a legitimate user recovering the correct password or an approved test.

**Recommended checks**
1. Confirm whether the source, account, and login time are expected; verify through an approved channel.
2. Review SSH daemon logs for authentication method, targeted usernames, session details, and any other source addresses.
3. Inspect host process execution, interactive sessions, new users/keys, privilege changes, persistence indicators, and subsequent access.
4. Correlate with identity, VPN, jump-host, endpoint, and change-management records.
5. Preserve relevant original logs and document collection times and hashes before remediation.

### F-02 — Long, high-entropy DNS query label

**Severity:** Low to medium pending context  
**Confidence:** Low; heuristic-only signal  
**Supporting evidence:** `dns-001`

The first label meets the evaluator's length and entropy thresholds. High entropy can occur in encoded data, but also in legitimate tracking IDs, CDN names, service-discovery records, and application-generated identifiers. A single query does not prove DNS tunnelling or data exfiltration.

**Recommended checks**
1. Retrieve the full query and response, record type, resolver, destination, response code, and frequency over time.
2. Compare the domain and label patterns with application baselines and known legitimate services.
3. Correlate the client IP and host identity with process/network telemetry around 02:05 UTC.
4. Look for repeated queries, unusual volume, long subdomain sequences, or other corroborating indicators.

### F-03 — CloudTrail ListBuckets event

**Severity:** Informational lead until contextualized  
**Confidence:** High that the synthetic record exists; no confidence in maliciousness from this record alone  
**Supporting evidence:** `cloudtrail-001`

The event records `ListBuckets` by `demo-role` from `198.51.100.24`. This address also appears in the single `deploy` SSH failure, but shared source IP alone does not establish a common actor or causal relationship.

**Recommended checks**
1. Inspect the full CloudTrail event, account, role session issuer, principal, user agent, source context, and event time.
2. Confirm whether the action is expected for the role and workload.
3. Correlate by session/principal and asset identity, not just IP address.
4. Review surrounding API calls and relevant access-denied or credential-use events.

## Alternative explanations

- **Legitimate SSH user:** The account owner may have mistyped credentials before a successful login.
- **Automation issue:** A deployment process may have retried an expired or rotated secret.
- **Shared egress:** VPN, NAT, or jump hosts can make unrelated activity share an IP address.
- **Benign DNS encoding:** The label may be a legitimate application identifier or tracking token.
- **Routine cloud administration:** `ListBuckets` may be normal for the role; the record lacks enough context to decide.

These explanations are not mutually exclusive. Validate them with independent records before concluding.

## Assessment and response recommendation

The strongest signal is the five-failure SSH burst followed closely by a same-source success. **Prioritize validating the login and account activity**, while investigating the DNS and CloudTrail records as separate leads. The available data does not support a conclusion that the host was compromised, that DNS exfiltration occurred, or that the cloud API call was related.

Do not automatically block the source, disable accounts, or isolate a host based only on these heuristics. If corroborating evidence indicates active compromise, follow the organization's approved incident-response process, preserve evidence, and obtain the appropriate authorization for containment.

## Evidence gaps

- No raw SSH/authentication logs, endpoint telemetry, or process history.
- No DNS response, resolver logs, packet capture, domain reputation, or baseline.
- No full CloudTrail JSON, role session context, or surrounding API events.
- No verified clock synchronization, source integrity, or chain-of-custody records.

## Reproducibility

From the repository root:

```bash
python src/analyze_case.py cases/001-suspicious-auth-and-dns/events.jsonl
python -m unittest discover -s tests -v
```

The dataset and findings are synthetic training material. The output should not be treated as evidence about a real person, account, host, or incident.
