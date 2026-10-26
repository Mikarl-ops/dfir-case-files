"""Normalize synthetic case events and produce explainable triage findings."""

import argparse
import ipaddress
import json
import math
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path


def parse_timestamp(value):
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def load_events(path):
    events = []
    for line_number, line in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid JSON on line {line_number}") from exc
        if not isinstance(event, dict):
            raise ValueError(f"Event on line {line_number} must be a JSON object")
        events.append(event)
    return events


def _valid_ip(value):
    try:
        return str(ipaddress.ip_address(value))
    except (ValueError, TypeError):
        return None


def shannon_entropy(value):
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def normalize_event(event):
    event_type = event.get("event_type")
    if event_type not in {"auth_failure", "auth_success", "dns_query", "cloudtrail_api"}:
        return None
    try:
        timestamp = parse_timestamp(event["timestamp"])
    except (KeyError, TypeError, ValueError):
        return None

    source = _valid_ip(event.get("source_ip") or event.get("client_ip"))
    normalized = {
        "event_id": str(event.get("event_id", "unknown")),
        "timestamp": timestamp,
        "event_type": event_type,
        "source_ip": source or "unknown",
        "asset": event.get("asset", "unknown"),
        "user": event.get("user", "unknown"),
        "summary": event.get("summary", ""),
        "query": event.get("query", ""),
        "event_name": event.get("event_name", ""),
    }
    return normalized


def analyze_events(events, threshold=5, window_seconds=300):
    if threshold < 1 or window_seconds < 1:
        raise ValueError("threshold and window_seconds must be positive")
    timeline = [normalized for event in events if (normalized := normalize_event(event)) is not None]
    timeline.sort(key=lambda event: (event["timestamp"], event["event_id"]))

    failures_by_source = defaultdict(list)
    for event in timeline:
        if event["event_type"] == "auth_failure" and event["source_ip"] != "unknown":
            failures_by_source[event["source_ip"]].append(event)

    findings = []
    window = timedelta(seconds=window_seconds)
    bursts = {}
    for source_ip, failures in failures_by_source.items():
        left = 0
        largest = (0, None, None)
        for right, event in enumerate(failures):
            while event["timestamp"] - failures[left]["timestamp"] > window:
                left += 1
            count = right - left + 1
            if count > largest[0]:
                largest = (count, failures[left], event)
        if largest[0] >= threshold:
            start_event, end_event = largest[1], largest[2]
            supporting = [
                item for item in failures
                if start_event["timestamp"] <= item["timestamp"] <= end_event["timestamp"]
            ]
            bursts[source_ip] = end_event["timestamp"]
            findings.append({
                "finding_id": f"ssh-failure-burst-{source_ip}",
                "type": "ssh_failed_login_burst",
                "source_ip": source_ip,
                "event_count": largest[0],
                "supporting_event_ids": [item["event_id"] for item in supporting],
                "confidence": "triage lead",
            })

    for event in timeline:
        if event["event_type"] == "auth_success" and event["source_ip"] in bursts:
            if timedelta(0) <= event["timestamp"] - bursts[event["source_ip"]] <= timedelta(minutes=15):
                findings.append({
                    "finding_id": f"ssh-success-after-burst-{event['event_id']}",
                    "type": "ssh_success_after_failure_burst",
                    "source_ip": event["source_ip"],
                    "event_count": 1,
                    "supporting_event_ids": [event["event_id"]],
                    "confidence": "triage lead",
                })

    for event in timeline:
        if event["event_type"] != "dns_query":
            continue
        first_label = event["query"].rstrip(".").split(".", 1)[0]
        entropy = shannon_entropy(first_label)
        if len(first_label) >= 32 and entropy >= 3.5:
            findings.append({
                "finding_id": f"long-dns-label-{event['event_id']}",
                "type": "possible_dns_tunneling",
                "source_ip": event["source_ip"],
                "event_count": 1,
                "supporting_event_ids": [event["event_id"]],
                "label_length": len(first_label),
                "label_entropy_bits_per_character": round(entropy, 3),
                "confidence": "triage lead",
            })

    rendered_timeline = [
        {**event, "timestamp": event["timestamp"].isoformat().replace("+00:00", "Z")}
        for event in timeline
    ]
    return {"timeline": rendered_timeline, "findings": findings}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("evidence", help="Path to JSON Lines evidence")
    parser.add_argument("--threshold", type=int, default=5)
    parser.add_argument("--window-seconds", type=int, default=300)
    args = parser.parse_args()
    result = analyze_events(load_events(args.evidence), args.threshold, args.window_seconds)
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
