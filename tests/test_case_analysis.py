import unittest

from src.analyze_case import analyze_events, load_events


class CaseAnalysisTests(unittest.TestCase):
    def test_case_fixture_produces_traceable_findings(self):
        result = analyze_events(load_events("cases/001-suspicious-auth-and-dns/events.jsonl"))
        finding_types = {finding["type"] for finding in result["findings"]}
        self.assertEqual(
            finding_types,
            {"ssh_failed_login_burst", "ssh_success_after_failure_burst", "possible_dns_tunneling"},
        )
        burst = next(item for item in result["findings"] if item["type"] == "ssh_failed_login_burst")
        self.assertEqual(burst["event_count"], 5)
        self.assertEqual(len(burst["supporting_event_ids"]), 5)

    def test_timeline_is_sorted_and_success_from_other_source_does_not_correlate(self):
        events = [
            {"event_id": "success", "timestamp": "2026-10-24T02:03:00Z", "event_type": "auth_success", "source_ip": "198.51.100.5"},
            {"event_id": "failure", "timestamp": "2026-10-24T02:00:00Z", "event_type": "auth_failure", "source_ip": "203.0.113.5"},
        ]
        result = analyze_events(events, threshold=1)
        self.assertEqual(result["timeline"][0]["event_id"], "failure")
        self.assertNotIn("ssh_success_after_failure_burst", {item["type"] for item in result["findings"]})

    def test_rejects_invalid_threshold(self):
        with self.assertRaises(ValueError):
            analyze_events([], threshold=0)


if __name__ == "__main__":
    unittest.main()
