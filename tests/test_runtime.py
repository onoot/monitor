"""Runtime actor attribution must stay consistent with the derived aggregates."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from ad import requests as reqs  # noqa: E402
from ad.config import load_config  # noqa: E402

RECORDS = [
    {
        "client_ip": "10.0.0.5",
        "method": "POST",
        "path": "/login",
        "body": {"username": "alice", "password": "hunter2"},
        "response": "{}",
    },
    {
        "client_ip": "10.0.0.5",
        "method": "GET",
        "path": "/startscreen",
        "body": "",
        "response": "alt{aaaaaaaaaaaaaaaa}",
    },
    {
        "client_ip": "203.0.113.7",
        "method": "PUT",
        "path": "/flags",
        "body": {"flag": "alt{bbbbbbbbbbbbbbbb}"},
        "response": "{}",
    },
]


def cfg_with_networks():
    cfg = load_config(ROOT / "configs" / "magiclib.json")
    from ad.config import TeamNetwork

    return cfg.__class__(
        **{
            **cfg.__dict__,
            "team_networks": [TeamNetwork(label="teams", cidr="10.0.0.0/8", source="test")],
            "checker_networks": [
                TeamNetwork(label="checker", cidr="203.0.113.0/24", source="test")
            ],
        }
    )


class RuntimeAttribution(unittest.TestCase):
    def setUp(self):
        self.cfg = cfg_with_networks()
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "requests.json"
        self.path.write_text(json.dumps(RECORDS), encoding="utf-8")
        self.report = reqs.load_requests([self.path], self.cfg)

    def tearDown(self):
        self.tmp.cleanup()

    def test_every_record_is_parsed(self):
        self.assertEqual(len(self.report.requests), 3)

    def test_classification_assigns_actors_by_network(self):
        applied = self.report.classify_unknown(self.cfg)
        self.assertEqual(applied["10.0.0.5"], "team")
        self.assertEqual(applied["203.0.113.7"], "checker")

    def test_profiles_are_recomputed_after_classification(self):
        self.report.classify_unknown(self.cfg)
        self.assertIn("team", self.report.profiles)
        self.assertIn("checker", self.report.profiles)
        self.assertNotIn("unknown", self.report.profiles)
        self.assertEqual(self.report.profiles["checker"].requests, 1)

    def test_flag_reads_land_on_the_team_not_the_checker(self):
        self.report.classify_unknown(self.cfg)
        self.assertEqual(self.report.profiles["team"].flag_reads, 1)
        self.assertEqual(self.report.profiles["checker"].flag_reads, 0)

    def test_checker_put_counts_as_a_write_not_a_read(self):
        self.report.classify_unknown(self.cfg)
        self.assertEqual(self.report.profiles["checker"].flag_writes, 1)
        self.assertEqual(self.report.profiles["team"].flag_writes, 0)

    def test_route_matrix_separates_reads_from_writes(self):
        self.report.classify_unknown(self.cfg)
        by_route = {
            entry["route"]: entry["actors"]
            for entry in self.report.route_matrix()
        }
        self.assertEqual(by_route["PUT /flags"]["checker"]["flag_writes"], 1)
        self.assertEqual(by_route["PUT /flags"]["checker"]["flag_reads"], 0)
        self.assertEqual(by_route["GET /startscreen"]["team"]["flag_reads"], 1)

    def test_route_matrix_reflects_classification(self):
        self.report.classify_unknown(self.cfg)
        actors = {
            entry["route"]: sorted(entry["actors"])
            for entry in self.report.route_matrix()
        }
        self.assertEqual(actors["POST /login"], ["team"])
        self.assertEqual(actors["PUT /flags"], ["checker"])

    def test_classification_is_idempotent(self):
        self.report.classify_unknown(self.cfg)
        first = sorted(self.report.profiles)
        second_applied = self.report.classify_unknown(self.cfg)
        self.assertEqual(second_applied, {})
        self.assertEqual(sorted(self.report.profiles), first)

    def test_unclassified_ip_stays_unknown_and_unpoisonable(self):
        self.report.requests[0].client_ip = "198.51.100.9"
        applied = self.report.classify_unknown(self.cfg)
        self.assertEqual(applied["198.51.100.9"], "unknown")
        self.assertIn("unknown", self.report.profiles)


# Real lines from `docker logs curs-curs-1`, captured from the Curs service. Before
# gin was a supported format these parsed to zero records, leaving the whole
# runtime section of a Go service empty.
GIN_LOG = """[GIN] 2026/10/02 - 04:28:12 | 200 | 365.216\u00b5s |      172.23.0.1 | GET      "/"
[GIN] 2026/10/02 - 04:28:12 | 303 |   38.502\u00b5s |      172.23.0.1 | GET      "/dashboard"
[GIN] 2026/10/02 - 04:28:20 | 409 |     52.55ms |      172.23.0.1 | POST     "/user/register"
[GIN] 2026/10/02 - 04:28:21 | 401 |    47.69ms |      172.23.0.1 | POST     "/user/login"
[GIN] 2026/10/02 - 04:28:36 | 200 |      5.06ms | 172.23.0.1 | POST     "/user/login?next=%2Fadmin"
"""


class GinAccessLog(unittest.TestCase):
    def setUp(self):
        self.cfg = cfg_with_networks()
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "curs-gin.log"
        self.path.write_text(GIN_LOG, encoding="utf-8")
        self.report = reqs.load_requests([self.path], self.cfg)

    def tearDown(self):
        self.tmp.cleanup()

    def test_every_gin_line_becomes_a_request(self):
        self.assertEqual(len(self.report.requests), 5)
        self.assertEqual(self.report.parser_notes, [])

    def test_fields_land_in_the_right_columns(self):
        first = self.report.requests[0]
        self.assertEqual(first.client_ip, "172.23.0.1")
        self.assertEqual(first.method, "GET")
        self.assertEqual(first.path, "/")
        self.assertEqual(first.status, 200)
        self.assertEqual(first.headers["user-agent"], "")

    def test_status_and_method_survive_multibyte_latency(self):
        conflict = self.report.requests[2]
        self.assertEqual(conflict.status, 409)
        self.assertEqual(conflict.method, "POST")
        self.assertEqual(conflict.path, "/user/register")
        self.assertEqual(self.report.requests[3].status, 401)

    def test_query_is_split_off_the_path(self):
        login = self.report.requests[4]
        self.assertEqual(login.path, "/user/login")
        self.assertEqual(login.query, "next=%2Fadmin")

    def test_gin_timestamp_is_normalised_to_iso(self):
        self.assertEqual(self.report.requests[0].ts, "2026-10-02T04:28:12")
        self.assertEqual(reqs.normalise_gin_ts("2026/10/02 - 04:28:12"), "2026-10-02T04:28:12")

    def test_bad_timestamp_is_left_alone_not_invented(self):
        self.assertEqual(reqs.normalise_gin_ts("not a timestamp"), "not a timestamp")

    def test_gin_open_bracket_does_not_trigger_a_json_note(self):
        # The line starts with `[`, which a JSON sniffer would otherwise blame.
        self.assertNotIn(
            "not valid JSON", " ".join(self.report.parser_notes)
        )

    def test_gin_lines_are_attributed_like_any_other_capture(self):
        self.report.requests[0].client_ip = "10.0.0.5"
        applied = self.report.classify_unknown(self.cfg)
        self.assertEqual(applied["10.0.0.5"], "team")
        self.assertEqual(self.report.profiles["team"].requests, 1)


# Records shaped exactly like `services/monitoring/data/<service>/<date>.jsonl`.
MONITOR_RECORDS = [
    {
        "at": "2026-10-02T17:22:31.000Z", "ip": "10.78.0.250", "principal": "checker",
        "team": "", "service": "curs", "host": "10.77.1.2", "method": "PUT",
        "target": "/flags?user=alice", "outcome": "allowed", "reason": "", "status": 200,
        "bytes": 42, "durationMs": 3, "rules": [], "flags": [],
        "artifacts": [], "headers": {"host": "curs:8083", "user-agent": "checker/1.0"},
        "body": "alctf{checkerwrite00000}",
    },
    {
        "at": "2026-10-02T17:22:35.000Z", "ip": "10.65.9.2", "principal": "team",
        "team": "attacker", "service": "curs", "host": "10.65.9.254", "method": "GET",
        "target": "/dashboard", "outcome": "allowed", "reason": "", "status": 200,
        "bytes": 900, "durationMs": 5, "rules": [], "flags": ["alctf{teamread0000000000}"],
        "artifacts": [], "headers": {"host": "10.65.9.254:8083", "user-agent": "curl/8.11.1"},
        "body": "",
    },
    {
        "at": "2026-10-02T17:22:36.000Z", "ip": "10.65.9.2", "principal": "team",
        "team": "attacker", "service": "curs", "host": "10.65.9.254", "method": "GET",
        "target": "/etc/passwd", "outcome": "blocked", "reason": "traversal", "status": None,
        "bytes": 0, "durationMs": 0, "rules": ["traversal"], "flags": [],
        "artifacts": [], "headers": {"host": "10.65.9.254:8083", "user-agent": "curl/8.11.1"},
        "body": "",
    },
]


class MonitorImport(unittest.TestCase):
    def setUp(self):
        self.cfg = cfg_with_networks()
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "curs-monitor.jsonl"
        self.path.write_text("\n".join(json.dumps(r) for r in MONITOR_RECORDS), encoding="utf-8")
        self.report = reqs.load_requests([self.path], self.cfg)

    def tearDown(self):
        self.tmp.cleanup()

    def test_every_monitor_line_becomes_a_request(self):
        self.assertEqual(len(self.report.requests), 3)
        self.assertFalse(any("unparsed" in note for note in self.report.parser_notes))

    def test_principal_is_used_as_the_actor(self):
        self.assertIn("checker", self.report.profiles)
        self.assertIn("team", self.report.profiles)
        self.assertEqual(self.report.profiles["checker"].requests, 1)
        self.assertEqual(self.report.profiles["team"].requests, 2)

    def test_monitor_flags_count_as_reads_for_the_team(self):
        self.assertEqual(self.report.profiles["team"].flag_reads, 1)

    def test_checker_put_counts_as_a_write(self):
        self.assertEqual(self.report.profiles["checker"].flag_writes, 1)

    def test_target_and_query_are_split(self):
        checker = self.report.requests[0]
        self.assertEqual(checker.path, "/flags")
        self.assertEqual(checker.query, "user=alice")
        self.assertEqual(checker.ts, "2026-10-02T17:22:31.000Z")

    def test_monitor_metadata_is_preserved_in_headers(self):
        blocked = self.report.requests[2]
        self.assertEqual(blocked.headers.get("x-monitor-outcome"), "blocked")
        self.assertEqual(blocked.headers.get("x-monitor-reason"), "traversal")
        self.assertEqual(blocked.headers.get("x-monitor-rules"), "traversal")
        self.assertEqual(blocked.headers.get("x-monitor-team"), "attacker")

    def test_route_matrix_separates_checker_write_from_team_read(self):
        by_route = {entry["route"]: entry["actors"] for entry in self.report.route_matrix()}
        self.assertEqual(by_route["PUT /flags"]["checker"]["flag_writes"], 1)
        self.assertEqual(by_route["GET /dashboard"]["team"]["flag_reads"], 1)

    def test_monitor_json_array_is_also_imported(self):
        path = Path(self.tmp.name) / "curs-array.json"
        path.write_text(json.dumps(MONITOR_RECORDS), encoding="utf-8")
        report = reqs.load_requests([path], self.cfg)
        self.assertEqual(len(report.requests), 3)
        self.assertIn("checker", report.profiles)


if __name__ == "__main__":
    unittest.main(verbosity=2)