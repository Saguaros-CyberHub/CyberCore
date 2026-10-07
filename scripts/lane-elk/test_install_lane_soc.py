"""Offline integration tests against an in-process HTTP server; never use a lane."""
import contextlib
import copy
import io
import json
import os
from pathlib import Path
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest import mock
import urllib.parse

import install_lane_soc as soc
import build_pasteable


def caps(name, kind="keyword"):
    return {name: {kind: {"type": kind, "searchable": True, "aggregatable": True}}}


class MockElastic:
    def __init__(self):
        self.version = "7.17.6"
        self.security = False
        self.encryption = True
        self.permission = True
        self.rules = {}
        self.objects = {}
        self.requests = []
        self.signal_index = False
        self.fail_rule_suffix = None
        self.fail_bulk = False
        self.fields = {}
        for name, kind in [("@timestamp", "date"), ("event.code", "keyword"), ("host.name", "keyword"), ("winlog.channel", "keyword"), ("source.ip", "ip"), ("process.command_line", "wildcard")]:
            self.fields.update(caps(name, kind))
        state = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def handle_request(self):
                length = int(self.headers.get("Content-Length", 0))
                body = json.loads(self.rfile.read(length)) if length else None
                state.requests.append((self.command, self.path, body, dict(self.headers)))
                parsed = urllib.parse.urlsplit(self.path)
                path = parsed.path
                if path.startswith("/s/"):
                    path = "/" + path.split("/", 3)[3]
                status, result = state.respond(self.command, path, urllib.parse.parse_qs(parsed.query), body)
                payload = json.dumps(result).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            do_GET = do_POST = do_PATCH = handle_request

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = "http://127.0.0.1:" + str(self.server.server_port)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *args):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()

    def respond(self, method, path, query, body):
        if path in ("/", "/api/status"):
            return 200, {"version": {"number": self.version}}
        if path.endswith("/_field_caps"):
            return 200, {"fields": self.fields}
        if path.endswith("/_search"):
            return 200, {"hits": {"total": {"value": 25}}, "aggregations": {"coverage": {"buckets": {key: {"doc_count": 5 if key != "sysmon_process_access" else 0} for key in body["aggs"]["coverage"]["filters"]["filters"]}}, "hosts": {"buckets": []}, "last_event": {"value_as_string": "2026-09-16T12:00:00Z"}}}
        if path == "/_xpack":
            return 200, {"features": {"security": {"enabled": self.security}}}
        if path == "/_security/user/_has_privileges":
            return 200, {"has_all_requested": self.permission}
        if path == "/api/detection_engine/privileges":
            return 200, {"is_authenticated": True, "has_encryption_key": self.encryption, "has_all_requested": self.permission}
        if path == "/api/detection_engine/index":
            if method == "POST":
                self.signal_index = True
            return (200, {"name": ".siem-signals-default"}) if self.signal_index else (404, {"message": "index for this space does not exist"})
        if path == "/api/detection_engine/rules":
            rule_id = query["rule_id"][0] if method == "GET" else body["rule_id"]
            if method == "GET":
                return (200, self.rules[rule_id]) if rule_id in self.rules else (404, {"message": "rule not found"})
            if self.fail_rule_suffix and rule_id.endswith(self.fail_rule_suffix):
                return 400, {"message": "intentional test failure"}
            if method == "POST":
                self.rules[rule_id] = copy.deepcopy(body)
            elif method == "PATCH":
                self.rules[rule_id].update(copy.deepcopy(body))
            return 200, self.rules[rule_id]
        if path == "/api/saved_objects/_bulk_get":
            return 200, {"saved_objects": [self.objects.get((o["type"], o["id"]), dict(o, error={"statusCode": 404})) for o in body]}
        if path == "/api/saved_objects/_bulk_create":
            if self.fail_bulk:
                return 200, {"saved_objects": [dict(o, error={"statusCode": 403, "message": "denied"}) for o in body]}
            for obj in body:
                self.objects[(obj["type"], obj["id"])] = copy.deepcopy(obj)
            return 200, {"saved_objects": body}
        return 500, {"message": "Unexpected mock route: " + method + " " + path}


class InstallerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.output = Path(self.temp.name)
        self.env = mock.patch.dict(os.environ, {key: "" for key in os.environ if key.startswith("LANE_")})
        self.env.start()

    def tearDown(self):
        self.env.stop()
        self.temp.cleanup()

    def run_installer(self, server=None, *extra):
        args = ["--output-dir", str(self.output)]
        if server:
            args += ["--kibana-url", server.url, "--elasticsearch-url", server.url]
        args += list(extra)
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            return soc.run(soc.parser().parse_args(args))

    def report(self):
        return json.loads((self.output / "install-report.json").read_text())

    def test_offline_bundle_references_resolve_and_rules_are_disabled(self):
        self.assertEqual(self.run_installer(None, "--export-only"), 0)
        objects = [json.loads(line) for line in (self.output / "saved-objects.ndjson").read_text(encoding="utf-8").splitlines()]
        identities = {(o["type"], o["id"]) for o in objects}
        self.assertEqual(len(identities), len(objects))
        for obj in objects:
            for ref in obj["references"]:
                self.assertIn((ref["type"], ref["id"]), identities)
        rules = [json.loads(line) for line in (self.output / "detection-rules.ndjson").read_text().splitlines()]
        self.assertEqual(len(rules), 15)
        self.assertTrue(all(r["enabled"] is False for r in rules))
        self.assertTrue(all("caldera" not in r["query"].lower() and "atomic" not in r["query"].lower() for r in rules))

    def test_security_off_installs_hunts_without_creating_native_rules(self):
        with MockElastic() as server:
            self.assertEqual(self.run_installer(server), 0)
            self.assertGreater(len(server.objects), 30)
            self.assertEqual(server.rules, {})
            self.assertFalse(any("/api/detection_engine/" in path for _, path, _, _ in server.requests))
        self.assertIn("security is disabled", self.report()["detection_status"])
        self.assertTrue(any("sysmon_process_access" in w for w in self.report()["warnings"]))

    def test_unsupported_version_fails_before_any_remote_mutation(self):
        with MockElastic() as server:
            server.version = "8.17.0"
            with self.assertRaisesRegex(soc.InstallError, "unsupported"):
                self.run_installer(server)
            self.assertTrue(all(method == "GET" for method, _, _, _ in server.requests))

    def test_enabled_rules_with_spaces_and_preserved_user_tuning_on_rerun(self):
        with MockElastic() as server:
            server.security = True
            self.assertEqual(self.run_installer(server, "--space", "lane-blue"), 0)
            self.assertEqual(len(server.rules), 15)
            self.assertTrue(all(rule["enabled"] for rule in server.rules.values()))
            first = next(iter(server.rules.values()))
            first.update(query="user.name: approved-tuning", interval="10m", enabled=False, exceptions_list=[{"id": "existing-exception"}], actions=[{"id": "existing-connector"}])
            self.assertEqual(self.run_installer(server, "--space", "lane-blue"), 0)
            self.assertEqual(first["query"], "user.name: approved-tuning")
            self.assertEqual(first["interval"], "10m")
            self.assertFalse(first["enabled"])
            self.assertEqual(first["actions"], [{"id": "existing-connector"}])
            self.assertTrue(all(path.startswith("/s/lane-blue/") for _, path, _, _ in server.requests if "/api/detection_engine" in path or "/api/saved_objects" in path))
            self.assertIn("/s/lane-blue/app/", self.report()["dashboard_url"])
            alert_pattern = server.objects[("index-pattern", soc.PREFIX + "-alerts")]
            self.assertEqual(alert_pattern["attributes"]["title"], ".siem-signals-lane-blue")

    def test_explicit_rule_state_is_honored_and_off_leaves_state_alone(self):
        with MockElastic() as server:
            server.security = True
            self.run_installer(server, "--rules", "disabled")
            self.assertTrue(all(not r["enabled"] for r in server.rules.values()))
            self.run_installer(server, "--rules", "enabled")
            self.assertTrue(all(r["enabled"] for r in server.rules.values()))
            previous = copy.deepcopy(server.rules)
            self.run_installer(server, "--rules", "off")
            self.assertEqual(server.rules, previous)

    def test_requested_rules_unavailable_returns_partial_status_but_keeps_dashboard(self):
        with MockElastic() as server:
            self.assertEqual(self.run_installer(server, "--rules", "enabled"), 2)
            self.assertTrue(server.objects)
            self.assertFalse(server.rules)

    def test_missing_encryption_key_does_not_attempt_rule_creation(self):
        with MockElastic() as server:
            server.security, server.encryption = True, False
            self.assertEqual(self.run_installer(server), 0)
            self.assertFalse(server.rules)
            self.assertIn("has_encryption_key", self.report()["detection_status"])

    def test_partial_rule_failure_is_reported_and_dashboard_still_installs(self):
        with MockElastic() as server:
            server.security = True
            server.fail_rule_suffix = "powershell-transfer"
            self.assertEqual(self.run_installer(server), 2)
            self.assertEqual(len(server.rules), 1)
            self.assertEqual(len(self.report()["rules"]), 1)
            self.assertTrue(self.report()["partial_failure"])
            self.assertTrue(server.objects)

    def test_unowned_object_is_not_overwritten(self):
        with MockElastic() as server:
            obj = {"type": "dashboard", "id": soc.DASHBOARD_ID, "attributes": {"description": "Someone else's dashboard"}}
            server.objects[(obj["type"], obj["id"])] = obj
            with self.assertRaisesRegex(soc.InstallError, "unowned"):
                self.run_installer(server)
            self.assertFalse(any("_bulk_create" in path for _, path, _, _ in server.requests))

    def test_unowned_rule_is_not_overwritten(self):
        with MockElastic() as server:
            server.security = True
            rule = soc.rule_catalog("winlogbeat-*")[0]
            rule["meta"] = {"managed_by": "another author"}
            server.rules[rule["rule_id"]] = copy.deepcopy(rule)
            self.assertEqual(self.run_installer(server), 2)
            self.assertEqual(server.rules[rule["rule_id"]], rule)

    def test_bulk_child_errors_fail_even_when_http_status_is_200(self):
        with MockElastic() as server:
            server.fail_bulk = True
            with self.assertRaisesRegex(soc.InstallError, "import was incomplete"):
                self.run_installer(server)

    def test_credentials_are_sent_but_not_written_to_artifacts(self):
        with MockElastic() as server, mock.patch.dict(os.environ, {"LANE_ELK_API_KEY": "test-secret-not-real"}):
            self.run_installer(server)
            self.assertTrue(all(headers.get("Authorization") == "ApiKey test-secret-not-real" for _, _, _, headers in server.requests))
        self.assertTrue(all("test-secret-not-real" not in path.read_text(encoding="utf-8") for path in self.output.iterdir()))

    def test_raw_windows_fields_and_numeric_ip_query_types(self):
        rule = soc.rule_catalog("winlogbeat-*")[-1]
        self.assertNotIn('"-"', rule["query"])
        raw = soc.rule_catalog("winlogbeat-*", "winlog.event_data.IpAddress")[-1]
        self.assertIn('"-"', raw["query"])
        self.assertEqual(raw["threshold"]["field"], ["winlog.event_data.IpAddress"])
        self.assertIn("NewProcessName", soc.process_name("cmd.exe"))
        log_clear = next(rule for rule in soc.rule_catalog("winlogbeat-*") if rule["rule_id"].endswith("log-cleared"))
        self.assertIn("Microsoft-Windows-Eventlog", log_clear["query"])
        fields = caps("winlog.event_data.IpAddress")
        self.assertEqual(soc.field_choice(fields, "source.ip", "winlog.event_data.IpAddress"), "winlog.event_data.IpAddress")

    def test_pasteable_matches_source(self):
        path = Path(__file__).with_name("install-lane-soc.sh")
        self.assertEqual(path.read_text(encoding="utf-8"), build_pasteable.content())

    def test_overbroad_source_pattern_is_refused(self):
        for pattern in ("*", ".siem-*", "_all", "winlogbeat-*,.siem-*", "winlogbeat-*/_delete_by_query"):
            with self.subTest(pattern=pattern), self.assertRaises(soc.InstallError):
                self.run_installer(None, "--index", pattern, "--export-only")


if __name__ == "__main__":
    unittest.main()
