"""Tests for the settings file, password hashing, the runtime and the embedded web UI.

Run with:  python3 -m unittest discover -s tests -v
"""

from __future__ import annotations

import http.client
import importlib.util
import json
import logging
import sys
import tempfile
import unittest
from pathlib import Path
from urllib.parse import urlencode

from test_unifi_technitium_sync import FakeTechnitium, FakeUnifi, client, uts

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("utsweb", ROOT / "unifi_technitium_web.py")
web = importlib.util.module_from_spec(_spec)
sys.modules["utsweb"] = web
assert _spec.loader is not None
_spec.loader.exec_module(web)

logging.getLogger("unifi-technitium-sync").setLevel(logging.CRITICAL)

BASE_ENV = {
    "UNIFI_URL": "https://udm",
    "UNIFI_API_KEY": "unifi-key",
    "UNIFI_SITE_ID": "site",
    "TECHNITIUM_URL": "http://dns:5380",
    "TECHNITIUM_API_TOKEN": "dns-token",
    "DNS_ZONE": "home.arpa",
}


class EnvFileTests(unittest.TestCase):
    def test_round_trip_preserves_comments_and_order(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "sync.env"
            path.write_text('# head\nexport A=1\nB="two words"\n# C=commented\nD=x\n')
            self.assertEqual(uts.read_env_file(path), {"A": "1", "B": "two words", "D": "x"})
            uts.write_env_file(path, {"B": "3 4", "E": "new", "F": "a=b"})
            lines = path.read_text().splitlines()
            self.assertEqual(lines[0], "# head")
            self.assertEqual(lines[1], "export A=1")
            self.assertEqual(lines[2], 'B="3 4"')
            self.assertIn("# C=commented", lines)
            self.assertIn("E=new", lines)
            self.assertIn("F=a=b", lines)
            self.assertEqual(uts.read_env_file(path), {"A": "1", "B": "3 4", "D": "x", "E": "new", "F": "a=b"})
            self.assertFalse((Path(d) / "sync.env.tmp").exists())

    def test_write_preserves_mode_and_ownership(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "sync.env"
            path.write_text("A=1\n")
            path.chmod(0o660)
            before = path.stat()
            uts.write_env_file(path, {"B": "2"})
            after = path.stat()
            self.assertEqual(after.st_mode & 0o777, 0o660)
            self.assertEqual((after.st_uid, after.st_gid), (before.st_uid, before.st_gid))

    def test_quoting_round_trip(self):
        for value in ['has "quotes"', "back\\slash", "sp ace", "{site_id}", ""]:
            self.assertEqual(uts.parse_env_value(uts.format_env_value(value)), value)


class ConfigMappingTests(unittest.TestCase):
    def test_defaults(self):
        cfg = uts.Config.from_mapping(BASE_ENV)
        self.assertEqual(cfg.unifi_clients_path, uts.DEFAULT_CLIENTS_PATH)
        self.assertEqual(cfg.name_fields, ("name", "hostname"))
        self.assertEqual(cfg.web_listen, "")
        self.assertEqual(cfg.log_level, "INFO")
        self.assertEqual(cfg.name_downgrade_polls, 288)

    def test_validation_errors(self):
        bad = [
            {**BASE_ENV, "DNS_TTL": "abc"},
            {**BASE_ENV, "SYNC_INTERVAL": "5"},
            {**BASE_ENV, "WEB_LISTEN": "nonsense"},
            {**BASE_ENV, "LOG_LEVEL": "LOUD"},
            {**BASE_ENV, "ALLOWED_NETWORKS": "10.0.0.0/8,notacidr"},
            {k: v for k, v in BASE_ENV.items() if k != "DNS_ZONE"},
        ]
        for mapping in bad:
            with self.assertRaises(ValueError):
                uts.Config.from_mapping(mapping)

    def test_parse_listen(self):
        self.assertEqual(uts.parse_listen("0.0.0.0:8089"), ("0.0.0.0", 8089))
        self.assertEqual(uts.parse_listen(":80"), ("0.0.0.0", 80))
        self.assertEqual(uts.parse_listen("127.0.0.1:0"), ("127.0.0.1", 0))
        with self.assertRaises(ValueError):
            uts.parse_listen("8089")

    def test_settings_schema_matches_config(self):
        keys = {spec.key for spec in uts.SETTINGS}
        for name in ("UNIFI_URL", "DNS_ZONE", "NAME_DOWNGRADE_POLLS", "WEB_LISTEN", "WEB_PASSWORD_HASH", "LOG_LEVEL"):
            self.assertIn(name, keys)
        mapping = {spec.key: spec.default for spec in uts.SETTINGS if spec.default}
        mapping.update(BASE_ENV)
        uts.Config.from_mapping(mapping)  # every documented default is valid


class PasswordTests(unittest.TestCase):
    def test_hash_and_verify(self):
        digest = uts.hash_password("correct horse", iterations=1000)
        self.assertTrue(digest.startswith("pbkdf2_sha256$1000$"))
        self.assertTrue(uts.verify_password(digest, "correct horse"))
        self.assertFalse(uts.verify_password(digest, "wrong"))
        self.assertFalse(uts.verify_password("garbage", "correct horse"))
        self.assertFalse(uts.verify_password("", "correct horse"))


def make_runtime(tmp: Path, poll, extra_env: dict | None = None, tech: FakeTechnitium | None = None):
    env_path = tmp / "sync.env"
    lines = [f"{k}={v}" for k, v in BASE_ENV.items()] + [f"STATE_FILE={tmp / 'state.json'}", "WEB_LISTEN=127.0.0.1:0"]
    for key, value in (extra_env or {}).items():
        lines.append(f"{key}={value}")
    env_path.write_text("\n".join(lines) + "\n")
    config = uts.Config.from_mapping(uts.read_env_file(env_path))
    technitium = tech or FakeTechnitium()
    def factory(cfg, dry):
        technitium.dry_run = dry
        return FakeUnifi(poll), technitium

    runtime = uts.Runtime(config, env_path, client_factory=factory)
    return runtime, env_path, technitium


class RuntimeTests(unittest.TestCase):
    def test_run_sync_records_history_and_actions(self):
        with tempfile.TemporaryDirectory() as d:
            runtime, _, tech = make_runtime(Path(d), [client("aa0000000001", "10.0.0.1", name="tv")])
            dry = runtime.run_sync(dry_run=True)
            self.assertTrue(dry.dry_run)
            self.assertEqual([a["op"] for a in dry.actions], ["ADD"])
            self.assertEqual(len(runtime.history), 0, "dry runs are not history")
            result = runtime.run_sync()
            self.assertEqual(result.adds, 1)
            self.assertEqual(result.error, None)
            self.assertEqual(len(runtime.history), 1)
            self.assertEqual(result.to_dict()["adds"], 1)
            runtime.client_factory = lambda cfg, dry: (_ for _ in ()).throw(RuntimeError("boom"))
            failed = runtime.run_sync()
            self.assertIn("boom", failed.error or "")
            self.assertEqual(runtime.history[0].error, failed.error)

    def test_apply_settings_persists_and_swaps(self):
        with tempfile.TemporaryDirectory() as d:
            runtime, env_path, _ = make_runtime(Path(d), [])
            runtime.apply_settings({"DNS_TTL": "600", "CREATE_PTR": "true"})
            self.assertEqual(runtime.current_config().dns_ttl, 600)
            self.assertTrue(runtime.current_config().create_ptr)
            self.assertEqual(uts.read_env_file(env_path)["DNS_TTL"], "600")
            with self.assertRaises(ValueError):
                runtime.apply_settings({"DNS_TTL": "nope"})
            self.assertEqual(uts.read_env_file(env_path)["DNS_TTL"], "600")
            self.assertEqual(runtime.current_config().dns_ttl, 600)
            self.assertTrue(runtime.wake.is_set())


class WebServerTests(unittest.TestCase):
    def start(self, password: str | None = None):
        self.tmp = tempfile.TemporaryDirectory()
        extra = {"WEB_PASSWORD_HASH": uts.hash_password(password, iterations=1000)} if password else {}
        poll = [client("aa0000000001", "10.0.0.1", name="tv")]
        self.runtime, self.env_path, self.tech = make_runtime(Path(self.tmp.name), poll, extra)
        self.server = web.start(self.runtime, uts)
        self.assertIsNotNone(self.server)
        self.port = self.server.server_address[1]

    def tearDown(self):
        if getattr(self, "server", None):
            self.server.shutdown()
            self.server.server_close()
        if getattr(self, "tmp", None):
            self.tmp.cleanup()

    def req(self, method, path, body=None, headers=None, cookie=None, form=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        hdrs = dict(headers or {})
        if cookie:
            hdrs["Cookie"] = cookie
        data = None
        if form is not None:
            data = urlencode(form).encode()
            hdrs["Content-Type"] = "application/x-www-form-urlencoded"
        elif body is not None:
            data = json.dumps(body).encode()
            hdrs["Content-Type"] = "application/json"
        conn.request(method, path, body=data, headers=hdrs)
        response = conn.getresponse()
        raw = response.read()
        conn.close()
        return response, raw

    def login(self, password):
        response, _ = self.req("POST", "/login", form={"password": password})
        self.assertEqual(response.status, 303)
        self.assertEqual(response.getheader("Location"), "/")
        cookie = response.getheader("Set-Cookie")
        self.assertIn("HttpOnly", cookie)
        self.assertIn("SameSite=Strict", cookie)
        token = cookie.split(";")[0]
        _, raw = self.req("GET", "/api/session", cookie=token)
        return token, json.loads(raw)["csrf"]

    def test_loopback_without_password_needs_no_login(self):
        self.start()
        response, raw = self.req("GET", "/")
        self.assertEqual(response.status, 200)
        self.assertIn(b"UniFi", raw)
        self.assertIn("text/html", response.getheader("Content-Type"))
        _, raw = self.req("GET", "/api/session")
        session = json.loads(raw)
        self.assertFalse(session["auth"])
        response, _ = self.req("POST", "/api/sync")
        self.assertEqual(response.status, 403, "CSRF token still required")
        response, raw = self.req("POST", "/api/sync", headers={"X-CSRF-Token": session["csrf"]})
        self.assertEqual(response.status, 200)
        self.assertTrue(self.runtime.take_sync_request())

    def test_non_loopback_without_password_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            runtime, _, _ = make_runtime(Path(d), [], {"WEB_LISTEN": "0.0.0.0:0"})
            self.assertIsNone(web.start(runtime, uts))

    def test_login_flow_and_api(self):
        self.start("correct horse battery")
        response, _ = self.req("GET", "/")
        self.assertEqual(response.status, 303)
        self.assertEqual(response.getheader("Location"), "/login")
        response, _ = self.req("GET", "/api/status")
        self.assertEqual(response.status, 401)
        response, raw = self.req("GET", "/login")
        self.assertEqual(response.status, 200)
        self.assertIn(b"Sign in", raw)
        response, _ = self.req("POST", "/login", form={"password": "wrong"})
        self.assertEqual(response.getheader("Location"), "/login?error=1")
        cookie, csrf = self.login("correct horse battery")

        response, raw = self.req("GET", "/api/status", cookie=cookie)
        self.assertEqual(response.status, 200)
        status = json.loads(raw)
        self.assertEqual(status["version"], uts.VERSION)
        self.assertEqual(status["config"]["zone"], "home.arpa")
        self.assertTrue(status["config"]["config_writable"])

        response, raw = self.req("POST", "/api/dry-run", cookie=cookie, headers={"X-CSRF-Token": csrf})
        self.assertEqual(response.status, 200)
        result = json.loads(raw)
        self.assertTrue(result["dry_run"])
        self.assertEqual([a["name"] for a in result["actions"]], ["tv.home.arpa"])
        self.assertEqual(self.tech.log, [], "dry run must not write")

        response, _ = self.req("POST", "/api/config", cookie=cookie, headers={"X-CSRF-Token": csrf},
                               body={"values": {"DNS_TTL": "600", "UNIFI_API_KEY": ""}})
        self.assertEqual(response.status, 200)
        self.assertEqual(uts.read_env_file(self.env_path)["DNS_TTL"], "600")
        self.assertEqual(uts.read_env_file(self.env_path)["UNIFI_API_KEY"], "unifi-key", "blank secret keeps the old one")
        self.assertEqual(self.runtime.current_config().dns_ttl, 600)

        response, raw = self.req("POST", "/api/config", cookie=cookie, headers={"X-CSRF-Token": csrf},
                               body={"values": {"DNS_TTL": "x"}})
        self.assertEqual(response.status, 400)
        self.assertIn("DNS_TTL", json.loads(raw)["error"])
        self.assertEqual(self.runtime.current_config().dns_ttl, 600)
        response, _ = self.req("POST", "/api/config", cookie=cookie, headers={"X-CSRF-Token": csrf},
                               body={"values": {"NOPE": "1"}})
        self.assertEqual(response.status, 400)
        response, _ = self.req("POST", "/api/config", cookie=cookie, headers={"X-CSRF-Token": "bad"},
                               body={"values": {"DNS_TTL": "700"}})
        self.assertEqual(response.status, 403)

        _, raw = self.req("GET", "/api/config", cookie=cookie)
        config = json.loads(raw)
        by_key = {s["key"]: s for s in config["settings"]}
        self.assertEqual(by_key["UNIFI_API_KEY"]["value"], "")
        self.assertTrue(by_key["UNIFI_API_KEY"]["set"])
        self.assertEqual(by_key["DNS_TTL"]["value"], "600")
        self.assertNotIn("unifi-key", raw.decode())
        self.assertNotIn("dns-token", raw.decode())

        self.runtime.run_sync()
        _, raw = self.req("GET", "/api/records", cookie=cookie)
        records = json.loads(raw)
        self.assertEqual([r["name"] for r in records["records"]], ["tv.home.arpa"])
        self.assertEqual(records["records"][0]["field"], "name")

        _, raw = self.req("GET", "/api/log", cookie=cookie)
        self.assertIn("lines", json.loads(raw))

        response, _ = self.req("POST", "/logout", cookie=cookie, headers={"X-CSRF-Token": csrf})
        self.assertEqual(response.status, 200)
        response, _ = self.req("GET", "/api/status", cookie=cookie)
        self.assertEqual(response.status, 401)

    def test_password_change(self):
        self.start("oldpassword1")
        cookie, csrf = self.login("oldpassword1")
        response, _ = self.req("POST", "/api/password", cookie=cookie, headers={"X-CSRF-Token": csrf},
                               body={"current": "nope", "new": "newpassword2"})
        self.assertEqual(response.status, 403)
        response, _ = self.req("POST", "/api/password", cookie=cookie, headers={"X-CSRF-Token": csrf},
                               body={"current": "oldpassword1", "new": "short"})
        self.assertEqual(response.status, 400)
        response, _ = self.req("POST", "/api/password", cookie=cookie, headers={"X-CSRF-Token": csrf},
                               body={"current": "oldpassword1", "new": "newpassword2"})
        self.assertEqual(response.status, 200)
        response, _ = self.req("GET", "/api/status", cookie=cookie)
        self.assertEqual(response.status, 401, "sessions are invalidated")
        response, _ = self.req("POST", "/login", form={"password": "oldpassword1"})
        self.assertEqual(response.getheader("Location"), "/login?error=1")
        self.login("newpassword2")
        self.assertTrue(uts.verify_password(uts.read_env_file(self.env_path)["WEB_PASSWORD_HASH"], "newpassword2"))


if __name__ == "__main__":
    unittest.main()
