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
import threading
import time
from types import SimpleNamespace
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



class SlowCore:
    """Stands in for the daemon module: a password check that takes a while."""

    def __init__(self, delay: float = 0.5):
        self.delay, self.calls, self.active, self.max_active = delay, 0, 0, 0
        self.guard = threading.Lock()

    def verify_password(self, stored: str, password: str) -> bool:
        with self.guard:
            self.calls += 1
            self.active += 1
            self.max_active = max(self.max_active, self.active)
        time.sleep(self.delay)
        with self.guard:
            self.active -= 1
        return password == "right"


class StubRuntime:
    def password_hash(self) -> str:
        return "stored-hash"

    def current_config(self):
        return SimpleNamespace(web_tls_cert=None)


def burst(state, attempts):
    """Start every (password, address) attempt at the same moment; return the outcomes."""
    barrier = threading.Barrier(len(attempts))
    results = [None] * len(attempts)

    def go(i, password, address):
        barrier.wait()
        results[i] = state.login(password, address)[0]

    threads = [threading.Thread(target=go, args=(i, pw, ip)) for i, (pw, ip) in enumerate(attempts)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(10)
    return results


class LoginThrottleTests(unittest.TestCase):
    """Parallel guessing must not bypass the limit (security review, High)."""

    def test_parallel_guesses_from_one_address_get_one_password_check(self):
        core = SlowCore()
        state = web.WebState(StubRuntime(), core)
        results = burst(state, [("wrong", "10.9.9.9")] * 25)
        self.assertEqual(core.calls, 1)
        self.assertEqual(results.count("denied"), 1)
        self.assertEqual(results.count("throttled"), 24)

    def test_limit_per_address_then_no_more_password_checks(self):
        core = SlowCore(delay=0)
        state = web.WebState(StubRuntime(), core)
        outcomes = [state.login("wrong", "10.9.9.9")[0] for _ in range(8)]
        self.assertEqual(outcomes, ["denied"] * web.LOGIN_MAX_FAILURES + ["throttled"] * 3)
        self.assertEqual(core.calls, web.LOGIN_MAX_FAILURES)
        self.assertEqual(state.login("right", "10.9.9.9")[0], "throttled", "even the right password waits")
        self.assertEqual(state.login("right", "10.9.9.10")[0], "ok", "other addresses are unaffected")

    def test_success_resets_and_old_failures_expire(self):
        core = SlowCore(delay=0)
        state = web.WebState(StubRuntime(), core)
        for _ in range(web.LOGIN_MAX_FAILURES - 1):
            state.login("wrong", "10.9.9.9")
        outcome, token = state.login("right", "10.9.9.9")
        self.assertEqual(outcome, "ok")
        self.assertTrue(token)
        self.assertNotIn("10.9.9.9", state.failures)
        for _ in range(web.LOGIN_MAX_FAILURES):
            state.login("wrong", "10.9.9.8")
        self.assertEqual(state.login("wrong", "10.9.9.8")[0], "throttled")
        state.failures["10.9.9.8"] = [t - web.LOGIN_WINDOW for t in state.failures["10.9.9.8"]]
        self.assertEqual(state.login("wrong", "10.9.9.8")[0], "denied")
        self.assertEqual(len(state.failures["10.9.9.8"]), 1, "expired failures are pruned")

    def test_password_checks_are_capped_across_addresses(self):
        core = SlowCore()
        state = web.WebState(StubRuntime(), core)
        results = burst(state, [("wrong", f"10.9.8.{i}") for i in range(12)])
        self.assertLessEqual(core.max_active, web.AUTH_CONCURRENCY)
        self.assertLess(core.calls, 12)
        self.assertEqual(results.count("denied"), core.calls)
        self.assertEqual(results.count("throttled"), 12 - core.calls)


class InsecureTransportTests(unittest.TestCase):
    """Plain HTTP on a network address needs an explicit opt-in (security review, High)."""

    def runtime(self, d, **extra):
        env = {"WEB_LISTEN": "0.0.0.0:0", "WEB_PASSWORD_HASH": uts.hash_password("pw123456", iterations=1000)}
        env.update(extra)
        return make_runtime(Path(d), [], env)[0]

    def test_network_address_without_tls_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertIsNone(web.start(self.runtime(d), uts))

    def test_explicit_override_starts_and_warns_on_the_page(self):
        with tempfile.TemporaryDirectory() as d:
            server = web.start(self.runtime(d, WEB_ALLOW_INSECURE_LAN="true"), uts)
            self.assertIsNotNone(server)
            try:
                state = server.RequestHandlerClass.state
                self.assertTrue(state.insecure_transport)
                self.assertIn('"insecure": true', web.render_page(state))
                conn = http.client.HTTPConnection("127.0.0.1", server.server_address[1], timeout=5)
                conn.request("GET", "/login")
                self.assertEqual(conn.getresponse().status, 200)
                conn.close()
            finally:
                server.shutdown()
                server.server_close()

    def test_loopback_is_not_flagged(self):
        with tempfile.TemporaryDirectory() as d:
            server = web.start(self.runtime(d, WEB_LISTEN="127.0.0.1:0"), uts)
            try:
                self.assertFalse(server.RequestHandlerClass.state.insecure_transport)
                self.assertIn('"insecure": false', web.render_page(server.RequestHandlerClass.state))
            finally:
                server.shutdown()
                server.server_close()


# --- 1.6.0: fixes for the remaining review findings ------------------------------
import shutil  # noqa: E402
import socket  # noqa: E402
import ssl  # noqa: E402
import subprocess  # noqa: E402


class SettingsConcurrencyTests(unittest.TestCase):
    def test_parallel_saves_keep_every_change(self):
        with tempfile.TemporaryDirectory() as d:
            runtime, env_path, _ = make_runtime(Path(d), [])
            changes = [("DNS_TTL", "301"), ("SYNC_INTERVAL", "61"), ("STALE_AFTER", "3601"),
                       ("REQUEST_TIMEOUT", "21"), ("IP_STABLE_POLLS", "3"), ("NAME_STABLE_POLLS", "4"),
                       ("EXCLUDED_NAMES", "x1"), ("ALLOWED_NETWORKS", "10.0.0.0/8")]
            barrier = threading.Barrier(len(changes))
            errors = []

            def save(key, value):
                barrier.wait()
                try:
                    runtime.apply_settings({key: value})
                except Exception as exc:  # noqa: BLE001
                    errors.append(exc)

            threads = [threading.Thread(target=save, args=change) for change in changes]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(10)
            self.assertEqual(errors, [])
            saved = uts.read_env_file(env_path)
            for key, value in changes:
                self.assertEqual(saved[key], value, key)
            config = runtime.current_config()
            self.assertEqual((config.dns_ttl, config.sync_interval, config.request_timeout), (301, 61, 21))
            self.assertEqual(list(Path(d).glob("*.tmp")), [])

    def test_settings_lock_is_reentrant_and_excludes_other_processes(self):
        probe = ("import fcntl, os, sys; fd = os.open(sys.argv[1], os.O_RDONLY); "
                 "fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)")
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "sync.env"
            path.write_text("A=1\n")
            with uts.settings_lock(path):
                with uts.settings_lock(path):  # nested in one thread: must not deadlock
                    pass
                busy = subprocess.run([sys.executable, "-c", probe, d], capture_output=True)
                self.assertNotEqual(busy.returncode, 0, "another process must not get the lock meanwhile")
            free = subprocess.run([sys.executable, "-c", probe, d], capture_output=True)
            self.assertEqual(free.returncode, 0)


class LiveServerCase(unittest.TestCase):
    """Starts the real web UI on 127.0.0.1 for each test."""

    extra_env: dict = {}

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.runtime, self.env_path, _ = make_runtime(Path(self.tmp.name), [], dict(self.extra_env))
        self.server = web.start(self.runtime, uts)
        self.port = self.server.server_address[1]
        self.host = f"127.0.0.1:{self.port}"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.tmp.cleanup()

    def call(self, method, path, headers=None, body=None, cookie=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        hdrs = {"Host": self.host}
        if cookie:
            hdrs["Cookie"] = cookie
        hdrs.update(headers or {})
        data = None
        if isinstance(body, dict):
            data = json.dumps(body).encode()
            hdrs["Content-Type"] = "application/json"
        elif isinstance(body, str):
            data = body.encode()
            hdrs["Content-Type"] = "application/x-www-form-urlencoded"
        conn.request(method, path, body=data, headers=hdrs)
        response = conn.getresponse()
        raw = response.read()
        conn.close()
        try:
            parsed = json.loads(raw) if raw else None
        except ValueError:
            parsed = raw
        return response.status, parsed, response


class HostAndOriginTests(LiveServerCase):
    """DNS rebinding: only our own host names may address the UI (review finding)."""

    extra_env = {"WEB_ALLOWED_HOSTS": "dns.example"}

    def test_foreign_host_names_are_refused(self):
        for host in ("evil.example", f"evil.example:{self.port}", "127.0.0.1.evil.example", ""):
            self.assertEqual(self.call("GET", "/api/session", {"Host": host})[0], 403, repr(host))
        for host in (self.host, f"localhost:{self.port}", "dns.example", f"[::1]:{self.port}"):
            self.assertEqual(self.call("GET", "/api/session", {"Host": host})[0], 200, host)

    def test_cross_origin_posts_are_refused(self):
        csrf = self.call("GET", "/api/session")[1]["csrf"]
        for origin, expected in (("http://evil.example", 403), ("null", 403), (f"http://{self.host}", 200)):
            status = self.call("POST", "/api/sync", {"X-CSRF-Token": csrf, "Origin": origin})[0]
            self.assertEqual(status, expected, origin)

    def raw(self, text):
        with socket.create_connection(("127.0.0.1", self.port), timeout=5) as sock:
            sock.sendall(text.encode())
            return sock.recv(200)

    def test_invalid_or_oversized_bodies_are_rejected(self):
        csrf = self.call("GET", "/api/session")[1]["csrf"]
        def post(length):
            return self.raw(f"POST /api/config HTTP/1.1\r\nHost: {self.host}\r\nX-CSRF-Token: {csrf}\r\n"
                            f"Content-Length: {length}\r\n\r\n")
        self.assertIn(b" 400 ", post("-5"))
        self.assertIn(b" 400 ", post("abc"))
        self.assertIn(b" 413 ", post(str(web.MAX_BODY + 1)))


class ConnectionLimitTests(unittest.TestCase):
    """Idle or slow connections cannot exhaust the server (review finding)."""

    def test_connection_cap_and_idle_timeout(self):
        saved = (web.MAX_CONNECTIONS, web.Handler.timeout)
        web.MAX_CONNECTIONS, web.Handler.timeout = 2, 1
        try:
            with tempfile.TemporaryDirectory() as d:
                runtime, _, _ = make_runtime(Path(d), [])
                server = web.start(runtime, uts)
                port = server.server_address[1]
                try:
                    idle = [socket.create_connection(("127.0.0.1", port), timeout=5) for _ in range(2)]
                    time.sleep(0.3)
                    with socket.create_connection(("127.0.0.1", port), timeout=5) as third:
                        self.assertIn(b"503", third.recv(100))
                    for sock in idle:
                        self.assertEqual(sock.recv(100), b"", "an idle connection is closed after the timeout")
                        sock.close()
                    time.sleep(0.3)
                    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                    conn.request("GET", "/api/session")
                    self.assertEqual(conn.getresponse().status, 200)
                    conn.close()
                finally:
                    server.shutdown()
                    server.server_close()
        finally:
            web.MAX_CONNECTIONS, web.Handler.timeout = saved

    @unittest.skipUnless(shutil.which("openssl"), "openssl is not installed")
    def test_stalled_tls_handshake_does_not_block_other_clients(self):
        with tempfile.TemporaryDirectory() as d:
            cert, key = Path(d) / "cert.pem", Path(d) / "key.pem"
            subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                            "-subj", "/CN=localhost", "-keyout", str(key), "-out", str(cert)],
                           check=True, capture_output=True)
            runtime, _, _ = make_runtime(Path(d), [], {"WEB_TLS_CERT": str(cert), "WEB_TLS_KEY": str(key)})
            server = web.start(runtime, uts)
            port = server.server_address[1]
            stalled = socket.create_connection(("127.0.0.1", port), timeout=5)  # never says hello
            try:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                started = time.monotonic()
                conn = http.client.HTTPSConnection("127.0.0.1", port, timeout=5, context=context)
                conn.request("GET", "/api/session")
                self.assertEqual(conn.getresponse().status, 200)
                conn.close()
                self.assertLess(time.monotonic() - started, 3)
            finally:
                stalled.close()  # first, so a regression fails fast instead of hanging shutdown()
                server.shutdown()
                server.server_close()


class SessionAndReauthTests(LiveServerCase):
    PASSWORD = "correct horse battery"
    extra_env = {"WEB_PASSWORD_HASH": uts.hash_password(PASSWORD, iterations=1000)}

    def setUp(self):
        super().setUp()
        status, _, response = self.call("POST", "/login", body=urlencode({"password": self.PASSWORD}))
        self.assertEqual(status, 303)
        self.cookie = response.getheader("Set-Cookie").split(";")[0]
        self.csrf = self.call("GET", "/api/session", cookie=self.cookie)[1]["csrf"]

    def post(self, path, body):
        return self.call("POST", path, {"X-CSRF-Token": self.csrf}, body, self.cookie)

    def save(self, values, password=None):
        body = {"values": values}
        if password is not None:
            body["current_password"] = password
        return self.post("/api/config", body)

    def test_password_changed_from_the_cli_ends_existing_sessions(self):
        self.assertEqual(self.call("GET", "/api/status", cookie=self.cookie)[0], 200)
        uts.write_env_file(self.env_path, {"WEB_PASSWORD_HASH": uts.hash_password("a new password", iterations=1000)})
        self.assertEqual(self.call("GET", "/api/status", cookie=self.cookie)[0], 401)

    def test_sensitive_settings_need_the_current_password(self):
        status, data, _ = self.save({"TECHNITIUM_URL": "http://attacker.example:8000"})
        self.assertEqual((status, data["needs_password"]), (403, ["TECHNITIUM_URL"]))
        self.assertEqual(self.save({"TECHNITIUM_URL": "http://attacker.example:8000"}, "wrong")[0], 403)
        self.assertEqual(uts.read_env_file(self.env_path)["TECHNITIUM_URL"], "http://dns:5380")
        self.assertEqual(self.save({"TECHNITIUM_URL": "http://dns2:5380"}, self.PASSWORD)[0], 200)
        self.assertEqual(self.runtime.current_config().technitium_url, "http://dns2:5380")

    def test_ordinary_settings_need_no_password(self):
        self.assertEqual(self.save({"DNS_TTL": "600"})[0], 200)

    def test_reauthentication_is_throttled(self):
        for _ in range(web.LOGIN_MAX_FAILURES):
            self.assertEqual(self.save({"DNS_ZONE": "x.example"}, "wrong")[0], 403)
        self.assertEqual(self.save({"DNS_ZONE": "x.example"}, self.PASSWORD)[0], 429)

    def test_unexpected_errors_do_not_leak_details(self):
        def boom(dry_run=None):
            raise RuntimeError("internal secret detail")
        self.runtime.run_sync = boom
        status, data, _ = self.post("/api/dry-run", {})
        self.assertEqual(status, 500)
        self.assertNotIn("internal secret detail", json.dumps(data))
        self.assertIn("reference", data["error"])

    def test_settings_list_marks_sensitive_entries(self):
        flags = {s["key"]: s["sensitive"] for s in self.call("GET", "/api/config", cookie=self.cookie)[1]["settings"]}
        self.assertTrue(flags["TECHNITIUM_URL"])
        self.assertTrue(flags["WEB_LISTEN"])
        self.assertFalse(flags["DNS_TTL"])

if __name__ == "__main__":
    unittest.main()
