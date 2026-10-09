"""Unit and multi-poll regression tests for unifi_technitium_sync.

Run with:  python3 -m unittest discover -s tests -v
"""

from __future__ import annotations

import importlib.util
import json
import logging
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("uts", ROOT / "unifi_technitium_sync.py")
uts = importlib.util.module_from_spec(_spec)
sys.modules["uts"] = uts  # @dataclass needs the module registered
assert _spec.loader is not None
_spec.loader.exec_module(uts)

logging.getLogger("unifi-technitium-sync").setLevel(logging.CRITICAL)

ZONE = "home.arpa"
STEP = 300  # seconds between polls


def make_config(state_file: Path, **overrides) -> "uts.Config":
    values = dict(
        unifi_url="https://udm",
        unifi_api_key="key",
        unifi_site_id="site",
        unifi_clients_path="/clients",
        unifi_verify_tls=False,
        unifi_ca_file=None,
        technitium_url="http://dns:5380",
        technitium_api_token="token",
        technitium_verify_tls=False,
        technitium_ca_file=None,
        dns_zone=ZONE,
        dns_ttl=300,
        sync_interval=STEP,
        stale_after=86400,
        state_file=state_file,
        name_fields=("name", "hostname"),
        strip_trailing_mac=False,
        allowed_networks=(),
        excluded_names=frozenset(),
        create_ptr=False,
        create_ptr_zone=False,
        request_timeout=5,
        log_level="INFO",
        ip_stable_polls=2,
        name_stable_polls=2,
        name_downgrade_polls=288,
        name_memory_ttl=604800,
        web_listen="",
        web_password_hash="",
        web_tls_cert=None,
        web_tls_key=None,
    )
    values.update(overrides)
    return uts.Config(**values)


def client(mac: str, ip: str, name: str | None = None, hostname: str | None = None) -> dict:
    item = {"mac": mac, "ip": ip}
    if name is not None:
        item["name"] = name
    if hostname is not None:
        item["hostname"] = hostname
    return item


def fqdn(label: str) -> str:
    return f"{label}.{ZONE}"


def managed(name: str, ip: str, comments: str = uts.MARKER) -> dict:
    return {"name": fqdn(name), "type": "A", "rData": {"ipAddress": ip}, "comments": comments}


class FakeUnifi:
    def __init__(self, poll: list[dict]):
        self.poll = poll

    def connected_clients(self) -> list[dict]:
        return [dict(c) for c in self.poll]


class FakeTechnitium:
    """In-memory zone that records every write."""

    def __init__(self, records: list[dict] | None = None):
        self.zone: list[dict] = [dict(r) for r in records or []]
        self.log: list[tuple[str, str, str]] = []
        self.actions: list[dict[str, str]] = []  # same interface as TechnitiumClient
        self.dry_run = False

    def records(self) -> list[dict]:
        return [dict(r) for r in self.zone]

    def add_a(self, name: str, address: str) -> None:
        if not self.dry_run:
            self.log.append(("ADD", name, address))
        self.actions.append({"op": "ADD", "type": "A", "name": name, "value": address})
        if self.dry_run:
            return
        self.zone.append(managed(name[: -len(ZONE) - 1], address))

    def delete_a(self, name: str, address: str) -> None:
        if not self.dry_run:
            self.log.append(("DELETE", name, address))
        self.actions.append({"op": "DELETE", "type": "A", "name": name, "value": address})
        if self.dry_run:
            return
        self.zone = [
            r for r in self.zone if not (r["name"] == name and r["rData"]["ipAddress"] == address)
        ]


class Harness:
    """Drives synchronize() poll by poll against fakes and a temp state file."""

    def __init__(self, records: list[dict] | None = None, state: dict | None = None, **cfg):
        self.tmp = tempfile.TemporaryDirectory()
        self.cfg = make_config(Path(self.tmp.name) / "state.json", **cfg)
        self.tech = FakeTechnitium(records)
        self.now = 1_000_000
        if state is not None:
            self.cfg.state_file.write_text(json.dumps(state))

    def run(self, poll: list[dict], advance: int = STEP, dry_run: bool = False) -> list[tuple]:
        self.now += advance
        start = len(self.tech.log)
        uts.synchronize(self.cfg, FakeUnifi(poll), self.tech, dry_run, now=self.now)
        return self.tech.log[start:]

    def state(self) -> dict:
        return json.loads(self.cfg.state_file.read_text())

    def names(self) -> list[str]:
        return sorted(r["name"] for r in self.tech.zone)

    def close(self) -> None:
        self.tmp.cleanup()


class PureFunctionTests(unittest.TestCase):
    def test_sanitize_label(self):
        self.assertEqual(uts.sanitize_label("Sam's iPhone"), "sam-s-iphone")
        self.assertEqual(uts.sanitize_label("pc.lan"), "pc")
        self.assertEqual(uts.sanitize_label("---"), "")
        self.assertEqual(len(uts.sanitize_label("a" * 80)), 63)

    def test_strip_trailing_mac(self):
        self.assertEqual(uts.strip_trailing_mac("esp-ab-cd", "aabbccddabcd"), "esp")
        self.assertEqual(uts.strip_trailing_mac("esp-ab-cd", "aabbccdd1234"), "esp-ab-cd")

    def test_client_labels_priority_and_types(self):
        fields = ("name", "hostname")
        c = {"name": "My Phone", "hostname": "iphone", "mac": "aa"}
        self.assertEqual(uts.client_labels(c, fields, "aa", False), [("name", "my-phone"), ("hostname", "iphone")])
        self.assertEqual(uts.client_labels({"name": 5, "hostname": "x"}, fields, "aa", False), [("hostname", "x")])
        self.assertEqual(uts.client_name({"hostname": "x"}, fields, "aa", False), "x")
        self.assertEqual(uts.client_name({}, fields, "aa", False), "")

    def test_field_priority_unknown_ranks_first(self):
        fields = ("name", "hostname")
        self.assertEqual(uts.field_priority(fields, "name"), 0)
        self.assertEqual(uts.field_priority(fields, "hostname"), 1)
        self.assertEqual(uts.field_priority(fields, ""), 0)
        self.assertEqual(uts.field_priority(fields, "displayName"), 0)

    def test_record_label_has_no_double_hyphen(self):
        label = "a" * 55 + "-" + "bbbbbb"
        out = uts.record_label(label, "112233")
        self.assertNotIn("--", out)
        self.assertTrue(out.endswith("-112233"))
        self.assertLessEqual(len(out), 63)
        self.assertEqual(uts.record_label("tv", ""), "tv")


class MigrationTests(unittest.TestCase):
    def test_v1_seeds_naming_memory(self):
        v1 = {
            "version": 1,
            "managed_records": {
                fqdn("tv"): {"ip": "10.0.0.1", "mac": "aabbcc112233", "last_seen": 100},
                fqdn("lwip0-6a7b8c"): {"ip": "10.0.0.2", "mac": "0011226a7b8c", "last_seen": 200},
                fqdn("ghost"): {"ip": "10.0.0.3", "mac": "", "last_seen": 300},
                fqdn("old-name"): {"ip": "10.0.0.4", "mac": "ddeeff445566", "last_seen": 50},
                fqdn("new-name"): {"ip": "10.0.0.4", "mac": "ddeeff445566", "last_seen": 400},
            },
        }
        out = uts.migrate_state(json.loads(json.dumps(v1)), ZONE)
        self.assertEqual(out["version"], 2)
        self.assertEqual(out["pending"], {})
        clients = out["clients"]
        self.assertEqual(set(clients), {"aabbcc112233", "0011226a7b8c", "ddeeff445566"})
        self.assertEqual(clients["aabbcc112233"]["label"], "tv")
        self.assertEqual(clients["aabbcc112233"]["suffix"], "")
        self.assertEqual(clients["aabbcc112233"]["field"], "")
        self.assertEqual(clients["0011226a7b8c"]["label"], "lwip0")
        self.assertEqual(clients["0011226a7b8c"]["suffix"], "6a7b8c")
        self.assertEqual(clients["ddeeff445566"]["label"], "new-name")
        again = uts.migrate_state(json.loads(json.dumps(out)), ZONE)
        self.assertEqual(again, out)

    def test_load_state_missing_file(self):
        with tempfile.TemporaryDirectory() as d:
            state = uts.load_state(Path(d) / "none.json", ZONE)
        self.assertEqual(state, {"version": 2, "managed_records": {}, "pending": {}, "clients": {}})


class FlipRegressionTests(unittest.TestCase):
    """The production bug: alias intermittently missing must not rename."""

    def test_alias_blips_never_rename(self):
        h = Harness()
        mac = "44aa55bb66cc"
        for i in range(60):
            if i % 5 == 4:
                poll = [client(mac, "10.0.0.9", hostname="thermostat")]
            else:
                poll = [client(mac, "10.0.0.9", name="ecobee-kitchen", hostname="thermostat")]
            log = h.run(poll)
            if i == 0:
                self.assertEqual(log, [("ADD", fqdn("ecobee-kitchen"), "10.0.0.9")])
            else:
                self.assertEqual(log, [], f"unexpected write on poll {i}: {log}")
        self.assertEqual(h.names(), [fqdn("ecobee-kitchen")])
        self.assertEqual(h.state()["clients"][mac]["field"], "name")
        h.close()

    def test_hostname_source_flapping_never_renames(self):
        """The real thermostat: no alias; UniFi's hostname alternates between discovery sources."""
        h = Harness()
        mac = "ee0000000001"
        pattern = ["ecobee-kitchen", "Thermostat", "ecobee-kitchen", "Thermostat", "Thermostat", "Thermostat",
                   "ecobee-kitchen", "Thermostat", "Thermostat", "ecobee-kitchen", "ecobee-kitchen"]
        for i in range(99):
            log = h.run([client(mac, "10.0.0.31", hostname=pattern[i % len(pattern)])])
            if i == 0:
                self.assertEqual(log, [("ADD", fqdn("ecobee-kitchen"), "10.0.0.31")])
            else:
                self.assertEqual(log, [], f"unexpected write on poll {i}: {log}")
        self.assertEqual(h.names(), [fqdn("ecobee-kitchen")])
        self.assertEqual(h.state()["clients"][mac]["field"], "hostname")
        h.close()

    def test_hostname_rename_applies_once_old_name_is_gone(self):
        h = Harness(name_downgrade_polls=4)
        mac = "ee0000000002"
        ip = "10.0.0.32"
        self.assertEqual(h.run([client(mac, ip, hostname="old-name")]), [("ADD", fqdn("old-name"), ip)])
        for _ in range(3):
            self.assertEqual(h.run([client(mac, ip, hostname="new-name")]), [])
        log = h.run([client(mac, ip, hostname="new-name")])
        self.assertEqual(sorted(log), sorted([("DELETE", fqdn("old-name"), ip), ("ADD", fqdn("new-name"), ip)]))
        h.close()

    def test_unique_hostname_replaces_shared_one_at_once(self):
        h = Harness()
        a, b, c = "aa000000aaaa", "bb000000bbbb", "cc000000cccc"
        base = lambda: [client(b, "10.0.0.2", hostname="lwip0"), client(c, "10.0.0.3", hostname="lwip0")]
        h.run([client(a, "10.0.0.1", hostname="lwip0")] + base())
        self.assertEqual(h.names(), [fqdn("lwip0-00aaaa"), fqdn("lwip0-00bbbb"), fqdn("lwip0-00cccc")])
        log = h.run([client(a, "10.0.0.1", hostname="plug-a")] + base())
        self.assertEqual(sorted(log), sorted([("DELETE", fqdn("lwip0-00aaaa"), "10.0.0.1"), ("ADD", fqdn("plug-a"), "10.0.0.1")]))
        for _ in range(5):
            self.assertEqual(h.run([client(a, "10.0.0.1", hostname="lwip0")] + base()), [], "shared name must not take back a unique one")
        # two unique names alternating: the stored one wins
        self.assertEqual(h.run([client(a, "10.0.0.1", hostname="plug-a-two")] + base()), [])
        self.assertEqual(h.names(), [fqdn("lwip0-00bbbb"), fqdn("lwip0-00cccc"), fqdn("plug-a")])
        h.close()

    def test_wemo_fleet_settles_then_stays_quiet(self):
        """Two Wemos alternate hostnames lwip0 <-> wemo-patio-N; a third only says lwip0."""
        h = Harness()
        w1, w2, w3 = "0000000a1b2c", "0000003d4e5f", "0000006a7b8c"
        wa, wb = "0000009d0e1f", "0000002a3b4c"
        ia, ib = "0000005d6e7f", "000000aaaaaa"
        total_after_settle = 0
        for i in range(60):
            poll = [
                client(w1, "10.0.0.11", hostname="wemo-patio-1" if i % 4 == 1 else "lwip0"),
                client(w2, "10.0.0.12", hostname="wemo-patio-2" if i % 4 == 3 else "lwip0"),
                client(w3, "10.0.0.13", hostname="lwip0"),
                client(wa, "10.0.0.21", hostname="watch"),
                client(ia, "10.0.0.31", hostname="iphone"),
            ]
            if i % 3 != 0:
                poll.append(client(wb, "10.0.0.22", hostname="watch"))
            if i % 7 < 4:
                poll.append(client(ib, "10.0.0.32", hostname="iphone"))
            log = h.run(poll)
            if i >= 4:
                total_after_settle += len(log)
        self.assertEqual(total_after_settle, 0)
        self.assertEqual(
            h.names(),
            sorted(fqdn(n) for n in [
                "wemo-patio-1", "wemo-patio-2", "lwip0",
                "watch-9d0e1f", "watch-2a3b4c", "iphone-5d6e7f", "iphone-aaaaaa",
            ]),
        )
        h.close()

    def test_legacy_settings_reproduce_old_flapping(self):
        h = Harness(name_stable_polls=1, name_downgrade_polls=1, name_memory_ttl=0)
        mac = "44aa55bb66cc"
        writes = 0
        for i in range(10):
            hostname_only = i % 2 == 1
            poll = [client(mac, "10.0.0.9", name=None if hostname_only else "ecobee-kitchen", hostname="thermostat")]
            writes += len(h.run(poll))
        self.assertGreater(writes, 10, "1/1/0 should flap like v1.2 did")
        h.close()


class RenameRuleTests(unittest.TestCase):
    def test_alias_removed_falls_back_after_downgrade_polls_online_only(self):
        h = Harness(name_downgrade_polls=5)
        mac = "aa0000000001"
        self.assertEqual(h.run([client(mac, "10.0.0.5", name="lamp", hostname="esp")]), [("ADD", fqdn("lamp"), "10.0.0.5")])
        hostname_only = [client(mac, "10.0.0.5", hostname="esp")]
        schedule = [hostname_only, [], [], hostname_only, hostname_only, hostname_only, hostname_only]
        logs = [h.run(poll) for poll in schedule]
        self.assertEqual(logs[:-1], [[]] * 6, "no write before the fifth online hostname-only poll")
        self.assertEqual(sorted(logs[-1]), sorted([("DELETE", fqdn("lamp"), "10.0.0.5"), ("ADD", fqdn("esp"), "10.0.0.5")]))
        self.assertEqual(h.state()["clients"][mac]["field"], "hostname")
        h.close()

    def test_same_priority_rename_dampened_and_blip_tolerant(self):
        h = Harness(name_stable_polls=2)
        mac = "aa0000000002"
        ip = "10.0.0.6"
        h.run([client(mac, ip, name="a", hostname="h")])
        self.assertEqual(h.run([client(mac, ip, name="b", hostname="h")]), [])
        self.assertEqual(h.run([client(mac, ip, hostname="h")]), [], "blip must not reset the candidate")
        log = h.run([client(mac, ip, name="b", hostname="h")])
        self.assertEqual(sorted(log), sorted([("DELETE", fqdn("a"), ip), ("ADD", fqdn("b"), ip)]))
        self.assertEqual(h.run([client(mac, ip, name="c", hostname="h")]), [])
        self.assertEqual(h.run([client(mac, ip, name="d", hostname="h")]), [], "a different candidate restarts the count")
        self.assertEqual(h.run([client(mac, ip, name="b", hostname="h")]), [], "confirmation clears the candidate")
        self.assertNotIn("candidate", h.state()["clients"][mac])
        self.assertEqual(h.names(), [fqdn("b")])
        h.close()

    def test_new_alias_wins_immediately_then_blips_are_held(self):
        h = Harness()
        mac = "aa0000000003"
        ip = "10.0.0.7"
        self.assertEqual(h.run([client(mac, ip, hostname="esp")]), [("ADD", fqdn("esp"), ip)])
        log = h.run([client(mac, ip, name="lamp", hostname="esp")])
        self.assertEqual(sorted(log), sorted([("DELETE", fqdn("esp"), ip), ("ADD", fqdn("lamp"), ip)]))
        for _ in range(20):
            self.assertEqual(h.run([client(mac, ip, hostname="esp")]), [])
        self.assertEqual(h.names(), [fqdn("lamp")])
        h.close()

    def test_migrated_unknown_field_is_held_then_learned(self):
        mac = "aa0000000004"
        ip = "10.0.0.8"
        v1 = {"version": 1, "managed_records": {fqdn("ecobee-kitchen"): {"ip": ip, "mac": mac, "last_seen": 999_000}}}
        h = Harness(records=[managed("ecobee-kitchen", ip)], state=v1)
        self.assertEqual(h.run([client(mac, ip, hostname="thermostat")]), [])
        self.assertEqual(h.state()["clients"][mac]["field"], "")
        self.assertEqual(h.run([client(mac, ip, name="ecobee-kitchen", hostname="thermostat")]), [])
        self.assertEqual(h.state()["clients"][mac]["field"], "name")
        h.close()

    def test_migrated_hostname_label_upgrades_on_first_alias(self):
        mac = "aa00000a1b2c"
        ip = "10.0.0.11"
        v1 = {"version": 1, "managed_records": {fqdn("lwip0"): {"ip": ip, "mac": mac, "last_seen": 999_000}}}
        h = Harness(records=[managed("lwip0", ip)], state=v1)
        self.assertEqual(h.run([client(mac, ip, hostname="lwip0")]), [])
        self.assertEqual(h.state()["clients"][mac]["field"], "hostname")
        log = h.run([client(mac, ip, name="wemo-patio-1", hostname="lwip0")])
        self.assertEqual(sorted(log), sorted([("DELETE", fqdn("lwip0"), ip), ("ADD", fqdn("wemo-patio-1"), ip)]))
        h.close()

    def test_nameless_client_holds_then_drops(self):
        h = Harness(name_downgrade_polls=3, stale_after=0)
        mac = "aa0000000005"
        ip = "10.0.0.15"
        self.assertEqual(h.run([client(mac, ip, hostname="esp")]), [("ADD", fqdn("esp"), ip)])
        self.assertEqual(h.run([client(mac, ip)]), [])
        self.assertEqual(h.run([client(mac, ip)]), [])
        self.assertEqual(h.run([client(mac, ip)]), [("DELETE", fqdn("esp"), ip)])
        self.assertEqual(h.state()["clients"][mac]["label"], "")
        self.assertEqual(h.run([client(mac, ip, hostname="esp")]), [("ADD", fqdn("esp"), ip)])
        h.close()


class DedupTests(unittest.TestCase):
    def test_suffix_is_sticky_across_twin_absence_and_expiry(self):
        h = Harness(name_memory_ttl=3600)
        a, b = "aa000000aaaa", "bb000000bbbb"
        log = h.run([client(a, "10.0.0.1", hostname="watch"), client(b, "10.0.0.2", hostname="watch")])
        self.assertEqual(sorted(log), sorted([("ADD", fqdn("watch-00aaaa"), "10.0.0.1"), ("ADD", fqdn("watch-00bbbb"), "10.0.0.2")]))
        for _ in range(3):
            self.assertEqual(h.run([client(a, "10.0.0.1", hostname="watch")]), [], "twin offline must not drop the suffix")
        log = h.run([client(a, "10.0.0.1", hostname="watch")], advance=7200)
        self.assertEqual(sorted(log), sorted([("DELETE", fqdn("watch-00aaaa"), "10.0.0.1"), ("ADD", fqdn("watch"), "10.0.0.1")]))
        log = h.run([client(a, "10.0.0.1", hostname="watch"), client(b, "10.0.0.2", hostname="watch")])
        self.assertIn(("DELETE", fqdn("watch"), "10.0.0.1"), log)
        self.assertIn(("ADD", fqdn("watch-00aaaa"), "10.0.0.1"), log)
        h.close()

    def test_suffix_released_when_twin_gets_its_own_alias(self):
        h = Harness()
        a, b = "aa000000aaaa", "bb000000bbbb"
        h.run([client(a, "10.0.0.1", hostname="watch"), client(b, "10.0.0.2", hostname="watch")])
        log = h.run([client(a, "10.0.0.1", hostname="watch"), client(b, "10.0.0.2", name="bobs-watch", hostname="watch")])
        self.assertEqual(
            sorted(log),
            sorted([
                ("DELETE", fqdn("watch-00aaaa"), "10.0.0.1"), ("ADD", fqdn("watch"), "10.0.0.1"),
                ("DELETE", fqdn("watch-00bbbb"), "10.0.0.2"), ("ADD", fqdn("bobs-watch"), "10.0.0.2"),
            ]),
        )
        h.close()

    def test_excluded_label_emits_nothing_even_when_shared(self):
        h = Harness(excluded_names=frozenset({"nas"}))
        poll = [client("aa000000aaaa", "10.0.0.1", name="nas", hostname="synology"), client("bb000000bbbb", "10.0.0.2", name="nas", hostname="qnap")]
        self.assertEqual(h.run(poll), [])
        self.assertEqual(h.run([client("aa000000aaaa", "10.0.0.1", hostname="synology"), poll[1]]), [])
        self.assertEqual(h.names(), [])
        h.close()

    def test_macless_clients_are_stateless(self):
        h = Harness()
        poll = [{"ip": "10.0.0.1", "hostname": "printer"}, {"ip": "10.0.0.2", "hostname": "printer"}]
        log = h.run(poll)
        self.assertEqual(sorted(n for _, n, _ in log), sorted([fqdn("printer-10-0-0-1"), fqdn("printer-10-0-0-2")]))
        h2 = Harness()
        self.assertEqual(h2.run([{"ip": "10.0.0.1", "hostname": "printer"}]), [("ADD", fqdn("printer"), "10.0.0.1")])
        h.close()
        h2.close()


class UpgradeAndSafetyTests(unittest.TestCase):
    def test_first_cycle_after_upgrade_writes_nothing(self):
        now = 1_000_000
        recs = {
            "tv": ("10.0.0.1", "aa0000000001"),
            "nas": ("10.0.0.2", "aa0000000002"),
            "lwip0-00aaaa": ("10.0.0.3", "aa000000aaaa"),
            "lwip0-00bbbb": ("10.0.0.4", "bb000000bbbb"),
            "watch-00cccc": ("10.0.0.5", "cc000000cccc"),
            "watch-00dddd": ("10.0.0.6", "dd000000dddd"),
            "ecobee-kitchen": ("10.0.0.7", "aa0000000007"),
            "phone": ("10.0.0.8", "aa0000000008"),
        }
        v1 = {"version": 1, "managed_records": {fqdn(n): {"ip": ip, "mac": mac, "last_seen": now} for n, (ip, mac) in recs.items()}}
        zone = [managed(n, ip) for n, (ip, _) in recs.items()]
        h = Harness(records=zone, state=v1)
        poll = [
            client("aa0000000001", "10.0.0.1", name="TV"),
            client("aa0000000002", "10.0.0.2", hostname="nas"),
            client("aa000000aaaa", "10.0.0.3", hostname="lwip0"),
            client("bb000000bbbb", "10.0.0.4", hostname="lwip0"),
            client("cc000000cccc", "10.0.0.5", hostname="watch"),  # twin dddd offline but remembered
            client("aa0000000007", "10.0.0.7", hostname="thermostat"),  # caught mid-blip
            client("aa0000000008", "10.0.0.8", name="phone"),
        ]
        self.assertEqual(h.run(poll), [])
        self.assertEqual(h.state()["version"], 2)
        self.assertEqual(len(h.state()["clients"]), 8)
        h.close()

    def test_rename_and_ip_change_in_same_cycle(self):
        h = Harness(name_stable_polls=2)
        mac = "aa0000000009"
        h.run([client(mac, "10.0.0.1", name="a")])
        self.assertEqual(h.run([client(mac, "10.0.0.2", name="b")]), [], "IP change deferred, rename deferred")
        log = h.run([client(mac, "10.0.0.2", name="b")])
        self.assertEqual(sorted(log), sorted([("ADD", fqdn("b"), "10.0.0.2"), ("DELETE", fqdn("a"), "10.0.0.1")]))
        self.assertEqual(h.state()["pending"], {})
        self.assertEqual(h.names(), [fqdn("b")])
        h.close()

    def test_stale_after_zero_keeps_naming_memory(self):
        h = Harness(stale_after=0)
        a, b = "aa000000aaaa", "bb000000bbbb"
        h.run([client(a, "10.0.0.1", hostname="watch"), client(b, "10.0.0.2", hostname="watch")])
        self.assertEqual(h.run([client(a, "10.0.0.1", hostname="watch")]), [("DELETE", fqdn("watch-00bbbb"), "10.0.0.2")])
        self.assertEqual(h.run([client(a, "10.0.0.1", hostname="watch"), client(b, "10.0.0.2", hostname="watch")]), [("ADD", fqdn("watch-00bbbb"), "10.0.0.2")])
        h.close()

    def test_ip_dampening_unchanged(self):
        h = Harness(ip_stable_polls=2)
        mac = "aa000000000a"
        h.run([client(mac, "10.0.0.1", name="box")])
        self.assertEqual(h.run([client(mac, "10.0.0.2", name="box")]), [])
        log = h.run([client(mac, "10.0.0.2", name="box")])
        self.assertEqual(sorted(log), sorted([("DELETE", fqdn("box"), "10.0.0.1"), ("ADD", fqdn("box"), "10.0.0.2")]))
        h.close()

    def test_dry_run_writes_no_state(self):
        h = Harness()
        self.assertEqual(h.run([client("aa000000000b", "10.0.0.1", name="box")], dry_run=True), [("ADD", fqdn("box"), "10.0.0.1")])
        self.assertFalse(h.cfg.state_file.exists())
        h.close()

    def test_unmanaged_record_still_wins(self):
        h = Harness(records=[managed("nas", "10.0.0.99", comments="manual")])
        self.assertEqual(h.run([client("aa000000000c", "10.0.0.2", name="nas")]), [])
        h.close()

    def test_allowed_networks_filter_does_not_track_names(self):
        h = Harness(allowed_networks=(uts.ipaddress.ip_network("10.0.0.0/24"),))
        poll = [client("aa000000000d", "10.0.0.1", hostname="iphone"), client("aa000000000e", "192.168.9.9", hostname="iphone")]
        self.assertEqual(h.run(poll), [("ADD", fqdn("iphone"), "10.0.0.1")])
        self.assertEqual(set(h.state()["clients"]), {"aa000000000d"})
        h.close()


if __name__ == "__main__":
    unittest.main()
