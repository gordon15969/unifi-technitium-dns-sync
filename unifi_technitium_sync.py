#!/usr/bin/env python3
"""Synchronize UniFi connected-client names to a Technitium DNS zone."""

from __future__ import annotations

import argparse
import getpass
import hashlib
import hmac
import ipaddress
import json
import logging
import os
import re
import secrets
import signal
import ssl
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import deque
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Mapping

VERSION = "1.4.0"
MARKER = "managed-by=unifi-technitium-sync"
STOP = False
WAKE = threading.Event()
DEFAULT_CLIENTS_PATH = "/proxy/network/api/s/default/stat/sta"
DEFAULT_NAME_FIELDS = "name,hostname"
DEFAULT_STATE_FILE = "/var/lib/unifi-technitium-sync/state.json"
LOG_LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR")
LOG = logging.getLogger("unifi-technitium-sync")
WARNED: set[tuple[str, str]] = set()


def env_bool(name: str, default: bool, env: Mapping[str, str] | None = None) -> bool:
    value = (os.environ if env is None else env).get(name)
    if value is None or not value.strip():
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def env_int(
    name: str, default: int, minimum: int = 0, env: Mapping[str, str] | None = None
) -> int:
    raw = (os.environ if env is None else env).get(name, "")
    try:
        value = int(raw) if raw.strip() else default
    except ValueError as exc:
        raise ValueError(f"{name} must be a whole number, got {raw.strip()!r}") from exc
    if value < minimum:
        raise ValueError(f"{name} must be at least {minimum}")
    return value


def parse_listen(value: str) -> tuple[str, int]:
    """Split a WEB_LISTEN value such as 0.0.0.0:8089 into host and port."""
    host, sep, port_text = value.strip().rpartition(":")
    if not sep or not port_text.isdigit() or not 0 <= int(port_text) <= 65535:
        raise ValueError("WEB_LISTEN must look like host:port, for example 127.0.0.1:8089")
    return (host.strip("[]") or "0.0.0.0", int(port_text))


def strip_url(value: str) -> str:
    return value.strip().rstrip("/")


@dataclass(frozen=True)
class Config:
    unifi_url: str
    unifi_api_key: str
    unifi_site_id: str
    unifi_clients_path: str
    unifi_verify_tls: bool
    unifi_ca_file: str | None
    technitium_url: str
    technitium_api_token: str
    technitium_verify_tls: bool
    technitium_ca_file: str | None
    dns_zone: str
    dns_ttl: int
    sync_interval: int
    stale_after: int
    state_file: Path
    name_fields: tuple[str, ...]
    strip_trailing_mac: bool
    allowed_networks: tuple[ipaddress.IPv4Network, ...]
    excluded_names: frozenset[str]
    create_ptr: bool
    create_ptr_zone: bool
    request_timeout: int
    log_level: str
    ip_stable_polls: int
    name_stable_polls: int
    name_downgrade_polls: int
    name_memory_ttl: int
    web_listen: str
    web_password_hash: str
    web_tls_cert: str | None
    web_tls_key: str | None

    @classmethod
    def from_env(cls) -> "Config":
        return cls.from_mapping(os.environ)

    @classmethod
    def from_mapping(cls, env: Mapping[str, str]) -> "Config":
        required = [
            "UNIFI_URL",
            "UNIFI_API_KEY",
            "UNIFI_SITE_ID",
            "TECHNITIUM_URL",
            "TECHNITIUM_API_TOKEN",
            "DNS_ZONE",
        ]
        missing = [name for name in required if not env.get(name, "").strip()]
        if missing:
            raise ValueError("Missing required settings: " + ", ".join(missing))

        networks: list[ipaddress.IPv4Network] = []
        for item in env.get("ALLOWED_NETWORKS", "").split(","):
            if item.strip():
                try:
                    network = ipaddress.ip_network(item.strip(), strict=False)
                except ValueError as exc:
                    raise ValueError(f"ALLOWED_NETWORKS: {exc}") from exc
                if network.version != 4:
                    raise ValueError("ALLOWED_NETWORKS currently supports IPv4 networks only")
                networks.append(network)

        zone = env["DNS_ZONE"].strip().lower().rstrip(".")
        if not zone or "." not in zone:
            raise ValueError("DNS_ZONE must be a valid zone such as home.arpa")

        web_listen = env.get("WEB_LISTEN", "").strip()
        if web_listen:
            parse_listen(web_listen)
        log_level = env.get("LOG_LEVEL", "").strip().upper() or "INFO"
        if log_level not in LOG_LEVELS:
            raise ValueError("LOG_LEVEL must be one of " + ", ".join(LOG_LEVELS))

        return cls(
            unifi_url=strip_url(env["UNIFI_URL"]),
            unifi_api_key=env["UNIFI_API_KEY"].strip(),
            unifi_site_id=env["UNIFI_SITE_ID"].strip(),
            unifi_clients_path=(env.get("UNIFI_CLIENTS_PATH") or DEFAULT_CLIENTS_PATH).strip(),
            unifi_verify_tls=env_bool("UNIFI_VERIFY_TLS", True, env),
            unifi_ca_file=env.get("UNIFI_CA_FILE") or None,
            technitium_url=strip_url(env["TECHNITIUM_URL"]),
            technitium_api_token=env["TECHNITIUM_API_TOKEN"].strip(),
            technitium_verify_tls=env_bool("TECHNITIUM_VERIFY_TLS", True, env),
            technitium_ca_file=env.get("TECHNITIUM_CA_FILE") or None,
            dns_zone=zone,
            dns_ttl=env_int("DNS_TTL", 300, 1, env),
            sync_interval=env_int("SYNC_INTERVAL", 300, 10, env),
            stale_after=env_int("STALE_AFTER", 86400, 0, env),
            state_file=Path(env.get("STATE_FILE") or DEFAULT_STATE_FILE),
            name_fields=tuple(
                item.strip()
                for item in (env.get("NAME_FIELDS") or DEFAULT_NAME_FIELDS).split(",")
                if item.strip()
            ),
            strip_trailing_mac=env_bool("STRIP_TRAILING_MAC", False, env),
            allowed_networks=tuple(networks),
            excluded_names=frozenset(
                sanitize_label(name)
                for name in env.get("EXCLUDED_NAMES", "").split(",")
                if name.strip()
            ),
            create_ptr=env_bool("CREATE_PTR", False, env),
            create_ptr_zone=env_bool("CREATE_PTR_ZONE", False, env),
            request_timeout=env_int("REQUEST_TIMEOUT", 20, 1, env),
            log_level=log_level,
            ip_stable_polls=env_int("IP_STABLE_POLLS", 2, 1, env),
            name_stable_polls=env_int("NAME_STABLE_POLLS", 2, 1, env),
            name_downgrade_polls=env_int("NAME_DOWNGRADE_POLLS", 288, 1, env),
            name_memory_ttl=env_int("NAME_MEMORY_TTL", 604800, 0, env),
            web_listen=web_listen,
            web_password_hash=env.get("WEB_PASSWORD_HASH", "").strip(),
            web_tls_cert=env.get("WEB_TLS_CERT") or None,
            web_tls_key=env.get("WEB_TLS_KEY") or None,
        )


@dataclass(frozen=True)
class Setting:
    """One configurable value: drives the env-file parser, the web form and validation."""

    key: str
    kind: str  # text | int | bool | secret | choice
    default: str
    help: str
    section: str
    required: bool = False
    choices: tuple[str, ...] = ()
    restart: bool = False  # a change only takes effect after a service restart


SETTINGS: tuple[Setting, ...] = (
    Setting("UNIFI_URL", "text", "", "Base URL of the UniFi gateway, e.g. https://192.168.1.1", "UniFi", required=True),
    Setting("UNIFI_API_KEY", "secret", "", "API key from Settings → Control Plane → Integrations", "UniFi", required=True),
    Setting("UNIFI_SITE_ID", "text", "", "Site ID from the same page; only substituted when the client path contains {site_id}", "UniFi", required=True),
    Setting("UNIFI_CLIENTS_PATH", "text", DEFAULT_CLIENTS_PATH, "API path for the client list; the legacy stat/sta path is the only one that exposes DHCP hostnames", "UniFi"),
    Setting("UNIFI_VERIFY_TLS", "bool", "true", "Verify the gateway's TLS certificate", "UniFi"),
    Setting("UNIFI_CA_FILE", "text", "", "PEM file with the gateway's CA certificate", "UniFi"),
    Setting("TECHNITIUM_URL", "text", "", "Technitium base URL, e.g. http://192.168.1.53:5380", "Technitium", required=True),
    Setting("TECHNITIUM_API_TOKEN", "secret", "", "Token of a Technitium user with zone-scoped permissions", "Technitium", required=True),
    Setting("TECHNITIUM_VERIFY_TLS", "bool", "true", "Verify Technitium's TLS certificate", "Technitium"),
    Setting("TECHNITIUM_CA_FILE", "text", "", "PEM file with Technitium's CA certificate", "Technitium"),
    Setting("DNS_ZONE", "text", "", "Existing primary zone the records go into, e.g. home.arpa", "Zone", required=True),
    Setting("DNS_TTL", "int", "300", "TTL in seconds for created records", "Zone"),
    Setting("CREATE_PTR", "bool", "false", "Maintain matching PTR records for reverse lookups", "Zone"),
    Setting("CREATE_PTR_ZONE", "bool", "false", "Let Technitium create missing reverse zones", "Zone"),
    Setting("SYNC_INTERVAL", "int", "300", "Seconds between synchronization cycles (minimum 10)", "Timing"),
    Setting("STALE_AFTER", "int", "86400", "Seconds a disappeared client's record is retained; 0 deletes on the first missing cycle", "Timing"),
    Setting("REQUEST_TIMEOUT", "int", "20", "HTTP timeout in seconds", "Timing"),
    Setting("IP_STABLE_POLLS", "int", "2", "Consecutive polls a new IP must be seen before an existing record is updated", "Timing"),
    Setting("NAME_STABLE_POLLS", "int", "2", "Sightings of an edited alias (the most preferred field) before a record is renamed", "Name stability"),
    Setting("NAME_DOWNGRADE_POLLS", "int", "288", "Consecutive online polls a client's stored name must go unreported before a less preferred field, a different device-announced hostname, or no name may replace it (288 ≈ 24 h at 300 s)", "Name stability"),
    Setting("NAME_MEMORY_TTL", "int", "604800", "Seconds a client's name is remembered after it was last seen; keeps de-dup suffixes stable", "Name stability"),
    Setting("NAME_FIELDS", "text", DEFAULT_NAME_FIELDS, "Client fields tried in order for the DNS label", "Naming and filters"),
    Setting("STRIP_TRAILING_MAC", "bool", "false", "Remove a trailing -xx-xx label suffix when it matches the client's MAC", "Naming and filters"),
    Setting("ALLOWED_NETWORKS", "text", "", "Comma-separated IPv4 CIDRs; clients outside are ignored (empty = all)", "Naming and filters"),
    Setting("EXCLUDED_NAMES", "text", "", "Comma-separated labels never to sync, e.g. hosts you manage by hand", "Naming and filters"),
    Setting("STATE_FILE", "text", DEFAULT_STATE_FILE, "Ownership and naming-memory database", "Service"),
    Setting("LOG_LEVEL", "choice", "INFO", "DEBUG shows skip, defer and hold detail every cycle", "Service", choices=LOG_LEVELS),
    Setting("WEB_LISTEN", "text", "", "host:port for the embedded web UI, e.g. 0.0.0.0:8089; empty disables it", "Web UI", restart=True),
    Setting("WEB_TLS_CERT", "text", "", "PEM certificate chain to serve the web UI over HTTPS", "Web UI", restart=True),
    Setting("WEB_TLS_KEY", "text", "", "PEM private key for WEB_TLS_CERT", "Web UI", restart=True),
    Setting("WEB_PASSWORD_HASH", "secret", "", "Set with --set-web-password or the password form", "Web UI"),
)


ENV_LINE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=(.*)$")


def parse_env_value(raw: str) -> str:
    value = raw.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        inner = value[1:-1]
        if value[0] == '"':
            inner = inner.replace('\\"', '"').replace("\\\\", "\\")
        return inner
    return value


def read_env_file(path: Path) -> dict[str, str]:
    """Parse a KEY=VALUE file of the kind systemd's EnvironmentFile= reads."""
    values: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        match = ENV_LINE.match(line)
        if match:
            values[match.group(1)] = parse_env_value(match.group(2))
    return values


def format_env_value(value: str) -> str:
    if value == "" or re.fullmatch(r"[A-Za-z0-9_./:,@+=\-{}]+", value):
        return value
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def write_env_file(path: Path, updates: Mapping[str, str]) -> None:
    """Rewrite KEY=VALUE lines in place, keeping comments and order; append new keys."""
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
        original: os.stat_result | None = path.stat()
    except FileNotFoundError:
        lines, original = [], None
    remaining = dict(updates)
    output: list[str] = []
    for line in lines:
        match = ENV_LINE.match(line)
        if match and match.group(1) in remaining:
            key = match.group(1)
            output.append(f"{key}={format_env_value(remaining.pop(key))}")
        else:
            output.append(line)
    if remaining:
        if output and output[-1].strip():
            output.append("")
        output.append("# Added by the web UI")
        output.extend(f"{key}={format_env_value(value)}" for key, value in remaining.items())
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text("\n".join(output) + "\n", encoding="utf-8")
    os.chmod(temporary, original.st_mode & 0o777 if original else 0o640)
    if original is not None:
        try:
            # Keep owner and group (root edits must stay readable by the service user).
            os.chown(temporary, original.st_uid, original.st_gid)
        except PermissionError:
            pass  # not root: the file stays owned by the writing user, which can read it
    os.replace(temporary, path)


def hash_password(password: str, iterations: int = 200_000) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return f"pbkdf2_sha256${iterations}${salt.hex()}${digest.hex()}"


def verify_password(stored: str, password: str) -> bool:
    try:
        algorithm, iterations, salt_hex, digest_hex = stored.split("$")
        if algorithm != "pbkdf2_sha256":
            return False
        digest = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), int(iterations)
        )
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(digest.hex(), digest_hex)


@dataclass
class SyncResult:
    """Outcome of one synchronization cycle, real or dry-run."""

    started: int
    duration: float
    dry_run: bool
    clients: int = 0
    desired: int = 0
    tracked: int = 0
    actions: list[dict[str, str]] = field(default_factory=list)
    skipped: list[dict[str, str]] = field(default_factory=list)
    deferred: list[dict[str, str]] = field(default_factory=list)
    error: str | None = None

    @property
    def adds(self) -> int:
        return sum(1 for action in self.actions if action["op"] == "ADD")

    @property
    def deletes(self) -> int:
        return sum(1 for action in self.actions if action["op"] == "DELETE")

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["adds"] = self.adds
        data["deletes"] = self.deletes
        return data


def ssl_context(verify: bool, ca_file: str | None) -> ssl.SSLContext:
    if not verify:
        return ssl._create_unverified_context()  # noqa: SLF001
    return ssl.create_default_context(cafile=ca_file)


def request_json(
    url: str,
    headers: dict[str, str],
    timeout: int,
    context: ssl.SSLContext,
    params: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if params:
        separator = "&" if "?" in url else "?"
        encoded = urllib.parse.urlencode(
            {key: str(value).lower() if isinstance(value, bool) else value
             for key, value in params.items()}
        )
        url = f"{url}{separator}{encoded}"
    request = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=timeout, context=context) as response:
            payload = response.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"HTTP {exc.code} from {url}: {body[:500]}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Cannot reach {url}: {exc.reason}") from exc
    try:
        data = json.loads(payload)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Non-JSON response from {url}: {payload[:200]}") from exc
    if not isinstance(data, dict):
        raise RuntimeError(f"Unexpected response from {url}: expected a JSON object")
    return data


class UnifiClient:
    def __init__(self, config: Config):
        self.config = config
        self.context = ssl_context(config.unifi_verify_tls, config.unifi_ca_file)

    def connected_clients(self) -> list[dict[str, Any]]:
        path = self.config.unifi_clients_path.format(
            site_id=urllib.parse.quote(self.config.unifi_site_id, safe="")
        )
        base_url = f"{self.config.unifi_url}/{path.lstrip('/')}"
        headers = {
            "Accept": "application/json",
            "X-API-Key": self.config.unifi_api_key,
            "User-Agent": f"unifi-technitium-sync/{VERSION}",
        }
        clients: list[dict[str, Any]] = []
        offset = 0
        limit = 200
        while True:
            data = request_json(
                base_url,
                headers,
                self.config.request_timeout,
                self.context,
                {"offset": offset, "limit": limit},
            )
            page = data.get("data")
            if page is None and isinstance(data.get("response"), dict):
                page = data["response"].get("data")
            if not isinstance(page, list):
                raise RuntimeError("UniFi response does not contain a client data array")
            clients.extend(item for item in page if isinstance(item, dict))
            count = int(data.get("count", len(page)))
            total = int(data.get("totalCount", len(clients)))
            if not page or count == 0 or len(clients) >= total:
                break
            offset += len(page)
        return clients


class TechnitiumClient:
    def __init__(self, config: Config, dry_run: bool):
        self.config = config
        self.dry_run = dry_run
        self.context = ssl_context(
            config.technitium_verify_tls, config.technitium_ca_file
        )
        self.headers = {
            "Accept": "application/json",
            "Authorization": f"Bearer {config.technitium_api_token}",
            "User-Agent": f"unifi-technitium-sync/{VERSION}",
        }
        self.actions: list[dict[str, str]] = []

    def _call(self, path: str, params: dict[str, Any]) -> dict[str, Any]:
        data = request_json(
            f"{self.config.technitium_url}{path}",
            self.headers,
            self.config.request_timeout,
            self.context,
            params,
        )
        if data.get("status") != "ok":
            message = data.get("errorMessage") or data.get("status") or "unknown error"
            raise RuntimeError(f"Technitium API error: {message}")
        return data

    def records(self) -> list[dict[str, Any]]:
        data = self._call(
            "/api/zones/records/get",
            {"domain": self.config.dns_zone, "zone": self.config.dns_zone, "listZone": True},
        )
        response = data.get("response", {})
        records = response.get("records", []) if isinstance(response, dict) else []
        if not isinstance(records, list):
            raise RuntimeError("Technitium response does not contain a records array")
        return [record for record in records if isinstance(record, dict)]

    def add_a(self, fqdn: str, address: str) -> None:
        LOG.info("%sADD A %s -> %s", "[dry-run] " if self.dry_run else "", fqdn, address)
        self.actions.append({"op": "ADD", "type": "A", "name": fqdn, "value": address})
        if self.dry_run:
            return
        self._call(
            "/api/zones/records/add",
            {
                "domain": fqdn,
                "zone": self.config.dns_zone,
                "type": "A",
                "ttl": self.config.dns_ttl,
                "ipAddress": address,
                "comments": MARKER,
                "ptr": self.config.create_ptr,
                "createPtrZone": self.config.create_ptr_zone,
            },
        )

    def delete_a(self, fqdn: str, address: str) -> None:
        LOG.info(
            "%sDELETE A %s -> %s", "[dry-run] " if self.dry_run else "", fqdn, address
        )
        self.actions.append({"op": "DELETE", "type": "A", "name": fqdn, "value": address})
        if not self.dry_run:
            self._call(
                "/api/zones/records/delete",
                {
                    "domain": fqdn,
                    "zone": self.config.dns_zone,
                    "type": "A",
                    "ipAddress": address,
                    "updateSvcbHints": True,
                },
            )
        if self.config.create_ptr:
            self.delete_ptr(fqdn, address)

    def delete_ptr(self, fqdn: str, address: str) -> None:
        """Remove the PTR left behind by an A-record deletion.

        Technitium's records/delete API does not cascade to the reverse zone.
        The ptrName filter ensures only a PTR still pointing at the deleted
        name is removed; a missing zone or already-replaced PTR is ignored.
        """
        reverse_name = ipaddress.ip_address(address).reverse_pointer
        LOG.info(
            "%sDELETE PTR %s -> %s",
            "[dry-run] " if self.dry_run else "",
            reverse_name,
            fqdn,
        )
        self.actions.append({"op": "DELETE", "type": "PTR", "name": reverse_name, "value": fqdn})
        if self.dry_run:
            return
        try:
            self._call(
                "/api/zones/records/delete",
                {"domain": reverse_name, "type": "PTR", "ptrName": fqdn},
            )
        except RuntimeError as exc:
            LOG.debug("PTR cleanup skipped for %s (%s): %s", fqdn, reverse_name, exc)

    def ensure_ptr(self, fqdn: str, address: str) -> None:
        """Create or refresh the PTR for an existing managed A record."""
        self._call(
            "/api/zones/records/update",
            {
                "domain": fqdn,
                "zone": self.config.dns_zone,
                "type": "A",
                "ipAddress": address,
                "newIpAddress": address,
                "ttl": self.config.dns_ttl,
                "comments": MARKER,
                "ptr": True,
                "createPtrZone": self.config.create_ptr_zone,
            },
        )


def sanitize_label(value: str) -> str:
    value = value.strip().lower()
    if "." in value:
        value = value.split(".", 1)[0]
    value = re.sub(r"[^a-z0-9-]+", "-", value)
    value = re.sub(r"-+", "-", value).strip("-")
    return value[:63].rstrip("-")


def strip_trailing_mac(label: str, mac: str) -> str:
    """Remove a final -xx-xx label suffix when it matches the client's MAC."""
    if len(mac) < 4:
        return label
    suffix = f"-{mac[-4:-2]}-{mac[-2:]}"
    if label.endswith(suffix) and len(label) > len(suffix):
        return label[: -len(suffix)].rstrip("-")
    return label


def client_labels(
    client: dict[str, Any],
    fields: tuple[str, ...],
    mac: str,
    strip_mac_suffix: bool,
) -> list[tuple[str, str]]:
    """Return every usable (field, label) pair in NAME_FIELDS priority order."""
    labels: list[tuple[str, str]] = []
    for field in fields:
        value = client.get(field)
        if isinstance(value, str):
            label = sanitize_label(value)
            if strip_mac_suffix:
                label = strip_trailing_mac(label, mac)
            if label:
                labels.append((field, label))
    return labels


def client_name(
    client: dict[str, Any],
    fields: tuple[str, ...],
    mac: str,
    strip_mac_suffix: bool,
) -> str:
    labels = client_labels(client, fields, mac, strip_mac_suffix)
    return labels[0][1] if labels else ""


def field_priority(fields: tuple[str, ...], field: str) -> int:
    """Rank of a name field (0 = most preferred).

    An empty or no-longer-configured field ranks first: a label whose origin
    is unknown (migrated state) is assumed to have come from the preferred
    field, so a lower-priority field cannot displace it on a blip.
    """
    try:
        return fields.index(field)
    except ValueError:
        return 0


def client_mac(client: dict[str, Any]) -> str:
    for field in ("macAddress", "mac", "mac_address"):
        value = client.get(field)
        if isinstance(value, str) and value.strip():
            return re.sub(r"[^0-9a-f]", "", value.lower())
    return ""


def client_ip(client: dict[str, Any]) -> str:
    for field in ("ipAddress", "ip", "fixedIp"):
        value = client.get(field)
        if isinstance(value, str):
            try:
                address = ipaddress.ip_address(value.strip())
            except ValueError:
                continue
            if address.version == 4:
                return str(address)
    return ""


def new_entry(label: str, field: str, now: int) -> dict[str, Any]:
    return {
        "label": label,
        "field": field,
        "suffix": "",
        "last_seen": now,
        "label_seen": now,
        "downgrade_polls": 0,
    }


def commit_label(entry: dict[str, Any], label: str, field: str, now: int) -> dict[str, Any]:
    entry["label"] = label
    entry["field"] = field
    entry["suffix"] = ""
    entry["label_seen"] = now
    entry["downgrade_polls"] = 0
    entry.pop("candidate", None)
    return entry


def resolve_label(
    config: Config,
    mac: str,
    entry: dict[str, Any] | None,
    candidates: list[tuple[str, str]],
    now: int,
    label_counts: Mapping[str, int] | None = None,
) -> dict[str, Any]:
    """Apply one poll's name candidates to a client's naming memory.

    A client's committed label only changes when the source data changes
    durably:
    - a label from a *more* preferred field (an alias appearing) wins at once;
    - a *different* label from the most preferred field (the alias was
      edited) must be reported for NAME_STABLE_POLLS sightings; blips in
      between do not reset the count;
    - a *different* label from a device-announced field is held like a
      downgrade, because UniFi's hostname can alternate between discovery
      sources (DHCP, mDNS, UPnP) for the same device. One tie-break: a label
      that is unique on the network replaces one shared with other clients at
      once, so a Wemo converges on "wemo-patio-1" rather than "lwip0-xxxxxx";
    - a label from a *less* preferred field, or no name at all, is held.
    Held labels are replaced only after the stored label has gone unreported
    for NAME_DOWNGRADE_POLLS consecutive polls in which the client was online.
    """
    best_field, best_label = candidates[0] if candidates else ("", "")
    if entry is None:
        if best_label:
            LOG.debug("Label for %s: %s (%s, new client)", mac, best_label, best_field)
        return new_entry(best_label, best_field, now)

    entry = dict(entry)
    entry["last_seen"] = now
    stored_label = str(entry.get("label", ""))
    stored_field = str(entry.get("field", ""))
    if not stored_label:
        if best_label:
            LOG.info("Label for %s: (none) -> %s (%s)", mac, best_label, best_field)
            return commit_label(entry, best_label, best_field, now)
        return entry

    fields = config.name_fields
    stored_priority = field_priority(fields, stored_field)
    best_priority = field_priority(fields, best_field) if best_label else len(fields)

    if best_label == stored_label:
        entry["label_seen"] = now
        entry["downgrade_polls"] = 0
        entry.pop("candidate", None)
        if not stored_field:
            entry["field"] = best_field
        return entry

    if best_label and best_priority < stored_priority:
        LOG.info(
            "Label for %s: %s -> %s (%s is preferred over %s)",
            mac, stored_label, best_label, best_field, stored_field or "unknown field",
        )
        return commit_label(entry, best_label, best_field, now)

    if best_label and best_priority == stored_priority:
        if stored_priority == 0:
            # The most preferred field is user-controlled: a different value is a deliberate rename.
            watch = entry.get("candidate") or {}
            count = int(watch.get("count", 0)) + 1 if watch.get("label") == best_label else 1
            entry["downgrade_polls"] = 0
            if count >= config.name_stable_polls:
                LOG.info(
                    "Label for %s: %s -> %s (%s, seen %d polls)",
                    mac, stored_label, best_label, best_field, count,
                )
                return commit_label(entry, best_label, best_field, now)
            entry["candidate"] = {"label": best_label, "field": best_field, "count": count}
            LOG.debug(
                "Deferring rename of %s: %s -> %s seen %d/%d polls",
                mac, stored_label, best_label, count, config.name_stable_polls,
            )
            return entry
        counts = label_counts or {}
        if counts.get(best_label, 0) == 0 and counts.get(stored_label, 0) > 1:
            LOG.info(
                "Label for %s: %s -> %s (%s; a unique name replaces one shared with %d other clients)",
                mac, stored_label, best_label, best_field, counts[stored_label] - 1,
            )
            return commit_label(entry, best_label, best_field, now)

    # A device-announced alternative, a less preferred field, or no usable
    # name at all: hold the stored label until it has gone unreported long enough.
    if not best_label or best_priority > stored_priority:
        reason = f"{stored_field or 'preferred field'} missing"
    else:
        reason = f"{best_label} reported instead"
    polls = int(entry.get("downgrade_polls", 0)) + 1
    if polls >= config.name_downgrade_polls:
        LOG.info(
            "Label for %s: %s -> %s (%s for %d polls)",
            mac, stored_label, best_label or "(none)", reason, polls,
        )
        return commit_label(entry, best_label, best_field, now)
    entry["downgrade_polls"] = polls
    LOG.debug(
        "Holding %s for %s: %s %d/%d polls",
        stored_label, mac, reason, polls, config.name_downgrade_polls,
    )
    return entry


def assign_suffixes(config: Config, memory: dict[str, dict[str, Any]]) -> None:
    """Suffix every client whose label is shared with another remembered client.

    Grouping covers clients that are offline but still remembered, so a
    device's name does not depend on which of its namesakes is online.
    """
    groups: dict[str, list[str]] = {}
    for mac, entry in memory.items():
        label = str(entry.get("label", ""))
        if label and label not in config.excluded_names:
            groups.setdefault(label, []).append(mac)
        else:
            entry["suffix"] = ""
    for macs in groups.values():
        for mac in macs:
            memory[mac]["suffix"] = mac[-6:] if len(macs) > 1 else ""


def record_label(label: str, suffix: str) -> str:
    if not suffix:
        return label
    return f"{label[:max(1, 62 - len(suffix))].rstrip('-')}-{suffix}"


def desired_records(
    config: Config,
    clients: list[dict[str, Any]],
    memory: dict[str, dict[str, Any]],
    now: int,
) -> tuple[dict[str, dict[str, str]], dict[str, dict[str, Any]]]:
    """Return the records the zone should hold and the updated naming memory."""
    next_memory: dict[str, dict[str, Any]] = {}
    online: dict[str, str] = {}
    stateless: list[tuple[str, str]] = []
    label_counts: dict[str, int] = {}
    for entry in memory.values():
        label = str(entry.get("label", ""))
        if label and now - int(entry.get("last_seen", 0)) < config.name_memory_ttl:
            label_counts[label] = label_counts.get(label, 0) + 1

    for client in clients:
        address = client_ip(client)
        if not address:
            continue
        ip_obj = ipaddress.ip_address(address)
        if config.allowed_networks and not any(ip_obj in net for net in config.allowed_networks):
            continue
        mac = client_mac(client)
        candidates = client_labels(client, config.name_fields, mac, config.strip_trailing_mac)
        if not mac:
            if candidates:
                stateless.append((candidates[0][1], address))
            continue
        if mac in online:
            continue
        online[mac] = address
        next_memory[mac] = resolve_label(config, mac, memory.get(mac), candidates, now, label_counts)

    for mac, entry in memory.items():
        if mac not in next_memory and now - int(entry.get("last_seen", 0)) < config.name_memory_ttl:
            next_memory[mac] = dict(entry)

    assign_suffixes(config, next_memory)

    desired: dict[str, dict[str, str]] = {}
    for mac, address in online.items():
        entry = next_memory[mac]
        label = str(entry.get("label", ""))
        if not label or label in config.excluded_names:
            continue
        fqdn = f"{record_label(label, str(entry.get('suffix', '')))}.{config.dns_zone}"
        desired[fqdn] = {"ip": address, "mac": mac}

    remembered = {str(entry.get("label", "")) for entry in next_memory.values()}
    stateless_counts: dict[str, int] = {}
    for label, _ in stateless:
        stateless_counts[label] = stateless_counts.get(label, 0) + 1
    for label, address in stateless:
        if label in config.excluded_names:
            continue
        collides = label in remembered or stateless_counts[label] > 1
        suffix = address.replace(".", "-") if collides else ""
        desired[f"{record_label(label, suffix)}.{config.dns_zone}"] = {"ip": address, "mac": ""}

    return dict(sorted(desired.items())), next_memory


def record_address(record: dict[str, Any]) -> str:
    rdata = record.get("rData", {})
    return str(rdata.get("ipAddress", "")) if isinstance(rdata, dict) else ""


def record_is_managed(record: dict[str, Any]) -> bool:
    comments = record.get("comments", "")
    return isinstance(comments, str) and MARKER in comments


STATE_VERSION = 2


def empty_state() -> dict[str, Any]:
    return {"version": STATE_VERSION, "managed_records": {}, "pending": {}, "clients": {}}


def migrate_state(data: dict[str, Any], zone: str) -> dict[str, Any]:
    """Upgrade a state document to the current schema (idempotent).

    Version 1 files have no naming memory; it is seeded from the records the
    service already owns so that the first cycle after an upgrade renames
    nothing.
    """
    if not isinstance(data.get("pending"), dict):
        data["pending"] = {}
    if not isinstance(data.get("clients"), dict):
        clients: dict[str, dict[str, Any]] = {}
        zone_suffix = f".{zone}"
        for fqdn, item in data["managed_records"].items():
            if not isinstance(item, dict):
                continue
            mac = str(item.get("mac", ""))
            if not mac:
                continue
            label = fqdn[: -len(zone_suffix)] if fqdn.endswith(zone_suffix) else fqdn
            suffix = ""
            tail = f"-{mac[-6:]}"
            if len(mac) >= 6 and label.endswith(tail) and len(label) > len(tail):
                label, suffix = label[: -len(tail)], mac[-6:]
            seen = int(item.get("last_seen", 0))
            current = clients.get(mac)
            if current and int(current.get("last_seen", 0)) >= seen:
                continue
            entry = new_entry(label, "", seen)
            entry["suffix"] = suffix
            clients[mac] = entry
        data["clients"] = clients
    data["version"] = STATE_VERSION
    return data


def load_state(path: Path, zone: str) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, dict) and isinstance(data.get("managed_records"), dict):
            return migrate_state(data, zone)
    except FileNotFoundError:
        pass
    except (OSError, json.JSONDecodeError) as exc:
        LOG.warning("Ignoring unreadable state file %s: %s", path, exc)
    return empty_state()


def skip_warning(skips: set[tuple[str, str]], fqdn: str, reason: str, message: str, *args: Any) -> None:
    """Warn on the first occurrence of a skip condition, then demote to debug."""
    key = (fqdn, reason)
    skips.add(key)
    if key in WARNED:
        LOG.debug(message, *args)
    else:
        LOG.warning(message, *args)


def save_state(path: Path, state: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def synchronize(
    config: Config,
    unifi: UnifiClient,
    technitium: TechnitiumClient,
    dry_run: bool,
    now: int | None = None,
) -> SyncResult:
    if now is None:
        now = int(time.time())
    clock_start = time.monotonic()
    action_start = len(technitium.actions)
    deferred: list[dict[str, str]] = []
    state = load_state(config.state_file, config.dns_zone)
    previous: dict[str, dict[str, Any]] = state["managed_records"]
    pending: dict[str, dict[str, Any]] = state["pending"]
    memory: dict[str, dict[str, Any]] = state["clients"]
    next_pending: dict[str, dict[str, Any]] = {}
    skips: set[tuple[str, str]] = set()

    clients = unifi.connected_clients()
    desired, next_memory = desired_records(config, clients, memory, now)
    zone_records = technitium.records()
    records_by_name: dict[str, list[dict[str, Any]]] = {}
    a_records: dict[str, list[dict[str, Any]]] = {}
    for record in zone_records:
        record_name = str(record.get("name", "")).lower().rstrip(".")
        records_by_name.setdefault(record_name, []).append(record)
        if record.get("type") == "A":
            a_records.setdefault(record_name, []).append(record)

    # Recover ownership after state loss only when Technitium retained our marker.
    for fqdn, records in a_records.items():
        for record in records:
            if record_is_managed(record) and fqdn not in previous:
                previous[fqdn] = {
                    "ip": record_address(record),
                    "mac": "",
                    "last_seen": now,
                }

    next_managed: dict[str, dict[str, Any]] = {}
    for fqdn, item in desired.items():
        address = item["ip"]
        existing = a_records.get(fqdn, [])
        owned = previous.get(fqdn)
        existing_addresses = {record_address(record) for record in existing}
        has_unmanaged = any(not record_is_managed(record) for record in existing)
        conflicting_types = sorted(
            {
                str(record.get("type", "unknown"))
                for record in records_by_name.get(fqdn, [])
                if record.get("type") != "A"
            }
        )

        if conflicting_types:
            skip_warning(
                skips,
                fqdn,
                "conflict",
                "Skipping %s: conflicting %s record already exists",
                fqdn,
                "/".join(conflicting_types),
            )
            continue
        if has_unmanaged and not owned:
            skip_warning(
                skips,
                fqdn,
                "unmanaged",
                "Skipping %s: an unmanaged A record already exists",
                fqdn,
            )
            continue

        old_address = str(owned.get("ip", "")) if owned else ""
        if old_address and old_address != address:
            # Dampen IP changes: only apply after the same new address has been
            # reported for ip_stable_polls consecutive cycles.
            watch = pending.get(fqdn, {})
            count = int(watch.get("count", 0)) + 1 if watch.get("ip") == address else 1
            if count < config.ip_stable_polls:
                next_pending[fqdn] = {"ip": address, "count": count}
                deferred.append({
                    "name": fqdn,
                    "kind": "ip",
                    "detail": f"{old_address} -> {address} seen {count}/{config.ip_stable_polls} polls",
                })
                LOG.debug(
                    "Deferring %s: %s -> %s seen %d/%d polls",
                    fqdn,
                    old_address,
                    address,
                    count,
                    config.ip_stable_polls,
                )
                next_managed[fqdn] = {
                    "ip": old_address,
                    "mac": item["mac"],
                    "last_seen": now,
                }
                continue
            if old_address in existing_addresses:
                technitium.delete_a(fqdn, old_address)
                existing_addresses.discard(old_address)
        if address not in existing_addresses:
            technitium.add_a(fqdn, address)
        next_managed[fqdn] = {"ip": address, "mac": item["mac"], "last_seen": now}

    mac_to_fqdn = {
        item["mac"]: fqdn for fqdn, item in next_managed.items() if item.get("mac")
    }
    for fqdn, old in previous.items():
        if fqdn in next_managed:
            continue
        old_mac = str(old.get("mac", ""))
        renamed = bool(old_mac) and mac_to_fqdn.get(old_mac, fqdn) != fqdn
        if renamed:
            LOG.info(
                "Client renamed: %s is now %s; removing the old record",
                fqdn,
                mac_to_fqdn[old_mac],
            )
        else:
            last_seen = int(old.get("last_seen", now))
            if now - last_seen < config.stale_after:
                next_managed[fqdn] = old
                continue
        old_address = str(old.get("ip", ""))
        records = a_records.get(fqdn, [])
        matching_managed = any(
            record_address(record) == old_address and record_is_managed(record)
            for record in records
        )
        if matching_managed:
            technitium.delete_a(fqdn, old_address)
        else:
            LOG.warning("Not deleting %s: the owned record marker or address no longer matches", fqdn)

    LOG.info(
        "Sync complete: %d UniFi clients, %d desired records, %d tracked records",
        len(clients),
        len(desired),
        len(next_managed),
    )
    WARNED.clear()
    WARNED.update(skips)
    if not dry_run:
        save_state(
            config.state_file,
            {
                "version": STATE_VERSION,
                "last_success": now,
                "managed_records": next_managed,
                "pending": next_pending,
                "clients": next_memory,
            },
        )
    online_macs = {item["mac"] for item in desired.values()}
    for mac, entry in next_memory.items():
        if mac not in online_macs:
            continue
        label = f"{entry.get('label', '')}.{config.dns_zone}"
        watch = entry.get("candidate")
        if isinstance(watch, dict):
            deferred.append({
                "name": label,
                "kind": "label",
                "detail": f"rename to {watch.get('label')} seen {watch.get('count')}/{config.name_stable_polls} polls",
            })
        elif int(entry.get("downgrade_polls", 0)) > 0:
            deferred.append({
                "name": label,
                "kind": "label",
                "detail": f"stored name not reported {entry['downgrade_polls']}/{config.name_downgrade_polls} polls",
            })
    return SyncResult(
        started=now,
        duration=round(time.monotonic() - clock_start, 3),
        dry_run=dry_run,
        clients=len(clients),
        desired=len(desired),
        tracked=len(next_managed),
        actions=list(technitium.actions[action_start:]),
        skipped=[{"name": name, "reason": reason} for name, reason in sorted(skips)],
        deferred=deferred,
    )


def backfill_ptr(config: Config, technitium: TechnitiumClient, dry_run: bool) -> int:
    """One-time creation of PTR records for existing managed A records."""
    if not config.create_ptr:
        print("CREATE_PTR is not enabled; nothing to backfill.", file=sys.stderr)
        return 2
    count = 0
    for record in technitium.records():
        if record.get("type") != "A" or not record_is_managed(record):
            continue
        fqdn = str(record.get("name", "")).lower().rstrip(".")
        address = record_address(record)
        if not fqdn or not address:
            continue
        LOG.info(
            "%sBACKFILL PTR %s -> %s", "[dry-run] " if dry_run else "", address, fqdn
        )
        if not dry_run:
            technitium.ensure_ptr(fqdn, address)
        count += 1
    LOG.info("Backfill complete: %d managed records processed", count)
    return 0


def stop_handler(_signum: int, _frame: Any) -> None:
    global STOP
    STOP = True
    WAKE.set()


class RingHandler(logging.Handler):
    """Keeps the last N formatted log lines in memory for the web UI."""

    def __init__(self, capacity: int = 500):
        super().__init__()
        self.lines: deque[str] = deque(maxlen=capacity)
        self._guard = threading.Lock()

    def emit(self, record: logging.LogRecord) -> None:
        try:
            line = self.format(record)
        except Exception:  # noqa: BLE001 - logging must never raise
            return
        with self._guard:
            self.lines.append(line)

    def tail(self, count: int) -> list[str]:
        with self._guard:
            return list(self.lines)[-count:]


def default_clients(config: Config, dry_run: bool) -> tuple[Any, Any]:
    return UnifiClient(config), TechnitiumClient(config, dry_run)


class Runtime:
    """State shared by the sync loop, the embedded web UI and the CLI."""

    def __init__(
        self,
        config: Config,
        config_path: Path | None = None,
        client_factory: Callable[[Config, bool], tuple[Any, Any]] | None = None,
        dry_run: bool = False,
    ):
        self.lock = threading.RLock()
        self.sync_lock = threading.Lock()
        self.wake = WAKE
        self.config = config
        self.config_path = config_path
        self.client_factory = client_factory or default_clients
        self.dry_run = dry_run
        self.history: deque[SyncResult] = deque(maxlen=50)
        self.next_run: float | None = None
        self.started = int(time.time())
        self.log = RingHandler()
        self._sync_requested = False

    def current_config(self) -> Config:
        with self.lock:
            return self.config

    def run_sync(self, dry_run: bool | None = None) -> SyncResult:
        """Run one cycle. Loop runs (dry_run=None) are recorded in the history."""
        config = self.current_config()
        dry = self.dry_run if dry_run is None else dry_run
        with self.sync_lock:
            started = int(time.time())
            clock_start = time.monotonic()
            technitium: Any = None
            try:
                unifi, technitium = self.client_factory(config, dry)
                result = synchronize(config, unifi, technitium, dry, now=started)
            except Exception as exc:  # noqa: BLE001 - one bad cycle must not stop the loop
                LOG.exception("Synchronization failed")
                result = SyncResult(
                    started=started,
                    duration=round(time.monotonic() - clock_start, 3),
                    dry_run=dry,
                    actions=list(getattr(technitium, "actions", None) or []),
                    error=f"{type(exc).__name__}: {exc}",
                )
        if dry_run is None:
            with self.lock:
                self.history.appendleft(result)
        return result

    def request_sync(self) -> None:
        with self.lock:
            self._sync_requested = True
        self.wake.set()

    def take_sync_request(self) -> bool:
        with self.lock:
            requested, self._sync_requested = self._sync_requested, False
        return requested

    def password_hash(self) -> str:
        """Current web password hash; re-read from the config file so --set-web-password applies live."""
        if self.config_path is not None:
            try:
                return read_env_file(self.config_path).get("WEB_PASSWORD_HASH", "").strip()
            except OSError:
                pass
        return self.current_config().web_password_hash

    def config_writable(self) -> bool:
        return (
            self.config_path is not None
            and os.access(self.config_path, os.W_OK)
            and os.access(self.config_path.parent, os.W_OK)
        )

    def apply_settings(self, updates: Mapping[str, str]) -> Config:
        """Validate, persist and activate configuration changes from the web UI."""
        if self.config_path is None:
            raise ValueError("No configuration file is in use; start with CONFIG_FILE or --config")
        merged: dict[str, str] = dict(os.environ)
        merged.update(read_env_file(self.config_path))
        merged.update(updates)
        config = Config.from_mapping(merged)
        write_env_file(self.config_path, updates)
        with self.lock:
            self.config = config
        logging.getLogger().setLevel(getattr(logging, config.log_level, logging.INFO))
        self.wake.set()
        LOG.info("Configuration updated from the web UI: %s", ", ".join(sorted(updates)))
        return config

    def status(self) -> dict[str, Any]:
        config = self.current_config()
        with self.lock:
            history = [result.to_dict() for result in self.history]
            next_run = self.next_run
        return {
            "version": VERSION,
            "started": self.started,
            "now": int(time.time()),
            "next_run": next_run,
            "dry_run": self.dry_run,
            "config": {
                "zone": config.dns_zone,
                "sync_interval": config.sync_interval,
                "unifi": urllib.parse.urlsplit(config.unifi_url).netloc,
                "technitium": urllib.parse.urlsplit(config.technitium_url).netloc,
                "create_ptr": config.create_ptr,
                "config_path": str(self.config_path) if self.config_path else None,
                "config_writable": self.config_writable(),
            },
            "last": history[0] if history else None,
            "history": history,
        }


def set_web_password(config_path: Path | None) -> int:
    if config_path is None:
        print("--set-web-password needs --config FILE (or CONFIG_FILE) to know where to store the hash",
              file=sys.stderr)
        return 2
    if sys.stdin.isatty():
        password = getpass.getpass("New web UI password: ")
        if password != getpass.getpass("Repeat password: "):
            print("Passwords do not match.", file=sys.stderr)
            return 2
    else:
        password = sys.stdin.readline().rstrip("\r\n")
    if len(password) < 8:
        print("Password must be at least 8 characters.", file=sys.stderr)
        return 2
    write_env_file(config_path, {"WEB_PASSWORD_HASH": hash_password(password)})
    print(f"Password hash written to {config_path}. A running web UI uses it for the next login; "
          "set WEB_LISTEN and restart the service if the UI is not enabled yet.")
    return 0


def start_web(runtime: Runtime) -> None:
    try:
        import unifi_technitium_web as web  # sibling file; only needed when WEB_LISTEN is set
    except ImportError as exc:
        LOG.error("WEB_LISTEN is set but unifi_technitium_web.py cannot be imported: %s", exc)
        return
    try:
        web.start(runtime, sys.modules[__name__])
    except OSError as exc:
        LOG.error("Web UI could not start on %s: %s", runtime.current_config().web_listen, exc)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--config", metavar="FILE",
        help="read settings from this env file (default: $CONFIG_FILE, else the environment only)",
    )
    parser.add_argument("--once", action="store_true", help="run one synchronization and exit")
    parser.add_argument("--dry-run", action="store_true", help="show changes without writing DNS")
    parser.add_argument(
        "--backfill-ptr",
        action="store_true",
        help="create PTR records for existing managed A records, then exit",
    )
    parser.add_argument(
        "--set-web-password",
        action="store_true",
        help="prompt for a web UI password, store its hash in the config file, then exit",
    )
    parser.add_argument(
        "--log-level", choices=LOG_LEVELS, help="override LOG_LEVEL for this run"
    )
    parser.add_argument("--version", action="version", version=VERSION)
    args = parser.parse_args()

    config_path: Path | None = None
    if args.config:
        config_path = Path(args.config)
    elif os.getenv("CONFIG_FILE", "").strip():
        config_path = Path(os.environ["CONFIG_FILE"].strip())

    if args.set_web_password:
        return set_web_password(config_path)

    mapping: dict[str, str] = dict(os.environ)
    if config_path is not None:
        try:
            mapping.update(read_env_file(config_path))
        except OSError as exc:
            print(f"Configuration error: cannot read {config_path}: {exc}", file=sys.stderr)
            return 2
    if args.log_level:
        mapping["LOG_LEVEL"] = args.log_level
    try:
        config = Config.from_mapping(mapping)
    except (ValueError, KeyError) as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        return 2

    log_format = "%(asctime)s %(levelname)s %(message)s"
    logging.basicConfig(level=getattr(logging, config.log_level, logging.INFO), format=log_format)
    runtime = Runtime(config, config_path, dry_run=args.dry_run)
    runtime.log.setFormatter(logging.Formatter(log_format))
    logging.getLogger().addHandler(runtime.log)
    if not config.unifi_verify_tls:
        LOG.warning("UNIFI_VERIFY_TLS=false; TLS certificate verification is disabled")
    if not config.technitium_verify_tls:
        LOG.warning("TECHNITIUM_VERIFY_TLS=false; TLS certificate verification is disabled")

    signal.signal(signal.SIGTERM, stop_handler)
    signal.signal(signal.SIGINT, stop_handler)

    if args.backfill_ptr:
        return backfill_ptr(config, TechnitiumClient(config, args.dry_run), args.dry_run)

    if config.web_listen and not args.once:
        start_web(runtime)

    while not STOP:
        result = runtime.run_sync()
        if args.once:
            return 1 if result.error else 0
        last_run = time.monotonic()
        runtime.next_run = time.time() + runtime.current_config().sync_interval
        while not STOP:
            deadline = last_run + runtime.current_config().sync_interval
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            if runtime.wake.wait(timeout=min(1.0, remaining)):
                runtime.wake.clear()
                if runtime.take_sync_request():
                    break
                runtime.next_run = time.time() + max(0.0, deadline - time.monotonic())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
