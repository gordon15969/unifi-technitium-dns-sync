#!/usr/bin/env python3
"""Embedded web UI for unifi-technitium-sync.

Standard library only. The main daemon imports this module when WEB_LISTEN is
set and never otherwise. Everything the browser needs (HTML, CSS, JavaScript)
is in this file, so there is nothing to install and nothing fetched from the
internet.

The daemon passes itself in as ``core`` so this module does not import it (the
main script runs as ``__main__`` and must not be loaded twice).
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import logging
import os
import secrets
import socket
import ssl
import sys
import threading
import time
from dataclasses import replace
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlsplit

SESSION_COOKIE = "uts_session"
SESSION_TTL = 12 * 3600
LOGIN_WINDOW = 300          # seconds a failed attempt counts against its address
LOGIN_MAX_FAILURES = 5      # failed attempts allowed per address within LOGIN_WINDOW
AUTH_CONCURRENCY = 2        # password checks (PBKDF2) running at once, all addresses
LOOPBACK = {"127.0.0.1", "::1", "localhost"}
MAX_BODY = 256 * 1024
LOG = logging.getLogger("unifi-technitium-sync")
MAX_CONNECTIONS = 32        # concurrent connections; more get an immediate 503
SOCKET_TIMEOUT = 15         # seconds a connection may stall mid-request before it is closed
HANDSHAKE_TIMEOUT = 10      # seconds allowed for a TLS handshake


def is_loopback(host: str) -> bool:
    return host in LOOPBACK


def split_host(value: str) -> str:
    """The host of a Host header or URL authority: lowercase, no port, no brackets."""
    value = value.strip().lower()
    if value.startswith("["):
        end = value.find("]")
        return value[1:end] if end > 0 else ""
    if value.count(":") == 1:
        value = value.split(":", 1)[0]
    return value.rstrip(".")


def is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


class RequestTooLarge(ValueError):
    """The declared request body exceeds MAX_BODY."""


class WebState:
    """Sessions, login throttling and references to the daemon runtime."""

    def __init__(self, runtime: Any, core: Any):
        self.runtime = runtime
        self.core = core
        self.lock = threading.Lock()
        self.sessions: dict[str, dict[str, Any]] = {}
        self.failures: dict[str, list[float]] = {}
        self.inflight: set[str] = set()
        self.auth_slots = threading.BoundedSemaphore(AUTH_CONCURRENCY)
        self.anonymous = {"csrf": secrets.token_urlsafe(32), "expires": float("inf")}
        self.tls = bool(runtime.current_config().web_tls_cert)
        self.insecure_transport = False  # set by start() for plain HTTP on a network address
        self.own_names = {"localhost"}
        for name in (socket.gethostname(), socket.getfqdn()):
            if name:
                self.own_names.add(name.lower().rstrip("."))
        self.refused_hosts: set[str] = set()

    def password_set(self) -> bool:
        return bool(self.runtime.password_hash())

    def password_fingerprint(self) -> str:
        """Identifies the current password hash; sessions die when it changes."""
        return hashlib.sha256(self.runtime.password_hash().encode("utf-8")).hexdigest()

    def host_allowed(self, host: str) -> bool:
        """Accept IP literals, localhost, this machine's own names and WEB_ALLOWED_HOSTS.

        Refusing every other Host header defeats DNS rebinding: a page on an
        attacker's domain that has been re-pointed at this machine still sends
        the attacker's domain as its Host.
        """
        if not host:
            return False
        if is_ip_literal(host) or host in self.own_names:
            return True
        return host in getattr(self.runtime.current_config(), "web_allowed_hosts", ())

    def note_refused_host(self, host: str, client_ip: str) -> None:
        with self.lock:
            first = host not in self.refused_hosts and len(self.refused_hosts) < 100
            if first:
                self.refused_hosts.add(host)
        (self.core.LOG.warning if first else self.core.LOG.debug)(
            "Web UI refused a request for host %r from %s; add it to WEB_ALLOWED_HOSTS if it is yours",
            host, client_ip,
        )

    def auth_required(self) -> bool:
        return self.password_set()

    def _prune_failures(self, now: float) -> None:
        for address in list(self.failures):
            recent = [t for t in self.failures[address] if now - t < LOGIN_WINDOW]
            if recent:
                self.failures[address] = recent
            else:
                del self.failures[address]

    def check_password(self, password: str, client_ip: str) -> str:
        """Verify a password under the throttle. Returns "ok", "denied" or "throttled".

        The attempt is reserved, counted as a failure, before the slow hash
        runs, so parallel requests cannot all slip past the limit: an address
        gets one check at a time and LOGIN_MAX_FAILURES per LOGIN_WINDOW, and
        at most AUTH_CONCURRENCY checks run at once across all addresses. Used
        for logins and for re-authentication before sensitive changes.
        """
        now = time.time()
        with self.lock:
            self._prune_failures(now)
            if client_ip in self.inflight or len(self.failures.get(client_ip, [])) >= LOGIN_MAX_FAILURES:
                return "throttled"
            if not self.auth_slots.acquire(blocking=False):
                return "throttled"
            self.inflight.add(client_ip)
            self.failures.setdefault(client_ip, []).append(now)
        try:
            ok = self.core.verify_password(self.runtime.password_hash(), password)
        finally:
            with self.lock:
                self.inflight.discard(client_ip)
            self.auth_slots.release()
        if not ok:
            return "denied"
        with self.lock:
            self.failures.pop(client_ip, None)
        return "ok"

    def login(self, password: str, client_ip: str) -> tuple[str, str | None]:
        """Check a password and open a session: ("ok", token), ("denied", None) or ("throttled", None)."""
        outcome = self.check_password(password, client_ip)
        if outcome != "ok":
            return outcome, None
        now = time.time()
        token = secrets.token_urlsafe(32)
        fingerprint = self.password_fingerprint()
        with self.lock:
            self.sessions = {t: s for t, s in self.sessions.items() if s["expires"] > now}
            self.sessions[token] = {
                "csrf": secrets.token_urlsafe(32),
                "expires": now + SESSION_TTL,
                "pw": fingerprint,
            }
        return "ok", token

    def session(self, token: str | None) -> dict[str, Any] | None:
        if not self.auth_required():
            return self.anonymous
        if not token:
            return None
        now = time.time()
        fingerprint = self.password_fingerprint()
        with self.lock:
            session = self.sessions.get(token)
            if session is None or session["expires"] <= now or session.get("pw") != fingerprint:
                # Expired, or the password changed since login (from the UI or the CLI).
                self.sessions.pop(token, None)
                return None
            session["expires"] = now + SESSION_TTL
            return session

    def logout(self, token: str | None) -> None:
        if token:
            with self.lock:
                self.sessions.pop(token, None)

    def invalidate_all(self) -> None:
        with self.lock:
            self.sessions.clear()


def records_payload(state: WebState) -> dict[str, Any]:
    runtime, core = state.runtime, state.core
    config = runtime.current_config()
    document = core.load_state(config.state_file, config.dns_zone)
    clients = document.get("clients", {})
    pending = document.get("pending", {})
    rows = []
    for fqdn, item in sorted(document["managed_records"].items()):
        mac = str(item.get("mac", ""))
        memory = clients.get(mac, {})
        rows.append({
            "name": fqdn,
            "ip": item.get("ip", ""),
            "mac": mac,
            "last_seen": item.get("last_seen"),
            "label": memory.get("label", ""),
            "field": memory.get("field", ""),
            "suffix": memory.get("suffix", ""),
            "downgrade_polls": memory.get("downgrade_polls", 0),
            "candidate": memory.get("candidate"),
            "pending_ip": pending.get(fqdn),
        })
    with runtime.lock:
        last = runtime.history[0] if runtime.history else None
    return {
        "records": rows,
        "skipped": last.skipped if last else [],
        "deferred": last.deferred if last else [],
        "last_success": document.get("last_success"),
        "clients_remembered": len(clients),
    }


def config_payload(state: WebState) -> dict[str, Any]:
    runtime, core = state.runtime, state.core
    values: dict[str, str] = {}
    if runtime.config_path is not None:
        try:
            values = core.read_env_file(runtime.config_path)
        except OSError:
            values = {}
    settings = []
    for spec in core.SETTINGS:
        raw = values.get(spec.key, os.environ.get(spec.key, ""))
        entry: dict[str, Any] = {
            "key": spec.key,
            "kind": spec.kind,
            "default": spec.default,
            "help": spec.help,
            "section": spec.section,
            "required": spec.required,
            "choices": list(spec.choices),
            "restart": spec.restart,
            "sensitive": spec.key in core.SENSITIVE_SETTINGS,
        }
        if spec.kind == "secret":
            entry["value"] = ""
            entry["set"] = bool(raw.strip())
        else:
            entry["value"] = raw
        settings.append(entry)
    return {
        "path": str(runtime.config_path) if runtime.config_path else None,
        "writable": runtime.config_writable(),
        "settings": settings,
    }


class Handler(BaseHTTPRequestHandler):
    state: WebState
    timeout = SOCKET_TIMEOUT  # applied to the connection by StreamRequestHandler.setup()
    protocol_version = "HTTP/1.1"
    server_version = "unifi-technitium-sync"
    sys_version = ""

    body_consumed = True

    def log_message(self, fmt: str, *args: Any) -> None:
        self.state.core.LOG.debug("web %s " + fmt, self.address_string(), *args)

    def parse_request(self) -> bool:
        # Nothing to drain while the request line and headers are parsed, or when they
        # are malformed (send_error closes the connection then).
        self.body_consumed = True
        if not super().parse_request():
            return False
        self.body_consumed = False
        return True

    def end_headers(self) -> None:
        # A reply sent before the request body was read (refused Host or Origin, 401,
        # 403, 413...) must not leave that body on a kept-alive connection: the next
        # request would be parsed starting with it. Discard it, or close.
        if not self.body_consumed and not self.close_connection:
            try:
                self.read_body()
            except (ValueError, OSError):
                self.send_header("Connection", "close")
        super().end_headers()

    # -- response helpers -------------------------------------------------
    def _send(self, status: int, body: bytes, content_type: str,
              extra: dict[str, str] | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        # Not "no-referrer": under that policy browsers send "Origin: null" on form
        # POSTs, which origin_ok() must refuse, and the login form stops working.
        self.send_header("Referrer-Policy", "same-origin")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; "
            "connect-src 'self'; form-action 'self'; base-uri 'none'",
        )
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def send_json(self, data: Any, status: int = 200, extra: dict[str, str] | None = None) -> None:
        self._send(status, json.dumps(data).encode("utf-8"), "application/json; charset=utf-8", extra)

    def send_html(self, text: str, status: int = 200, extra: dict[str, str] | None = None) -> None:
        self._send(status, text.encode("utf-8"), "text/html; charset=utf-8", extra)

    def redirect(self, location: str, extra: dict[str, str] | None = None) -> None:
        self.send_response(HTTPStatus.SEE_OTHER)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.send_header("Cache-Control", "no-store")
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        self.end_headers()

    def cookie_token(self) -> str | None:
        raw = self.headers.get("Cookie")
        if not raw:
            return None
        cookie: SimpleCookie = SimpleCookie()
        try:
            cookie.load(raw)
        except Exception:  # noqa: BLE001 - malformed cookie header
            return None
        morsel = cookie.get(SESSION_COOKIE)
        return morsel.value if morsel else None

    def cookie_header(self, token: str, max_age: int | None = None) -> dict[str, str]:
        parts = [f"{SESSION_COOKIE}={token}", "Path=/", "HttpOnly", "SameSite=Strict"]
        if self.state.tls:
            parts.append("Secure")
        if max_age is not None:
            parts.append(f"Max-Age={max_age}")
        return {"Set-Cookie": "; ".join(parts)}

    def read_body(self) -> bytes:
        if self.headers.get("Transfer-Encoding"):
            raise ValueError("chunked request bodies are not supported")
        raw = (self.headers.get("Content-Length") or "").strip()
        if not raw:
            self.body_consumed = True
            return b""
        if not raw.isdigit():
            raise ValueError("invalid Content-Length")
        length = int(raw)
        if length > MAX_BODY:
            raise RequestTooLarge("request body too large")
        body = self.rfile.read(length) if length else b""
        self.body_consumed = True
        return body

    def host_ok(self) -> bool:
        """Refuse requests whose Host header is not one of ours (DNS rebinding)."""
        host = split_host(self.headers.get("Host", ""))
        if self.state.host_allowed(host):
            return True
        self.state.note_refused_host(host[:100], self.client_ip())
        self.send_html(
            "<!doctype html><title>Host not allowed</title><p>This host name is not allowed for "
            "the UniFi &rarr; Technitium web UI. Use the server's IP address, or add the name to "
            "WEB_ALLOWED_HOSTS.</p>",
            403,
        )
        return False

    def origin_ok(self) -> bool:
        """A browser's Origin on a state-changing request must also be one of our hosts."""
        origin = self.headers.get("Origin")
        if origin is None:
            return True
        if origin.strip().lower() == "null":
            return False
        return self.state.host_allowed(split_host(urlsplit(origin.strip()).netloc))

    def read_json(self) -> dict[str, Any]:
        body = self.read_body()
        if not body:
            return {}
        data = json.loads(body.decode("utf-8"))
        if not isinstance(data, dict):
            raise ValueError("expected a JSON object")
        return data

    def client_ip(self) -> str:
        return str(self.client_address[0])

    def authenticate(self) -> dict[str, Any] | None:
        return self.state.session(self.cookie_token())

    # -- GET ----------------------------------------------------------------
    def do_GET(self) -> None:  # noqa: N802 - http.server API
        if not self.host_ok():
            return
        parts = urlsplit(self.path)
        path = parts.path
        if path == "/login":
            if self.authenticate() is not None:
                return self.redirect("/")
            error = bool(parse_qs(parts.query).get("error"))
            return self.send_html(render_login(error))
        session = self.authenticate()
        if session is None:
            if path.startswith("/api/"):
                return self.send_json({"error": "unauthorized"}, 401)
            return self.redirect("/login")
        if path == "/":
            return self.send_html(render_page(self.state))
        if path == "/api/session":
            return self.send_json({"csrf": session["csrf"], "auth": self.state.auth_required()})
        if path == "/api/status":
            return self.send_json(self.state.runtime.status())
        if path == "/api/records":
            return self.send_json(records_payload(self.state))
        if path == "/api/config":
            return self.send_json(config_payload(self.state))
        if path == "/api/log":
            return self.send_json({"lines": self.state.runtime.log.tail(400)})
        self.send_json({"error": "not found"}, 404)

    def do_HEAD(self) -> None:  # noqa: N802
        self.do_GET()

    # -- POST ---------------------------------------------------------------
    def do_POST(self) -> None:  # noqa: N802
        if not self.host_ok():
            return
        if not self.origin_ok():
            return self.send_json({"error": "cross-origin request refused"}, 403)
        path = urlsplit(self.path).path
        try:
            if path == "/login":
                return self.handle_login()
            session = self.authenticate()
            if session is None:
                return self.send_json({"error": "unauthorized"}, 401)
            token = self.headers.get("X-CSRF-Token", "")
            if not hmac.compare_digest(token, session["csrf"]):
                return self.send_json({"error": "invalid CSRF token"}, 403)
            if path == "/logout":
                self.state.logout(self.cookie_token())
                return self.send_json({"ok": True}, extra=self.cookie_header("", 0))
            if path == "/api/sync":
                self.state.runtime.request_sync()
                return self.send_json({"ok": True})
            if path == "/api/dry-run":
                return self.send_json(self.state.runtime.run_sync(dry_run=True).to_dict())
            if path == "/api/config":
                return self.handle_config()
            if path == "/api/password":
                return self.handle_password()
            self.send_json({"error": "not found"}, 404)
        except RequestTooLarge as exc:
            self.send_json({"error": str(exc)}, 413)
        except ValueError as exc:
            self.send_json({"error": str(exc)}, 400)
        except Exception:  # noqa: BLE001 - report, never crash the server thread
            reference = secrets.token_hex(4)
            self.state.core.LOG.exception("Web request failed (reference %s)", reference)
            self.send_json({"error": f"internal error; see the service log for reference {reference}"}, 500)

    def handle_login(self) -> None:
        if not self.state.auth_required():
            return self.redirect("/")
        form = parse_qs(self.read_body().decode("utf-8", errors="replace"))
        password = (form.get("password") or [""])[0]
        outcome, token = self.state.login(password, self.client_ip())
        if outcome == "throttled" or token is None:
            log = self.state.core.LOG.debug if outcome == "throttled" else self.state.core.LOG.warning
            log("Web UI login %s from %s", "throttled" if outcome == "throttled" else "failed", self.client_ip())
            return self.redirect("/login?error=1")
        self.state.core.LOG.info("Web UI login from %s", self.client_ip())
        return self.redirect("/", self.cookie_header(token, SESSION_TTL))

    def handle_config(self) -> None:
        data = self.read_json()
        values = data.get("values")
        if not isinstance(values, dict):
            raise ValueError("expected a 'values' object")
        specs = {spec.key: spec for spec in self.state.core.SETTINGS}
        updates: dict[str, str] = {}
        for key, value in values.items():
            spec = specs.get(str(key))
            if spec is None:
                raise ValueError(f"unknown setting {key}")
            if spec.key == "WEB_PASSWORD_HASH":
                continue
            if not isinstance(value, str):
                raise ValueError(f"{key}: expected a string")
            text = value.strip()
            if spec.kind == "secret" and not text:
                continue
            updates[spec.key] = text
        if not updates:
            return self.send_json({"ok": True, "changed": [], "restart": []})
        core, runtime = self.state.core, self.state.runtime
        current = core.read_env_file(runtime.config_path) if runtime.config_path else {}
        sensitive = sorted(
            key for key, value in updates.items()
            if key in core.SENSITIVE_SETTINGS and value != current.get(key, "")
        )
        if sensitive and self.state.auth_required():
            # These decide where the API credentials go, which files are written and how
            # the UI is exposed: a stolen session alone must not be enough to change them.
            password = data.get("current_password")
            if not isinstance(password, str) or not password:
                return self.send_json({
                    "error": "enter your current password to change " + ", ".join(sensitive),
                    "needs_password": sensitive,
                }, 403)
            outcome = self.state.check_password(password, self.client_ip())
            if outcome == "throttled":
                return self.send_json({"error": "too many password attempts; wait a few minutes",
                                       "needs_password": sensitive}, 429)
            if outcome != "ok":
                core.LOG.warning("Settings change from %s refused: wrong current password", self.client_ip())
                return self.send_json({"error": "current password is wrong", "needs_password": sensitive}, 403)
        runtime.apply_settings(updates)
        if sensitive:
            core.LOG.warning("Sensitive settings changed from the web UI by %s: %s",
                             self.client_ip(), ", ".join(sensitive))
        return self.send_json({
            "ok": True,
            "changed": sorted(updates),
            "restart": sorted(key for key in updates if specs[key].restart),
        })

    def handle_password(self) -> None:
        data = self.read_json()
        current = str(data.get("current", ""))
        new = str(data.get("new", ""))
        runtime, core = self.state.runtime, self.state.core
        if len(new) < 8:
            raise ValueError("the new password must be at least 8 characters")
        if runtime.password_hash():
            outcome = self.state.check_password(current, self.client_ip())
            if outcome == "throttled":
                return self.send_json({"error": "too many password attempts; wait a few minutes"}, 429)
            if outcome != "ok":
                return self.send_json({"error": "current password is wrong"}, 403)
        if runtime.config_path is None:
            raise ValueError("no configuration file is in use; use --config")
        digest = core.hash_password(new)
        with core.settings_lock(runtime.config_path):
            core.write_env_file(runtime.config_path, {"WEB_PASSWORD_HASH": digest})
            with runtime.lock:
                runtime.config = replace(runtime.config, web_password_hash=digest)
        self.state.invalidate_all()
        core.LOG.info("Web UI password changed from %s", self.client_ip())
        return self.send_json({"ok": True, "relogin": True})


class BoundedHTTPServer(ThreadingHTTPServer):
    """ThreadingHTTPServer with a connection cap and TLS handshakes off the accept loop.

    The stock server starts one thread per connection without limit, and
    wrapping its listening socket in TLS makes accept() run every handshake in
    the single accepting thread, where one stalled client blocks everyone.
    """

    daemon_threads = True

    def __init__(self, address, handler, ssl_context: ssl.SSLContext | None = None,
                 max_connections: int = MAX_CONNECTIONS):
        self.ssl_context = ssl_context
        self.slots = threading.BoundedSemaphore(max_connections)
        super().__init__(address, handler)

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            if self.ssl_context is None:
                try:
                    request.sendall(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n"
                                    b"Connection: close\r\nRetry-After: 5\r\n\r\n")
                except OSError:
                    pass
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()

    def handle_error(self, request, client_address):
        """Log instead of printing a traceback to stderr; a client hanging up is routine."""
        error = sys.exc_info()[1]
        if isinstance(error, (ConnectionError, TimeoutError, ssl.SSLError)):
            LOG.debug("Web UI connection from %s ended: %s", client_address[0], error)
        else:
            LOG.exception("Web UI request from %s failed", client_address[0])

    def finish_request(self, request, client_address):
        if self.ssl_context is None:
            return super().finish_request(request, client_address)
        request.settimeout(HANDSHAKE_TIMEOUT)
        try:
            connection = self.ssl_context.wrap_socket(request, server_side=True)
        except (ssl.SSLError, OSError):
            return None
        try:
            self.RequestHandlerClass(connection, client_address, self)
        finally:
            try:
                connection.close()
            except OSError:
                pass
        return None


def start(runtime: Any, core: Any) -> ThreadingHTTPServer | None:
    """Start the UI in a daemon thread. Returns the server, or None if refused."""
    config = runtime.current_config()
    host, port = core.parse_listen(config.web_listen)
    state = WebState(runtime, core)
    if not state.password_set() and not is_loopback(host):
        core.LOG.error(
            "Web UI not started: WEB_LISTEN=%s is not a loopback address and no "
            "WEB_PASSWORD_HASH is set. Run: unifi_technitium_sync.py --config <file> --set-web-password",
            config.web_listen,
        )
        return None
    if not is_loopback(host) and not config.web_tls_cert:
        if not config.web_allow_insecure_lan:
            core.LOG.error(
                "Web UI not started: WEB_LISTEN=%s is reachable from the network but WEB_TLS_CERT "
                "is not set, so the password and session cookie would cross the network "
                "unencrypted. Set WEB_TLS_CERT and WEB_TLS_KEY, or bind to 127.0.0.1 and use an "
                "SSH tunnel or an HTTPS reverse proxy, or set WEB_ALLOW_INSECURE_LAN=true to "
                "accept the risk.",
                config.web_listen,
            )
            return None
        core.LOG.warning(
            "Web UI is serving plain HTTP on %s (WEB_ALLOW_INSECURE_LAN=true): the password and "
            "session cookie are not encrypted on the network",
            config.web_listen,
        )
        state.insecure_transport = True

    class BoundHandler(Handler):
        pass

    BoundHandler.state = state
    context = None
    scheme = "http"
    if config.web_tls_cert:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(config.web_tls_cert, config.web_tls_key)
        scheme = "https"
    server = BoundedHTTPServer((host, port), BoundHandler, ssl_context=context,
                               max_connections=MAX_CONNECTIONS)
    thread = threading.Thread(target=server.serve_forever, name="web-ui", daemon=True)
    thread.start()
    core.LOG.info(
        "Web UI listening on %s://%s:%d%s",
        scheme, host, server.server_address[1],
        "" if state.password_set() else " without a password (loopback only)",
    )
    return server


# ---------------------------------------------------------------------------
# Pages
# ---------------------------------------------------------------------------

BASE_CSS = r"""
:root{--bg:#f4f6f8;--fg:#1c2230;--muted:#667085;--card:#ffffff;--line:#dfe3e8;--accent:#2563eb;--ok:#15803d;--warn:#b45309;--err:#b91c1c;--mono:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;color-scheme:light}
@media(prefers-color-scheme:dark){:root{--bg:#0f1317;--fg:#e6e8eb;--muted:#9aa3b2;--card:#171c22;--line:#2a313b;--accent:#60a5fa;--ok:#4ade80;--warn:#fbbf24;--err:#f87171;color-scheme:dark}}
*{box-sizing:border-box}[hidden]{display:none!important}
body{margin:0;font:14px/1.45 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;background:var(--bg);color:var(--fg)}
h1{font-size:16px;margin:0}h3{font-size:13px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted);margin:22px 0 8px}
a{color:var(--accent)}
.card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:12px 14px}
.card h3{margin:0 0 6px;font-size:11px}.card .big{font-size:20px;font-weight:600;word-break:break-word}
button{font:inherit;cursor:pointer;border-radius:6px;padding:7px 14px}
button.primary{background:var(--accent);color:#fff;border:1px solid var(--accent)}
button.ghost{background:transparent;border:1px solid var(--line);color:var(--fg)}
button:disabled{opacity:.5;cursor:default}
input,select{font:inherit;padding:6px 8px;border:1px solid var(--line);border-radius:6px;background:var(--bg);color:var(--fg)}
.ok{color:var(--ok)}.err{color:var(--err)}.warn{color:var(--warn)}.muted{color:var(--muted)}
.mono{font-family:var(--mono);font-size:12px}
.msg{margin:10px 0;padding:8px 12px;border-radius:6px;border:1px solid var(--line);background:var(--card)}
.msg.err{border-color:var(--err)}.msg.ok{border-color:var(--ok)}.msg.warn{border-color:var(--warn)}
"""

PAGE_CSS = r"""
header{display:flex;flex-wrap:wrap;gap:10px;align-items:center;padding:12px 20px;border-bottom:1px solid var(--line);background:var(--card);position:sticky;top:0;z-index:1}
header h1{margin-right:auto}header h1 span{font-weight:400;color:var(--muted);font-size:13px;margin-left:6px}
nav{display:flex;gap:6px;flex-wrap:wrap}nav button.active{border-color:var(--accent);color:var(--accent)}
main{padding:20px;max-width:1200px;margin:0 auto}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:12px}
.toolbar{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin:14px 0}
.wrap{overflow-x:auto;border:1px solid var(--line);border-radius:8px;background:var(--card)}
table{width:100%;border-collapse:collapse}
th,td{text-align:left;padding:6px 10px;border-bottom:1px solid var(--line);vertical-align:top;white-space:nowrap}
th{font-size:12px;color:var(--muted);font-weight:600}tbody tr:last-child td{border-bottom:0}
td.wrapcell{white-space:normal}
pre{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:12px;overflow:auto;max-height:70vh;margin:0}
form.settings fieldset{border:1px solid var(--line);border-radius:8px;margin:0 0 14px;padding:6px 14px 10px;background:var(--card)}
legend{padding:0 6px;color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.04em}
.field{display:grid;grid-template-columns:minmax(200px,1fr) minmax(220px,2fr);gap:4px 16px;align-items:start;padding:8px 0;border-bottom:1px solid var(--line)}
.field:last-child{border-bottom:0}.field label{font-family:var(--mono);font-size:12px;padding-top:8px}
.field input,.field select{width:100%}.field small{display:block;color:var(--muted);margin-top:4px}
input.filter{min-width:260px;background:var(--card)}
@media(max-width:640px){.field{grid-template-columns:1fr}main{padding:12px}header{padding:10px 12px}}
"""

LOGIN_CSS = r"""
main.login{min-height:100vh;display:grid;place-items:center;padding:20px}
form.card{width:min(360px,100%);display:grid;gap:10px}
form.card label{font-size:12px;color:var(--muted)}
"""

PAGE_JS = r"""
(function () {
  'use strict';
  const BOOT = JSON.parse(document.getElementById('boot').textContent);
  const S = { csrf: null, tab: 'status', config: null, initial: {}, records: null };
  const $ = (sel, root) => (root || document).querySelector(sel);
  function el(tag, attrs) {
    const node = document.createElement(tag);
    if (attrs) for (const [k, v] of Object.entries(attrs)) {
      if (k === 'class') node.className = v;
      else if (k === 'text') node.textContent = v;
      else if (k.startsWith('on')) node.addEventListener(k.slice(2), v);
      else node.setAttribute(k, v);
    }
    for (let i = 2; i < arguments.length; i++) {
      const kid = arguments[i];
      if (kid == null) continue;
      node.append(kid.nodeType ? kid : document.createTextNode(String(kid)));
    }
    return node;
  }
  async function api(path, opts) {
    opts = opts || {};
    const headers = {};
    if (opts.method && opts.method !== 'GET') { headers['X-CSRF-Token'] = S.csrf; headers['Content-Type'] = 'application/json'; }
    const r = await fetch(path, { method: opts.method || 'GET', headers, body: opts.body ? JSON.stringify(opts.body) : undefined, credentials: 'same-origin' });
    if (r.status === 401) { location.href = '/login'; throw new Error('Session expired'); }
    let data; try { data = await r.json(); } catch (e) { data = { error: r.statusText }; }
    if (!r.ok) throw new Error(data.error || r.statusText);
    return data;
  }
  const fmt = {
    time: ts => ts ? new Date(ts * 1000).toLocaleString() : '—',
    ago: ts => { if (!ts) return '—'; const s = Math.max(0, Math.round(Date.now() / 1000 - ts)); return s < 60 ? s + ' s ago' : s < 3600 ? Math.round(s / 60) + ' min ago' : s < 86400 ? (s / 3600).toFixed(1) + ' h ago' : (s / 86400).toFixed(1) + ' d ago'; },
    until: ts => { if (!ts) return '—'; const s = Math.round(ts - Date.now() / 1000); return s <= 0 ? 'now' : s < 60 ? 'in ' + s + ' s' : 'in ' + Math.round(s / 60) + ' min'; },
    dur: d => d == null ? '—' : Number(d).toFixed(2) + ' s',
  };
  function table(headers, rows) {
    const t = el('table');
    const head = el('tr'); headers.forEach(h => head.append(el('th', { text: h }))); t.append(el('thead', null, head));
    const body = el('tbody');
    if (!rows.length) body.append(el('tr', null, el('td', { colspan: String(headers.length), class: 'muted', text: 'Nothing to show' })));
    rows.forEach(r => { const tr = el('tr'); r.forEach(c => tr.append(c && c.nodeType ? el('td', { class: 'wrapcell' }, c) : el('td', { text: c == null ? '' : String(c) }))); body.append(tr); });
    t.append(body);
    return el('div', { class: 'wrap' }, t);
  }
  function message(target, text, kind) { $(target).replaceChildren(el('div', { class: 'msg ' + (kind || ''), text })); }
  function card(title, big, small) { return el('div', { class: 'card' }, el('h3', { text: title }), el('div', { class: 'big' }, big), small != null ? el('div', { class: 'muted' }, small) : null); }

  async function renderStatus() {
    const s = await api('/api/status');
    const last = s.last;
    $('#status-cards').replaceChildren(
      card('Service', 'v' + s.version, 'up since ' + fmt.time(s.started) + (s.dry_run ? ' · DRY-RUN MODE' : '')),
      card('Last sync', last ? fmt.ago(last.started) : '—', last ? (last.error ? el('span', { class: 'err', text: 'failed: ' + last.error }) : el('span', { class: 'ok', text: 'ok · ' + fmt.dur(last.duration) })) : 'no cycle yet'),
      card('Next sync', fmt.until(s.next_run), 'every ' + s.config.sync_interval + ' s'),
      card('Records', last ? last.desired + ' desired' : '—', last ? last.tracked + ' tracked · ' + last.clients + ' UniFi clients' : ''),
      card('Last cycle', last ? last.adds + ' added · ' + last.deletes + ' deleted' : '—', last ? last.skipped.length + ' skipped · ' + last.deferred.length + ' deferred' : ''),
      card('Zone', s.config.zone, (s.config.create_ptr ? 'A + PTR' : 'A only') + ' · UniFi ' + s.config.unifi + ' · DNS ' + s.config.technitium)
    );
    $('#history').replaceChildren(table(['Time', 'Duration', 'Clients', 'Desired', 'Tracked', 'Adds', 'Deletes', 'Skipped', 'Deferred', 'Result'],
      s.history.map(h => [fmt.time(h.started), fmt.dur(h.duration), h.clients, h.desired, h.tracked, h.adds, h.deletes, h.skipped.length, h.deferred.length,
        h.error ? el('span', { class: 'err', text: h.error }) : el('span', { class: 'ok', text: 'ok' })])));
    const notes = $('#last-notes'); notes.replaceChildren();
    if (last && last.skipped.length) notes.append(el('h3', { text: 'Skipped in the last cycle' }), table(['Name', 'Reason'], last.skipped.map(x => [x.name, x.reason])));
    if (last && last.deferred.length) notes.append(el('h3', { text: 'Deferred changes' }), table(['Name', 'Kind', 'Detail'], last.deferred.map(x => [x.name, x.kind, x.detail])));
  }
  async function dryRun() {
    const out = $('#dryrun'); out.replaceChildren(el('div', { class: 'msg', text: 'Running dry run…' }));
    try {
      const r = await api('/api/dry-run', { method: 'POST' });
      const summary = r.error ? 'Dry run failed: ' + r.error : 'Dry run finished in ' + fmt.dur(r.duration) + ': ' + r.clients + ' clients, ' + r.desired + ' desired records, ' + r.actions.length + ' change(s) would be made';
      out.replaceChildren(el('div', { class: 'msg ' + (r.error ? 'err' : 'ok'), text: summary }), table(['Op', 'Type', 'Name', 'Value'], r.actions.map(a => [a.op, a.type, a.name, a.value])));
    } catch (e) { out.replaceChildren(el('div', { class: 'msg err', text: e.message })); }
  }
  async function syncNow() {
    try { await api('/api/sync', { method: 'POST' }); message('#dryrun', 'Sync requested; the status refreshes in a few seconds.', 'ok'); setTimeout(refresh, 4000); }
    catch (e) { message('#dryrun', e.message, 'err'); }
  }

  async function renderRecords() { S.records = await api('/api/records'); drawRecords(); }
  function drawRecords() {
    const r = S.records; if (!r) return;
    const q = ($('#filter').value || '').toLowerCase();
    const rows = r.records.filter(x => !q || [x.name, x.ip, x.mac, x.label, x.field].join(' ').toLowerCase().includes(q)).map(x => {
      let pending = '';
      if (x.pending_ip) pending = 'IP change to ' + x.pending_ip.ip + ' seen ' + x.pending_ip.count + '×';
      else if (x.candidate) pending = 'rename to ' + x.candidate.label + ' seen ' + x.candidate.count + '×';
      else if (x.downgrade_polls) pending = (x.field || 'preferred field') + ' missing ' + x.downgrade_polls + ' polls';
      return [x.name, x.ip, x.mac, fmt.ago(x.last_seen), x.field || '?', x.suffix ? '-' + x.suffix : '', pending];
    });
    $('#records-summary').textContent = r.records.length + ' managed records · ' + r.clients_remembered + ' clients remembered · state saved ' + fmt.ago(r.last_success);
    $('#records').replaceChildren(table(['Name', 'IP', 'MAC', 'Last seen', 'Field', 'Suffix', 'Pending'], rows));
  }

  async function renderConfig() {
    const c = await api('/api/config'); S.config = c; S.initial = {};
    const form = $('#settings'); form.replaceChildren();
    const sections = new Map();
    for (const s of c.settings) { if (!sections.has(s.section)) sections.set(s.section, []); sections.get(s.section).push(s); }
    for (const [name, items] of sections) {
      const fs = el('fieldset', null, el('legend', { text: name }));
      for (const s of items) {
        if (s.key === 'WEB_PASSWORD_HASH') continue;
        let input;
        if (s.kind === 'bool') { input = el('select'); ['true', 'false'].forEach(v => input.append(el('option', { value: v, text: v }))); input.value = (s.value || s.default).toLowerCase() === 'true' ? 'true' : 'false'; }
        else if (s.kind === 'choice') { input = el('select'); s.choices.forEach(v => input.append(el('option', { value: v, text: v }))); input.value = s.value || s.default; }
        else if (s.kind === 'secret') { input = el('input', { type: 'password', autocomplete: 'new-password', placeholder: s.set ? '(set — leave blank to keep)' : '(not set)' }); }
        else { input = el('input', { type: s.kind === 'int' ? 'number' : 'text', value: s.value || '', placeholder: s.default ? 'default: ' + s.default : '' }); }
        input.name = s.key; input.id = 'f-' + s.key;
        S.initial[s.key] = s.kind === 'secret' ? '' : input.value;
        const help = s.help + (s.required ? ' (required)' : '') + (s.restart ? ' — needs a service restart' : '') + (s.sensitive && BOOT.auth ? ' — changing this requires your current password' : '');
        fs.append(el('div', { class: 'field' }, el('label', { for: input.id, text: s.key }), el('div', null, input, el('small', { text: help }))));
      }
      form.append(fs);
    }
    $('#config-path').textContent = c.path ? ('Settings file: ' + c.path + (c.writable ? '' : ' (not writable by the service user; saving will fail)')) : 'No settings file in use (start the service with CONFIG_FILE or --config to enable editing).';
    $('#save').disabled = !c.writable;
    $('#pw-current-row').hidden = !BOOT.auth;
    $('#reauth-row').hidden = !BOOT.auth;
    $('#reauth').value = '';
  }
  async function saveConfig(ev) {
    ev.preventDefault();
    const values = {};
    for (const s of S.config.settings) {
      const input = $('#f-' + s.key); if (!input) continue;
      if (s.kind === 'secret') { if (input.value) values[s.key] = input.value; }
      else if (input.value !== S.initial[s.key]) values[s.key] = input.value;
    }
    if (!Object.keys(values).length) { message('#config-msg', 'Nothing changed.'); return; }
    const body = { values };
    const sensitive = Object.keys(values).filter(k => S.config.settings.some(s => s.key === k && s.sensitive));
    if (sensitive.length && BOOT.auth) {
      const pw = $('#reauth').value;
      if (!pw) { message('#config-msg', 'Enter your current password to change ' + sensitive.join(', ') + '.', 'err'); $('#reauth').focus(); return; }
      body.current_password = pw;
    }
    try {
      const r = await api('/api/config', { method: 'POST', body });
      message('#config-msg', 'Saved ' + r.changed.join(', ') + (r.restart.length ? '. Restart the service for: ' + r.restart.join(', ') + '.' : '. Changes apply from the next cycle.'), 'ok');
      renderConfig();
    } catch (e) { message('#config-msg', 'Not saved: ' + e.message, 'err'); }
  }
  async function changePassword(ev) {
    ev.preventDefault();
    const current = $('#pw-current').value, a = $('#pw-new').value, b = $('#pw-repeat').value;
    if (a !== b) { message('#pw-msg', 'The new passwords do not match.', 'err'); return; }
    try { await api('/api/password', { method: 'POST', body: { current, new: a } }); message('#pw-msg', 'Password changed. Please sign in again.', 'ok'); setTimeout(() => { location.href = '/login'; }, 1200); }
    catch (e) { message('#pw-msg', e.message, 'err'); }
  }
  async function renderLog() { const r = await api('/api/log'); const pre = $('#log'); pre.textContent = r.lines.join('\n'); pre.scrollTop = pre.scrollHeight; }

  const renderers = { status: renderStatus, records: renderRecords, config: renderConfig, log: renderLog };
  function show(tab) {
    S.tab = tab;
    document.querySelectorAll('nav [data-tab]').forEach(b => b.classList.toggle('active', b.dataset.tab === tab));
    document.querySelectorAll('main > section').forEach(sec => { sec.hidden = sec.id !== 'tab-' + tab; });
    refresh();
  }
  async function refresh() {
    $('#global-msg').replaceChildren();
    try { await renderers[S.tab](); } catch (e) { if (e.message !== 'Session expired') message('#global-msg', e.message, 'err'); }
  }
  async function init() {
    const session = await api('/api/session'); S.csrf = session.csrf;
    $('#ver').textContent = 'v' + BOOT.version;
    if (BOOT.insecure) {
      const w = $('#transport-warning');
      w.textContent = 'This page is served over plain HTTP: your password and session cookie cross the network unencrypted. Configure WEB_TLS_CERT and WEB_TLS_KEY to fix this (see the README, "TLS").';
      w.hidden = false;
    }
    $('#logout').hidden = !session.auth;
    document.querySelectorAll('nav [data-tab]').forEach(b => b.addEventListener('click', () => show(b.dataset.tab)));
    $('#sync-now').addEventListener('click', syncNow);
    $('#dry-run').addEventListener('click', dryRun);
    $('#filter').addEventListener('input', drawRecords);
    $('#settings').addEventListener('submit', saveConfig);
    $('#pw-form').addEventListener('submit', changePassword);
    $('#refresh').addEventListener('click', refresh);
    $('#logout').addEventListener('click', async () => { try { await api('/logout', { method: 'POST' }); } finally { location.href = '/login'; } });
    show('status');
    setInterval(() => { if (S.tab === 'status' || (S.tab === 'log' && $('#log-auto').checked)) refresh(); }, 10000);
  }
  init().catch(e => message('#global-msg', e.message, 'err'));
})();
"""

PAGE_HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>UniFi → Technitium DNS Sync</title>
<style>__BASE_CSS____PAGE_CSS__</style>
</head>
<body>
<header>
  <h1>UniFi → Technitium DNS Sync <span id="ver"></span></h1>
  <nav>
    <button class="ghost" data-tab="status">Status</button>
    <button class="ghost" data-tab="records">Records</button>
    <button class="ghost" data-tab="config">Settings</button>
    <button class="ghost" data-tab="log">Log</button>
  </nav>
  <button class="ghost" id="refresh">Refresh</button>
  <button class="ghost" id="logout" hidden>Sign out</button>
</header>
<main>
  <div id="transport-warning" class="msg warn" hidden></div>
  <div id="global-msg"></div>
  <section id="tab-status">
    <div class="cards" id="status-cards"></div>
    <div class="toolbar">
      <button class="primary" id="sync-now">Sync now</button>
      <button class="ghost" id="dry-run">Dry-run preview</button>
    </div>
    <div id="dryrun"></div>
    <div id="last-notes"></div>
    <h3>Recent cycles</h3>
    <div id="history"></div>
  </section>
  <section id="tab-records" hidden>
    <div class="toolbar">
      <input class="filter" id="filter" placeholder="Filter by name, IP, MAC…" autocomplete="off">
      <span class="muted" id="records-summary"></span>
    </div>
    <div id="records"></div>
  </section>
  <section id="tab-config" hidden>
    <p class="muted" id="config-path"></p>
    <form id="settings" class="settings"></form>
    <div class="toolbar" id="reauth-row" hidden>
      <label for="reauth">Current password</label>
      <input id="reauth" type="password" autocomplete="current-password">
      <span class="muted">needed to save settings marked as requiring it</span>
    </div>
    <div class="toolbar"><button class="primary" id="save" type="submit" form="settings">Save settings</button></div>
    <div id="config-msg"></div>
    <h3>Web UI password</h3>
    <form id="pw-form" class="settings">
      <fieldset>
        <legend>Change password</legend>
        <div class="field" id="pw-current-row"><label for="pw-current">Current</label><div><input id="pw-current" type="password" autocomplete="current-password"></div></div>
        <div class="field"><label for="pw-new">New</label><div><input id="pw-new" type="password" autocomplete="new-password" minlength="8" required><small>At least 8 characters. Everyone is signed out afterwards.</small></div></div>
        <div class="field"><label for="pw-repeat">Repeat</label><div><input id="pw-repeat" type="password" autocomplete="new-password" minlength="8" required></div></div>
      </fieldset>
      <div class="toolbar"><button class="primary" type="submit">Change password</button></div>
      <div id="pw-msg"></div>
    </form>
  </section>
  <section id="tab-log" hidden>
    <div class="toolbar"><label><input type="checkbox" id="log-auto" checked> auto-refresh every 10 s</label></div>
    <pre id="log" class="mono"></pre>
  </section>
</main>
<script id="boot" type="application/json">__BOOT__</script>
<script>__PAGE_JS__</script>
</body>
</html>
"""

LOGIN_HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sign in · UniFi → Technitium DNS Sync</title>
<style>__BASE_CSS____LOGIN_CSS__</style>
</head>
<body>
<main class="login">
  <form method="post" action="/login" class="card">
    <h1>UniFi → Technitium DNS Sync</h1>
    __ERROR__
    <label for="password">Password</label>
    <input id="password" name="password" type="password" autocomplete="current-password" autofocus required>
    <button class="primary" type="submit">Sign in</button>
  </form>
</main>
</body>
</html>
"""


def render_page(state: WebState) -> str:
    boot = json.dumps({
        "version": state.core.VERSION,
        "auth": state.auth_required(),
        "insecure": state.insecure_transport,
    })
    boot = boot.replace("</", "<\\/")
    return (
        PAGE_HTML.replace("__BASE_CSS__", BASE_CSS)
        .replace("__PAGE_CSS__", PAGE_CSS)
        .replace("__PAGE_JS__", PAGE_JS)
        .replace("__BOOT__", boot)
    )


def render_login(error: bool) -> str:
    notice = (
        '<p class="err">Wrong password, or too many attempts. Wait a few minutes and try again.</p>'
        if error else ""
    )
    return (
        LOGIN_HTML.replace("__BASE_CSS__", BASE_CSS)
        .replace("__LOGIN_CSS__", LOGIN_CSS)
        .replace("__ERROR__", notice)
    )
