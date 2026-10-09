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

import hmac
import json
import os
import secrets
import ssl
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
LOGIN_WINDOW = 300
LOGIN_MAX_FAILURES = 5
LOGIN_LOCK_SECONDS = 60
LOOPBACK = {"127.0.0.1", "::1", "localhost"}
MAX_BODY = 256 * 1024


def is_loopback(host: str) -> bool:
    return host in LOOPBACK


class WebState:
    """Sessions, login throttling and references to the daemon runtime."""

    def __init__(self, runtime: Any, core: Any):
        self.runtime = runtime
        self.core = core
        self.lock = threading.Lock()
        self.sessions: dict[str, dict[str, Any]] = {}
        self.failures: dict[str, list[float]] = {}
        self.anonymous = {"csrf": secrets.token_urlsafe(32), "expires": float("inf")}
        self.tls = bool(runtime.current_config().web_tls_cert)

    def password_set(self) -> bool:
        return bool(self.runtime.password_hash())

    def auth_required(self) -> bool:
        return self.password_set()

    def login(self, password: str, client_ip: str) -> str | None:
        now = time.time()
        with self.lock:
            recent = [t for t in self.failures.get(client_ip, []) if now - t < LOGIN_WINDOW]
            self.failures[client_ip] = recent
            if len(recent) >= LOGIN_MAX_FAILURES and now - recent[-1] < LOGIN_LOCK_SECONDS:
                return None
        if not self.core.verify_password(self.runtime.password_hash(), password):
            with self.lock:
                self.failures.setdefault(client_ip, []).append(now)
            return None
        token = secrets.token_urlsafe(32)
        with self.lock:
            self.failures.pop(client_ip, None)
            self.sessions = {t: s for t, s in self.sessions.items() if s["expires"] > now}
            self.sessions[token] = {"csrf": secrets.token_urlsafe(32), "expires": now + SESSION_TTL}
        return token

    def session(self, token: str | None) -> dict[str, Any] | None:
        if not self.auth_required():
            return self.anonymous
        if not token:
            return None
        now = time.time()
        with self.lock:
            session = self.sessions.get(token)
            if session is None or session["expires"] <= now:
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
    protocol_version = "HTTP/1.1"
    server_version = "unifi-technitium-sync"
    sys_version = ""

    def log_message(self, fmt: str, *args: Any) -> None:
        self.state.core.LOG.debug("web %s " + fmt, self.address_string(), *args)

    # -- response helpers -------------------------------------------------
    def _send(self, status: int, body: bytes, content_type: str,
              extra: dict[str, str] | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
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
        length = int(self.headers.get("Content-Length") or 0)
        if length > MAX_BODY:
            raise ValueError("request body too large")
        return self.rfile.read(length) if length else b""

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
        except ValueError as exc:
            self.send_json({"error": str(exc)}, 400)
        except Exception as exc:  # noqa: BLE001 - report, never crash the server thread
            self.state.core.LOG.exception("Web request failed")
            self.send_json({"error": f"{type(exc).__name__}: {exc}"}, 500)

    def handle_login(self) -> None:
        if not self.state.auth_required():
            return self.redirect("/")
        form = parse_qs(self.read_body().decode("utf-8", errors="replace"))
        password = (form.get("password") or [""])[0]
        token = self.state.login(password, self.client_ip())
        if token is None:
            self.state.core.LOG.warning("Web UI login failed from %s", self.client_ip())
            return self.redirect("/login?error=1")
        self.state.core.LOG.info("Web UI login from %s", self.client_ip())
        return self.redirect("/", self.cookie_header(token, SESSION_TTL))

    def handle_config(self) -> None:
        values = self.read_json().get("values")
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
        self.state.runtime.apply_settings(updates)
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
        stored = runtime.password_hash()
        if stored and not core.verify_password(stored, current):
            return self.send_json({"error": "current password is wrong"}, 403)
        if runtime.config_path is None:
            raise ValueError("no configuration file is in use; use --config")
        digest = core.hash_password(new)
        core.write_env_file(runtime.config_path, {"WEB_PASSWORD_HASH": digest})
        with runtime.lock:
            runtime.config = replace(runtime.config, web_password_hash=digest)
        self.state.invalidate_all()
        core.LOG.info("Web UI password changed from %s", self.client_ip())
        return self.send_json({"ok": True, "relogin": True})


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

    class BoundHandler(Handler):
        pass

    BoundHandler.state = state
    server = ThreadingHTTPServer((host, port), BoundHandler)
    server.daemon_threads = True
    scheme = "http"
    if config.web_tls_cert:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(config.web_tls_cert, config.web_tls_key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        scheme = "https"
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
.msg.err{border-color:var(--err)}.msg.ok{border-color:var(--ok)}
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
        const help = s.help + (s.required ? ' (required)' : '') + (s.restart ? ' — needs a service restart' : '');
        fs.append(el('div', { class: 'field' }, el('label', { for: input.id, text: s.key }), el('div', null, input, el('small', { text: help }))));
      }
      form.append(fs);
    }
    $('#config-path').textContent = c.path ? ('Settings file: ' + c.path + (c.writable ? '' : ' (not writable by the service user; saving will fail)')) : 'No settings file in use (start the service with CONFIG_FILE or --config to enable editing).';
    $('#save').disabled = !c.writable;
    $('#pw-current-row').hidden = !BOOT.auth;
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
    try {
      const r = await api('/api/config', { method: 'POST', body: { values } });
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
    boot = json.dumps({"version": state.core.VERSION, "auth": state.auth_required()})
    boot = boot.replace("</", "<\\/")
    return (
        PAGE_HTML.replace("__BASE_CSS__", BASE_CSS)
        .replace("__PAGE_CSS__", PAGE_CSS)
        .replace("__PAGE_JS__", PAGE_JS)
        .replace("__BOOT__", boot)
    )


def render_login(error: bool) -> str:
    notice = (
        '<p class="err">Wrong password, or too many attempts. Wait a minute and try again.</p>'
        if error else ""
    )
    return (
        LOGIN_HTML.replace("__BASE_CSS__", BASE_CSS)
        .replace("__LOGIN_CSS__", LOGIN_CSS)
        .replace("__ERROR__", notice)
    )
