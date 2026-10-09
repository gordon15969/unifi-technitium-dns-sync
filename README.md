# UniFi → Technitium DNS Sync

A lightweight, dependency-free Python service that reads the connected clients
from a UniFi gateway (UniFi Dream Machine SE/Pro, or any UniFi Network
controller) and keeps matching IPv4 `A` records (and optionally PTR records)
up to date in an **existing** [Technitium DNS](https://technitium.com/dns/)
primary zone.

Point your LAN's DNS at Technitium and every device on your network becomes
resolvable by name — `nas.home.arpa`, `printer.home.arpa`, `homeassistant.home.arpa` —
without touching a zone file by hand.

- Python 3 standard library only — no pip packages, no web server to install
- Optional built-in web UI: status, records, settings and dry-run preview,
  served by the daemon itself
- Runs as a hardened systemd service under a dedicated system user
- Never touches records it does not own; safe to run against a zone that also
  contains manual records
- Dry-run mode shows every change before you commit to anything

**Status:** v1.5.0. In production since July 2026 on a Proxmox LXC, syncing
roughly 100 UniFi clients into about 80 managed records every 5 minutes.
1.3.0 fixed the record churn described in
[Code review notes](#code-review-notes-october-2026), 1.4.0 added the
[Web UI](#web-ui), and 1.5.0 fixes the findings of an October 2026 security
review. See the [Changelog](#changelog) for release history.

## Contents

- [How it works](#how-it-works)
- [Requirements](#requirements)
- [Setting up your UniFi Dream Machine](#setting-up-your-unifi-dream-machine)
- [Setting up Technitium](#setting-up-technitium)
- [Installation](#installation)
- [Configuration reference](#configuration-reference)
- [Reverse DNS (PTR records)](#reverse-dns-ptr-records)
- [Web UI](#web-ui)
- [Troubleshooting](#troubleshooting)
- [Project layout](#project-layout)
- [Code review notes (October 2026)](#code-review-notes-october-2026)
- [Roadmap](#roadmap)
- [Upgrading](#upgrading) · [Changelog](#changelog) · [Removal](#removal) · [License](#license)

## How it works

Every `SYNC_INTERVAL` seconds (default 300) the service performs one
synchronization cycle:

1. **Fetch clients** from the UniFi API (`UNIFI_CLIENTS_PATH`). The default is
   the legacy `stat/sta` endpoint because it is the only endpoint that exposes
   the DHCP-reported `hostname` in addition to the administrator-assigned
   alias (`name`). Both endpoints accept the same API key.
2. **Choose a name** for each client from `NAME_FIELDS`, in order (default:
   `name`, then `hostname`). Names are sanitized into valid DNS labels:
   lowercased, punctuation and spaces become hyphens, an existing domain
   suffix is stripped (`pc.lan` → `pc`), and the label is capped at 63
   characters. The result is then checked against the client's **naming
   memory** (see "How names are chosen" below) so that a one-off blip in the
   UniFi data does not rename the record.
3. **Filter**: clients without a usable name or IPv4 address are skipped, as
   are labels in `EXCLUDED_NAMES` and addresses outside `ALLOWED_NETWORKS`.
4. **De-duplicate**: if two or more *remembered* clients (online, or seen
   within `NAME_MEMORY_TTL`) share a label, each gets a suffix from the last
   six hex digits of its MAC (`iphone-a1b2c3.home.arpa`), or more digits when
   two of those MACs end the same way. Because offline namesakes count, a
   device's name does not change when its twin comes and goes. A client keeps
   the exact name it already holds, so a newcomer that copies its hostname,
   the end of its MAC, or even its full suffixed name gets a different name
   instead of taking that one over. Names are always unique; a record is never
   silently replaced. MACs that are not 12 hex digits get no naming memory.
5. **Fetch the zone** from Technitium and compute the difference.
6. **Apply changes** (see "What it modifies" below).
7. **Save state** to `STATE_FILE` — a JSON file recording which records the
   service owns, when each client was last seen, any pending IP changes, and
   the per-client naming memory.

### How names are chosen

Since 1.3.0 the service keeps a small **naming memory** per client (keyed by
MAC) in the state file and only renames a record when the source data changes
durably:

| What UniFi reports for a known client | Result |
|---|---|
| The same label as before | Nothing changes |
| A label from a **more** preferred field (an alias was just set) | Renamed immediately |
| A **different** label from the **most** preferred field (the alias was edited) | Renamed once it has been reported `NAME_STABLE_POLLS` times (default 2); a blip in between does not reset the count |
| A **different** label from a **device-announced** field (`hostname`) | Held: UniFi's hostname can alternate between discovery sources for the same device. One tie-break: a name that is unique on the network replaces one shared with other clients immediately, so a Wemo ends up as `wemo-patio-1` rather than `lwip0-xxxxxx` |
| Only a **less** preferred field (alias missing, hostname present), or no name at all | Held |

A held label is replaced only after the stored name has gone unreported for
`NAME_DOWNGRADE_POLLS` consecutive polls **while the client was online**
(default 288 ≈ 24 h); offline time does not count.

This exists because UniFi learns a client's `hostname` from several sources
(DHCP, mDNS, UPnP; the API record carries a `hostname_source`) and for some
IoT devices those sources disagree, so the field alternates (finding 1
below). Consequences to be aware of: setting or changing an alias in UniFi
takes effect within one or two cycles, but *removing* an alias, or changing a
device's own hostname, takes about a day to propagate. To force it sooner,
set an alias, or stop the service, delete that MAC's entry from `clients` in
the state file, and start it again. Setting `NAME_STABLE_POLLS=1`,
`NAME_DOWNGRADE_POLLS=1` and `NAME_MEMORY_TTL=0` restores the pre-1.3.0
behaviour exactly.

### What it modifies during synchronization

The service only ever creates or deletes **`A` records inside the configured
`DNS_ZONE`** (plus matching PTR records if `CREATE_PTR=true`). Specifically:

| Situation | Action |
|---|---|
| New client appears | `A` record added, tagged with the comment `managed-by=unifi-technitium-sync` |
| Client's IP changes | New `A` record added first, then the old one deleted, so a failure in between never leaves the name unresolvable. Applied only after the new IP has been reported for `IP_STABLE_POLLS` consecutive cycles (default 2), which suppresses churn from clients whose reported IP flaps |
| Client's chosen label changes durably (see "How names are chosen") | The record under the old name is deleted and a record under the new name is created in the same cycle (matched by MAC) |
| Client disappears (powered off, roaming) | Record is kept for `STALE_AFTER` seconds (default 24 h), then deleted |
| A record with the same name already exists **without** the marker comment | Skipped, warning logged once — manual records always win |
| A CNAME/TXT/other record type exists at the same name | Skipped, warning logged once |

### Safety model

- The service **never creates or deletes a forward DNS zone**. (With
  `CREATE_PTR_ZONE=true` it lets Technitium create missing *reverse* zones.)
- Every record it creates carries the Technitium comment
  `managed-by=unifi-technitium-sync`. It will only delete a record when the
  marker **and** the recorded IP address both match — a record you edited by
  hand no longer matches and is left alone.
- Existing unmanaged records always win; the service will not overwrite them.
- The state file provides ownership tracking across restarts; if it is lost,
  ownership is recovered from the marker comments in the zone itself.
- State is written atomically (temp file + rename), so a crash mid-write
  cannot corrupt it.
- Both API credentials travel in HTTP headers, never in URLs, so they do not
  appear in logs or error messages.
- `--dry-run` performs all reads and logs every intended change without
  writing anything.

## Requirements

- A Debian/Ubuntu host, VM, or LXC with Python 3.9+ (no packages needed)
- Network access to the UniFi gateway's HTTPS API and Technitium's web API
- UniFi Network application 9.x+ (for local API keys)
- Technitium DNS 13+ with an existing primary zone

## Setting up your UniFi Dream Machine

1. **Create an API key**: in the UniFi Network application go to
   **Settings → Control Plane → Integrations** and create an API key. Note the
   key and the **Site ID** shown on the same page.
2. **Name your devices**: the default name priority is the client *alias*
   (the name you assign under **Client Devices → select client → Settings →
   Name**), falling back to the DHCP hostname the device announces. Devices
   with neither get no DNS record. Set aliases for devices with unhelpful
   hostnames (IoT gadgets often announce names like `wiz_8a9b0c` or `lwip0`).
3. **Reserve IPs for servers** (recommended): give important machines a fixed
   IP (**Client Devices → client → Settings → Use Fixed IP Address**). DNS
   follows DHCP, so a stable lease means a stable record. The flap-dampening
   feature protects against clients that misreport their IP, but a
   reservation is the real fix.
4. **TLS**: the UDM ships with a self-signed certificate. Either export its CA
   certificate and set `UNIFI_CA_FILE`, or (LAN-only, less secure) set
   `UNIFI_VERIFY_TLS=false`.

## Setting up Technitium

1. Create (or reuse) a **primary zone**, e.g. `home.arpa`, and point your
   clients' DNS at Technitium.
2. Create a **dedicated API token**: add a Technitium user that has
   View/Modify/Delete permission **only on the target zone**, then create a
   non-expiring API token for it (**Administration → Sessions → Create
   Token**). The Delete permission is needed for IP changes and stale-record
   cleanup. If you enable `CREATE_PTR_ZONE`, the user also needs permission to
   create zones.
3. If Technitium serves HTTPS with a private CA, set `TECHNITIUM_CA_FILE`.

## Installation

Get the files onto the machine that will run the service, either from a
release package or by cloning the repository, then run the installer as root
from the unpacked directory.

**From a release** (recommended). Each [release](../../releases) has a
`unifi-technitium-sync-X.Y.Z.tar.gz` package and a `SHA256SUMS` file. This
repository is private, so you need the GitHub CLI signed in to an account with
access (`gh auth login`), or download the two files from the Releases page in
a browser while signed in:

```sh
gh release download --repo gordon15969/unifi-technitium-dns-sync \
  --pattern '*.tar.gz' --pattern SHA256SUMS
sha256sum -c SHA256SUMS
tar xzf unifi-technitium-sync-*.tar.gz
cd unifi-technitium-sync-*/
sudo ./install.sh
```

**From git:** `git clone` the repository, `cd` into it, and run
`sudo ./install.sh`.

The installer creates the `unifi-dns-sync` system user, installs the script to
`/opt/unifi-technitium-sync/`, seeds `/etc/unifi-technitium-sync/sync.env`
from the example (existing config is preserved), and registers the systemd
unit.

Edit the configuration and fill in your values:

```sh
sudo nano /etc/unifi-technitium-sync/sync.env
```

At minimum set `UNIFI_URL`, `UNIFI_API_KEY`, `UNIFI_SITE_ID`,
`TECHNITIUM_URL`, `TECHNITIUM_API_TOKEN`, `DNS_ZONE`, and
`ALLOWED_NETWORKS`.

### Test with a dry run

```sh
sudo runuser -u unifi-dns-sync -- /opt/unifi-technitium-sync/unifi_technitium_sync.py \
  --config /etc/unifi-technitium-sync/sync.env --once --dry-run
```

Review every proposed `ADD`/`DELETE` line. When satisfied, run once for real
(drop `--dry-run`), check the records in Technitium, then enable the service:

```sh
sudo systemctl enable --now unifi-technitium-sync
sudo journalctl -u unifi-technitium-sync -f
```

## Configuration reference

All settings live in `/etc/unifi-technitium-sync/sync.env`. The service reads
that file itself (the unit sets `CONFIG_FILE`; on the command line pass
`--config`), so changes saved from the web UI apply on the next cycle without a
restart. Values in the file take precedence over environment variables. The
real file contains two API credentials and is deliberately **not** in this
repository; only `unifi-technitium-sync.env.example` is tracked.

| Variable | Default | Purpose |
|---|---|---|
| `UNIFI_URL` | — | Base URL of the UniFi gateway, e.g. `https://192.168.1.1` |
| `UNIFI_API_KEY` | — | API key from Settings → Control Plane → Integrations |
| `UNIFI_SITE_ID` | — | Site UUID from the same page (only substituted into `UNIFI_CLIENTS_PATH` when it contains `{site_id}`; see finding 3) |
| `UNIFI_CLIENTS_PATH` | legacy `stat/sta` | API path for the client list; `{site_id}` is substituted if present |
| `UNIFI_VERIFY_TLS` / `UNIFI_CA_FILE` | `true` / unset | TLS verification for the UniFi API |
| `TECHNITIUM_URL` | — | Technitium base URL, e.g. `http://192.168.1.53:5380` |
| `TECHNITIUM_API_TOKEN` | — | Token of a user with zone-scoped permissions |
| `TECHNITIUM_VERIFY_TLS` / `TECHNITIUM_CA_FILE` | `true` / unset | TLS verification for the Technitium API |
| `DNS_ZONE` | — | Existing primary zone the records go into |
| `DNS_TTL` | `300` | TTL for created records |
| `SYNC_INTERVAL` | `300` | Seconds between synchronization cycles (minimum 10) |
| `STALE_AFTER` | `86400` | Seconds a disappeared client's record is retained; `0` deletes on the first cycle it is missing |
| `IP_STABLE_POLLS` | `2` | Consecutive polls a new IP must be seen before an existing record is updated; `1` = immediate |
| `NAME_STABLE_POLLS` | `2` | Sightings of an edited alias before a record is renamed; `1` = immediate |
| `NAME_DOWNGRADE_POLLS` | `288` | Consecutive online polls a client's stored name must go unreported before a less preferred field, a different device-announced hostname, or no name may replace it (288 ≈ 24 h at a 5-minute interval); `1` = immediate |
| `NAME_MEMORY_TTL` | `604800` | Seconds a client's name is remembered after it was last seen, which keeps de-duplication suffixes stable while a namesake is offline; `0` = online clients only |
| `REQUEST_TIMEOUT` | `20` | HTTP timeout in seconds |
| `ALLOWED_NETWORKS` | all | Comma-separated IPv4 CIDRs; clients outside are ignored |
| `NAME_FIELDS` | `name,hostname` | Client fields tried in order for the DNS label |
| `EXCLUDED_NAMES` | empty | Comma-separated sanitized labels never to sync (e.g. hosts you manage manually) |
| `STRIP_TRAILING_MAC` | `false` | Remove a trailing `-xx-xx` label suffix when it matches the client's MAC |
| `CREATE_PTR` / `CREATE_PTR_ZONE` | `false` | Maintain PTR records for reverse lookups / allow Technitium to create missing reverse zones (see below) |
| `STATE_FILE` | `/var/lib/unifi-technitium-sync/state.json` | Ownership/state database |
| `LOG_LEVEL` | `INFO` | `DEBUG` shows skip/defer detail on every cycle; `--log-level` overrides it for one run |
| `WEB_LISTEN` | empty | `host:port` for the built-in web UI, e.g. `0.0.0.0:8089`; empty keeps it off. Needs a restart |
| `WEB_PASSWORD_HASH` | empty | Written by `--set-web-password` or the UI's password form; never edit by hand |
| `WEB_TLS_CERT` / `WEB_TLS_KEY` | unset | PEM certificate chain and key to serve the UI over HTTPS; the service loads but never creates them (see [TLS](#tls)). Needs a restart |
| `WEB_ALLOW_INSECURE_LAN` | `false` | Without TLS the UI only starts on a loopback address. `true` allows plain HTTP on a network address, sending the password and session cookie unencrypted, and puts a warning banner on every page. Needs a restart |

## Reverse DNS (PTR records)

With `CREATE_PTR=true` the service maintains matching PTR records so reverse
lookups (`dig -x 192.168.1.50`) return the device name:

- Every `A` record it adds also creates the PTR in the corresponding
  `in-addr.arpa` zone; with `CREATE_PTR_ZONE=true` a missing reverse zone is
  created automatically (the API token's user needs zone-create permission).
- When an `A` record is deleted (IP change, rename, stale cleanup), the
  matching PTR is deleted too. Technitium's delete API does not cascade to
  the reverse zone on its own, so the service removes the PTR explicitly —
  filtered by name, so a PTR that already points somewhere else is left alone.
- If a PTR deletion fails for a transient reason (timeout, HTTP error,
  Technitium unreachable), it is kept in the state file and retried every
  cycle, even when the cycle that failed did not complete. It shows under
  "Deferred changes" in the web UI. A queued deletion is dropped as soon as
  that name points at that address again, and abandoned with a warning after
  7 days. A refusal from Technitium (no such zone or record) is not retried.
- Enabling PTR on an existing installation only affects records created from
  then on. Create PTRs for everything already managed with a one-time backfill:

```sh
sudo runuser -u unifi-dns-sync -- /opt/unifi-technitium-sync/unifi_technitium_sync.py \
  --config /etc/unifi-technitium-sync/sync.env --backfill-ptr
```

(add `--dry-run` to preview). Only zone data is touched; DHCP reservations and
manual records are unaffected.

## Web UI

The daemon can serve its own management page. Nothing else is installed: the
page, its stylesheet and its script are embedded in `unifi_technitium_web.py`
and served by Python's standard-library HTTP server from a thread of the same
process. It stays off until `WEB_LISTEN` is set.

1. Set a password (required unless you bind to `127.0.0.1`):

   ```sh
   sudo /opt/unifi-technitium-sync/unifi_technitium_sync.py \
     --config /etc/unifi-technitium-sync/sync.env --set-web-password
   ```

2. Choose how to reach it, set `WEB_LISTEN` in `sync.env`, and run
   `sudo systemctl restart unifi-technitium-sync`:
   - **HTTPS on the LAN** (recommended): `WEB_LISTEN=0.0.0.0:8089` plus
     `WEB_TLS_CERT` and `WEB_TLS_KEY` (see [TLS](#tls)). Open
     `https://<host>:8089/`.
   - **Loopback only**: `WEB_LISTEN=127.0.0.1:8089`, then
     `ssh -L 8089:127.0.0.1:8089 <host>` and open `http://localhost:8089/`,
     or put an HTTPS reverse proxy on the same host in front of it.
   - **Plain HTTP on the LAN**: refused unless you also set
     `WEB_ALLOW_INSECURE_LAN=true`, because the password and session cookie
     would cross the network unencrypted. Every page then shows a warning.
3. Sign in.

| Tab | What it shows |
|---|---|
| **Status** | Last and next cycle, duration, client/record counts, writes in the last cycle, skipped and deferred changes, the last 50 cycles. **Sync now** runs a cycle immediately; **Dry-run preview** lists every change a cycle would make without writing anything |
| **Records** | Every managed record with its IP, MAC, last-seen time and naming memory (which field named it, de-dup suffix, pending IP change or rename), with a filter box |
| **Settings** | Every setting from the configuration reference with help text, grouped by section. Secrets are write-only (shown as set/not set). **Save** validates the whole configuration first, writes `sync.env` atomically (comments and order preserved) and applies from the next cycle; `WEB_*` settings say when a restart is needed. A password form is at the bottom |
| **Log** | The last 400 log lines, auto-refreshing |

How it is secured:

- The password is stored as a PBKDF2-SHA256 hash (200 000 iterations) in
  `sync.env`. Sessions are HttpOnly, SameSite=Strict cookies that expire after
  12 hours; every write request also needs the session's CSRF token.
- Password guessing is throttled before the slow hash runs, so parallel
  requests cannot slip past the limit: each address gets one attempt at a
  time and at most five failed attempts per five minutes, and no more than two
  password checks run at once across all addresses. Behind a reverse proxy
  every client shares the proxy's address and therefore one limit.
- Without a password the UI refuses to start on anything but a loopback
  address. Reach a loopback-only UI with `ssh -L 8089:127.0.0.1:8089 <host>`.
- The response headers set a strict Content-Security-Policy, `X-Frame-Options:
  DENY` and `Cache-Control: no-store`.
- Plain HTTP is only allowed on a loopback address unless you opt in with
  `WEB_ALLOW_INSECURE_LAN=true`; see [TLS](#tls) below. The UI does not send
  HSTS, because that would make browsers refuse a self-signed certificate
  outright.
- Anyone who can sign in can read device names and change where the API
  tokens are sent, so bind the UI to a management VLAN or loopback where you
  can. The installer makes `sync.env` group-writable by the service user
  (`0660 root:unifi-dns-sync`) so the UI can save settings; it is still not
  readable by other users.
- Sessions live in memory, so a service restart signs everyone out.

### TLS

The UI speaks plain HTTP unless `WEB_TLS_CERT` and `WEB_TLS_KEY` point at a
PEM certificate chain and private key. The service **does not generate,
request or renew certificates**: Python's standard library cannot create one,
and the two files are loaded once, at startup. Where the certificate comes
from is your choice:

| Option | When it fits | What to do |
|---|---|---|
| **Self-signed** | A LAN-only admin tool used from a handful of browsers | One `openssl` command (below); accept the warning once per browser, or import the certificate on your devices |
| **Let's Encrypt via DNS-01** | You own a public domain and want a browser-trusted certificate on the host itself | `certbot` or `acme.sh` with your DNS provider's API. The DNS-01 challenge needs no inbound access to the host. A deploy hook copies the renewed files into place and restarts the service (example below) |
| **Reverse proxy** | You already run a proxy with real certificates (Caddy, Traefik, nginx, Pangolin, …) | Leave the UI on HTTP, set `WEB_LISTEN` to an address only the proxy can reach, and let the proxy terminate TLS. No certificate handling on this host at all |

Self-signed, valid for ten years. Put every name and address you will actually
type into the SAN; browsers ignore the CN:

```sh
sudo openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj "/CN=dns-sync" \
  -addext "subjectAltName=DNS:dns-sync.home.arpa,IP:192.168.1.53" \
  -keyout /etc/unifi-technitium-sync/web.key -out /etc/unifi-technitium-sync/web.crt
```

Whatever the source, three things apply:

1. The service runs as `unifi-dns-sync` with a read-only view of the
   filesystem, so the key and certificate must be readable by that user. Keep
   them in the configuration directory:

   ```sh
   sudo chown root:unifi-dns-sync /etc/unifi-technitium-sync/web.crt /etc/unifi-technitium-sync/web.key
   sudo chmod 640 /etc/unifi-technitium-sync/web.crt /etc/unifi-technitium-sync/web.key
   ```

2. Point the service at them in `sync.env` (or on the Settings tab) and
   restart. The startup log line changes from `http://` to `https://`, and
   the session cookie gains the `Secure` flag:

   ```
   WEB_TLS_CERT=/etc/unifi-technitium-sync/web.crt
   WEB_TLS_KEY=/etc/unifi-technitium-sync/web.key
   ```

3. Restart after every renewal or replacement, because the files are read
   only at startup. A `certbot` deploy hook that does both, saved as
   `/etc/letsencrypt/renewal-hooks/deploy/unifi-technitium-sync` and made
   executable:

   ```sh
   #!/bin/sh
   install -o root -g unifi-dns-sync -m 0640 "$RENEWED_LINEAGE/fullchain.pem" /etc/unifi-technitium-sync/web.crt
   install -o root -g unifi-dns-sync -m 0640 "$RENEWED_LINEAGE/privkey.pem" /etc/unifi-technitium-sync/web.key
   systemctl restart unifi-technitium-sync
   ```

If the certificate or key cannot be loaded, the sync keeps running and the
journal shows `Web UI could not start on …` with the reason (a missing file,
a permission error, or an SSL error for a key that does not match the
certificate).

## Troubleshooting

| Log message | Meaning |
|---|---|
| `Skipping X: an unmanaged A record already exists` | A manual record with that name exists; the service will not touch it. Add the label to `EXCLUDED_NAMES` to silence permanently, or delete the manual record to let the service manage it. Logged once, then demoted to debug. |
| `Skipping X: conflicting CNAME record already exists` | Another record type occupies the name; resolve in Technitium. |
| `Label for <mac>: X -> Y (…)` | The naming memory committed a new label; the parenthesis says why (a preferred field appeared, seen N polls, or the preferred field was missing for N polls). |
| `Client renamed: X is now Y` | The client's label changed durably; the old record was removed in the same cycle. Before 1.3.0 this line alternating every few cycles was finding 1 below. |
| `Not deleting X: the owned record marker or address no longer matches` | A record the service used to own was modified by hand; it is now yours. |
| `Configuration error: …` on start | A required variable is missing or invalid in `sync.env`. |
| `Web UI not started: WEB_LISTEN=… no WEB_PASSWORD_HASH is set` | Set a password with `--set-web-password`, or bind to `127.0.0.1`. The sync keeps running without the UI. |
| `Web UI could not start on …: Address already in use` | Another program owns that port; change `WEB_LISTEN` and restart. |
| `Web UI not started: WEB_LISTEN=… is reachable from the network but WEB_TLS_CERT is not set` | Plain HTTP on a network address is refused. Configure [TLS](#tls), bind to `127.0.0.1` and use an SSH tunnel or a reverse proxy, or set `WEB_ALLOW_INSECURE_LAN=true` to accept unencrypted logins. The sync itself keeps running. |
| `Could not delete the PTR … will retry on later cycles` | Technitium did not answer the PTR deletion; it is queued in the state file and retried each cycle for up to 7 days. |
| `Web UI could not start on …: [Errno 13]` / `No such file` / `[SSL]` | `WEB_TLS_CERT` or `WEB_TLS_KEY` is missing, unreadable by the `unifi-dns-sync` user, or the key does not match the certificate. See [TLS](#tls). The sync itself keeps running. |
| `Synchronization failed` + traceback | One cycle failed (usually a timeout or an unreachable API). The service retries on the next interval; state is not written for a failed cycle. |

Note that the service logs to stdout, so journald records every line at
priority *info* — `journalctl -p warning` will **not** surface warnings. Grep
for the level instead:

```sh
sudo journalctl -u unifi-technitium-sync --since -1d -o cat | grep -E 'WARNING|ERROR'
```

Run a single verbose cycle at any time:

```sh
sudo runuser -u unifi-dns-sync -- /opt/unifi-technitium-sync/unifi_technitium_sync.py \
  --config /etc/unifi-technitium-sync/sync.env --log-level DEBUG --once --dry-run
```

`--dry-run` never writes the state file, so the naming memory does not advance
between dry runs: two dry runs in a row show the same decisions.

Count how much the zone is actually changing (a healthy network should show
a handful of lines per day, not hundreds):

```sh
sudo journalctl -u unifi-technitium-sync --since -1d -o cat | grep -oE '(ADD|DELETE) (A|PTR)' | sort | uniq -c
```

## Project layout

| File | Purpose |
|---|---|
| `unifi_technitium_sync.py` | The service: settings schema and file handling, UniFi and Technitium API clients, naming memory, sync algorithm, shared runtime, CLI (`--config`, `--once`, `--dry-run`, `--backfill-ptr`, `--set-web-password`, `--log-level`) |
| `unifi_technitium_web.py` | Optional web UI: HTTP server, JSON API, sessions, and the embedded page. Imported only when `WEB_LISTEN` is set |
| `unifi-technitium-sync.env.example` | Annotated configuration template; copy to `/etc/unifi-technitium-sync/sync.env` |
| `unifi-technitium-sync.service` | Hardened systemd unit (dedicated user, `ProtectSystem=strict`, state dir is the only writable path) |
| `install.sh` | Idempotent installer: user, `/opt`, `/etc`, `/var/lib`, unit file |
| `.gitignore` | Keeps `sync.env`, certificates, `state.json`, and bytecode out of the repository |
| `tests/test_unifi_technitium_sync.py` | `unittest` suite, no dependencies: pure functions, state migration, and multi-poll regression fixtures for the alias-blip and de-dup churn (`python3 -m unittest discover -s tests`) |
| `tests/test_web_and_config.py` | Settings-file round trips, validation, password hashing, the runtime, and the web UI end to end over a real socket |
| `scripts/release.sh` | Maintainer tool, not shipped in packages: runs the tests and builds `dist/unifi-technitium-sync-X.Y.Z.tar.gz` plus `SHA256SUMS` and release notes with `git archive`; with `--tag` it tags `vX.Y.Z` and pushes the tag to start the Release workflow |
| `.github/workflows/ci.yml` | Tests on Python 3.9, 3.11 and 3.13 for every push and pull request, plus a trial package build kept as an artifact for 7 days |
| `.github/workflows/release.yml` | On a `vX.Y.Z` tag: checks it matches `VERSION`, runs the tests, builds the package and creates the GitHub release |
| `.gitattributes` | Keeps `scripts/`, `.github/`, `.gitignore` and itself out of release packages |
| `LICENSE` | MIT |

## Code review notes (October 2026)

A full read-through of the source plus thirty days of production journal.
Nothing below is a crash bug and the service has been stable, but the first two
items caused real, continuous write load on Technitium. Findings 1, 2 and 4 are
fixed in 1.3.0 and kept here for the record. Items are ordered by impact.

**1. Label flips cause continuous record churn — confirmed in production; fixed in 1.3.0 / 1.4.0.**
In one 24-hour window (287 cycles) four clients were renamed back and forth
about 50–60 times each, producing roughly **500 A-record deletes, 500 adds and
500 PTR deletes per day** against a zone of 80 records. Each pattern is one
MAC alternating between two labels: a thermostat between `thermostat` and
`ecobee-kitchen`, two Wemo plugs between the lwIP default `lwip0` and
`wemo-patio-N`. The first analysis assumed an alias blinking in and out;
dumping the raw API records showed that none of these devices has an alias
at all. It is UniFi's **`hostname` field that alternates**: UniFi learns
hostnames from several discovery sources (DHCP, mDNS, UPnP; the record has a
`hostname_source` field) and for these devices the sources disagree, so
consecutive polls seconds apart can return different values. v1.1.0 dampens
**IP** changes with `IP_STABLE_POLLS`, but a **label** change was applied
immediately by design ("immediate rename cleanup by MAC"), so every flip was
a delete + add.
*Fixed* by the naming memory described in "How names are chosen": 1.3.0 added
the memory, the alias-priority rules and sighting-based dampening; 1.4.0
corrected the rule for device-announced names, which are now held until the
stored name has gone unreported for `NAME_DOWNGRADE_POLLS` online polls,
with a unique name winning over a shared one immediately. Regression tests:
`test_hostname_source_flapping_never_renames`,
`test_unique_hostname_replaces_shared_one_at_once`,
`test_wemo_fleet_settles_then_stays_quiet`, `test_alias_blips_never_rename`.

**2. De-duplication suffixes are unstable — fixed in 1.3.0.** When several clients sanitize to
the same label, each gets a six-hex-digit MAC suffix; when only one is online
it gets the bare label. The suffix therefore depends on which *other* clients
happen to be connected, so a device alternates between `lwip0` and
`lwip0-6a7b8c` as its neighbours come and go (`iphone`/`iphone-5d6e7f` and
`mac`/`mac-1d2e3f` showed the same, less often). Finding 1 amplifies this:
every time the two Wemos announce `lwip0` they collide with the third.
*Fixed in 1.3.0:* de-duplication now groups every client remembered within
`NAME_MEMORY_TTL` (default 7 days), online or not, so a suffix persists until
the namesake has been gone for a week. Regression test:
`test_suffix_is_sticky_across_twin_absence_and_expiry`.

**3. `UNIFI_SITE_ID` is required but unused with the default endpoint.** The
legacy path `/proxy/network/api/s/default/stat/sta` carries the site *name*
(`default`) and has no `{site_id}` placeholder, yet config validation still
demands the UUID. Harmless but confusing during setup, and a non-default site
name cannot be expressed without overriding the whole path. *Fix:* require
`UNIFI_SITE_ID` only when the path contains `{site_id}`, and add a
`UNIFI_SITE_NAME` (default `default`) substituted into the legacy path.

**4. No automated tests — fixed in 1.3.0.** `tests/test_unifi_technitium_sync.py`
covers the pure functions, state migration and multi-poll fixtures for
findings 1 and 2 (27 tests, `python3 -m unittest discover -s tests`).

**5. IPv4 only.** AAAA records are never created, IPv6 addresses from UniFi
are ignored, and an IPv6 CIDR in `ALLOWED_NETWORKS` is rejected at startup.

**6. No back-off after failures.** An unreachable Technitium host produces a
full traceback every `SYNC_INTERVAL` forever (this happened for a day in
August 2026 during a DNS-host rebuild). The last thirty days show seven
transient failures, all on the UniFi side: five HTTP 500 responses and two
malformed bodies (one truncated JSON document, one HTML page). Each failed
cycle is skipped cleanly without writing state, which is correct. *Fix:*
exponential back-off capped at around 30 minutes, one-line error at INFO,
traceback at DEBUG.

**7. Log levels are invisible to journald.** Python logs to stdout, so every
line is priority *info* and `journalctl -p warning` is empty. *Fix:* log to
stderr with `sd-daemon` prefixes (`<4>` for warning) — still zero
dependencies — so the unit's warnings show up in `journalctl -p warning` and
in Proxmox/Cockpit log views.

**8. Minor.**
- `sanitize_label` drops everything after the first dot, so a client named
  `192.168.1.5` or `node.js-box` becomes `192` / `node`.
- ~~The dedup suffix can produce a double hyphen when a long label is
  truncated~~ — fixed in 1.3.0.
- When a client is renamed **and** changes IP in the same cycle the new name
  is created immediately with the new IP (no dampening), which is correct but
  worth knowing.
- The systemd unit could add `ProtectKernelTunables=true`,
  `ProtectControlGroups=true`, `RestrictAddressFamilies=AF_INET AF_INET6`,
  `CapabilityBoundingSet=` and `SystemCallFilter=@system-service`.
- Error messages echo up to 500 characters of the failing response body into
  the journal. Harmless for Technitium, but a UniFi excerpt can include
  client names and MACs.
- There are no git tags for the v1.1.0 / v1.2.0 releases, only commit
  messages.

**What the review confirmed is sound:** ownership via marker comment plus
state file; recovery from a lost state file; refusal to touch unmanaged or
conflicting records; atomic state writes; IP-flap dampening; explicit PTR
cleanup (Technitium does not cascade); pagination that works for both the
legacy and Integration v1 response shapes; credentials in headers only;
graceful SIGTERM handling; hardened systemd unit; zero dependencies. The
repository history contains only placeholder credentials — the live
configuration has never been committed.

## Roadmap

The embedded web UI proposed in the October 2026 review shipped in 1.4.0 as
designed: opt-in standard-library HTTP server in the daemon's own process, the
sync loop in the main thread with a "sync now" event, one settings schema
shared by the file parser, the form and validation, and the daemon owning
`sync.env`. Still open, in rough priority order:

- Finding 3: require `UNIFI_SITE_ID` only when the client path uses it, and add
  a `UNIFI_SITE_NAME` for the legacy path.
- Exponential back-off after failed cycles (finding 6) and `sd-daemon` log
  prefixes so journald sees warning levels (finding 7).
- IPv6 / AAAA records (finding 5).
- A per-record "ignore this client" action in the UI that appends to
  `EXCLUDED_NAMES`, and a live-updating status page using server-sent events.

## Releasing

For maintainers. Bump `VERSION` in `unifi_technitium_sync.py`, add a changelog
entry below, and commit and push to `main`. Every push runs the CI workflow:
the tests on Python 3.9, 3.11 and 3.13 (the README promises 3.9 and newer), and
a trial build of the release package that is kept as a build artifact for a
week. When CI is green, start the release:

```sh
scripts/release.sh --tag
```

That tags `vX.Y.Z` on the pushed commit and pushes the tag. The Release
workflow then checks that the tag matches `VERSION`, runs the tests, builds
`unifi-technitium-sync-X.Y.Z.tar.gz` and `SHA256SUMS` with the same script, and
creates the GitHub release with both attached and the changelog entry as the
notes. Follow it with `gh run watch`.

`scripts/release.sh` with no argument builds `dist/` from the current commit
for inspection and touches nothing else. The script refuses to run with
uncommitted changes, failing tests, a missing changelog entry, or (for `--tag`)
an unpushed commit or a tag that already exists. Packages contain only
committed files, so a release can never include `sync.env`, state files, or
certificates. If Actions is ever unavailable, build locally and publish by
hand:

```sh
gh release create vX.Y.Z dist/*.tar.gz dist/SHA256SUMS \
  --verify-tag --title vX.Y.Z --notes-file dist/RELEASE_NOTES.md --latest
```

## Upgrading

Pull the new version and rerun `sudo ./install.sh`. The installer preserves
`/etc/unifi-technitium-sync/sync.env` and the state file. Restart the service
afterwards: `sudo systemctl restart unifi-technitium-sync`.

Upgrading from 1.2.x to 1.3.0 migrates the state file to version 2 on the
first cycle and seeds the naming memory from the records already owned, so
that cycle renames nothing except a client whose de-duplication twin's record
had already been removed (its suffix is released) or a client caught mid-blip.
No configuration change is required; the three new `NAME_*` settings have
defaults.

Upgrading to 1.4.0: the installer now also copies `unifi_technitium_web.py`,
makes `sync.env` group-writable by the service user, and the unit passes the
file path as `CONFIG_FILE` instead of loading it with `EnvironmentFile=`.
Rerun `sudo ./install.sh`, then restart. The web UI stays off until you set
`WEB_LISTEN`.

Upgrading to 1.5.0: if the UI listens on a network address without TLS, it no
longer starts (the journal says why). Configure `WEB_TLS_CERT` and
`WEB_TLS_KEY`, or set `WEB_ALLOW_INSECURE_LAN=true` to keep plain HTTP. The
state file gains a `ptr_cleanup` list automatically; nothing else changes.

## Removal

```sh
sudo systemctl disable --now unifi-technitium-sync
```

Records created by the service are intentionally left in place; they are
identifiable in Technitium by the `managed-by=unifi-technitium-sync` comment.

## Changelog

- **1.5.0** (2026-10-09) — Fixes from a Codex code and security review.
  Login throttling can no longer be bypassed with parallel requests: attempts
  are reserved before the password hash runs, one per address at a time, five
  failures per five minutes, at most two hashes at once. Plain HTTP on a
  network address is refused unless `WEB_ALLOW_INSECURE_LAN=true`, and then
  every page shows a warning. Clients whose MACs end in the same six hex
  digits get longer suffixes instead of one record silently replacing the
  other; clients keep the name they hold, so a newcomer cannot take it over;
  MACs that are not 12 hex digits get no naming memory. IP changes add the new
  record before deleting the old one. PTR deletions that fail transiently are
  queued in the state file and retried for up to 7 days, even when the cycle
  fails. 63 tests.
- **1.4.0** (2026-10-09) — Built-in web UI (`WEB_LISTEN`, `WEB_TLS_*`,
  `--set-web-password`): status, records with naming memory, settings editor
  with validation and live apply, dry-run preview, log tail. Naming rule
  corrected after inspecting raw API data: a different device-announced
  hostname is held like a downgrade, and a unique name replaces a shared one
  at once (the real cause of the churn was UniFi's hostname alternating
  between discovery sources, not a blinking alias). The daemon now
  reads `sync.env` itself (`CONFIG_FILE` / `--config`) and can rewrite it;
  `--log-level`; sync cycles return a result object; client-factory errors
  (bad CA path) are reported as failed cycles instead of stopping the loop.
  Code default for `UNIFI_CLIENTS_PATH` is now the legacy `stat/sta` path and
  for `NAME_FIELDS` is `name,hostname`, matching this README and the template.
- **1.3.0** (2026-10-09) — Per-client naming memory: renames are dampened
  (`NAME_STABLE_POLLS`), a less preferred name field cannot displace a more
  preferred one on a blip (`NAME_DOWNGRADE_POLLS`), de-duplication suffixes
  stay stable while a namesake is offline (`NAME_MEMORY_TTL`); state file v2
  with automatic migration; `unittest` suite; no more double hyphen in
  suffixed labels.
- **1.2.0** (2026-09-05) — Full PTR lifecycle: PTRs created on add, deleted
  explicitly on remove, `--backfill-ptr` for existing records,
  `CREATE_PTR_ZONE`.
- **1.1.0** (2026-08-03) — IP flap dampening (`IP_STABLE_POLLS`), warn-once
  skip logging, immediate rename cleanup by MAC, hardened systemd unit.

## License

MIT
