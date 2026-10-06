# Network Monitor

![Tests](https://github.com/ydhitler1-arch/network-monitor/actions/workflows/tests.yml/badge.svg)

A local network monitoring dashboard: live bandwidth usage, connected device
discovery, port scanning, and rule-based security alerts. Python (Flask)
backend, React (Vite) frontend.

> **Scope note:** the device scan and port scanner operate on your own local
> network only. Only scan hosts/networks you own or are authorized to test.

## Features

- **Live traffic monitoring** — real bandwidth in/out sampled from `psutil`,
  charted in the browser, polled every 2s. Toggle to "Extended" for a
  longer-range view (~24h, 5s resolution) backed by SQLite instead of the
  in-memory buffer.
- **Connected devices** — discovers real IP/MAC pairs on your local subnet(s).
  Uses a `scapy` ARP scan when available (best results, needs Npcap on
  Windows / root on Linux/macOS), and otherwise falls back to a ping sweep +
  the OS ARP cache (`arp -a` / `arp -n`) — no extra privileges required.
- **Port scanning** — a fast threaded socket connect-scan of common ports by
  default, with an optional `python-nmap` engine if the `nmap` binary is
  installed on your system.
- **Security alerts** — a background rule engine flags:
  - high-risk open ports (Telnet, SMB, RDP, unauthenticated Redis/Mongo, etc.)
  - unusual traffic spikes (upload/download rate far above recent baseline)
  - new devices joining the network (diffed against previously seen MACs)
  - devices leaving the network (missing from scans for 5 minutes) and coming back

Traffic samples and alerts are persisted to a local SQLite database
(`data/scan_history.db`) so history survives a restart.

### Hardening built in

- **Login required** — a login form (session-cookie based, `backend/auth.py`
  + `frontend/src/components/Login.jsx`) gates every `/api/*` route.
  Credentials come from `NETMON_USERNAME` / `NETMON_PASSWORD`; if unset, a
  random password is generated and printed to the console on each startup.
  Login attempts are rate-limited (`NETMON_LOGIN_RATE_LIMIT`).
- **Scan targets restricted to private/local addresses** — the `host`
  parameter on `/api/ports/scan` is resolved and checked
  (`backend/security.py`); public IPs/hostnames are rejected with a 403. This
  keeps the scanner from being turned into an open scanning proxy against
  third parties.
- **Rate limiting** — the scan endpoints are capped (default 10/minute,
  `NETMON_SCAN_RATE_LIMIT`) via `flask-limiter`.
- **CORS locked to configured origins** (`NETMON_CORS_ORIGINS`), not `*`.
- **Runs on `waitress`**, a production-grade WSGI server, instead of the
  Flask dev server.

## Project layout

```
network-monitor/
├── README.md
├── requirements.txt
├── run.py                   # entry point — starts the Flask server
├── backend/
│   ├── app.py                # Flask app, routes, background monitor loop
│   ├── traffic.py            # bandwidth sampling (psutil)
│   ├── devices.py             # local network device discovery
│   ├── ports.py               # port scanner (socket / python-nmap)
│   ├── alerts.py               # alert rule engine
│   ├── db.py                  # SQLite persistence
│   ├── config.py               # env-based configuration
│   ├── auth.py                  # login/logout/status + session auth guard
│   ├── limiter.py                # shared rate limiter instance
│   └── security.py               # restricts scan targets to private IPs
├── frontend/                  # React (Vite) app
│   ├── src/
│   │   ├── App.jsx
│   │   ├── api.js
│   │   └── components/
│   │       ├── Login.jsx
│   │       ├── TrafficChart.jsx
│   │       ├── DeviceList.jsx
│   │       ├── PortScanTable.jsx
│   │       ├── FindingsPanel.jsx
│   │       └── AlertsPanel.jsx
│   └── vite.config.js
└── data/
    └── scan_history.db        # created automatically on first run
```

(This uses Vite instead of Create React App for the frontend tooling — it's
faster and has no build config to eject. Vite serves `index.html` from the
`frontend/` root rather than `frontend/public/`, which is the only structural
difference from a CRA project.)

## Requirements

- Python 3.9+
- Node.js 18+ and npm
- Optional, for the best device/port scan results:
  - [Npcap](https://npcap.com/) (Windows) so `scapy` can send raw ARP
    packets — without it, device discovery still works via ARP-cache fallback
  - [nmap](https://nmap.org/download.html) on your PATH so the port scanner
    can use the `nmap` engine — without it, the socket-based scanner is used

## Setup

### Quick start (Windows): one command

Once you've done the one-time setup below (venv + `pip install` + `.env`),
`start.ps1` builds the frontend, launches the backend, and — if
`bin\cloudflared.exe` is present — starts a Cloudflare quick tunnel and
prints both the local and public URLs:

```powershell
.\start.ps1
```

It always stops any leftover instance of itself first (this project's
backend/tunnel processes have a habit of outliving a closed terminal on
Windows — a stale backend silently serving old code is worse than a clean
restart). Shut everything down with:

```powershell
.\stop.ps1
```

For day-to-day frontend development (hot reload on save) use `npm run dev`
in a second terminal instead of `start.ps1` — see step 2 below.

### 1. Backend

```bash
# from the project root
python -m venv .venv
.venv\Scripts\activate        # Windows
# source .venv/bin/activate   # macOS/Linux

pip install -r requirements.txt
cp .env.example .env          # then edit .env — at minimum set NETMON_PASSWORD
python run.py
```

The API server starts on **http://localhost:5000** (bound to `127.0.0.1` by
default — see "Exposing this beyond localhost" below before changing that).
Device discovery and ARP-based scanning may prompt for admin/root privileges
depending on your OS and whether `scapy` is installed — the app degrades
gracefully if it can't get raw socket access.

If you skip `.env`/`NETMON_PASSWORD`, a random password is generated and
printed to the console each time you start the server — copy it from there,
or set real credentials in `.env` to keep them stable across restarts.

### 2. Frontend

In a second terminal:

```bash
cd frontend
npm install
npm run dev
```

The dashboard opens on **http://localhost:5173** and proxies `/api` requests
to the backend on port 5000 (configured in `frontend/vite.config.js`).

### 3. Open the dashboard

Visit http://localhost:5173 in your browser and sign in with the username/
password configured above. A session cookie keeps you logged in for 12
hours (`PERMANENT_SESSION_LIFETIME` in `backend/app.py`), or until you hit
"Log out". Traffic starts streaming immediately after login; the first
device scan runs a few seconds after the backend starts (every 30s
afterward), and you can trigger an on-demand rescan from the dashboard.

## Exposing this beyond localhost

By default `NETMON_HOST=127.0.0.1`, so only this machine can reach the app.
Before it's reachable by anyone else:

1. **Set real credentials and a stable `NETMON_SECRET_KEY`** in `.env`. Never
   rely on the auto-generated values once anyone but you can reach this.
2. **Put TLS in front of it.** The login form posts your password in
   plaintext and the session cookie isn't encrypted in transit — both
   trivially readable over plain HTTP.
3. Set `NETMON_COOKIE_SECURE=true` once it's served over HTTPS.
4. **Scan targets are already restricted to private/local IPs** regardless of
   who's asking (`backend/security.py`) — this stays on even with auth, since
   it protects third parties from being scanned via your server, not just
   your own data.
5. **Keep the rate limits on** (`NETMON_LOGIN_RATE_LIMIT` /
   `NETMON_SCAN_RATE_LIMIT`) — lower them further if this is public-facing.

The backend also serves the built frontend directly (`app.py`'s `/` route),
so once you've built it there's exactly one process and one port to expose
— no separate frontend server, no CORS to configure.

### Option A: Cloudflare Tunnel (what this project uses, no domain required)

This gets you a public HTTPS URL without owning a domain, creating an
account, or forwarding any ports on your router — `cloudflared` makes an
outbound connection to Cloudflare, which handles TLS and proxies requests
back to your machine.

Set `NETMON_COOKIE_SECURE=true` in `.env` (Cloudflare terminates TLS for
you), then run `.\start.ps1` — it builds the frontend, starts the backend,
starts the tunnel, and prints the public URL for you. `.\stop.ps1` tears
both down.

Under the hood, that script is just:

```bash
cd frontend && npm run build && cd ..
python run.py
# in a second terminal:
bin\cloudflared.exe tunnel --url http://127.0.0.1:5000
```

(`bin/cloudflared.exe` is already downloaded in this project, from
https://github.com/cloudflare/cloudflared/releases — gitignored, not
committed. Re-download it there if `bin/` is missing.)

`cloudflared` prints a `https://<random-words>.trycloudflare.com` URL —
that's your public dashboard. Two caveats: this URL changes every time you
restart `cloudflared` (there's no way to pin it without a Cloudflare account
+ your own domain), and Cloudflare gives no uptime guarantee for these
account-less "quick tunnels" — fine for occasional access, not for
something you need up 24/7. Stop it any time with Ctrl+C; nothing stays
exposed once both processes are stopped.

### Option B: Reverse proxy + your own domain

If you later get a domain, [Caddy](https://caddyserver.com/) gets you a
stable URL with automatic HTTPS in one line:

```
# Caddyfile
your-domain.example {
    reverse_proxy 127.0.0.1:5000
}
```

You'd still need to either port-forward from your router (exposes your home
IP directly) or run this on a small cloud VPS instead of your home machine.

### Option C: Just your LAN, no public internet

Set `NETMON_HOST=0.0.0.0` and skip the tunnel/proxy entirely — other devices
on your home network can reach `http://<this-machine's-LAN-IP>:5000`
directly. Simpler, but only reachable from inside your network.

## Running tests

Covers the security-critical pieces: scan-target restriction, session
auth/login gating, and the alert rule engine.

```bash
pip install -r requirements-dev.txt
pytest tests/ -v
```

## API overview

All routes require an active login session except `/api/auth/login`,
`/api/auth/logout`, and `/api/auth/status`.

| Method | Path                  | Description                                   |
|--------|-----------------------|------------------------------------------------|
| POST   | `/api/auth/login`    | Sign in with `{username, password}` (rate-limited) |
| POST   | `/api/auth/logout`   | Clear the session                              |
| GET    | `/api/auth/status`   | Whether the current session is authenticated   |
| GET    | `/api/traffic/current`| Latest bandwidth sample                        |
| GET    | `/api/traffic/history`| Recent bandwidth samples (`?limit=`)           |
| GET    | `/api/devices`        | Last discovered device list                    |
| POST   | `/api/devices/scan`   | Trigger an immediate device scan (rate-limited)|
| GET    | `/api/ports/scan`     | Scan a private/local host (`?host=&ports=&engine=nmap`, rate-limited) |
| GET    | `/api/alerts`         | Recent alerts (`?limit=`)                      |
| GET    | `/api/meta`           | Engine availability + high-risk port reference |

## Configuration

Environment variables (see `.env.example`), loaded via `backend/config.py`:

- `NETMON_HOST` / `NETMON_PORT` — bind address (default `127.0.0.1:5000`)
- `NETMON_USERNAME` / `NETMON_PASSWORD` — login credentials
- `NETMON_SECRET_KEY` — session cookie signing key (set a stable value or
  every restart logs everyone out)
- `NETMON_COOKIE_SECURE` — set `true` once served over HTTPS
- `NETMON_CORS_ORIGINS` — comma-separated allowed origins
- `NETMON_LOGIN_RATE_LIMIT` / `NETMON_SCAN_RATE_LIMIT` — rate limits
  (default `5 per minute` / `10 per minute`)
- `NETMON_THREADS` — server worker threads (default 8)

Other tunable constants live at the top of `backend/app.py` and
`backend/alerts.py`:

- `TRAFFIC_INTERVAL` / `DEVICE_SCAN_INTERVAL` — polling cadence for the
  background monitor
- `MAX_PORTS_PER_SCAN` — cap on ports requested in a single scan
- `HIGH_RISK_PORTS` — ports flagged as high-risk in alerts
- `SPIKE_MULTIPLIER` / `SPIKE_MIN_RATE` — traffic spike sensitivity

## License

[MIT](LICENSE)
