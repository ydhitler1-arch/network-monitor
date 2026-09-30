"""Rule engine: risky ports, traffic spikes, new devices.

Severity tiers (applied to port_findings, NOT hardcoded to 'critical'):
  critical — direct RCE / active-exploit targets  (Telnet, RDP, SMB)
  high     — unauthenticated data stores          (MySQL, MSSQL, Redis, MongoDB)
  medium   — info-disclosure / lateral movement   (MSRPC, NetBIOS, FTP)
  low      — weak legacy services                 (VNC)

Deduplication strategy
  Port findings are stored in the `port_findings` DB table (one row per
  host+port).  Each scan cycle calls db.upsert_port_finding(), which either
  creates a new row (is_new=True) or updates last_seen + seen_count
  (is_new=False).  A one-time event-alert is emitted to the `alerts` table
  ONLY when is_new=True.  This means:
  - The findings table always reflects current state, surviving restarts.
  - The alerts log captures only genuine first-seen events.
  - No duplicate alert rows accumulate across scan cycles.
"""

import logging
import statistics
import time

from backend import db

log = logging.getLogger(__name__)

# ── Severity-tiered port catalogue ───────────────────────────────────────────
# key → (display_name, severity, description)
PORT_INFO: dict[int, tuple[str, str, str]] = {
    23:    ("Telnet",   "critical", "Telnet is unencrypted and frequently exploited"),
    3389:  ("RDP",      "critical", "RDP is a top target for ransomware and brute force"),
    445:   ("SMB",      "critical", "SMB has been the target of major ransomware (WannaCry, NotPetya)"),
    1433:  ("MSSQL",    "high",     "MSSQL exposed to the network can be brute-forced"),
    3306:  ("MySQL",    "high",     "MySQL exposed to the network can be brute-forced"),
    6379:  ("Redis",    "high",     "Redis has no auth by default and is often exposed by mistake"),
    27017: ("MongoDB",  "high",     "MongoDB has no auth by default and is often exposed by mistake"),
    21:    ("FTP",      "medium",   "FTP allows unencrypted credential transfer"),
    135:   ("MSRPC",    "medium",   "MSRPC is a common attack surface (e.g. worms)"),
    139:   ("NetBIOS",  "medium",   "NetBIOS can leak host and share information"),
    5900:  ("VNC",      "low",      "VNC is frequently left unauthenticated"),
}

# Flat description map kept for backward-compat (used by /api/meta)
HIGH_RISK_PORTS: dict[int, str] = {p: info[2] for p, info in PORT_INFO.items()}

# Traffic-spike cooldown (per direction): 5 minutes between repeated alerts
SPIKE_COOLDOWN = 300
_spike_seen: dict[str, float] = {}


# ── Helpers ───────────────────────────────────────────────────────────────────

def _emit(severity: str, category: str, message: str) -> dict:
    """Write a one-time event to the alerts log and return it."""
    alert = {
        "timestamp": time.time(),
        "severity": severity,
        "category": category,
        "message": message,
    }
    db.insert_alert(alert)
    # Log every emitted alert with its severity so it's easy to verify the fix.
    log.info("[ALERT] severity=%-8s  category=%-14s  %s", severity, category, message)
    return alert


# ── Public rule functions ─────────────────────────────────────────────────────

def check_traffic_spike(history: list) -> list:
    """Flag upload/download rates that are far above their recent baseline."""
    SPIKE_WINDOW = 30
    SPIKE_MULTIPLIER = 4
    SPIKE_MIN_RATE = 50 * 1024   # 50 KB/s floor so idle jitter doesn't fire

    alerts = []
    if len(history) < SPIKE_WINDOW + 1:
        return alerts

    recent = history[-(SPIKE_WINDOW + 1):]
    baseline, latest = recent[:-1], recent[-1]
    now = time.time()

    for direction, key in (("upload", "send_rate"), ("download", "recv_rate")):
        mean = statistics.mean(h[key] for h in baseline)
        if not (latest[key] > SPIKE_MIN_RATE and mean > 0 and latest[key] > mean * SPIKE_MULTIPLIER):
            continue
        if now - _spike_seen.get(direction, 0) < SPIKE_COOLDOWN:
            continue
        _spike_seen[direction] = now
        alerts.append(_emit(
            "warning", "traffic_spike",
            f"Unusual {direction} spike: {latest[key] / 1024:.0f} KB/s "
            f"(baseline {mean / 1024:.0f} KB/s)",
        ))
    return alerts


def check_new_devices(devices: list) -> list:
    """Diff discovered devices against known MACs and flag newcomers."""
    alerts = []
    known = db.get_known_devices()
    now = time.time()
    for dev in devices:
        is_new = dev["mac"] not in known
        db.upsert_known_device(dev["mac"], dev["ip"], dev.get("hostname", ""), "", now)
        if is_new:
            label = f" - {dev['hostname']}" if dev.get("hostname") else ""
            alerts.append(_emit(
                "info", "new_device",
                f"New device joined the network: {dev['ip']} ({dev['mac']}){label}",
            ))
    return alerts


def check_risky_ports(host: str, open_ports: list) -> list:
    """Update persistent port findings and emit a one-time alert only on first discovery.

    For each (host, port):
      - db.upsert_port_finding() is called every scan — it updates last_seen
        and seen_count in the DB without creating a new row.
      - Only when the finding is brand-new (upsert returns True) do we write
        an entry to the alerts log.
      - The severity comes from PORT_INFO, never hardcoded to 'critical'.
    """
    new_alerts = []
    now = time.time()

    for entry in open_ports:
        port = entry["port"]
        if port not in PORT_INFO:
            continue

        service, severity, description = PORT_INFO[port]

        # Log the severity value at the point of generation so it can be verified.
        log.debug(
            "[FINDING] host=%-16s  port=%-5s  service=%-8s  severity=%s",
            host, port, service, severity,
        )

        is_new = db.upsert_port_finding(host, port, service, severity, description, now)

        if is_new:
            # First time we've ever seen this host+port — write a one-time alert.
            new_alerts.append(_emit(
                severity, "risky_port",
                f"{service} (port {port}) first detected on {host}: {description}",
            ))

    return new_alerts


def get_recent_alerts(limit: int = 100) -> list:
    """Return the most recent one-time event alerts (new device, spike, first-seen findings)."""
    return db.get_alerts(limit)


def get_port_findings(limit: int = 200) -> list:
    """Return all known port findings ordered by severity then last_seen."""
    return db.get_port_findings(limit)
