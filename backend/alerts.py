"""Rule engine: high-risk open ports, traffic spikes, and new devices joining."""

import statistics
import time

from backend import db

HIGH_RISK_PORTS = {
    21: "FTP allows unencrypted credential transfer",
    23: "Telnet is unencrypted and frequently exploited",
    135: "MSRPC is a common attack surface (e.g. worms)",
    139: "NetBIOS can leak host and share information",
    445: "SMB has been the target of major ransomware (WannaCry, NotPetya)",
    1433: "MSSQL exposed to the network can be brute-forced",
    3306: "MySQL exposed to the network can be brute-forced",
    3389: "RDP is a top target for ransomware and brute force",
    5900: "VNC is frequently left unauthenticated",
    6379: "Redis has no auth by default and is often exposed by mistake",
    27017: "MongoDB has no auth by default and is often exposed by mistake",
}

SPIKE_WINDOW = 30
SPIKE_MULTIPLIER = 4
SPIKE_MIN_RATE = 50 * 1024  # 50 KB/s floor so idle jitter doesn't fire


def _emit(severity, category, message):
    alert = {"timestamp": time.time(), "severity": severity, "category": category, "message": message}
    db.insert_alert(alert)
    return alert


def check_traffic_spike(history):
    """Flag upload/download rates that are far above their recent baseline."""
    alerts = []
    if len(history) < SPIKE_WINDOW + 1:
        return alerts
    recent = history[-(SPIKE_WINDOW + 1):]
    baseline, latest = recent[:-1], recent[-1]
    for direction, key in (("upload", "send_rate"), ("download", "recv_rate")):
        mean = statistics.mean(h[key] for h in baseline)
        if latest[key] > SPIKE_MIN_RATE and mean > 0 and latest[key] > mean * SPIKE_MULTIPLIER:
            alerts.append(
                _emit(
                    "warning",
                    "traffic_spike",
                    f"Unusual {direction} spike: {latest[key] / 1024:.0f} KB/s "
                    f"(baseline {mean / 1024:.0f} KB/s)",
                )
            )
    return alerts


def check_new_devices(devices):
    """Diff discovered devices against known MACs and flag newcomers."""
    alerts = []
    known = db.get_known_devices()
    now = time.time()
    for dev in devices:
        is_new = dev["mac"] not in known
        db.upsert_known_device(dev["mac"], dev["ip"], dev.get("hostname", ""), "", now)
        if is_new:
            label = f" - {dev['hostname']}" if dev.get("hostname") else ""
            alerts.append(
                _emit(
                    "info",
                    "new_device",
                    f"New device joined the network: {dev['ip']} ({dev['mac']}){label}",
                )
            )
    return alerts


def check_risky_ports(host, open_ports):
    """Flag any open port that's on the high-risk list."""
    alerts = []
    for entry in open_ports:
        port = entry["port"]
        if port in HIGH_RISK_PORTS:
            alerts.append(
                _emit(
                    "critical",
                    "risky_port",
                    f"High-risk port {port} ({entry['service']}) open on {host}: {HIGH_RISK_PORTS[port]}",
                )
            )
    return alerts


def get_recent_alerts(limit=100):
    return db.get_alerts(limit)
