"""SQLite persistence for traffic history, alerts, and known devices."""

import os
import sqlite3
import threading

DB_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "scan_history.db"
)
_lock = threading.Lock()


def get_connection():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with _lock:
        conn = get_connection()
        conn.execute(
            """CREATE TABLE IF NOT EXISTS traffic_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL NOT NULL,
                bytes_sent INTEGER NOT NULL,
                bytes_recv INTEGER NOT NULL,
                send_rate REAL NOT NULL,
                recv_rate REAL NOT NULL
            )"""
        )
        conn.execute(
            """CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL NOT NULL,
                severity TEXT NOT NULL,
                category TEXT NOT NULL,
                message TEXT NOT NULL
            )"""
        )
        conn.execute(
            """CREATE TABLE IF NOT EXISTS known_devices (
                mac TEXT PRIMARY KEY,
                ip TEXT,
                hostname TEXT,
                vendor TEXT,
                first_seen REAL,
                last_seen REAL
            )"""
        )
        conn.commit()
        conn.close()


# Persisted every TRAFFIC_PERSIST_INTERVAL (5s, see app.py) — 17280 rows
# covers roughly 24h at that cadence.
TRAFFIC_HISTORY_RETENTION = 17280


def insert_traffic(sample):
    with _lock:
        conn = get_connection()
        conn.execute(
            "INSERT INTO traffic_history (timestamp, bytes_sent, bytes_recv, send_rate, recv_rate) "
            "VALUES (?, ?, ?, ?, ?)",
            (
                sample["timestamp"],
                sample["bytes_sent"],
                sample["bytes_recv"],
                sample["send_rate"],
                sample["recv_rate"],
            ),
        )
        conn.execute(
            "DELETE FROM traffic_history WHERE id NOT IN "
            "(SELECT id FROM traffic_history ORDER BY id DESC LIMIT ?)",
            (TRAFFIC_HISTORY_RETENTION,),
        )
        conn.commit()
        conn.close()


def get_traffic_history(limit=200):
    with _lock:
        conn = get_connection()
        rows = conn.execute(
            "SELECT * FROM traffic_history ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        conn.close()
        return [dict(r) for r in reversed(rows)]


def insert_alert(alert):
    with _lock:
        conn = get_connection()
        conn.execute(
            "INSERT INTO alerts (timestamp, severity, category, message) VALUES (?, ?, ?, ?)",
            (alert["timestamp"], alert["severity"], alert["category"], alert["message"]),
        )
        conn.execute(
            "DELETE FROM alerts WHERE id NOT IN (SELECT id FROM alerts ORDER BY id DESC LIMIT 500)"
        )
        conn.commit()
        conn.close()


def get_alerts(limit=100):
    with _lock:
        conn = get_connection()
        rows = conn.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        conn.close()
        return [dict(r) for r in rows]


def upsert_known_device(mac, ip, hostname, vendor, now):
    """Returns True if this MAC was not previously known (i.e. a new device)."""
    with _lock:
        conn = get_connection()
        existing = conn.execute("SELECT mac FROM known_devices WHERE mac=?", (mac,)).fetchone()
        if existing:
            conn.execute(
                "UPDATE known_devices SET ip=?, hostname=?, vendor=?, last_seen=? WHERE mac=?",
                (ip, hostname, vendor, now, mac),
            )
        else:
            conn.execute(
                "INSERT INTO known_devices (mac, ip, hostname, vendor, first_seen, last_seen) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (mac, ip, hostname, vendor, now, now),
            )
        conn.commit()
        conn.close()
        return existing is None


def get_known_devices():
    with _lock:
        conn = get_connection()
        rows = conn.execute("SELECT * FROM known_devices").fetchall()
        conn.close()
        return {r["mac"]: dict(r) for r in rows}
