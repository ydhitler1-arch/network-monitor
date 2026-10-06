"""Pure rule-engine tests for backend/alerts.py — traffic-spike detection
and the high-risk-port list, using synthetic data (no real network I/O)."""

import pytest

from backend import alerts, db


@pytest.fixture(autouse=True)
def _reset_spike_cooldown():
    alerts._spike_seen.clear()
    yield
    alerts._spike_seen.clear()


@pytest.fixture()
def temp_db(tmp_path, monkeypatch):
    """Point backend.db at a throwaway SQLite file with the schema created."""
    monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "test.db"))
    monkeypatch.setattr(db, "_conn", None)
    db.init_db()
    yield
    db._conn.close()


def _sample(t, send_rate, recv_rate):
    return {"timestamp": t, "send_rate": send_rate, "recv_rate": recv_rate}


def test_no_spike_with_insufficient_history():
    history = [_sample(i, 100, 100) for i in range(5)]
    assert alerts.check_traffic_spike(history) == []


def test_detects_upload_spike(monkeypatch):
    monkeypatch.setattr(alerts.db, "insert_alert", lambda alert: None)
    baseline_rate = 20 * 1024
    spike_rate = baseline_rate * 6  # over both SPIKE_MULTIPLIER and SPIKE_MIN_RATE
    history = [_sample(i, baseline_rate, baseline_rate) for i in range(alerts.SPIKE_WINDOW)]
    history.append(_sample(alerts.SPIKE_WINDOW, spike_rate, baseline_rate))

    found = alerts.check_traffic_spike(history)

    assert any(a["category"] == "traffic_spike" and "upload" in a["message"] for a in found)


def test_no_spike_when_within_baseline(monkeypatch):
    monkeypatch.setattr(alerts.db, "insert_alert", lambda alert: None)
    history = [_sample(i, 100 * 1024, 100 * 1024) for i in range(alerts.SPIKE_WINDOW + 1)]
    assert alerts.check_traffic_spike(history) == []


def test_flags_high_risk_port(temp_db):
    open_ports = [{"port": 3389, "service": "RDP", "state": "open"}]

    found = alerts.check_risky_ports("10.0.0.5", open_ports)

    assert len(found) == 1
    assert found[0]["severity"] == "critical"


def test_risky_port_alerts_only_once_per_host_port(temp_db):
    open_ports = [{"port": 6379, "service": "Redis", "state": "open"}]

    first = alerts.check_risky_ports("10.0.0.5", open_ports)
    second = alerts.check_risky_ports("10.0.0.5", open_ports)

    assert len(first) == 1 and first[0]["severity"] == "high"
    assert second == []
    findings = alerts.get_port_findings()
    assert len(findings) == 1 and findings[0]["seen_count"] == 2


def test_ignores_safe_port(monkeypatch):
    monkeypatch.setattr(alerts.db, "insert_alert", lambda alert: None)
    open_ports = [{"port": 80, "service": "HTTP", "state": "open"}]
    assert alerts.check_risky_ports("10.0.0.5", open_ports) == []


def test_finding_closes_when_port_no_longer_open(temp_db):
    redis = [{"port": 6379, "service": "Redis", "state": "open"}]
    alerts.check_risky_ports("10.0.0.5", redis, scanned_ports=[6379, 3389])

    alerts.check_risky_ports("10.0.0.5", [], scanned_ports=[6379, 3389])

    finding = alerts.get_port_findings()[0]
    assert finding["status"] == "closed" and finding["closed_at"] is not None


def test_close_ignores_ports_outside_the_scan(temp_db):
    redis = [{"port": 6379, "service": "Redis", "state": "open"}]
    alerts.check_risky_ports("10.0.0.5", redis, scanned_ports=[6379])

    alerts.check_risky_ports("10.0.0.5", [], scanned_ports=[80])  # didn't cover 6379

    assert alerts.get_port_findings()[0]["status"] == "open"


def test_reopened_finding_alerts_again(temp_db):
    redis = [{"port": 6379, "service": "Redis", "state": "open"}]
    alerts.check_risky_ports("10.0.0.5", redis, scanned_ports=[6379])
    alerts.check_risky_ports("10.0.0.5", [], scanned_ports=[6379])

    again = alerts.check_risky_ports("10.0.0.5", redis, scanned_ports=[6379])

    assert len(again) == 1
    finding = alerts.get_port_findings()[0]
    assert finding["status"] == "open" and finding["closed_at"] is None


def test_init_db_migrates_old_port_findings_table(tmp_path, monkeypatch):
    import sqlite3

    path = str(tmp_path / "old.db")
    old = sqlite3.connect(path)
    old.execute("""CREATE TABLE port_findings (
        id INTEGER PRIMARY KEY AUTOINCREMENT, host TEXT NOT NULL, port INTEGER NOT NULL,
        service TEXT NOT NULL, severity TEXT NOT NULL, description TEXT NOT NULL,
        first_seen REAL NOT NULL, last_seen REAL NOT NULL, seen_count INTEGER NOT NULL DEFAULT 1,
        UNIQUE(host, port))""")
    old.execute("INSERT INTO port_findings VALUES (1,'h',23,'Telnet','critical','d',1,1,1)")
    old.commit()
    old.close()
    monkeypatch.setattr(db, "DB_PATH", path)
    monkeypatch.setattr(db, "_conn", None)

    db.init_db()

    assert db.get_port_findings()[0]["status"] == "open"
    db._conn.close()


def test_old_rows_pruned_in_batches(temp_db, monkeypatch):
    monkeypatch.setattr(db, "ALERTS_RETENTION", 5)
    monkeypatch.setattr(db, "PRUNE_EVERY", 10)
    monkeypatch.setitem(db._inserts_since_prune, "alerts", 0)

    def add(i):
        db.insert_alert({"timestamp": i, "severity": "info", "category": "t", "message": str(i)})

    for i in range(10):          # prune ran on insert 0 only, so nothing trimmed yet
        add(i)
    assert len(db.get_alerts(100)) == 10

    add(10)                      # next prune cycle starts: trims to newest 5, then keeps this one
    rows = db.get_alerts(100)
    assert len(rows) <= 6 and rows[0]["message"] == "10"
