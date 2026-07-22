"""Pure rule-engine tests for backend/alerts.py — traffic-spike detection
and the high-risk-port list, using synthetic data (no real network I/O)."""

from backend import alerts


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


def test_flags_high_risk_port(monkeypatch):
    monkeypatch.setattr(alerts.db, "insert_alert", lambda alert: None)
    open_ports = [{"port": 3389, "service": "RDP", "state": "open"}]

    found = alerts.check_risky_ports("10.0.0.5", open_ports)

    assert len(found) == 1
    assert found[0]["severity"] == "critical"


def test_ignores_safe_port(monkeypatch):
    monkeypatch.setattr(alerts.db, "insert_alert", lambda alert: None)
    open_ports = [{"port": 80, "service": "HTTP", "state": "open"}]
    assert alerts.check_risky_ports("10.0.0.5", open_ports) == []
