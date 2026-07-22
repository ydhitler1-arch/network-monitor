"""Validation on /api/ports/scan — host required, scan targets restricted to
private/local addresses, and the port-list size/range capped. None of these
cases should trigger an actual socket scan, so they stay fast."""


def test_scan_requires_host(auth_client):
    resp = auth_client.get("/api/ports/scan")
    assert resp.status_code == 400


def test_scan_rejects_public_target(auth_client):
    resp = auth_client.get("/api/ports/scan?host=8.8.8.8")
    assert resp.status_code == 403


def test_scan_rejects_too_many_ports(auth_client):
    ports = ",".join(str(p) for p in range(1, 1030))
    resp = auth_client.get(f"/api/ports/scan?host=127.0.0.1&ports={ports}")
    assert resp.status_code == 400


def test_scan_rejects_out_of_range_port(auth_client):
    resp = auth_client.get("/api/ports/scan?host=127.0.0.1&ports=70000")
    assert resp.status_code == 400


def test_scan_rejects_non_integer_ports(auth_client):
    resp = auth_client.get("/api/ports/scan?host=127.0.0.1&ports=abc")
    assert resp.status_code == 400


def test_scan_route_requires_auth(client):
    resp = client.get("/api/ports/scan?host=127.0.0.1")
    assert resp.status_code == 401
