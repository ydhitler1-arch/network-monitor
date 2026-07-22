"""Session-based login gates every /api/* route except the auth routes
themselves — verifies the before_request guard in backend/app.py."""


def test_status_reachable_without_a_session(client):
    resp = client.get("/api/auth/status")
    assert resp.status_code == 200
    assert resp.get_json() == {"authenticated": False}


def test_protected_route_without_session_is_rejected(client):
    resp = client.get("/api/health")
    assert resp.status_code == 401


def test_login_with_wrong_password_is_rejected(client):
    resp = client.post("/api/auth/login", json={"username": "testuser", "password": "wrong"})
    assert resp.status_code == 401


def test_login_success_grants_access(auth_client):
    resp = auth_client.get("/api/health")
    assert resp.status_code == 200
    assert auth_client.get("/api/auth/status").get_json() == {"authenticated": True}


def test_logout_revokes_access(auth_client):
    auth_client.post("/api/auth/logout")
    resp = auth_client.get("/api/health")
    assert resp.status_code == 401
