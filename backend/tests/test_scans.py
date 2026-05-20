from unittest.mock import patch


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _register_and_login(client, email="scan_user@example.com", password="password123"):
    client.post("/api/auth/register", json={"email": email, "password": password})
    resp = client.post("/api/auth/login", json={"email": email, "password": password})
    return resp.json()["access_token"]


def _auth(token):
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------------------
# POST /api/scans
# ---------------------------------------------------------------------------

def test_create_scan_ip(client):
    token = _register_and_login(client, "create_ip@example.com")
    with patch("app.workers.scan_tasks.run_scan.delay"):
        resp = client.post("/api/scans", json={"target": "8.8.8.8"}, headers=_auth(token))
    assert resp.status_code == 201
    data = resp.json()
    assert data["target"] == "8.8.8.8"
    assert data["status"] == "pending"
    assert data["progress"] == 0


def test_create_scan_domain(client):
    token = _register_and_login(client, "create_domain@example.com")
    with patch("app.workers.scan_tasks.run_scan.delay"):
        resp = client.post("/api/scans", json={"target": "example.com"}, headers=_auth(token))
    assert resp.status_code == 201


def test_create_scan_invalid_target(client):
    token = _register_and_login(client, "invalid_target@example.com")
    resp = client.post("/api/scans", json={"target": "not a valid target!!"}, headers=_auth(token))
    assert resp.status_code == 422


def test_create_scan_unauthenticated(client):
    resp = client.post("/api/scans", json={"target": "8.8.8.8"})
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# GET /api/scans
# ---------------------------------------------------------------------------

def test_list_scans(client):
    token = _register_and_login(client, "list_scans@example.com")
    resp = client.get("/api/scans", headers=_auth(token))
    assert resp.status_code == 200
    data = resp.json()
    assert "total" in data
    assert "items" in data


def test_list_scans_unauthenticated(client):
    resp = client.get("/api/scans")
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# GET /api/scans/{id}
# ---------------------------------------------------------------------------

def test_get_scan_not_found(client):
    token = _register_and_login(client, "get_notfound@example.com")
    import uuid
    resp = client.get(f"/api/scans/{uuid.uuid4()}", headers=_auth(token))
    assert resp.status_code == 404


def test_get_scan_invalid_id(client):
    token = _register_and_login(client, "get_invalid@example.com")
    resp = client.get("/api/scans/not-a-uuid", headers=_auth(token))
    assert resp.status_code == 400


def test_get_scan_exists(client):
    token = _register_and_login(client, "get_exists@example.com")
    with patch("app.workers.scan_tasks.run_scan.delay"):
        create_resp = client.post("/api/scans", json={"target": "1.1.1.1"}, headers=_auth(token))
    scan_id = create_resp.json()["id"]
    resp = client.get(f"/api/scans/{scan_id}", headers=_auth(token))
    assert resp.status_code == 200
    assert resp.json()["id"] == scan_id


# ---------------------------------------------------------------------------
# DELETE /api/scans/{id}
# ---------------------------------------------------------------------------

def test_delete_scan(client):
    token = _register_and_login(client, "delete_scan@example.com")
    with patch("app.workers.scan_tasks.run_scan.delay"):
        create_resp = client.post("/api/scans", json={"target": "2.2.2.2"}, headers=_auth(token))
    scan_id = create_resp.json()["id"]
    resp = client.delete(f"/api/scans/{scan_id}", headers=_auth(token))
    assert resp.status_code == 204
    # Verify it's gone
    get_resp = client.get(f"/api/scans/{scan_id}", headers=_auth(token))
    assert get_resp.status_code == 404
