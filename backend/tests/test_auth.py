import pytest


def test_register_success(client):
    resp = client.post("/api/auth/register", json={
        "email": "user1@example.com",
        "password": "password123",
    })
    assert resp.status_code == 201
    data = resp.json()
    assert data["email"] == "user1@example.com"
    assert data["is_active"] is True
    assert "id" in data


def test_register_duplicate_email(client):
    payload = {"email": "dup@example.com", "password": "password123"}
    client.post("/api/auth/register", json=payload)
    resp = client.post("/api/auth/register", json=payload)
    assert resp.status_code == 400


def test_register_password_too_short(client):
    resp = client.post("/api/auth/register", json={
        "email": "short@example.com",
        "password": "123",
    })
    assert resp.status_code == 422


def test_login_success(client):
    client.post("/api/auth/register", json={
        "email": "login@example.com",
        "password": "password123",
    })
    resp = client.post("/api/auth/login", json={
        "email": "login@example.com",
        "password": "password123",
    })
    assert resp.status_code == 200
    data = resp.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"


def test_login_wrong_password(client):
    client.post("/api/auth/register", json={
        "email": "wrong@example.com",
        "password": "password123",
    })
    resp = client.post("/api/auth/login", json={
        "email": "wrong@example.com",
        "password": "badpassword",
    })
    assert resp.status_code == 401


def test_login_unknown_email(client):
    resp = client.post("/api/auth/login", json={
        "email": "nobody@example.com",
        "password": "password123",
    })
    assert resp.status_code == 401


def test_me_authenticated(client):
    client.post("/api/auth/register", json={
        "email": "me@example.com",
        "password": "password123",
    })
    token = client.post("/api/auth/login", json={
        "email": "me@example.com",
        "password": "password123",
    }).json()["access_token"]

    resp = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    assert resp.json()["email"] == "me@example.com"


def test_me_unauthenticated(client):
    resp = client.get("/api/auth/me")
    assert resp.status_code == 401


def test_me_invalid_token(client):
    resp = client.get("/api/auth/me", headers={"Authorization": "Bearer invalidtoken"})
    assert resp.status_code == 401
