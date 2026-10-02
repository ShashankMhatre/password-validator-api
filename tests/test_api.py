from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)


def test_health() -> None:
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_policy() -> None:
    response = client.get("/policy")
    assert response.status_code == 200
    body = response.json()
    assert body["min_length"] == 12
    assert body["require_uppercase"] is True
    assert body["require_symbol"] is True


def test_strong_password_is_valid() -> None:
    response = client.post(
        "/validate",
        json={
            "password": "Nebula!River7Quartz",
            "username": "demo-user",
            "email": "demo@example.com",
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["valid"] is True
    assert body["score"] == 4
    assert body["strength"] == "very_strong"
    assert body["violations"] == []


def test_weak_password_returns_feedback() -> None:
    response = client.post("/validate", json={"password": "password1"})
    assert response.status_code == 200
    body = response.json()
    assert body["valid"] is False
    assert body["score"] <= 2
    assert len(body["violations"]) > 0
    assert len(body["suggestions"]) > 0


def test_identity_term_is_rejected() -> None:
    response = client.post(
        "/validate",
        json={
            "password": "Shashank!Secure2026",
            "username": "Shashank",
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["valid"] is False
    assert any("account-specific" in item for item in body["violations"])


def test_password_is_not_echoed_in_response() -> None:
    secret = "Nebula!River7Quartz"
    response = client.post("/validate", json={"password": secret})
    assert response.status_code == 200
    assert secret not in response.text
