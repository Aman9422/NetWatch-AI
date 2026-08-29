"""Tests for the NetWatch AI API endpoints."""

from fastapi.testclient import TestClient


def test_health_endpoint(client: TestClient) -> None:
    """The health endpoint returns HTTP 200 with a healthy status."""
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    assert response.json() == {"status": "healthy"}


def test_health_endpoint_method_not_allowed(client: TestClient) -> None:
    """POST to the health endpoint is not allowed."""
    response = client.post("/api/v1/health")
    assert response.status_code == 405


def test_invalid_route_returns_404(client: TestClient) -> None:
    """An unknown route returns HTTP 404."""
    response = client.get("/api/v1/does-not-exist")
    assert response.status_code == 404


def test_docs_available(client: TestClient) -> None:
    """Swagger documentation is served at /docs."""
    response = client.get("/docs")
    assert response.status_code == 200


def test_redoc_available(client: TestClient) -> None:
    """ReDoc documentation is served at /redoc."""
    response = client.get("/redoc")
    assert response.status_code == 200
