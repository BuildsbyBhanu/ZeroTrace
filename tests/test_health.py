"""Tests for the health check endpoint (Phase 3)."""

import pytest
from fastapi.testclient import TestClient

from zerotrace.main import create_app


def test_health_endpoint_returns_200():
    """Health endpoint should return HTTP 200."""
    app = create_app()
    client = TestClient(app)
    
    response = client.get("/health")
    
    assert response.status_code == 200


def test_health_endpoint_returns_correct_structure():
    """Health endpoint should return status, service, and version."""
    app = create_app()
    client = TestClient(app)
    
    response = client.get("/health")
    data = response.json()
    
    assert "status" in data
    assert "service" in data
    assert "version" in data


def test_health_endpoint_returns_healthy_status():
    """Health endpoint should report 'healthy' status."""
    app = create_app()
    client = TestClient(app)
    
    response = client.get("/health")
    data = response.json()
    
    assert data["status"] == "healthy"


def test_health_endpoint_returns_service_name():
    """Health endpoint should report 'ZeroTrace' as service."""
    app = create_app()
    client = TestClient(app)
    
    response = client.get("/health")
    data = response.json()
    
    assert data["service"] == "ZeroTrace"


def test_health_endpoint_returns_version():
    """Health endpoint should report a version string."""
    app = create_app()
    client = TestClient(app)
    
    response = client.get("/health")
    data = response.json()
    
    assert data["version"] == "0.1.0"


def test_health_endpoint_returns_json():
    """Health endpoint should return JSON content type."""
    app = create_app()
    client = TestClient(app)
    
    response = client.get("/health")
    
    assert "application/json" in response.headers["content-type"]