"""
Leadline - API Endpoint Tests
Phase 10: Tests + Docker
"""


def test_root_endpoint(client):
    """Test root endpoint."""
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert "Leadline" in data["name"]


def test_health_check(client):
    """Test health check endpoint."""
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"


def test_list_targets_empty(client):
    """Test listing targets when empty."""
    response = client.get("/api/targets")
    assert response.status_code == 200
    assert isinstance(response.json(), list)


def test_host_allow_list_rejects_unknown_host(client):
    """DNS-rebinding defense: unknown Host headers are rejected."""
    response = client.get("/api/targets", headers={"host": "evil.example"})
    assert response.status_code == 400
    assert response.json()["detail"] == "Host header not allowed"


def test_host_allow_list_accepts_loopback(client):
    response = client.get("/api/targets", headers={"host": "127.0.0.1:8000"})
    assert response.status_code == 200


def test_create_target(client):
    """Test creating a target."""
    target_data = {
        "name": "Test Target",
        "url": "test.local",
        "notes": "Test notes"
    }
    response = client.post("/api/targets", json=target_data)
    assert response.status_code == 201
    data = response.json()
    assert data["name"] == "Test Target"
    assert data["url"] == "test.local"

    # Cleanup
    client.delete(f"/api/targets/{data['id']}")


def test_target_history_starts_empty(client):
    """A new target has a valid, empty timeline."""
    response = client.post("/api/targets", json={
        "name": "History Test",
        "url": "history.local",
    })
    assert response.status_code == 201
    target_id = response.json()["id"]

    history = client.get(f"/api/targets/{target_id}/history")
    assert history.status_code == 200
    data = history.json()
    assert data["target"]["id"] == target_id
    assert data["scans"] == []
    assert data["latest_diff"] is None

    client.delete(f"/api/targets/{target_id}")


def test_create_duplicate_target(client):
    """Test creating duplicate target fails."""
    target_data = {
        "name": "Duplicate Test",
        "url": "duplicate.local"
    }
    # Create first
    response1 = client.post("/api/targets", json=target_data)
    assert response1.status_code == 201

    # Try to create duplicate
    response2 = client.post("/api/targets", json=target_data)
    assert response2.status_code == 400

    # Cleanup
    client.delete(f"/api/targets/{response1.json()['id']}")


def test_get_nonexistent_target(client):
    """Test getting nonexistent target."""
    response = client.get("/api/targets/99999")
    assert response.status_code == 404


def test_list_scans_empty(client):
    """Test listing scans when empty."""
    response = client.get("/api/scans")
    assert response.status_code == 200
    assert isinstance(response.json(), list)
