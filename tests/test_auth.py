def test_unauthenticated_request_rejected(client):
    res = client.get("/api/v1/auth/me")
    assert res.status_code == 401
    assert "Authorization header is required" in res.json()["detail"]


def test_invalid_bearer_token_rejected(client):
    res = client.get("/api/v1/auth/me", headers={"Authorization": "Bearer invalid-secret-token"})
    assert res.status_code == 401
    assert "Invalid credentials" in res.json()["detail"]


def test_malformed_auth_header_rejected(client):
    res = client.get("/api/v1/auth/me", headers={"Authorization": "Basic 12345"})
    assert res.status_code == 401
    assert "Use Bearer token authentication" in res.json()["detail"]


def test_red_team_auth_success(client, red_headers):
    res = client.get("/api/v1/auth/me", headers={**red_headers})
    assert res.status_code == 200
    assert res.json()["role"] == "red"
    assert res.json()["authenticated"] is True


def test_blue_team_auth_success(client, blue_headers):
    res = client.get("/api/v1/auth/me", headers={**blue_headers})
    assert res.status_code == 200
    assert res.json()["role"] == "blue"
    assert res.json()["authenticated"] is True


def test_admin_auth_success(client, admin_headers):
    res = client.get("/api/v1/auth/me", headers={**admin_headers})
    assert res.status_code == 200
    assert res.json()["role"] == "admin"
    assert res.json()["authenticated"] is True


def test_red_team_forbidden_from_admin_endpoints(client, red_headers):
    # Admin users endpoint
    res = client.get("/api/v1/admin/users", headers={**red_headers})
    assert res.status_code == 403
    assert "Access denied" in res.json()["detail"]

    # Admin audit verify endpoint
    res2 = client.get("/api/v1/admin/audit/verify", headers={**red_headers})
    assert res2.status_code == 403

    # Admin sandbox smoke-test
    res3 = client.post("/api/v1/admin/sandbox/smoke-test", headers={**red_headers})
    assert res3.status_code == 403


def test_blue_team_forbidden_from_admin_endpoints(client, blue_headers):
    res = client.get("/api/v1/admin/users", headers={**blue_headers})
    assert res.status_code == 403
    assert "Access denied" in res.json()["detail"]

    res2 = client.get("/api/v1/admin/audit/events", headers={**blue_headers})
    assert res2.status_code == 403
