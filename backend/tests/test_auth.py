"""Authentication and RBAC tests."""


async def test_login_success(client):
    resp = await client.post("/api/auth/login", data={"username": "admin", "password": "admin"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["token_type"] == "bearer"
    assert body["role"] == "admin"


async def test_login_wrong_password(client):
    resp = await client.post("/api/auth/login", data={"username": "admin", "password": "nope"})
    assert resp.status_code == 401


async def test_protected_requires_token(client):
    resp = await client.get("/api/alerts")
    assert resp.status_code == 401


async def test_me_endpoint(client, auth_headers):
    resp = await client.get("/api/auth/me", headers=auth_headers)
    assert resp.status_code == 200
    assert resp.json()["username"] == "admin"


async def test_rbac_viewer_cannot_ingest(client, auth_headers):
    # Admin provisions a viewer.
    r = await client.post("/api/auth/users", headers=auth_headers,
                          json={"username": "view1", "password": "pw", "role": "viewer"})
    assert r.status_code == 201
    login = await client.post("/api/auth/login", data={"username": "view1", "password": "pw"})
    vheaders = {"Authorization": f"Bearer {login.json()['access_token']}"}
    # Viewer may read but not ingest.
    assert (await client.get("/api/alerts", headers=vheaders)).status_code == 200
    ingest = await client.post("/api/events", headers=vheaders,
                               json={"source": "linux", "event_type": "login"})
    assert ingest.status_code == 403
