from pathlib import Path

from app import create_app
from core.endpoint_prober import probe_endpoint
from models.database import Audit, User, db
from werkzeug.security import check_password_hash


def _test_app(tmp_path):
    class TestConfig:
        TESTING = True
        SECRET_KEY = "test-key"
        SQLALCHEMY_DATABASE_URI = f"sqlite:///{tmp_path / 'phase3.db'}"
        SQLALCHEMY_TRACK_MODIFICATIONS = False
        UPLOAD_FOLDER = str(tmp_path / "uploads")
        STORAGE_FOLDER = str(tmp_path / "storage")
        SEVERITY_WEIGHTS = {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 5, "LOW": 2}

    app = create_app(TestConfig)
    with app.app_context():
        db.drop_all()
        db.create_all()
    return app


def test_tc11_endpoint_prober_handles_invalid_url():
    result = probe_endpoint("not-a-url")
    assert result["reachable"] is False
    assert result["latency_ms"] == 0
    assert "offline" in result["notice"].lower()


def test_tc12_demo_login_and_dashboard_render(tmp_path):
    app = _test_app(tmp_path)
    client = app.test_client()
    login_response = client.get("/login")
    assert login_response.status_code == 200
    root_response = client.get("/", follow_redirects=False)
    assert root_response.status_code in {302, 303}
    assert "/login" in (root_response.headers.get("Location") or "")
    response = client.get("/demo-login", follow_redirects=True)
    assert response.status_code == 200
    assert b"Audit dashboard" in response.data


def test_login_page_creates_hashed_user_and_signs_them_in(tmp_path):
    app = _test_app(tmp_path)
    client = app.test_client()

    login_page = client.get("/login")
    assert b'data-auth-mode="login"' in login_page.data
    assert b'data-auth-mode="register"' in login_page.data
    assert b'name="name"' in login_page.data
    assert b'data-signup-action="/signup"' in login_page.data
    signup_page = client.get("/login?mode=register")
    assert b'action="/signup"' in signup_page.data
    assert client.get("/signup").headers["Location"].endswith("/login")
    invalid_signup = client.post("/signup", data={"name": "", "email": "", "password": ""})
    assert invalid_signup.status_code == 200
    assert b"Name, email, and password are required." in invalid_signup.data

    response = client.post("/signup", data={
        "name": "New Analyst",
        "email": "analyst@example.com",
        "password": "secure-password",
    })
    assert response.status_code == 302
    assert response.headers["Location"].endswith("/dashboard")
    assert b"Audit dashboard" in client.get("/dashboard").data

    with app.app_context():
        user = User.query.filter_by(email="analyst@example.com").one()
        assert user.username == "New Analyst"
        assert user.password_hash != "secure-password"
        assert check_password_hash(user.password_hash, "secure-password")

    duplicate = client.post("/signup", data={
        "name": "Another Name",
        "email": "analyst@example.com",
        "password": "another-password",
    }, follow_redirects=True)
    assert duplicate.status_code == 200
    assert b"That email is already registered." in duplicate.data

    client.get("/logout")
    signed_in = client.post("/login", data={
        "action": "login",
        "email": "analyst@example.com",
        "password": "secure-password",
    }, follow_redirects=True)
    assert signed_in.status_code == 200
    assert b"Audit dashboard" in signed_in.data


def test_tc13_sample_medbot_end_to_end(tmp_path):
    app = _test_app(tmp_path)
    client = app.test_client()
    client.get("/demo-login")
    response = client.post("/audit/new", data={
        "project_name": "Sample MedBot",
        "use_sample_medbot": "on",
        "check_ast": "on",
        "check_cve": "on",
        "check_rag": "on",
    }, follow_redirects=True)
    assert response.status_code == 200
    assert b"Security score" in response.data
    with app.app_context():
        audit = Audit.query.one()
        assert audit.risk_score < 100
        tags = {finding.owasp_tag for finding in audit.findings}
        assert "LLM01" in tags
        assert "LLM06" in tags
        assert {"AST", "CVE", "RAG"} <= {finding.category for finding in audit.findings}
        assert audit.findings
        assert "profile" in audit.policy_config_json


def test_tc14_empty_upload_and_invalid_github_are_safe(tmp_path):
    client = _test_app(tmp_path).test_client()
    client.get("/demo-login")
    response = client.post("/audit/new", data={
        "project_name": "Invalid source",
        "github_url": "invalid-url",
        "check_ast": "on",
    }, follow_redirects=True)
    assert response.status_code == 200
    assert b"Invalid GitHub URL" in response.data
