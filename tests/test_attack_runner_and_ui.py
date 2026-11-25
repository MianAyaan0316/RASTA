from pathlib import Path

from app import create_app
from core.red_team_engine import run_ai_attack_tests
from models.database import AttackLog, Audit, db


def _test_app(tmp_path):
    class TestConfig:
        TESTING = True
        SECRET_KEY = "test-key"
        SQLALCHEMY_DATABASE_URI = f"sqlite:///{tmp_path / 'attack.db'}"
        SQLALCHEMY_TRACK_MODIFICATIONS = False
        UPLOAD_FOLDER = str(tmp_path / "uploads")
        STORAGE_FOLDER = str(tmp_path / "storage")
        SEVERITY_WEIGHTS = {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 5, "LOW": 2}

    app = create_app(TestConfig)
    with app.app_context():
        db.drop_all()
        db.create_all()
    return app


def test_selectable_attacks_run_offline_for_empty_endpoint():
    profile = {
        "code_files": [str(Path(__file__).resolve().parents[1] / "sample_targets" / "medbot_app.py")],
        "rag_documents": [],
        "env_files": [],
    }
    results = run_ai_attack_tests("", profile, [
        "prompt_injection",
        "system_leak",
        "jailbreak",
        "output_injection",
    ])
    assert len(results) == 4
    assert {result["category"] for result in results} == {
        "prompt_injection", "system_leak", "jailbreak", "output_injection",
    }
    assert all(result["status"] in {"Safe", "Vulnerable"} for result in results)
    assert all(result["prompt_sent"] for result in results)


def test_attack_results_persist_and_report_renders(tmp_path):
    app = _test_app(tmp_path)
    client = app.test_client()
    client.get("/demo-login")
    response = client.post("/audit/new", data={
        "project_name": "Live Attack Workspace",
        "use_sample_medbot": "on",
        "check_code": "on",
        "attack_prompt_injection": "on",
        "attack_system_leak": "on",
        "target_url": "",
    }, follow_redirects=True)
    assert response.status_code == 200

    with app.app_context():
        audit = Audit.query.one()
        assert audit.attack_surface_json
        logs = AttackLog.query.filter_by(audit_id=audit.id).all()
        assert len(logs) == 2
        assert {log.category for log in logs} == {"prompt_injection", "system_leak"}
        assert all(log.verdict in {"Safe", "Vulnerable"} for log in logs)
        audit_id = audit.id

    results = client.get(f"/audit/{audit_id}/results")
    report = client.get(f"/audit/{audit_id}/report")
    assert results.status_code == 200
    assert report.status_code == 200
    assert b"Security Audit Report" in report.data
    assert b"Print / Save as PDF" in report.data
