import json
import shutil
import uuid
from pathlib import Path

from flask import Blueprint, current_app, flash, redirect, render_template, request, session, url_for

from core.dependency_cve_scanner import run_dependency_scan
from core.endpoint_prober import probe_endpoint
from core.project_ingestor import ingest_github_repo, ingest_local_files
from core.rag_doc_sanitizer import run_rag_sanitization
from core.red_team_engine import run_ai_attack_tests
from core.static_ast_analyzer import analyze_attack_surface, run_static_analysis
from models.database import AttackLog, Audit, Finding, Project, User, db


web_bp = Blueprint("web", __name__)


def _current_user():
    user_id = session.get("user_id")
    return User.query.get(user_id) if user_id else None


@web_bp.before_request
def require_login():
    if request.endpoint and request.endpoint.startswith("web.") and not session.get("user_id"):
        return redirect(url_for("auth.login"))
    return None


@web_bp.route("/")
def home():
    if not session.get("user_id"):
        return redirect(url_for("auth.login"))
    return redirect(url_for("web.dashboard"))


@web_bp.route("/dashboard")
def dashboard():
    audits = (
        Audit.query.join(Project).filter(Project.user_id == session["user_id"])
        .order_by(Audit.created_at.desc()).all()
    )
    average_score = round(sum(audit.risk_score or 0 for audit in audits) / len(audits)) if audits else 100
    code_library_issues = sum(
        1 for audit in audits for finding in audit.findings
        if finding.category in {"AST", "CVE"}
    )
    blocked_attacks = sum(
        1 for audit in audits for log in audit.attack_logs if log.verdict == "Safe"
    )
    breached_attacks = sum(
        1 for audit in audits for log in audit.attack_logs if log.verdict == "Vulnerable"
    )
    return render_template(
        "dashboard.html",
        audits=audits,
        total_audits=len(audits),
        average_score=average_score,
        code_library_issues=code_library_issues,
        blocked_attacks=blocked_attacks,
        breached_attacks=breached_attacks,
    )


@web_bp.route("/audit/new", methods=["GET", "POST"])
def new_audit():
    if request.method == "GET":
        return render_template("new_audit.html")

    project_name = request.form.get("project_name", "").strip() or "Untitled Project"
    target_url = request.form.get("target_url", "").strip()
    workspace = Path(current_app.config["UPLOAD_FOLDER"]) / uuid.uuid4().hex
    notices = []
    try:
        if request.form.get("use_sample_medbot"):
            profile = ingest_local_files(Path(current_app.root_path) / "sample_targets", workspace)
            source_type = "sample_medbot"
        elif request.form.get("github_url", "").strip():
            profile = ingest_github_repo(request.form.get("github_url", "").strip(), workspace)
            source_type = "github"
        else:
            saved_files = []
            workspace.mkdir(parents=True, exist_ok=True)
            for uploaded in request.files.getlist("files"):
                if uploaded and uploaded.filename:
                    destination = workspace / Path(uploaded.filename).name
                    uploaded.save(destination)
                    saved_files.append(destination)
            profile = ingest_local_files(saved_files, workspace)
            source_type = "upload"
        notices.extend(profile.get("notices", []))
    except Exception as exc:
        profile = {"workspace_path": str(workspace), "detected_languages": [], "detected_frameworks": [],
                   "code_files": [], "dependency_files": [], "rag_documents": [], "env_files": [],
                   "skipped_files_count": 0, "notices": [f"Project ingestion completed with a notice: {exc}"]}
        notices.extend(profile["notices"])

    findings = []
    if request.form.get("check_ast") or request.form.get("check_code"):
        result = run_static_analysis(profile)
        findings.extend(result["findings"])
        notices.extend(result["notices"])
    if request.form.get("check_cve") or request.form.get("check_dependencies"):
        result = run_dependency_scan(profile)
        findings.extend(result["findings"])
        notices.extend(result["notices"])
    if request.form.get("check_rag") or request.form.get("check_documents"):
        result = run_rag_sanitization(profile)
        findings.extend(result["findings"])
        notices.extend(result["notices"])
    probe = probe_endpoint(target_url) if request.form.get("check_probe") else {
        "model_detected": "Not requested", "latency_ms": 0, "notice": ""
    }
    if probe.get("notice"):
        notices.append(probe["notice"])

    attack_surface = analyze_attack_surface(profile)

    selected_attacks = []
    if request.form.get("attack_prompt_injection"):
        selected_attacks.append("prompt_injection")
    if request.form.get("attack_system_leak"):
        selected_attacks.append("system_leak")
    if request.form.get("attack_jailbreak"):
        selected_attacks.append("jailbreak")
    if request.form.get("attack_output_injection"):
        selected_attacks.append("output_injection")

    attack_results = run_ai_attack_tests(target_url, profile, selected_attacks)

    weights = current_app.config["SEVERITY_WEIGHTS"]
    risk_score = max(0, 100 - sum(weights.get(finding.get("severity", ""), 0) for finding in findings))
    project = Project(name=project_name, target_url=target_url, source_type=source_type, user_id=session["user_id"])
    audit = Audit(project=project, policy_config_json=json.dumps({
        "policy": dict(request.form), "profile": profile, "notices": notices,
        "attack_surface": attack_surface, "attack_results": attack_results,
    }), attack_surface_json=json.dumps(attack_surface), status="completed",
                  risk_score=risk_score, model_detected=probe.get("model_detected"), latency_ms=probe.get("latency_ms"))
    db.session.add(audit)
    db.session.flush()
    for item in findings:
        db.session.add(Finding(audit_id=audit.id, category=item.get("category"), severity=item.get("severity"),
                               owasp_tag=item.get("owasp_tag"), title=item.get("title", "Finding"),
                               description=item.get("description"), evidence_snippet=item.get("evidence_snippet"),
                               recommended_fix_code=item.get("recommended_fix_code"),
                               remediation=item.get("remediation"),
                               file_path=item.get("file_path"),
                               line_number=item.get("line_number")))
    for index, item in enumerate(attack_results, 1):
        db.session.add(AttackLog(
            audit=audit,
            attack_name=item["attack_name"],
            attack_technique=item["attack_name"],
            category=item["category"],
            attempt_number=index,
            prompt_sent=item["prompt_sent"],
            response_received=item["ai_response"],
            ai_response=item["ai_response"],
            verdict=item["status"],
            latency_ms=item["latency_ms"],
            verification_layer="live" if target_url else "offline",
            remediation=item["remediation"],
        ))
    db.session.commit()
    audit._profile = profile
    audit._notices = notices
    return redirect(url_for("web.audit_results", audit_id=audit.id))


@web_bp.route("/audit/<int:audit_id>/results")
def audit_results(audit_id):
    audit = Audit.query.join(Project).filter(Audit.id == audit_id, Project.user_id == session["user_id"]).first_or_404()
    stored = {}
    try:
        stored = json.loads(audit.policy_config_json or "{}")
    except (TypeError, ValueError):
        pass
    profile = stored.get("profile", {"detected_languages": [], "detected_frameworks": []})
    notices = stored.get("notices", [])
    attack_surface = stored.get("attack_surface", {})
    attack_results = stored.get("attack_results")
    if attack_results is None:
        attack_results = [{
            "attack_name": log.attack_name or log.attack_technique,
            "category": log.category,
            "prompt_sent": log.prompt_sent,
            "ai_response": log.ai_response or log.response_received,
            "latency_ms": log.latency_ms or 0,
            "status": log.verdict,
            "remediation": log.remediation,
        } for log in audit.attack_logs]
    code_count = sum(1 for finding in audit.findings if finding.category == "AST")
    dependency_count = sum(1 for finding in audit.findings if finding.category == "CVE")
    document_count = sum(1 for finding in audit.findings if finding.category == "RAG")
    attack_count = sum(1 for item in attack_results if item.get("status") == "Vulnerable")
    return render_template(
        "audit_results.html",
        audit=audit,
        profile=profile,
        notices=notices,
        attack_surface=attack_surface,
        attack_results=attack_results,
        risk_counts={"Code": code_count, "Dependency": dependency_count, "Document": document_count, "Live Attack": attack_count},
    )


@web_bp.route("/audit/<int:audit_id>/report")
def audit_report(audit_id):
    audit = Audit.query.join(Project).filter(Audit.id == audit_id, Project.user_id == session["user_id"]).first_or_404()
    stored = {}
    try:
        stored = json.loads(audit.policy_config_json or "{}")
    except (TypeError, ValueError):
        pass
    profile = stored.get("profile", {"detected_languages": [], "detected_frameworks": []})
    attack_surface = stored.get("attack_surface", {})
    attack_results = stored.get("attack_results")
    if attack_results is None:
        attack_results = [{
            "attack_name": log.attack_name or log.attack_technique,
            "category": log.category,
            "prompt_sent": log.prompt_sent,
            "ai_response": log.ai_response or log.response_received,
            "latency_ms": log.latency_ms or 0,
            "status": log.verdict,
            "remediation": log.remediation,
        } for log in audit.attack_logs]
    return render_template(
        "audit_report.html",
        audit=audit,
        profile=profile,
        attack_surface=attack_surface,
        attack_results=attack_results,
        notices=stored.get("notices", []),
    )
