from datetime import datetime, timezone

from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash


db = SQLAlchemy()


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False, unique=True)
    email = db.Column(db.String(120), nullable=False, unique=True)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    projects = db.relationship("Project", back_populates="user", cascade="all, delete-orphan")

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)


class Project(db.Model):
    __tablename__ = "projects"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    name = db.Column(db.String(120), nullable=False)
    target_url = db.Column(db.String(500))
    source_type = db.Column(db.String(50), nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    user = db.relationship("User", back_populates="projects")
    audits = db.relationship("Audit", back_populates="project", cascade="all, delete-orphan")


class Audit(db.Model):
    __tablename__ = "audits"

    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey("projects.id"), nullable=False)
    policy_config_json = db.Column(db.Text)
    status = db.Column(db.String(50), nullable=False, default="pending")
    risk_score = db.Column(db.Integer, default=0)
    model_detected = db.Column(db.String(120))
    latency_ms = db.Column(db.Integer)
    attack_surface_json = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    project = db.relationship("Project", back_populates="audits")
    findings = db.relationship("Finding", back_populates="audit", cascade="all, delete-orphan")
    attack_logs = db.relationship("AttackLog", back_populates="audit", cascade="all, delete-orphan")


class Finding(db.Model):
    __tablename__ = "findings"

    id = db.Column(db.Integer, primary_key=True)
    audit_id = db.Column(db.Integer, db.ForeignKey("audits.id"), nullable=False)
    category = db.Column(db.String(120))
    severity = db.Column(db.String(20))
    owasp_tag = db.Column(db.String(50))
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    evidence_snippet = db.Column(db.Text)
    recommended_fix_code = db.Column(db.Text)
    remediation = db.Column(db.Text)
    file_path = db.Column(db.String(500))
    line_number = db.Column(db.Integer)

    audit = db.relationship("Audit", back_populates="findings")


class AttackLog(db.Model):
    __tablename__ = "attack_logs"

    id = db.Column(db.Integer, primary_key=True)
    audit_id = db.Column(db.Integer, db.ForeignKey("audits.id"), nullable=False)
    attack_technique = db.Column(db.String(120))
    attempt_number = db.Column(db.Integer)
    prompt_sent = db.Column(db.Text)
    response_received = db.Column(db.Text)
    verdict = db.Column(db.String(50))
    verification_layer = db.Column(db.String(50))
    attack_name = db.Column(db.String(120))
    category = db.Column(db.String(50))
    latency_ms = db.Column(db.Integer)
    remediation = db.Column(db.Text)
    ai_response = db.Column(db.Text)

    audit = db.relationship("Audit", back_populates="attack_logs")
