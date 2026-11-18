import os


class Config:
    """Application settings kept together for a simple setup."""

    SECRET_KEY = os.environ.get("RASTA_SECRET_KEY", "dev-secret-key")
    SQLALCHEMY_DATABASE_URI = "sqlite:///rasta_shield.db"
    UPLOAD_FOLDER = "uploaded_projects"
    STORAGE_FOLDER = "storage"
    OLLAMA_DEFAULT_URL = "http://localhost:11434"
    MAX_REASONER_ATTEMPTS = 4
    SEVERITY_WEIGHTS = {
        "CRITICAL": 25,
        "HIGH": 15,
        "MEDIUM": 5,
        "LOW": 2,
    }
