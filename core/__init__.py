"""Core project ingestion and analysis helpers."""

from .project_ingestor import ingest_github_repo, ingest_local_files

__all__ = ["ingest_local_files", "ingest_github_repo"]
