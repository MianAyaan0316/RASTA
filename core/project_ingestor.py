import os
import re
import shutil
import subprocess
from pathlib import Path
from urllib.parse import urlparse


IGNORED_DIRECTORIES = {".git", "node_modules", "venv", "__pycache__"}
MAX_FILE_SIZE = 5 * 1024 * 1024
CODE_EXTENSIONS = {".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".go", ".rb", ".php"}
DEPENDENCY_NAMES = {"requirements.txt", "package.json", "pyproject.toml", "poetry.lock", "package-lock.json"}
RAG_EXTENSIONS = {".pdf", ".txt", ".md"}
LANGUAGE_BY_EXTENSION = {".py": "Python", ".js": "JavaScript", ".jsx": "JavaScript", ".ts": "TypeScript", ".tsx": "TypeScript", ".java": "Java", ".go": "Go", ".rb": "Ruby", ".php": "PHP"}


def _empty_profile(workspace):
    return {
        "workspace_path": str(Path(workspace).resolve()),
        "detected_languages": [],
        "detected_frameworks": [],
        "code_files": [],
        "dependency_files": [],
        "rag_documents": [],
        "env_files": [],
        "skipped_files_count": 0,
        "notices": [],
    }


def _add_notice(profile, message):
    profile["notices"].append(message)


def _record_file(profile, path):
    suffix = path.suffix.lower()
    path_string = str(path)
    if suffix in CODE_EXTENSIONS:
        profile["code_files"].append(path_string)
        language = LANGUAGE_BY_EXTENSION.get(suffix)
        if language and language not in profile["detected_languages"]:
            profile["detected_languages"].append(language)
    if path.name.lower() in DEPENDENCY_NAMES:
        profile["dependency_files"].append(path_string)
    if suffix in RAG_EXTENSIONS:
        profile["rag_documents"].append(path_string)
    if path.name == ".env" or path.name.startswith(".env."):
        profile["env_files"].append(path_string)
    if suffix == ".py":
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
            if re.search(r"\b(?:from|import)\s+flask\b", text, re.IGNORECASE) and "Flask" not in profile["detected_frameworks"]:
                profile["detected_frameworks"].append("Flask")
        except OSError:
            pass
    if path.name == "package.json":
        try:
            text = path.read_text(encoding="utf-8", errors="ignore").lower()
            if '"express"' in text and "Express" not in profile["detected_frameworks"]:
                profile["detected_frameworks"].append("Express")
        except OSError:
            pass


def _walk_and_record(profile, root):
    try:
        for current, directories, filenames in os.walk(root):
            directories[:] = [name for name in directories if name not in IGNORED_DIRECTORIES]
            for filename in filenames:
                path = Path(current) / filename
                try:
                    if path.stat().st_size > MAX_FILE_SIZE:
                        profile["skipped_files_count"] += 1
                        _add_notice(profile, f"Skipped file larger than 5 MB: {path.name}")
                        continue
                    _record_file(profile, path)
                except OSError as exc:
                    profile["skipped_files_count"] += 1
                    _add_notice(profile, f"Could not inspect {path.name}: {exc}")
    except OSError as exc:
        _add_notice(profile, f"Could not walk project directory: {exc}")


def ingest_local_files(file_paths_or_dir, workspace_dir):
    profile = _empty_profile(workspace_dir)
    destination = Path(workspace_dir)
    try:
        destination.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        _add_notice(profile, f"Could not create workspace directory: {exc}")
        return profile

    sources = [file_paths_or_dir] if isinstance(file_paths_or_dir, (str, Path)) else list(file_paths_or_dir or [])
    for source_value in sources:
        source = Path(source_value)
        try:
            if not source.exists():
                _add_notice(profile, f"Source does not exist: {source}")
                continue
            target = destination / source.name
            if source.is_dir():
                shutil.copytree(source, target, dirs_exist_ok=True, ignore=shutil.ignore_patterns(*IGNORED_DIRECTORIES))
                _walk_and_record(profile, target)
            elif source.stat().st_size <= MAX_FILE_SIZE:
                if source.resolve() != target.resolve():
                    shutil.copy2(source, target)
                _record_file(profile, target)
            else:
                profile["skipped_files_count"] += 1
                _add_notice(profile, f"Skipped file larger than 5 MB: {source.name}")
        except (OSError, shutil.Error) as exc:
            _add_notice(profile, f"Could not ingest {source}: {exc}")
    return profile


def ingest_github_repo(github_url, workspace_dir):
    profile = _empty_profile(workspace_dir)
    parsed = urlparse(str(github_url or ""))
    if parsed.scheme != "https" or parsed.netloc.lower() != "github.com" or not re.fullmatch(r"/[^/]+/[^/]+/?", parsed.path):
        _add_notice(profile, "Invalid GitHub URL. Use an https://github.com/owner/repository URL.")
        return profile
    destination = Path(workspace_dir)
    try:
        destination.mkdir(parents=True, exist_ok=True)
        result = subprocess.run(
            ["git", "clone", "--depth", "1", str(github_url), str(destination)],
            capture_output=True, text=True, timeout=20, check=False,
        )
        if result.returncode != 0:
            _add_notice(profile, f"GitHub clone failed: {(result.stderr or 'unknown error').strip()}")
            return profile
        _walk_and_record(profile, destination)
    except subprocess.TimeoutExpired:
        _add_notice(profile, "GitHub clone timed out after 20 seconds.")
    except (OSError, subprocess.SubprocessError) as exc:
        _add_notice(profile, f"Could not clone GitHub repository: {exc}")
    return profile
