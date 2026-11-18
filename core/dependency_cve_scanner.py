import json
import re
from pathlib import Path


def _version_tuple(value):
    match = re.search(r"(\d+)(?:\.(\d+))?(?:\.(\d+))?", value or "")
    return tuple(int(part or 0) for part in match.groups()) if match else None


def _is_affected(version, rule):
    actual = _version_tuple(version)
    target = _version_tuple(rule)
    if not actual or not target:
        return False
    if rule.startswith("<"):
        return actual < target
    if rule.startswith("=="):
        return actual == target
    return False


def _finding(package, version, vulnerability, path):
    return {"category": "CVE", "severity": vulnerability["severity"], "owasp_tag": vulnerability["owasp_tag"],
            "title": f"{vulnerability['cve_id']} affects {package}", "description": vulnerability["description"],
            "file_path": str(path), "line_number": 1, "evidence_snippet": f"{package} {version}",
            "recommended_fix_code": f"{package}>=latest-safe-version", "remediation": "Upgrade the dependency to a patched version."}


def run_dependency_scan(project_profile):
    findings, notices = [], []
    database_path = Path(__file__).resolve().parents[1] / "storage" / "cve_database.json"
    try:
        database = json.loads(database_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return {"findings": [], "notices": [f"Could not load offline CVE database: {exc}"]}

    for file_value in project_profile.get("dependency_files", []):
        path = Path(file_value)
        try:
            if path.name == "package.json":
                dependencies = json.loads(path.read_text(encoding="utf-8"))
                packages = {**dependencies.get("dependencies", {}), **dependencies.get("devDependencies", {})}
                ecosystem = "npm"
            elif path.name == "requirements.txt":
                packages, ecosystem = {}, "python"
                for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
                    match = re.match(r"\s*([A-Za-z0-9_.-]+)\s*(?:==|>=|<=|~=|>|<)?\s*v?(\d+(?:\.\d+){0,2})", line)
                    if match:
                        packages[match.group(1).lower()] = match.group(2)
            else:
                continue
            for package, version_spec in packages.items():
                version = str(version_spec).lstrip("^~>=< ")
                for vulnerability in database.get(ecosystem, {}).get(package.lower(), []):
                    if _is_affected(version, vulnerability["affected_versions"]):
                        findings.append(_finding(package, version, vulnerability, path))
        except (OSError, UnicodeError, json.JSONDecodeError, AttributeError) as exc:
            notices.append(f"Could not parse dependency file {path.name}: {exc}")
    return {"findings": findings, "notices": notices}
