import ast
import re
from pathlib import Path


SECRET_PATTERNS = [
    re.compile(r"\bsk-[A-Za-z0-9_-]{10,}"),
    re.compile(r"\bghp_[A-Za-z0-9]{10,}"),
    re.compile(r"\bAIza[A-Za-z0-9_-]{10,}"),
    re.compile(r"\bAPI_KEY\s*=\s*['\"][^'\"]+['\"]", re.IGNORECASE),
]
CONFIG_EXTENSIONS = {".py", ".js", ".ts", ".env", ".json"}


def _finding(title, description, path, line, evidence, tag, fix, remediation, severity="HIGH"):
    return {"category": "AST", "severity": severity, "owasp_tag": tag, "title": title, "description": description,
            "file_path": str(path), "line_number": line, "evidence_snippet": evidence[:500],
            "recommended_fix_code": fix, "remediation": remediation}


def _python_findings(path, text):
    findings = []
    try:
        tree = ast.parse(text)
    except SyntaxError as exc:
        for number, line in enumerate(text.splitlines(), 1):
            if re.search(r"""['"][^'"]*['"]\s*\+\s*[A-Za-z_][A-Za-z0-9_]*""", line):
                findings.append(_finding("Unsafe prompt concatenation", "A likely prompt is built through string concatenation in a file with invalid Python syntax.", path, number, line, "LLM01", "prompt = build_prompt(user_input)", "Repair the syntax, then use structured prompt variables and validate user input."))
        return findings, f"Syntax error in {path.name} at line {exc.lineno or '?'}; used regex fallback."

    lines = text.splitlines()
    def contains_string(node):
        return any(isinstance(item, ast.Constant) and isinstance(item.value, str) for item in ast.walk(node))

    for node in ast.walk(tree):
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            values = [node.left, node.right]
            if any(isinstance(value, (ast.Name, ast.Call, ast.Subscript)) for value in values) and any(contains_string(value) for value in values):
                line = getattr(node, "lineno", 1)
                findings.append(_finding("Unsafe prompt concatenation", "User-controlled data is concatenated into a prompt.", path, line, lines[line - 1] if lines else "", "LLM01", "prompt = build_prompt(user_input)", "Use structured prompt variables and validate user input."))
        if isinstance(node, ast.Call):
            name = ""
            if isinstance(node.func, ast.Name):
                name = node.func.id
            elif isinstance(node.func, ast.Attribute):
                name = f"{getattr(node.func.value, 'id', '')}.{node.func.attr}"
            if name in {"eval", "exec", "os.system", "subprocess.Popen", "pickle.loads"}:
                line = getattr(node, "lineno", 1)
                findings.append(_finding("Dangerous dynamic call", f"Use of {name} can execute untrusted content.", path, line, lines[line - 1] if lines else "", "LLM07", "# Avoid executing untrusted input.", "Remove the call or use a safe, allow-listed alternative.", "CRITICAL"))
    return findings, None


def _secret_findings(path, text):
    findings = []
    for number, line in enumerate(text.splitlines(), 1):
        for pattern in SECRET_PATTERNS:
            if pattern.search(line):
                findings.append(_finding("Hardcoded secret detected", "A likely credential is stored directly in source or configuration.", path, number, line, "LLM06", "API_KEY = os.environ.get('API_KEY')", "Move secrets to environment variables or a secret manager.", "CRITICAL"))
                break
    return findings


def run_static_analysis(project_profile):
    findings, notices = [], []
    file_values = (
        project_profile.get("code_files", [])
        + project_profile.get("dependency_files", [])
        + project_profile.get("env_files", [])
    )
    for file_value in file_values:
        path = Path(file_value)
        if path.suffix.lower() not in CONFIG_EXTENSIONS:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
            if path.suffix.lower() == ".py":
                python_findings, notice = _python_findings(path, text)
                findings.extend(python_findings)
                if notice:
                    notices.append(notice)
            findings.extend(_secret_findings(path, text))
        except (OSError, UnicodeError) as exc:
            notices.append(f"Could not analyze {path}: {exc}")
    return {"findings": findings, "notices": notices}


def analyze_attack_surface(profile):
    """Identify input entry points, AI connections, and unvalidated input-to-prompt flows."""
    entry_points = set()
    ai_connections = set()
    flows = []
    prompt_context = []

    text_by_path = {}
    for file_value in (
        profile.get("code_files", [])
        + profile.get("dependency_files", [])
        + profile.get("env_files", [])
    ):
        path = Path(file_value)
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
            text_by_path[str(path)] = text
        except (OSError, UnicodeError):
            continue

    input_patterns = {
        "Python input()": re.compile(r"\binput\s*\("),
        "Flask request.form": re.compile(r"\brequest\.form\b"),
        "Flask request.json": re.compile(r"\brequest\.json\b"),
        "Flask request.args": re.compile(r"\brequest\.args\b"),
    }
    ai_patterns = {
        "OpenAI": re.compile(r"\b(?:openai|OpenAI)\b"),
        "Ollama": re.compile(r"\b(?:ollama|/api/generate|/api/chat)\b", re.I),
        "LangChain": re.compile(r"\b(?:langchain|LangChain)\b"),
        "ChromaDB": re.compile(r"\b(?:chromadb|Chroma)\b"),
        "FAISS": re.compile(r"\b(?:faiss|FAISS)\b"),
    }

    for path, text in text_by_path.items():
        for label, pattern in input_patterns.items():
            if pattern.search(text):
                entry_points.add(label)
        for label, pattern in ai_patterns.items():
            if pattern.search(text):
                ai_connections.add(label)

        prompt_lines = [
            line for line in text.splitlines()
            if re.search(r"\b(prompt|messages|query)\b", line, re.I)
        ]
        has_input = any(pattern.search(text) for pattern in input_patterns.values())
        has_ai = any(pattern.search(text) for pattern in ai_patterns.values())
        has_concat = bool(re.search(r"(prompt_sent|prompt)\s*=.*(?:\+|format\(|f[\"'])", text))
        if has_input and (has_ai or has_concat):
            flows.append({
                "source": next((label for label, pattern in input_patterns.items() if pattern.search(text)), "User input"),
                "flow": "User input -> AI prompt",
                "target": next((label for label, pattern in ai_patterns.items() if pattern.search(text)), "Prompt builder"),
                "validated": not has_concat,
                "file_path": path,
            })
        if prompt_lines:
            prompt_context.append({"file_path": path, "lines": prompt_lines[:5]})

    return {
        "user_input_entry_points": sorted(entry_points),
        "ai_connections": sorted(ai_connections),
        "unvalidated_data_flows": flows,
        "prompt_context": prompt_context,
        "summary": {
            "entry_point_count": len(entry_points),
            "ai_connection_count": len(ai_connections),
            "unvalidated_flow_count": sum(1 for flow in flows if not flow["validated"]),
        },
    }
