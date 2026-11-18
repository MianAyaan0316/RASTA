import re
from pathlib import Path

from pypdf import PdfReader


INJECTION_PATTERNS = re.compile(r"ignore previous instructions|system override|reveal the admin|disregard safety", re.IGNORECASE)


def run_rag_sanitization(project_profile):
    findings, notices = [], []
    for file_value in project_profile.get("rag_documents", []):
        path = Path(file_value)
        try:
            if path.suffix.lower() == ".pdf":
                reader = PdfReader(str(path))
                if reader.is_encrypted:
                    try:
                        reader.decrypt("")
                    except Exception:
                        notices.append(f"Encrypted PDF could not be decrypted: {path.name}")
                        continue
                text = "\n".join(page.extract_text() or "" for page in reader.pages)
            else:
                text = path.read_text(encoding="utf-8", errors="replace")
            for match in INJECTION_PATTERNS.finditer(text):
                line_number = text[:match.start()].count("\n") + 1
                evidence = text[max(0, match.start() - 40):match.end() + 80].replace("\n", " ")
                findings.append({"category": "RAG", "severity": "HIGH", "owasp_tag": "LLM01",
                                 "title": "Indirect prompt injection detected", "description": "Document content attempts to override model instructions.",
                                 "file_path": str(path), "line_number": line_number, "evidence_snippet": evidence,
                                 "recommended_fix_code": "Filter untrusted document instructions before retrieval.",
                                 "remediation": "Remove or quarantine the instruction and treat document text as untrusted data."})
        except Exception as exc:
            notices.append(f"Could not read document {path.name}: {exc}")
    return {"findings": findings, "notices": notices}
