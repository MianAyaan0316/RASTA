import time
from urllib.parse import urlparse

import requests


OFFLINE_RESULT = {
    "reachable": False,
    "model_detected": "Offline / Static-Only Mode",
    "latency_ms": 0,
    "notice": "Target AI endpoint unreachable; completed offline static, CVE, and RAG audit.",
}


def probe_endpoint(target_url):
    """Probe an Ollama endpoint without allowing network errors to escape."""
    try:
        parsed = urlparse(str(target_url or "").strip())
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            return dict(OFFLINE_RESULT)
        endpoint = str(target_url).rstrip("/") + "/api/tags"
        started = time.perf_counter()
        response = requests.get(endpoint, timeout=4)
        latency_ms = round((time.perf_counter() - started) * 1000)
        response.raise_for_status()
        payload = response.json()
        models = [item.get("name") for item in payload.get("models", []) if item.get("name")]
        return {
            "reachable": True,
            "model_detected": ", ".join(models) or "Ollama (no models reported)",
            "latency_ms": latency_ms,
            "notice": "",
        }
    except (requests.RequestException, ValueError, TypeError):
        return dict(OFFLINE_RESULT)
