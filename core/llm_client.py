"""Small LLM connectivity facade used by the web audit flow."""

from .endpoint_prober import probe_endpoint

__all__ = ["probe_endpoint"]
