# RASTA-SHIELD Roadmap

## Phase 1: Foundation

**Status: Completed**

Phase 1 established the Flask configuration, database foundation, sample vulnerable target,
PDF test fixture, and initial automated test cases. Later phases will add the security
scanning engine, AI reasoning workflows, report generation, and web interface.

## Phase 2: Jury-Proof Project Ingestor and Offline Analyzers

**Status: IN PROGRESS**

Phase 2 adds safe local/GitHub project ingestion, offline dependency CVE matching,
static AST and secret analysis, and RAG document prompt-injection sanitization.
Malformed files and external inputs produce notices instead of terminating analysis.
