# Phase 1 Test Cases

| Test Case ID | Test Scenario | Preconditions | Test Steps | Test Input | Expected Result | Actual Result | Pass/Fail Status |
|---|---|---|---|---|---|---|---|
| TC-01 | Config values load properly | `config.py` exists | Import `Config`; compare every Phase 1 setting | `Config` class | All database, storage, Ollama, attempt, secret, and severity values match expected values | 1 test passed | PASS |
| TC-02 | All 5 SQLite tables are created | Flask and Flask-SQLAlchemy are installed | Create a Flask app, configure an in-memory SQLite database, initialize `db`, and call `db.create_all()` | In-memory SQLite URI | Tables `users`, `projects`, `audits`, `findings`, and `attack_logs` exist | 1 test passed | PASS |
| TC-03 | User -> Project -> Audit -> Finding links properly | In-memory database is initialized | Create and commit linked model records; inspect relationship paths | One user, project, audit, and finding | Foreign keys and relationships connect the records correctly | 1 test passed | PASS |
| TC-04 | Sample target files exist and PDF generates cleanly | `fpdf2` is installed; sample target directory exists | Check all sample files, run the PDF generator, and inspect the output file | MedBot source, dependency list, PDF generator | Required files exist and `clinic_policy.pdf` is created with content | 1 test passed; PDF size is greater than zero | PASS |
