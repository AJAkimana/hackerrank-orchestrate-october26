# Author: AJAkimana
"""Shared building blocks: file paths, CSV I/O, and the step contract.

Everything that the solver (code/main.py) and the evaluator
(code/evaluation/main.py) must agree on lives here, so the two never drift.
"""

import csv
import json
from pathlib import Path

# Paths are resolved from this file, so the code works from any working
# directory and on any OS.
REPO_ROOT = Path(__file__).resolve().parents[2]
DATASET_DIR = REPO_ROOT / "dataset"
EVIDENCE_DIR = DATASET_DIR / "evidence"
OUTPUT_COLUMNS = ["case_id", "deletion_status", "steps_json"]
STATUSES = ("COMPLETE", "INCOMPLETE", "NOT_APPLICABLE")
PHASES = ("FINDING", "REMEDIATION", "VERIFICATION")

# The allowed operations, in the exact order of the table in
# problem_statement.md. That order is also the sort order inside a phase.
OPERATIONS = [
    ("FINDING", "REPORT_REMAINING_RECORD", "PRESENT"),
    ("FINDING", "REPORT_EXPOSED_PII", "PRESENT"),
    ("FINDING", "REPORT_ACTIVE_DATA_FLOW", "ACTIVE"),
    ("FINDING", "REPORT_RESTORE_RISK", "ACTIVE"),
    ("REMEDIATION", "DISABLE_DATA_FLOW", "DISABLED"),
    ("REMEDIATION", "BLOCK_RESTORE", "BLOCKED"),
    ("REMEDIATION", "DELETE_RECORD", "ABSENT"),
    ("REMEDIATION", "REDACT_RECORD", "REDACTED"),
    ("REMEDIATION", "ANONYMIZE_RECORD", "ANONYMIZED"),
    ("VERIFICATION", "VERIFY_RECORD_ABSENT", "ABSENT"),
    ("VERIFICATION", "VERIFY_RECORD_PRESENT", "PRESENT"),
    ("VERIFICATION", "VERIFY_RECORD_REDACTED", "REDACTED"),
    ("VERIFICATION", "VERIFY_RECORD_ANONYMIZED", "ANONYMIZED"),
    ("VERIFICATION", "VERIFY_DATA_FLOW_DISABLED", "DISABLED"),
    ("VERIFICATION", "VERIFY_RESTORE_BLOCKED", "BLOCKED"),
]
OP_PHASE = {op: phase for phase, op, _ in OPERATIONS}
OP_STATE = {op: state for _, op, state in OPERATIONS}
OP_RANK = {op: i for i, (_, op, _) in enumerate(OPERATIONS)}
STEP_FIELDS = ("step_no", "phase", "system_id", "resource_id", "operation", "state", "evidence_id")


def read_csv(path):
    with open(path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def make_step(system_id, resource_id, operation, evidence_id=""):
    """Build one step; phase and state are implied by the operation."""
    return {
        "phase": OP_PHASE[operation],
        "system_id": system_id,
        "resource_id": resource_id,
        "operation": operation,
        "state": OP_STATE[operation],
        "evidence_id": evidence_id,
    }


def order_steps(steps):
    """Sort by operation-table order (which also orders phases), then
    system_id and resource_id, and number the steps from 1."""
    ordered = sorted(steps, key=lambda s: (OP_RANK[s["operation"]], s["system_id"], s["resource_id"]))
    return [{"step_no": i, **{k: s[k] for k in STEP_FIELDS[1:]}} for i, s in enumerate(ordered, 1)]


def dump_steps(steps):
    # Compact, key-ordered JSON keeps output byte-for-byte deterministic.
    return json.dumps(steps, ensure_ascii=False, separators=(",", ":"))


def case_sort_key(case_id):
    # IDs are not zero-padded (case_33 ... case_550), so sort numerically;
    # a plain string sort would put case_100 before case_33.
    prefix, _, number = case_id.rpartition("_")
    return (prefix, int(number)) if number.isdigit() else (case_id, 0)


def write_output(rows, path):
    """rows: iterable of (case_id, status, steps). Written sorted by case_id."""
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(OUTPUT_COLUMNS)
        for case_id, status, steps in sorted(rows, key=lambda r: case_sort_key(r[0])):
            writer.writerow([case_id, status, dump_steps(steps)])
