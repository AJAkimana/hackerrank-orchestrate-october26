# Author: AJAkimana
"""Turn resource states into the ordered steps and a case status.

Each (treatment, status) pair maps to at most one finding, one remediation
and one verification:

    treatment  status       finding                  remediation        verification
    DELETE     EXPOSED      REPORT_REMAINING_RECORD  DELETE_RECORD      VERIFY_RECORD_ABSENT
    DELETE     ABSENT       -                        -                  VERIFY_RECORD_ABSENT
    REDACT     EXPOSED      REPORT_EXPOSED_PII       REDACT_RECORD      VERIFY_RECORD_REDACTED
    REDACT     CLEAN        -                        -                  VERIFY_RECORD_REDACTED
    ANONYMIZE  EXPOSED      REPORT_EXPOSED_PII       ANONYMIZE_RECORD   VERIFY_RECORD_ANONYMIZED
    ANONYMIZE  CLEAN        -                        -                  VERIFY_RECORD_ANONYMIZED
    RETAIN     PRESENT      -                        -                  VERIFY_RECORD_PRESENT
    FLOW       ACTIVE       REPORT_ACTIVE_DATA_FLOW  DISABLE_DATA_FLOW  VERIFY_DATA_FLOW_DISABLED
    FLOW       DISABLED     -                        -                  VERIFY_DATA_FLOW_DISABLED
    BACKUP     RESTORABLE   REPORT_RESTORE_RISK      BLOCK_RESTORE      VERIFY_RESTORE_BLOCKED
    BACKUP     BLOCKED      -                        -                  VERIFY_RESTORE_BLOCKED

A resource whose state is UNKNOWN (no visible evidence) gets no steps: a
step must be backed by evidence, and guessing would add false findings.

Status: any finding -> INCOMPLETE, otherwise COMPLETE. Evidence ids:
findings cite the proving file; verification cites it only for COMPLETE
cases, because for INCOMPLETE ones it is a check to run after the fix.
order_steps() applies the official order (phase, operation, system, resource),
which also puts disabling flows and blocking restores before record changes.
"""

from .common import make_step, order_steps

PLAN = {
    ("DELETE", "EXPOSED"): ("REPORT_REMAINING_RECORD", "DELETE_RECORD", "VERIFY_RECORD_ABSENT"),
    ("DELETE", "ABSENT"): (None, None, "VERIFY_RECORD_ABSENT"),
    ("REDACT", "EXPOSED"): ("REPORT_EXPOSED_PII", "REDACT_RECORD", "VERIFY_RECORD_REDACTED"),
    ("REDACT", "CLEAN"): (None, None, "VERIFY_RECORD_REDACTED"),
    ("ANONYMIZE", "EXPOSED"): ("REPORT_EXPOSED_PII", "ANONYMIZE_RECORD", "VERIFY_RECORD_ANONYMIZED"),
    ("ANONYMIZE", "CLEAN"): (None, None, "VERIFY_RECORD_ANONYMIZED"),
    ("RETAIN", "PRESENT"): (None, None, "VERIFY_RECORD_PRESENT"),
    ("FLOW", "ACTIVE"): ("REPORT_ACTIVE_DATA_FLOW", "DISABLE_DATA_FLOW", "VERIFY_DATA_FLOW_DISABLED"),
    ("FLOW", "DISABLED"): (None, None, "VERIFY_DATA_FLOW_DISABLED"),
    ("BACKUP", "RESTORABLE"): ("REPORT_RESTORE_RISK", "BLOCK_RESTORE", "VERIFY_RESTORE_BLOCKED"),
    ("BACKUP", "BLOCKED"): (None, None, "VERIFY_RESTORE_BLOCKED"),
}


def build_steps(states):
    """states: {resource_id: state dict} -> (deletion_status, ordered steps)."""
    findings, remediation, checks = [], [], []
    for state in states.values():
        plan = PLAN.get((state["treatment"], state["status"]))
        if plan is None:
            continue
        finding, fix, verify = plan
        system, resource = state["system_id"], state["resource_id"]
        if finding:
            findings.append(make_step(system, resource,
                            finding, state["evidence_id"]))
            remediation.append(make_step(system, resource, fix))
        checks.append((system, resource, verify, state["evidence_id"]))

    status = "INCOMPLETE" if findings else "COMPLETE"
    verification = [make_step(system, resource, op, evidence if status == "COMPLETE" else "")
                    for system, resource, op, evidence in checks]
    return status, order_steps(findings + remediation + verification)
