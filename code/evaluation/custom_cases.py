# Author: AJAkimana
"""Custom evaluation cases written by the team (not taken from the dataset).

Usage (from the repository root):
    python3 code/evaluation/custom_cases.py

Each case builds a small, hand-made scenario (synthetic people, records and
snapshots), runs the real audit modules on it, and compares the result with
the answer we derived by hand from problem_statement.md. The cases target
rules the 32 public samples exercise weakly or not at all.

    C1  ghost copy in a failover replica after a "successful" deletion
    C2  evidence captured after audit_at must not change the answer
    C3  account tombstone: user_id may stay, direct identifiers may not
    C4  active sync + restorable backup: disable/block before deleting
    C5  request made with a historical email (identity resolution)
    C6  non-deletion requests in several phrasings -> NOT_APPLICABLE
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from audit.evidence import make_record  # noqa: E402
from audit.identity import IdentityIndex, email_hash  # noqa: E402
from audit.intent import classify  # noqa: E402
from audit.state import StateResolver  # noqa: E402
from audit.steps import build_steps  # noqa: E402

AUDIT_AT = "2026-10-10T12:00:00Z"
SUBJECT = {"user_id": "user_900", "identifiers": ["zuri.test@example.org", "user_900"]}


def rec(file_id, captured_at, resource, fields, source="sql", container="t"):
    return make_record(file_id, captured_at, resource, fields, source, container)


def link(resource, records, events=()):
    return {"resource_id": resource, "system_id": records[0]["system_id"] if records else None,
            "reasons": ["identifier"], "records": list(records), "events": list(events)}


def run(links, manifest=()):
    """Resolve states for a synthetic request and build its steps."""
    request = {"audit_at": AUDIT_AT}
    states = StateResolver(list(manifest)).resolve(request, SUBJECT, links)
    return build_steps(states)


def brief(steps):
    return [(s["phase"][:5], s["resource_id"], s["operation"], s["evidence_id"]) for s in steps]


# ------------------------------------------------------------------ cases

def case_ghost_replica():
    """Primary says the account is gone (404) but the failover replica,
    captured later, still has the full profile -> INCOMPLETE."""
    primary = rec("ev_A", "2026-10-01T09:00:00Z", "account_900",
                  {"resource_id": "account_900", "status_code": 404, "profile": None}, source="json")
    replica = rec("ev_B", "2026-10-02T09:00:00Z", "account_900",
                  {"resource_id": "account_900", "user_id": "user_900", "full_name": "Zuri Test",
                   "email": "zuri.test@example.org", "account_status": "ACTIVE"},
                  container="customer_profiles_failover_replica")
    status, steps = run({"account_900": link("account_900", [primary, replica])})
    return status, brief(steps), ("INCOMPLETE", [
        ("FINDI", "account_900", "REPORT_REMAINING_RECORD", "ev_B"),
        ("REMED", "account_900", "DELETE_RECORD", ""),
        ("VERIF", "account_900", "VERIFY_RECORD_ABSENT", "")])


def case_future_evidence_ignored():
    """A record reappears in a file captured AFTER audit_at. At audit time
    the latest visible evidence says it was absent -> COMPLETE, citing it."""
    before = rec("ev_C", "2026-10-05T09:00:00Z", "search_900",
                 {"resource_id": "search_900", "hits": {"total": 0, "documents": []}}, source="json")
    after = rec("ev_D", "2026-10-20T09:00:00Z", "search_900",
                {"resource_id": "search_900", "email": "zuri.test@example.org"})
    status, steps = run({"search_900": link("search_900", [before, after])})
    return status, brief(steps), ("COMPLETE", [
        ("VERIF", "search_900", "VERIFY_RECORD_ABSENT", "ev_C")])


def case_tombstone():
    """Tombstone keeps subject_reference (allowed) but still shows the
    email (forbidden) -> REDACT. A clean tombstone only needs verification."""
    dirty = rec("ev_E", "2026-10-03T09:00:00Z", "tombstone_900",
                {"resource_id": "tombstone_900", "subject_reference": "user_900",
                 "name": None, "email": "zuri.test@example.org", "phone": None,
                 "email_hash": None, "account_status": "DELETED"}, source="json")
    clean = rec("ev_F", "2026-10-03T09:00:00Z", "tombstone_901",
                {"resource_id": "tombstone_901", "subject_reference": "user_901",
                 "name": None, "email": None, "phone": None, "email_hash": None,
                 "account_status": "DELETED"}, source="json")
    status, steps = run({"tombstone_900": link("tombstone_900", [dirty]),
                         "tombstone_901": link("tombstone_901", [clean])})
    return status, brief(steps), ("INCOMPLETE", [
        ("FINDI", "tombstone_900", "REPORT_EXPOSED_PII", "ev_E"),
        ("REMED", "tombstone_900", "REDACT_RECORD", ""),
        ("VERIF", "tombstone_900", "VERIFY_RECORD_REDACTED", ""),
        ("VERIF", "tombstone_901", "VERIFY_RECORD_REDACTED", "")])


def case_flow_and_backup_order():
    """An enabled connector and a restorable backup can recreate a search
    entry that still exists. Remediation must disable the flow and block the
    restore before deleting the record; the retained audit record stays."""
    flow = rec("ev_G", "2026-10-04T09:00:00Z", "data_flow_900",
               {"resource_id": "data_flow_900", "customer_email": "zuri.test@example.org",
                "enabled": 1, "last_delivery_status": "delivered"})
    backup = rec("ev_G", "2026-10-04T09:00:00Z", "backup_900",
                 {"resource_id": "backup_900", "customer_reference": "user_900", "restore_allowed": 1})
    search = rec("ev_G", "2026-10-04T09:00:00Z", "search_900",
                 {"resource_id": "search_900", "email": "zuri.test@example.org"})
    audit = rec("ev_G", "2026-10-04T09:00:00Z", "audit_record_900",
                {"resource_id": "audit_record_900", "subject_reference": "user_900",
                 "event_code": "ACCOUNT_DELETION_RECORDED"})
    links = {r["resource_id"]: link(r["resource_id"], [r]) for r in (search, flow, audit, backup)}
    status, steps = run(links)
    return status, brief(steps), ("INCOMPLETE", [
        ("FINDI", "search_900", "REPORT_REMAINING_RECORD", "ev_G"),
        ("FINDI", "data_flow_900", "REPORT_ACTIVE_DATA_FLOW", "ev_G"),
        ("FINDI", "backup_900", "REPORT_RESTORE_RISK", "ev_G"),
        ("REMED", "data_flow_900", "DISABLE_DATA_FLOW", ""),
        ("REMED", "backup_900", "BLOCK_RESTORE", ""),
        ("REMED", "search_900", "DELETE_RECORD", ""),
        ("VERIF", "search_900", "VERIFY_RECORD_ABSENT", ""),
        ("VERIF", "audit_record_900", "VERIFY_RECORD_PRESENT", ""),
        ("VERIF", "data_flow_900", "VERIFY_DATA_FLOW_DISABLED", ""),
        ("VERIF", "backup_900", "VERIFY_RESTORE_BLOCKED", "")])


def case_historical_email():
    """Request sent from an email the user changed twice. All three emails
    and their hashes must be recovered, and the match must say historical."""
    identities = [{"user_id": "user_900", "name": "Zuri Test", "email": "z.test@example.org",
                   "phone": "+254 700 000 900", "email_hash": email_hash("z.test@example.org"),
                   "updated_at": "2026-05-01T00:00:00Z"}]
    history = [
        {"audit_id": "audit_A", "user_id": "user_900", "event_time": "2025-01-01T00:00:00Z",
         "field_name": "email", "old_value": "zuri.old@example.org", "new_value": "zuri.mid@example.org"},
        {"audit_id": "audit_B", "user_id": "user_900", "event_time": "2026-01-01T00:00:00Z",
         "field_name": "email", "old_value": "zuri.mid@example.org", "new_value": "z.test@example.org"}]
    subject = IdentityIndex(identities, history).resolve("  Zuri.OLD@example.org ")
    got = (subject["user_id"], subject["matched_via"], subject["emails"],
           email_hash("zuri.old@example.org") in subject["email_hashes"])
    want = ("user_900", "historical",
            ["z.test@example.org", "zuri.mid@example.org", "zuri.old@example.org"], True)
    return "n/a", got, ("n/a", want)


def case_intent():
    """Deletion vs non-deletion wording, including the traps."""
    texts = [
        ("Please delete my account. You may keep anonymous statistics.", True),
        ("Please remove me from marketing lists only.", False),
        ("Do not close the account, I only need a password reset.", False),
        ("Bitte löschen Sie mein Konto und alle Daten.", True),
        ("Could you confirm my profile is gone and nothing can identify me?", True),
        ("I want a copy of my data. Please don't delete anything.", False),
        ("Hello, what are your opening hours?", False),
    ]
    got = [classify(t)[0] for t, _ in texts]
    return "n/a", got, ("n/a", [want for _, want in texts])


CASES = [
    ("C1", "Ghost copy in failover replica", case_ghost_replica),
    ("C2", "Evidence after audit_at is ignored", case_future_evidence_ignored),
    ("C3", "Account tombstone redaction", case_tombstone),
    ("C4", "Flow/backup remediation order", case_flow_and_backup_order),
    ("C5", "Historical email identity", case_historical_email),
    ("C6", "Deletion intent (7 phrasings)", case_intent),
]


def main():
    passed = 0
    for code, title, fn in CASES:
        status, got, (want_status, want) = fn()
        ok = status == want_status and got == want
        passed += ok
        print(f"{'PASS' if ok else 'FAIL'}  {code}  {title}")
        if not ok:
            print(f"      got  {status} {got}\n      want {want_status} {want}")
    print(f"\n{passed}/{len(CASES)} custom cases passed")
    return 0 if passed == len(CASES) else 1


if __name__ == "__main__":
    sys.exit(main())
