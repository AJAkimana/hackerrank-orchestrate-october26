# Author: AJAkimana
"""Measure (state at audit time) against the sample answers.

Usage (from the repository root):
    python3 code/evaluation/state_check.py [--case case_05] [--quiet]

Each gold step implies, for its resource:
    treatment  from the verification operation (ABSENT -> DELETE, ...)
    status     from the finding if there is one (REMAINING -> EXPOSED, ...),
               otherwise from the verification (already compliant)
    evidence   the file cited by the finding, or by a COMPLETE verification
Only resources the linker found are compared; missing links are Phase 3's.
"""

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from audit.common import DATASET_DIR, read_csv  # noqa: E402
from audit.evidence import load_evidence  # noqa: E402
from audit.identity import IdentityIndex  # noqa: E402
from audit.linking import Linker  # noqa: E402
from audit.state import StateResolver  # noqa: E402

VERIFY_TREATMENT = {
    "VERIFY_RECORD_ABSENT": "DELETE", "VERIFY_RECORD_PRESENT": "RETAIN",
    "VERIFY_RECORD_REDACTED": "REDACT", "VERIFY_RECORD_ANONYMIZED": "ANONYMIZE",
    "VERIFY_DATA_FLOW_DISABLED": "FLOW", "VERIFY_RESTORE_BLOCKED": "BACKUP"}
VERIFY_STATUS = {
    "VERIFY_RECORD_ABSENT": "ABSENT", "VERIFY_RECORD_PRESENT": "PRESENT",
    "VERIFY_RECORD_REDACTED": "CLEAN", "VERIFY_RECORD_ANONYMIZED": "CLEAN",
    "VERIFY_DATA_FLOW_DISABLED": "DISABLED", "VERIFY_RESTORE_BLOCKED": "BLOCKED"}
FINDING_STATUS = {
    "REPORT_REMAINING_RECORD": "EXPOSED", "REPORT_EXPOSED_PII": "EXPOSED",
    "REPORT_ACTIVE_DATA_FLOW": "ACTIVE", "REPORT_RESTORE_RISK": "RESTORABLE"}


def expected(steps, status):
    out = {}
    for s in steps:
        e = out.setdefault(s["resource_id"], {"evidence": ""})
        if s["phase"] == "VERIFICATION":
            e["treatment"] = VERIFY_TREATMENT[s["operation"]]
            e.setdefault("status", VERIFY_STATUS[s["operation"]])
            if status == "COMPLETE":
                e["evidence"] = s["evidence_id"]
        elif s["phase"] == "FINDING":
            e["status"] = FINDING_STATUS[s["operation"]]
            e["evidence"] = s["evidence_id"]
    return out


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--case")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args(argv)

    records, manifest = load_evidence()
    index = IdentityIndex()
    linker = Linker(records, index)
    resolver = StateResolver(manifest)
    samples = read_csv(DATASET_DIR / "sample_deletion_requests.csv")
    everything = samples + read_csv(DATASET_DIR / "deletion_requests.csv")
    subjects = {r["case_id"]: index.resolve(r["email"]) for r in everything}
    all_links = linker.link_all(everything, subjects)
    gold = {row["case_id"]: expected(json.loads(row["steps_json"]), row["deletion_status"])
            for row in read_csv(DATASET_DIR / "sample_output.csv")}

    hits, total, wrong = Counter(), 0, Counter()
    for request in samples:
        case = request["case_id"]
        links = all_links[case]
        for r, link in links.items():
            link["all_records"] = linker.records_for(r, link)
        states = resolver.resolve(request, subjects[case], links)
        for r, want in gold[case].items():
            if r not in states:
                continue
            got = states[r]
            total += 1
            for field, got_value in (("treatment", got["treatment"]), ("status", got["status"]),
                                     ("evidence", got["evidence_id"] if want["evidence"] else "")):
                if got_value == want[field]:
                    hits[field] += 1
                else:
                    wrong[field] += 1
                    if not args.quiet:
                        print(f"{case} {r}: {field} got {got_value!r} want {want[field]!r}"
                              f"  [{got['basis']}; history {got['history'][-3:]}]")
        if args.case == case:
            for r, st in sorted(states.items()):
                print(f"  {r}: {st['treatment']} {st['status']} {st['evidence_id']} ({st['basis']})"
                      f" gold={gold[case].get(r)}")
    print(f"\ncompared {total} linked gold resources")
    for field in ("treatment", "status", "evidence"):
        print(
            f"  {field:<10} {hits[field]}/{total} = {hits[field] / max(total, 1):.1%}")


if __name__ == "__main__":
    main()
