# Author: AJAkimana
"""Check identity resolution.

Usage (from the repository root):
    python3 code/evaluation/identity_check.py [--case case_10]

Checks
    1. every request email (samples + evaluation) resolves to exactly one user
    2. for the sample answers, how many gold resources already share an
       identifier with the resolved subject in some evidence record. The rest
       must be linked another way in Phase 3 (activity log, aliases, ...).
"""

import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from audit.common import DATASET_DIR, read_csv  # noqa: E402
from audit.evidence import load_evidence  # noqa: E402
from audit.identity import IdentityIndex  # noqa: E402


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--case", help="print the resolved subject for one case")
    args = parser.parse_args(argv)

    index = IdentityIndex()
    samples = read_csv(DATASET_DIR / "sample_deletion_requests.csv")
    evaluation = read_csv(DATASET_DIR / "deletion_requests.csv")

    print("[1] resolution")
    for label, requests in (("samples", samples), ("evaluation", evaluation)):
        subjects = [index.resolve(r["email"]) for r in requests]
        how = Counter(s["matched_via"]
                      if s else "UNRESOLVED" for s in subjects)
        print(f"    {label:<10} {len(requests)} requests: {dict(how)}")
        users = Counter(s["user_id"] for s in subjects if s)
        shared = {u: n for u, n in users.items() if n > 1}
        if shared:
            print(f"    {label:<10} users with more than one request: {shared}")

    records, _ = load_evidence()
    by_resource = defaultdict(list)
    for r in records:
        by_resource[r["resource_id"]].append(r)

    print("\n[2] gold resources linked to the subject by an identifier")
    linked = unlinked = 0
    gold = {row["case_id"]: json.loads(row["steps_json"]) for row in read_csv(
        DATASET_DIR / "sample_output.csv")}
    for request in samples:
        subject = index.resolve(request["email"])
        ids = set(subject["identifiers"])
        for system, resource in sorted({(s["system_id"], s["resource_id"]) for s in gold[request["case_id"]]}):
            hits = [r for r in by_resource[resource]
                    if ids & set(r["identifiers"])]
            if hits:
                linked += 1
            else:
                unlinked += 1
                print(
                    f"    not yet linked: {request['case_id']} {system}/{resource}")
    print(f"    linked {linked}, not yet linked {unlinked}")

    if args.case:
        request = next(r for r in samples +
                       evaluation if r["case_id"] == args.case)
        subject = index.resolve(request["email"])
        print(json.dumps({k: v for k, v in subject.items()
              if k != "history"}, indent=1, ensure_ascii=False))
        for change in subject["history"]:
            print("   ", change["audit_id"], change["event_time"], change["field_name"],
                  change["old_value"], "->", change["new_value"])


if __name__ == "__main__":
    main()
