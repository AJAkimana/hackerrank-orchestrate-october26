# Author: AJAkimana
"""Measure record linking against the sample answers.

Usage (from the repository root):
    python3 code/evaluation/linking_check.py [--case case_31] [--quiet]

For each sample case, the resources named in the gold steps are the ones
that truly belong to the subject. We report:
    recall     share of gold resources the linker found
    precision  share of linked resources that are gold

Extra links are not all errors yet: resources whose state is UNKNOWN get
no steps later (audit.steps). The numbers show what is left to filter.
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


def main(argv=None):
    """Link all requests together, then score the sample cases."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--case", help="show every link for one case")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args(argv)

    records, _ = load_evidence()
    index = IdentityIndex()
    linker = Linker(records, index)
    gold = {row["case_id"]: {s["resource_id"] for s in json.loads(row["steps_json"])}
            for row in read_csv(DATASET_DIR / "sample_output.csv")}

    samples = read_csv(DATASET_DIR / "sample_deletion_requests.csv")
    # link samples together with the evaluation requests: they share one
    # activity stream, so attribution must consider every request at once
    everything = samples + read_csv(DATASET_DIR / "deletion_requests.csv")
    all_links = linker.link_all(
        everything, {r["case_id"]: index.resolve(r["email"]) for r in everything})

    found = linked_total = gold_total = 0
    missed_by_prefix, extra_reasons = Counter(), Counter()
    for request in samples:
        case = request["case_id"]
        links = all_links[case]
        want, got = gold[case], set(links)
        found += len(want & got)
        linked_total += len(got)
        gold_total += len(want)
        for r in want - got:
            missed_by_prefix[r.rsplit("_", 1)[0]] += 1
        for r in got - want:
            extra_reasons["+".join(links[r]["reasons"])] += 1
        if not args.quiet and (want - got or got - want):
            print(f"{case}: missed {sorted(want - got)}")
            print(
                f"{'':>8} extra  {sorted((r, '+'.join(links[r]['reasons'])) for r in got - want)}")
        if args.case == case:
            for r, link in sorted(links.items()):
                mark = "GOLD " if r in want else "extra"
                ev = [e["activity_id"] for e in link["events"]]
                files = sorted({x["file_id"] for x in link["records"]})
                print(
                    f"  {mark} {link['system_id']}/{r} via {link['reasons']} files={files} events={ev}")

    print(f"\nrecall    {found}/{gold_total} = {found / gold_total:.1%}")
    print(
        f"precision {found}/{linked_total} = {found / max(linked_total, 1):.1%}")
    print(f"missed by type: {dict(missed_by_prefix)}")
    print(f"extra links by reason: {dict(extra_reasons)}")


if __name__ == "__main__":
    main()
