# Author: AJAkimana
"""Check that the evidence parsers (audit.evidence) extract everything.

Usage (from the repository root):
    python3 code/evaluation/evidence_coverage.py [--show RESOURCE_ID]

Checks
    1. every manifest file yields at least one record
    2. every resource id written in a file's raw text appears in that file's records
    3. every evidence citation in sample_output.csv is backed by an extracted record
       (a VERIFY_RECORD_ABSENT step may legitimately cite a file where the
       resource is missing: the snapshot proves absence)
"""

import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from audit.common import DATASET_DIR, read_csv  # noqa: E402
from audit.evidence import RESOURCE_RE, image_text, load_evidence, pdf_text  # noqa: E402


def raw_text(entry):
    """The file's text as a human would read it (PDF text / OCR / raw)."""
    path = DATASET_DIR / entry["file_path"]
    if path.suffix == ".pdf":
        return pdf_text(path)
    if path.suffix == ".png":
        return image_text(path, entry["file_id"])
    return path.read_text(encoding="utf-8")


def main(argv=None):
    """Run the three coverage checks and print what is missing."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--show", help="print every record for this resource id")
    args = parser.parse_args(argv)

    records, manifest = load_evidence()
    by_file = defaultdict(list)
    for r in records:
        by_file[r["file_id"]].append(r)

    print(f"{len(records)} records from {len(manifest)} files")
    print("By source:", dict(Counter(r["source"] for r in records)))
    print("By system:", dict(Counter(r["system_id"] for r in records).most_common()))

    empty = [e["file_id"] for e in manifest if not by_file[e["file_id"]]]
    print(f"\n[1] files with no records: {empty or 'none'}")

    gaps = {}
    for entry in manifest:
        in_text = {f"{p}_{n}" for p, n in RESOURCE_RE.findall(raw_text(entry))}
        missing = in_text - {r["resource_id"] for r in by_file[entry["file_id"]]}
        if missing:
            gaps[entry["file_id"]] = sorted(missing)
    print(f"[2] resource ids in raw text but not extracted: {gaps or 'none'}")

    have = {(r["file_id"], r["resource_id"]) for r in records}
    unbacked = Counter()
    for row in read_csv(DATASET_DIR / "sample_output.csv"):
        for step in json.loads(row["steps_json"]):
            ev = step["evidence_id"]
            if ev.startswith("evidence_") and (ev, step["resource_id"]) not in have:
                unbacked[(row["case_id"], step["operation"], step["resource_id"], ev)] += 1
    print(f"[3] sample citations without an extracted record: {len(unbacked)}")
    for key in unbacked:
        print("    ", *key)

    if args.show:
        for r in records:
            if r["resource_id"] == args.show:
                print(json.dumps(r, ensure_ascii=False, indent=1)[:1500])


if __name__ == "__main__":
    main()
