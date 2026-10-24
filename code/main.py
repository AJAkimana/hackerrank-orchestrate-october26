# Author: AJAkimana
"""Entry point: audit every deletion request and write output.csv.

Usage (from the repository root):
    python3 code/main.py                       # 518 evaluation cases -> ./output.csv
    python3 code/main.py --requests dataset/sample_deletion_requests.csv --out /tmp/sample_pred.csv

Phase 0 ships a deliberately naive baseline that trusts the workflow's
reported_status. It exists to prove the pipeline and the evaluator work end
to end, and to show how far "believing the claim" gets you. Later phases
replace audit_case() with real evidence-driven reasoning.
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from audit.common import DATASET_DIR, REPO_ROOT, read_csv, write_output  # noqa: E402


def audit_case(request):
    """Return (deletion_status, steps) for one request."""
    status = "COMPLETE" if request["reported_status"] == "COMPLETE" else "INCOMPLETE"
    return status, []


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--requests", type=Path, default=DATASET_DIR / "deletion_requests.csv")
    parser.add_argument("--out", type=Path, default=REPO_ROOT / "output.csv")
    args = parser.parse_args(argv)

    requests = read_csv(args.requests)
    rows = [(r["case_id"], *audit_case(r)) for r in requests]
    write_output(rows, args.out)
    print(f"Wrote {len(rows)} rows to {args.out}")


if __name__ == "__main__":
    main()
