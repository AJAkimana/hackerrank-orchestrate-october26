# Author: AJAkimana
"""Entry point: audit every deletion request and write output.csv.

Usage (from the repository root):
    python3 code/main.py                       # 518 evaluation cases -> ./output.csv
    python3 code/main.py --requests dataset/sample_deletion_requests.csv --out /tmp/sample_pred.csv

The work happens in audit.pipeline.Auditor; see that module for the
phases (evidence -> identity -> linking -> state -> steps -> intent).
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from audit.common import DATASET_DIR, REPO_ROOT, read_csv, write_output  # noqa: E402
from audit.pipeline import Auditor  # noqa: E402


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--requests", type=Path, default=DATASET_DIR / "deletion_requests.csv")
    parser.add_argument("--out", type=Path, default=REPO_ROOT / "output.csv")
    args = parser.parse_args(argv)

    requests = read_csv(args.requests)
    rows = Auditor().audit(requests)
    write_output(rows, args.out)
    print(f"Wrote {len(rows)} rows to {args.out}")


if __name__ == "__main__":
    main()
