# Author: AJAkimana
"""Evaluate predictions: contract checks plus accuracy against gold answers.

Usage (from the repository root):
    # score the sample cases end to end (runs the solver first)
    python3 code/evaluation/main.py --run-samples

    # score an existing prediction file against a gold file
    python3 code/evaluation/main.py --pred pred.csv --gold dataset/sample_output.csv \
        --requests dataset/sample_deletion_requests.csv

    # only check the submission contract (no gold answers needed)
    python3 code/evaluation/main.py --pred output.csv

Metrics
    status accuracy    share of cases whose deletion_status matches
    step P / R / F1    steps compared as whole objects (all fields except step_no)
    field accuracy     each gold step is paired with the predicted step for the
                       same (phase, system_id, resource_id); a missing pair counts
                       as wrong for every field
    sequence accuracy  share of cases whose ordered step list matches exactly
    exact case         status and full step sequence both match
"""

import argparse
import importlib.util
import json
import sys
import tempfile
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from audit.common import (  # noqa: E402
    DATASET_DIR, OP_PHASE, OP_RANK, OP_STATE, OUTPUT_COLUMNS, PHASES, STATUSES,
    STEP_FIELDS, case_sort_key, read_csv,
)

SOLVER_PATH = Path(__file__).resolve().parents[1] / "main.py"
COMPARED_FIELDS = STEP_FIELDS[1:]  # step_no is positional, so it is not compared
FIELD_SCORED = ("operation", "state", "evidence_id")


def load_predictions(path):
    """Return {case_id: (status, steps)} plus a list of parse errors."""
    rows, errors = {}, []
    for line_no, row in enumerate(read_csv(path), 2):
        try:
            steps = json.loads(row["steps_json"])
        except (json.JSONDecodeError, TypeError) as exc:
            errors.append(f"line {line_no} {row.get('case_id')}: invalid steps_json ({exc})")
            steps = []
        rows[row["case_id"]] = (row["deletion_status"], steps)
    return rows, errors


def check_contract(path, requests):
    """Return a list of human-readable contract violations (empty = valid)."""
    problems = []
    with open(path, encoding="utf-8") as f:
        header = f.readline().strip()
    if header != ",".join(OUTPUT_COLUMNS):
        problems.append(f"header is {header!r}, expected {','.join(OUTPUT_COLUMNS)!r}")

    preds, parse_errors = load_predictions(path)
    problems += parse_errors
    ids_in_file = [r["case_id"] for r in read_csv(path)]
    expected = [r["case_id"] for r in requests]
    if len(ids_in_file) != len(expected):
        problems.append(f"{len(ids_in_file)} data rows, expected {len(expected)}")
    if len(set(ids_in_file)) != len(ids_in_file):
        problems.append("duplicate case_id rows")
    missing = set(expected) - set(ids_in_file)
    if missing:
        problems.append(f"missing cases: {sorted(missing, key=case_sort_key)[:10]}")
    if ids_in_file != sorted(ids_in_file, key=case_sort_key):
        problems.append("rows are not sorted by case_id")

    for case_id, (status, steps) in preds.items():
        where = f"{case_id}:"
        if status not in STATUSES:
            problems.append(f"{where} invalid status {status!r}")
        if not isinstance(steps, list):
            problems.append(f"{where} steps_json is not a JSON array")
            continue
        if status == "NOT_APPLICABLE" and steps:
            problems.append(f"{where} NOT_APPLICABLE must have []")
        if status == "COMPLETE" and any(s.get("phase") != "VERIFICATION" for s in steps):
            problems.append(f"{where} COMPLETE may only contain VERIFICATION steps")
        last_rank = -1
        for i, step in enumerate(steps, 1):
            if set(step) != set(STEP_FIELDS):
                problems.append(f"{where} step {i} has fields {sorted(step)}")
                continue
            op = step["operation"]
            if step["step_no"] != i:
                problems.append(f"{where} step {i} has step_no {step['step_no']}")
            if op not in OP_RANK:
                problems.append(f"{where} step {i} unknown operation {op}")
                continue
            if step["phase"] != OP_PHASE[op] or step["state"] != OP_STATE[op]:
                problems.append(f"{where} step {i} {op} has phase/state {step['phase']}/{step['state']}")
            if OP_RANK[op] < last_rank:
                problems.append(f"{where} step {i} {op} is out of phase/operation order")
            last_rank = OP_RANK[op]
            future = step["phase"] == "REMEDIATION" or (status == "INCOMPLETE" and step["phase"] == "VERIFICATION")
            if future and step["evidence_id"]:
                problems.append(f"{where} step {i} is future work and must have empty evidence_id")
            if not future and not step["evidence_id"]:
                problems.append(f"{where} step {i} {op} must cite evidence")
    return problems


def step_tuple(step):
    """A step's compared fields as a hashable tuple (step_no excluded)."""
    return tuple(step.get(k) for k in COMPARED_FIELDS)


def score(preds, gold):
    """Compare predictions with gold answers; returns a metrics dict."""
    status_hits = seq_hits = exact_hits = 0
    tp = n_pred = n_gold = 0
    field_hits = Counter()
    confusion = Counter()
    failures = []
    for case_id, (g_status, g_steps) in gold.items():
        p_status, p_steps = preds.get(case_id, ("<missing>", []))
        confusion[(g_status, p_status)] += 1
        status_ok = p_status == g_status
        seq_ok = [step_tuple(s) for s in p_steps] == [step_tuple(s) for s in g_steps]
        status_hits += status_ok
        seq_hits += seq_ok
        exact_hits += status_ok and seq_ok

        g_bag, p_bag = Counter(map(step_tuple, g_steps)), Counter(map(step_tuple, p_steps))
        tp += sum((g_bag & p_bag).values())
        n_gold += len(g_steps)
        n_pred += len(p_steps)

        by_key = {(s["phase"], s["system_id"], s["resource_id"]): s for s in p_steps}
        for g in g_steps:
            p = by_key.get((g["phase"], g["system_id"], g["resource_id"]))
            for field in FIELD_SCORED:
                field_hits[field] += p is not None and p[field] == g[field]
            field_hits["resource"] += p is not None

        if not (status_ok and seq_ok):
            failures.append({
                "case_id": case_id, "gold_status": g_status, "pred_status": p_status,
                "missing": sorted(set(g_bag) - set(p_bag)), "extra": sorted(set(p_bag) - set(g_bag)),
                "order_only": set(g_bag) == set(p_bag) and not seq_ok,
            })

    n = len(gold) or 1
    precision = tp / n_pred if n_pred else 0.0
    recall = tp / n_gold if n_gold else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "cases": len(gold),
        "status_accuracy": status_hits / n,
        "sequence_accuracy": seq_hits / n,
        "exact_case_accuracy": exact_hits / n,
        "step_precision": precision, "step_recall": recall, "step_f1": f1,
        "gold_steps": n_gold, "pred_steps": n_pred, "matched_steps": tp,
        "field_accuracy": {f: field_hits[f] / (n_gold or 1) for f in ("resource",) + FIELD_SCORED},
        "confusion": confusion,
        "failures": sorted(failures, key=lambda f: case_sort_key(f["case_id"])),
    }


def print_report(metrics, show_failures):
    """Print the metrics table, the status confusion, and failing cases."""
    pct = lambda x: f"{100 * x:6.2f}%"  # noqa: E731
    print(f"\nCases scored          {metrics['cases']}")
    print(f"Status accuracy       {pct(metrics['status_accuracy'])}")
    print(f"Sequence accuracy     {pct(metrics['sequence_accuracy'])}")
    print(f"Exact case accuracy   {pct(metrics['exact_case_accuracy'])}")
    print(f"Step precision        {pct(metrics['step_precision'])}  "
          f"({metrics['matched_steps']}/{metrics['pred_steps']} predicted steps correct)")
    print(f"Step recall           {pct(metrics['step_recall'])}  "
          f"({metrics['matched_steps']}/{metrics['gold_steps']} gold steps found)")
    print(f"Step F1               {pct(metrics['step_f1'])}")
    print("Field accuracy (over gold steps):")
    for field, value in metrics["field_accuracy"].items():
        print(f"  {field:<18}  {pct(value)}")

    print("\nStatus confusion (gold -> predicted):")
    for (g, p), count in sorted(metrics["confusion"].items()):
        print(f"  {g:<15} -> {p:<15} {count}")

    if show_failures and metrics["failures"]:
        print(f"\nFailing cases ({len(metrics['failures'])}):")
        for f in metrics["failures"]:
            note = " [right steps, wrong order]" if f["order_only"] else ""
            print(f"- {f['case_id']}: gold {f['gold_status']}, predicted {f['pred_status']}{note}")
            for label in ("missing", "extra"):
                for step in f[label][:8]:
                    print(f"    {label:<7} {' | '.join(map(str, step))}")


def main(argv=None):
    """Contract-check a prediction file and, with gold answers, score it.
    Returns a non-zero exit code when the contract check fails."""
    parser = argparse.ArgumentParser(description="Evaluate deletion-audit predictions.")
    parser.add_argument("--run-samples", action="store_true", help="run code/main.py on the samples, then score")
    parser.add_argument("--pred", type=Path)
    parser.add_argument("--gold", type=Path)
    parser.add_argument("--requests", type=Path, default=DATASET_DIR / "deletion_requests.csv")
    parser.add_argument("--quiet", action="store_true", help="hide the per-case failure list")
    args = parser.parse_args(argv)

    if args.run_samples:
        # Load code/main.py by path: a plain "import main" would find this file.
        spec = importlib.util.spec_from_file_location("solver", SOLVER_PATH)
        solver = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(solver)
        args.requests = DATASET_DIR / "sample_deletion_requests.csv"
        args.gold = DATASET_DIR / "sample_output.csv"
        args.pred = Path(tempfile.gettempdir()) / "ghost_audit_sample_predictions.csv"
        solver.main(["--requests", str(args.requests), "--out", str(args.pred)])
    if not args.pred:
        parser.error("give --pred (and optionally --gold) or --run-samples")

    requests = read_csv(args.requests)
    problems = check_contract(args.pred, requests)
    print(f"Contract check: {'OK' if not problems else f'{len(problems)} problem(s)'}")
    for p in problems[:25]:
        print(f"  - {p}")

    if args.gold:
        preds, _ = load_predictions(args.pred)
        gold, _ = load_predictions(args.gold)
        print_report(score(preds, gold), show_failures=not args.quiet)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
