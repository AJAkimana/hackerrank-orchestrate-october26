# Ghost Data Still Exists — Deletion-Audit Agent

HackerRank Orchestrate, October 2026 · Author: **AJAkimana**

A deletion workflow can report **Complete** while personal data still sits in
replicas, search indexes, support attachments, exports, analytics, logs or
backups — and sync or restore jobs can bring it back. This agent checks every
deletion request against the evidence and answers, for each case:

* `COMPLETE`: every copy has the treatment policy requires; the output is the
  verification steps that prove it, each citing evidence;
* `INCOMPLETE`: the output is what remains (findings), the ordered fix
  (remediation), and the checks that must pass afterwards (verification);
* `NOT_APPLICABLE`: the person never asked for deletion; the output is `[]`.

The full challenge contract is in [`problem_statement.md`](./problem_statement.md).

## Results at a glance

On the 32 public sample cases (details in
[`code/evaluation/evaluation_report.md`](code/evaluation/evaluation_report.md)):

| Status accuracy | Step precision | Step recall | Step F1 | Exact sequence |
|---|---|---|---|---|
| **100%** | 94.1% | 90.7% | 92.4% | 50.0% |

The full run on all 518 evaluation cases takes ~6 seconds, makes **no model
calls** (0 tokens, $0, see
[`usage_report.md`](code/evaluation/usage_report.md)), and is deterministic:
the same input always gives a byte-identical `output.csv`.

---

## Setup

| Requirement | Why | Install |
|---|---|---|
| **Python 3.9+** | Runs everything; standard library only, no `pip install` | python.org, or the system Python |
| **Ghostscript** (`gs`) | Reads the text of the 4 PDF evidence files | macOS `brew install ghostscript` · Ubuntu `sudo apt install ghostscript` · Windows: ghostscript.com (`gswin64c` is detected) |
| Tesseract *(optional)* | OCR for the 11 screenshots. Not needed: the text is cached in `code/cache/ocr/` | `brew install tesseract` / `sudo apt install tesseract-ocr` |

No API keys, environment variables or `.env` file are needed.

The `dataset/` folder must sit at the repository root, next to `code/`.

## Run

From the repository root:

```bash
python3 code/main.py
```

This reads `dataset/` and writes **`output.csv`** at the repository root:
518 rows, sorted by `case_id`, columns `case_id,deletion_status,steps_json`.

Any request file in the same format can be audited:

```bash
python3 code/main.py --requests dataset/sample_deletion_requests.csv --out sample_predictions.csv
```

## Evaluate

```bash
python3 code/evaluation/main.py --pred output.csv   # contract check of the submission
python3 code/evaluation/main.py --run-samples       # score against the 32 sample answers
python3 code/evaluation/custom_cases.py             # 6 team-made test cases
```

Per-stage diagnostics, useful for tracing a failure to one stage:

```bash
python3 code/evaluation/evidence_coverage.py --show account_5334  # what was extracted
python3 code/evaluation/identity_check.py --case case_10          # who a request is about
python3 code/evaluation/linking_check.py --case case_31           # which records were linked
python3 code/evaluation/state_check.py --case case_05             # state at audit time
```

---

## How it works

```
request ─► intent ─► identity ─► linking ─► state at audit_at ─► steps ─► output.csv
                         ▲           ▲               ▲
                         │           │               │
              user_identities  evidence records   deletion_rules
              + audit log      + activity stream  + snapshot scope
```

| Stage | Module | What it does |
|---|---|---|
| Evidence | [`audit/evidence.py`](code/audit/evidence.py) | Turns all 94 files (JSON, 6 log formats, SQL snapshots run in in-memory SQLite, handover text, PDFs, OCR'd screenshots) into 2,934 uniform records: *file, time, system, resource, fields, identifiers*. Also records each snapshot's **scope**, so an empty snapshot can prove a record is gone. |
| Intent | [`audit/intent.py`](code/audit/intent.py) | Decides from `request_text` whether deletion is authorized. Narrow "keep" rules (*"do not close the account"*, *"marketing lists only"*) come first, then deletion words in 9 languages. Each decision carries the phrase that triggered it. |
| Identity | [`audit/identity.py`](code/audit/identity.py) | Maps the request email (current or historical, any case) to the user, and rebuilds every email, phone and email hash the user has had. `email_hash` is sha256 of the email, so hashes of old emails are recomputed. |
| Linking | [`audit/linking.py`](code/audit/linking.py) | Finds the user's resources: **identifier** matches in evidence, plus **deletion-worker activity** in a timing window around `reported_at` (deleted records have no identifiers left). Requests share one activity stream, so collisions are settled **globally**: one account per subject, matched one-to-one; the status↔result consistency (`COMPLETE`↔`SUCCESS`…); and records go to the request whose account was processed just before them. |
| State | [`audit/state.py`](code/audit/state.py) | For each resource: the **treatment** policy requires (`deletion_rules.csv`: delete / redact / anonymize / retain / disable flow / block restore) and its **status at `audit_at`** from the latest visible evidence. Activity results are treated as claims, never proof, and evidence captured after `audit_at` is ignored. |
| Steps | [`audit/steps.py`](code/audit/steps.py) | Maps each (treatment, status) to finding / remediation / verification, sets the case status, and orders steps by phase → operation → system → resource. That order also puts disabling flows and blocking restores before record changes. |
| Pipeline | [`audit/pipeline.py`](code/audit/pipeline.py) | Wires the stages together; `code/main.py` is the command-line entry point. |

### Key rules applied

* **Evidence over claims.** `reported_status` and activity `SUCCESS` are never
  taken as proof; the naive "trust the claim" baseline scores 53% status
  accuracy.
* **Time travel is forbidden.** Only evidence captured at or before `audit_at`
  counts.
* **Replicas count.** A row in a failover, regional or reporting replica is a
  remaining copy, even when the primary is clean.
* **Absence must be proven.** By an explicit lookup (404, zero rows, no hits),
  or by a snapshot that covered the system without the record. The snapshot
  fallback applies only to records that must be deleted; anything else without
  evidence gets no step rather than a guess.
* **Policy-aware treatment.** Security audit records are retained and
  verified as present; account tombstones keep the stable `user_id` but lose
  name/email/phone/hash; support messages are redacted, attachments deleted;
  analytics are anonymized (marketing contacts deleted).

## Repository layout

```
code/
├── main.py                  entry point: python3 code/main.py
├── audit/                   the agent (stages listed above) + common.py (paths, step contract)
├── cache/ocr/               cached OCR text of the 11 screenshots
└── evaluation/
    ├── main.py              contract checker and scorer
    ├── custom_cases.py      6 custom evaluation cases
    ├── *_check.py, evidence_coverage.py   per-stage diagnostics
    ├── evaluation_report.md
    └── usage_report.md
dataset/                     participant data (not part of code.zip)
output.csv                   generated predictions (518 rows)
log.txt                      AI-assistant transcript (chat_transcript submission)
```

## Packaging and submission

Build `code.zip` from the repository root (it excludes `dataset/`, caches and
virtual environments; the OCR cache under `code/cache/` is included on
purpose):

```bash
zip -r code.zip README.md code -x "*/__pycache__/*" "*/.venv/*" "*/venv/*" "*/.DS_Store"
```

Windows (PowerShell):

```powershell
Compress-Archive -Path README.md, code -DestinationPath code.zip -Force
```

| Item | File |
|---|---|
| `code.zip` | `README.md` + `code/` (includes both evaluation reports) |
| `output.csv` | repository root, 518 rows |
| `chat_transcript` | `log.txt` at the repository root |

Submit at:
https://www.hackerrank.com/contests/hackerrank-orchestrate-october26/challenges/ghost-data-still-exists

The repository contains no API keys, credentials or real personal data; all
people in the dataset are fictional.
