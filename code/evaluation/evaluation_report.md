# Evaluation Report — Ghost Data Still Exists

Author: AJAkimana

This report measures the deletion-audit agent in `code/` against the 32 public
sample answers (`dataset/sample_output.csv`), checks the 518-case submission
against the output contract, and documents the custom test cases, the failures
found during development, and the improvements made.

All numbers below come from the commands in [Reproducing](#reproducing) and
were produced by the final code that wrote `output.csv`.

## 1. Headline results (32 sample cases)

| Metric | Result |
|---|---|
| **Case-level status accuracy** (`deletion_status`) | **100.00%** (32/32) |
| **Sequence accuracy** (ordered step list matches exactly) | **50.00%** (16/32) |
| Exact case accuracy (status *and* full sequence) | 50.00% (16/32) |
| **Step precision** (predicted steps that are correct) | **94.09%** (175/186) |
| **Step recall** (gold steps found) | **90.67%** (175/193) |
| **Step F1** | **92.35%** |

A step counts as correct only when every field matches (`phase`, `system_id`,
`resource_id`, `operation`, `state`, `evidence_id`); `step_no` is positional.

### Field-level accuracy

Each gold step is paired with the predicted step for the same
`(phase, system_id, resource_id)`; a missing pair counts as wrong for every field.

| Field | Accuracy |
|---|---|
| resource (`system_id` + `resource_id` found) | 90.67% |
| `operation` | 90.67% |
| `state` | 90.67% |
| `evidence_id` | 90.67% |

All four are equal: whenever the agent finds the right resource, it also picks
the right operation, state and cited evidence. Every remaining error is a
*which resource* error (see §5), not a policy or evidence error.

### Status confusion

| Gold → Predicted | COMPLETE | INCOMPLETE | NOT_APPLICABLE |
|---|---|---|---|
| COMPLETE (10) | **10** | 0 | 0 |
| INCOMPLETE (22) | 0 | **22** | 0 |

The workflow's own `reported_status`, used as a naive baseline, gets only 53.1%:
11 of the 22 incomplete cases claim `COMPLETE`.

## 2. Component diagnostics

Each stage has its own check script, so a failure can be traced to a stage.

| Stage | Check | Result |
|---|---|---|
| Evidence parsing (`audit/evidence.py`) | `evidence_coverage.py` | 2,934 records from 94 files; every file parsed; every sample citation of a present record is backed by an extracted record (the 4 unbacked citations are absence proofs, as expected) |
| Identity (`audit/identity.py`) | `identity_check.py` | 550/550 request emails resolve to exactly one user (evaluation set: 418 current, 100 historical) |
| Linking (`audit/linking.py`) | `linking_check.py` | resource recall 83.8%, precision 89.4% against gold resources* |
| State at `audit_at` (`audit/state.py`) | `state_check.py` | for every gold resource the linker finds: treatment 100%, status 100%, cited evidence 100% |
| Intent (`audit/intent.py`) | custom case C6 + all texts | 32/32 samples classified as deletion; exactly 10/518 evaluation requests classified as non-deletion, each with the triggering phrase |

\* `linking_check.py` links all 550 requests without the intent filter, so its
numbers differ slightly from the end-to-end run, which excludes the 10
non-deletion requests from linking.

## 3. Submission (518 evaluation cases)

There are no public answers for these cases; we check the contract and sanity-check the distribution.

| Check | Result |
|---|---|
| Contract check (`main.py --pred output.csv`) | **OK**: header, 518 rows, sorted numerically by `case_id`, valid JSON, consecutive `step_no`, phase/operation order, allowed operation→state pairs, empty `evidence_id` on future steps, evidence on findings and on COMPLETE verifications, `[]` for NOT_APPLICABLE |
| Status distribution | 351 INCOMPLETE, 157 COMPLETE, 10 NOT_APPLICABLE (samples: 22 / 10 / 0) |
| Steps | 3,099 in total, 6.0 per case on average (max 14) |
| Runtime | ~6 s for the full run on a laptop (OCR text is cached) |

## 4. Custom evaluation cases

`python3 code/evaluation/custom_cases.py` runs six cases we wrote ourselves.
Each builds synthetic people, records and snapshots (none taken from the
dataset), runs the real modules, and compares the result with an answer
derived by hand from `problem_statement.md`. They target rules the public
samples cover weakly or not at all. **Result: 6/6 pass.**

| # | Scenario | Rule exercised | Expected answer |
|---|---|---|---|
| C1 | The primary database answers 404, but a later **failover replica** still holds the full profile | Replicas count; a workflow's "success" is a claim | `INCOMPLETE`: REPORT_REMAINING_RECORD (cites the replica file) → DELETE_RECORD → VERIFY_RECORD_ABSENT |
| C2 | A search entry is absent at audit time but **reappears in a file captured after `audit_at`** | Only evidence at or before `audit_at` counts | `COMPLETE`: VERIFY_RECORD_ABSENT citing the earlier file |
| C3 | Two **account tombstones**: one keeps `subject_reference` but still shows the email; one is clean | Tombstone keeps the stable user id, drops direct identifiers | `INCOMPLETE`: REPORT_EXPOSED_PII + REDACT_RECORD for the first; VERIFY_RECORD_REDACTED for both |
| C4 | Remaining search entry + **enabled connector** + **restorable backup** + retained security audit record | Remediation order: disable flows and block restores before changing records; retained records are verified as present | 3 findings → DISABLE_DATA_FLOW, BLOCK_RESTORE, DELETE_RECORD → 4 verifications incl. VERIFY_RECORD_PRESENT |
| C5 | Request sent from an email the user **changed twice**, typed with odd casing and spaces | Identity resolution across history; email hashes of old emails | user found, `matched_via=historical`, all 3 emails and the hash of the oldest one recovered |
| C6 | 7 phrasings: "delete… you may keep anonymous statistics", "marketing lists only", "do not close", German "löschen", "confirm my profile is gone", "copy of my data, don't delete", an unrelated question | Deletion authorization from text, including traps | True, False, False, True, True, False, False |

**Sanity check that the cases can fail:** moving C2's audit date after the late
file makes C2 produce `INCOMPLETE` and fail, as it should.

## 5. Remaining failures (sample set) and why

16 of 32 sample cases are not exact matches. Every miss is a linking problem
(*which* resources belong to the subject); none is a status, policy, ordering,
or evidence-citation problem.

| Cause | Steps affected | Fixable? |
|---|---|---|
| **Retained security audit records with no participant evidence.** For 7 INCOMPLETE cases the gold answer verifies an `audit_record_*` that appears in no evidence file and no activity row (e.g. `audit_record_6645` exists only in `sample_output.csv`). | 7 missing steps | No: the id is not discoverable from participant data |
| **True ties between requests.** Pairs such as case_25/26, case_28/29 and case_31 share the same `reported_at`, the same `reported_status`, and equally well-timed deletion events, so their accounts (and the analytics records that follow them) can be swapped. We checked request duration and other features for a pattern and found none. | ~16 steps (each swap costs a missing and an extra step) | Only with signals not present in the data |
| **Account with no trace.** `account_004` (case_04) appears in no evidence and no activity; the gold cites a file where it is absent. | 1 missing step | No |
| **Over-linked anonymized analytics.** A few activity-only analytics records land on a neighbouring request (case_03, case_11, case_20). | ~5 extra steps | Partly; see §7 |

## 6. Failures found during development and improvements made

| # | Problem found | How it was found | Fix | Effect |
|---|---|---|---|---|
| 1 | Trusting `reported_status` | Naive baseline scored by the evaluator | Rebuild state from evidence | Status 53.1% → 100% |
| 2 | Plain string sort puts `case_100` before `case_33` | Inspected case ids | Numeric `case_sort_key` | Contract-compliant ordering |
| 3 | The evaluator imported itself (`import main` resolved to its own file) | Code review before first run | Load the solver by file path | Evaluator runs |
| 4 | Emails extracted from documents had a stray leading `n` (`nharuka…`) | Coverage check compared OCR emails with known identities | Extract from raw strings, not `json.dumps` (which escapes newlines as `\n`) | Document identifiers became correct |
| 5 | OCR misread `ingrid.dahl` as `ingrid.dahli` | Same check | Strict fuzzy correction (≥ 0.95 similarity, exactly one candidate) for image records only, so decoys like `g.silva76.jr` stay separate | 1 correction, no false merges |
| 6 | Empty snapshots produced no records, so absence could not be proven | Coverage check listed empty files | Track each file's **scope** (systems and tables captured) | Absence proofs such as case_31's `account_4857` via `evidence_51` |
| 7 | Deleted and anonymized records had no identifiers left to link by | Identity check: 28/111 gold resources unlinked | Link by deletion-worker activity in a timing window | Recall up to 92.8% |
| 8 | Overlapping windows pulled in other people's records (precision 46%) | `linking_check.py` | Ownership exclusion plus **global** attribution across all 550 requests (one account per subject, matched one-to-one) | Precision 46% → 87% |
| 9 | Ties between requests reported at the same time | Failure list | Found that `reported_status` mirrors the account event's result (COMPLETE↔SUCCESS, PARTIAL↔PARTIAL, NOT_STARTED↔FAILED); used it as a penalty | Recall 81.1% → 85.6% |
| 10 | Analytics record `analytics_9914` should be deleted, not anonymized | `state_check.py` / sample case_12 | It is a marketing contact (`email_opt_in`); the treatment also uses the worker's attempted operation | Treatment 100% |
| 11 | Support attachment PDF treated as a redactable message | `state_check.py` | Detect attachments in documents | Treatment 100% |
| 12 | Snapshot absence wrongly applied to records that should be anonymized or retained | Distribution check on the 518 cases | Absence fallback only for DELETE; otherwise UNKNOWN (no step) | 52 unsupported steps avoided |
| 13 | Catalog-only links added resources the samples never include | End-to-end failures (case_07, case_17) | Catalog used only to exclude other people's resources | Fewer extra steps |
| 14 | A "not found" lookup by the user's email counted as ownership | case_17's `account_6523` | Ignore 404 / zero-row lookups as identifier evidence | Fewer extra steps |
| 15 | Contested analytics went to the wrong request | Failure list | Assign by gap from the request's own account event | F1 91.0% → 92.35%, exact 46.9% → 50.0% |
| 16 | Sample case_26 ("confirm the profile is gone") classified as non-deletion | Intent run over all texts | Added outcome phrasing to the deletion patterns | 32/32 samples deletion |

### Score progression (sample set)

| Version | Status acc. | Step F1 | Exact cases |
|---|---|---|---|
| Baseline: trust `reported_status`, no steps | 53.1% | 0.0% | 0.0% |
| First end-to-end pipeline | 100.0% | 91.0% | 46.9% |
| + linking refinements (#13–#15) | **100.0%** | **92.35%** | **50.0%** |

## 7. Limitations and next steps

* **Tuned on 32 cases.** The timing windows (account ~1 h before
  `reported_at`, other systems within ~2 h after) and the status↔result
  mapping were learned from the samples. They are simple and explainable, but
  could fit the hidden set less well.
* **Rule-based intent.** Exact on all 550 texts in this dataset, but an
  unfamiliar phrasing could slip through; an LLM fallback for texts that match
  no rule is a natural extension.
* **OCR on screenshots** is cached and corrected only conservatively; a vision
  model could read console screenshots (backup / connector status) more
  reliably than keyword rules.
* **Tie-breaking** between requests with identical timing is still a guess;
  more evidence types (e.g. per-request trace ids) would be needed.

## Reproducing

From the repository root:

```bash
python3 code/main.py                              # writes output.csv (518 rows)
python3 code/evaluation/main.py --pred output.csv # contract check
python3 code/evaluation/main.py --run-samples     # sample metrics + failing cases
python3 code/evaluation/custom_cases.py           # custom cases C1-C6
python3 code/evaluation/evidence_coverage.py      # evidence parsing coverage
python3 code/evaluation/identity_check.py         # identity resolution
python3 code/evaluation/linking_check.py --quiet  # linking recall / precision
python3 code/evaluation/state_check.py --quiet    # state at audit time
```
