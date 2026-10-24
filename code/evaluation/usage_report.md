# Usage Report — Final Full-Dataset Run

Author: AJAkimana

This report covers the run that produced the submitted `output.csv`
(518 requests from `dataset/deletion_requests.csv`).

## Summary

The final pipeline is **fully deterministic and makes no language-model
calls**. Every stage — evidence parsing, identity resolution, record
linking, state reconstruction, policy application, step generation, and
deletion-intent classification — is implemented as explicit Python rules
over the participant data. So the token and cost totals below are zero.
They were measured, not estimated: the code contains no model client and no
network calls (`grep` for API clients or HTTP libraries in `code/` finds
none).

## Model usage

| Provider | Model | Model calls | Input tokens | Output tokens | Total tokens | Estimated cost |
|---|---|---|---|---|---|---|
| — (none) | — | 0 | 0 | 0 | 0 | $0.00 |
| **Overall** | | **0** | **0** | **0** | **0** | **$0.00** |

| Per-request figure | Value |
|---|---|
| Requests processed | 518 |
| Average model calls per request | 0 |
| Average tokens per request | 0 |
| Estimated cost per request | $0.00 |

There is a single row because no model is used; the per-model and overall
totals are therefore the same.

## Non-model resources used by the run

| Resource | Role | Calls in the final run | Cost |
|---|---|---|---|
| Python 3.15 standard library (`csv`, `json`, `re`, `sqlite3`, `difflib`, `hashlib`) | All logic; SQL snapshots run in in-memory SQLite | — | $0 |
| Ghostscript 10.05 (`gs`, local) | Text extraction from the 4 PDF evidence files | 4 | $0 |
| Tesseract 5.5 OCR (local) | Text from the 11 screenshots; run once, then cached in `code/cache/ocr/` | 0 (cache hits); 11 on the first run | $0 |

| Run metric | Value |
|---|---|
| Wall-clock time, full run (`python3 code/main.py`) | ~6 s (macOS laptop, warm OCR cache) |
| Evidence files read | 94 → 2,934 normalized records |
| Requests linked together (shared activity stream) | 550 (518 evaluation + 32 samples) |
| Output | 518 rows: 351 INCOMPLETE, 157 COMPLETE, 10 NOT_APPLICABLE |

## Why no model is used

* **Intent detection** is the one task that most needs language understanding.
  The dataset has only 27 distinct request wordings across 6 languages, and
  explicit multilingual rules classify all 550 request texts correctly (see
  `evaluation_report.md` §2 and custom case C6). Rules are free, return the
  same answer on every run, and give the phrase behind each decision.
* **Evidence reading** is structured: JSON, SQL, logs and handover text are
  parsed exactly, and the PDFs have a text layer. Only the screenshots need
  OCR, which runs locally.
* **Determinism** is part of the contract: the same input always yields a
  byte-identical `output.csv`.

## Development-time assistance (not part of the run)

The solution was built with the help of an AI coding assistant (Claude Code,
model `claude-opus-5-5`), recorded in the root `log.txt` transcript. That
usage happened while writing the code; it is not invoked by the submitted
program and is not counted in the totals above. Its token usage was not
metered from inside the session, so no figure is reported for it.

## Cost if an LLM fallback were added

A possible extension (`evaluation_report.md` §7) is to send only the texts
that match no intent rule to a model. On this dataset no text falls through,
so such a fallback would add 0 calls. In general its cost would be bounded by
the number of unmatched texts × one short classification prompt per text.
