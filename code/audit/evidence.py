# Author: AJAkimana
"""Phase 1: turn every evidence file into one uniform list of records.

Each record answers: "file F, at time T, shows system S / resource R with
these fields". Interpreting what the fields *mean* (present? redacted?
enabled?) is left to later phases; this module only extracts faithfully.

Record shape (a plain dict):
    file_id       evidence_NN from evidence_files.csv
    captured_at   when the file was captured (manifest)
    observed_at   the most specific timestamp for this record
    system_id     owning system, e.g. account_service
    resource_id   e.g. account_005
    source        json | log | sql | text | pdf | image
    container     table / collection / log event family the record came from
    fields        flat dict of the record's own values
    identifiers   normalized identifiers found anywhere in the record
"""

import difflib
import json
import re
import shutil
import sqlite3
import subprocess
import tempfile
from pathlib import Path

from .common import DATASET_DIR, EVIDENCE_DIR, REPO_ROOT, read_csv

OCR_CACHE_DIR = REPO_ROOT / "code" / "cache" / "ocr"

# Resource-id prefix -> owning system. Used when a file does not say.
PREFIX_SYSTEM = {
    "account": "account_service",
    "analytics": "analytics_platform",
    "audit_record": "security_service",
    "backup": "backup_service",
    "cache": "cache_service",
    "data_flow": "integration_service",
    "email_delivery": "email_delivery_service",
    "export": "export_service",
    "legal_hold": "legal_service",
    "marketing": "marketing_platform",
    "object": "object_storage",
    "search": "search_service",
    "support": "support_platform",
    "tombstone": "identity_service",
}
RESOURCE_RE = re.compile(r"\b(" + "|".join(sorted(PREFIX_SYSTEM, key=len, reverse=True)) + r")_(\d+)\b")
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
USER_RE = re.compile(r"\buser_\d+\b")
HASH_RE = re.compile(r"\b[0-9a-f]{64}\b")
PHONE_RE = re.compile(r"\+\d[\d ()-]{6,}\d")
TIME_KEYS = ("observed_at", "recorded_at", "captured_at", "updated_at", "indexed_at")


# ---------------------------------------------------------------- helpers

def system_for(resource_id, declared=None):
    m = RESOURCE_RE.fullmatch(resource_id or "")
    return PREFIX_SYSTEM[m.group(1)] if m else declared


def norm_phone(value):
    return "phone:" + re.sub(r"\D", "", value)


def strings_in(value):
    if isinstance(value, dict):
        return [s for v in value.values() for s in strings_in(v)]
    if isinstance(value, list):
        return [s for v in value for s in strings_in(v)]
    return [str(value)] if value is not None else []


def identifiers_in(value):
    """All identifiers inside any (possibly nested) value, normalized:
    emails lower-cased, phones reduced to digits, hashes and user ids as-is."""
    text = "\n".join(strings_in(value))  # not json.dumps: it turns newlines into "\\n"
    found = {e.lower() for e in EMAIL_RE.findall(text)}
    found |= set(USER_RE.findall(text)) | set(HASH_RE.findall(text))
    found |= {norm_phone(p) for p in PHONE_RE.findall(text)}
    return found


def make_record(file_id, captured_at, resource_id, fields, source, container, system=None, observed_at=None):
    return {
        "file_id": file_id,
        "captured_at": captured_at,
        "observed_at": observed_at or next((fields[k] for k in TIME_KEYS if fields.get(k)), captured_at),
        "system_id": system_for(resource_id, system) or system,
        "resource_id": resource_id,
        "source": source,
        "container": container,
        "fields": fields,
        "identifiers": sorted(identifiers_in(fields)),
    }


def seen_scope(records):
    """For logs and lists, the scope is just the systems that appear."""
    pairs = {(r["system_id"], r["container"]) for r in records}
    return [{"system_id": s, "container": c, "captured_at": None} for s, c in sorted(pairs, key=str)]


# ------------------------------------------------------------------- JSON

def parse_json(path, file_id, captured_at):
    """Walk any JSON layout. A dict with a resource_id is a record; the system
    and timestamp come from the closest ancestor that names them."""
    records, scope = [], []

    def walk(node, system, container, when):
        if isinstance(node, list):
            for item in node:
                walk(item, system, container, when)
            return
        if not isinstance(node, dict):
            return
        system = node.get("data_store") or node.get("system") or system
        container = node.get("collection") or container
        when = next((node[k] for k in TIME_KEYS + ("exported_at",) if node.get(k)), when)
        if "records" in node and system:  # a snapshot section, possibly empty
            scope.append({"system_id": system, "container": container, "captured_at": when})
        if "resource_id" in node:
            records.append(make_record(file_id, captured_at, node["resource_id"], node, "json",
                                       container, system, when))
            return  # nested hits belong to this record's fields
        for key, value in node.items():
            if key == "service_exports":  # {system: {collection: [...]}}
                for sys_name, collections in value.items():
                    for coll, items in collections.items():
                        scope.append({"system_id": sys_name, "container": coll, "captured_at": when})
                        walk(items, sys_name, coll, when)
            elif isinstance(value, (dict, list)):
                walk(value, system, container, when)

    walk(json.loads(path.read_text(encoding="utf-8")), None, None, captured_at)
    return records, scope


# ------------------------------------------------------------- plain text

HANDOVER_RE = re.compile(r"^- (\S+) \| (\S+) \| (\S+) \| (\S+) \| (\S+) \| (.+)$")


def parse_handover(path, file_id, captured_at):
    records = []
    for line in path.read_text(encoding="utf-8").splitlines():
        m = HANDOVER_RE.match(line.strip())
        if m:
            when, system, rid, category, result, subject = m.groups()
            fields = {"record_type": category, "result": result, "subject_reference": subject}
            records.append(make_record(file_id, captured_at, rid, fields, "text", "handover", system, when))
    return records, seen_scope(records)


# ------------------------------------------------------------------- logs

KV_RE = re.compile(r'(\w+)=(?:"((?:[^"\\]|\\.)*)"|([^\s"|,]+))')
LINE_TS_RE = re.compile(r"^(\d{4}-\d\d-\d\dT[\d:]+Z)\s*(.*)$")
# Positional layouts: syslog, [bracket], and | pipe | lines.
SYSLOG_RE = re.compile(r"^<\d+>\d+ \S+ (\S+) (\S+) ")
BRACKET_RE = re.compile(r"^\[\w+\] \[(\w+)\] \[([\w.-]+)\] (\w+):")
PIPE_RE = re.compile(r"^\| \w+ \| (\w+) \| ([\w.-]+) \| (\w+) \|")


def parse_log_line(line):
    """One log line -> flat dict, whatever the layout."""
    m = LINE_TS_RE.match(line.strip())
    if not m:
        return None
    ts, rest = m.groups()
    event = {"ts": ts}
    if rest.startswith("{"):
        try:
            event.update(json.loads(rest))
        except json.JSONDecodeError:
            pass
    else:
        for regex, names in ((SYSLOG_RE, ("service", "trace_id")),
                             (BRACKET_RE, ("service", "trace_id", "event")),
                             (PIPE_RE, ("service", "trace_id", "event"))):
            pm = regex.match(rest)
            if pm:
                event.update(zip(names, pm.groups()))
                break
        # cloud-runtime lines wrap their key/values in an escaped message="..."
        flat = rest.replace('\\"', '"')
        for key, quoted, bare in KV_RE.findall(flat):
            if key != "message":
                event[key] = quoted if quoted or not bare else bare
    event["service"] = event.get("service") or event.get("function") or event.get("logger")
    event["trace_id"] = event.get("trace_id") or event.get("requestId")
    return event


def parse_log(path, file_id, captured_at):
    """Group lines by trace: the "started" line names the lookup key and the
    "completed" line names the resource and result, so a trace is a record."""
    groups = {}
    for n, line in enumerate(path.read_text(encoding="utf-8").splitlines()):
        event = parse_log_line(line)
        if event is None:
            continue
        key = event.get("trace_id") or f"line-{n}"
        groups.setdefault(key, []).append(event)

    records = []
    for trace, events in groups.items():
        rids = list(dict.fromkeys(e["resource_id"] for e in events if e.get("resource_id")))
        for rid in rids:
            merged = {}
            for e in events:
                if e.get("resource_id") in (None, rid):
                    merged.update({k: v for k, v in e.items() if v not in (None, "")})
            merged["events"] = [e.get("event") for e in events]
            records.append(make_record(file_id, captured_at, rid, merged, "log",
                                       merged.get("event"), merged.get("system") or merged.get("service"),
                                       max(e["ts"] for e in events)))
    return records, seen_scope(records)


# -------------------------------------------------------------------- SQL

SQL_HEADER_TS = re.compile(r"Captured at: (\S+)")
TABLE_SYSTEM = {
    "customer_profiles": "account_service",
    "customer_search_documents": "search_service",
    "customer_analytics_profiles": "analytics_platform",
    "support_records": "support_platform",
    "customer_exports": "export_service",
    "connector_subscriptions": "integration_service",
    "backup_restore_entries": "backup_service",
    "security_audit_records": "security_service",
}


def parse_sql(path, file_id, captured_at):
    """Execute the snapshot in an in-memory SQLite DB and read every row.
    Generic tables (record_json) are expanded; the table name is kept as the
    container so primary vs replica copies can be compared later."""
    text = path.read_text(encoding="utf-8")
    m = SQL_HEADER_TS.search(text)
    snapshot_at = m.group(1) if m else captured_at
    db = sqlite3.connect(":memory:")
    db.row_factory = sqlite3.Row
    db.executescript(text)
    records, scope = [], []
    tables = [r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")]
    if "snapshot_scope" in tables:
        for system, at in db.execute("SELECT origin_system, captured_at FROM snapshot_scope"):
            scope.append({"system_id": system, "container": None, "captured_at": at})
    for table in tables:
        if table == "snapshot_scope":
            continue
        table_systems = {r[0] for r in db.execute(f'SELECT DISTINCT origin_system FROM "{table}"')} \
            if "origin_system" in [c[1] for c in db.execute(f'PRAGMA table_info("{table}")')] else set()
        for system in table_systems or {TABLE_SYSTEM.get(table) or table_system_guess(table)}:
            scope.append({"system_id": system, "container": table, "captured_at": snapshot_at})
        for row in db.execute(f'SELECT * FROM "{table}"'):
            fields = dict(row)
            if "record_json" in fields:
                fields.update(json.loads(fields.pop("record_json")))
            system = fields.get("origin_system") or TABLE_SYSTEM.get(table) or table_system_guess(table)
            records.append(make_record(file_id, snapshot_at, fields["resource_id"], fields, "sql",
                                       table, system, fields.get("updated_at") or snapshot_at))
    db.close()
    return records, scope


def table_system_guess(table):
    # customer_profiles_primary / _failover_replica -> account_service, etc.
    for prefix, system in (("customer_profiles", "account_service"), ("search_documents", "search_service")):
        if table.startswith(prefix):
            return system
    return None


# ------------------------------------------------------- PDFs and images

def pdf_text(path):
    gs = shutil.which("gs") or shutil.which("gswin64c")
    if not gs:
        raise RuntimeError("Ghostscript (gs) is required to read PDF evidence")
    out = subprocess.run([gs, "-q", "-dNOPAUSE", "-dBATCH", "-sDEVICE=txtwrite", "-sOutputFile=-", str(path)],
                         capture_output=True, text=True, check=True)
    return out.stdout


def image_text(path, file_id):
    """OCR an image once and cache the text, so normal runs need no OCR tools
    and always see the same text. Upscaling first makes small UI text legible."""
    cache = OCR_CACHE_DIR / f"{file_id}.txt"
    if cache.exists():
        return cache.read_text(encoding="utf-8")
    tesseract = shutil.which("tesseract")
    if not tesseract:
        raise RuntimeError(f"No OCR cache for {file_id} and tesseract is not installed")
    with tempfile.TemporaryDirectory() as tmp:
        source = path
        if shutil.which("sips"):  # macOS built-in image tool
            source = Path(tmp) / "big.png"
            subprocess.run(["sips", "-Z", "4000", str(path), "--out", str(source)], capture_output=True, check=True)
        out = subprocess.run([tesseract, str(source), "-", "--psm", "11"], capture_output=True, text=True, check=True)
    OCR_CACHE_DIR.mkdir(parents=True, exist_ok=True)
    cache.write_text(out.stdout, encoding="utf-8")
    return out.stdout


def parse_document(text, file_id, captured_at, source):
    """Unstructured text: one record per resource id mentioned, carrying the
    nearby lines as context plus the whole document text."""
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    records = {}
    for i, line in enumerate(lines):
        for prefix, number in RESOURCE_RE.findall(line):
            rid = f"{prefix}_{number}"
            rec = records.setdefault(rid, {"context": [], "text": "\n".join(lines)})
            rec["context"].extend(lines[max(0, i - 2): i + 3])
    out = [make_record(file_id, captured_at, None, {"text": "\n".join(lines)}, source, "document_text")]
    for rid, fields in records.items():
        fields["context"] = list(dict.fromkeys(fields["context"]))
        rec = make_record(file_id, captured_at, rid, fields, source, "document")
        rec["identifiers"] = sorted(identifiers_in(fields["context"]))  # whole text would mix subjects
        out.append(rec)
    return out, [{"system_id": r["system_id"], "container": "document", "captured_at": captured_at}
                 for r in out[1:]]


# ------------------------------------------------------------- entry point

def load_manifest():
    return read_csv(DATASET_DIR / "evidence_files.csv")


def parse_file(entry):
    """Returns (records, scope) for one manifest entry."""
    path = DATASET_DIR / entry["file_path"]
    fid, cap = entry["file_id"], entry["captured_at"]
    suffix = path.suffix.lower()
    if suffix == ".json":
        return parse_json(path, fid, cap)
    if suffix == ".log":
        return parse_log(path, fid, cap)
    if suffix == ".sql":
        return parse_sql(path, fid, cap)
    if suffix == ".txt":
        return parse_handover(path, fid, cap)
    if suffix == ".pdf":
        return parse_document(pdf_text(path), fid, cap, "pdf")
    if suffix == ".png":
        return parse_document(image_text(path, fid), fid, cap, "image")
    raise ValueError(f"unsupported evidence type: {path}")


def load_evidence():
    """Parse every manifest file.

    Returns (records, manifest) where each manifest entry gains a "scope"
    list: the systems/tables the file captured, even when they were empty.
    An empty but in-scope snapshot is how absence gets proven."""
    if not EVIDENCE_DIR.exists():
        raise FileNotFoundError(f"dataset not found at {EVIDENCE_DIR}")
    manifest = load_manifest()
    records = []
    for entry in manifest:
        file_records, entry["scope"] = parse_file(entry)
        records.extend(file_records)
    snap_ocr_emails(records)
    return records, manifest


def known_emails():
    emails = {r["email"].lower() for r in read_csv(DATASET_DIR / "user_identities.csv")}
    for r in read_csv(DATASET_DIR / "user_audit_log.csv"):
        if r["field_name"] == "email":
            emails |= {r["old_value"].lower(), r["new_value"].lower()}
    return emails


def snap_ocr_emails(records, threshold=0.95):
    """OCR sometimes misreads one character (ingrid.dahli -> ingrid.dahl).
    For image records only, replace an unknown email with the single known
    email that is nearly identical. The bar is strict so look-alike decoys
    (g.silva76.jr vs g.silva76) are never merged."""
    known = known_emails()
    for rec in records:
        if rec["source"] != "image":
            continue
        fixed = []
        for ident in rec["identifiers"]:
            if "@" in ident and ident not in known:
                close = difflib.get_close_matches(ident, known, n=2, cutoff=threshold)
                if len(close) == 1:
                    rec.setdefault("ocr_corrections", {})[ident] = close[0]
                    ident = close[0]
            fixed.append(ident)
        rec["identifiers"] = sorted(set(fixed))
