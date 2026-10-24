# Author: AJAkimana
"""What state is each linked resource in at audit_at?

For every resource we linked to the subject we decide:

    treatment  what policy requires (deletion_rules.csv):
               DELETE | REDACT | ANONYMIZE | RETAIN | FLOW | BACKUP
    status     what the evidence shows at audit_at:
               ABSENT          the record is gone
               EXPOSED         present and still carrying identifiers
               CLEAN           present without prohibited identifiers
                               (redacted / anonymized)
               PRESENT         present (for records that must be kept)
               ACTIVE/DISABLED a data flow is running / stopped
               RESTORABLE/BLOCKED a backup can / cannot be restored
    evidence   the file that proves it

Rules for reading the evidence:
  * only files captured at or before audit_at count;
  * the most recent explicit observation of the resource wins;
  * activity results are claims, never proof of state;
  * with no explicit observation, the latest snapshot that covered the
    system and does not contain the resource proves it is absent - but
    only for records that must be deleted; anything else stays UNKNOWN.
"""

from .linking import ts

DIRECT_IDENTIFIERS = (
    "email", "phone", "full_name", "name", "display_name", "email_hash",
    "requester_name", "requester_email", "requester_phone", "owner_email",
    "owner_phone", "customer_email", "matched_value", "subject_selector")
# Anonymized analytics must not even keep the internal link to the user.
ATTRIBUTION = ("customer_reference", "user_id")
TRUE = {"true", "1", "yes", "True"}
FALSE = {"false", "0", "no", "False"}
WORKER_TREATMENT = {"DELETE_RECORD": "DELETE", "REDACT_RECORD": "REDACT",
                    "ANONYMIZE_RECORD": "ANONYMIZE"}
SNAPSHOT_SOURCES = ("sql", "json")


def kind(resource):
    return resource.rsplit("_", 1)[0]


def flag(value):
    """Booleans arrive as True/1/"true"/"1" depending on the format."""
    text = str(value)
    return True if text in TRUE else False if text in FALSE else None


def filled(value):
    return value not in (None, "", "null", "None")


# ------------------------------------------------------------- treatment

def treatment_for(resource, link):
    k = kind(resource)
    if k == "data_flow":
        return "FLOW"
    if k == "backup":
        return "BACKUP"
    if k in ("audit_record", "legal_hold"):
        return "RETAIN"
    if k == "tombstone":
        return "REDACT"  # ACCOUNT_TOMBSTONE: keep user_id, drop identifiers
    if k in ("account", "search", "export", "cache", "marketing", "object"):
        return "DELETE"
    # analytics / support / email logs: the worker's own operation is the
    # clearest statement of which rule applied (activity is a claim about the
    # result, not about the policy)
    for event in link["events"]:
        if event.get("event_type") in WORKER_TREATMENT:
            return WORKER_TREATMENT[event["event_type"]]
    fields = [r["fields"] for r in link["records"]]
    if k == "analytics":
        return "DELETE" if any("email_opt_in" in f for f in fields) else "ANONYMIZE"
    if k == "support":
        attachment = any("ATTACHMENT" in str(f.get("record_type", "")).upper()
                         or "attachment" in str(f.get("collection_name", "")) or f.get("file")
                         for f in fields) \
            or any(r["container"] == "ticket_attachments" for r in link["records"]) \
            or any(r["source"] in ("pdf", "image") and "attachment" in r["fields"].get("text", "").lower()
                   for r in link["records"])
        return "DELETE" if attachment else "REDACT"
    if k == "email_delivery":
        return "REDACT"
    return "DELETE"


# ---------------------------------------------------------- one record

def absent(f):
    if str(f.get("http_status", f.get("status_code", ""))) == "404":
        return True
    if str(f.get("rows", "")) == "0":
        return True
    if str(f.get("result", "")).upper() in ("NOT_FOUND", "ABSENT", "DELETED"):
        return True
    if "profile" in f and f["profile"] is None:
        return True
    hits = f.get("hits")
    if isinstance(hits, dict) and hits.get("total") == 0:
        return True
    return str(f.get("total_hits", "")) == "0"


def exposed(f, treatment):
    """Does a present record still carry identifiers policy forbids?"""
    result = str(f.get("result", "")).upper()
    if result in ("IDENTIFIABLE", "EXPOSED"):
        return True
    if result in ("ANONYMIZED", "REDACTED"):
        return False
    if f.get("detector") == "direct_identifier":
        return True
    if str(f.get("direct_identifiers", "")) == "0":
        return False
    values = dict(f)
    for doc in (f.get("hits") or {}).get("documents", []) if isinstance(f.get("hits"), dict) else []:
        values.update({k: v for k, v in doc.items() if filled(v)})
    if isinstance(f.get("profile"), dict):
        values.update(f["profile"])
    keys = DIRECT_IDENTIFIERS + \
        (ATTRIBUTION if treatment == "ANONYMIZE" else ())
    return any(filled(values.get(k)) for k in keys)


def classify(record, treatment, subject_ids):
    """Status shown by one evidence record, or None if it says nothing."""
    f = record["fields"]
    if record["source"] in ("pdf", "image"):
        return classify_document(record, treatment, subject_ids)
    if treatment == "FLOW":
        enabled = flag(f.get("enabled"))
        result = str(f.get("result", "")).upper()
        if result in ("ACTIVE", "DISABLED"):
            return result
        return None if enabled is None else ("ACTIVE" if enabled else "DISABLED")
    if treatment == "BACKUP":
        result = str(f.get("result", "")).upper()
        if result == "ACTIVE":
            return "RESTORABLE"
        if result == "BLOCKED" or f.get("decision") == "deny":
            return "BLOCKED"
        allowed = flag(f.get("restore_allowed"))
        if allowed is None and flag(f.get("eligible")) is not None:
            allowed = flag(f.get("eligible")) and not flag(
                f.get("deletion_block"))
        return None if allowed is None else ("RESTORABLE" if allowed else "BLOCKED")
    if absent(f):
        return "ABSENT"
    if treatment == "RETAIN":
        return "PRESENT"
    if treatment in ("REDACT", "ANONYMIZE"):
        return "EXPOSED" if exposed(f, treatment) else "CLEAN"
    return "EXPOSED"  # DELETE: any surviving copy is a remaining record


def classify_document(record, treatment, subject_ids):
    """PDFs and screenshots: the resource appears next to the subject."""
    context = " ".join(record["fields"].get("context", [])).lower()
    if treatment == "FLOW":
        return "DISABLED" if "disabled" in context or "paused" in context else "ACTIVE"
    if treatment == "BACKUP":
        return "BLOCKED" if "blocked" in context else "RESTORABLE"
    if treatment == "RETAIN":
        return "PRESENT"
    if set(record["identifiers"]) & subject_ids:
        return "EXPOSED"
    return "CLEAN" if treatment in ("REDACT", "ANONYMIZE") else "EXPOSED"


# ------------------------------------------------------------ resolver

class StateResolver:
    def __init__(self, manifest):
        # snapshot files and the systems they fully captured
        self.snapshots = []
        for entry in manifest:
            path = entry["file_path"]
            if not path.endswith((".sql", ".json")):
                continue
            systems = {s["system_id"]
                       for s in entry.get("scope", []) if s["system_id"]}
            self.snapshots.append(
                (ts(entry["captured_at"]), entry["file_id"], systems))
        self.snapshots.sort()

    def resolve(self, request, subject, links):
        """Return {resource_id: state dict} for one request."""
        audit_at = ts(request["audit_at"])
        subject_ids = set(subject["identifiers"])
        states = {}
        for resource, link in links.items():
            treatment = treatment_for(resource, link)
            observations = []
            for rec in link_records(link):
                if ts(rec["captured_at"]) > audit_at:
                    continue
                status = classify(rec, treatment, subject_ids)
                if status:
                    when = ts(rec["captured_at"] if rec["source"]
                              == "sql" else rec["observed_at"])
                    observations.append(
                        (when, ts(rec["captured_at"]), status, rec["file_id"]))
            basis = "observed"
            # Absence from a snapshot only proves something when absence is
            # the goal; an anonymized or retained record should still be there.
            if not observations and treatment == "DELETE":
                found = self.absence_snapshot(link["system_id"], audit_at)
                if found:
                    observations.append(
                        (found[0], found[0], "ABSENT", found[1]))
                    basis = "snapshot_absence"
            if not observations:
                states[resource] = {"resource_id": resource, "system_id": link["system_id"],
                                    "treatment": treatment, "status": "UNKNOWN",
                                    "evidence_id": "", "basis": "none", "history": []}
                continue
            # latest observation wins; at equal times a worse state wins
            severity = {"EXPOSED": 3, "ACTIVE": 3,
                        "RESTORABLE": 3, "PRESENT": 2}
            observations.sort(key=lambda o: (
                o[0], o[1], severity.get(o[2], 1)))
            when, _, status, file_id = observations[-1]
            states[resource] = {
                "resource_id": resource, "system_id": link["system_id"],
                "treatment": treatment, "status": status, "evidence_id": file_id,
                "observed_at": when.isoformat(), "basis": basis,
                "history": [(o[0].isoformat(), o[2], o[3]) for o in observations],
            }
        return states

    def absence_snapshot(self, system_id, audit_at):
        latest = None
        for when, file_id, systems in self.snapshots:
            if when <= audit_at and system_id in systems:
                latest = (when, file_id)
        return latest


def link_records(link):
    """Evidence records behind a link: those it was found with, plus any
    other record of the same resource (attached by the caller)."""
    return link.get("all_records", link["records"])
