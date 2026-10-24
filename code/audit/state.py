# Author: AJAkimana
"""What state is each linked resource in at audit_at?

For every resource linked to the subject we decide:

    treatment  what policy requires (deletion_rules.csv):
               DELETE | REDACT | ANONYMIZE | RETAIN | FLOW | BACKUP
    status     what the evidence shows at audit_at:
               ABSENT              the record is gone
               EXPOSED             present and still carrying identifiers
               CLEAN               present without prohibited identifiers
                                   (redacted / anonymized)
               PRESENT             present (for records that must be kept)
               ACTIVE / DISABLED   a data flow is running / stopped
               RESTORABLE / BLOCKED a backup can / cannot be restored
               UNKNOWN             no visible evidence says anything
    evidence   the file that proves it

Rules for reading the evidence:
  * only files captured at or before audit_at count;
  * the most recent explicit observation of the resource wins;
  * activity results are claims, never proof of state;
  * with no explicit observation, the latest snapshot that covered the
    system and does not contain the resource proves it is absent - but
    only for records that must be deleted; anything else stays UNKNOWN.
"""

from .common import parse_time

DIRECT_IDENTIFIERS = (
    "email", "phone", "full_name", "name", "display_name", "email_hash",
    "requester_name", "requester_email", "requester_phone", "owner_email",
    "owner_phone", "customer_email", "matched_value", "subject_selector")
# Anonymized analytics must not even keep the internal link to the user.
ATTRIBUTION = ("customer_reference", "user_id")
TRUE = {"true", "1", "yes", "True"}
FALSE = {"false", "0", "no", "False"}
# The deletion worker's attempted operation tells which rule applied.
WORKER_TREATMENT = {"DELETE_RECORD": "DELETE", "REDACT_RECORD": "REDACT",
                    "ANONYMIZE_RECORD": "ANONYMIZE"}
# Resource kinds whose treatment never depends on the record itself.
FIXED_TREATMENT = {
    "data_flow": "FLOW", "backup": "BACKUP",
    "audit_record": "RETAIN", "legal_hold": "RETAIN",
    "tombstone": "REDACT",  # ACCOUNT_TOMBSTONE: keep user_id, drop identifiers
    "account": "DELETE", "search": "DELETE", "export": "DELETE",
    "cache": "DELETE", "marketing": "DELETE", "object": "DELETE",
}
# At equal times, the state that needs action wins, to stay on the safe side.
SEVERITY = {"EXPOSED": 3, "ACTIVE": 3, "RESTORABLE": 3, "PRESENT": 2}


def kind(resource):
    """account_005 -> account, data_flow_12 -> data_flow."""
    return resource.rsplit("_", 1)[0]


def flag(value):
    """Booleans arrive as True/1/"true"/"1" depending on the format."""
    text = str(value)
    return True if text in TRUE else False if text in FALSE else None


def filled(value):
    return value not in (None, "", "null", "None")


# ------------------------------------------------------------- treatment

def treatment_for(resource, link):
    """Which deletion rule applies to this resource.

    Most kinds have a fixed rule. Analytics and support records depend on
    what the record is: the deletion worker's own attempted operation says
    so most clearly; otherwise the record's fields decide (a marketing
    opt-in record is deleted, a support attachment is deleted, a support
    message is redacted).
    """
    k = kind(resource)
    if k in FIXED_TREATMENT:
        return FIXED_TREATMENT[k]
    for event in link["events"]:
        if event.get("event_type") in WORKER_TREATMENT:
            return WORKER_TREATMENT[event["event_type"]]
    if k == "analytics":
        is_marketing = any("email_opt_in" in r["fields"] for r in link["records"])
        return "DELETE" if is_marketing else "ANONYMIZE"
    if k == "support":
        return "DELETE" if is_attachment(link["records"]) else "REDACT"
    if k == "email_delivery":
        return "REDACT"
    return "DELETE"


def is_attachment(records):
    """A support record is an attachment (deleted whole) rather than a
    conversation (redacted) when any of its records says so."""
    for r in records:
        f = r["fields"]
        if ("ATTACHMENT" in str(f.get("record_type", "")).upper()
                or "attachment" in str(f.get("collection_name", ""))
                or f.get("file")
                or r["container"] == "ticket_attachments"
                or (r["source"] in ("pdf", "image")
                    and "attachment" in f.get("text", "").lower())):
            return True
    return False


# ---------------------------------------------------------- one record

def absent(f):
    """Does this record say the resource does not exist? Each format says it
    differently: HTTP 404, zero rows, a NOT_FOUND result, a null profile,
    or a search with no hits."""
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
    """Does a present record still carry identifiers policy forbids?

    Explicit verdicts in the record (IDENTIFIABLE, REDACTED, a PII detector
    hit) win. Otherwise look for any filled direct-identifier field,
    including inside nested search hits and profiles. For anonymization the
    internal user link (customer_reference / user_id) also counts.
    """
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
    hits = f.get("hits")
    for doc in hits.get("documents", []) if isinstance(hits, dict) else []:
        values.update({k: v for k, v in doc.items() if filled(v)})
    if isinstance(f.get("profile"), dict):
        values.update(f["profile"])
    keys = DIRECT_IDENTIFIERS + (ATTRIBUTION if treatment == "ANONYMIZE" else ())
    return any(filled(values.get(k)) for k in keys)


def classify(record, treatment, subject_ids):
    """Status shown by one evidence record, or None if it says nothing."""
    f = record["fields"]
    if record["source"] in ("pdf", "image"):
        return classify_document(record, treatment, subject_ids)
    if treatment == "FLOW":
        return flow_status(f)
    if treatment == "BACKUP":
        return backup_status(f)
    if absent(f):
        return "ABSENT"
    if treatment == "RETAIN":
        return "PRESENT"
    if treatment in ("REDACT", "ANONYMIZE"):
        return "EXPOSED" if exposed(f, treatment) else "CLEAN"
    return "EXPOSED"  # DELETE: any surviving copy is a remaining record


def flow_status(f):
    """ACTIVE / DISABLED from a connector record, or None."""
    result = str(f.get("result", "")).upper()
    if result in ("ACTIVE", "DISABLED"):
        return result
    enabled = flag(f.get("enabled"))
    return None if enabled is None else ("ACTIVE" if enabled else "DISABLED")


def backup_status(f):
    """RESTORABLE / BLOCKED from a backup record, or None. Restore policy
    logs use eligible + deletion_block instead of restore_allowed."""
    result = str(f.get("result", "")).upper()
    if result == "ACTIVE":
        return "RESTORABLE"
    if result == "BLOCKED" or f.get("decision") == "deny":
        return "BLOCKED"
    allowed = flag(f.get("restore_allowed"))
    if allowed is None and flag(f.get("eligible")) is not None:
        allowed = flag(f.get("eligible")) and not flag(f.get("deletion_block"))
    return None if allowed is None else ("RESTORABLE" if allowed else "BLOCKED")


def classify_document(record, treatment, subject_ids):
    """PDFs and screenshots: read the lines around the resource id."""
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
    """Decides the state of a request's linked resources at its audit_at."""

    def __init__(self, manifest):
        # (captured_at, file_id, systems covered) for every SQL/JSON snapshot,
        # oldest first; used to prove absence when nothing else is known
        self.snapshots = []
        for entry in manifest:
            if not entry["file_path"].endswith((".sql", ".json")):
                continue
            systems = {s["system_id"] for s in entry.get("scope", []) if s["system_id"]}
            self.snapshots.append((parse_time(entry["captured_at"]), entry["file_id"], systems))
        self.snapshots.sort()

    def resolve(self, request, subject, links):
        """Return {resource_id: state} for one request's links.

        A state holds treatment, status, evidence_id, observed_at, the basis
        ("observed", "snapshot_absence" or "none") and the full observation
        history for debugging.
        """
        audit_at = parse_time(request["audit_at"])
        subject_ids = set(subject["identifiers"])
        states = {}
        for resource, link in links.items():
            treatment = treatment_for(resource, link)
            observations = self.observations(link, treatment, subject_ids, audit_at)
            basis = "observed"
            # Absence from a snapshot only proves something when absence is
            # the goal; an anonymized or retained record should still exist.
            if not observations and treatment == "DELETE":
                found = self.absence_snapshot(link["system_id"], audit_at)
                if found:
                    observations = [(found[0], found[0], "ABSENT", found[1])]
                    basis = "snapshot_absence"
            states[resource] = self.state(resource, link, treatment, observations, basis)
        return states

    @staticmethod
    def observations(link, treatment, subject_ids, audit_at):
        """(observed time, capture time, status, file_id) for every visible
        record of the resource that says something about its state. SQL rows
        are timed by the snapshot, since updated_at may be much older."""
        found = []
        for rec in link.get("all_records", link["records"]):
            captured = parse_time(rec["captured_at"])
            if captured > audit_at:
                continue
            status = classify(rec, treatment, subject_ids)
            if status:
                when = captured if rec["source"] == "sql" else parse_time(rec["observed_at"])
                found.append((when, captured, status, rec["file_id"]))
        return found

    @staticmethod
    def state(resource, link, treatment, observations, basis):
        """The latest observation becomes the state (UNKNOWN if none)."""
        base = {"resource_id": resource, "system_id": link["system_id"], "treatment": treatment}
        if not observations:
            return {**base, "status": "UNKNOWN", "evidence_id": "", "basis": "none", "history": []}
        observations.sort(key=lambda o: (o[0], o[1], SEVERITY.get(o[2], 1)))
        when, _, status, file_id = observations[-1]
        return {**base, "status": status, "evidence_id": file_id,
                "observed_at": when.isoformat(), "basis": basis,
                "history": [(o[0].isoformat(), o[2], o[3]) for o in observations]}

    def absence_snapshot(self, system_id, audit_at):
        """(time, file_id) of the latest snapshot at or before audit_at that
        covered this system, or None."""
        latest = None
        for when, file_id, systems in self.snapshots:
            if when <= audit_at and system_id in systems:
                latest = (when, file_id)
        return latest
