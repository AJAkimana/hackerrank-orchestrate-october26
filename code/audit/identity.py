# Author: AJAkimana
"""Work out who a request is about, past and present.

A request gives one email. It may be the user's current email or one they
used before. Old systems and evidence can still hold any identifier the user
ever had, so we rebuild the full set:

    current snapshot (user_identities.csv)
  + every old/new value in the change history (user_audit_log.csv)
  + sha256(email) for every email, since email_hash is exactly that

Identifiers use the same normalized form as audit.evidence.identifiers_in,
so a subject's identifiers can be intersected directly with a record's.
"""

import hashlib

from .common import DATASET_DIR, read_csv
from .evidence import norm_phone


def norm_email(value):
    return value.strip().lower()


def email_hash(email):
    return hashlib.sha256(norm_email(email).encode("utf-8")).hexdigest()


class IdentityIndex:
    """Lookup from any email a user ever had to that user's full identity."""

    def __init__(self, identities=None, audit_log=None):
        identities = identities if identities is not None else read_csv(
            DATASET_DIR / "user_identities.csv")
        audit_log = audit_log if audit_log is not None else read_csv(
            DATASET_DIR / "user_audit_log.csv")
        self.users = {row["user_id"]: row for row in identities}
        self.history = {}
        for row in sorted(audit_log, key=lambda r: r["event_time"]):
            self.history.setdefault(row["user_id"], []).append(row)

        # email -> (user_id, how it matched, audit_id or "")
        self.by_email = {}
        for user_id, row in self.users.items():
            self.by_email[norm_email(row["email"])] = (user_id, "current", "")
        for user_id, changes in self.history.items():
            for change in changes:
                if change["field_name"] == "email":
                    # setdefault: a current email always wins over an old one
                    self.by_email.setdefault(norm_email(
                        change["old_value"]), (user_id, "historical", change["audit_id"]))
                    self.by_email.setdefault(norm_email(
                        change["new_value"]), (user_id, "historical", change["audit_id"]))

    def resolve(self, email):
        """Return a subject dict for this email, or None if nobody matches."""
        hit = self.by_email.get(norm_email(email))
        if hit is None:
            return None
        user_id, matched_via, audit_id = hit
        row = self.users[user_id]
        changes = self.history.get(user_id, [])

        emails = {norm_email(row["email"])}
        phones = {row["phone"]}
        hashes = {row["email_hash"]}
        for change in changes:
            values = {change["old_value"], change["new_value"]} - {""}
            if change["field_name"] == "email":
                emails |= {norm_email(v) for v in values}
            elif change["field_name"] == "phone":
                phones |= values
            elif change["field_name"] == "email_hash":
                hashes |= values
        hashes |= {email_hash(e) for e in emails}

        return {
            "user_id": user_id,
            "name": row["name"],
            "request_email": norm_email(email),
            "matched_via": matched_via,          # "current" or "historical"
            "matched_audit_id": audit_id,        # the change that proves an old email
            "current_email": norm_email(row["email"]),
            "emails": sorted(emails),
            "phones": sorted(phones),
            "email_hashes": sorted(hashes),
            "history": changes,
            "identifiers": sorted(emails | hashes | {norm_phone(p) for p in phones} | {user_id}),
        }
