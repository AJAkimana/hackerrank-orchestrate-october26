# Author: AJAkimana
"""Find every resource that belongs to a request's subject.

Three independent signals, from strongest to weakest:

1. identifier  - an evidence record of the resource carries one of the
                 subject's identifiers (email, phone, hash, user_id).
2. catalog     - a LINK_RESOURCE_IDENTITY event names the subject as owner.
                 It may also give an alias (a statement number, a file
                 name) that a document uses instead of the resource id.
3. activity    - the deletion worker acted on the resource around the
                 time the request was reported. Deleted or anonymized
                 records have no identifiers left, so this is often the
                 only trail. Windows of different requests overlap, so a
                 resource is dropped when its evidence belongs to someone
                 else.

Only evidence captured, and activity logged, at or before audit_at is used.
"""

import re
from collections import defaultdict
from datetime import datetime, timedelta

from .common import DATASET_DIR, read_csv

# Deletion-worker events for a request cluster around reported_at: the
# primary account is submitted ~1h before it, other systems follow within
# ~2h after. (window start, window end, expected offset) per resource kind.
ACCOUNT_TIMING = (timedelta(hours=-1.5),
                  timedelta(hours=0.25), timedelta(hours=-1))
OTHER_TIMING = (timedelta(hours=-1), timedelta(hours=2.25),
                timedelta(hours=0.5))


# The workflow's reported_status mirrors its account-deletion result.
STATUS_RESULT = {"COMPLETE": "SUCCESS",
                 "PARTIALLY_COMPLETE": "PARTIAL", "NOT_STARTED": "FAILED"}


def shows_absence(fields):
    """True for a lookup that found nothing (404, zero rows, NOT_FOUND)."""
    return (str(fields.get("http_status", fields.get("status_code", ""))) == "404"
            or str(fields.get("rows", "")) == "0"
            or str(fields.get("result", "")).upper() == "NOT_FOUND"
            or ("profile" in fields and fields["profile"] is None))


def timing(resource):
    return ACCOUNT_TIMING if resource.startswith("account_") else OTHER_TIMING


LINK_RE = re.compile(r"linked (\S+) \(([^)]+)\) to (\S+) and (user_\d+)"
                     r"|confirmed (\S+) \(([^)]+)\) belongs only to (\S+) and (user_\d+)")


def ts(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


class Linker:
    """Built once; link(request, subject) is then called per case."""

    def __init__(self, records, identity_index, activity=None):
        self.activity = activity if activity is not None else read_csv(
            DATASET_DIR / "system_activity.csv")
        self.identity_index = identity_index

        # identifier -> user_id, for every user, to know who owns a record
        self.owner_of = {}
        for user_id, row in identity_index.users.items():
            subject = identity_index.resolve(row["email"])
            for ident in subject["identifiers"]:
                self.owner_of[ident] = user_id

        self.records_by_resource = defaultdict(list)
        self.documents = []  # whole-document records (resource_id None)
        for rec in records:
            if rec["resource_id"]:
                self.records_by_resource[rec["resource_id"]].append(rec)
            else:
                self.documents.append(rec)

        # catalog links: resource -> (owner user_id, alias, event)
        self.catalog = {}
        for event in self.activity:
            if event["event_type"] != "LINK_RESOURCE_IDENTITY":
                continue
            m = LINK_RE.search(event["details"])
            if m:
                groups = [g for g in m.groups() if g is not None]
                resource, alias, _email, user_id = groups
                self.catalog[resource] = (user_id, alias, event)

    # ------------------------------------------------------------ helpers

    def owners(self, record):
        return {self.owner_of[i] for i in record["identifiers"] if i in self.owner_of}

    def visible(self, records, audit_at):
        return [r for r in records if ts(r["captured_at"]) <= audit_at]

    # --------------------------------------------------------------- main

    def link(self, request, subject):
        """Return {resource_id: link} where a link lists its reasons and the
        evidence records / activity events that support it."""
        audit_at = ts(request["audit_at"])
        user_id = subject["user_id"]
        ids = set(subject["identifiers"])
        links = {}

        def add(resource, system, reason, support):
            link = links.setdefault(resource, {
                "resource_id": resource, "system_id": system,
                "reasons": [], "records": [], "events": []})
            if reason not in link["reasons"]:
                link["reasons"].append(reason)
            key = "events" if reason == "activity" or "activity_id" in support else "records"
            if support not in link[key]:
                link[key].append(support)

        # 1. identifier matches in evidence visible at audit time. A lookup
        #    that came back "not found" only shows someone searched for the
        #    identifier, not that the resource stores it, so it is skipped.
        for resource, recs in self.records_by_resource.items():
            for rec in self.visible(recs, audit_at):
                if ids & set(rec["identifiers"]) and not shows_absence(rec["fields"]):
                    add(resource, rec["system_id"], "identifier", rec)

        # 2. Catalog links (LINK_RESOURCE_IDENTITY) are activity claims. On
        #    the samples, resources linked only by the catalog are never part
        #    of the answer, so they are used just to exclude other people's
        #    resources (see belongs_to_someone_else), not to add any.

        # 3. deletion-worker activity around reported_at
        reported = ts(request["reported_at"])
        for event in self.activity:
            if event["source_system"] != "deletion_worker":
                continue
            resource = event["resource_id"]
            before, after, _ = timing(resource)
            when = ts(event["event_time"])
            if not (max(ts(request["requested_at"]), reported + before) <= when
                    <= min(audit_at, reported + after)):
                continue
            if self.belongs_to_someone_else(resource, user_id, audit_at):
                continue
            add(resource, event["target_system"], "activity", event)

        return links

    # ------------------------------------------------- global attribution

    def link_all(self, requests, subjects):
        """Link every request at once.

        The deletion worker's activity stream is shared by all requests, so
        an activity-only resource is a claim several overlapping requests
        may make. Claims are settled globally:

          * an identifier link beats any activity-only claim;
          * a subject has exactly one primary account. Accounts are matched
            to requests one-to-one, best fit first. The fit is the timing
            (submitted ~1h before reported_at) plus a penalty when the
            event's result disagrees with the request's reported_status,
            because the workflow derives that status from this very event
            (COMPLETE <- SUCCESS, PARTIALLY_COMPLETE <- PARTIAL,
            NOT_STARTED <- FAILED);
          * any other contested resource goes to the request whose own
            account deletion happened just before it.
        """
        links = {r["case_id"]: self.link(
            r, subjects[r["case_id"]]) for r in requests}
        by_case = {r["case_id"]: r for r in requests}

        def activity_only(case, resource):
            return links[case][resource]["reasons"] == ["activity"]

        def is_account(resource):
            return resource.startswith("account_")

        def cost(case, resource):
            event = links[case][resource]["events"][0]
            offset = ts(event["event_time"]) - ts(by_case[case]["reported_at"])
            hours = abs(offset - timing(resource)[2]).total_seconds() / 3600
            if is_account(resource) and STATUS_RESULT.get(by_case[case]["reported_status"]) != event["reported_result"]:
                hours += 10
            return hours

        def follow_cost(case, resource):
            """A request's other resources are processed right after its own
            account, so measure the gap from that account's event."""
            when = ts(links[case][resource]["events"][0]["event_time"])
            starts = [ts(e["event_time"]) for r, link in links[case].items() if is_account(r)
                      for e in link["events"] if e.get("source_system") == "deletion_worker"]
            if not starts:
                return cost(case, resource)
            gap = (when - max(starts)).total_seconds() / 3600
            return gap if gap >= 0 else 10 - gap

        claims = defaultdict(set)  # activity-only resource -> claiming cases
        strong = set()             # resources some request links for sure
        for case, case_links in links.items():
            for r in case_links:
                (claims[r].add(case) if activity_only(
                    case, r) else strong.add(r))
        for r in strong & set(claims):
            for case in claims.pop(r):
                del links[case][r]

        # accounts: one-to-one, best fit first
        has_account = {case for case, cl in links.items()
                       if any(is_account(r) and not activity_only(case, r) for r in cl)}
        pairs = sorted((cost(case, r), case, r) for r, cases in claims.items()
                       if is_account(r) for case in cases)
        taken = set()
        for _, case, r in pairs:
            if case not in has_account and r not in taken:
                has_account.add(case)
                taken.add(r)
                claims[r] = {case}
        for case, case_links in links.items():
            for r in [r for r in case_links if is_account(r) and activity_only(case, r)]:
                if claims.get(r) != {case}:
                    del case_links[r]

        # everything else: the request whose account was processed just
        # before it wins
        for r, cases in claims.items():
            if not is_account(r) and len(cases) > 1:
                best = min(sorted(cases), key=lambda c: follow_cost(c, r))
                for case in cases - {best}:
                    del links[case][r]
        return links

    def records_for(self, resource, link):
        """Every evidence record about a linked resource: once the resource
        is ours, a 404 or a redacted copy is just as relevant as a match."""
        records = list(self.records_by_resource.get(resource, []))
        return records + [r for r in link["records"] if r not in records]

    def belongs_to_someone_else(self, resource, user_id, audit_at):
        catalog = self.catalog.get(resource)
        if catalog and catalog[0] != user_id:
            return True
        owners = set()
        for rec in self.visible(self.records_by_resource.get(resource, []), audit_at):
            owners |= self.owners(rec)
        return bool(owners) and user_id not in owners
