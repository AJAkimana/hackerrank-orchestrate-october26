# Author: AJAkimana
"""Find every resource that belongs to a request's subject.

Two signals add a resource to a request:

  identifier  an evidence record of the resource stores one of the
              subject's identifiers (email, phone, email hash, user_id).
  activity    the deletion worker acted on the resource around the time the
              request was reported. Deleted or anonymized records have no
              identifiers left, so this is often their only trail.

Catalog events (LINK_RESOURCE_IDENTITY) name an owner for a few resources.
On the samples a resource linked only by the catalog is never part of the
answer, so the catalog is used only to rule out other people's resources.

All requests share one activity stream, so activity claims from different
requests can collide; link_all() settles them across every request at once.
Only evidence captured, and activity logged, at or before audit_at is used.
"""

import re
from collections import defaultdict
from datetime import timedelta

from .common import DATASET_DIR, parse_time, read_csv

# When does the deletion worker touch a request's resources, relative to the
# request's reported_at? The primary account is submitted ~1h before it and
# the other systems follow within ~2h. Each tuple is
# (window start, window end, typical offset).
ACCOUNT_TIMING = (timedelta(hours=-1.5), timedelta(hours=0.25), timedelta(hours=-1))
OTHER_TIMING = (timedelta(hours=-1), timedelta(hours=2.25), timedelta(hours=0.5))

# The workflow's reported_status is derived from its account-deletion result.
STATUS_RESULT = {"COMPLETE": "SUCCESS", "PARTIALLY_COMPLETE": "PARTIAL",
                 "NOT_STARTED": "FAILED"}
# Added to an account's fit when its result contradicts reported_status:
# larger than any timing difference, so a consistent account always wins.
STATUS_MISMATCH_PENALTY = 10
# Added to the gap when a resource was processed before the request's own
# account, which the worker never does for its own request.
BEFORE_ACCOUNT_PENALTY = 10

# "Data catalog linked R (alias) to email and user_N." and the attachment
# variant "... confirmed R (alias) belongs only to email and user_N; ..."
CATALOG_RE = re.compile(
    r"(?:linked|confirmed) (\S+) \([^)]+\) (?:to|belongs only to) \S+ and (user_\d+)")


def is_account(resource):
    return resource.startswith("account_")


def timing(resource):
    """The (start, end, typical offset) window for this kind of resource."""
    return ACCOUNT_TIMING if is_account(resource) else OTHER_TIMING


def shows_absence(fields):
    """True for a lookup that found nothing (404, zero rows, NOT_FOUND)."""
    return (str(fields.get("http_status", fields.get("status_code", ""))) == "404"
            or str(fields.get("rows", "")) == "0"
            or str(fields.get("result", "")).upper() == "NOT_FOUND"
            or ("profile" in fields and fields["profile"] is None))


def activity_only(link):
    """True when the deletion worker's activity is the only evidence."""
    return link["reasons"] == ["activity"]


def worker_times(link):
    return [parse_time(e["event_time"]) for e in link["events"]
            if e.get("source_system") == "deletion_worker"]


class Linker:
    """Indexes evidence once; link_all() then links any set of requests."""

    def __init__(self, records, identity_index, activity=None):
        self.activity = activity if activity is not None else read_csv(
            DATASET_DIR / "system_activity.csv")

        # identifier -> user_id for every known user, to tell who owns a record
        self.owner_of = {}
        for user_id, row in identity_index.users.items():
            for ident in identity_index.resolve(row["email"])["identifiers"]:
                self.owner_of[ident] = user_id

        self.records_by_resource = defaultdict(list)
        for rec in records:
            if rec["resource_id"]:
                self.records_by_resource[rec["resource_id"]].append(rec)

        # resource -> (owner user_id, catalog event)
        self.catalog = {}
        for event in self.activity:
            if event["event_type"] == "LINK_RESOURCE_IDENTITY":
                m = CATALOG_RE.search(event["details"])
                if m:
                    self.catalog[m.group(1)] = (m.group(2), event)

    # ------------------------------------------------------------- lookups

    def owners(self, record):
        """Users whose identifiers appear in an evidence record."""
        return {self.owner_of[i] for i in record["identifiers"] if i in self.owner_of}

    @staticmethod
    def visible(records, audit_at):
        """Records captured at or before the audit time."""
        return [r for r in records if parse_time(r["captured_at"]) <= audit_at]

    def records_for(self, resource, link):
        """Every evidence record about a linked resource: once the resource
        is ours, a 404 or a redacted copy is as relevant as a match."""
        records = list(self.records_by_resource.get(resource, []))
        return records + [r for r in link["records"] if r not in records]

    def belongs_to_someone_else(self, resource, user_id, audit_at):
        """True when the catalog or the visible evidence names an owner for
        the resource and that owner is not this user."""
        catalog = self.catalog.get(resource)
        if catalog and catalog[0] != user_id:
            return True
        owners = set()
        for rec in self.visible(self.records_by_resource.get(resource, []), audit_at):
            owners |= self.owners(rec)
        return bool(owners) and user_id not in owners

    # ------------------------------------------------------ one request

    def link(self, request, subject):
        """Candidate resources for one request, before collisions with other
        requests are settled.

        Returns {resource_id: link}; a link records why it was made
        ("identifier" and/or "activity") and the evidence records and
        activity events behind it.
        """
        audit_at = parse_time(request["audit_at"])
        requested_at = parse_time(request["requested_at"])
        reported_at = parse_time(request["reported_at"])
        user_id = subject["user_id"]
        ids = set(subject["identifiers"])
        links = {}

        def add(resource, system, reason, support):
            link = links.setdefault(resource, {
                "resource_id": resource, "system_id": system,
                "reasons": [], "records": [], "events": []})
            if reason not in link["reasons"]:
                link["reasons"].append(reason)
            bucket = link["events"] if reason == "activity" else link["records"]
            if support not in bucket:
                bucket.append(support)

        # Identifier matches. A lookup that came back "not found" only shows
        # someone searched for the identifier, not that the resource stores
        # it, so such records do not count.
        for resource, recs in self.records_by_resource.items():
            for rec in self.visible(recs, audit_at):
                if ids & set(rec["identifiers"]) and not shows_absence(rec["fields"]):
                    add(resource, rec["system_id"], "identifier", rec)

        # Deletion-worker activity inside this request's timing window.
        for event in self.activity:
            if event["source_system"] != "deletion_worker":
                continue
            resource = event["resource_id"]
            start, end, _ = timing(resource)
            when = parse_time(event["event_time"])
            in_window = (max(requested_at, reported_at + start) <= when
                         <= min(audit_at, reported_at + end))
            if in_window and not self.belongs_to_someone_else(resource, user_id, audit_at):
                add(resource, event["target_system"], "activity", event)

        return links

    # ------------------------------------------------------ all requests

    def link_all(self, requests, subjects):
        """Link every request, settling resources that several requests claim.

        Activity windows of different requests overlap, so the same
        activity-only resource can be claimed by several requests. Claims
        are settled in three passes:

          1. a resource some request links by identifier belongs to that
             request; activity-only claims on it elsewhere are dropped;
          2. accounts: every subject has exactly one primary account, so
             accounts and requests are paired one-to-one, best fit first
             (see account_fit);
          3. any other contested resource goes to the request whose own
             account was processed just before it (see follow_gap).

        Returns {case_id: {resource_id: link}}.
        """
        links = {r["case_id"]: self.link(r, subjects[r["case_id"]]) for r in requests}
        by_case = {r["case_id"]: r for r in requests}
        claims = self._drop_claims_on_identified(links)
        self._pair_accounts(links, by_case, claims)
        self._settle_other_claims(links, by_case, claims)
        return links

    @staticmethod
    def _drop_claims_on_identified(links):
        """Pass 1. Returns the remaining claims: {resource: {case ids}}
        for every activity-only link."""
        claims = defaultdict(set)
        identified = set()
        for case, case_links in links.items():
            for resource, link in case_links.items():
                if activity_only(link):
                    claims[resource].add(case)
                else:
                    identified.add(resource)
        for resource in identified & set(claims):
            for case in claims.pop(resource):
                del links[case][resource]
        return claims

    @staticmethod
    def account_fit(link, request):
        """Lower is better: hours between the account event and where this
        request expects it (~1h before reported_at), plus a penalty when the
        event's result contradicts the request's reported_status."""
        event = link["events"][0]
        offset = parse_time(event["event_time"]) - parse_time(request["reported_at"])
        hours = abs(offset - timing(link["resource_id"])[2]).total_seconds() / 3600
        if STATUS_RESULT.get(request["reported_status"]) != event["reported_result"]:
            hours += STATUS_MISMATCH_PENALTY
        return hours

    def _pair_accounts(self, links, by_case, claims):
        """Pass 2. Greedy one-to-one matching of activity-only accounts to
        requests that have no identified account yet, best fit first."""
        has_account = {case for case, case_links in links.items()
                       if any(is_account(r) and not activity_only(link)
                              for r, link in case_links.items())}
        candidates = sorted(
            (self.account_fit(links[case][r], by_case[case]), case, r)
            for r, cases in claims.items() if is_account(r) for case in cases)
        taken = set()
        for _, case, resource in candidates:
            if case not in has_account and resource not in taken:
                has_account.add(case)
                taken.add(resource)
                claims[resource] = {case}
        for case, case_links in links.items():
            for resource in [r for r, link in case_links.items()
                             if is_account(r) and activity_only(link)]:
                if claims.get(resource) != {case}:
                    del case_links[resource]

    def follow_gap(self, case_links, link, request):
        """Lower is better: hours from this request's own account event to
        the resource's event. Resources processed before the account get a
        large value; a request without an account event falls back to the
        expected offset from reported_at."""
        account_times = [t for r, l in case_links.items() if is_account(r) for t in worker_times(l)]
        if not account_times:
            event = link["events"][0]
            offset = parse_time(event["event_time"]) - parse_time(request["reported_at"])
            return abs(offset - timing(link["resource_id"])[2]).total_seconds() / 3600
        when = parse_time(link["events"][0]["event_time"])
        gap = (when - max(account_times)).total_seconds() / 3600
        return gap if gap >= 0 else BEFORE_ACCOUNT_PENALTY - gap

    def _settle_other_claims(self, links, by_case, claims):
        """Pass 3. Each contested non-account resource stays only with the
        request whose own account was processed just before it."""
        for resource, cases in claims.items():
            if is_account(resource) or len(cases) < 2:
                continue
            best = min(sorted(cases), key=lambda c: self.follow_gap(
                links[c], links[c][resource], by_case[c]))
            for case in cases - {best}:
                del links[case][resource]
