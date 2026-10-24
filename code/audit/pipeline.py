# Author: AJAkimana
"""The whole audit, wired together.

    evidence   every file -> uniform records + snapshot scope
    identity   request email -> subject with all identifiers
    linking    subject -> its resources (global attribution)
    state      resource -> treatment + status at audit_at
    steps      states -> status + ordered steps
    intent     does the request authorize deletion at all?
"""

from .common import DATASET_DIR, read_csv
from .evidence import load_evidence
from .identity import IdentityIndex
from .intent import classify
from .linking import Linker
from .state import StateResolver
from .steps import build_steps


def authorizes_deletion(request):
    """Only requests whose text asks for deletion are audited (audit.intent)."""
    return classify(request["request_text"])[0]


class Auditor:
    def __init__(self):
        self.records, self.manifest = load_evidence()
        self.identities = IdentityIndex()
        self.linker = Linker(self.records, self.identities)
        self.states = StateResolver(self.manifest)
        # All known requests share one activity stream, so linking always
        # considers all of them, whichever subset we are asked to answer.
        self.context = (read_csv(DATASET_DIR / "sample_deletion_requests.csv")
                        + read_csv(DATASET_DIR / "deletion_requests.csv"))

    def audit(self, requests):
        """Return [(case_id, deletion_status, steps)] for these requests."""
        known = {r["case_id"] for r in self.context}
        everything = self.context + \
            [r for r in requests if r["case_id"] not in known]
        subjects = {r["case_id"]: self.identities.resolve(
            r["email"]) for r in everything}
        authorized = [r for r in everything if authorizes_deletion(
            r) and subjects[r["case_id"]]]
        links = self.linker.link_all(authorized, subjects)

        results = []
        for request in requests:
            case = request["case_id"]
            if case not in links:
                results.append((case, "NOT_APPLICABLE", []))
                continue
            case_links = links[case]
            for resource, link in case_links.items():
                link["all_records"] = self.linker.records_for(resource, link)
            states = self.states.resolve(request, subjects[case], case_links)
            results.append((case, *build_steps(states)))
        return results
