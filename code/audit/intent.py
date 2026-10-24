# Author: AJAkimana
"""Phase 6: does a request actually authorize deletion?

Requests arrive in several languages. Non-deletion requests (marketing
opt-out, data copy/export, correction, login help) look like deletion cases
in every other field, so the text decides.

The classifier is a small set of transparent rules, applied in order:

  1. KEEP: the person explicitly wants the account kept, or explicitly says
     this is not a deletion ("do not close the account", "not asking for
     deletion", "marketing lists only", "don't delete"). -> not deletion.
     These phrases are narrow on purpose: deletion requests also say things
     like "you can keep anonymous statistics" or "keeping an internal
     deleted-account reference is fine".
  2. DELETE: a deletion verb or noun in any supported language
     (delete/erase/remove/close, eliminar, supprimer, excluir, 削除, 삭제, ...)
     -> deletion. Verification requests ("verify my account was deleted")
     count, because they ask us to audit an authorized deletion.
  3. Anything else -> not deletion (no destructive action without consent).

classify() returns (authorizes, reason) so every decision can be explained.
"""

import re

KEEP_PATTERNS = [
    r"\bnot (?:asking|requesting) (?:for )?(?:a |an )?(?:deletion|erasure)",
    r"\bnot a request to (?:erase|delete|remove)",
    r"\b(?:do not|don't|dont) (?:close|delete|remove|erase|change)",
    r"\bwithout (?:removing|deleting|erasing|closing)",
    r"\bleave (?:the|my) (?:account|profile)",
    r"\bkeep (?:the|my) account\b",
    r"\bkeep the account as it is",
    r"\bstill (?:need|want|use)\b",
    r"\bcontinue using\b",
    r"\bmarketing lists only\b",
    r"\bstop the promotional\b",
    r"\binformation request\b",
]
DELETE_PATTERNS = [
    # English
    r"\bdelet(?:e|ed|es|ing|ion)\b", r"\beras(?:e|ed|ure)\b", r"\bremov(?:e|ed|al)\b",
    r"\bclos(?:e|ed|ing)\b[^.]*\baccount\b", r"\baccount\b[^.]*\bclos(?:e|ed)\b",
    # deletion described by its outcome ("confirm the profile is gone")
    r"\b(?:profile|account|data) (?:is|was|has been) gone\b", r"\bcannot identify me\b",
    # Spanish / Portuguese / French / German / Italian
    r"\belimin(?:ar|ación|acion|e)\b", r"\bborr(?:ar|ado)\b", r"\bexclus(?:ão|ao)\b", r"\bexclu(?:ir|a)\b",
    r"\bsuppr(?:ession|imer|imez)\b", r"\beffac(?:er|ement)\b", r"\blösch", r"\bcancell(?:are|azione)\b",
    # Japanese / Korean / Chinese
    r"削除", r"消去", r"삭제", r"탈퇴", r"删除", r"註銷", r"注销",
]
KEEP_RE = [re.compile(p, re.IGNORECASE) for p in KEEP_PATTERNS]
DELETE_RE = [re.compile(p, re.IGNORECASE) for p in DELETE_PATTERNS]


def classify(text):
    """Return (authorizes_deletion: bool, reason: str)."""
    text = text.replace("’", "'")  # curly apostrophes: don’t -> don't
    for pattern in KEEP_RE:
        m = pattern.search(text)
        if m:
            return False, f"keep: {m.group(0)!r}"
    for pattern in DELETE_RE:
        m = pattern.search(text)
        if m:
            return True, f"delete: {m.group(0)!r}"
    return False, "no deletion wording"
