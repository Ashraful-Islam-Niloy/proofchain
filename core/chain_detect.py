from itertools import combinations
from typing import List
from core.models import Finding

class PotentialChain:
    def __init__(self, reason: str, finding_a: Finding, finding_b: Finding):
        self.reason = reason
        self.finding_a = finding_a
        self.finding_b = finding_b

def detect_potential_chains(findings: List[Finding]) -> List[PotentialChain]:
    out = []
    seen = set()
    def push(reason, a, b):
        if a.id == b.id: return
        k = (reason, *sorted((a.id, b.id)))
        if k in seen: return
        seen.add(k)
        out.append(PotentialChain(reason, a, b))

    for a, b in combinations(findings, 2):
        if a.host and a.host == b.host and a.service and a.service == b.service:
            push("Shared host + service", a, b)

    for a, b in combinations(findings, 2):
        ta = (a.title + " " + a.description).lower()
        tb = (b.title + " " + b.description).lower()
        a_priv = any(w in ta for w in ("privilege", "priv-esc", "escalation"))
        b_priv = any(w in tb for w in ("privilege", "priv-esc", "escalation"))
        a_cred = any(w in ta for w in ("credential", "password", "hash"))
        b_cred = any(w in tb for w in ("credential", "password", "hash"))
        if a.host and a.host == b.host:
            if a_priv and b_cred: push("Priv-esc on host with credential exposure", a, b)
            elif b_priv and a_cred: push("Priv-esc on host with credential exposure", a, b)
    return out
