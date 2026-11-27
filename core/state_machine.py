ALLOWED_FINDING_TRANSITIONS = {
    "raw": {"in_review"},
    "in_review": {"validated", "false_positive"},
    "validated": {"in_review"},
    "false_positive": {"in_review"},
}
ALLOWED_CHAIN_TRANSITIONS = {
    "potential": {"confirmed", "dismissed"},
    "confirmed": {"potential", "dismissed"},
    "dismissed": {"potential"},
}

class TransitionError(Exception):
    pass

def can_transition_finding(current: str, target: str) -> bool:
    return target in ALLOWED_FINDING_TRANSITIONS.get(current, set())

def transition_finding(finding, target: str, evidence_count: int, fp_reason: str = ""):
    if not can_transition_finding(finding.state, target):
        raise TransitionError(f"Cannot move finding from '{finding.state}' to '{target}'.")
    if target == "validated" and evidence_count < 1:
        raise TransitionError("Cannot validate a finding without at least one piece of evidence.")
    if target == "false_positive" and not fp_reason.strip():
        raise TransitionError("Marking as false positive requires a reason note.")
    finding.state = target

def can_transition_chain(current: str, target: str) -> bool:
    return target in ALLOWED_CHAIN_TRANSITIONS.get(current, set())

def transition_chain(chain, target: str):
    if not can_transition_chain(chain.state, target):
        raise TransitionError(f"Cannot move chain from '{chain.state}' to '{target}'.")
    chain.state = target
