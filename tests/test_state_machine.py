from core.models import Finding
from core.state_machine import transition_finding, TransitionError
def test_cannot_validate_without_evidence():
    f = Finding(title="x", state="in_review")
    try: transition_finding(f, "validated", 0); assert False
    except TransitionError: pass
def test_validate_with_evidence():
    f = Finding(title="x", state="in_review"); transition_finding(f, "validated", 1); assert f.state == "validated"
def test_fp_requires_reason():
    f = Finding(title="x", state="in_review")
    try: transition_finding(f, "false_positive", 0, ""); assert False
    except TransitionError: pass
def test_raw_cannot_jump_to_validated():
    f = Finding(title="x", state="raw")
    try: transition_finding(f, "validated", 3); assert False
    except TransitionError: pass
