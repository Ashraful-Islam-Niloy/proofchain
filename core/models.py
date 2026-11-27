from dataclasses import dataclass
from typing import Optional

@dataclass
class Finding:
    id: Optional[int] = None
    engagement_id: int = 0
    title: str = ""
    description: str = ""
    host: str = ""
    port: str = ""
    service: str = ""
    severity: str = "info"
    cvss: Optional[float] = None
    cve: str = ""
    state: str = "raw"
    source: str = "manual"
    created_at: str = ""
    updated_at: str = ""

@dataclass
class Evidence:
    id: Optional[int] = None
    finding_id: int = 0
    kind: str = "note"
    path_or_text: str = ""
    sha256: str = ""
    added_at: str = ""

@dataclass
class Chain:
    id: Optional[int] = None
    engagement_id: int = 0
    title: str = ""
    description: str = ""
    state: str = "potential"
    created_at: str = ""

@dataclass
class ChainLink:
    chain_id: int = 0
    finding_id: int = 0
    role_note: str = ""

SEVERITIES = ["critical", "high", "medium", "low", "info"]
FINDING_STATES = ["raw", "in_review", "validated", "false_positive"]
CHAIN_STATES = ["potential", "confirmed", "dismissed"]
EVIDENCE_KINDS = ["file", "command_output", "http_request", "http_response", "screenshot", "note"]
