import json, os
from typing import List
from core.models import Finding, Evidence, Chain, ChainLink

def export_bundle(out_dir: str, findings: List[Finding], evidence_map: dict, chains: List[Chain], chain_links_map: dict):
    os.makedirs(out_dir, exist_ok=True)
    md_path, json_path = os.path.join(out_dir, "findings.md"), os.path.join(out_dir, "findings.json")
    validated, confirmed = [f for f in findings if f.state == "validated"], [c for c in chains if c.state == "confirmed"]
    with open(md_path, "w", encoding="utf-8") as fh:
        fh.write("# ProofChain Export\n\n")
        fh.write(f"Validated findings: {len(validated)}\nConfirmed chains: {len(confirmed)}\n\n## Validated Findings\n\n")
        for f in validated:
            fh.write(f"### [{f.severity.upper()}] {f.title}\n- Host: {f.host}:{f.port} ({f.service})\n- CVE: {f.cve or '—'} | CVSS: {f.cvss or '—'}\n- Source: {f.source}\n\n{f.description}\n\n")
            for e in evidence_map.get(f.id, []): fh.write(f"- ({e.kind}) `{e.sha256[:16]}...` {e.path_or_text}\n")
            fh.write("\n")
        fh.write("## Confirmed Chains\n\n")
        for c in confirmed:
            fh.write(f"### {c.title}\n{c.description}\n\n")
            for link in chain_links_map.get(c.id, []): fh.write(f"- Finding #{link.finding_id} — {link.role_note}\n")
            fh.write("\n")
    bundle = {"findings": [f.__dict__ for f in findings], "evidence": {str(k): [e.__dict__ for e in v] for k, v in evidence_map.items()}, "chains": [c.__dict__ for c in chains], "chain_links": {str(k): [l.__dict__ for l in v] for k, v in chain_links_map.items()}}
    with open(json_path, "w", encoding="utf-8") as fh: json.dump(bundle, fh, indent=2)
    return md_path, json_path
