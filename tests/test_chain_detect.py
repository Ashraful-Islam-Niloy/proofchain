from core.models import Finding
from core.chain_detect import detect_potential_chains
def test_shared_host_service():
    a = Finding(id=1, title="A", host="h1", service="smb"); b = Finding(id=2, title="B", host="h1", service="smb")
    res = detect_potential_chains([a, b]); assert any("Shared host + service" in p.reason for p in res)
def test_priv_esc_with_creds():
    a = Finding(id=1, title="Privilege escalation via sudo", host="h1"); b = Finding(id=2, title="Stored credentials in config", host="h1")
    res = detect_potential_chains([a, b]); assert any("Priv-esc" in p.reason for p in res)
