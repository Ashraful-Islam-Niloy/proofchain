import csv, xml.etree.ElementTree as ET
from typing import List
from core.models import Finding

def parse_nmap_xml(path: str) -> List[Finding]:
    out = []
    tree = ET.parse(path)
    root = tree.getroot()
    for host in root.findall("host"):
        addr = ""
        for a in host.findall("address"):
            if a.get("addrtype") in ("ipv4", "ipv6"):
                addr = a.get("addr")
                break
        hostname = ""
        hn = host.find("hostnames/hostname")
        if hn is not None: hostname = hn.get("name", "")
        display = hostname or addr
        for port in host.findall("ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open": continue
            portid = port.get("portid", "")
            svc = port.find("service")
            service, version = "", ""
            if svc is not None:
                service = svc.get("name", "")
                version = (svc.get("product", "") + " " + svc.get("version", "")).strip()
            title = f"Open port {portid}/{service or 'unknown'}"
            desc = f"Nmap detected open port {portid}"
            if version: desc += f" - {version}"
            out.append(Finding(title=title, description=desc, host=display, port=portid, service=service, severity="info", source="nmap"))
    return out

def parse_generic_csv(path: str) -> List[Finding]:
    out = []
    with open(path, newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            title = (row.get("title") or "").strip()
            if not title: continue
            cvss = None
            raw_cvss = (row.get("cvss") or "").strip()
            if raw_cvss:
                try: cvss = float(raw_cvss)
                except ValueError: pass
            sev = (row.get("severity") or "info").strip().lower()
            if sev not in ("critical", "high", "medium", "low", "info"): sev = "info"
            out.append(Finding(title=title, host=(row.get("host") or "").strip(), port=(row.get("port") or "").strip(), service=(row.get("service") or "").strip(), severity=sev, cvss=cvss, cve=(row.get("cve") or "").strip(), description=(row.get("description") or "").strip(), source="csv"))
    return out
