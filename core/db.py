import os, sqlite3
from datetime import datetime
from typing import Optional, List
from core.models import Finding, Evidence, Chain, ChainLink

SCHEMA = """CREATE TABLE IF NOT EXISTS engagement (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, client TEXT, scope_notes TEXT, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS finding (id INTEGER PRIMARY KEY AUTOINCREMENT, engagement_id INTEGER NOT NULL, title TEXT NOT NULL, description TEXT DEFAULT '', host TEXT DEFAULT '', port TEXT DEFAULT '', service TEXT DEFAULT '', severity TEXT DEFAULT 'info', cvss REAL, cve TEXT DEFAULT '', state TEXT DEFAULT 'raw', source TEXT DEFAULT 'manual', created_at TEXT, updated_at TEXT);
CREATE TABLE IF NOT EXISTS evidence (id INTEGER PRIMARY KEY AUTOINCREMENT, finding_id INTEGER NOT NULL, kind TEXT DEFAULT 'note', path_or_text TEXT DEFAULT '', sha256 TEXT DEFAULT '', added_at TEXT);
CREATE TABLE IF NOT EXISTS chain (id INTEGER PRIMARY KEY AUTOINCREMENT, engagement_id INTEGER NOT NULL, title TEXT NOT NULL, description TEXT DEFAULT '', state TEXT DEFAULT 'potential', created_at TEXT);
CREATE TABLE IF NOT EXISTS chain_link (chain_id INTEGER NOT NULL, finding_id INTEGER NOT NULL, role_note TEXT DEFAULT '', PRIMARY KEY (chain_id, finding_id));"""

def _now() -> str: return datetime.utcnow().isoformat(timespec="seconds")

class DatabaseManager:
    def __init__(self):
        self.conn = None; self.db_path = None; self.evidence_dir = None; self.engagement_id = None

    def open_engagement(self, path: str, name: str, client: str = "", scope_notes: str = "") -> int:
        self.db_path = path; self.conn = sqlite3.connect(path); self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA); self.conn.commit()
        base = os.path.dirname(os.path.abspath(path)); self.evidence_dir = os.path.join(base, "evidence"); os.makedirs(self.evidence_dir, exist_ok=True)
        row = self.conn.execute("SELECT id FROM engagement LIMIT 1").fetchone()
        if row: self.engagement_id = row["id"]
        else:
            cur = self.conn.execute("INSERT INTO engagement(name, client, scope_notes, created_at) VALUES (?,?,?,?)", (name, client, scope_notes, _now()))
            self.conn.commit(); self.engagement_id = cur.lastrowid
        return self.engagement_id

    def close(self):
        if self.conn: self.conn.close(); self.conn = None

    def _require(self):
        if self.conn is None: raise RuntimeError("No engagement open.")

    def add_finding(self, f: Finding) -> int:
        self._require()
        cur = self.conn.execute("INSERT INTO finding(engagement_id,title,description,host,port,service,severity,cvss,cve,state,source,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)", (self.engagement_id, f.title, f.description, f.host, f.port, f.service, f.severity, f.cvss, f.cve, f.state, f.source, _now(), _now()))
        self.conn.commit(); return cur.lastrowid

    def update_finding(self, f: Finding):
        self._require()
        self.conn.execute("UPDATE finding SET title=?,description=?,host=?,port=?,service=?,severity=?,cvss=?,cve=?,state=?,source=?,updated_at=? WHERE id=?", (f.title, f.description, f.host, f.port, f.service, f.severity, f.cvss, f.cve, f.state, f.source, _now(), f.id))
        self.conn.commit()

    def delete_finding(self, fid: int):
        self._require()
        self.conn.execute("DELETE FROM evidence WHERE finding_id=?", (fid,)); self.conn.execute("DELETE FROM chain_link WHERE finding_id=?", (fid,)); self.conn.execute("DELETE FROM finding WHERE id=?", (fid,)); self.conn.commit()

    def get_finding(self, fid: int) -> Optional[Finding]:
        self._require()
        row = self.conn.execute("SELECT * FROM finding WHERE id=?", (fid,)).fetchone()
        return self._row_to_finding(row) if row else None

    def list_findings(self) -> List[Finding]:
        self._require()
        rows = self.conn.execute("SELECT * FROM finding WHERE engagement_id=? ORDER BY id DESC", (self.engagement_id,)).fetchall()
        return [self._row_to_finding(r) for r in rows]

    @staticmethod
    def _row_to_finding(r) -> Finding:
        return Finding(id=r["id"], engagement_id=r["engagement_id"], title=r["title"], description=r["description"], host=r["host"], port=r["port"], service=r["service"], severity=r["severity"], cvss=r["cvss"], cve=r["cve"], state=r["state"], source=r["source"], created_at=r["created_at"], updated_at=r["updated_at"])

    def add_evidence(self, e: Evidence) -> int:
        self._require()
        cur = self.conn.execute("INSERT INTO evidence(finding_id,kind,path_or_text,sha256,added_at) VALUES (?,?,?,?,?)", (e.finding_id, e.kind, e.path_or_text, e.sha256, _now()))
        self.conn.commit(); return cur.lastrowid

    def list_evidence(self, finding_id: int) -> List[Evidence]:
        self._require()
        rows = self.conn.execute("SELECT * FROM evidence WHERE finding_id=? ORDER BY id", (finding_id,)).fetchall()
        return [Evidence(id=r["id"], finding_id=r["finding_id"], kind=r["kind"], path_or_text=r["path_or_text"], sha256=r["sha256"], added_at=r["added_at"]) for r in rows]

    def list_all_evidence(self) -> List[Evidence]:
        self._require()
        rows = self.conn.execute("SELECT e.* FROM evidence e JOIN finding f ON e.finding_id=f.id WHERE f.engagement_id=? ORDER BY e.id DESC", (self.engagement_id,)).fetchall()
        return [Evidence(id=r["id"], finding_id=r["finding_id"], kind=r["kind"], path_or_text=r["path_or_text"], sha256=r["sha256"], added_at=r["added_at"]) for r in rows]

    def evidence_count(self, finding_id: int) -> int:
        self._require()
        return self.conn.execute("SELECT COUNT(*) c FROM evidence WHERE finding_id=?", (finding_id,)).fetchone()["c"]

    def add_chain(self, c: Chain) -> int:
        self._require()
        cur = self.conn.execute("INSERT INTO chain(engagement_id,title,description,state,created_at) VALUES (?,?,?,?,?)", (self.engagement_id, c.title, c.description, c.state, _now()))
        self.conn.commit(); return cur.lastrowid

    def update_chain(self, c: Chain):
        self._require()
        self.conn.execute("UPDATE chain SET title=?, description=?, state=? WHERE id=?", (c.title, c.description, c.state, c.id)); self.conn.commit()

    def delete_chain(self, cid: int):
        self._require()
        self.conn.execute("DELETE FROM chain_link WHERE chain_id=?", (cid,)); self.conn.execute("DELETE FROM chain WHERE id=?", (cid,)); self.conn.commit()

    def get_chain(self, cid: int) -> Optional[Chain]:
        self._require()
        row = self.conn.execute("SELECT * FROM chain WHERE id=?", (cid,)).fetchone()
        if not row: return None
        return Chain(id=row["id"], engagement_id=row["engagement_id"], title=row["title"], description=row["description"], state=row["state"], created_at=row["created_at"])

    def list_chains(self) -> List[Chain]:
        self._require()
        rows = self.conn.execute("SELECT * FROM chain WHERE engagement_id=? ORDER BY id DESC", (self.engagement_id,)).fetchall()
        return [Chain(id=r["id"], engagement_id=r["engagement_id"], title=r["title"], description=r["description"], state=r["state"], created_at=r["created_at"]) for r in rows]

    def add_chain_link(self, link: ChainLink):
        self._require()
        self.conn.execute("INSERT OR REPLACE INTO chain_link(chain_id,finding_id,role_note) VALUES (?,?,?)", (link.chain_id, link.finding_id, link.role_note)); self.conn.commit()

    def remove_chain_link(self, chain_id: int, finding_id: int):
        self._require()
        self.conn.execute("DELETE FROM chain_link WHERE chain_id=? AND finding_id=?", (chain_id, finding_id)); self.conn.commit()

    def list_chain_links(self, chain_id: int) -> List[ChainLink]:
        self._require()
        rows = self.conn.execute("SELECT * FROM chain_link WHERE chain_id=?", (chain_id,)).fetchall()
        return [ChainLink(chain_id=r["chain_id"], finding_id=r["finding_id"], role_note=r["role_note"]) for r in rows]
