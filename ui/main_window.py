from PySide6.QtWidgets import QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QTabWidget, QPushButton, QLabel, QFileDialog, QMessageBox, QDialog, QLineEdit, QFormLayout, QDialogButtonBox, QTextEdit
from core.db import DatabaseManager
from core.export import export_bundle
from ui.findings_view import FindingsView
from ui.chains_view import ChainsView
from ui.evidence_vault import EvidenceVault

class OpenEngagementDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Open / Create Engagement"); form = QFormLayout(self)
        self.name = QLineEdit("Engagement"); self.client = QLineEdit(""); self.scope = QTextEdit()
        form.addRow("Name", self.name); form.addRow("Client", self.client); form.addRow("Scope notes", self.scope)
        btns = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel); btns.accepted.connect(self.accept); btns.rejected.connect(self.reject); form.addRow(btns)

class MainWindow(QMainWindow):
    def __init__(self, dbm: DatabaseManager):
        super().__init__()
        self.dbm = dbm; self.setWindowTitle("ProofChain"); self.resize(1280, 800)
        central = QWidget(); layout = QVBoxLayout(central); bar = QHBoxLayout()
        open_btn = QPushButton("Open / Create Engagement"); open_btn.clicked.connect(self.open_engagement)
        export_btn = QPushButton("Export Bundle"); export_btn.clicked.connect(self.export)
        self.eng_label = QLabel("No engagement open"); bar.addWidget(open_btn); bar.addWidget(export_btn); bar.addWidget(self.eng_label); bar.addStretch(); layout.addLayout(bar)
        self.tabs = QTabWidget(); self.findings_view = FindingsView(dbm, on_change=self.update_status); self.chains_view = ChainsView(dbm, on_change=self.update_status); self.evidence_vault = EvidenceVault(dbm)
        self.tabs.addTab(self.findings_view, "Findings"); self.tabs.addTab(self.chains_view, "Chains"); self.tabs.addTab(self.evidence_vault, "Evidence Vault"); self.tabs.currentChanged.connect(self._on_tab_change); layout.addWidget(self.tabs)
        self.status = QLabel("Ready."); layout.addWidget(self.status); self.setCentralWidget(central)

    def _on_tab_change(self, idx):
        if idx == 2: self.evidence_vault.refresh()

    def open_engagement(self):
        dlg = OpenEngagementDialog(self)
        if not dlg.exec(): return
        path, _ = QFileDialog.getSaveFileName(self, "Engagement Database", "engagement.sqlite", "SQLite (*.sqlite *.db)")
        if not path: return
        try: self.dbm.close(); self.dbm.open_engagement(path, dlg.name.text().strip() or "Engagement", dlg.client.text().strip(), dlg.scope.toPlainText().strip())
        except Exception as e: QMessageBox.critical(self, "Error opening", str(e)); return
        self.eng_label.setText(f"Engagement: {dlg.name.text()} — {path}"); self.findings_view.refresh(); self.chains_view.refresh(); self.evidence_vault.refresh(); self.update_status()

    def update_status(self):
        try:
            findings = self.dbm.list_findings(); validated = sum(1 for f in findings if f.state == "validated"); chains = self.dbm.list_chains(); confirmed = sum(1 for c in chains if c.state == "confirmed")
            self.status.setText(f"{len(findings)} findings · {validated} validated · {len(chains)} chains ({confirmed} confirmed)")
        except Exception: self.status.setText("No engagement open.")

    def export(self):
        if not self.dbm.conn: QMessageBox.information(self, "No engagement", "Open an engagement first."); return
        out_dir = QFileDialog.getExistingDirectory(self, "Export folder")
        if not out_dir: return
        findings = self.dbm.list_findings(); chains = self.dbm.list_chains(); evidence_map = {f.id: self.dbm.list_evidence(f.id) for f in findings}; chain_links_map = {c.id: self.dbm.list_chain_links(c.id) for c in chains}
        try: md, js = export_bundle(out_dir, findings, evidence_map, chains, chain_links_map)
        except Exception as e: QMessageBox.critical(self, "Export error", str(e)); return
        QMessageBox.information(self, "Exported", f"Wrote:\n{md}\n{js}")
