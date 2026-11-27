from PySide6.QtCore import Qt, QUrl
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QTableWidget, QTableWidgetItem, QSplitter, QLabel, QTextEdit, QMessageBox, QListWidget, QComboBox, QInputDialog, QLineEdit, QDoubleSpinBox, QFormLayout, QDialog, QDialogButtonBox, QFileDialog
from core.db import DatabaseManager
from core.evidence import copy_into_evidence, sha256_text
from core.models import Finding, Evidence, SEVERITIES
from core.state_machine import transition_finding, TransitionError
from core.importers import parse_nmap_xml, parse_generic_csv
from ui.widgets import color_for_state

class FindingDialog(QDialog):
    def __init__(self, finding: Finding = None, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Edit Finding" if finding else "New Finding")
        self._finding = finding
        form = QFormLayout(self)
        self.title = QLineEdit(finding.title if finding else "")
        self.host = QLineEdit(finding.host if finding else "")
        self.port = QLineEdit(finding.port if finding else "")
        self.service = QLineEdit(finding.service if finding else "")
        self.severity = QComboBox()
        self.severity.addItems(SEVERITIES)
        if finding: self.severity.setCurrentText(finding.severity)
        self.cvss = QDoubleSpinBox(); self.cvss.setRange(0.0, 10.0); self.cvss.setDecimals(1)
        if finding and finding.cvss: self.cvss.setValue(finding.cvss)
        self.cve = QLineEdit(finding.cve if finding else "")
        self.description = QTextEdit(finding.description if finding else "")
        for label, w in [("Title", self.title), ("Host", self.host), ("Port", self.port), ("Service", self.service), ("Severity", self.severity), ("CVSS", self.cvss), ("CVE", self.cve), ("Description", self.description)]: form.addRow(label, w)
        btns = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        btns.accepted.connect(self.accept); btns.rejected.connect(self.reject); form.addRow(btns)

    def value(self, engagement_id: int) -> Finding:
        base = self._finding or Finding(engagement_id=engagement_id)
        base.title = self.title.text().strip(); base.host = self.host.text().strip(); base.port = self.port.text().strip(); base.service = self.service.text().strip(); base.severity = self.severity.currentText(); base.cvss = self.cvss.value() or None; base.cve = self.cve.text().strip(); base.description = self.description.toPlainText().strip()
        return base

class FindingsView(QWidget):
    def __init__(self, dbm: DatabaseManager, on_change=None):
        super().__init__()
        self.dbm = dbm; self.on_change = on_change; self._current_finding = None
        root = QVBoxLayout(self); splitter = QSplitter(Qt.Horizontal); root.addWidget(splitter)
        left = QWidget(); ll = QVBoxLayout(left); toolbar = QHBoxLayout()
        for label, slot in [("+ New Finding", self._new_finding), ("Import Nmap XML", self._import_nmap), ("Import CSV", self._import_csv), ("Refresh", self.refresh)]:
            b = QPushButton(label); b.clicked.connect(slot); toolbar.addWidget(b)
        toolbar.addStretch(); ll.addLayout(toolbar)
        self.table = QTableWidget(0, 6); self.table.setHorizontalHeaderLabels(["SEV", "Title", "Host", "State", "Evidence", "Source"]); self.table.horizontalHeader().setStretchLastSection(True); self.table.cellClicked.connect(self._select_row); ll.addWidget(self.table); splitter.addWidget(left)
        right = QWidget(); rl = QVBoxLayout(right); self.detail_title = QLabel("Select a finding"); self.detail_title.setStyleSheet("font-weight:700; font-size:14px;"); rl.addWidget(self.detail_title)
        self.detail_meta = QLabel(""); self.detail_meta.setStyleSheet("color:#555;"); self.detail_meta.setWordWrap(True); rl.addWidget(self.detail_meta)
        self.detail_desc = QTextEdit(); self.detail_desc.setReadOnly(True); rl.addWidget(self.detail_desc)
        act1 = QHBoxLayout()
        for label, slot in [("Start Review", lambda: self._transition("in_review")), ("Validate", lambda: self._transition("validated")), ("Mark FP", lambda: self._transition("false_positive")), ("Edit", self._edit_finding), ("Delete", self._delete_finding)]:
            b = QPushButton(label); b.clicked.connect(slot); act1.addWidget(b)
        rl.addLayout(act1)
        act2 = QHBoxLayout(); self.add_ev_btn = QPushButton("+ Add Evidence (text)"); self.add_file_btn = QPushButton("+ Attach File"); act2.addWidget(self.add_ev_btn); act2.addWidget(self.add_file_btn); rl.addLayout(act2)
        self.add_ev_btn.clicked.connect(self._add_text_evidence); self.add_file_btn.clicked.connect(self._add_file_evidence)
        rl.addWidget(QLabel("Evidence (double-click to open):")); self.evidence_list = QListWidget(); self.evidence_list.itemDoubleClicked.connect(self._open_evidence); rl.addWidget(self.evidence_list); splitter.addWidget(right); splitter.setSizes([650, 450])

    def refresh(self):
        findings = self.dbm.list_findings(); self.table.setRowCount(len(findings))
        for row, f in enumerate(findings): self._fill_row(row, f)
        if self.on_change: self.on_change()

    def _fill_row(self, row, f):
        items = [f.severity.upper(), f.title, f.host, f.state, str(self.dbm.evidence_count(f.id)), f.source]
        for col, text in enumerate(items):
            item = QTableWidgetItem(text); item.setData(Qt.UserRole, f.id)
            if col == 3: item.setForeground(color_for_state(f.state))
            self.table.setItem(row, col, item)

    def _select_row(self, row, _col):
        fid = self.table.item(row, 0).data(Qt.UserRole); f = self.dbm.get_finding(fid)
        if not f: return
        self._current_finding = f; self.detail_title.setText(f.title)
        self.detail_meta.setText(f"Host: {f.host}:{f.port} ({f.service})  |  Severity: {f.severity}  |  CVSS: {f.cvss or '—'}  |  CVE: {f.cve or '—'}  |  State: {f.state}  |  Source: {f.source}")
        self.detail_desc.setPlainText(f.description); self._refresh_evidence()

    def _select_row_by_id(self, fid):
        for row in range(self.table.rowCount()):
            if self.table.item(row, 0).data(Qt.UserRole) == fid: self._select_row(row, 0); return

    def _refresh_evidence(self):
        self.evidence_list.clear()
        if not self._current_finding: return
        for e in self.dbm.list_evidence(self._current_finding.id):
            label = f"[{e.kind}] {e.path_or_text[:70]}  ({e.sha256[:10]}...)"
            self.evidence_list.addItem(label); idx = self.evidence_list.count() - 1; self.evidence_list.item(idx).setData(Qt.UserRole, e)

    def _open_evidence(self, item):
        e = item.data(Qt.UserRole)
        if e.kind == "note": QMessageBox.information(self, "Evidence note", e.path_or_text)
        else: QDesktopServices.openUrl(QUrl.fromLocalFile(e.path_or_text))

    def _new_finding(self):
        dlg = FindingDialog(parent=self)
        if dlg.exec():
            f = dlg.value(self.dbm.engagement_id)
            if not f.title: QMessageBox.warning(self, "Missing", "Title is required."); return
            self.dbm.add_finding(f); self.refresh()

    def _edit_finding(self):
        if not self._current_finding: return
        dlg = FindingDialog(self._current_finding, parent=self)
        if dlg.exec():
            updated = dlg.value(self.dbm.engagement_id)
            if not updated.title: QMessageBox.warning(self, "Missing", "Title is required."); return
            self.dbm.update_finding(updated); self.refresh(); self._select_row_by_id(updated.id)

    def _delete_finding(self):
        if not self._current_finding: return
        if QMessageBox.question(self, "Delete", f"Delete '{self._current_finding.title}' and its evidence?") != QMessageBox.Yes: return
        self.dbm.delete_finding(self._current_finding.id); self._current_finding = None; self.refresh()

    def _transition(self, target: str):
        if not self._current_finding: return
        f = self._current_finding; count = self.dbm.evidence_count(f.id); fp_reason = ""
        if target == "false_positive":
            fp_reason, ok = QInputDialog.getText(self, "Reason", "Why is this a false positive?")
            if not ok: return
        try: transition_finding(f, target, count, fp_reason)
        except TransitionError as e: QMessageBox.warning(self, "Blocked", str(e)); return
        self.dbm.update_finding(f); self.refresh(); self._current_finding = self.dbm.get_finding(f.id); self._select_row_by_id(f.id)

    def _add_text_evidence(self):
        if not self._current_finding: QMessageBox.information(self, "No finding", "Select a finding first."); return
        text, ok = QInputDialog.getMultiLineText(self, "Add Evidence", "Paste note / command output / HTTP text:")
        if not ok or not text.strip(): return
        self.dbm.add_evidence(Evidence(finding_id=self._current_finding.id, kind="note", path_or_text=text.strip(), sha256=sha256_text(text.strip()))); self.refresh(); self._refresh_evidence()

    def _add_file_evidence(self):
        if not self._current_finding: QMessageBox.information(self, "No finding", "Select a finding first."); return
        path, _ = QFileDialog.getOpenFileName(self, "Select evidence file")
        if not path: return
        stored, digest = copy_into_evidence(path, self.dbm.evidence_dir)
        self.dbm.add_evidence(Evidence(finding_id=self._current_finding.id, kind="file", path_or_text=stored, sha256=digest)); self.refresh(); self._refresh_evidence()

    def _import_nmap(self):
        path, _ = QFileDialog.getOpenFileName(self, "Nmap XML", "", "XML (*.xml)")
        if not path: return
        try: findings = parse_nmap_xml(path)
        except Exception as e: QMessageBox.critical(self, "Parse error", str(e)); return
        for f in findings: self.dbm.add_finding(f)
        self.refresh(); QMessageBox.information(self, "Imported", f"Imported {len(findings)} port(s).")

    def _import_csv(self):
        path, _ = QFileDialog.getOpenFileName(self, "CSV", "", "CSV (*.csv)")
        if not path: return
        try: findings = parse_generic_csv(path)
        except Exception as e: QMessageBox.critical(self, "Parse error", str(e)); return
        for f in findings: self.dbm.add_finding(f)
        self.refresh(); QMessageBox.information(self, "Imported", f"Imported {len(findings)} finding(s).")
