from PySide6.QtCore import Qt
from PySide6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QTableWidget, QTableWidgetItem, QLabel, QMessageBox, QListWidget, QSplitter, QInputDialog, QDialog, QFormLayout, QLineEdit, QTextEdit, QDialogButtonBox, QComboBox
from core.db import DatabaseManager
from core.models import Chain, ChainLink
from core.chain_detect import detect_potential_chains
from core.state_machine import transition_chain, TransitionError
from ui.widgets import color_for_state

class ChainDialog(QDialog):
    def __init__(self, chain: Chain = None, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Edit Chain" if chain else "New Chain")
        self._chain = chain
        form = QFormLayout(self)
        self.title = QLineEdit(chain.title if chain else "")
        self.description = QTextEdit(chain.description if chain else "")
        form.addRow("Title", self.title); form.addRow("Description", self.description)
        btns = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        btns.accepted.connect(self.accept); btns.rejected.connect(self.reject); form.addRow(btns)
    def value(self, engagement_id: int) -> Chain:
        base = self._chain or Chain(engagement_id=engagement_id)
        base.title = self.title.text().strip(); base.description = self.description.toPlainText().strip()
        return base

class ChainsView(QWidget):
    def __init__(self, dbm: DatabaseManager, on_change=None):
        super().__init__()
        self.dbm = dbm; self.on_change = on_change; self._current_chain = None
        root = QVBoxLayout(self); bar = QHBoxLayout()
        for label, slot in [("Detect Potential Chains", self.detect), ("+ New Chain", self._new_chain), ("Refresh", self.refresh)]:
            b = QPushButton(label); b.clicked.connect(slot); bar.addWidget(b)
        bar.addStretch(); root.addLayout(bar)
        splitter = QSplitter(Qt.Horizontal); root.addWidget(splitter)
        self.table = QTableWidget(0, 3); self.table.setHorizontalHeaderLabels(["State", "Title", "Findings"]); self.table.horizontalHeader().setStretchLastSection(True); self.table.cellClicked.connect(self._select_row); splitter.addWidget(self.table)
        right = QWidget(); rl = QVBoxLayout(right); self.title = QLabel("Select a chain"); self.title.setStyleSheet("font-weight:700;"); rl.addWidget(self.title)
        self.desc = QLabel(""); self.desc.setWordWrap(True); rl.addWidget(self.desc)
        btn_row = QHBoxLayout()
        for label, slot in [("Confirm", lambda: self._transition("confirmed")), ("Dismiss", lambda: self._transition("dismissed")), ("Edit", self._edit_chain), ("Delete", self._delete_chain)]:
            b = QPushButton(label); b.clicked.connect(slot); btn_row.addWidget(b)
        rl.addLayout(btn_row); rl.addWidget(QLabel("Linked findings (double-click to remove):"))
        self.links = QListWidget(); self.links.itemDoubleClicked.connect(self._remove_link); rl.addWidget(self.links)
        add_row = QHBoxLayout(); self.finding_combo = QComboBox(); add_btn = QPushButton("+ Link Finding"); add_btn.clicked.connect(self._add_link); add_row.addWidget(self.finding_combo); add_row.addWidget(add_btn); rl.addLayout(add_row)
        splitter.addWidget(right); splitter.setSizes([650, 450])

    def refresh(self):
        chains = self.dbm.list_chains(); self.table.setRowCount(len(chains))
        for row, c in enumerate(chains):
            n = len(self.dbm.list_chain_links(c.id))
            for col, text in enumerate([c.state, c.title, str(n)]):
                item = QTableWidgetItem(text); item.setData(Qt.UserRole, c.id)
                if col == 0: item.setForeground(color_for_state(c.state))
                self.table.setItem(row, col, item)
        self._refresh_combo()
        if self.on_change: self.on_change()

    def _refresh_combo(self):
        self.finding_combo.clear()
        for f in self.dbm.list_findings(): self.finding_combo.addItem(f"#{f.id} {f.title}", f.id)

    def _select_row(self, row, _col):
        cid = self.table.item(row, 0).data(Qt.UserRole); c = self.dbm.get_chain(cid)
        if not c: return
        self._current_chain = c; self.title.setText(c.title); self.desc.setText(c.description); self._refresh_links()

    def _refresh_links(self):
        self.links.clear()
        if not self._current_chain: return
        for link in self.dbm.list_chain_links(self._current_chain.id):
            f = self.dbm.get_finding(link.finding_id); label = f"#{link.finding_id} {f.title if f else '?'}"
            self.links.addItem(label); idx = self.links.count() - 1; self.links.item(idx).setData(Qt.UserRole, link.finding_id)

    def _add_link(self):
        if not self._current_chain: QMessageBox.information(self, "No chain", "Select a chain first."); return
        fid = self.finding_combo.currentData()
        if fid is None: return
        note, ok = QInputDialog.getText(self, "Role note", "How does this finding contribute?")
        if not ok: return
        self.dbm.add_chain_link(ChainLink(chain_id=self._current_chain.id, finding_id=fid, role_note=note)); self._refresh_links(); self.refresh()

    def _remove_link(self, item):
        if not self._current_chain: return
        fid = item.data(Qt.UserRole); self.dbm.remove_chain_link(self._current_chain.id, fid); self._refresh_links(); self.refresh()

    def _new_chain(self):
        dlg = ChainDialog(parent=self)
        if dlg.exec():
            c = dlg.value(self.dbm.engagement_id)
            if not c.title: return
            self.dbm.add_chain(c); self.refresh()

    def _edit_chain(self):
        if not self._current_chain: return
        dlg = ChainDialog(self._current_chain, parent=self)
        if dlg.exec(): updated = dlg.value(self.dbm.engagement_id); self.dbm.update_chain(updated); self.refresh()

    def _delete_chain(self):
        if not self._current_chain: return
        if QMessageBox.question(self, "Delete", "Delete this chain?") != QMessageBox.Yes: return
        self.dbm.delete_chain(self._current_chain.id); self._current_chain = None; self.refresh()

    def _transition(self, target: str):
        if not self._current_chain: return
        try: transition_chain(self._current_chain, target)
        except TransitionError as e: QMessageBox.warning(self, "Blocked", str(e)); return
        self.dbm.update_chain(self._current_chain); self.refresh()

    def detect(self):
        findings = self.dbm.list_findings()
        if len(findings) < 2: QMessageBox.information(self, "Not enough findings", "Add at least two findings first."); return
        potentials = detect_potential_chains(findings)
        if not potentials: QMessageBox.information(self, "No matches", "No potential chains detected."); return
        existing_titles = {c.title for c in self.dbm.list_chains()}; made = 0
        for p in potentials:
            title = f"{p.reason}: {p.finding_a.title[:30]} <-> {p.finding_b.title[:30]}"
            if title in existing_titles: continue
            cid = self.dbm.add_chain(Chain(engagement_id=self.dbm.engagement_id, title=title, description=f"Rule: {p.reason}. Review and confirm.", state="potential"))
            self.dbm.add_chain_link(ChainLink(chain_id=cid, finding_id=p.finding_a.id, role_note=f"Finding A ({p.finding_a.state})"))
            self.dbm.add_chain_link(ChainLink(chain_id=cid, finding_id=p.finding_b.id, role_note=f"Finding B ({p.finding_b.state})"))
            made += 1
        self.refresh(); QMessageBox.information(self, "Done", f"Created {made} chain(s).")
