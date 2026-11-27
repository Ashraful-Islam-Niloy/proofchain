from PySide6.QtCore import QUrl
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QTableWidget, QTableWidgetItem, QMessageBox, QLabel
from core.db import DatabaseManager
from core.evidence import sha256_file

class EvidenceVault(QWidget):
    def __init__(self, dbm: DatabaseManager):
        super().__init__()
        self.dbm = dbm; root = QVBoxLayout(self); bar = QHBoxLayout()
        refresh_btn = QPushButton("Refresh"); refresh_btn.clicked.connect(self.refresh); verify_btn = QPushButton("Verify All Hashes"); verify_btn.clicked.connect(self.verify)
        bar.addWidget(refresh_btn); bar.addWidget(verify_btn); bar.addStretch(); root.addLayout(bar)
        self.table = QTableWidget(0, 4); self.table.setHorizontalHeaderLabels(["Finding", "Kind", "Path / Text", "SHA-256"]); self.table.horizontalHeader().setStretchLastSection(True); self.table.cellDoubleClicked.connect(self._open); root.addWidget(self.table)
        self.status = QLabel(""); root.addWidget(self.status)

    def refresh(self):
        evs = self.dbm.list_all_evidence(); self.table.setRowCount(len(evs))
        for row, e in enumerate(evs):
            f = self.dbm.get_finding(e.finding_id); cells = [f"#{e.finding_id} {f.title if f else '?'}", e.kind, e.path_or_text, e.sha256]
            for col, text in enumerate(cells):
                item = QTableWidgetItem(text); item.setData(0x0100, e); self.table.setItem(row, col, item)
        self.status.setText(f"{len(evs)} evidence item(s).")

    def verify(self):
        evs = self.dbm.list_all_evidence(); ok, fail, skipped = 0, 0, 0; problems = []
        for e in evs:
            if e.kind == "note" or not e.path_or_text: skipped += 1; continue
            try: digest = sha256_file(e.path_or_text)
            except FileNotFoundError: fail += 1; problems.append(f"MISSING: {e.path_or_text}"); continue
            if digest == e.sha256: ok += 1
            else: fail += 1; problems.append(f"MISMATCH: {e.path_or_text}")
        msg = f"OK: {ok}  Mismatch: {fail}  Skipped: {skipped}"
        if problems: msg += "\n\n" + "\n".join(problems[:20])
        QMessageBox.information(self, "Hash verification", msg); self.status.setText(msg.split("\n")[0])

    def _open(self, row, _col):
        e = self.table.item(row, 0).data(0x0100)
        if e.kind == "note": QMessageBox.information(self, "Note", e.path_or_text)
        else: QDesktopServices.openUrl(QUrl.fromLocalFile(e.path_or_text))
