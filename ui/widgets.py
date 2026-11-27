from PySide6.QtGui import QColor
STATE_COLORS = {"raw": "#9e9e9e", "in_review": "#f0a500", "validated": "#2e7d32", "false_positive": "#c62828", "potential": "#f0a500", "confirmed": "#2e7d32", "dismissed": "#9e9e9e"}
SEVERITY_COLORS = {"critical": "#c62828", "high": "#ef6c00", "medium": "#f0a500", "low": "#1976d2", "info": "#616161"}
def color_for_state(state: str) -> QColor: return QColor(STATE_COLORS.get(state, "#9e9e9e"))
def color_for_severity(sev: str) -> QColor: return QColor(SEVERITY_COLORS.get(sev, "#616161"))
