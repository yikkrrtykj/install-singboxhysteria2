"""Client-management tab: read both VPS, show the union and pick clients.

The panel never talks to SSH itself: it hands a plain "password field snapshot"
to :class:`~ha_ui.ui.session_service.SessionGenerationService` inside a
:class:`~ha_ui.ui.workers.WorkerRunner` worker, so the whole connect + preview
operation runs off the GUI thread and both sessions are closed when it ends.

Safety rules enforced by the view:

* a row that exists on only one server, or whose Reality/HY2 protocol or
  credential is incomplete on either side, is rendered as blocked: it has no
  checkbox (so "全选可生成" can never select it) and the fixed reason token is
  translated into visible diagnosis text - no fake dual-active row;
* only the client name and fixed structural tokens are rendered; the preview
  carries no YAML/UUID/password, and this panel never displays a path;
* the certificate PIN *fingerprint* is intentionally not rendered; only the
  ``not_after`` validity date and the safe ``pin_warning``/preview warnings are.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Mapping, Protocol

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QBrush, QColor
from PySide6.QtWidgets import (
    QAbstractItemView,
    QComboBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from ..core.errors import HaUiError
from ..core.models import ClientRecord, SelectedClient
from ..core.service import PreviewResult
from .session_service import SessionGenerationService
from .workers import WorkerRunner

COLUMNS = (
    "选择",
    "客户端",
    "A 存在",
    "B 存在",
    "Reality",
    "HY2",
    "导出文件",
    "分组",
    "问题/诊断",
)
COL_SELECT, COL_NAME, COL_A, COL_B = 0, 1, 2, 3
COL_REALITY, COL_HY2, COL_EXPORT, COL_GROUP, COL_DIAGNOSIS = 4, 5, 6, 7, 8

GROUPS = ("A-first", "B-first")

# Fixed structural tokens from core.remote._build_records -> fixed Chinese text.
# Unknown tokens are mapped to a generic label so nothing raw is ever rendered.
PROBLEM_TEXT: dict[str, str] = {
    "missing-reality": "Reality 缺失",
    "no-reality-credential": "Reality 凭据缺失",
    "missing-hy2": "HY2 缺失",
    "no-hy2-credential": "HY2 凭据缺失",
    "name-set-mismatch": "本端协议名称集不一致",
    "reality-inbound-count": "Reality 入站数量异常",
    "hy2-inbound-count": "HY2 入站数量异常",
    "unnamed-reality": "存在未命名 Reality 用户",
    "unnamed-hy2": "存在未命名 HY2 用户",
    "duplicate-name": "存在重复客户端名",
    "reality-entry": "Reality 条目格式异常",
    "hy2-entry": "HY2 条目格式异常",
}
UNKNOWN_PROBLEM_TEXT = "结构异常"

NO_PREVIEW_TEXT = "未读取：请先确认 A/B 服务器配置与主机指纹，再点击「读取两端客户端」。"
UNREADABLE_NOTE = "不显示 YAML、UUID 或密码；仅显示客户端名称与完整性状态。"


class GenerationNotifier(Protocol):
    """The parts of ``MainWindow`` these tabs are allowed to call."""

    def show_error(self, error: HaUiError) -> None: ...


@dataclass(frozen=True)
class RowState:
    """Computed, display-only state for one union client."""

    name: str
    a: ClientRecord | None
    b: ClientRecord | None
    reasons: tuple[str, ...]
    notes: tuple[str, ...]

    @property
    def ready(self) -> bool:
        return not self.reasons


def _problem_text(token: str) -> str:
    return PROBLEM_TEXT.get(token, UNKNOWN_PROBLEM_TEXT)


def _present(value: bool | None) -> str:
    if value is None:
        return "—"
    return "✓" if value else "✗"


class ClientsPanel(QWidget):
    """Preview both VPS inventories; choose complete clients and their group."""

    selection_changed = Signal()
    preview_loaded = Signal()

    def __init__(
        self,
        service: SessionGenerationService,
        runner: WorkerRunner,
        notifier: GenerationNotifier,
        password_provider: Callable[[], Mapping[str, str]] | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._service = service
        self._runner = runner
        self._notifier = notifier
        self._password_provider = password_provider or (lambda: {})
        self._preview: PreviewResult | None = None
        self._busy = False
        self._populating = False
        self._build_ui()

    # ------------------------------------------------------------------ build --
    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(8)

        toolbar = QHBoxLayout()
        self.preview_button = QPushButton("读取两端客户端", self)
        self.select_all_button = QPushButton("全选可生成", self)
        self.select_all_button.setToolTip("只选择两端协议完整且一致的客户端")
        self.clear_button = QPushButton("清除选择", self)
        toolbar.addWidget(self.preview_button)
        toolbar.addWidget(self.select_all_button)
        toolbar.addWidget(self.clear_button)
        toolbar.addStretch(1)
        self.count_label = QLabel("尚未选择客户端", self)
        self.count_label.setObjectName("selectionCount")
        toolbar.addWidget(self.count_label)
        layout.addLayout(toolbar)

        self.pin_label = QLabel("证书 PIN 有效期：未读取", self)
        self.pin_label.setObjectName("pinStatus")
        self.pin_label.setWordWrap(True)
        layout.addWidget(self.pin_label)

        self.warning_label = QLabel("", self)
        self.warning_label.setObjectName("previewWarnings")
        self.warning_label.setWordWrap(True)
        layout.addWidget(self.warning_label)

        self.table = QTableWidget(0, len(COLUMNS), self)
        self.table.setObjectName("clientsTable")
        self.table.setHorizontalHeaderLabels(list(COLUMNS))
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.NoSelection)
        self.table.setAlternatingRowColors(True)
        self.table.verticalHeader().setVisible(False)
        header = self.table.horizontalHeader()
        header.setStretchLastSection(True)
        for column in (COL_SELECT, COL_A, COL_B, COL_REALITY, COL_HY2,
                       COL_EXPORT, COL_GROUP):
            header.setSectionResizeMode(
                column, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(COL_NAME, QHeaderView.ResizeMode.Interactive)
        self.table.setColumnWidth(COL_NAME, 180)
        layout.addWidget(self.table, 1)

        note = QLabel(UNREADABLE_NOTE, self)
        note.setObjectName("hint")
        note.setWordWrap(True)
        layout.addWidget(note)

        self.status_label = QLabel(NO_PREVIEW_TEXT, self)
        self.status_label.setObjectName("previewStatus")
        self.status_label.setWordWrap(True)
        self.status_label.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse)
        layout.addWidget(self.status_label)

        self.preview_button.clicked.connect(self._on_preview_clicked)
        self.select_all_button.clicked.connect(self.select_all_generatable)
        self.clear_button.clicked.connect(self.clear_selection)
        self.table.itemChanged.connect(self._on_item_changed)

    # ----------------------------------------------------------------- state ---
    @property
    def preview_result(self) -> PreviewResult | None:
        return self._preview

    @property
    def busy(self) -> bool:
        return self._busy

    @property
    def ready_count(self) -> int:
        return sum(1 for row in range(self.table.rowCount())
                   if self._row_state(row).ready)

    # --------------------------------------------------------------- preview ---
    def _on_preview_clicked(self) -> None:
        if self._busy:
            return
        try:
            passwords = self._password_provider()
            self._begin_preview()
        except BaseException:  # noqa: BLE001 - hard GUI boundary
            self._preview_failed(HaUiError(errors.E_INTERNAL))
            return

        def job() -> PreviewResult:
            return self._service.preview(password_overrides=passwords)

        self._runner.run(job, on_success=self._apply_preview,
                         on_error=self._preview_failed,
                         on_done=self._end_preview)

    def _begin_preview(self) -> None:
        self._busy = True
        self.preview_button.setEnabled(False)
        self.select_all_button.setEnabled(False)
        self.clear_button.setEnabled(False)
        self.status_label.setText("正在连接两端并读取客户端清单…")
        self._clear_view()

    def _end_preview(self) -> None:
        self._busy = False
        self.preview_button.setEnabled(True)
        self.select_all_button.setEnabled(True)
        self.clear_button.setEnabled(True)

    def _clear_view(self) -> None:
        """Drop a previous preview before the new one is known to be valid."""
        self._preview = None
        self._populating = True
        try:
            self.table.setRowCount(0)
        finally:
            self._populating = False
        self.pin_label.setText("证书 PIN 有效期：未读取")
        self.warning_label.setText("警告：未读取")
        self.count_label.setText("尚未选择客户端")
        self.selection_changed.emit()

    def _preview_failed(self, error: HaUiError) -> None:
        # A failed refresh must never leave a stale "ready" table behind.
        self._clear_view()
        self.status_label.setText("读取失败：%s" % error.safe_text)
        self._notifier.show_error(error)

    def _apply_preview(self, result: PreviewResult) -> None:
        self._preview = result
        self._populate_table(result)
        self.pin_label.setText(self._pin_summary(result))
        warnings = "；".join(result.warnings) if result.warnings else "无"
        self.warning_label.setText("警告：%s" % warnings)
        ready = self.ready_count
        self.status_label.setText(
            "读取完成：A 端 %d 个客户端，B 端 %d 个客户端，其中 %d 个可生成。"
            % (len(result.clients_a), len(result.clients_b), ready))
        self.preview_loaded.emit()
        self.selection_changed.emit()

    @staticmethod
    def _pin_summary(result: PreviewResult) -> str:
        parts = []
        for role in ("A", "B"):
            preview = result.servers.get(role)
            if preview is None:
                continue
            # Deliberately no fingerprint: only the validity date is UI material.
            parts.append("%s 端证书到期：%s" % (
                role, preview.pins.not_after.strftime("%Y-%m-%d %H:%M UTC")))
        return "；".join(parts) if parts else "证书 PIN 有效期：未读取"

    # ---------------------------------------------------------------- table ----
    def _populate_table(self, result: PreviewResult) -> None:
        self._populating = True
        try:
            self.table.setRowCount(0)
            for name in result.names:
                row = self.table.rowCount()
                self.table.insertRow(row)
                state = self._union_state(name, result)
                self._fill_row(row, state)
        finally:
            self._populating = False
        self._refresh_selection()

    def _union_state(self, name: str, result: PreviewResult) -> RowState:
        a = result.clients_a.get(name)
        b = result.clients_b.get(name)
        reasons: list[str] = []
        notes: list[str] = []
        if a is None:
            reasons.append("仅 B 端存在，A 端缺失")
        if b is None:
            reasons.append("仅 A 端存在，B 端缺失")
        for role, record in (("A", a), ("B", b)):
            if record is None:
                continue
            for token in record.problems:
                reasons.append("%s 端%s" % (role, _problem_text(token)))
            if not record.reality_ok and not (
                    "missing-reality" in record.problems
                    or "no-reality-credential" in record.problems):
                reasons.append("%s 端 Reality 不完整" % role)
            if not record.hy2_ok and not (
                    "missing-hy2" in record.problems
                    or "no-hy2-credential" in record.problems):
                reasons.append("%s 端 HY2 不完整" % role)
            if not record.derived_export_present:
                notes.append("%s 端导出需运行 miaomiao 菜单生成" % role)
        return RowState(name=name, a=a, b=b,
                        reasons=tuple(reasons), notes=tuple(notes))

    def _row_state(self, row: int) -> RowState:
        name_item = self.table.item(row, COL_NAME)
        name = name_item.data(Qt.ItemDataRole.UserRole) if name_item else ""
        if self._preview is None or not isinstance(name, str):
            return RowState(name=str(name or ""), a=None, b=None,
                            reasons=("未读取",), notes=())
        return self._union_state(name, self._preview)

    def _fill_row(self, row: int, state: RowState) -> None:
        blocked = not state.ready
        grey = QBrush(QColor("#7a828e"))
        red = QBrush(QColor("#9a2a00"))

        check = QTableWidgetItem()
        if blocked:
            check.setFlags(Qt.ItemFlag.ItemIsEnabled)
        else:
            check.setFlags(Qt.ItemFlag.ItemIsEnabled
                           | Qt.ItemFlag.ItemIsUserCheckable)
            check.setCheckState(Qt.CheckState.Unchecked)
        self.table.setItem(row, COL_SELECT, check)

        name_item = QTableWidgetItem(state.name)
        name_item.setData(Qt.ItemDataRole.UserRole, state.name)
        name_item.setToolTip(state.name)
        if blocked:
            name_item.setForeground(red)
        self.table.setItem(row, COL_NAME, name_item)

        values = {
            COL_A: "是" if state.a is not None else "否",
            COL_B: "是" if state.b is not None else "否",
            COL_REALITY: "A %s / B %s" % (
                _present(state.a.reality_ok if state.a else None),
                _present(state.b.reality_ok if state.b else None)),
            COL_HY2: "A %s / B %s" % (
                _present(state.a.hy2_ok if state.a else None),
                _present(state.b.hy2_ok if state.b else None)),
            COL_EXPORT: self._export_text(state),
            COL_DIAGNOSIS: self._diagnosis_text(state),
        }
        for column, text in values.items():
            item = QTableWidgetItem(text)
            if blocked:
                item.setForeground(grey)
            if column == COL_DIAGNOSIS:
                item.setToolTip(text)
            self.table.setItem(row, column, item)

        combo = QComboBox(self.table)
        combo.setObjectName("groupCombo")
        for group in GROUPS:
            combo.addItem(group, group)
        combo.setEnabled(not blocked)
        combo.setToolTip("选择哪一端优先（A-first / B-first）")
        combo.currentIndexChanged.connect(
            lambda _index, _combo=combo: self._on_group_changed())
        self.table.setCellWidget(row, COL_GROUP, combo)

        self.table.setRowHeight(row, 26)

    @staticmethod
    def _export_text(state: RowState) -> str:
        parts = []
        for role, record in (("A", state.a), ("B", state.b)):
            if record is None:
                parts.append("%s —" % role)
            elif record.derived_export_present:
                parts.append("%s 已就绪" % role)
            else:
                parts.append("%s 需生成" % role)
        return " / ".join(parts)

    @staticmethod
    def _diagnosis_text(state: RowState) -> str:
        if state.reasons:
            text = "不可生成：" + "；".join(state.reasons)
            if state.notes:
                text += "；" + "；".join(state.notes)
            return text
        if state.notes:
            return "可生成（需同意运行 miaomiao 菜单）：" + "；".join(state.notes)
        return "可生成"

    # ------------------------------------------------------------ selection ---
    def _on_item_changed(self, item: QTableWidgetItem) -> None:
        if self._populating or item.column() != COL_SELECT:
            return
        self._refresh_selection()

    def _on_group_changed(self) -> None:
        if self._populating:
            return
        self._refresh_selection()

    def select_all_generatable(self) -> None:
        """Select exactly the complete/consistent clients; never a blocked row."""
        self._populating = True
        try:
            for row in range(self.table.rowCount()):
                item = self.table.item(row, COL_SELECT)
                if item is None or not (
                        item.flags() & Qt.ItemFlag.ItemIsUserCheckable):
                    continue
                if self._row_state(row).ready:
                    item.setCheckState(Qt.CheckState.Checked)
        finally:
            self._populating = False
        self._refresh_selection()

    def clear_selection(self) -> None:
        self._populating = True
        try:
            for row in range(self.table.rowCount()):
                item = self.table.item(row, COL_SELECT)
                if item is not None and (
                        item.flags() & Qt.ItemFlag.ItemIsUserCheckable):
                    item.setCheckState(Qt.CheckState.Unchecked)
        finally:
            self._populating = False
        self._refresh_selection()

    def _refresh_selection(self) -> None:
        selected = self.selected_clients()
        if selected:
            self.count_label.setText(
                "已选 %d 个：%s" % (len(selected), "、".join(
                    "%s→%s" % (item.name, item.group) for item in selected)))
        else:
            self.count_label.setText("尚未选择客户端")
        self.selection_changed.emit()

    def selected_clients(self) -> list[SelectedClient]:
        result: list[SelectedClient] = []
        for row in range(self.table.rowCount()):
            check = self.table.item(row, COL_SELECT)
            if check is None or check.checkState() != Qt.CheckState.Checked:
                continue
            state = self._row_state(row)
            if not state.ready:
                continue
            combo = self.table.cellWidget(row, COL_GROUP)
            group = "A-first"
            if isinstance(combo, QComboBox):
                data = combo.currentData()
                if data in GROUPS:
                    group = str(data)
            result.append(SelectedClient(name=state.name, group=group))
        return result

    # --------------------------------------------------------------- consent ---
    def requires_generation_consent(
            self, selected: list[SelectedClient]) -> bool:
        """True when any selected client lacks a fresh derived export somewhere."""
        preview = self._preview
        if preview is None:
            return True
        for item in selected:
            for role in ("A", "B"):
                server = preview.servers.get(role)
                if server is None:
                    return True
                record = server.records.get(item.name)
                if record is None or not record.derived_export_present:
                    return True
        return False
