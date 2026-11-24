"""Client management page for HA-UI 0.2.0.

The page is a deliberately plain operator surface:

* top: A/B connection state, client counts and certificate health;
* primary action: create the same logical client on both VPSes;
* table: selection, name, two endpoint states, generation readiness and the
  A-first/B-first choice;
* bottom: the explicit "generate YAML" next step.

Technical diagnosis stays out of the default view. A blocked row shows one short
status, and its full fixed-token explanation is available from "查看原因" or the
status tooltip. Nothing here renders a UUID, password, YAML, remote path or raw
remote output.

The panel never talks to SSH itself: the service opens both pinned sessions for
one operation inside :class:`WorkerRunner`, and closes them again. A create click
is only a request; the actual remote write happens after the modal
:class:`~ha_ui.ui.dialogs.ClientCreateDialog` explicit confirmation.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Mapping, Protocol

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QBrush, QColor
from PySide6.QtWidgets import (
    QAbstractItemView,
    QComboBox,
    QDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from ..core import errors
from ..core.errors import HaUiError
from ..core.models import ClientCreationResult, ClientRecord, SelectedClient
from ..core.service import PreviewResult
from .dialogs import ClientCreateDialog
from .session_service import SessionGenerationService
from .workers import WorkerRunner

COLUMNS = (
    "选择",
    "客户端",
    "A 端",
    "B 端",
    "状态",
    "优先节点",
    "详情",
)
COL_SELECT, COL_NAME, COL_A, COL_B = 0, 1, 2, 3
COL_STATUS, COL_GROUP, COL_DETAIL = 4, 5, 6

GROUPS = ("A-first", "B-first")

# Fixed structural tokens from core.remote._build_records -> fixed Chinese text.
# Unknown tokens map to a generic label so nothing raw is ever rendered.
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

NO_PREVIEW_TEXT = "尚未读取客户端。点击「刷新客户端」连接 A/B 两端。"
EMPTY_TEXT = "尚无客户端。点击「新建客户端」在两台 VPS 上创建同名客户端。"
HINT_TEXT = "创建会修改两台 VPS 的 sing-box 配置，并可能触发 reload。"

CREATE_OK_TEMPLATE = "客户端「%s」已创建"
CREATE_REPAIR_TEMPLATE = "客户端「%s」已补齐"
CREATE_PARTIAL_TEMPLATE = (
    "已保留已创建的一端；失败端需要单独检查，软件不会自动删除或重试写入。"
)
# A failure that may have crossed the write boundary must never claim that the
# servers were untouched.
CREATE_UNCONFIRMED_TEXT = (
    "创建结果待确认：%s\n可能已写入服务器。请刷新两端状态核实；"
    "确认之前不要重复创建同名客户端。"
)
CREATE_PREWRITE_FAILED_TEXT = (
    "创建失败：%s\n未修改任何客户端（在预写检查/确认阶段停止）。"
)
STALE_TEXT = (
    "两端状态未能刷新（STALE / UNKNOWN）。本地显示可能已过期；"
    "请恢复连接后重新读取，不能据此判断服务器未被修改。"
)
TX_RUNNING_TEXT = (
    "远端创建事务尚未结束（%s）。软件已停止等待，但没有终止远端事务；"
    "请稍后刷新，确认终局前不要重复创建同名客户端。"
)
UNCONFIRMED_RETRY_TEXT = (
    "客户端「%s」上次创建结果未确认。请先刷新两端并确认实际状态，再决定是否重建。"
)

# Errors raised strictly before the canonical add path could replace the config
# file. Everything else may have written, so the panel must refresh instead of
# claiming "nothing changed".
_PREWRITE_ONLY_CODES = frozenset({
    errors.E_USAGE, errors.E_CONFIG, errors.E_CONFIG_SCHEMA,
    errors.E_HOSTKEY_MISSING, errors.E_HOSTKEY_MISMATCH,
    errors.E_HOSTKEY_FORMAT, errors.E_SSH_CONNECT, errors.E_SSH_AUTH,
    errors.E_CREDENTIAL_MISSING, errors.E_CREDENTIAL_STORE,
    errors.E_CREDENTIAL_UNAVAILABLE, errors.E_REMOTE_PREFLIGHT,
    errors.E_REMOTE_PIN, errors.E_REMOTE_COMMAND, errors.E_REMOTE_LIST,
    errors.E_REMOTE_NOT_ROOT, errors.E_REMOTE_PLATFORM,
    errors.E_INSTALLER_UNTRUSTED, errors.E_CLIENT_EXISTS,
    errors.E_CLIENT_INCOMPLETE, errors.E_CLIENT_PARTIAL_EXISTS,
    errors.E_CANCELLED,
})


class GenerationNotifier(Protocol):
    """The parts of ``MainWindow`` this page is allowed to call."""

    def show_error(self, error: HaUiError) -> None: ...

    def show_info(self, title: str, text: str) -> None: ...

    def show_warning(self, title: str, text: str) -> None: ...

    def confirm_partial_creation(self, name: str,
                                 existing_role: str) -> bool: ...


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

    @property
    def status(self) -> str:
        if self.a is None:
            return "缺少 A 端"
        if self.b is None:
            return "缺少 B 端"
        if self.reasons:
            return "配置异常"
        if not self.a.derived_export_present or not self.b.derived_export_present:
            return "待生成"
        return "可生成"

    @property
    def detail_text(self) -> str:
        if self.reasons:
            parts = list(self.reasons)
            if self.notes:
                parts.extend(self.notes)
            return "；".join(parts)
        if self.notes:
            return "可生成；" + "；".join(self.notes)
        return "两端协议完整，规范导出已就绪。"


def _problem_text(token: str) -> str:
    return PROBLEM_TEXT.get(token, UNKNOWN_PROBLEM_TEXT)


def _endpoint_text(record: ClientRecord | None) -> str:
    if record is None:
        return "缺失"
    return "正常" if record.complete else "异常"


class ClientsPanel(QWidget):
    """Preview both VPS inventories; create clients; choose the next step."""

    selection_changed = Signal()
    preview_loaded = Signal()
    generate_requested = Signal()
    client_created = Signal(str)

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
        self._pending_select: str | None = None
        self._pending_repair: tuple[str, bool] | None = None
        self._creation_allow_partial = False
        self._creation_needs_refresh = False
        self._unconfirmed: set[str] = set()
        self._pending_running: list[str] = []
        self._build_ui()

    # ------------------------------------------------------------------ build --
    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)

        summary = QHBoxLayout()
        self.server_a_label = QLabel("A：未读取", self)
        self.server_a_label.setObjectName("serverSummary")
        self.server_b_label = QLabel("B：未读取", self)
        self.server_b_label.setObjectName("serverSummary")
        self.client_count_label = QLabel("客户端 0 个", self)
        self.client_count_label.setObjectName("clientCount")
        summary.addWidget(self.server_a_label)
        summary.addSpacing(18)
        summary.addWidget(self.server_b_label)
        summary.addStretch(1)
        summary.addWidget(self.client_count_label)
        layout.addLayout(summary)

        toolbar = QHBoxLayout()
        self.create_button = QPushButton("＋ 新建客户端", self)
        self.create_button.setObjectName("primaryButton")
        self.create_button.setToolTip(
            "在两台 VPS 上创建同一个逻辑客户端；每端各自生成 Reality UUID 和 HY2 密码")
        self.refresh_button = QPushButton("刷新客户端", self)
        self.refresh_button.setObjectName("secondaryButton")
        toolbar.addWidget(self.create_button)
        toolbar.addWidget(self.refresh_button)
        toolbar.addStretch(1)

        self.cert_label = QLabel("证书：未读取", self)
        self.cert_label.setObjectName("certSummary")
        self.cert_detail_button = QPushButton("详情", self)
        self.cert_detail_button.setObjectName("linkButton")
        self.cert_detail_button.setVisible(False)
        toolbar.addWidget(self.cert_label)
        toolbar.addWidget(self.cert_detail_button)
        layout.addLayout(toolbar)

        self.creation_result_label = QLabel("", self)
        self.creation_result_label.setObjectName("creationResult")
        self.creation_result_label.setWordWrap(True)
        self.creation_result_label.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse)
        self.creation_result_label.setVisible(False)
        layout.addWidget(self.creation_result_label)

        self.table = QTableWidget(0, len(COLUMNS), self)
        self.table.setObjectName("clientsTable")
        self.table.setHorizontalHeaderLabels(list(COLUMNS))
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.NoSelection)
        self.table.setAlternatingRowColors(True)
        self.table.setWordWrap(False)
        self.table.setTextElideMode(Qt.TextElideMode.ElideRight)
        self.table.verticalHeader().setVisible(False)
        header = self.table.horizontalHeader()
        header.setStretchLastSection(False)
        for column in (COL_SELECT, COL_A, COL_B, COL_STATUS):
            header.setSectionResizeMode(
                column, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(COL_NAME, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(COL_GROUP, QHeaderView.ResizeMode.Fixed)
        header.setSectionResizeMode(COL_DETAIL, QHeaderView.ResizeMode.Fixed)
        self.table.setColumnWidth(COL_GROUP, 112)
        self.table.setColumnWidth(COL_DETAIL, 86)
        layout.addWidget(self.table, 1)

        self.empty_label = QLabel(NO_PREVIEW_TEXT, self)
        self.empty_label.setObjectName("emptyState")
        self.empty_label.setWordWrap(True)
        self.empty_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.empty_label)

        footer = QHBoxLayout()
        self.select_all_button = QPushButton("全选可生成", self)
        self.select_all_button.setObjectName("secondaryButton")
        self.select_all_button.setToolTip("只选择两端协议完整且一致的客户端")
        self.clear_button = QPushButton("清除选择", self)
        self.clear_button.setObjectName("secondaryButton")
        self.selection_label = QLabel("尚未选择", self)
        self.selection_label.setObjectName("selectionCount")
        self.generate_yaml_button = QPushButton("生成 YAML", self)
        self.generate_yaml_button.setObjectName("primaryButton")
        self.generate_yaml_button.setEnabled(False)
        footer.addWidget(self.select_all_button)
        footer.addWidget(self.clear_button)
        footer.addSpacing(8)
        footer.addWidget(self.selection_label)
        footer.addStretch(1)
        footer.addWidget(self.generate_yaml_button)
        layout.addLayout(footer)

        self.status_label = QLabel(NO_PREVIEW_TEXT, self)
        self.status_label.setObjectName("previewStatus")
        self.status_label.setWordWrap(True)
        self.status_label.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse)
        layout.addWidget(self.status_label)

        self.hint_label = QLabel(HINT_TEXT, self)
        self.hint_label.setObjectName("hint")
        self.hint_label.setWordWrap(True)
        layout.addWidget(self.hint_label)

        self.create_button.clicked.connect(self._on_create_clicked)
        self.refresh_button.clicked.connect(self._on_refresh_clicked)
        self.select_all_button.clicked.connect(self.select_all_generatable)
        self.clear_button.clicked.connect(self.clear_selection)
        self.generate_yaml_button.clicked.connect(
            self.generate_requested.emit)
        self.cert_detail_button.clicked.connect(self._show_certificate_details)
        self.table.itemChanged.connect(self._on_item_changed)

        self.empty_label.setVisible(True)
        self._apply_controls()

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

    def set_configured_servers(self, servers: Mapping[str, object]) -> None:
        """Initial summary before any connection: configured or not."""
        for role, label in (("A", self.server_a_label),
                            ("B", self.server_b_label)):
            server = servers.get(role)
            host = getattr(server, "host", "")
            if host:
                label.setText("%s：已配置" % role)
                label.setToolTip("%s 端已保存连接信息，尚未读取" % role)
            else:
                label.setText("%s：未配置" % role)
                label.setToolTip("请先在「服务器」页填写并保存")

    def _apply_controls(self) -> None:
        enabled = not self._busy
        self.create_button.setEnabled(enabled)
        self.refresh_button.setEnabled(enabled)
        self.select_all_button.setEnabled(enabled)
        self.clear_button.setEnabled(enabled)
        self.generate_yaml_button.setEnabled(
            enabled and bool(self.selected_clients()))

    # --------------------------------------------------------------- preview ---
    def _on_refresh_clicked(self) -> None:
        self.refresh_clients()

    def refresh_clients(self, on_loaded: Callable[[], None] | None = None) -> None:
        """Read both inventories off the GUI thread; always close the sessions."""
        if self._busy:
            return
        try:
            passwords = self._password_provider()
            self._begin_preview()
        except BaseException:  # noqa: BLE001 - hard GUI boundary
            self._preview_failed(HaUiError(errors.E_INTERNAL))
            return

        def job() -> PreviewResult:
            return self._service.preview(
                password_overrides=passwords,
                pending_names=tuple(sorted(self._unconfirmed)))

        def success(result: PreviewResult) -> None:
            self._apply_preview(result)
            if on_loaded is not None:
                try:
                    on_loaded()
                except BaseException:  # noqa: BLE001 - GUI boundary
                    pass

        self._runner.run(job, on_success=success,
                         on_error=self._preview_failed,
                         on_done=self._end_preview)

    def _begin_preview(self) -> None:
        self._busy = True
        self._apply_controls()
        self.status_label.setText("正在连接 A/B 两端并读取客户端清单…")
        self._clear_view()

    def _end_preview(self) -> None:
        self._busy = False
        self._apply_controls()

    def _clear_view(self) -> None:
        """Drop a previous preview before the new one is known to be valid."""
        self._preview = None
        self._populating = True
        try:
            self.table.setRowCount(0)
        finally:
            self._populating = False
        self.empty_label.setVisible(True)
        self.empty_label.setText(NO_PREVIEW_TEXT)
        self.client_count_label.setText("客户端 0 个")
        self.cert_label.setText("证书：未读取")
        self.cert_label.setStyleSheet("")
        self.cert_detail_button.setVisible(False)
        self.selection_label.setText("尚未选择")
        self.generate_yaml_button.setEnabled(False)
        self.selection_changed.emit()

    def _preview_failed(self, error: HaUiError) -> None:
        # A failed refresh must never leave a stale "ready" table behind.
        self._clear_view()
        self.status_label.setText("刷新失败：%s" % error.safe_text)
        if self._unconfirmed:
            # The unconfirmed write and the refresh failure compose: the local
            # view is unknown, and that says nothing about the servers.
            self.creation_result_label.setText(STALE_TEXT)
            self.creation_result_label.setVisible(True)
        self._notifier.show_error(error)

    def _apply_preview(self, result: PreviewResult) -> None:
        self._preview = result
        # A successful snapshot is NOT proof that the remote transaction ended.
        # Only a durable "absent" or "terminal" state may release a blocked name.
        for name, state in result.pending.items():
            if state in ("absent", "terminal"):
                self._unconfirmed.discard(name)
        self._pending_running = sorted(
            name for name, state in result.pending.items()
            if name in self._unconfirmed)
        self._populate_table(result)
        self._update_certificate_summary(result)
        for role, label in (("A", self.server_a_label),
                            ("B", self.server_b_label)):
            preview = result.servers.get(role)
            count = len(preview.records) if preview is not None else 0
            label.setText("%s：已连接 · %d 个" % (role, count))
            label.setToolTip("%s 端客户端清单已读取" % role)
        self.client_count_label.setText(
            "客户端 %d 个 · 可生成 %d 个" % (len(result.names),
                                            self.ready_count))
        if result.names:
            self.status_label.setText(
                "读取完成：A 端 %d 个，B 端 %d 个。"
                % (len(result.clients_a), len(result.clients_b)))
        else:
            self.status_label.setText("读取完成：两端都还没有客户端。")
            self.empty_label.setText(EMPTY_TEXT)
        if self._unconfirmed:
            self.status_label.setText(
                self.status_label.text()
                + "\n⚠ 仍有未确认的远端创建事务（%s）；确认前不要重建同名客户端。"
                % "、".join(sorted(self._unconfirmed)))
        self.empty_label.setVisible(not bool(result.names))
        self.preview_loaded.emit()
        self.selection_changed.emit()

    def _update_certificate_summary(self, result: PreviewResult) -> None:
        warnings = [text for text in result.warnings if "证书" in text]
        if warnings:
            self.cert_label.setText("证书提醒")
            self.cert_label.setStyleSheet("color: #9a5b00; font-weight: 600;")
            self.cert_detail_button.setVisible(True)
            self.cert_label.setToolTip("；".join(warnings))
            self._cert_warning_text = "；".join(warnings)
            return
        self.cert_label.setText("证书：A / B 正常")
        self.cert_label.setStyleSheet("color: #1f6b3a; font-weight: 600;")
        self.cert_detail_button.setVisible(False)
        self._cert_warning_text = ""

    def _show_certificate_details(self) -> None:
        preview = self._preview
        if preview is None:
            return
        lines = [getattr(self, "_cert_warning_text", "")
                 or "A/B 两端 HY2 证书均在正常有效期。"]
        lines.append("")
        for role in ("A", "B"):
            server = preview.servers.get(role)
            if server is None:
                continue
            local = server.pins.not_after.astimezone()
            lines.append(
                "%s 端到期：%s（本地）/ %s UTC"
                % (role, local.strftime("%Y-%m-%d %H:%M"),
                   server.pins.not_after.strftime("%Y-%m-%d %H:%M")))
        self._notifier.show_info("HY2 证书", "\n".join(lines))

    # ---------------------------------------------------------------- table ----
    def _populate_table(self, result: PreviewResult) -> None:
        self._populating = True
        try:
            self.table.setRowCount(0)
            for name in result.names:
                row = self.table.rowCount()
                self.table.insertRow(row)
                self._fill_row(row, self._union_state(name, result))
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
            role_problems = [_problem_text(token)
                             for token in record.problems]
            # A structural token may appear globally more than once; keep the
            # row short and deterministic.
            for text in dict.fromkeys(role_problems):
                value = "%s 端 %s" % (role, text)
                if value not in reasons:
                    reasons.append(value)
            if not record.reality_ok and not any(
                    "Reality" in text for text in role_problems):
                reasons.append("%s 端 Reality 不完整" % role)
            if not record.hy2_ok and not any(
                    "HY2" in text for text in role_problems):
                reasons.append("%s 端 HY2 不完整" % role)
            if not record.derived_export_present:
                notes.append("%s 端规范导出待生成" % role)
        return RowState(name=name, a=a, b=b,
                        reasons=tuple(dict.fromkeys(reasons)),
                        notes=tuple(notes))

    def _row_state(self, row: int) -> RowState:
        name_item = self.table.item(row, COL_NAME)
        name = name_item.data(Qt.ItemDataRole.UserRole) if name_item else ""
        if self._preview is None or not isinstance(name, str):
            return RowState(name=str(name or ""), a=None, b=None,
                            reasons=("未读取",), notes=())
        return self._union_state(name, self._preview)

    def _fill_row(self, row: int, state: RowState) -> None:
        blocked = not state.ready
        grey = QBrush(QColor("#8a929e"))
        red = QBrush(QColor("#9a2a00"))
        amber = QBrush(QColor("#9a5b00"))

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

        for column, text in (
                (COL_A, _endpoint_text(state.a)),
                (COL_B, _endpoint_text(state.b)),
                (COL_STATUS, state.status)):
            item = QTableWidgetItem(text)
            item.setToolTip(state.detail_text if column == COL_STATUS else text)
            if blocked and column in (COL_A, COL_B) and text in ("缺失", "异常"):
                item.setForeground(red)
            elif blocked and column == COL_STATUS:
                item.setForeground(red)
            elif blocked:
                item.setForeground(grey)
            elif state.status == "待生成":
                item.setForeground(amber)
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

        if blocked:
            detail = QPushButton("查看原因", self.table)
            detail.setObjectName("linkButton")
            detail.setToolTip(state.detail_text)
            detail.clicked.connect(
                lambda _checked=False, name=state.name: self._show_reasons(name))
            self.table.setCellWidget(row, COL_DETAIL, detail)
        else:
            item = QTableWidgetItem("")
            self.table.setItem(row, COL_DETAIL, item)
        self.table.setRowHeight(row, 30)

    def _show_reasons(self, name: str) -> None:
        preview = self._preview
        if preview is None:
            return
        state = self._union_state(name, preview)
        self._notifier.show_info("客户端「%s」" % name, state.detail_text)

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

    def select_client(self, name: str) -> bool:
        """Check exactly one ready client; return whether it was selectable."""
        found = False
        self._populating = True
        try:
            for row in range(self.table.rowCount()):
                item = self.table.item(row, COL_SELECT)
                name_item = self.table.item(row, COL_NAME)
                if item is None or name_item is None:
                    continue
                checkable = bool(
                    item.flags() & Qt.ItemFlag.ItemIsUserCheckable)
                is_target = name_item.text() == name and checkable
                item.setCheckState(
                    Qt.CheckState.Checked if is_target
                    else Qt.CheckState.Unchecked)
                found = found or is_target
        finally:
            self._populating = False
        self._refresh_selection()
        return found

    def _refresh_selection(self) -> None:
        selected = self.selected_clients()
        if selected:
            self.selection_label.setText("已选 %d 项" % len(selected))
            self.selection_label.setToolTip(
                "、".join(item.name for item in selected))
        else:
            self.selection_label.setText("尚未选择")
            self.selection_label.setToolTip("")
        self.generate_yaml_button.setEnabled(
            not self._busy and bool(selected))
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

    # ---------------------------------------------------------------- create ---
    def _ask_create_name(self) -> str | None:
        dialog = ClientCreateDialog(self)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return None
        return dialog.client_name

    def _on_create_clicked(self) -> None:
        if self._busy:
            return
        try:
            name = self._ask_create_name()
        except BaseException:  # noqa: BLE001 - hard GUI boundary
            self._notifier.show_error(HaUiError(errors.E_INTERNAL))
            return
        if not name:
            return
        if name in self._unconfirmed:
            # A previous attempt may have written this name; the operator must
            # look at the live state before writing again.
            self._notifier.show_warning(
                "创建结果尚未确认", UNCONFIRMED_RETRY_TEXT % name)
            self.status_label.setText(UNCONFIRMED_RETRY_TEXT % name)
            return
        self._start_creation(name, allow_partial_repair=False)

    def _start_creation(self, name: str, *, allow_partial_repair: bool) -> None:
        # Passwords are snapshotted HERE, on the GUI thread: the worker closure
        # must never touch a QWidget or the session password provider.
        try:
            passwords = dict(self._password_provider())
        except BaseException:  # noqa: BLE001 - hard GUI boundary
            self._notifier.show_error(HaUiError(errors.E_INTERNAL))
            return
        self._busy = True
        self._creation_allow_partial = allow_partial_repair
        self._pending_repair = None
        self._pending_select = None
        self._creation_needs_refresh = False
        self.creation_result_label.setVisible(False)
        self.creation_result_label.setText("")
        self._apply_controls()
        self.status_label.setText(
            "正在创建「%s」：检查两端并顺序提交，可能需要几十秒…" % name)
        self._pending_creation = (name, allow_partial_repair)

        def job() -> ClientCreationResult:
            return self._service.create_client(
                name=name,
                confirmed=True,
                allow_partial_repair=allow_partial_repair,
                password_overrides=passwords,
            )

        self._runner.run(
            job,
            on_success=self._creation_succeeded,
            on_error=self._creation_failed,
            on_done=self._creation_done,
        )

    def _creation_succeeded(self, result: ClientCreationResult) -> None:
        if result.complete:
            self.creation_result_label.setVisible(False)
            self.creation_result_label.setText("")
            if result.repaired_existing:
                title = CREATE_REPAIR_TEMPLATE % result.name
            else:
                title = CREATE_OK_TEMPLATE % result.name
            detail = self._creation_detail(result)
            self._notifier.show_info(title, detail)
            self.status_label.setText("创建成功；正在刷新两端状态…")
            self._pending_select = result.name
        else:
            message = self._creation_detail(result)
            self.creation_result_label.setText(
                "上次创建「%s」未全部完成：\n%s" % (result.name, message))
            self.creation_result_label.setVisible(True)
            self._notifier.show_warning("创建未全部完成", message)
            self.status_label.setText("创建未全部完成；正在刷新实际状态…")
            # A side that is not proven terminal keeps the name blocked until a
            # durable terminal state (or absence) is observed.
            for role in ("A", "B"):
                side = result.side(role)
                if side is not None and side.status == "uncertain":
                    self._unconfirmed.add(result.name)
        self._creation_needs_refresh = True

    def _creation_failed(self, error: HaUiError) -> None:
        if (error.code == errors.E_CLIENT_PARTIAL_EXISTS
                and not self._creation_allow_partial):
            name = getattr(self, "_pending_creation", ("", False))[0]
            role = error.detail or "一端"
            try:
                allowed = self._notifier.confirm_partial_creation(name, role)
            except BaseException:  # noqa: BLE001 - GUI boundary
                allowed = False
            if allowed:
                self._pending_repair = (name, True)
                self.status_label.setText(
                    "已确认仅补齐缺失端；准备重新连接…")
                return
        if self._may_have_written(error):
            name = getattr(self, "_pending_creation", ("", False))[0]
            if name:
                self._unconfirmed.add(name)
            if error.detail in ("running", "tx-transport", "tx-unfinished",
                                "tx-absent"):
                self.creation_result_label.setText(
                    TX_RUNNING_TEXT % (error.detail or "unknown"))
            else:
                self.creation_result_label.setText(
                    CREATE_UNCONFIRMED_TEXT % error.safe_text)
            self.creation_result_label.setVisible(True)
            self.status_label.setText(
                "创建结果待确认；正在刷新两端实际状态…")
            self._creation_needs_refresh = True
            self._notifier.show_error(error)
            return
        self.creation_result_label.setText(
            CREATE_PREWRITE_FAILED_TEXT % error.safe_text)
        self.creation_result_label.setVisible(True)
        self.status_label.setText("创建失败：%s" % error.safe_text)
        self._notifier.show_error(error)
        # Pre-write refusals never changed either VPS, so do not open another
        # pair of sessions just to show the same failure again. Write outcomes
        # (including partial/uncertain) are returned as a result and do refresh.

    @staticmethod
    def _may_have_written(error: HaUiError) -> bool:
        """True unless the error is a fixed pre-write refusal.

        Fail-safe: an unknown code counts as "may have written" so the operator
        is asked to re-read instead of being told nothing changed.
        """
        return error.code not in _PREWRITE_ONLY_CODES

    def _creation_done(self) -> None:
        self._busy = False
        self._apply_controls()
        repair = self._pending_repair
        if repair is not None:
            self._pending_repair = None
            self._start_creation(repair[0], allow_partial_repair=True)
            return
        if self._creation_needs_refresh:
            self._creation_needs_refresh = False
            self._refresh_after_create()

    def _refresh_after_create(self) -> None:
        pending_name = self._pending_select
        if pending_name:
            self._pending_select = None

            def after() -> None:
                if self.select_client(pending_name):
                    self.client_created.emit(pending_name)

            self.refresh_clients(on_loaded=after)
            return
        self.refresh_clients()

    @staticmethod
    def _creation_detail(result: ClientCreationResult) -> str:
        lines = ["客户端：%s" % result.name]
        for role in ("A", "B"):
            side = result.side(role)
            if side is None:
                continue
            if side.status == "created":
                lines.append("%s 端：已创建" % role)
            elif side.status == "existing":
                lines.append("%s 端：原已存在（未改动）" % role)
            elif side.status == "failed":
                if side.detail == "rolled-back":
                    lines.append("%s 端：已回滚，配置已恢复（未提交）" % role)
                else:
                    lines.append("%s 端：失败（%s）" % (role, side.code or "E_REMOTE"))
            elif side.status == "uncertain":
                lines.append("%s 端：待确认（%s）" % (role, side.code or "E_CREATE_UNCERTAIN"))
            elif side.status == "skipped":
                lines.append("%s 端：未执行" % role)
        if result.partial:
            lines.append("")
            lines.append(CREATE_PARTIAL_TEMPLATE)
        return "\n".join(lines)
