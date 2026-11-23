"""Generation page for HA-UI 0.2.0.

The page is intentionally outcome-first: a prominent "生成 YAML" button, a short
selection summary, and a compact success state. Probe policy, progress log and
failure cleanup live under a collapsed "高级选项" panel. The CLI-consent checkbox
is shown only when the selected exports are stale; normal runs do not ask the
operator to re-read a page of safety prose.

Security behaviour is unchanged from 0.1.0: both pinned sessions are opened for
one operation, generation runs off the GUI thread, cancellation is checked
between stages, failures keep the previous successful output, and no path,
YAML, UUID or password is rendered in the log.
"""

from __future__ import annotations

import threading
from pathlib import Path
from typing import Callable, Mapping, Protocol

from PySide6.QtCore import QObject, Qt, Signal
from PySide6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QComboBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QPlainTextEdit,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from ..core import errors
from ..core.errors import HaUiError
from ..core.models import (
    DeliveredFile,
    GenerationResult,
    ProbePolicy,
    SelectedClient,
)
from .clients_panel import ClientsPanel
from .session_service import SessionGenerationService, format_stage
from .workers import WorkerRunner

POLICY_OPTIONS: tuple[tuple[str, ProbePolicy], ...] = (
    ("5s / 5000ms（默认）", ProbePolicy()),
    ("5s / 2000ms", ProbePolicy(5, 2000)),
    ("3s / 1000ms", ProbePolicy(3, 1000)),
    ("10s / 5000ms", ProbePolicy(10, 5000)),
)

CONSENT_TEXT = (
    "同意运行服务器上现有的 miaomiao CLI 菜单（幂等的主机依赖/权限维护，"
    "以及派生配置文件写入；不修改 sing-box 配置，不激活 Monitor/TUN/Clash）"
)

RESULT_COLUMNS = ("客户端", "文件", "操作")
COL_CLIENT, COL_FILE, COL_FOLDER = 0, 1, 2

NO_OUTPUT_TEXT = "生成结果会保存在本地私有目录。"


class GenerationNotifier(Protocol):
    def show_error(self, error: HaUiError) -> None: ...


class _ProgressBridge(QObject):
    """Thread-safe bridge: the worker emits, the GUI thread renders."""

    advanced = Signal(str)


class GeneratePanel(QWidget):
    """Request one generation attempt at a time; show safe progress/results."""

    def __init__(
        self,
        service: SessionGenerationService,
        runner: WorkerRunner,
        notifier: GenerationNotifier,
        clients_panel: ClientsPanel,
        password_provider: Callable[[], Mapping[str, str]] | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._service = service
        self._runner = runner
        self._notifier = notifier
        self._clients_panel = clients_panel
        self._password_provider = password_provider or (lambda: {})
        self._progress = _ProgressBridge(self)
        self._progress.advanced.connect(self._append_stage_label)
        self._busy = False
        self._cancel_event: threading.Event | None = None
        self._failed_run_id: str | None = None
        self._last_run_id: str | None = None
        self._output_dir: str | None = None
        self._build_ui()
        self._clients_panel.selection_changed.connect(self._refresh_context)
        self._clients_panel.preview_loaded.connect(self._refresh_context)
        self._refresh_context()
        self._apply_controls()

    # ------------------------------------------------------------------ build --
    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(10)

        top = QHBoxLayout()
        self.selection_label = QLabel("尚未选择客户端。", self)
        self.selection_label.setObjectName("generationSelection")
        self.selection_label.setWordWrap(True)
        top.addWidget(self.selection_label, 1)
        self.generate_button = QPushButton("生成 YAML", self)
        self.generate_button.setObjectName("primaryButton")
        self.generate_button.setMinimumHeight(38)
        self.generate_button.setMinimumWidth(160)
        top.addWidget(self.generate_button)
        layout.addLayout(top)

        self.consent_widget = QWidget(self)
        consent_layout = QVBoxLayout(self.consent_widget)
        consent_layout.setContentsMargins(0, 0, 0, 0)
        consent_layout.setSpacing(4)
        self.consent_hint_label = QLabel("", self.consent_widget)
        self.consent_hint_label.setObjectName("consentHint")
        self.consent_hint_label.setWordWrap(True)
        self.consent_checkbox = QCheckBox(CONSENT_TEXT, self.consent_widget)
        self.consent_checkbox.setObjectName("consentCheckbox")
        self.consent_checkbox.setToolTip(CONSENT_TEXT)
        consent_layout.addWidget(self.consent_hint_label)
        consent_layout.addWidget(self.consent_checkbox)
        self.consent_widget.setVisible(False)
        layout.addWidget(self.consent_widget)

        self.failure_label = QLabel("", self)
        self.failure_label.setObjectName("generationFailure")
        self.failure_label.setWordWrap(True)
        self.failure_label.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse)
        self.failure_label.setVisible(False)
        layout.addWidget(self.failure_label)

        success = QHBoxLayout()
        self.success_label = QLabel(NO_OUTPUT_TEXT, self)
        self.success_label.setObjectName("generationSuccess")
        self.success_label.setWordWrap(True)
        self.success_label.setStyleSheet("color: #667085; font-weight: 400;")
        success.addWidget(self.success_label, 1)
        self.open_output_button = QPushButton("打开文件夹", self)
        self.open_output_button.setObjectName("secondaryButton")
        self.open_output_button.setEnabled(False)
        success.addWidget(self.open_output_button)
        layout.addLayout(success)

        self.results_table = QTableWidget(0, len(RESULT_COLUMNS), self)
        self.results_table.setObjectName("generationResults")
        self.results_table.setHorizontalHeaderLabels(list(RESULT_COLUMNS))
        self.results_table.setEditTriggers(
            QAbstractItemView.EditTrigger.NoEditTriggers)
        self.results_table.setSelectionMode(
            QAbstractItemView.SelectionMode.NoSelection)
        self.results_table.verticalHeader().setVisible(False)
        self.results_table.setAlternatingRowColors(True)
        header = self.results_table.horizontalHeader()
        header.setStretchLastSection(False)
        header.setSectionResizeMode(COL_CLIENT,
                                    QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(COL_FILE,
                                    QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(COL_FOLDER,
                                    QHeaderView.ResizeMode.Fixed)
        self.results_table.setColumnWidth(COL_FOLDER, 100)
        layout.addWidget(self.results_table, 1)

        self.advanced_toggle = QToolButton(self)
        self.advanced_toggle.setObjectName("advancedToggle")
        self.advanced_toggle.setText("高级选项（探测策略 / 进度日志）")
        self.advanced_toggle.setCheckable(True)
        self.advanced_toggle.setChecked(False)
        self.advanced_toggle.setToolButtonStyle(
            Qt.ToolButtonStyle.ToolButtonTextBesideIcon)
        self.advanced_toggle.setArrowType(Qt.ArrowType.RightArrow)
        layout.addWidget(self.advanced_toggle, 0, Qt.AlignmentFlag.AlignLeft)

        self.advanced_widget = QWidget(self)
        advanced = QVBoxLayout(self.advanced_widget)
        advanced.setContentsMargins(8, 4, 8, 4)
        advanced.setSpacing(6)
        policy_row = QHBoxLayout()
        policy_row.addWidget(QLabel("探测策略", self.advanced_widget))
        self.policy_combo = QComboBox(self.advanced_widget)
        self.policy_combo.setObjectName("policyCombo")
        for text, policy in POLICY_OPTIONS:
            self.policy_combo.addItem(text, policy)
        self.policy_combo.setCurrentIndex(0)
        policy_row.addWidget(self.policy_combo)
        hint = QLabel("默认 5s / 5000ms；旧值仍可选，仅影响生成的 YAML。",
                      self.advanced_widget)
        hint.setObjectName("hint")
        policy_row.addWidget(hint)
        policy_row.addStretch(1)
        advanced.addLayout(policy_row)

        self.progress_log = QPlainTextEdit(self.advanced_widget)
        self.progress_log.setObjectName("generationLog")
        self.progress_log.setReadOnly(True)
        self.progress_log.setMaximumBlockCount(300)
        self.progress_log.setFixedHeight(110)
        advanced.addWidget(self.progress_log)

        controls = QHBoxLayout()
        self.cancel_button = QPushButton("取消", self.advanced_widget)
        self.retry_button = QPushButton("重试", self.advanced_widget)
        self.delete_failed_button = QPushButton("删除失败运行目录",
                                                self.advanced_widget)
        controls.addWidget(self.cancel_button)
        controls.addWidget(self.retry_button)
        controls.addWidget(self.delete_failed_button)
        controls.addStretch(1)
        advanced.addLayout(controls)
        self.advanced_widget.setVisible(False)
        layout.addWidget(self.advanced_widget)

        self.generate_button.clicked.connect(self._on_generate_clicked)
        self.cancel_button.clicked.connect(self._on_cancel_clicked)
        self.open_output_button.clicked.connect(self._on_open_output_clicked)
        self.retry_button.clicked.connect(self._on_retry_clicked)
        self.delete_failed_button.clicked.connect(
            self._on_delete_failed_clicked)
        self.advanced_toggle.toggled.connect(self._toggle_advanced)

    # ----------------------------------------------------------------- state ---
    @property
    def busy(self) -> bool:
        return self._busy

    @property
    def output_dir(self) -> str | None:
        return self._output_dir

    @property
    def failed_run_id(self) -> str | None:
        return self._failed_run_id

    def focus_generate(self) -> None:
        self.generate_button.setFocus(Qt.FocusReason.OtherFocusReason)

    def _toggle_advanced(self, shown: bool) -> None:
        self.advanced_widget.setVisible(shown)
        self.advanced_toggle.setArrowType(
            Qt.ArrowType.DownArrow if shown else Qt.ArrowType.RightArrow)

    def _has_attempt(self) -> bool:
        return self._last_run_id is not None or self._failed_run_id is not None

    def _apply_controls(self) -> None:
        if self._busy:
            self.generate_button.setEnabled(False)
            self.retry_button.setEnabled(False)
            self.policy_combo.setEnabled(False)
            self.consent_checkbox.setEnabled(False)
            self.cancel_button.setEnabled(self._cancel_event is not None)
            self.open_output_button.setEnabled(False)
            self.delete_failed_button.setEnabled(False)
            return
        self.generate_button.setEnabled(
            bool(self._clients_panel.selected_clients()))
        self.retry_button.setEnabled(self._has_attempt())
        self.policy_combo.setEnabled(True)
        self.consent_checkbox.setEnabled(True)
        self.cancel_button.setEnabled(False)
        self.open_output_button.setEnabled(bool(self._output_dir))
        self.delete_failed_button.setEnabled(
            self._failed_run_id is not None
            and self._service.run_dir_exists(self._failed_run_id))

    def _refresh_context(self) -> None:
        selected = self._clients_panel.selected_clients()
        if self._clients_panel.preview_result is None:
            self.selection_label.setText(
                "尚未读取客户端清单。请先在「客户端」页刷新。")
            self.consent_widget.setVisible(False)
            self._apply_controls()
            return
        if not selected:
            self.selection_label.setText(
                "尚未选择客户端。请在「客户端」页勾选可生成的客户端。")
            self.consent_widget.setVisible(False)
            self._apply_controls()
            return
        names = "、".join(item.name for item in selected)
        self.selection_label.setText(
            "已选 %d 项：%s" % (len(selected), names))
        if self._clients_panel.requires_generation_consent(selected):
            self.consent_hint_label.setText(
                "所选客户端在至少一端缺少最新导出；生成前需要明确同意运行 "
                "miaomiao 菜单生成派生文件。")
            self.consent_widget.setVisible(True)
        else:
            self.consent_widget.setVisible(False)
        self._apply_controls()

    # --------------------------------------------------------------- request ---
    def _collect_request(
        self,
    ) -> tuple[list[SelectedClient], ProbePolicy, bool, Mapping[str, str]]:
        if self._clients_panel.preview_result is None:
            raise HaUiError(errors.E_CONFIG, detail="preview",
                            message="请先刷新两端客户端清单")
        selected = self._clients_panel.selected_clients()
        if not selected:
            raise HaUiError(
                errors.E_USAGE, detail="clients",
                message="请先在「客户端」页勾选至少一个可生成的客户端")
        consent_required = self._clients_panel.requires_generation_consent(
            selected)
        allow_cli = self.consent_checkbox.isChecked() if consent_required else False
        if consent_required and not allow_cli:
            raise HaUiError(
                errors.E_USAGE, detail="cli-consent",
                message="所选客户端缺少最新导出，请先勾选同意运行 miaomiao 菜单")
        policy = self.policy_combo.currentData()
        if not isinstance(policy, ProbePolicy):
            raise HaUiError(errors.E_USAGE, detail="policy")
        return selected, policy, allow_cli, self._password_provider()

    def _on_generate_clicked(self) -> None:
        if self._busy:
            return
        try:
            request = self._collect_request()
        except HaUiError as exc:
            self._report_validation_error(exc)
            return
        except BaseException:  # noqa: BLE001 - hard GUI boundary
            self._report_validation_error(HaUiError(errors.E_INTERNAL))
            return
        self._start_generation(*request)

    def _on_retry_clicked(self) -> None:
        self._on_generate_clicked()

    def _report_validation_error(self, error: HaUiError) -> None:
        self.failure_label.setText(error.safe_text)
        self.failure_label.setVisible(True)
        self._show_advanced()
        self._append_line("未开始：%s" % error.safe_text)
        self._notifier.show_error(error)

    # -------------------------------------------------------------- generate ---
    def _start_generation(self, selected: list[SelectedClient],
                          policy: ProbePolicy, allow_cli: bool,
                          passwords: Mapping[str, str]) -> None:
        run_id = self._service.new_run_id()
        self._busy = True
        self._cancel_event = threading.Event()
        self.failure_label.setVisible(False)
        self.failure_label.setText("")
        self._append_line(
            "开始生成：%d 个客户端，策略 %s。" % (len(selected), policy.label))
        self._apply_controls()
        progress = self._progress.advanced.emit
        cancel = self._cancel_event.is_set

        def job() -> GenerationResult:
            return self._service.generate(
                selected=selected,
                policy=policy,
                allow_cli=allow_cli,
                run_id=run_id,
                password_overrides=passwords,
                progress=progress,
                cancel=cancel,
                cleanup_failed=False,
            )

        self._runner.run(
            job,
            on_success=lambda result: self._apply_success(result, run_id),
            on_error=lambda error: self._apply_failure(error, run_id),
            on_done=self._end_generation,
        )

    def _end_generation(self) -> None:
        self._busy = False
        self._cancel_event = None
        self._apply_controls()

    def _apply_success(self, result: GenerationResult, run_id: str) -> None:
        if result.failed_stage is not None:
            stage = result.failed_stage
            self._apply_failure(
                HaUiError(stage.code or errors.E_INTERNAL,
                          detail=stage.summary or None), run_id)
            return
        files = list(result.files)
        self._last_run_id = run_id
        self._failed_run_id = None
        self._output_dir = (str(Path(files[0].path).parent) if files else None)
        self._populate_results(files)
        self.failure_label.setVisible(False)
        self.failure_label.setText("")
        if files:
            self.success_label.setText("已生成 %d 个文件" % len(files))
            self.success_label.setStyleSheet(
                "color: #1f6b3a; font-size: 15px; font-weight: 600;")
            self.open_output_button.setEnabled(True)
            self._append_line("生成完成：%d 个文件。" % len(files))
        else:
            self.success_label.setText("生成完成，但没有返回交付文件。")
            self.success_label.setStyleSheet("color: #667085;")
            self.open_output_button.setEnabled(False)
            self._append_line("生成完成：没有返回交付文件。")

    def _apply_failure(self, error: HaUiError, run_id: str) -> None:
        # Previous successful output (table + success label) is deliberately kept.
        self._append_line("失败：%s" % error.safe_text)
        self.failure_label.setText(error.safe_text)
        self.failure_label.setVisible(True)
        self._show_advanced()
        self._notifier.show_error(error)
        if run_id is not None:
            self._failed_run_id = run_id
        self._apply_controls()

    def _populate_results(self, files: list[DeliveredFile]) -> None:
        self.results_table.setRowCount(0)
        for entry in files:
            row = self.results_table.rowCount()
            self.results_table.insertRow(row)
            client_item = QTableWidgetItem(entry.client)
            file_item = QTableWidgetItem(entry.filename)
            file_item.setToolTip("%s\nSHA-256: %s" % (entry.filename,
                                                     entry.sha256))
            self.results_table.setItem(row, COL_CLIENT, client_item)
            self.results_table.setItem(row, COL_FILE, file_item)
            button = QPushButton("打开目录", self.results_table)
            button.setObjectName("linkButton")
            folder = str(Path(entry.path).parent)
            button.clicked.connect(
                lambda _checked=False, target=folder: self._open_folder(target))
            self.results_table.setCellWidget(row, COL_FOLDER, button)
            self.results_table.setRowHeight(row, 30)

    # ---------------------------------------------------------------- cancel ---
    def _on_cancel_clicked(self) -> None:
        event = self._cancel_event
        if event is None or not self._busy:
            error = HaUiError(errors.E_CANCELLED)
            self.failure_label.setText(error.safe_text)
            self.failure_label.setVisible(True)
            self._show_advanced()
            self._append_line(error.safe_text)
            return
        event.set()
        self.cancel_button.setEnabled(False)
        self._append_line("已请求取消；当前阶段结束后停止。")

    # ---------------------------------------------------------------- folders --
    def _open_folder(self, path: str) -> None:
        try:
            self._service.open_output_folder(path)
        except HaUiError as exc:
            self._notifier.show_error(exc)
        except BaseException:  # noqa: BLE001 - hard GUI boundary
            self._notifier.show_error(HaUiError(errors.E_INTERNAL))

    def _on_open_output_clicked(self) -> None:
        if self._output_dir:
            self._open_folder(self._output_dir)

    # ---------------------------------------------------------- failed run ----
    def _on_delete_failed_clicked(self) -> None:
        if self._busy:
            return
        run_id = self._failed_run_id
        if not run_id:
            return
        if not self._service.run_dir_exists(run_id):
            self._failed_run_id = None
            self._apply_controls()
            self._append_line("没有需要删除的失败运行目录。")
            return
        self._busy = True
        self._apply_controls()

        def job() -> None:
            self._service.discard_failed_run(run_id)

        def success(_result: object) -> None:
            self._failed_run_id = None
            self._append_line("已删除失败运行目录。")

        def failure(error: HaUiError) -> None:
            self._append_line("删除失败：%s" % error.safe_text)
            self._notifier.show_error(error)

        self._runner.run(job, on_success=success, on_error=failure,
                         on_done=self._end_generation)

    # ------------------------------------------------------------------ log ---
    def _show_advanced(self) -> None:
        self.advanced_toggle.setChecked(True)

    def _append_stage_label(self, token: str) -> None:
        self._append_line(format_stage(token))

    def _append_line(self, text: str) -> None:
        self.progress_log.appendPlainText(text)
