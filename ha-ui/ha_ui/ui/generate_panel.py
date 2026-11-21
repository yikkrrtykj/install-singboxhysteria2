"""Generation tab: policy, explicit CLI consent, progress, cancel and results.

The panel owns no security decision:

* the actual connect + HA-chain work runs in :class:`~ha_ui.ui.workers.WorkerRunner`
  off the GUI thread, through the injected
  :class:`~ha_ui.ui.session_service.SessionGenerationService`;
* cancellation is a :class:`threading.Event` handed to the core pipeline, which
  checks it between stages and raises a safe ``E_CANCELLED``;
* the progress bridge only maps the core's fixed stage tokens to fixed labels -
  no path, YAML, UUID or password is ever rendered in the log;
* a failed attempt keeps the previous output notes and delivered-file table
  untouched; only a failed run can offer 删除失败运行目录.

Nothing here imports, activates or configures TUN/Clash/Monitor, and the panel
never imports a generated configuration file: it only reports the delivered
file names and their SHA-256 digests.
"""

from __future__ import annotations

import threading
from pathlib import Path
from typing import Callable, Mapping, Protocol

from PySide6.QtCore import QObject, Qt, Signal
from PySide6.QtGui import QFontDatabase
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
    ("5s / 2000ms（默认）", ProbePolicy(5, 2000)),
    ("3s / 1000ms", ProbePolicy(3, 1000)),
    ("10s / 5000ms", ProbePolicy(10, 5000)),
)

CONSENT_TEXT = (
    "同意运行服务器上现有的 miaomiao CLI 菜单（幂等的主机依赖/权限维护，"
    "以及派生配置文件写入；不修改 sing-box 配置，不激活 Monitor/TUN/Clash）"
)

RESULT_COLUMNS = ("客户端", "文件", "SHA-256", "输出目录")
COL_CLIENT, COL_FILE, COL_SHA, COL_FOLDER = 0, 1, 2, 3

NO_OUTPUT_TEXT = "尚无成功输出。"


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
        self._sha_font = QFontDatabase.systemFont(
            QFontDatabase.SystemFont.FixedFont)
        self._build_ui()
        self._clients_panel.selection_changed.connect(self._refresh_context)
        self._clients_panel.preview_loaded.connect(self._refresh_context)
        self._refresh_context()
        self._apply_controls()

    # ------------------------------------------------------------------ build --
    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(8)

        self.selection_label = QLabel(
            "尚未读取客户端清单：请先在「客户端管理」点击「读取两端客户端」。",
            self)
        self.selection_label.setObjectName("generationSelection")
        self.selection_label.setWordWrap(True)
        layout.addWidget(self.selection_label)

        policy_row = QHBoxLayout()
        self.policy_label = QLabel("探测策略", self)
        self.policy_combo = QComboBox(self)
        self.policy_combo.setObjectName("policyCombo")
        for text, policy in POLICY_OPTIONS:
            self.policy_combo.addItem(text, policy)
        self.policy_combo.setCurrentIndex(0)
        policy_hint = QLabel(
            "HA-04 快速探测间隔/超时；默认 5s / 2000ms。", self)
        policy_hint.setObjectName("hint")
        policy_row.addWidget(self.policy_label)
        policy_row.addWidget(self.policy_combo)
        policy_row.addWidget(policy_hint)
        policy_row.addStretch(1)
        layout.addLayout(policy_row)

        self.consent_hint_label = QLabel("", self)
        self.consent_hint_label.setObjectName("consentHint")
        self.consent_hint_label.setWordWrap(True)
        layout.addWidget(self.consent_hint_label)

        self.consent_checkbox = QCheckBox(CONSENT_TEXT, self)
        self.consent_checkbox.setObjectName("consentCheckbox")
        self.consent_checkbox.setToolTip(CONSENT_TEXT)
        layout.addWidget(self.consent_checkbox)

        buttons = QHBoxLayout()
        self.generate_button = QPushButton("生成", self)
        self.cancel_button = QPushButton("取消", self)
        self.open_output_button = QPushButton("打开输出目录", self)
        self.retry_button = QPushButton("重试", self)
        self.delete_failed_button = QPushButton("删除失败运行目录", self)
        for button in (self.generate_button, self.cancel_button,
                       self.open_output_button, self.retry_button,
                       self.delete_failed_button):
            buttons.addWidget(button)
        buttons.addStretch(1)
        layout.addLayout(buttons)

        log_label = QLabel("进度", self)
        layout.addWidget(log_label)
        self.progress_log = QPlainTextEdit(self)
        self.progress_log.setObjectName("generationLog")
        self.progress_log.setReadOnly(True)
        self.progress_log.setMaximumBlockCount(300)
        self.progress_log.setFixedHeight(110)
        layout.addWidget(self.progress_log)

        results_label = QLabel("生成结果", self)
        layout.addWidget(results_label)
        self.results_table = QTableWidget(0, len(RESULT_COLUMNS), self)
        self.results_table.setObjectName("generationResults")
        self.results_table.setHorizontalHeaderLabels(list(RESULT_COLUMNS))
        self.results_table.setEditTriggers(
            QAbstractItemView.EditTrigger.NoEditTriggers)
        self.results_table.setSelectionMode(
            QAbstractItemView.SelectionMode.NoSelection)
        self.results_table.verticalHeader().setVisible(False)
        header = self.results_table.horizontalHeader()
        header.setStretchLastSection(False)
        header.setSectionResizeMode(COL_CLIENT,
                                    QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(COL_FILE,
                                    QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(COL_SHA,
                                    QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(COL_FOLDER,
                                    QHeaderView.ResizeMode.ResizeToContents)
        layout.addWidget(self.results_table, 1)

        self.output_note = QLabel(NO_OUTPUT_TEXT, self)
        self.output_note.setObjectName("outputNote")
        self.output_note.setWordWrap(True)
        layout.addWidget(self.output_note)

        self.failure_label = QLabel("", self)
        self.failure_label.setObjectName("generationFailure")
        self.failure_label.setWordWrap(True)
        self.failure_label.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse)
        layout.addWidget(self.failure_label)

        self.generate_button.clicked.connect(self._on_generate_clicked)
        self.cancel_button.clicked.connect(self._on_cancel_clicked)
        self.open_output_button.clicked.connect(self._on_open_output_clicked)
        self.retry_button.clicked.connect(self._on_retry_clicked)
        self.delete_failed_button.clicked.connect(
            self._on_delete_failed_clicked)

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
        self.generate_button.setEnabled(True)
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
                "尚未读取客户端清单：请先在「客户端管理」点击「读取两端客户端」。")
            self.consent_hint_label.setText("")
            return
        if not selected:
            self.selection_label.setText(
                "尚未选择客户端：请在「客户端管理」勾选可生成的客户端并设置分组。")
            self.consent_hint_label.setText("")
            return
        mapping = "、".join("%s → %s" % (item.name, item.group)
                           for item in selected)
        self.selection_label.setText(
            "已选 %d 个客户端：%s" % (len(selected), mapping))
        if self._clients_panel.requires_generation_consent(selected):
            self.consent_hint_label.setText(
                "所选客户端在至少一端缺少最新导出：生成前必须勾选下方同意。")
        else:
            self.consent_hint_label.setText(
                "所选客户端导出均为最新：本次无需勾选同意，不会运行 miaomiao 菜单。")

    # --------------------------------------------------------------- request ---
    def _collect_request(
        self,
    ) -> tuple[list[SelectedClient], ProbePolicy, bool, Mapping[str, str]]:
        if self._clients_panel.preview_result is None:
            raise HaUiError(errors.E_CONFIG, detail="preview",
                            message="请先读取两端客户端清单")
        selected = self._clients_panel.selected_clients()
        if not selected:
            raise HaUiError(
                errors.E_USAGE, detail="clients",
                message="请先在「客户端管理」勾选至少一个可生成的客户端")
        allow_cli = self.consent_checkbox.isChecked()
        if (self._clients_panel.requires_generation_consent(selected)
                and not allow_cli):
            raise HaUiError(
                errors.E_USAGE, detail="cli-consent",
                message="所选客户端在至少一端缺少最新导出，"
                        "请先勾选同意运行 miaomiao CLI 菜单")
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
        # A retry is a brand-new attempt: _start_generation creates a new run id.
        self._on_generate_clicked()

    def _report_validation_error(self, error: HaUiError) -> None:
        self.failure_label.setText(error.safe_text)
        self._append_line("未开始：%s" % error.safe_text)
        self._notifier.show_error(error)

    # -------------------------------------------------------------- generate ---
    def _start_generation(self, selected: list[SelectedClient],
                          policy: ProbePolicy, allow_cli: bool,
                          passwords: Mapping[str, str]) -> None:
        run_id = self._service.new_run_id()
        self._busy = True
        self._cancel_event = threading.Event()
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
        self.failure_label.setText("")
        if files:
            self.output_note.setText(
                "上次成功输出：%d 个文件（运行 %s）。" % (len(files), run_id))
            self._append_line("生成完成：%d 个文件。" % len(files))
        else:
            self._append_line("生成完成：没有返回交付文件。")

    def _apply_failure(self, error: HaUiError, run_id: str) -> None:
        # Previous successful output (table + note) is deliberately kept.
        self._append_line("失败：%s" % error.safe_text)
        self.failure_label.setText(error.safe_text)
        self._notifier.show_error(error)
        if run_id is not None:
            self._failed_run_id = run_id

    def _populate_results(self, files: list[DeliveredFile]) -> None:
        self.results_table.setRowCount(0)
        for entry in files:
            row = self.results_table.rowCount()
            self.results_table.insertRow(row)
            self.results_table.setItem(row, COL_CLIENT,
                                       QTableWidgetItem(entry.client))
            self.results_table.setItem(row, COL_FILE,
                                       QTableWidgetItem(entry.filename))
            sha_item = QTableWidgetItem(entry.sha256)
            sha_item.setFont(self._sha_font)
            self.results_table.setItem(row, COL_SHA, sha_item)
            button = QPushButton("打开目录", self.results_table)
            folder = str(Path(entry.path).parent)
            button.clicked.connect(
                lambda _checked=False, target=folder: self._open_folder(target))
            self.results_table.setCellWidget(row, COL_FOLDER, button)
            self.results_table.setRowHeight(row, 26)
        self.results_table.resizeColumnsToContents()
        self.results_table.horizontalHeader().setSectionResizeMode(
            COL_SHA, QHeaderView.ResizeMode.Stretch)

    # ---------------------------------------------------------------- cancel ---
    def _on_cancel_clicked(self) -> None:
        event = self._cancel_event
        if event is None or not self._busy:
            # Surface the fixed cancellation code even when nothing is running.
            error = HaUiError(errors.E_CANCELLED)
            self.failure_label.setText(error.safe_text)
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
    def _append_stage_label(self, token: str) -> None:
        # Only fixed labels are rendered; an unknown future token is generic.
        self._append_line(format_stage(token))

    def _append_line(self, text: str) -> None:
        self.progress_log.appendPlainText(text)
