"""Modal dialogs for the local HA-UI app.

The host-key dialog is the one place where the fingerprint is rendered. It is
not logged, and the OK button stays disabled until the operator explicitly
confirms they compared it against a trusted source (the cloud console or the
server itself). A changed fingerprint gets an extra warning before this dialog.
"""

from __future__ import annotations

import re

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QLabel,
    QLineEdit,
    QVBoxLayout,
)

from ..core.models import HostKeyInfo

CLIENT_NAME_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._-]{0,31}\Z")
RESERVED_CLIENT_NAME = "legacy"


class HostKeyDialog(QDialog):
    """Show algorithm + ``SHA256:`` fingerprint; require explicit confirmation."""

    def __init__(self, info: HostKeyInfo,
                 replace_existing: bool = False,
                 parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("确认服务器主机指纹")
        self.setModal(True)
        self._info = info

        layout = QVBoxLayout(self)
        intro = QLabel(
            "连接前必须人工核对服务器主机指纹。请通过云控制台或其他可信渠道"
            "比对下面的值；确认后才会保存，之后指纹不一致的连接会被拒绝。")
        intro.setWordWrap(True)
        layout.addWidget(intro)

        if replace_existing:
            warning = QLabel(
                "⚠ 本次探测到的指纹与已保存的指纹不同。只有在你确认服务器"
                "确实更换了主机密钥时才替换；否则请取消并排查。")
            warning.setObjectName("hostKeyWarning")
            warning.setWordWrap(True)
            layout.addWidget(warning)

        form = QFormLayout()
        self.algorithm_label = QLabel(info.algorithm)
        self.algorithm_label.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse)
        self.fingerprint_label = QLabel(info.fingerprint)
        self.fingerprint_label.setObjectName("fingerprintValue")
        self.fingerprint_label.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse)
        font = self.fingerprint_label.font()
        font.setFamily("Consolas")
        self.fingerprint_label.setFont(font)
        form.addRow("算法", self.algorithm_label)
        form.addRow("SHA256 指纹", self.fingerprint_label)
        layout.addLayout(form)

        self.verify_checkbox = QCheckBox("我已核对")
        self.verify_checkbox.setObjectName("hostKeyVerified")
        layout.addWidget(self.verify_checkbox)

        self.buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok
            | QDialogButtonBox.StandardButton.Cancel,
            parent=self)
        self.ok_button = self.buttons.button(QDialogButtonBox.StandardButton.Ok)
        self.ok_button.setText("确认并保存")
        self.ok_button.setEnabled(False)
        self.buttons.button(QDialogButtonBox.StandardButton.Cancel).setText("取消")
        self.verify_checkbox.toggled.connect(self.ok_button.setEnabled)
        self.buttons.accepted.connect(self.accept)
        self.buttons.rejected.connect(self.reject)
        layout.addWidget(self.buttons)

    @property
    def verified(self) -> bool:
        """True only when the operator ticked the explicit confirmation box."""
        return self.verify_checkbox.isChecked()

    @property
    def info(self) -> HostKeyInfo:
        return self._info


class ClientCreateDialog(QDialog):
    """Name + explicit write confirmation for a dual-VPS client creation.

    The dialog only validates shape and consent; it never contacts a VPS. The
    remote preflight and duplicate checks happen in the worker after this dialog
    is accepted, so the dialog must not promise that the name is unused.
    """

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("新建客户端")
        self.setModal(True)
        self.setMinimumWidth(520)

        layout = QVBoxLayout(self)
        intro = QLabel(
            "将在 A、B 两台 VPS 上创建同一个逻辑客户端。两端各自生成独立的 "
            "Reality UUID 和 HY2 密码，不会在服务器之间同步凭据。")
        intro.setWordWrap(True)
        layout.addWidget(intro)

        form = QFormLayout()
        self.name_edit = QLineEdit(self)
        self.name_edit.setObjectName("newClientName")
        self.name_edit.setMaxLength(32)
        self.name_edit.setPlaceholderText("例如 event-vmix01")
        form.addRow("客户端名称", self.name_edit)
        self.target_label = QLabel("A + B 两端（同名）", self)
        form.addRow("创建目标", self.target_label)
        layout.addLayout(form)

        self.error_label = QLabel("", self)
        self.error_label.setObjectName("validationError")
        self.error_label.setWordWrap(True)
        layout.addWidget(self.error_label)

        warning = QLabel(
            "此操作会修改两台 VPS 的 sing-box 客户端配置，并可能执行 reload，"
            "当前连接可能短暂受影响。若名称已在一端存在，操作会停止；"
            "软件不会覆盖已有凭据，也不会自动删除已创建的一端。")
        warning.setObjectName("createWarning")
        warning.setWordWrap(True)
        layout.addWidget(warning)

        self.confirm_checkbox = QCheckBox(
            "我已了解并确认修改两台 VPS 的客户端配置", self)
        self.confirm_checkbox.setObjectName("createConfirm")
        layout.addWidget(self.confirm_checkbox)

        self.buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok
            | QDialogButtonBox.StandardButton.Cancel,
            parent=self)
        self.ok_button = self.buttons.button(QDialogButtonBox.StandardButton.Ok)
        self.ok_button.setText("创建")
        self.ok_button.setObjectName("primaryButton")
        self.ok_button.setEnabled(False)
        self.buttons.button(QDialogButtonBox.StandardButton.Cancel).setText("取消")
        self.buttons.accepted.connect(self.accept)
        self.buttons.rejected.connect(self.reject)
        layout.addWidget(self.buttons)

        self.name_edit.textChanged.connect(self._validate)
        self.confirm_checkbox.toggled.connect(self._validate)
        self._validate()
        self.name_edit.setFocus()

    @property
    def client_name(self) -> str:
        return self.name_edit.text().strip()

    def _validate(self) -> None:
        name = self.client_name
        problem = ""
        if name:
            if not CLIENT_NAME_RE.fullmatch(name):
                problem = (
                    "名称需以字母或数字开头，只允许字母、数字、点、下划线和横线，"
                    "长度 1–32。")
            elif name.casefold() == RESERVED_CLIENT_NAME.casefold():
                problem = "legacy 是保留名称，不能新建。"
        self.error_label.setText(problem)
        self.ok_button.setEnabled(
            bool(name) and not problem and self.confirm_checkbox.isChecked())
