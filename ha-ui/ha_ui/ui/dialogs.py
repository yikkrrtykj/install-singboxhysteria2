"""Modal dialogs for the local HA-UI app.

The host-key dialog is the one place where the fingerprint is rendered. It is
not logged, and the OK button stays disabled until the operator explicitly
confirms they compared it against a trusted source (the cloud console or the
server itself). A changed fingerprint gets an extra warning before this dialog.
"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QLabel,
    QVBoxLayout,
)

from ..core.models import HostKeyInfo


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
