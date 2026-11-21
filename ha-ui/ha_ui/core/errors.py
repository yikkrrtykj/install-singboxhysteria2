"""Fixed, non-secret error taxonomy for the local HA-UI app.

Rules that every caller must keep:

* an :class:`HaUiError` carries a *fixed* code and a *safe* message; it must
  never carry a password, credential, rendered YAML or remote path that could
  embed them;
* ``detail`` is for small structured context (a role name, a stage, an error
  code returned by an existing tool). It is rendered into the UI and the local
  run log, so it must stay non-secret by construction;
* unexpected exceptions are converted at the UI/worker boundary into
  ``E_INTERNAL`` and the original exception text is NOT shown (it could include
  a path or a credential-bearing command line).
"""

from __future__ import annotations

from typing import Final

# --- configuration / local storage -------------------------------------------
E_USAGE: Final = "E_USAGE"
E_CONFIG: Final = "E_CONFIG"
E_CONFIG_SCHEMA: Final = "E_CONFIG_SCHEMA"
E_STORE_IO: Final = "E_STORE_IO"
E_ACL: Final = "E_ACL"
E_PATH: Final = "E_PATH"
E_OUTPUT_EXISTS: Final = "E_OUTPUT_EXISTS"
E_CANCELLED: Final = "E_CANCELLED"

# --- Windows Credential Manager ----------------------------------------------
E_CREDENTIAL_MISSING: Final = "E_CREDENTIAL_MISSING"
E_CREDENTIAL_STORE: Final = "E_CREDENTIAL_STORE"
E_CREDENTIAL_UNAVAILABLE: Final = "E_CREDENTIAL_UNAVAILABLE"

# --- SSH transport ------------------------------------------------------------
E_HOSTKEY_MISSING: Final = "E_HOSTKEY_MISSING"
E_HOSTKEY_MISMATCH: Final = "E_HOSTKEY_MISMATCH"
E_HOSTKEY_FORMAT: Final = "E_HOSTKEY_FORMAT"
E_SSH_CONNECT: Final = "E_SSH_CONNECT"
E_SSH_AUTH: Final = "E_SSH_AUTH"
E_SSH_TIMEOUT: Final = "E_SSH_TIMEOUT"
E_SSH_PROTOCOL: Final = "E_SSH_PROTOCOL"
E_SSH_CLOSED: Final = "E_SSH_CLOSED"

# --- remote read-only operations ---------------------------------------------
E_REMOTE_PREFLIGHT: Final = "E_REMOTE_PREFLIGHT"
E_REMOTE_NOT_ROOT: Final = "E_REMOTE_NOT_ROOT"
E_REMOTE_PLATFORM: Final = "E_REMOTE_PLATFORM"
E_REMOTE_COMMAND: Final = "E_REMOTE_COMMAND"
E_REMOTE_MENU: Final = "E_REMOTE_MENU"
E_REMOTE_LIST: Final = "E_REMOTE_LIST"
E_REMOTE_EXPORT: Final = "E_REMOTE_EXPORT"
E_REMOTE_FILE: Final = "E_REMOTE_FILE"
E_REMOTE_HASH: Final = "E_REMOTE_HASH"
E_REMOTE_PIN: Final = "E_REMOTE_PIN"

# --- local HA chain -----------------------------------------------------------
E_TOOL_MISSING: Final = "E_TOOL_MISSING"
E_TOOL_FAILED: Final = "E_TOOL_FAILED"
E_CHAIN_STAGE: Final = "E_CHAIN_STAGE"
E_CHAIN_CHECK: Final = "E_CHAIN_CHECK"
E_PIN_FORMAT: Final = "E_PIN_FORMAT"
E_PIN_EXPIRED: Final = "E_PIN_EXPIRED"
E_PIN_REUSED: Final = "E_PIN_REUSED"
E_CLIENT_MISSING: Final = "E_CLIENT_MISSING"
E_CLIENT_INCOMPLETE: Final = "E_CLIENT_INCOMPLETE"
E_CREDENTIAL_REUSE: Final = "E_CREDENTIAL_REUSE"
E_FRIENDLY_EXPORT: Final = "E_FRIENDLY_EXPORT"

# --- fallback ----------------------------------------------------------------
E_INTERNAL: Final = "E_INTERNAL"

_RETRIABLE: Final = frozenset({
    E_SSH_CONNECT,
    E_SSH_TIMEOUT,
    E_SSH_PROTOCOL,
    E_REMOTE_COMMAND,
    E_REMOTE_MENU,
    E_REMOTE_FILE,
    E_REMOTE_HASH,
    E_STORE_IO,
})

# Safe, fixed user-facing text. Keep them short; the UI may append a safe
# ``detail`` token but never raw exception text.
_MESSAGES = {
    E_USAGE: "参数无效",
    E_CONFIG: "本地配置无效",
    E_CONFIG_SCHEMA: "本地配置结构不受支持（可能被手工改坏）",
    E_STORE_IO: "本地文件读写失败",
    E_ACL: "本地私有目录权限校验失败，已停止",
    E_PATH: "路径不安全，已停止",
    E_OUTPUT_EXISTS: "目标文件已存在，拒绝覆盖",
    E_CANCELLED: "操作已取消",
    E_CREDENTIAL_MISSING: "未找到该服务器的已保存 SSH 密码",
    E_CREDENTIAL_STORE: "Windows 凭据管理器操作失败，不能声称密码已保存",
    E_CREDENTIAL_UNAVAILABLE: "Windows 凭据管理器不可用；可选择不保存密码",
    E_HOSTKEY_MISSING: "尚未确认该服务器的 SSH 主机指纹",
    E_HOSTKEY_MISMATCH: "SSH 主机指纹与已确认值不一致，已拒绝连接",
    E_HOSTKEY_FORMAT: "主机指纹格式无效",
    E_SSH_CONNECT: "SSH 连接失败（网络不可达、端口错误或被拒绝）",
    E_SSH_AUTH: "SSH 认证失败（用户名或密码错误）",
    E_SSH_TIMEOUT: "SSH 操作超时",
    E_SSH_PROTOCOL: "SSH 协议错误或输出异常",
    E_SSH_CLOSED: "SSH 会话已关闭",
    E_REMOTE_PREFLIGHT: "服务器前置检查未通过",
    E_REMOTE_NOT_ROOT: "MVP 需要 root SSH；当前用户不是 root",
    E_REMOTE_PLATFORM: "服务器不是受支持的 Linux/systemd 环境",
    E_REMOTE_COMMAND: "远端只读命令失败",
    E_REMOTE_MENU: "现有 miaomiao 客户端菜单执行失败或输出无法识别",
    E_REMOTE_LIST: "无法读取服务器客户端列表",
    E_REMOTE_EXPORT: "无法生成或读取规范导出",
    E_REMOTE_FILE: "远端导出文件校验失败",
    E_REMOTE_HASH: "远端导出文件与远端 SHA-256 不一致",
    E_REMOTE_PIN: "无法读取 HY2 证书 PIN/有效期",
    E_TOOL_MISSING: "缺少本地 HA 工具文件（安装不完整）",
    E_TOOL_FAILED: "本地 HA 工具执行失败",
    E_CHAIN_STAGE: "HA 生成链某个阶段失败",
    E_CHAIN_CHECK: "HA 生成链某个 --check 未通过",
    E_PIN_FORMAT: "HY2 证书 PIN 格式无效",
    E_PIN_EXPIRED: "HY2 证书有效期不足或已过期",
    E_PIN_REUSED: "A/B 两端 HY2 证书 PIN 重复，角色独立性不成立",
    E_CLIENT_MISSING: "客户端在某一端不存在",
    E_CLIENT_INCOMPLETE: "客户端 Reality/HY2 协议不完整",
    E_CREDENTIAL_REUSE: "A/B 两端使用了相同凭据，已停止",
    E_FRIENDLY_EXPORT: "A-first/B-first 交付文件发布失败",
    E_INTERNAL: "内部错误（已隐藏细节）",
}


class HaUiError(Exception):
    """A safe, typed application error. See the module docstring."""

    def __init__(self, code: str, detail: str | None = None,
                 message: str | None = None) -> None:
        self.code = code if code in _MESSAGES else E_INTERNAL
        self.message = message or _MESSAGES[self.code]
        self.detail = detail
        super().__init__(self.safe_text)

    @property
    def retriable(self) -> bool:
        return self.code in _RETRIABLE

    @property
    def safe_text(self) -> str:
        if self.detail:
            return "%s: %s (%s)" % (self.code, self.message, self.detail)
        return "%s: %s" % (self.code, self.message)

    def __str__(self) -> str:
        return self.safe_text

    def __repr__(self) -> str:
        return "HaUiError(%r, detail=%r)" % (self.code, self.detail)


def wrap_unexpected(exc: BaseException) -> HaUiError:
    """Collapse an unexpected exception to a fixed, detail-free error."""
    del exc  # never stringify: message/args may embed paths or secrets
    return HaUiError(E_INTERNAL)


def require(condition: bool, code: str, detail: str | None = None) -> None:
    if not condition:
        raise HaUiError(code, detail=detail)
