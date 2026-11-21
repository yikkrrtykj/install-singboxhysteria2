# Windows HA-UI — 安全模型与验收边界

本文件描述 Windows 本地双 VPS 配置生成器（Issue #110 MVP）的安全模型。数据获取路径
的选择与证据见 `docs/windows-ha-ui-data-path.md`；操作步骤见
`docs/windows-ha-ui-operator.md`。

## 1. 资产与信任边界

| 资产 | 位置 | 保护 |
| --- | --- | --- |
| SSH 登录密码 | Windows 凭据管理器（`ha-ui-ssh` 服务命名空间） | 仅用户勾选“记住密码”时保存；保存后读回校验；失败不降级为明文 |
| SSH 主机指纹 | `%LOCALAPPDATA%\HASingbox\servers.json`（非机密） | 用户显式核对 SHA-256 后保存；连接前强制比对 |
| 规范导出/HA 交付/YAML | 私有工作区 `%LOCALAPPDATA%\HASingbox\runs\<run-id>\` | NTFS ACL：当前用户 + SYSTEM + Administrators；文件 0600；创建后由仓库既有 ACL gate 内核级复验 |
| 运行回执 | 同 run 目录 `run.json` | 只含文件名/SHA-256/阶段/tool 哈希，不含凭据 |
| 服务器 `sbconfig_server.json` | VPS root | **只读**；本工具不写、不改服务、不重启 |
| Monitor/E3 管理面 | VPS sboxweb/sbox-cm | **不使用、不激活、不绕过** |

## 2. 本地文件与 ACL

- 工作区根目录在 `%LOCALAPPDATA%\HASingbox`；创建时用 `icacls` 移除继承并只授予
  当前用户/SYSTEM/Builtin Administrators，并移除 OWNER RIGHTS 伪 ACE；
- 每个新建目录/文件立即应用 ACL，任何一步失败即停止（fail-closed）；
- 随后调用 `tools/mihomo-competition-ha-batch.py` 的
  `check_private_path`/`check_local_boundary`/`check_directory`（从内核读取 owner+DACL
  的保守 allowlist）复验；失败报 `E_ACL` 并停止；
- 拒绝 UNC、非固定盘、路径逃逸、symlink/junction 等 reparse point；
- 写入使用同目录私有临时文件 + fsync + hard-link（no-clobber）或原子 replace；
  发布后读回比对；失败即删除半成品；
- 失败运行目录自动清理，避免残留凭据副本；历史成功目录永不覆盖。

## 3. 凭据处理

- SSH 密码只进入：密码输入框（默认 `Password` echo mode）→ 凭据管理器（若保存）→
  Paramiko `connect(password=...)` 调用栈。不写日志、不写 `servers.json`、不进命令行、
  不进环境变量、不写临时文件；
- `servers.json` 解析时**拒绝**任何 password/secret/token/uuid 等键，防止旧版或手工
  文件把秘密当普通配置；
- 完整 YAML/导出字节仅在私有工作区与内存中存在；UI 只显示文件名与 SHA-256，不显示
  YAML、UUID、HY2 密码或分享链接；
- 菜单驱动的远端导出生成在服务器侧用 `sed` 先把 `Reality/HY2 链接:` 行替换为
  `[redacted-link]` 再回传，凭据链接不离开服务器；YAML 本身只经 SFTP 二进制下载；
- 错误只显示固定 `E_...` 码 + 安全消息；未预期异常统一折叠为 `E_INTERNAL`，不回显
  原始异常文本。

## 4. SSH 与服务器边界

- 仅密码认证（`look_for_keys=False, allow_agent=False`），避免本机其它密钥被隐式使用；
- 主机指纹未知/变化在**认证前**拒绝（Paramiko `MissingHostKeyPolicy`），连接后再核对
  一次协商密钥；
- 命令由固定模板构造，客户端名先经 `^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$` 校验，端口/
  用户名/主机只作为 Paramiko 参数，不进入 shell；
- 输出有大小上限；远端文件下载前/打开后/读完后各校验 root 属主、0600、普通文件、
  大小、lstat/fstat 一致性，并与远端 `sha256sum` 对比；
- 生成前若检测到 E3 管理面激活标记或 service.api secret 缺失，直接拒绝（不跨事务边界、
  不触发交互式迁移）；
- 不打开任何公网/本地监听端口，不建立反向隧道，不下载/执行第三方二进制。

## 5. HA 链复用

- 不重新实现 HA 算法、manifest、渲染器、ACL 或 no-clobber 写入：全部通过
  `ha_tools` 加载仓库既有 `tools/mihomo-competition-ha-batch.py` →
  `mihomo-competition-ha-profile.py` → `mihomo-competition-ha4-fastprobe.py` →
  `mihomo-competition-ha-friendly-export.py` 并调用其 `main(argv)`；ACL 校验直接复用
  batch 模块的内核级实现；
- 每个阶段使用工具自身的退出码与错误码；GUI 额外执行 HA-03 `--check`、HA-04 `--check`；
- friendly-export 只在全部检查通过后发布 `<client>-A-first.yaml`/`-B-first.yaml`，
  并复验 manifest 的 group/physical A/B role、文件 SHA-256、no-clobber。

## 6. 已知残余风险（MVP 边界）

1. **root SSH 即信任锚**：本工具需要 root 以运行既有管理 CLI；root 失陷时任何本地
   保护都无意义。建议专用强密码、限制来源 IP、按需关闭 root 密码登录。
2. **CLI 生成不是事务**：`generate_client_configuration` 读配置时未持有 `config.lock`
   （既有 CLI 行为）。MVP 通过“管理面未激活”前置条件 + 下载后 HA-02 的一致性/凭据
   独立性校验降低风险；仍存在与并发人工操作的 TOCTOU 窗口，故激活管理面时拒绝生成。
3. **自动菜单生成仍执行既有 `install.sh`（但已版本锚定）**：执行前从 reviewed commit
   （非 `main`）下载 installer 与 `lib/client-management.sh`，分别校验独立嵌入的
   SHA-256，并校验 installer 内嵌 lib pin；随后用清洗环境 + 已校验 lib 路径执行
   installer（`timeout` + `PIPESTATUS` + 逐客户端成功文本 + 前后 stat/SHA-256 变化，
   见 `docs/windows-ha-ui-data-path.md` §6）。前置检查要求 installer 的 host 依赖命令
   全部存在，因此不会触发 `apt/yum` 安装未锁定仓库代码；菜单 3 不修改
   `sbconfig_server.json`、不重启 sing-box。导出已新鲜时完全不执行脚本。更彻底的只读
   `--client-export` 模式与 Monitor `client.export` 路线仍需服务器端单独审批。
4. **版本/哈希不匹配的自动禁用**：installer 或 lib 哈希不匹配、内嵌 pin 漂移、菜单结构
   变化都 fail-closed；哈希类错误为不可重试的 `E_INSTALLER_UNTRUSTED`，UI 明确提示
   “自动菜单生成已禁用；已有规范导出仍可读取”。已有新鲜导出文件的读取模式不受影响。
5. **菜单版本漂移**：结构标记校验拒绝重编号/改名的菜单，避免管道输入落到错误操作；
   若 main 改变成功文案/菜单结构，工具 fail-closed 而不是猜测；升级需发新版本并重新
   审查 pin。
6. **Windows 同用户威胁**：ACL 允许当前用户与管理员读取，无法防御同账户恶意软件或
   已提权攻击者；请保持本机干净、开启磁盘加密、勿同步私有目录。
7. **Manifest/交付文件非签名**：哈希与 manifest 提供完整性与角色绑定，不提供发布者
   身份签名；EXE 未代码签名，下载后请核对 `receipt.json` 中的 EXE SHA-256 与 CI 产物。
8. **真实 VPS 验收未执行**：本仓库内验证为合成凭据 + 本机 Windows 环境；接入真实
   A/B 前须按 `docs/windows-ha-ui-acceptance.md` 的三层验收执行（含两台 VPS 只读层与
   隔离测试 VPS 生成层）；CI/本机测试不能替代该验收。

## 7. 非目标

- 不新增公网 Web 服务/管理端口；不实现 Monitor 登录、不激活 E3 管理面；
- 不创建/删除/轮换客户端，不做跨两端补偿事务；
- 不自动导入 Clash/Verge、不开关 TUN、不改系统代理、不自动测速或故障注入；
- 不自动轮换已泄露凭据（独立人工操作）。
