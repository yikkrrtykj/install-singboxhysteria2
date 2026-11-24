# Windows HA-UI 0.2.0 — 安全模型与验收边界

本文件描述 Windows 双 VPS 工具（0.2.0）的安全模型。数据获取/写入路径的选择与证据见
`docs/windows-ha-ui-data-path.md`；操作步骤见 `docs/windows-ha-ui-operator.md`。

## 1. 资产与信任边界

| 资产 | 位置 | 保护 |
| --- | --- | --- |
| SSH 登录密码 | Windows 凭据管理器（`ha-ui-ssh`） | 仅勾选“记住密码”时保存；保存后读回校验；失败不降级为明文 |
| SSH 主机指纹 | `%LOCALAPPDATA%\HASingbox\servers.json`（非机密） | 用户显式核对 SHA-256 后保存；连接前强制比对 |
| 规范导出/HA 交付/YAML | 私有工作区 `%LOCALAPPDATA%\HASingbox\runs\<run-id>\` | NTFS ACL：当前用户 + SYSTEM + Administrators；文件 0600；由既有 ACL gate 复验 |
| 运行回执 | 同 run 目录 `run.json` | 只含文件名/SHA-256/阶段/tool 哈希，不含凭据 |
| 服务器 `sbconfig_server.json` | VPS root | **生成链只读**；0.2.0 创建仅通过既有 canonical add 事务写入 |
| 新建客户端的 UUID/HY2 密码 | VPS root 配置 | 只在服务器端生成并写入；不进入 UI、日志、argv、环境变量、本地临时文件 |
| Monitor/E3 管理面 | VPS sboxweb/sbox-cm | **不使用、不激活、不绕过**；`management.active` 存在时拒绝创建/生成 |

## 2. 本地文件与 ACL

- 工作区根目录 `%LOCALAPPDATA%\HASingbox`；创建时用 `icacls` 移除继承并只授予当前
  用户/SYSTEM/Builtin Administrators，并移除 OWNER RIGHTS 伪 ACE；
- 每个新建目录/文件立即应用 ACL，任何一步失败即停止（fail-closed）；
- 随后调用 `tools/mihomo-competition-ha-batch.py` 的
  `check_private_path`/`check_local_boundary`/`check_directory` 复验；
- 拒绝 UNC、非固定盘、路径逃逸、symlink/junction 等 reparse point；
- 写入使用同目录私有临时文件 + fsync + hard-link（no-clobber）或原子 replace；
- 失败运行目录自动清理；历史成功目录永不覆盖。

## 3. 凭据处理

- SSH 密码只进入：密码输入框 → 凭据管理器（若保存）→ Paramiko `connect(password=...)`。
  不写日志、不写 `servers.json`、不进命令行、不进环境变量、不写临时文件；
- `servers.json` 解析时拒绝任何 password/secret/token/uuid 等键；
- 完整 YAML/导出字节仅在私有工作区与内存中存在；UI 只显示文件名与 SHA-256 摘要，
  不显示 YAML、UUID、HY2 密码或分享链接；
- 菜单驱动的远端生成在服务器侧把 `Reality/HY2 链接:` 行替换为 `[redacted-link]`
  再回传；
- 创建客户端的凭据由服务端 `cm_plan_client_credential` 在 shell 内存中生成，经匿名
  管道进入 jq；不进入 argv、环境变量、stdout/stderr 或临时文件。GUI 只读取创建后的
  布尔完整性，不读取凭据值；
- 错误只显示固定 `E_...` 码 + 安全消息；未预期异常统一折叠为 `E_INTERNAL`。

## 4. SSH 与服务器边界

- 仅密码认证（`look_for_keys=False, allow_agent=False`）；
- 主机指纹未知/变化在**认证前**拒绝；连接后再核对一次协商密钥；
- 命令由固定模板构造，客户端名先经 `^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$` 校验，且
  `legacy` 保留名在本地与服务端都被拒绝；
- 远端输出有大小上限；导出下载前/打开后/读完后校验 root 属主、0600、普通文件、
  大小、lstat/fstat 一致性，并与远端 `sha256sum` 对比；
- 检测到 E3 管理面激活标记或 service.api secret 缺失时直接拒绝；
- 不打开任何公网/本地监听端口，不建立反向隧道，不下载/执行第三方二进制。

## 5. 创建客户端的信任链（0.2.0 新增）

创建不是“本地生成 YAML”，而是真实的远程写操作。实现只允许以下路径：

```text
GUI 明确确认
  -> pinned install.sh + pinned lib/client-management.sh（固定 reviewed commit，
     独立 SHA-256 + installer 内嵌 lib pin）
  -> 菜单 10 -> 2 -> add_client
  -> with_client_lock（flock，fail-closed）
  -> cm_add_client_candidate_planned（独立 CSPRNG 凭据）
  -> commit_server_config（sing-box check、备份、原子替换、reload/health、失败回滚）
  -> 重新读取两端 live 清单（名称 + Reality/HY2 布尔完整性）
```

安全性质：

- 不直接编辑 `sbconfig_server.json`，不调用 `sbox-cm` worker 绕过 Session/step-up/激活门禁；
- 不把 GitHub `main` 的可变脚本作为执行目标；host 依赖缺失时 preflight 直接拒绝，
  不会触发 apt/yum；
- 菜单退出码 0 不等于创建成功：必须同时看到 canonical add 成功行与提交行
  （`配置已提交`），并在创建后完成 live 复核且该记录 `exportable`（双协议 + 无结构异常）；
- **回滚分类必须精确**：`lib/client-management.sh` 有三种回滚结局都含“回滚”字样，只有
  `已回滚并重新加载上一份配置` 能证明写入已撤销，且还要通过只读核对（config SHA-256
  回到写入前、名称不存在）；`回滚恢复失败` / `服务未能确认恢复` 一律 `uncertain`；
- **A/B 不是分布式事务**：先 A 后 B，每端独立回执。A 成功、B 失败时保留 A，不自动
  删除（删除可能触发凭据吊销），不把部分成功显示为完成；
- 一端已存在时默认 STOP；只有 UI 第二次明确确认“仅补齐缺失端”才允许创建缺失端，
  绝不覆盖已有凭据；
- 任一端创建结果不确定（超时/断连/无法复核）时，状态为“待确认”；操作员必须先刷新
  实际状态，不能盲目重发。刷新失败显示 `STALE / UNKNOWN`，绝不推断服务器未被修改；
- 后台 worker 不读取任何 QWidget：密码在 GUI 线程快照后以不可变 dict 传入，
  `MainWindow.password_overrides()` 对非 GUI 线程调用直接失败（fail-closed）。

## 6. HA 链复用

- 不重新实现 HA 算法、manifest、渲染器、ACL 或 no-clobber 写入：全部通过
  `ha_tools` 加载既有 `tools/mihomo-competition-ha-*.py` 并调用其 `main(argv)`；
- 每个阶段使用工具自身退出码与错误码；GUI 额外执行 HA-03/04 `--check`；
- friendly-export 只在全部检查通过后发布 `<client>-A-first.yaml` / `-B-first.yaml`，
  并复验 manifest 的 group/physical role、文件 SHA-256、no-clobber。

## 7. 已知残余风险（0.2.0 边界）

1. **root SSH 即信任锚**：root 失陷时任何本地保护都无意义。建议专用强密码、限制来源 IP。
2. **两端创建不是原子事务**：不存在跨 VPS 的分布式事务/补偿删除。部分成功必须由
   操作员根据实际状态处理；本版本故意不自动删除已成功的一端。
3. **服务端 reload 影响**：canonical add 会 reload/health；虽然失败会回滚，但 reload
   本身可能短暂影响现有连接。确认弹窗已明确告知，不能在未授权窗口执行。
4. **菜单版本漂移**：结构标记校验拒绝重编号/改名/成功文案变化；不匹配即 fail-closed，
   升级需发新版本并重新审查信任锚。
5. **Windows 同用户威胁**：ACL 允许当前用户与管理员读取，无法防御同账户恶意软件或
   已提权攻击者。
6. **Manifest/交付文件非签名**：哈希与 manifest 提供完整性/角色绑定，不提供发布者
   身份签名；EXE 未代码签名，下载后请核对 receipt/SHA-256。
7. **真实 VPS 验收未执行**：仓库内验证为合成凭据 + 本机 Windows 环境；接入真实 A/B
   前须按 `docs/windows-ha-ui-acceptance.md` 执行，尤其创建/补齐/部分成功路径必须在
   隔离测试 VPS 验证。CI/本机测试不能替代真实环境验收。
8. **单端写入已被受管事务隔离（P0 实现完成，待独立复审）**：创建通过 detached
   worker 执行，stdin/stdout 为文件，GUI 超时/SSH 断开不再直接终止 `replace` 后的
   reload/health/rollback；每个阶段经 `CM_TX_JOURNAL_HOOK`（函数名合同，由 BASH_ENV
   在事务 shell 内定义）fsync 到 root-only journal，终局以原子 `result` 发布。
   **不覆盖**机器断电/内核崩溃/人工 kill -9 整个进程组；这些只能被检出为
   `UNCERTAIN` 并阻断重试。细节见 `docs/windows-ha-ui-data-path.md` §7–§8。

## 8. 非目标

- 不新增公网 Web 服务/管理端口；不实现 Monitor 登录、不激活 E3 管理面；
- 不实现客户端删除/轮换/批量迁移（创建与补齐仅限本版本明确路径）；
- 不做跨 VPS 补偿事务或自动删除；
- 不自动导入 Clash/Verge、不开关 TUN、不改系统代理、不自动测速或故障注入；
- 不自动轮换已泄露凭据（独立人工操作）。
