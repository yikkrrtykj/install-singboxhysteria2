# Integration Round 2 — Final Report

## Integration Round 2

- **base**: `f948dc8eacfd894593e87b47bee45dfc99883519`（frozen Round 1.1 head，PRECHECK 精确匹配，工作区干净）
- **legacy commits integrated**（按序 cherry-pick，仅此二提交）:
  - `e3713f2366f66b92fb5b5098d4f490d05b9c2646` — security: serialize legacy sing-box config mutations
  - `a52ab8837909f6947db0c19472f4908efbf4f1c0` — fix(security): make legacy dual-file rollback atomic
- **new head**: `3ee9a162a3fb53d9fddc95cb6eba95b3bcc5702e`

## Diff

- **conflicts**: 无（两次 cherry-pick 均干净合入）
- **changed files**:
  - 来自 cherry-pick：`install.sh`、`tests/test-legacy-config-transactions.sh`（新增）、`docs/legacy-config-transaction-hardening.md`（新增）、`.github/workflows/tests.yml`（新增 legacy 套件步骤）
  - 来自 Round 2 文档/清理提交：`docs/monitor-v2-integration.md`、`docs/legacy-config-transaction-hardening.md`、`monitor-v2/deploy/lib/monitor-deploy-lib.sh`、`monitor-v2/deploy/app-bin/monitor-service`
- **new commits**:
  - `af1f5e26fafee92178420911b4c4dfa3b1348d20`（← e3713f2）
  - `94c0eb063a326d85e0d634fb6bf98afd243adb07`（← a52ab88）
  - `3ee9a162a3fb53d9fddc95cb6eba95b3bcc5702e`（docs + 非阻塞清理）

## Contract review

- **Round 1.1 preservation**: `git diff f948dc8..HEAD` 仅触及 legacy 块、legacy 套件、docs 与 workflow 的 legacy 步骤；Packaging/Web 代码字节/语义零改动。本地基线对比（shellcheck HEAD vs f948dc8）问题集完全一致。
- **Legacy preservation**: 全局锁仍为 `/root/sbox/config.lock`；Phase C、Phase D、`modify_singbox`、`process_doko`、`process_dokoko`、`process_ssko`、HY2 hopping 状态写入器全部使用同一把锁（fail-closed flock、不嵌套、锁内不等待交互输入）。
- 临时文件：全部为 `mktemp …XXXXXX` 唯一临时文件，无固定 legacy 临时文件回归（套件 T8 断言通过）。
- L3 `restore_file_atomically` 完整保留（唯一临时文件 + 原子重命名 + 逐字节校验，全程 fail-closed）。
- Monitor Packaging 代码零引用 `sbconfig_server.json`（S0 秘钥锚点除外，静态隔离断言绿）。
- E2 保持只读；E4 保持未在服务端暂存。
- One Collector / one SnapshotBroker / one service.api consumer 成立。
- service.api 身份语义不变：Device = `Connection.user`，Protocol = inbound tag，lifecycle = `Connection.id`。

- **I0-7**: **CLOSED**（Round 2，方案 A）— 所有 legacy 运行时写入器已纳入同一把锁，旧的 lost-update 阻塞不再存在。
- **L5 status**: L5 标记**仅是临时性的 E3 激活接口**（provisional activation interface）；它本身不使 E3 安全，且今日无任何生产代码创建该标记。**并发 E3 启用仍被阻塞**，等待 E3 rev5 activation / privileged-helper 设计定案（E3 如何在同一把锁下以特权 helper 执行变更、以及标记的发布与批准机制）。

## Full combined Linux CI（GitHub Actions Ubuntu，head `3ee9a16`，权威门禁）

| Gate | 结果 | 达标线 |
|---|---|---|
| Phase C | **121/121 PASS** | 121/121 ✅ |
| Phase D | **105/105 PASS** | 105/105 ✅ |
| S0 | **133/133 PASS** | 133/133 ✅ |
| Legacy | **161/161 PASS** | 161/161 ✅ |
| E1 | **188/188 PASS** | 188/188 ✅ |
| E2 | **272/272 PASS** | 272/272 ✅ |
| E4 | **161/161 PASS** | 161/161 ✅ |
| Packaging fixture | **473/473 PASS** | ≥ 473 ✅ |
| Packaging root metadata | **488/488 PASS** | ≥ 488 ✅ |
| `bash -n` | PASS（workflow 步骤，全部 shell 源） | ✅ |
| `shellcheck -S warning` | PASS（套件内断言；本地 HEAD 与 f948dc8 问题集一致，未引入新问题） | ✅ |

无任何既有断言被删除或削弱；Round 2 未改动任何断言。

补充说明（非权威）：本地 Windows 开发基线 — Phase C 119/0、Phase D 105/0、S0 117/0、Legacy 157/0（4 条 Linux-only 断言在 Windows 跳过）、E1 188/0、E2 272/0（首跑 1 条计时假象，重跑 3 次全绿，代码与 f948dc8 零差异）、E4 161/0、Packaging fixture 模式 256/0（Windows 精简模式，root 模式需 Linux 真实元数据）。

## 非阻塞清理（仅这两项，未扩大范围）

1. 移除零调用者的死代码 `sbmon_chown()`（全仓库唯一出现处即定义本身）。
2. 修正 `monitor-service` 注释：unit 实际**未**配置 stdout 重定向；collector-loop 模式下由 shim 自行将 collector stdout 重定向到状态目录。未新增任何日志子系统。

## PR 状态

- **PR #16**: **DRAFT / OPEN / NOT MERGED** — body 已更新（Round 1.1 frozen head、Legacy frozen head、Round 2 integrated head、权威 Linux CI 计数、I0-7 CLOSED、L5/E3 激活仍待 E3 rev5、VPS NOT RUN、production UNCHANGED）。未标记 Ready。
- **PR #17**: **UNCHANGED / DRAFT / DO NOT MERGE**（未合并、未触碰）。

## Final status

- **VPS**: NOT RUN
- **production**: UNCHANGED
- **E3**: NOT STARTED
