# UM-127 — 统一监控开发基线与 Go 迁移计划（Round 2 同步）

- 状态：**PROPOSED（规划文档，Draft PR）· 已按最终契约 rev-5 同步**。不构成实现、合并、部署或生产操作授权。
- 唯一跟踪 Issue：[#127 Unified Monitor｜统一监控与 Go 迁移](https://github.com/yikkrrtykj/install-singboxhysteria2/issues/127)
- 最终契约：[PR #126](https://github.com/yikkrrtykj/install-singboxhysteria2/pull/126)（UM-A revision 5，HEAD `048fc170`，tree `1b726de9…`）
- 设计基线与计划修订：[PR #128](https://github.com/yikkrrtykj/install-singboxhysteria2/pull/128)（本 PR，保留原 PR，不做 PR-A2）
- Go 开发分支：`codex/um-windows-foundation`（HEAD `24cfd2ff`，保留不动；仅在 Owner 授权的门禁后同步）

本目录是 UM-127 第二轮交付：**结束设计阶段的重复工作，把恢复语义、双平台契约、数值/存储规则和 Windows 遥测冻结进 #126 rev-5，并把 #128 的规划基线同步到该最终契约**。独立审查、Owner 合并授权与生产部署仍单独进行。

## 1. 本轮完成范围

| 内容 | 状态 |
| --- | --- |
| 在 #126 原分支纳入 rev-5 targeted amendment（不创建 PR-A2） | **完成**，见 #126 HEAD `048fc170` |
| A-1..A-5 恢复语义、bounded generation jump、首接触 `seq>1`、ACK `next_seq`、rotation 全量校验 | 已冻结进 `04` §5–§7/§13；`negative-vectors` 新增用例 |
| uint64 边界、ACK exhaustion、SQLite 存储语义 | 已冻结（`MAX_NUMERIC=2^63−2`，`MAX_BOOT_GAP=65535`，INTEGER + CHECK） |
| `node_class`（linux_vps/windows_terminal）、token scope 绑定事件与类别、平台隔离 | 已冻结进 enrollment/schema/`04` §4/§9.1 |
| Windows 六路径遥测（a_reality/a_hy2/b_reality/b_hy2/direct/unknown）、独立采样、UNKNOWN/UNAVAILABLE、版本化 A/B 映射、隐私负例、签名向量 | 已冻结进 `report-snapshot`/`report-events`/`enroll`/agent 规则与 `examples/` |
| 更新旧行为向量中与 rev-5 冲突的期望，保留历史追溯 | `superseded_rev4_expectations` + `historical_rev4_enroll_vector` |
| #128 保留 30 个 REC 用例、Owner 决策登记、UM-B1..UM-G 路线、Go 复用资产、迁移阶段/验收门禁 | **本 PR 同步**；移除独立 PR-A2 前置 |
| 独立审查 / Owner 合并授权 / 合并 #126 / 合并 #128 / 同步 Go 分支 / UM-B1 实现 / 部署 | **未做，等待授权** |

## 2. 基线与审查记录

| 对象 | 状态（2026-11-26 核对） |
| --- | --- |
| `main` | `885171c0`（PR #125 merge），CI 绿；无分支保护（流程风险） |
| PR #126 | OPEN + Draft；**rev-5 HEAD `048fc170`**，tree `1b726de9…`；相对 Round-1 新增 `docs(um): freeze rev-5 final contract`；独立 review 仍无 GitHub 记录；CI 以 PR 检查为准（含已知 Windows harness flake 的 recorded rerun） |
| PR #128 | OPEN + Draft；本 PR 保留，不做 PR-A2；本轮把规划基线同步到 rev-5；仍需独立 review 与 Owner merge 授权 |
| Go 分支 | `codex/um-windows-foundation` @ `24cfd2ff`；3 个开发提交（`17b2f3e2`/`758e75be`/`24cfd2ff`）；CI run `45706557111` 双平台绿；基于 rev-3，不含 rev-5；**分支与提交保持不动** |
| #48 | **CLOSED / completed**（2026-11-25T20:49:12Z，已实时核实）；#33/#67 OPEN 且未变 |
| Owner Round-2 结论 | #128 计划 PASS；恢复设计方向 ACCEPTED；双平台架构 PASS；Go 路线 PASS；最终契约需 targeted update（已在 #126 rev-5 完成）；CI PASS with recorded rerun；**merge/deployment 仍需单独 Owner 授权** |

## 3. 关键结论（rev-5 最终契约）

1. **恢复语义**：center 接受 `1..65535` 的 generation 前跳；新 generation 首个**被接受**请求的 `seq` 可大于 1；ACK `next_seq` 由 agent 采纳；被取代 attempt 的迟到响应被忽略；rotation retry 必须完整执行 boot/seq/nonce/identity 校验，intent replay 不得绕过 high-water。旧 generation、身份冲突、撤销与不安全恢复继续 fail-closed。
2. **数值/存储**：gen/seq 为 canonical decimal，范围 `1..2^63−2`；SQLite 以 signed INTEGER + CHECK 存储，禁止 TEXT/BLOB/REAL/wrap；`next_seq:null` 表示 generation 数值耗尽，agent 必须重启新一代或进入 operator recovery。
3. **双平台与平台隔离**：`node_class` 由 admin bootstrap token scope 绑定 event+class，注册即固化，不能自选；Linux 与 Windows 只允许各自 payload/kind/source，`platform_mismatch` 在存储前拒绝。
4. **Windows 六路径**：`a_reality/a_hy2/b_reality/b_hy2/direct/unknown`（与现有 `windowsobs` 角色枚举一致）；center 做 A/B 聚合与协议下钻；selection 与 active_connections 独立采样；未映射/歧义一律 `unknown`，**绝不自动 DIRECT**；A/B→VPS ID 映射由 center 以**版本 + effective_from** 管理，历史归属不被新映射改写；本地代理名/私有 YAML/凭据/原始目标不上传；**R2 真正只读源优先**，R1（写能力 controller 凭据）需后续单独 Owner 风险接受，不自动启用。
5. **Controller 事实**：Mihomo external controller 凭据可写（`PUT/PATCH /configs`、`/restart`、`PUT/DELETE /proxies`、`DELETE /connections` 等）；GET 白名单不是授权证明，任何“安全只读”表述都被禁止。

## 4. 文档索引（本轮已同步 rev-5）

| 文件 | 内容 |
| --- | --- |
| [01-baseline-status.md](01-baseline-status.md) | #126 rev-5 HEAD/tree/CI/审查、main、Go 分支、Issue 状态、复现命令；Round-1→rev-5 差异 |
| [02-dual-platform-contract.md](02-dual-platform-contract.md) | node_class、六路径 Windows 遥测、版本化映射、R2/R1、平台隔离与隐私（最终契约版） |
| [03-recovery-semantics.md](03-recovery-semantics.md) | A-1..A-5 在 rev-5 中的规范性结果、REC-01..REC-30 关联、数值/存储与旋转规则、决策状态 |
| [04-implementation-plan.md](04-implementation-plan.md) | 实施门禁与顺序、Go 复用/差距、UM-B1..UM-G、Go 分支同步、CI 要求（无 PR-A2） |
| [05-owner-decisions.md](05-owner-decisions.md) | 18 项既有 + rev-5 方向/运行参数 + 门禁登记；全部非 APPROVED |
| [conformance/transport-recovery.cases.json](conformance/transport-recovery.cases.json) | UM-B1/B2/B3 规范性恢复用例（REC-01..REC-30，rev-5 绑定） |

## 5. 下一步（需 Owner 授权）

1. 独立审查 #126 rev-5（独立于 owner Round-2 方向），Owner 给合并授权 → 普通 Merge Commit 合并 #126 → 确认 main CI。
2. #128 完成独立审查/合并门禁 → 合并 #128（保留原 PR，不建 PR-A2）。
3. 最新 main CI 通过后，Owner 授权同步 Go 分支：保留 `17b2f3e2`/`758e75be`/`24cfd2ff`，不 rebase、不 force-push，`docs/um` 与 main 完全一致，不因旧 Go 签名测试失败回退新契约。
4. 进入 UM-B1：复用 `um/internal/wire`、`windowsobs`、`cmd/um-windows-observe`、`um-go.yml`；交付最终契约向量、SQLite 数据层、恢复状态机与自动化一致性测试；Windows 观察器保持实验组件、不服务化、不接入生产。

## 6. 开发边界（本轮再次确认）

- #127 为唯一长期跟踪 Issue；不新增重复设计 PR 或长期 Issue；不创建 PR-A2。
- 不修改 main；不未经授权合并 PR；本 PR 为 Draft。
- 不将两个 Coding AI 分支的旧协议或重复实现直接混合；签名库/观察器不重复实现。
- 不操作生产 VPS；不修改 Clash Verge、HA-UI、monitor-v2、sbox-cm、#67；不购买 VPS、不创建 Cloudflare 应用、不索取生产凭据。
- 不把旧版 UM-A 文档覆盖到新 main；Go 分支同步时 `docs/um` 冲突一律取 main。
- 已知 Windows harness flake 单独处理，不混入设计 PR；UM-F 继续 DEFERRED；生产部署继续 HOLD。

## 7. 验证说明

- 本 PR 为 docs-only；#126 rev-5 的 schema/向量验证结果为：10 个 schema 有效、10 个正例通过、7 个 schema 负例被拒绝、2 个 runtime-only 负例 schema 有效；report/Windows-terminal/enroll/rotate/config 签名向量全部验证通过；45→67 个 behavioural cases（22 个 rev-5 新增）；历史向量可追溯。
- 本 PR 的 JSON 用例、链接、编码与敏感值检查在本地完成；CI 只运行仓库既有回归检查（现有 workflow 不读取 `docs/um/`）。
- 所有 owner 决策仍未批准；本 PR 与 #126 均需独立 review 和 Owner 授权才可合并。
