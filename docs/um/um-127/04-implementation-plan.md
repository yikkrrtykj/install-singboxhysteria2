# UM-127 04 — 统一开发基线与 Go 迁移实施计划（rev-5 最终契约版）

- 状态：**PROPOSED（规划，Draft PR）**。不构成实现/合并/部署授权。
- 最终契约：PR #126（UM-A revision 5），HEAD `048fc170`，tree `1b726de9…`；本文与 #128 已同步该基线。
- 旧基线：`main` `885171c0`；Go 分支 `codex/um-windows-foundation` @ `24cfd2ff`（3 个开发提交，保持不动）。

## 1. 总原则

1. **唯一契约**：#126 rev-5 是唯一设计基线；不再创建独立 PR-A2，不再重复设计；#128 只保留规划/实施说明并同步到 rev-5。
2. **单实现**：`um/internal/wire` 是唯一签名库；`windowsobs` 是唯一 Windows 路由观察原型；不得复制出第二套签名/角色枚举/接收器。
3. **门禁顺序**：#126 独立审查 → Owner 合并授权 → 普通 Merge Commit → main CI → #128 独立审查/合并 → 最新 main CI → Owner 授权同步 Go 分支 → UM-B1。
4. **不越权**：不直接改 main；未授权不合并；不操作生产；不申请 VPS/Cloudflare/凭据；UM-F DEFERRED；生产 HOLD。
5. **旧测试失败不倒退契约**：Go 分支旧 wire 测试基于 rev-3（无 `X-UM-Boot-Gen`），同步后**预期失败**；必须在 UM-B1 修正，禁止回退 docs/um 或简化协议以迁就旧测试。

## 2. 可复用资产清单（Go 分支）

| 资产 | 路径/API | 复用方式 | 注意 |
| --- | --- | --- | --- |
| 签名库 | `um/internal/wire/signing.go`：`Fields`、`SigningInput`、`Verify`；strict base64url/hex/UUID/key-id/boot-id；LF join；`{}` config body | **UM-B1 扩展**（不重写） | rev-3 缺 `X-UM-Boot-Gen`；node 签名串需改为 rev-5 15 行 |
| 签名测试 | `signing_test.go` | UM-B1 扩展 | 当前只跑 rev-3 向量；同步 rev-5 后失败，B1 修 |
| Windows 观察器 | `um/internal/windowsobs/observe.go`：loopback-only GET `/proxies`+`/connections`、四角色 `a_reality/a_hy2/b_reality/b_hy2`、selection/active_connections 分离、observed/unknown/unavailable、隐私断言 | **保持实验组件**；UM-B3 扩展为 rev-5 六 token（新增 `direct`/`unknown`）并契约化输出 | 不在 B1/B2 服务化，不接入生产 |
| 观察器 CLI | `um/cmd/um-windows-observe/main.go`：one-shot、`-profile`/`-secret-file`、exit 0/1/2 | 保留原型；服务化/安装器在 UM-B3 | 无 spool/签名/上报 |
| Go 模块 | `um/go.mod`：module `.../um`，`go 1.22.0`，零依赖 | 保留 | B1 引 SQLite 依赖需 ADR + 新/改 CI |
| Go CI | `.github/workflows/um-go.yml`：ubuntu-24.04 + windows-2022，`go test`/`go build -trimpath`，`GOPROXY=off`，`GOTOOLCHAIN=local` | UM-B1 扩展 | 需 `setup-go` 固定版本、`go vet`、Linux `-race`、contract path 触发、依赖审计 |
| 迁移顺序说明 | `um/README.md`：Shell 继续安装/systemd；配置迁移先只读校验/生成/预览，写事务最后 | UM-G 依据 | 与 Issue #127 一致 |

## 3. 契约/实现差距矩阵（rev-5）

| # | 能力 | rev-5 来源 | Go 分支现状 | 结论 | 切片 |
| --- | --- | --- | --- | --- | --- |
| 1 | Enrollment 签名 + class/token scope | 04 §3–§4 | 签名正确（旧向量）；无 token scope/class 状态 | **REUSE 签名 + NEW 状态** | B1/B2 |
| 2 | Report/Windows terminal 签名 | 04 §3、§9.2；Windows 向量 | rev-3 14 行签名、无 boot-gen；windowsobs 输出非 contract body | **EXTEND wire + EXTEND observer** | B1/B3 |
| 3 | Rotate/config 签名 + 全量 retry 校验 | 04 §3、§7、§13 | endpoint 串存在缺 boot-gen；无 rotate intent/high-water | **EXTEND wire + NEW state** | B1/B2 |
| 4 | Boot generation/A-1..A-5 | 04 §5–§6.4、§13 | 缺失 | **NEW** | B1/B2/B3 |
| 5 | Numeric/SQLite/ACK exhaustion | 04 §2、§13 | 缺失 | **NEW** | B1/B2 |
| 6 | Replay/dedupe/fingerprint | 04 §5–§6 | 缺失 | **NEW** | B1/B2 |
| 7 | Center ingest/listener | 04 §1–§8 | 无 | **NEW** | B2 |
| 8 | SQLite store（WAL/FULL/30d/ledger/mapping versions） | 04 §13、05 | 无 | **NEW** | B1/B2 |
| 9 | Linux Agent + Linux 数据源 | 04 §11 | 无 | **NEW** | B3 |
| 10 | Windows Agent 六 token/R2-R1/服务化 | 04 §9.2、§11 | 实验 observer，无服务/签名/spool/真实构建验证 | **EXTEND（受 rev-5 约束）** | B3 |
| 11 | 冻结向量/负例可执行测试 | 04 §12；contracts/v1 | 只跑 rev-3 加密向量 | **EXTEND + NEW** | B1/B2 |
| 12 | 双平台 CI | ADR-UM-002；07 | 已绿（旧） | **KEEP + EXTEND** | B1 |

## 4. 门禁与合并顺序

| 门禁 | 条件 | 状态 |
| --- | --- | --- |
| G-0 | #127 唯一 Issue；#128 计划被 Owner 审阅；rev-5 已进入 #126 | 已完成（Owner Round-2 结论见 05） |
| G-1 | #126 rev-5 **独立审查 PASS**（独立于 Owner Round-2 方向） | **未满足**（GitHub 仍无 review 记录） |
| G-2 | Owner 合并授权 → 普通 **Merge Commit** 合并 #126 → 该 merge commit main CI 全绿 | 未授权 |
| G-3 | #128 同步后完成独立审查/合并门禁 → 合并 #128（保留原 PR，不建 PR-A2） | 未满足 |
| G-4 | 最新 main CI 通过 + Owner 授权 → 同步 Go 分支（保留 3 提交，不 rebase/force，docs/um 与 main 一致） | HOLD |
| G-5 | Owner 按切片批准 UM-B1..UM-G 的独立 Draft PR | HOLD |
| G-6 | 生产部署/发布/凭据/VPS/Cloudflare | HOLD |

## 5. Go 分支保存与同步规程

**现在到 G-4：** 不 rebase、不 force-push、不 cherry-pick、不 merge main；保留 `17b2f3e2`、`758e75be`、`24cfd2ff`。

**G-4 后（Owner 授权）：**

```bash
git fetch origin
git switch codex/um-windows-foundation
git merge --no-ff --no-commit origin/main
git checkout origin/main -- docs/um          # 冲突/非冲突均取 main；禁止 rev-3 文档覆盖新 main
git add docs/um
git commit -m "merge: sync main (UM-A rev-5) into Go foundation"
git diff --exit-code origin/main -- docs/um  # 必须为空
git diff --exit-code 24cfd2ff -- um .github/workflows/um-go.yml  # 代码内容不变
git push origin codex/um-windows-foundation  # 普通 push，禁止 --force
```

验证：`git log --format='%h %an <%ae>' origin/main..HEAD` 全部为 `yikkrrtykj <152189277+yikkrrtykj@users.noreply.github.com>`；3 个提交仍在祖先链；`docs/um` 与 main 完全一致；`cd um && go build ./...` 通过；`go test ./...` **预期失败**（旧 rev-3 签名测试 vs rev-5 fixtures）→ 在 UM-B1 修复，禁止回退契约。

## 6. 实施切片

### 通用规则

- 每切片独立 Draft PR、单一目的、写范围明确、CI 证据、不弱化测试。
- 不改现有 6 个 workflow；Go 相关 CI 只改/新增 `um-go.yml` 或新的 `um-*.yml`。
- 契约修订只能通过 #126 分支的 amendment（本轮已完成 rev-5），不得在实现 PR 私自改契约。
- 跟踪 Issue 只保留 #127。

### UM-B1：Go 工程、共享签名库、SQLite、契约一致性

交付：

1. `um/internal/wire`：加 `BootGen`，node 签名串改 15 行；header 常量、typed error、fingerprint helper；rev-5 正/负向量测试。
2. `um/internal/store`：SQLite WAL + `synchronous=FULL`；表：`nodes`（含 node_class）、`node_keys`、`key_rotations`、`node_boot`、`seq_dedupe`、`nonce_dedupe`、`report_dedupe`、`boot_registry`、`route_mapping_versions`、`security_ledger`；数值 INTEGER+CHECK；30d retention 骨架。
3. `um/internal/protocol`：A-1..A-5 状态机纯逻辑；REC-01..REC-30 中 B1 用例；schema 校验器（真实校验，不允许只 parse JSON）。
4. `um/internal/windows`（仅 schema/类型/转换，不服务化）：六 token、terminal 对象、独立采样一致性、privacy sentinel 类型校验。
5. CI：`setup-go` 固定版本；`go build`/`go vet`/`go test`/Linux `-race`；path 触发加 `docs/um/contracts/v1/**`；依赖审计（`go.sum` + ADR）；coverage artifact。
6. 验收：全部 rev-5 正负向量与 schema 例执行；SQLite 重启/崩溃/最大数值 round-trip 测试；禁止“简化 schema 校验、恒真测试、仅 JSON 解析冒充一致性”。

### UM-B2：中心注册、认证、接收、去重与安全状态

- `/v1/agent/enroll|report|rotate|config`；token scope 绑定 event+class；active-on-commit；platform isolation；A-1..A-5；rotation 状态机（全量校验）；revocation；单事务去重/high-water；security ledger；`route_mapping_versions` 不重写历史；合成 Agent harness 跑 REC 全矩阵 + 67 behavioural cases；center 重启/并发/背压/负载 smoke；机器入口与 admin 入口隔离；TLS 方案按 Q-INGRESS 决策。
- 写范围：`um/internal/**`、`um/cmd/um-center`、测试、CI。

### UM-B3：Linux/Windows Agent、真实数据源、断线恢复

- Linux Agent：boot state fsync、spool（32 MiB/7d、单写者、fsync-before-send、quarantine、1→60s backoff）、rotation intent、center client；`singbox_api`（server-side 授权审计后启用）、`/proc`、只读 D-Bus；无 exec/root。
- Windows Agent：仅在 rev-5 与 OD-P3 门禁后；`windowsobs` 契约化（六 token、独立采样、UNKNOWN/UNAVAILABLE、privacy）、服务化、凭据存储（DPAPI/ACL）、R2 优先、R1 仅单独 Owner 接受后启用；**不改 Mihomo 配置、不切换、不关连接、不改 HA**。
- 安装/运行：Shell 继续负责主机安装/systemd；root 一次性编排/非 root 运行；Windows 安装器/服务；runbook。
- 恢复矩阵：连续离线重启、首请求丢失/ACK 丢失、rotation 跨重启、撤销、boot-state 丢失、旧快照、数值耗尽。
- 验收：双平台 CI、真实 Clash Verge Rev/Mihomo 只读/HA 断言、Linux no-exec/D-Bus proof、隐私 sentinel。

### UM-B4：管理 API/CLI

- event/node 注册与类别查询、revoke、retention、device/route alias、`route_mapping_versions`（版本+effective_from、审计、不重写历史）、RBAC 基础；无 Web UI（UM-C）。

### UM-C / UM-D / UM-E / UM-F / UM-G

- **UM-C**：Cloudflare Tunnel/Access 或 Q-INGRESS 选型、登录/TOTP、会话/CSRF/rate limit、admin/machine 入口隔离、两个赛事权限隔离；生产仍 HOLD。
- **UM-D**：Vue 3+TS+Vite+uPlot；同一赛事视图展示 Linux VPS + Windows 终端；A/B 汇总+协议下钻；selection vs active_connections 差异；采样时间、UNKNOWN/UNAVAILABLE/STALE、缺口/故障时间线；30 天历史；映射版本历史展示。
- **UM-E**：负载/容量、故障注入、备份/恢复、撤销/轮换、隐私扫查、双平台 CI、独立安全审查、部署准备/回滚；≥2 赛事隔离、真实 Clash Verge Rev/Mihomo A/B 验证；生产发布单独批准。
- **UM-F**：DEFERRED；UM-E 后另行授权设计，v1 中心只读。
- **UM-G**：Stage 0 兼容语料 → Stage 1 纯校验 → Stage 2 生成+预览（字节一致、零写、无 secret 泄漏）→ Stage 3 只读影子 → Stage 4 写事务（最后；同 `config.lock`/journal/reload/rollback，复用 `sing-box check`）→ Stage 5 受控切换 → Stage 6 退役重复 shell。硬限制：不改 monitor-v2/sbox-cm/ha-ui/tools/windows/6 workflows/#33/#67/#48；不新建第二 lock/commit engine/renderer/digest；不破坏 install.sh:789/HA-UI `9402be91`/`配置已提交` 信任锚；Shell 保留安装/systemd；UM-G 是运营方本地工具，不是 center 写路径。

## 7. CI 矩阵演进

| 阶段 | ubuntu-24.04 | windows-2022 | 说明 |
| --- | --- | --- | --- |
| 现状 | native（旧） | native（旧） | 现有 6 workflow 不改 |
| UM-B1 | build/vet/test/race/coverage | build/test | 路径加 `docs/um/contracts/v1/**`；固定 Go；依赖审计 |
| UM-B2 | 全量 + load smoke | 全量 | center job |
| UM-B3 | agent unit + systemd lab | agent unit + 服务测试 | Linux seccomp/D-Bus；Windows 只读/HA |
| UM-C/D | Web build/test | E2E（可选） | 不改现有 workflow |
| UM-G | shell-oracle 对照 | — | 现有 shell 测试保持不动 |

`um-go.yml` 变更（B1 内，需 Owner 批准）：`setup-go` 固定版本；`go vet`；Linux `-race`；coverage 上传；`docs/um/contracts/v1/**` 触发；依赖登记/`go.sum`/proxy 或 vendor 策略（不得静默放宽 `GOPROXY=off`）。

## 8. 风险登记

| 风险 | 影响 | 缓解 |
| --- | --- | --- |
| #126 rev-5 长期无独立审查 | 全部实现/G-2 阻塞 | Owner 指定审查方；保持 Go 分支不动 |
| 18 项 Owner 决策 + 运行参数未决 | 设计/运行边界不清 | 05 分设计/运行/未批准三类；不默认批准 |
| Windows R2 不可行、R1 未接受 | Windows 遥测缺失 | 02 §4；R2 优先；R1 单独 Owner 风险接受 |
| 六 token/映射被简化 | 协议完整性/历史归属破坏 | rev-5 schema/负例/审计；UM-B1 严格测试；#126 变更控制 |
| Go 分支旧签名测试失败 | 误以为可回退契约 | G-4 明确预期失败；B1 修复；禁止回退 docs/um |
| Go 依赖/CI 策略 | `GOPROXY=off` 无法构建 SQLite | B1 ADR + workflow PR；固定工具链/依赖审计 |
| 既有系统被误改 | HA/监控回归 | 写范围硬限制；PR 审查清单 |
| 信任锚被破坏（UM-G） | HA-UI/安装器拒绝 | Stage 4 前不碰 install.sh/lib；重 pin 流程 |
| Windows harness flake | CI 噪声/误判 | 单独处理；同 HEAD rerun；不混入设计 PR |
| 计划被当成实现授权 | 越权开发/部署 | 所有文档 PROPOSED/FINAL contract-only；PR Draft；门禁 |

## 9. 本轮交付物

1. #126 rev-5 targeted amendment（24 files；schema/向量/负例/文档）。
2. #128 规划基线同步 rev-5（本文及 01/02/03/05/conformance）。
3. Owner 决策/门禁登记（05）、REC-30、UM-B1..UM-G 路线、Go 复用资产、迁移阶段与验收门禁。
4. 本轮**不做**：不合并 #126/#128、不改 main、不同步 Go 分支、不实现 UM-B1、不部署、不申请资源。
