# UM-127 04 — 统一开发基线与 Go 迁移实施计划

- 状态：**PROPOSED（提案，未批准）**。本文档不构成实现、合并或部署授权。
- 基线：`origin/main` = `885171c08210ad0f4e91f0fed0243460d294b15e`（PR #125 merge，CI 全绿）。
- 设计依赖：PR #126（Draft，HEAD `5089cdeb`，UM-A rev-4）；Go 开发分支 `codex/um-windows-foundation`（HEAD `24cfd2ff`，基于 rev-3 `089f27a5`）。
- 所有 Owner 决策见 `05-owner-decisions.md`，全部 **PENDING**。

## 1. 总原则

1. **单基线**：以 main `885171c0` + PR #126 rev-4 为唯一设计基线；不得把 rev-3 的旧协议/旧文档当成最新契约，也不得把两个 Coding AI 分支的旧协议或重复实现直接混合。
2. **单实现**：`um/internal/wire` 是唯一签名库；不得复制签名逻辑到 center/agent 包，也不得新增第二套 Python/JS 验签实现。`windowsobs` 是唯一 Windows Mihomo 只读观察器原型，不得重写第二个。
3. **先设计后实现**：rev-4 冻结契约需要修正/扩展的部分（`03-recovery-semantics.md`、`02-dual-platform-contract.md`）先走 UM-A rev-5 amendment 并获得 Owner 授权，再进入 UM-B 代码冻结。
4. **每个切片独立 Draft PR**：一个切片一个 PR，写范围互不重叠；不直接推 main，不未经授权合并。
5. **不重复既有系统**：不修改/替换 `monitor-v2`、`sbox-cm`、`ha-ui`、`tools/`、`windows/`、#67 Remote Probe、#33/#48 verdicts 和现有 6 个 workflow；UM 代码只落在新的 `um/`、`docs/um/` 与新的 Go workflow。
6. **不操作生产**：不购买 VPS、不创建 Cloudflare 资源、不接触生产凭据、不部署。

## 2. 可复用资产清单（Go 分支）

| 资产 | 路径/API | 复用方式 | 注意 |
| --- | --- | --- | --- |
| 签名库 | `um/internal/wire/signing.go`：`Fields`、`SigningInput`、`Verify`；strict base64url/hex/UUID/key-id/boot-id 正则；LF join；`{}` config body | **UM-B1 扩展**（不重写） | 缺 `X-UM-Boot-Gen`；node 签名串为 rev-3 的 14 行，rev-4 要求 15 行 |
| 签名测试 | `um/internal/wire/signing_test.go` | **UM-B1 扩展** | 当前只跑 rev-3 向量；rev-4 下会失败；`report-boot-gen-tamper` 未处理 |
| Windows 观察器 | `um/internal/windowsobs/observe.go`：loopback-only、GET /proxies + /connections、4 角色映射、observed/unknown/unavailable、隐私断言 | **保持实验状态**，UM-B3 仅在平台契约扩展获批后接入 | rev-4 的 `mihomo_api` 在 v1 默认关闭且不纳入验收；观察器当前不属于任何 UM-B 切片 |
| 观察器 CLI | `um/cmd/um-windows-observe/main.go`：one-shot，`-profile`/`-secret-file`，exit 0/1/2，无状态 | **保留原型** | 不是服务、无 spool/签名/上报；Windows 服务化在 UM-B3 |
| Go 模块 | `um/go.mod`：module `github.com/yikkrrtykj/install-singboxhysteria2/um`，`go 1.22.0`，零依赖 | 保留 | B1 引入 SQLite 依赖时需 ADR + workflow 变更 |
| Go CI | `.github/workflows/um-go.yml`：ubuntu-24.04 + windows-2022，`go test`/`go build -trimpath`，`GOPROXY=off`，`GOTOOLCHAIN=local` | **UM-B1 扩展** | 需加 `go vet`、`-race`（Linux）、`setup-go` 版本固定、`docs/um/contracts/v1/**` 路径触发、依赖策略 |
| 迁移顺序说明 | `um/README.md`：Shell 继续负责安装/systemd；配置迁移先读校验/生成/预览，写事务最后 | UM-G 依据 | 与 Issue #127 一致 |

## 3. 契约/实现差距矩阵

| # | 能力 | rev-4 来源 | Go 分支现状 | 结论 | 目标切片 |
| --- | --- | --- | --- | --- | --- |
| 1 | Enrollment 签名 | 04 §3–§4 | 正确（向量通过）；无 token/状态/orphan 处理 | **REUSE 签名 + NEW 状态** | B1 签名 / B2 状态 |
| 2 | Report 签名 | 04 §3 | **rev-3 签名串，缺 boot-gen** | **EXTEND** | B1 |
| 3 | Rotate/Config 签名 | 04 §3/§7 | endpoint 串存在但缺 boot-gen；config `{}` 规则正确；无 rotate intent/状态机 | **EXTEND + NEW** | B1 / B2 |
| 4 | Boot generation | 04 §0-A/§2/§5–§6；NEG-BOOT-01..05 | 完全缺失 | **NEW** | B1 wire 字段 + B2 node_boot + B3 Agent 持久化 |
| 5 | Nonce/seq/report_id/fingerprint | 04 §5–§6；NEG-REPORT-* | 完全缺失 | **NEW**（fingerprint helper 放 wire 包，保持唯一 canonicalization） | B1 / B2 |
| 6 | 有界 spool/断线补传 | 04 §6.2–§6.3、§11 | 无（one-shot） | **NEW** | B3 |
| 7 | Center ingest listener | 04 §1–§8、§12；45 个 behavioural negatives | 无 | **NEW** | B2 |
| 8 | SQLite store（WAL/FULL/30d/ledger） | 04 §5–§6、05、08 | 无 | **NEW** | B1 / B2 |
| 9 | Linux Agent | 04 §11；07 B3 | 无 | **NEW** | B3 |
| 10 | Windows 真实数据源 | rev-4 中 **不在 v1**（mihomo 禁用；Q-AGENT-OS 仅 Debian/Ubuntu） | 只读观察器原型 + 合成测试，无真实 Clash Verge Rev 验证，无签名/spool | **EXTEND（受 02 提案约束）** | B3（平台 amendment 批准后） |
| 11 | 冻结正负向量为可执行测试 | 04 §12；contracts/v1 | 只跑 rev-3 加密向量；忽略 45 个 behavioural negatives（ENROLL 11 + REPORT 15 + ROT 11 + GEN 3 + BOOT 5）；无 schema 校验 | **EXTEND + NEW** | B1（crypto/schema）/ B2（behavioural） |
| 12 | 双平台 CI | ADR-UM-002；07 B1 | ubuntu-24.04 + windows-2022 绿 | **KEEP + EXTEND** | B1 |

## 4. 前置门禁

| 门禁 | 条件 | 状态 | 影响 |
| --- | --- | --- | --- |
| G-0 | #127 作为唯一跟踪 Issue；本基线文档获 Owner 认可 | 本文档提交即请求认可 | 计划冻结 |
| G-1 | #126 独立审查 PASS、Owner 合并授权、#126 已合并、main CI（该 merge commit）全绿 | **未满足**（#126 为 Draft，GitHub 上无 review 记录，18 项 Owner 决策 PENDING） | 文档基线/后续 PR 的依赖 |
| G-2 | Owner 批准 UM-A rev-5 amendment（恢复语义 A-1..A-5 + 双平台扩展） | **未满足**（提案见 02/03） | UM-B1/B2/B3 代码冻结 |
| G-3 | Owner 授权同步 Go 分支到最新 main | **未满足** | Go 分支保持不动 |
| G-4 | Owner 按切片批准 Draft PR 的实施 | **未满足** | UM-B..UM-G 全部 HOLD |
| G-5 | 生产部署授权（UM-E 后另行批准） | HOLD | 任何部署/资源 |

## 5. Go 分支保存与同步规程

### 5.1 保存（现在到 G-3 之前）

- 不 rebase、不 force-push、不 cherry-pick、不 merge main 到 `codex/um-windows-foundation`；不删除分支；3 个开发提交保持原 SHA：
  - `17b2f3e2` Go observer
  - `758e75be` Go CI
  - `24cfd2ff` signing primitives
- 分支基于 `089f27a5`（rev-3），与 #126 HEAD `5089cdeb`（rev-4）为兄弟关系；不得把两者混为一条线。
- 本文档只记录事实，不改变分支。

### 5.2 同步（G-1 + G-3 之后）

推荐 **merge main 进 Go 分支**，保留 3 个提交 SHA（不用 rebase/force-push）：

```bash
git fetch origin
git switch codex/um-windows-foundation
git merge --no-ff --no-commit origin/main        # 保留 3 个开发提交；冲突先不提交
git checkout origin/main -- docs/um              # 无论是否冲突，docs/um 一律取 main（rev-4）
git add docs/um
git commit -m "merge: sync main (UM-A rev-4) into Go foundation"
git diff --exit-code origin/main -- docs/um      # 必须为空：Go 分支的 docs/um 与 main 完全一致
git diff --exit-code 24cfd2ff -- um .github/workflows/um-go.yml  # 代码内容不变
git push origin codex/um-windows-foundation      # 普通 push，禁止 --force
```

验证清单：

- [ ] `git log --format='%h %an <%ae>' origin/main..HEAD` 全部为 `yikkrrtykj <152189277+yikkrrtykj@users.noreply.github.com>`。
- [ ] `git diff --stat origin/main -- docs/um` 为空（不得把旧版 UM-A 文档覆盖新 main）。
- [ ] 3 个开发提交仍在祖先链上（`git merge-base --is-ancestor 24cfd2ff HEAD`）。
- [ ] `cd um && go build ./...` 通过。
- [ ] `cd um && go test ./...` **预期失败**：fixtures 已变为 rev-4，而 wire 仍是 rev-3（缺 `X-UM-Boot-Gen`）——这是 B1 的已知待修项，不是回退文档的理由；在 B1 修复前不得把 Go 分支作为 PR 合并到 main，也不得宣称 v1 合规。
- [ ] 合并后 main CI（6 个既有 workflow）绿；`um-go.yml` 不会因 `docs/um` 变更触发（path filter 只含 `um/**`），属预期。

禁止：直接 cherry-pick Go 提交到 main（fixtures 在 main 不存在，`go test` 会失败）；在文档未合并前合并 Go 分支。

## 6. 实施切片

### 通用 PR 规则

- 每个 PR：单一目的、独立 Draft、写范围明确、CI 证据、不过度放宽测试/不跳过检查。
- 提交身份：`yikkrrtykj <152189277+yikkrrtykj@users.noreply.github.com>`（AGENTS.md）。
- 不修改现有 6 个 workflow；Go 相关 CI 只改/新增 `um-go.yml`（或新的 `um-*.yml`）。
- 不改 `docs/um/um-a/**` 的 rev-4 内容；契约修订只通过 amendment PR（UM-A rev-5）。
- 每个 PR 的验收证据贴在本 PR；跟踪 Issue 只保留 #127，不新建重复主 Issue。

### PR-A2（先于 B1/B2/B3 代码冻结）：UM-A rev-5 amendment

- 内容：合并 `03-recovery-semantics.md`（A-1..A-5）与 `02-dual-platform-contract.md`（node_class/terminal/controller 授权）为 `docs/um/um-a/04`/`contracts/v1` 的修订版；新增/更新正负向量（含缺失的 **rotate/config 正向量**、Windows terminal 正负向量、REC-01..REC-30 引用的行为用例）；更新 07 的 UM-B entry criteria 与文档一致性清单（01 §4.1）。
- 写范围：`docs/um/**`（只增改 amendment 指定文件）。
- 前置：G-1（#126 合并）+ Owner 对 OD-R1..R5、OD-P1..P8 的裁决。
- 验收：schema 校验、正负向量（新增 Windows/恢复 case）、文档一致性检查、独立审查；45 个既有 behavioural cases（ENROLL 11 + REPORT 15 + ROT 11 + GEN 3 + BOOT 5）与 13 个 state-transition cases 全部保留并重新验证。
- 不做：任何代码。

### UM-B1：Go 工程、共享签名库、SQLite、协议一致性测试

- 交付：
  1. `um/` 包结构：`internal/wire`（加 BootGen、header 常量、typed error、fingerprint helper）、`internal/store`（SQLite schema/migrations/事务封装）、`internal/protocol`（A-1/A-2 状态机纯逻辑）、`internal/vectors`（conformance harness 读取 `docs/um/contracts/v1/**`）。
  2. SQLite：WAL + `synchronous=FULL`；表：`nodes`、`node_keys`、`key_rotations`、`node_boot`、`seq_dedupe`、`nonce_dedupe`、`report_dedupe`、`boot_registry`、`security_ledger`（B1 先建 schema/迁移/基本写入）；30 天 retention 引擎骨架。
  3. 契约一致性：rev-4 全部正负向量 + `conformance/transport-recovery.cases.json` 中 UM-B1 用例；schema 校验器（不引第三方 JSON Schema 依赖则实现最小校验或引入受批准依赖）。
  4. CI：`um-go.yml` 扩展（`go vet`、Linux `-race`、`setup-go` 固定版本、`docs/um/contracts/v1/**` 路径触发、coverage artifact）；依赖引入需 ADR（`modernc.org/sqlite` 等）与 `go.sum`。
- 写范围：`um/**`、`.github/workflows/um-go.yml`（及必要时新 workflow 文件）。
- 前置：G-1 + G-2（amendment 批准）+ G-4。
- 验收：`go test ./...`、`go vet`、`-race`（Linux）、SQLite 崩溃/重开测试、retention 加速测试、向量全绿；无 listener、无 Agent。
- 不做：HTTP ingest、Agent、Web、Windows 服务。

### UM-B2：中心注册、认证、数据接收、去重及安全状态

- 交付：
  1. `um/internal/nodewire` HTTP 绑定：raw header 重复检查、encoding 一致性、size caps、±300s 新鲜度、错误码表、签名验证调用 `wire`。
  2. `um/internal/center`：`/v1/agent/enroll|report|rotate|config`；enrollment active-on-commit；rotation 状态机；revocation；单事务去重（nonce/boot/seq/report_id + 数据 + high-water）；security ledger 写入；A-1/A-2 恢复语义。
  3. 合成 Agent harness：REC-01..REC-30 全部（或按切片分配）、45 behavioural negatives、center 重启、并发/背压、rate limit。
  4. 监听器隔离：机器入口与未来 admin 入口不同 listener/路由命名空间；TLS 终止方式按 Q-INGRESS 决策（Cloudflare Tunnel 或 direct TLS）；不实现 web admin。
- 写范围：`um/internal/**`、`um/cmd/um-center`、测试、`um-go.yml`（如需新 lane）。
- 前置：G-1/G-2/G-4；B1 完成。
- 验收：向量/负向全绿、恢复用例全绿、load smoke（如 150 nodes 合成）、无数据伪造/隐私 sentinel、审计条目正确。
- 不做：Web UI、TOTP、生产部署。

### UM-B3：Linux Agent、Windows Agent、真实数据源及断线恢复

- 交付：
  1. Linux Agent：`cmd/um-agent`、boot state（fsync、+1、随机 boot_id、损坏 fail-closed）、有界 spool（32 MiB/7 d、单写者、fsync-before-send、quarantine、1→60s backoff）、rotation intent、中心客户端；数据源：sing-box `service.api`（启用前 server-side 授权审计）、`/proc`、只读 D-Bus；`singbox_api` 默认关闭。
  2. Windows Agent（仅在平台 amendment + OD-P3 批准后）：服务化、DPAPI/私有 ACL 凭据、`windowsobs` 契约化输出（terminal snapshot/events）、A/B token 映射、UNKNOWN/UNAVAILABLE；真实 Clash Verge Rev/Mihomo 版本验证。
  3. 安装/运行：Shell 继续负责主机安装/systemd；root 一次性编排 + 非 root 运行；Windows 安装器/服务管理；runbook。
  4. 恢复矩阵：连续离线重启、首请求失败、ACK 丢失、rotation 跨重启、撤销、boot-state 丢失/旧快照。
- 写范围：`um/cmd/um-agent`、`um/internal/agent`、`um/internal/spool`、`um/internal/collect`、`um/internal/windowsobs`（契约化）、Windows 服务代码、安装脚本（新增路径，不改既有 install.sh 逻辑 unless owner-approved）。
- 前置：B2 完成；G-2 平台扩展批准；OD-P3 裁决；Linux 数据源授权审计记录。
- 验收：Linux/Windows CI；离线/崩溃/恢复矩阵；只读/HA 断言；隐私 sentinel；Linux systemd/no-exec 证明；Windows 真实联调记录（UM-E 继续完整验收）。
- 不做：Mihomo 配置修改、节点切换、关连接、HA 变更、远程控制面。

### UM-B4：赛事、节点、别名和平台管理 API

- 交付：admin API/CLI：event/node 注册与查询、平台类别、revocation、retention、device/route alias、`terminal_route_map` 配置、审计；RBAC 基础。
- 前置：B2；G-4。
- 验收：跨 event 隔离、审计、data-honesty API；无 Web UI（UM-C）。

### UM-C：公网安全认证

- 交付：Cloudflare Tunnel/Access（或 Q-INGRESS 决策）、登录/TOTP、会话/CSRF/rate limit、admin 与 machine 入口隔离、subject 绑定。
- 前置：Q-INGRESS/Q-DNS/Q-ADMIN 决策；B4。
- 验收：两个赛事权限隔离、未认证/越权/重放测试；生产部署仍 HOLD。

### UM-D：统一赛事 Dashboard

- 交付：Vue 3 + TS + Vite + uPlot；同一赛事视图展示 Linux VPS 与 Windows 终端；当前选路 vs 活动连接分布；采样时间、UNKNOWN/UNAVAILABLE/STALE、数据缺口/故障时间线；30 天历史。
- 前置：UM-C；B2/B3 数据可用。
- 验收：数据诚实性 UI 测试、A/B 切换与旧连接同时识别、跨赛事隔离。

### UM-E：完整安全和运行验收

- 交付：负载/容量、故障注入、备份/恢复（局部 + 整机）、撤销/轮换、隐私扫查、双平台 CI、独立安全审查、部署准备与回滚。
- 前置：UM-B..D 完成；Owner 授权。
- 验收：≥2 赛事隔离、真实 Clash Verge Rev/Mihomo A/B 验证、断网恢复、中心故障、回滚；生产发布单独批准。

### UM-F：网页受控客户端管理（DEFERRED）

- 仅在 UM-E 通过后另行授权/设计；v1 中心保持只读；不实现远程写。

### UM-G：旧配置逻辑迁移 Go

分阶段（每阶段独立 PR，前置 Owner 批准；Stage 0 以前只做调研/夹具，不改现有文件）：

| Stage | 范围 | 退出条件 |
| --- | --- | --- |
| 0 | 兼容性语料与 harness：`install.sh`/`lib/client-management.sh` SHA 锚、合成配置、规范 YAML（普通+hopping）、problem set/exit code 快照、故障注入 trace、历史导出 | 语料冻结在只含 `um/**`（及经 Owner 批准的 `tests/um/**`）的 PR；不修改现有文件 |
| 1 | 纯校验 Go：`validate_client_name`、`client_structure_problems`、`candidate_problems`、legacy JSON prechecks、`phase_d_*`、`existing_api_auth_classify`；`um config validate` | 与 shell oracle 语义/字节对齐（含 fail-closed）；无特权、离线 |
| 2 | 生成+预览：`cm_render_client_mihomo_yaml`（含 hopping）字节一致、`phase_d_inject_api_service` transform、profile merge/transform 对照、`--check`/`plan` preview 与机器可读 diff；**无写入** | `cmp` 字节一致；preview 零变更（strace/文件审计）；secret 不进 argv/env/temp（泄漏扫查） |
| 3 | 只读影子采用：CI/测试以 Go validate/preview 与 shell 对照，shell 仍权威 | 语料 + 真实历史导出零差异；独立审查 |
| 4 | 写事务（最后）：candidate→check→journal→backup→atomic replace→reload→health→rollback；同一 `config.lock` 路径/语义；复用 `sing-box check`；入口点不变 | 重放 legacy T1–T18b、X1–X18、e3 crash 矩阵；HA-UI 入场点/成功标记/信任锚兼容 |
| 5 | 受控切换非破坏性入口（或并行版本化入口）；Shell 保留安装/systemd | Owner 批准的发布/回滚计划 + 每入口证据 |
| 6 | 退役重复 shell 逻辑（仅在所有入口验证后）；破坏性/系统操作留 Shell | Owner 明确决定 + 更新信任锚（install.sh/lib SHA、HA-UI reviewed commit） |

硬限制：

- 不改 `monitor-v2`、`sbox-cm`、`ha-ui`、`tools/`、`windows/`、6 个既有 workflow、被部署服务、#67/#33/#48 判定。
- 不在 UM 中心/Agent v1 中写配置；UM-G 是运营方本地工具/CLI，直到单独写入授权。
- 不新建第二个 `config.lock`、commit engine、YAML renderer、credential digest。
- 不破坏信任锚：`install.sh:789` 的 lib SHA、HA-UI `9402be91` reviewed commit、`配置已提交` 成功标记；任何 install.sh/lib 字节改动需重 pin + HA-UI 发布审查。
- 保留 fail-closed 与诚实状态；不伪造 rollback 成功/新鲜度/凭据回显。
- `sing-box check`/`sing-box generate` 继续作为二进制权威，不重实现 sing-box 校验。
- Go CI 依赖诚实：`GOPROXY=off` 现状；任何模块引入需独立审查的 workflow/依赖登记（新文件，不改既有 workflow）。
- 计划前核实 #48 实时状态（本地缓存与 UM-A 文档冲突：文档称 Closed/Completed，缓存称 OPEN）；无论结果如何不重开/关闭/重解释。

## 7. CI 矩阵演进

| 阶段 | ubuntu-24.04 | ubuntu-22.04 | windows-2022 | 其他 |
| --- | --- | --- | --- | --- |
| 现状 | native | — | native | 现有 6 workflow 不变 |
| UM-B1 | build/test/vet/race/coverage | 可选兼容 job（Go 版本与 glibc 无关，优先级低） | build/test | 路径触发加 `docs/um/contracts/v1/**`；`setup-go` 固定版本 |
| UM-B2 | 全量 + load smoke | — | 全量 | 新增（或同一 workflow）center job |
| UM-B3 | Agent unit + systemd lab | 可选 | Agent unit + 服务测试 | Linux seccomp/D-Bus 测试 |
| UM-C/D | Web 构建/测试 | — | 浏览器/E2E（可选） | 不修改现有 workflow |
| UM-G | 与 shell oracle 对照 | 需要（22.04 兼容） | — | 现有 shell 测试保持不动 |

`um-go.yml` 建议变更（UM-B1 PR 内完成，需 Owner 批准）：
- `setup-go` 固定 Go 版本（与 `go.mod`/ADR 一致）；
- 增加 `go vet ./...`、Linux `-race`、coverage 上传；
- path filter 增加 `docs/um/contracts/v1/**`（否则 fixture 变化无信号）；
- 依赖策略：若引入 `modernc.org/sqlite`/`x/crypto` 等，记录依赖登记、`go.sum`、允许的 proxy/vendor 方案；不得静默放宽 `GOPROXY=off`。

## 8. 风险登记

| 风险 | 影响 | 缓解 |
| --- | --- | --- |
| #126 长期 Draft / 无独立审查 | 全部实现被 G-1 阻塞 | Owner 指定审查方/授权；保持 Go 分支不动 |
| 18 项 Owner 决策未决 | 设计冻结无法完成 | 05 统一登记，逐项要 Owner 裁决；不默认批准 |
| 恢复语义与 rev-4 冲突（F1/F2） | 离线重启节点永久停摆 | 03 提案 A-1/A-2 + 红先测试；先 amendment |
| Windows 契约扩展未批准 | 首版 Windows 遥测缺失 | 02 提案 + OD-P1..P8；不静默改范围 |
| Controller 凭据写能力 | 安全宣称不实/业务风险 | 02 §6 事实披露 + R1/R2 方案 + Owner 风险接受 |
| Go 分支与 rev-4 fixture 不兼容 | 合并后 Go CI 失败 | 5.2 同步规程；B1 修 boot-gen；禁止提前合并 |
| Go 依赖/CI 策略 | `GOPROXY=off` 无法构建 SQLite | B1 内 ADR + workflow PR；Q-TECH 决策 |
| 既有系统被误改 | HA/监控回归 | 写范围硬限制；PR 审查 check list |
| 信任锚被破坏（UM-G） | HA-UI/安装器拒绝 | Stage 4 前不碰 install.sh/lib；重 pin 流程 |
| #48 状态矛盾 | 计划引用错误事实 | G-0 前实时核实；不改变其状态 |
| 计划被当成实现授权 | 越权开发/部署 | 每份文档标注 PROPOSED；PR 均为 Draft |

## 9. 本轮（UM-127 round 1）交付物

1. 本文档与 01/02/03/05、`conformance/transport-recovery.cases.json`（docs-only）。
2. UM-A 收口状态记录：见 `01-baseline-status.md`（#126 HEAD/tree/CI/审查、main CI、Go 分支与 CI、#127/#48/#33/#67）。
3. Owner 决策登记：见 `05-owner-decisions.md`（全部 PENDING）。
4. 本轮**不**做的事：不合并 #126、不改 main、不合并/改写 Go 分支、不创建实现 PR、不部署、不申请凭据。

后续动作（需 Owner 授权）：

- 认可本基线 → 进入 G-1（#126 审查/合并）。
- 批准恢复语义与双平台 amendment 决策 → PR-A2。
- 授权/排期 UM-B1 → 独立 Draft PR。
