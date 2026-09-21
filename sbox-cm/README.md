# sbox-cm — 特权执行平面（E3 M1）

状态：**M1 已实现（仓库内），未部署、未启用管理面、未触碰生产 sing-box。**

```text
M0    shared transaction / lock / rollback        ✅
M0.5  step-up / web privilege boundary            ✅
M1    sbox-cm privileged backend                  本目录
M2    Web → sbox-cm adapter                       后续
M3    production activation / canary              后续

E3 MANAGEMENT ENABLED = NO
PRODUCTION DEPLOYED   = NO
```

M1 只交付**特权执行面**：Web 接入（M2）、激活（M3）、生产 canary 都不在本轮。

---

## 1. 架构

```text
Browser
   │  M2 才接入
   ▼
singbox-monitor.service (User=sboxweb)
   │  AF_UNIX / e3-rpc/1
   ▼
sbox-cm.service (User=root)
   ├── RPC core            sbox-cm/sbox-cm      (Python, transport only)
   └── transaction worker  sbox-cm/sbox-cm-ops  (bash, privileged)
           ├── lib/client-management.sh   唯一 commit engine（digest-pinned）
           ├── lib/sbox-cm-state.sh       ledger / journal / audit / marker
           ├── /root/sbox/config.lock     唯一全局锁
           └── commit_server_config
                   ▼
        /root/sbox/sbconfig_server.json
```

固定安全原则：

```text
一条特权通道 / 一把全局锁 / 一套 commit engine / 一套 restore primitive / 零 Web 文件系统旁路
```

**RPC core 绝不读写 `sbconfig_server.json`、绝不算凭据 digest、绝不见 UUID/password。**
七个 op 全部 dispatch 给 root worker —— op 语义只有一份实现。

## 2. 文件

| 路径 | 角色 | 权限 |
| --- | --- | --- |
| `sbox-cm/sbox-cm` | RPC core（Python 3.10+ stdlib） | 0755 root |
| `sbox-cm/sbox-cm-ops` | 特权事务 worker（bash） | 0755 root |
| `lib/client-management.sh` | 唯一事务引擎 + 客户端管理语义 + planned credential 原语 | digest-pinned |
| `lib/sbox-cm-state.sh` | ledger / journal / audit / marker / degraded | — |
| `sbox-cm/deploy/sbox-cm.socket.in` | systemd socket（`/run/sbox-cm/sbox-cm.sock`，root:sboxweb 0660） | — |
| `sbox-cm/deploy/sbox-cm.service.in` | systemd service（`User=root`，AF_UNIX only） | — |
| `sbox-cm/deploy/install-sbox-cm.sh` | 部署 / enable / disable / recover | — |

运行时状态（`/var/lib/sbox-cm`，root:root 0700）：

```text
/var/lib/sbox-cm/
├── management.active          0644  激活标记
├── degraded.json              0600  无法证明安全态时的降级标志
├── last_transaction.json      0600  最近一次事务（status 用）
├── ledger/cm-ledger.jsonl     0600  权威幂等账本
├── journal/<request_id>.json  0600  事务阶段日志（完成即删）
└── audit/cm.jsonl             0600  特权审计
```

## 3. 部署

```bash
# 部署文件与 units；默认 disabled + inactive（默认安全态）
sudo sbox-cm/deploy/install-sbox-cm.sh install

# 开启特权通道：只 enable --now sbox-cm.socket；
# service 由 socket activation 在第一个连接到达时拉起，不会被独立 enable
sudo sbox-cm/deploy/install-sbox-cm.sh enable

# 关闭特权通道（回滚次序固定）：
#   stop socket -> stop service -> disable socket -> disable service（仅当其确实 enabled）
sudo sbox-cm/deploy/install-sbox-cm.sh disable

# active_stale 恢复（唯一路径；不要手工 rm 标记文件）
sudo sbox-cm/deploy/install-sbox-cm.sh recover

# 只读状态（不触发 reconcile、不触发任何 repair）
sudo sbox-cm/deploy/install-sbox-cm.sh status
```

**启用模型（有意选择，非混用）**：`sbox-cm.socket` 是唯一受支持的激活路径，`enable` 只
enable socket；service unit 保留 `[Install]` 段，允许运维**显式**选择
`systemctl enable sbox-cm.service`（daemon 无论有无流量都常驻），部署脚本绝不替你做，
且 `disable` 在 service 恰好被 enable 过的情况下仍会把它停掉并 disable。

**reconcile 的唯一发生点**：daemon **startup**（`acquire config.lock → scan journal →
reconcile → … → unlock`，先于第一个请求被服务）。两条 status 都是**只读**：

```text
deploy CLI status          → 读 units/路径 + durable 的 degraded.json（绝不调 daemon）
RPC management.status      → 不取 config.lock、不读 live 配置、绝不 reconcile/repair；
                             只报告 management_state / degraded / reconcile /
                             lock.acquirable（非阻塞探测，瞬时释放）/ last_transaction
```

> socket 采用 **systemd socket activation**：路径、属主、模式、陈旧清理都由 PID 1 负责，
> 因此 service **不需要 `CAP_CHOWN`**。关闭时若只停 service，socket 会在下一次连接时
> 重新拉起它 —— 所以 `disable` 必须停止 socket 并 disable 它。

## 4. 协议

```text
AF_UNIX SOCK_STREAM，每连接恰好 1 request + 1 response
帧：[4 字节大端 uint32 L][L 字节 UTF-8 JSON]，0 < L ≤ 65536
版本：e3-rpc/1（未知版本/未知字段/未知 op 一律拒绝）
D-read：5 s（帧头收完后读满 payload 的上限）
```

非法帧（`L=0` / `L>65536` / 截断 / 非 UTF-8 / 非 JSON）→ **直接 close，不回错误帧**（不给协议 oracle），但仍写连接级审计。

七个 op（M4 起固定；再扩展须新一轮论证）：

| op | config.lock | degraded 时 | 需要 active |
| --- | --- | --- | --- |
| `management.status` | 否 | 可用 | 否 |
| `client.list` | 是（短持有） | 可用 | 否 |
| `management.activate` | 是 | 拒绝 | 否 |
| `management.deactivate` | 是 | 拒绝 | 否 |
| `client.add` | 是 | 拒绝 | 是 |
| `client.delete` | 是 | 拒绝 | 是 |
| `client.export` | 是（只读，短持有） | 拒绝 | 是 |

`client.list` 只返回 `name / protocols / reserved / mutable / source`（≤1000 条 + `truncated`），
**零 UUID、零 password、零私钥、零 YAML、零分享 URI**；`source` 只认正向证据，缺失即 `untracked`（绝不猜 `cli`）。

`client.export`（M4）是唯一允许返回凭据材料的**只读** op：与 CLI 共用同一把
`config.lock` 和同一个 canonical 渲染器 `cm_render_client_mihomo_yaml`
（字节级一致），锁内现场渲染、每次 dispatch 都重跑。它**不是事务**：无
`Idempotency-Key`（携带即拒绝）、无 ledger、无 journal、无 reload；前置条件
fail-closed（`E_NOT_FOUND` / `E_CONFIG_INCONSISTENT` / `E_ACTIVATION_STATE` /
`E_MANUAL_INTERVENTION`）；渲染结果超过 48 KiB 一律拒绝，且**先序列化、先证明
尺寸**：YAML 经管道交给 `jq -Rs` 得到最终 JSON 响应（只留在 shell 内存），按
UTF-8 字节度量到 `MAX_FRAME` 预算内才允许交付——超限一律 fail-closed、绝不截断，
且尺寸证明发生在成功审计**之前**（装不进帧的导出绝不会留下"凭据已交付"的审计）。
审计只记元数据；`client.export` 每次真实交付各写一条独立审计（见 §9）。
daemon 将其列入 `SENSITIVE_RESPONSE_OPS`：响应**永不读写
replay cache**，也不落任何日志。

## 5. 凭据卫生（M1-A）

```text
digest = SHA256(uuid + "\n" + password)      ← 唯一实现：cm_cred_digest_of
```

凭据**绝不跨越 privileged worker 信任边界**（唯一例外：M4 `client.export`
的一次性只读响应，见下）：

```text
不得进入：argv / env / stdout / stderr / journald / audit / journal / ledger /
          replay cache / client.list / error detail / 任何缓存或持久化的响应
          （Python daemon 只做帧转发：对 export 响应不落日志、不入 replay cache）
唯一 sanctioned 投递路径：worker 锁内渲染 → 私有 AF_UNIX socket 的一次性响应
          → sboxweb 进程内存 → loopback/SSH 隧道内的 HTTP 附件下载 → 用户本地文件
其余仅存在于：worker 进程树内存、匿名管道 / 私有 FD、live 服务端配置、
          root-only 账本中的不可逆 digest
```

`cm_plan_client_credential` 把生成的凭据留在 shell 内存；`cm_render_planned_candidate`
通过**匿名管道**把它们交给 `jq`（`jq` 只从 stdin 读凭据对象，argv 里只有路径与 name）。
CLI 的 `_add_client_locked` 也走同一条路径，因此 `jq --arg uuid` 在仓库中已不存在。

## 6. 事务次序与幂等

`client.add`（锁内）：

```text
live reread + 一致性审计 → 管理面激活检查 → 账本查询/调和
→ 生成 planned 凭据 → planned_cred_digest → durable intent（fsync 文件+目录）
→ 【mutation 边界：此后不可取消】→ 用同一组凭据生成 candidate
→ commit_server_config → derived/advisory → durable outcome → audit → unlock
```

核心不变量：**任何真正参与 mutation 的凭据计划，必须先有对应的 durable ledger intent。**
mutation 实际使用的凭据 ⇔ 已 fsync 的 `planned_cred_digest`。

`client.delete`：先账本、后 live 前置；锁内现算 `old_cred_digest`。重跑条件严格：

```text
name 不存在                                   → 期望状态已达成 → 补 outcome / replay
name 存在 && current == old_cred_digest       → supersede 后重跑 delete
name 存在 && current != old_cred_digest       → E_RECONCILE_CONFLICT（绝不删除当前对象）
```

（最后一条正是为了不误删"被重建的同名第二代客户端"。）

`request_id`（daemon 内存 10 min / 512 条，传输层降噪）与 `Idempotency-Key`
（root-only 账本，权威幂等，16–128 字符 `[A-Za-z0-9._:-]`）严格分开。

## 7. 持久性、调和与降级

```text
任何 durable state：write → fsync(file) → fsync(parent dir)
（覆盖 journal 的创建/更新/删除、ledger 的 intent/outcome、marker、降级标志）
```

启动调和（接受任何 mutation 之前，同一把 `config.lock` 下）：

```text
acquire lock → scan journal → reconcile → reload/health →（必要时 restore 回滚）
→ outcome → audit → clear journal → unlock
```

无法证明安全态（journal 损坏 / restore 失败 / health 仍失败）⇒ `degraded = true`：

```text
management.status ✅   client.list ✅
其余五个 op ❌ E_MANUAL_INTERVENTION
```

## 8. 取消语义

```text
durable intent 之前 → 可超时 / 断连 / 取消（零变更）
durable intent 之后 → 绝不中止：browser 断连、web 重启、RPC 断连、deadline 一律不杀 worker；
                     事务跑到 commit-or-rollback → health → durable outcome → audit
```

因此 daemon 里**没有** `communicate(timeout=...)`，也**没有** kill —— 120 s 只是调用方等待预算。
该契约由 `tests/e3/m1-rpc-probe.py` 的 AST 断言守（不是 grep）。

## 9. 审计 exactly-once

```text
未 dispatch worker（peer 拒绝 / 非法帧 / 超时 / schema 失败 / dispatch 失败）
    → RPC core 写一条连接级审计（source="rpc"）
已 dispatch worker
    → worker 写一条事务审计（source="worker"），RPC core 绝不再补第二条
audit_id = request_id + ":" + generation（mutation）
调和时：audit_id 已 durable 则不再追加，否则补一条
client.export 例外（敏感披露，逐次留痕）：audit_id 额外携带每次派发的
nonce 后缀，真实交付一次 = 审计一条；mutation 的 request_id:generation
exactly-once 语义原封不动。
```

## 10. 测试

```bash
bash tests/e3/test-m1-shared-lib.sh    # M1-A0/M1-A：canonical closure + 凭据卫生（含 jq argv 运行时断言）
bash tests/e3/test-m1-static.sh        # 单引擎 / 七 op / systemd 候选 / 无隐式激活
bash tests/e3/test-m1-worker.sh        # 七个 op、ledger、幂等、调和、degraded、回滚、锁失败、/proc 动态卫生
bash tests/e3/test-m4-renderer.sh      # canonical Mihomo 渲染器：与 CLI 字节级一致、纯度、fail-closed
bash tests/e3/test-m1-rpc.sh           # schema + AST 不变量 + frame + peer(含 uid 0) + replay（含 sensitive 旁路）
bash tests/e3/test-m1-deploy.sh        # install 不激活 / enable / disable 双停 / recover / uninstall
bash tests/e3/test-m0-shared-lib.sh    # M0 回归（pin 已随 M1-A0 更新）
bash tests/e3/test-m0-static-contract.sh
```

动态凭据卫生是**运行时采样**而非 grep：mock 生成器与 `jq` shim 在凭据真实存在于 worker 进程树的那一刻扫描
`/proc/*/cmdline` 与 `/proc/*/environ`，要求 sentinel 0 命中；`test-m1-shared-lib.sh` 另有一条「jq argv 不含凭据」断言。

Linux acceptance：`SKIP=0`。Windows 本地允许 `flock`/AF_UNIX/权限位相关项 SKIP，
但这些 SKIP **不构成 M1 acceptance**。

## 11. 非目标（本目录明确不做）

```text
Web RPC adapter / 真实 Web Add/Delete UI / type-to-confirm        → M2
client.rotate / client.get                                         → 未纳入（须新一轮论证）
client.export / Web 凭据下载（只读导出）                            → M4 已纳入（见 §4 表格与 §5 卫生契约）
生产 activation / VPS deployment / sing-box reload                → M3
```
