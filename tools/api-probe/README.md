# Phase A - sing-box 官方 API 可行性探针（`tools/api-probe/`）

## 这是什么 / 不是什么

**是**：一个**手动运行**的开发/诊断工具，用来回答一个具体问题——sing-box 的官方 API 能否为 Reality / Hysteria2 提供
`source IP`、`inbound user`、`connection` 粒度、`upload` / `download` 这些监控数据。

**不是**：

- **不是**正式安装功能。`install.sh` 不会调用它，它也不会被安装到任何服务器上。
- **不属于 Monitor v2**。它不采集产线数据、不常驻、不随安装器部署。
- **不会自动安装到用户服务器**。只能由人主动复制到 VPS 并手动执行。
- **不代表任何结论**。在没有真实运行结果之前，它的输出只能是 `NOT TESTED / WAITING FOR RUNTIME DATA`。

### 它服务的目标

用于决定 **Monitor v2 是否采用 sing-box API**：如果 API 能提供 `user` / `source IP` / `connection` / `upload` / `download`，
那么监控的数据面就可以从 `ss` + `conntrack` 换成对 sing-box 自身 API 的只读查询。

### 与 `ss` / `conntrack` 的关系（重要）

- API 能被**非 root** 读取，只能证明两件事：业务监控的**字节数据源可以降权**，以及**可以去掉 `conntrack` 和 `nf_conntrack_acct`**。
- **如果将来仍然需要 Reality 的 TCP RTT / retrans，`ss` 继续作为只读辅助数据源保留**。不要因为 API 可用就提前删除 `ss`。
- `conntrack` / `nf_conntrack_acct` 是否删除，要**等 Phase A 实测结果**出来再决定，本工具不做这个决定。

---

## 安全边界（硬性约束，并由 `tests/selftest.sh` 静态检查）

| 约束 | 实现方式 |
|---|---|
| 只写 `/root/sbox-probe/` | 所有产物都在 `PROBE_ROOT` 下，可用 `--probe-root` 覆盖但必须在 `/root/` 下 |
| 不修改 `/root/sbox/config`、`sbconfig_server.json`、生产二进制 | 代码里没有任何写入生产路径的操作；lint 会拦截 `> $PROD_*`、`sed -i` |
| 不 stop / restart / disable / enable `sing-box.service` | 代码里不存在该命令；lint 会拦截 `systemctl <verb> ... sing-box` |
| 不写生产 iptables / nftables | 代码里不存在相关命令；lint 会拦截 |
| 不开启 Port Hopping | 探针配置不含 `HY_HOPPING`，也不创建任何跳端口规则 |
| 不可能误杀生产进程 | 只对 `/proc/<pid>/cmdline` **命中 `PROBE_ROOT`** 且**不是生产 `MainPID`** 的 pid 发信号；库里不存在 `pkill`/`killall` |
| 不创建 systemd unit | 探针是普通独立进程（`setsid`/`nohup`），因此不会开机自启 |
| Clash API 只监听 `127.0.0.1` | 探针配置固定 `external_controller: 127.0.0.1:<port>` + 随机 secret |
| 不读生产密钥/证书 | 探针用独立生成的 Reality keypair / short_id / 自签证书（30 天，仅探针用） |

默认 `prepare`/`run` 时探针 inbound **只绑定 `127.0.0.1`**；要测外部客户端的公网源 IP 必须显式加 `--expose`（此时会临时监听两个额外端口）。

---

## 依赖

- root 权限
- `curl`、`ss`（iproute2）、`python3`（仅用标准库）、`openssl`、`od`（coreutils）
- 目标机器上已用本仓库安装器装好的 `/root/sbox/sing-box`（工具只执行它的 `version` / `generate` / `check` / `run` 子命令）

`prepare` 会一次性报告所有缺失依赖。

---

## 流程

```bash
# 1) 只生成配置并检查，不启动任何进程
bash phase-a-probe.sh prepare

# 2) 启动独立探针 + 一次性客户端与 sink，跑本机测试矩阵，采集 evidence 并分析，结束后停止探针自有进程
bash phase-a-probe.sh run

# 3)（可选）需要外部客户端测试时：保留探针运行
bash phase-a-probe.sh run --keep --expose
#    外部设备上执行完测试后，再补一次采集
bash phase-a-probe.sh collect --label reality-external

# 4) 查看状态
bash phase-a-probe.sh status

# 5) 结束：只停止探针自有进程并删除 PROBE_ROOT
bash phase-a-probe.sh cleanup
```

### 端口（都可用参数覆盖）

| 用途 | 默认 | 说明 |
|---|---|---|
| probe Reality inbound | `18443` | 独立端口 |
| probe Hysteria2 inbound | `18444` | 独立端口 |
| Clash API | `127.0.0.1:19090` | 仅回环 |
| 本机 sink（已知大小流量） | `127.0.0.1:18080` | 仅回环 |
| 一次性客户端 socks | `18081/18082/18083/18084` | 每个 (用户 × 协议) 一个，避免路由歧义 |

`prepare` 会先检查这些端口是否空闲；被占用直接报错退出。

---

## 测试矩阵

每个协议（Reality / Hysteria2）都跑三轮，`PAYLOAD_BYTES` 默认 64 MiB，`--rate` 默认 4 MiB/s（都按字节/秒给出，不依赖 curl 的速率后缀语义）：

1. **方向测试 - 下载**：单个具名用户，客户端**接收**已知大小数据（单向），前后各取快照
2. **方向测试 - 上传**：单个具名用户，客户端**发送**已知大小数据（单向），前后各取快照
3. **归因测试**：`probe-a` 与 `probe-b` 并发，各一半数据量，中途取快照
4. 传输结束后再取一次快照，用于判断连接关闭行为

流量终点是**本机回环 sink**（`lib/sink.py`），测试负载不离开这台机器。

---

## evidence 目录

```
/root/sbox-probe/evidence/
├── meta.json                     本次采集的期望值（版本、端口、用户、tag、字节数）
├── 00-production-before.txt      生产基线：版本 / 服务状态 / 三个 sha256 / HY_HOPPING
├── 00-api-version.json           GET /version 原始响应
├── 05-probe-check.txt            sing-box check 的输出
├── <proto>-dl-pre|mid|post.connections.json     方向测试前后的原始 /connections
├── <proto>-ul-pre|mid|post.connections.json
├── <proto>-ab-pre|mid|post.connections.json     归因测试
├── <proto>-final.connections.json               关闭后
├── <label>.traffic.json / <label>.memory.json   /traffic、/memory 原始响应
├── <label>.keys.txt              该快照的 root / connection / 嵌套 keys 全量枚举
├── 90-production-after.txt       生产基线（复采样，用于证明未被改动）
├── analysis.json                 机器可读结论
├── report.md                     人读报告
└── SUMMARY.txt                   终端汇总表
```

`collect --label X` 生成的 `X.connections.json` 会被分析器自动纳入（用于折入外部客户端的公网源 IP 证据）。

---

## 判定是机械的，不是硬编码的

`lib/analyze.py` 不假设任何字段名的“人类含义”：

- **user 字段名**：扫描 `metadata` 与 connection 顶层的所有键，找出**取值恰好等于 `probe-a` / `probe-b`** 的那个键；找不到就输出 `NO`，并把检查过的字段与连接数写进证据。
- **upload / download 方向**：用**已知大小的单向流量**实测。哪个计数器的增量 ≈ 已知字节数，它就是“朝客户端方向”的计数器；再据此给出
  `语义=客户端下行(服务器->客户端)` / `语义=客户端上行(客户端->服务器)`，并判断**字段命名与客户端视角一致还是相反**（相反时提示渲染必须对调）。
  两个方向如果命中的是同一个计数器，直接判 `INCONCLUSIVE`。
- **inbound**：找一个取值等于该 inbound tag 的字段，同时兼容 `tag` 与 `type/tag` 两种形状。
- **source IP**：找 IP 形态的取值，优先 `source` 前缀的键；只有回环地址时判 `PARTIAL` 并明确写出“公网源 IP 未验证”。
- **连接粒度 / 关闭行为**：按 tag 过滤后数连接数，比较 mid / post 快照里的连接 id。

状态取值：`VERIFIED`（机械验证通过）、`PARTIAL`（部分验证，含明确缺口）、`NO`（机械否证）、`INCONCLUSIVE`（数据不足以判定）、
`FAILED`（仅用于生产基线漂移）、`NOT TESTED / WAITING FOR RUNTIME DATA`（没有运行时数据）。

`tests/selftest.sh` 会用**合成 fixture** 验证这套推导逻辑（包括故意把计数器命名反过来的变体，必须被识别为“相反”），
合成数据带 `_fixture` 标记，分析器在未加 `--fixture-mode` 时**一律忽略**它们。

---

## 如何从结果走到 Monitor v2 决策

| 实测结果 | 对 Monitor v2 的含义 |
|---|---|
| Reality 与 HY2 都有 user 归因（YES） | 可按**设备**归因，不再依赖源 IP；但需要“每设备独立凭据”作为前置 |
| Reality YES / HY2 NO | Reality 按 user，HY2 回退源 IP（或每设备独立端口），面板必须标注两种口径 |
| 都 NO | 只能按源 IP 聚合，与现状同级，需重新评估是否值得做 v2 |
| source IP 正确 + 方向语义明确 | 具备替换 `conntrack` 的字节数据源条件 |
| API 可非 root 读取 | 字节数据源可降权；但**`ss` 仍保留**做 Reality RTT/retrans |
| 同一 NAT 后 user 仍可区分 | 赛事多机场景可行；否则必须先落“每设备凭据” |

---

## 外部客户端测试（可选，`--expose`）

`run --keep --expose` 会写出外部客户端配置（`client-*-external.json`，server 用 `--public-ip` 或只读读取生产 `SERVER_IP`），
并打印外部设备上要执行的命令。需要覆盖两种场景：

1. **两个不同公网出口**的客户端 → 验证 `source IP` 真的是客户端公网 IP
2. **同一个 NAT 后两个不同具名用户** → 验证源 IP 合并时 `user` 是否仍能区分设备

测完在服务器上执行 `collect --label <场景名>`，再 `cleanup`。注意 `--expose` 期间这两个端口对外可达，测完请关闭安全组/防火墙放行。

---

## 自检

```bash
bash tests/selftest.sh
```

包含：`bash -n`、`python3 -m py_compile`、**guardrail lint**（断言脚本里不存在 `pkill`/`killall`、`systemctl <verb> ... sing-box`、
`iptables`/`nft`/`ufw`、`rm -rf .../root/sbox`、`sed -i`、写生产路径）、以及分析器在“空证据 / 合成证据 / 反向命名”三种输入下的行为。
有 `shellcheck` 时会额外跑 `shellcheck -S warning`。

---

## 仍需在真实 VPS 上验证的项目（本仓库无法证明）

1. `sing-box 1.14.x`（以及你实际运行的版本）下 `/connections` 是否包含 `metadata.sourceIP`、inbound 标识、user 字段与逐连接计数
2. **HY2 是否有 inbound user 归因**（本工具最重要的一项，必须给出 YES / NO，不能推测）
3. `upload` / `download` 的真实方向语义
4. 1.14 对现有生产配置的兼容性（`sing-box check` 是否通过、有无 deprecated 警告）
5. 高连接数、开启/关闭端口跳跃时的行为
6. 探针配置里 `up_mbps` / `down_mbps`、`users[].name`、`utls` 等字段在目标版本上是否被接受（`check` 会先拦住）

未通过真实运行之前，本文档与工具都**不主张**任何 API 能力结论。

---

## 故障排查

| 现象 | 处理 |
|---|---|
| `sing-box check` 失败 | 看 `evidence/05-probe-check.txt`；检查目标版本是否接受探针配置里的字段（如 `up_mbps`/`down_mbps`） |
| Clash API 20 秒未就绪 | 看 `/root/sbox-probe/probe.log`；确认端口未被占用、secret 文件存在 |
| 端口被占用 | 用 `--reality-port/--hy2-port/--clash-port/--sink-port` 换端口，或先 `cleanup` 残留探针 |
| 连接数为 0 | 确认客户端 socks 已监听、sink 已启动；看 `*-curl.txt` 里的 `http_code` |
| 报告里大量 `NOT TESTED` | 说明没有取到运行时数据（快照缺失/API 请求失败），按上面的条目排查后重跑 |
| `status` 显示 `stale/foreign pid` | pidfile 与真实进程不一致（通常进程已退出），`cleanup` 会清理 pidfile |
