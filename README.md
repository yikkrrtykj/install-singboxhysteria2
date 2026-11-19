# Reality + Hysteria2 二合一 sing-box

本文是仓库当前唯一的部署与使用入口，覆盖 VPS 安装、客户端创建与管理、Monitor、Windows 客户端交付、双 VPS 离线配置合并、Linux Mihomo 网关和故障排查。各节的“正式 / 试验 / 未验收”状态按仓库当前代码与文档标注；设计背景、验收证据和操作细节以链接文档为准，不用 CI 结果或草稿合同代替业务验收。

## 1. VPS 安装

以 root 登录 VPS 后执行：

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/yikkrrtykj/install-singboxhysteria2/main/install.sh)
```

作用：安装 Reality + Hysteria2 服务端、systemd 服务与 `miaomiao` 管理命令。全新安装会自动启用并启动 `sing-box.service`，不使用手工进程；已有安装会进入管理菜单。

主机依赖（host dependency）：脚本先保证这些命令在本机可用——`qrencode`、`jq`、`iptables`，以及服务器 Monitor 的 journal 诊断激活所需的 `setfacl` / `getfacl`（package `acl`）与 `runuser`（package `util-linux`）。判定按“命令是否解析”而不是包名（`command -v acl` 证明不了任何事）；全部已满足时一次包管理器都不会调用，安装之后必须重新解析到命令才算成功，仍缺任一命令则带明确诊断中止，绝不假装成功、也不进入后续部署步骤。详见 [monitor-v2/deploy/README.md](monitor-v2/deploy/README.md) §21。

Hysteria2 新安装默认使用 BBR 拥塞控制：服务端启用 `ignore_client_bandwidth: true`，服务端和生成的 sing-box / Mihomo 客户端不再设置固定上下行带宽。BBR 不保证零丢包，也不是公网带宽限速或流量配额控制；需要硬限速或额度时应使用独立机制，不能把 HY2 带宽声明当作硬限速。GitHub 脚本更新不会自动修改旧服务器配置；兼容性、测试范围与手动备份/迁移/回滚步骤见 [HY2 BBR 说明](docs/hysteria2-bbr.md)。需要重新启用本机 BBR 与 Hysteria2 UDP 缓冲优化时，进入 `miaomiao` → `5. 启用本地 BBR + 优化 Hysteria2 UDP 缓冲`。

服务端生成的客户端文件：

```text
/root/sbox/mihomo_client.yaml
/root/sbox/sbconfig_client.json
```

两个文件都以 `0600` 写入，属于共享 `legacy` 账号的展示输出，不是逐客户端导出；多设备用法见第 2 节。

## 2. 客户端创建与管理

```bash
miaomiao
```

选择 `10. 客户端管理（多设备身份 / legacy 迁移 / 一致性检查）`：

| 选项 | 作用 |
| --- | --- |
| 1. 查看客户端 | 打印 `NAME / REALITY / HY2` 对照表；任一协议缺失会标出并给出一致性告警。 |
| 2. 添加客户端 | 输入客户端名称，原子地同时加入 Reality 与 HY2，并生成新的 UUID 和密码。 |
| 3. 生成客户端配置 | 校验一致性后，为指定客户端渲染并保存 Mihomo/Clash Meta YAML。 |
| 4. 删除客户端 | 从 Reality 与 HY2 同时删除凭据，并清理该客户端的派生配置目录。 |
| 5. 迁移旧客户端为 legacy | 只给没有 `name` 的旧共享用户补上 `name=legacy`；绝不更换 UUID/password。 |
| 6. 检查客户端一致性 | 完整身份审计：名称集合、重复项、空凭据、`flow` 等。 |

客户端名称须字母或数字开头，仅含字母、数字、`.`、`_`、`-`，长度 1–32；`legacy` 是保留名称，不能通过“添加客户端”创建，本版本也不允许删除。Reality 与 HY2 的用户集合不一致、存在重复名称或凭据、或缺少必要字段时，添加、生成、删除和 Phase D 升级都会被拒绝，应先修复一致性。

**逐客户端派生配置**：

```text
/root/sbox/clients/<name>/mihomo.yaml
```

目录权限 `0700`，文件权限 `0600`。内容完全由服务端配置 `/root/sbox/sbconfig_server.json` 派生，可由菜单重新生成；源配置始终是唯一事实源。删除客户端时会先撤销该客户端已登记设备的上传凭据（如果本机已部署 P6 管理面），撤销未确认则不改配置。

**配置修改走同一把锁**：添加、删除、迁移和 Phase D 升级等所有写入 `/root/sbox/sbconfig_server.json` 的操作都经过 `/root/sbox/config.lock`；flock 缺失、锁文件打不开或等待超时（默认 15s，可用 `SB_LOCK_TIMEOUT` 调整）都会直接中止，绝不无锁修改配置。生成客户端配置只做只读派生，不修改服务端配置。

**菜单 3 的共享账号只用于展示**：`3. 显示客户端配置和 Linux 安装命令` 展示并写出保留的共享 `legacy` 账号（两个入站的首个用户），用于查看 Reality/HY2 链接与二维码、复制 sing-box 客户端 JSON、获取 Linux 网关安装命令；`/root/sbox/mihomo_client.yaml` 不是某个独立客户端的逐设备导出。需要按设备隔离凭据时，使用菜单 10 的“生成客户端配置”，或在 Monitor 的客户端管理中下载逐客户端 `<name>-mihomo.yaml`。

## 3. Monitor 安装与使用

Monitor v2 是只读的事件监控与 Web Dashboard：通过本机 `service.api`（`127.0.0.1:9091`）读取 sing-box 事件，独立运行 `singbox-monitor.service`（非 root 用户），并默认只监听 `127.0.0.1:9191`。Monitor **不由 `install.sh` 安装**，部署入口是 `monitor-v2/deploy/install-monitor.sh`。

### 3.1 安装与首次配置

在 VPS 上准备一份本仓库的 checkout（示例路径 `/root/sbox-src`，可按需替换），在仓库根目录执行：

```bash
git clone https://github.com/yikkrrtykj/install-singboxhysteria2.git /root/sbox-src
cd /root/sbox-src
sudo bash monitor-v2/deploy/install-monitor.sh install
sudo bash monitor-v2/deploy/install-monitor.sh web-setup
```

`install` 是幂等收敛：没有已激活 release 时执行 fresh 安装，同版本重跑是 no-op，新版本升级会原子切换 release 且只重启 `singbox-monitor`，失败自动回滚；它不覆盖 `monitor.conf`、不重置认证/白名单/状态、不触碰 `/root/sbox`、不重启 sing-box。`web-setup` 以 `sboxweb` 身份交互设置管理口令与一次性 recovery key（可选白名单），不打印或记录这些秘密；若服务此前处于 active，成功时只重启 Monitor。

### 3.2 打开 Web

Monitor 默认只监听服务器回环地址 `127.0.0.1:9191`，不要把 9191 直接开放到公网。在自己的电脑建立 SSH 本地端口转发：

```bash
ssh -N -L 9191:127.0.0.1:9191 root@<VPS_IP>
```

SSH 不是默认 22 端口时加 `-p <SSH_PORT>`。保持该 SSH 会话打开，然后在本机浏览器访问：

```text
http://127.0.0.1:9191/
```

本机 9191 已被占用时可改用其他本地端口，例如 `-L 19191:127.0.0.1:9191`，再访问 `http://127.0.0.1:19191/`。部分 SSH 服务器会终止 `-N` 纯转发会话，可改用普通 shell 形式或加 keepalive；不要为此修改 `sshd_config`。经隧道访问时 Monitor 看到的对端是 loopback，不需要额外加白名单。

### 3.3 状态、健康、回滚与卸载

```bash
sudo bash monitor-v2/deploy/install-monitor.sh status
sudo bash monitor-v2/deploy/install-monitor.sh health
sudo bash monitor-v2/deploy/install-monitor.sh history
sudo bash monitor-v2/deploy/install-monitor.sh rollback            # 回滚到最近保留的非当前 release
sudo bash monitor-v2/deploy/install-monitor.sh rollback <release-id>
sudo bash monitor-v2/deploy/install-monitor.sh uninstall [--purge-state] [--purge-config] [--purge-backups]
```

`status` 输出 Monitor 版本、目录与 unit 状态；`health` 输出分离式健康 JSON（`overall` 只是汇总词，各字段单独可读；退出码 0 = healthy、1 = unhealthy、2 = degraded）。`rollback` 只重启 `singbox-monitor`，不触碰 sing-box；回滚失败会恢复原 release，不写成功历史。`uninstall` 默认保留 `/var/lib/singbox-monitor`、`/etc/singbox-monitor` 和 `/var/backups/singbox-monitor`，三个 `--purge-*` 分别清除对应目录；卸载不删除系统身份，也不删除 sing-box 配置或客户端凭据。

Monitor 的采集模型、Web 安全边界与当前已知限制见 [monitor-v2/README.md](monitor-v2/README.md)，安装语义、健康模型与回滚事务见 [monitor-v2/deploy/README.md](monitor-v2/deploy/README.md)；0.9.0 起的服务器状态/资源记录（独立存储、7 天保留、事件时段内展示）见 [服务器证据说明](docs/monitor-v2-host-evidence.md)。

## 4. Windows 客户端交付

本节的 P6Setup 是**可选的监控客户端**交付方式，用于需要 P6 设备监控、上传确认和后台服务的受控电脑。若只需要把 Clash/Mihomo 配置导入终端、不使用 P6 监控服务，可仅导入菜单 10 生成的逐客户端 `<name>-mihomo.yaml`（或 Monitor 客户端管理下载的逐客户端 YAML）到 Clash Verge Rev/Mihomo，不必安装 P6Setup；第 5 节的双 VPS 合并输出同样只是 Clash 配置，是否叠加 P6 监控客户端由终端用途决定。

当前流程基于 Monitor 的客户端管理（E3 管理面）：

1. 在 Monitor 的客户端管理中为每台电脑单独登记设备；同一客户端账号的不同电脑仍各有独立上传身份。
2. 设备登记确认后，点击“下载 Windows 客户端包”。
3. 完整解压 ZIP，保留同目录文件；将 `<client>-mihomo.yaml` 导入 Clash 并启用，本机 API 地址按配置要求设置。
4. 运行 `P6Setup.exe`（程序显示名“客户端管理”），核对自动识别的客户端和设备，再点击“安装 / 更新”。仅识别配置不会安装或启动服务。
5. 安装后可在程序中查看采样、上传确认、队列和后台服务状态；关闭窗口后后台服务继续运行。

客户端管理入口依赖已评审的 E3 特权执行面（`sbox-cm`）。该平面部署后默认关闭，启用 / 停用与生产 go-live 按 [sbox-cm/README.md](sbox-cm/README.md) 与 [E3 M3 部署 runbook](docs/e3-m3-deploy-runbook.md) 的独立步骤执行；`install.sh` 既不安装也不启用它。

下载包包含该设备的代理凭据和上传密钥，只供所选设备使用，请私密保管；`server.pem` 只用于 Monitor 客户端按固定证书验证连接，不导入系统证书库；它是 Monitor 链路信任材料，不是 HY2 服务端身份证明。规范 HY2 导出仍使用 legacy `skip-cert-verify: true`，HY2 服务端身份验证（证书链/固定 pinning 等）属 HA-03 范围，当前不声称已验证。标注为受控测试的 `lab` 包不能用于正式发布。Windows 客户端面向公司受控设备内部发行，固定内部签名身份、首次受控信任与签名策略见 [Code signing policy](docs/p6b2-free-signing.md)；生产包的发布要求见第 8 节，完整交付说明见 [Windows 客户端包](docs/windows-client-package.md)。

## 5. 双 VPS 双活配置生成

双 VPS 配置由操作员在本地离线生成。先在 VPS A、B 上用同一逻辑客户端名分别创建客户端并各自持有独立凭据，再从两台 VPS 的 Monitor 客户端管理分别下载该客户端的规范导出 `<name>-mihomo.yaml`。

在操作员电脑（Python 3.10+，仅用标准库）执行：

```bash
python3 tools/mihomo-multi-vps-merge.py \
  --name <name> \
  --primary .../A/<name>-mihomo.yaml \
  --backup  .../B/<name>-mihomo.yaml \
  --output  .../<name>-ha.yaml
```

成功时只打印 `merge: OK` / `mode: dual` / `output: written`。输出包含四个节点：`Reality`、`Hysteria2`、`Backup-Reality`、`Backup-Hysteria2`；主 VPS 的两个节点在前，备 VPS 的节点加 `Backup-` 前缀，`proxy-groups` 沿用 #42 的 `select` + `fallback` 结构与 60s / 5000ms 探测策略。输入必须是本仓库生成的规范导出；工具会校验文件名与 `--name` 一致、两个输入使用不同服务器、凭据互不复用；输出已存在时拒绝覆盖（没有 `--force`），正常输出在 POSIX 上为 `0600`。

该流程完全离线、operator-local：只打开两个输入和一个输出；VPS A 不连接 VPS B，不同步服务端配置，不共享 UUID/密码，也没有中心数据库。生成结果只是客户端拓扑，不证明两台 VPS 分属不同运营商、ASN 或机房，也不代表业务级 HA。

详细规则与验证方式见 [PR-48A 文档](docs/mihomo-multi-vps-failover-p48a.md)。竞赛用双 VPS 双活 HA 的 **HA-01 合同文档已合并入 main**（PR #95，merge `f69d9976609b`），但真实 HA 运行时/应用/机群验收仍为 **NOT ACCEPTED、默认 OFF**；其合同与验收门见 [HA 合同](docs/mihomo-competition-ha-contract.md) 和 [HA 验收](docs/mihomo-competition-ha-acceptance.md)，当前边界见第 8 节。

## 6. Linux Mihomo 网关

Mihomo 网关把另一台 Linux 主机变成 TUN 透明网关，Mihomo 只安装在网关主机上；安装器会拒绝在代理服务端本机安装。支持 Ubuntu 22.04/24.04、Debian 12、amd64/arm64、systemd 和 `/dev/net/tun`。

### 6.1 从服务端生成安装命令

在服务端执行 `miaomiao` → `3. 显示客户端配置和 Linux 安装命令`，菜单末尾会输出三条命令：先把本次节点配置写入 `/tmp/mihomo_client.yaml`（base64 解码并 `chmod 600`），再下载安装器，最后安装 Mihomo、启用 TUN 网关并开放局域网 9090 UI。命令 1 由菜单直接生成（内容较长，照抄即可）；命令 2 是：

```bash
curl -fsSL -o /tmp/install-linux-gateway.sh https://raw.githubusercontent.com/yikkrrtykj/install-singboxhysteria2/main/install-linux-gateway.sh && chmod 700 /tmp/install-linux-gateway.sh
```

命令 3 是：

```bash
if [ "$(id -u)" -eq 0 ]; then bash /tmp/install-linux-gateway.sh --config /tmp/mihomo_client.yaml --ui-lan --yes; else sudo bash /tmp/install-linux-gateway.sh --config /tmp/mihomo_client.yaml --ui-lan --yes; fi
```

安装器会检查 `53/7897/9090` 端口（systemd-resolved 占用 53 除外），安装 Mihomo 和 MetaCubeXD，生成随机 UI 密钥，并在失败时自动恢复。`--ui-lan` 让 9090 监听局域网；不加该参数时默认只监听 `127.0.0.1`。只向可信内网开放 DNS `53`、代理 `7897` 和管理面板 `9090`，不要暴露到公网。菜单 3 输出的配置属于共享 `legacy` 账号；需要逐设备身份时，先在服务端客户端管理中生成独立导出再用于网关。

### 6.2 网关常用命令

```bash
cat /etc/mihomo/ui-secret
```

作用：查看 9090 Web UI 密钥。UI 地址为 `http://<Linux网关IP>:9090/ui/`，只从可信局域网打开。

```bash
/usr/local/bin/mihomo -t -d /etc/mihomo
```

作用：检查 Mihomo 配置，成功后再重启。

```bash
systemctl restart mihomo
systemctl status mihomo --no-pager
journalctl -u mihomo -n 100 --no-pager
ss -lntup | grep mihomo
```

作用：重启、查看状态、查看最近日志和监听端口。

### 6.3 其他 Linux 服务器接入同一台网关

只向可信内网开放 DNS `53`、代理 `7897` 和管理面板 `9090`。按新服务器的用途选择接入方式：

- **应用显式代理**：应用支持 HTTP 代理时配置 `http://<网关IP>:7897`，服务器继续使用原有网关和 DNS；用 `curl -q -4 -fsS --noproxy '' --max-time 10 --proxy http://<网关IP>:7897 https://api.ipify.org` 验证代理路径与公网出口。
- **同网段透明接入**：把新服务器的 IPv4 默认网关和 DNS 都指向 Mihomo，同时单独保留跨网段管理流量的回程路由；确认网关开启 IPv4 转发、与新服务器同二层网段，并接受客户端 DNS 查询。
- **跨 VLAN 透明接入**：在三层网关为指定源地址配置策略路由，确认下一跳可达并验证回程；客户端继续使用本 VLAN 的网关。

修改前先在现有 SSH 会话中检查管理端回程；以下地址均为示例，按现场地址、掩码和网卡名替换：

```bash
ip -4 route get <Mihomo网关IP>
ip -4 route get <管理端IP>
```

单网卡、单 IPv4 默认路由、由 `systemd-resolved` 管理 DNS 时，可先做临时接入（改动立即生效，重启或网络重配后可能恢复）：

```bash
IFACE=<网卡名>
MIHOMO_IP=<Mihomo网关IP>
OLD_GATEWAY=<原网关IP>
SSH_CLIENT_IP=<SSH管理端源地址>

sudo ip -4 route replace "$SSH_CLIENT_IP/32" via "$OLD_GATEWAY" dev "$IFACE" &&
sudo resolvectl dns "$IFACE" "$MIHOMO_IP" &&
sudo ip -4 route replace default via "$MIHOMO_IP" dev "$IFACE"
```

三条命令依次保留 SSH 回程、设置接口 DNS、切换 IPv4 默认网关。执行后必须新开一个 SSH 会话确认仍可登录，并检查默认路由、管理回程、系统 DNS 和**透明** HTTPS 出口。

透明出口验证必须显式绕过继承的代理设置，并另用实际业务 URL 验证一次：

```bash
curl -q -4 -fsS --noproxy '*' --max-time 10 https://api.ipify.org
echo
```

```bash
ip -4 route get "$SSH_CLIENT_IP"
ip -4 route get 1.1.1.1
resolvectl dns "$IFACE"
```

持久化以 Ubuntu Netplan + 静态 IPv4 为例：备份现有 Netplan 文件，只替换该接口原有的 IPv4 默认路由与 DNS，保留其他地址和业务路由；为确认过的管理端保留一条回程路由。用 `sudo netplan generate && sudo netplan try --timeout 120` 试应用；只有在试用窗口内**新开 SSH 会话确认仍可登录**、默认路由/管理回程/系统 DNS 正确，且透明 `curl` 与实际业务 URL 验证通过后才确认；试用失败时从控制台恢复备份。恢复网关安装前配置使用 `mihomo-gateway-installer --restore /var/backups/mihomo-gateway/<备份目录名>`。

```yaml
network:
  version: 2
  renderer: networkd
  ethernets:
    <网卡名>:
      dhcp4: false
      addresses:
        - <新服务器地址>/24
      routes:
        - to: default
          via: <Mihomo网关IP>
        - to: <管理端IP>/32
          via: <原网关IP>
      nameservers:
        addresses:
          - <Mihomo网关IP>
```

### 6.4 接入排查

- **显式代理可用、透明访问超时**：先用 `getent ahostsv4 <域名>` 查客户端解析结果，再用 `ip -4 route get <解析地址> ipproto tcp dport 443` 核对下一跳；策略路由要为业务和 Fake-IP 网段一起规划通往 Mihomo 的路径。
- **应用要求 DNS 返回真实公网地址**：Mihomo 默认的 IPv4 Fake-IP 范围为 `198.18.0.0/16`（以网关当前配置为准）；在 `dns.fake-ip-filter` 中排除对应域名。返回 `SERVFAIL` 时检查网关的上游解析，必要时用 `dns.nameserver-policy` 为这些域名指定解析器。
- **查出口 IP 正常、Ping 超时**：Ping 使用 ICMP；只匹配 TCP/443 的策略路由无法验证 ICMP、UDP 或 IPv6 的出口。本节的示例按 IPv4 配置，IPv6 出口需单独验证。
- **DNS 和连接日志**：在客户端查询实际业务域名，在网关用 `journalctl -u mihomo -n 50 --no-pager` 对照时间、匹配规则和出口节点。

## 7. 故障排查与回滚

### 7.1 服务端检查与日志

```bash
/root/sbox/sing-box check -c /root/sbox/sbconfig_server.json
systemctl status sing-box --no-pager
journalctl -u sing-box -n 100 --no-pager
jq '.inbounds[] | {tag, listen_port}' /root/sbox/sbconfig_server.json
```

作用：检查服务端配置、查看 systemd 状态、最近 100 行日志和 Reality/HY2 监听端口。配置检查通过后再执行 `systemctl restart sing-box`。`miaomiao` → `4. sing-box基础操作` 也提供“检查现有配置，成功后重启”、服务状态、实时日志和完整配置查看（完整配置包含 UUID、密码和私钥，不要公开）。`service.api` 只监听 `127.0.0.1:9091`，不向公网开放。

### 7.2 安全基线与认证

安装器对敏感文件显式收紧权限（不依赖系统默认 umask）：`/root/sbox/sbconfig_server.json`、`/root/sbox/config`、`/root/sbox/monitor-api.secret`、`/root/sbox/self-cert/private.key`、`/root/sbox/mihomo_client.yaml`、`/root/sbox/sbconfig_client.json` 与客户端 `clients/<name>/mihomo.yaml` 为 `0600`；`clients/` 及其子目录为 `0700`；自签公钥 `cert.pem` 为 `0644`；事务生成的配置备份同样以 `0600` 写入。老服务器重跑安装器时先做一次幂等的权限修复，任何 `chmod` 失败都会终止安装（fail-closed）。

monitor-api 认证 secret：`sbconfig_server.json` 中 `monitor-api` 的 `secret` 是唯一事实来源；`/root/sbox/monitor-api.secret` 是给本机 collector 使用的受控派生文件（root:root `0600`）。两者不一致时以配置为准重新生成派生文件（有 warning，但不打印 secret）；已配置的非空 secret 在重跑/升级时永不轮换。升级后建议手动执行一次认证金丝雀：

```bash
bash tests/canary-api-auth.sh --with-collector
```

验证：无凭据/错误凭据必须被拒绝（Unauthenticated），正确凭据可调用，collector 可用 `monitor-api.secret` 建立 SubscribeConnections 流。配置锁：添加/删除客户端与 Phase D 升级都经过 `/root/sbox/config.lock`，flock 缺失、锁文件打不开或等待超时都会中止（默认 15s，`SB_LOCK_TIMEOUT` 可调）。

### 7.3 Phase D 升级的备份与回滚

`miaomiao` → `4. sing-box基础操作` → `2. 升级 sing-box 内核（Phase D: 1.14.x + 本机 service.api）`。升级在配置锁内依次执行身份/API/配置审计、candidate `sing-box check`、binary + config 成对 `0600` 备份、原子替换、重启、Reality/HY2/localhost `service.api` 健康检查；替换后的任一步失败会自动双回滚（binary + config）并再次验证，替换前的候选检查失败不会修改正式环境。升级输出会打印两份备份路径（形如 `/root/sbox/sing-box.bak.<时间戳>.*` 与 `/root/sbox/sbconfig_server.json.bak.<时间戳>.*`），请保留到确认稳定之后。

需要人工回滚时必须同时恢复 binary 与 config、重启并验证；只替换 config 会造成 binary/config 混搭。旧服务器若仍有无名的共享账号，先 `10. 客户端管理` → `5. 迁移旧客户端为 legacy` 再升级。BBR 相关的备份、迁移与手动回滚步骤见 [HY2 BBR 说明](docs/hysteria2-bbr.md)。

### 7.4 Monitor 与 Linux 网关回滚

Monitor 健康与回滚：

```bash
sudo bash monitor-v2/deploy/install-monitor.sh health
sudo bash monitor-v2/deploy/install-monitor.sh rollback <release-id>
```

回滚只重启 `singbox-monitor`，不触碰 sing-box；回滚失败会恢复原 release，不会声称成功。健康 JSON 的字段语义与部署事务见 [monitor-v2/deploy/README.md](monitor-v2/deploy/README.md)。

Linux 网关恢复：

```bash
ls -1 /var/backups/mihomo-gateway/
sudo mihomo-gateway-installer --restore /var/backups/mihomo-gateway/<备份目录名>
```

作用：查看安装器创建的备份，并恢复安装前的 Mihomo、systemd、DNS 和网络配置；恢复后按 6.2 的命令重新检查配置与 systemd 状态。不要照抄示例目录名，使用安装时实际打印的备份目录。

## 8. 正式功能与试验功能

| 功能 | 当前状态 | 入口与边界 |
| --- | --- | --- |
| VPS 服务端安装与 `miaomiao` 客户端管理 | 正式当前路径 | `install.sh`；第 1–2 节 |
| Monitor Web / 事件监控 | 正式部署路径；E3 客户端管理面默认关闭 | [monitor-v2/deploy/README.md](monitor-v2/deploy/README.md)；第 3 节 |
| Windows P6 客户端包 | 正式包要求 production scope + 内部时间戳发布者；`lab` 包仅受控测试 | [内部发行流程](docs/p6b2-internal-release.md)、[p6_distribution.py](monitor-v2/p6_distribution.py) |
| Linux Mihomo 网关 | 产品功能（独立网关主机）；竞赛 HA 验收中 deferred | `install-linux-gateway.sh`；[HA 合同](docs/mihomo-competition-ha-contract.md) |
| Windows 质量切换 EXE | 独立、opt-in 试验，不是 P6 监控服务的一部分 | [质量切换说明](docs/mihomo-quality-windows.md) |
| 竞赛双 VPS 双活 HA | HA-01 合同已合并；真实运行时/应用验收 **NOT ACCEPTED、默认 OFF** | [HA 合同](docs/mihomo-competition-ha-contract.md)、[HA 验收](docs/mihomo-competition-ha-acceptance.md) |

正式 Windows 包：生产包必须由内部固定发布者签署并带时间戳，发布时由操作员显式提供 `scope=production`；[`monitor-v2/p6_distribution.py`](monitor-v2/p6_distribution.py) 校验 `p6-windows-distribution/1` 清单，生产 scope 要求 `timestamped=true`、`installation=P6RemoteProbe`，发布者指纹必须匹配。root 发布入口是 `tools/publish-p6-windows.py`（部署时安装到受控 libexec）。内部签名身份的创建/复用、首次受控信任与普通更新见 [内部发行流程](docs/p6b2-internal-release.md)，签名策略与数据边界见 [Code signing policy](docs/p6b2-free-signing.md)。`lab` 包会明确标注为受控测试，不能自动变成正式包（仅保留显式过渡流程）。

Windows 质量切换 EXE：`docs/mihomo-quality-windows.md` 所述的 `质量切换.exe` 是独立便携程序，按接收方显式操作启用，不安装服务，不改 TUN、自启动、Clash 配置或系统证书信任；现有 9191 的 P6 Windows 下载不包含它。它属于 opt-in 试验，构建、签名和接收方工作流见 [质量切换说明](docs/mihomo-quality-windows.md)；多用户 rollout 仍需单独的并发容量验收，不能由打包本身推定。

竞赛双 VPS 双活 HA：HA-01 合同文档已合并入 main（PR #95，merge `f69d9976609b`），但真实 HA 运行时/应用/机群验收仍为 **NOT ACCEPTED；all new competition features default OFF**，验收文档明确 **No competition runtime/application/fleet PASS claimed**，冻结验收要求未改变。第 5 节的合并工具只生成客户端拓扑，不声称 10s 故障恢复、10s 业务恢复、应用验收或机群验收；文档合并、CI 绿灯、204 响应或绿色节点都不等于真实应用验收。Linux Mihomo 网关是产品功能，但在竞赛交付中 deferred、不纳入该验收；`srt-cam` 与 Haivision SRT Tools 超出范围。

## License / Code signing policy

本项目自有代码采用 [MIT License](LICENSE)；第三方软件及代码保留其原有许可证和版权声明，不因本项目采用 MIT 而改变。

Windows 客户端面向公司受控设备内部发行，采用固定内部签名身份和首次受控信任配置；签名私钥仅由管理员控制的发布环境持有，不进入服务器、客户端包或设备配置，VPS TLS 信任与 Windows 代码签名信任相互独立。发布状态与边界见 [Code signing policy](docs/p6b2-free-signing.md)。
