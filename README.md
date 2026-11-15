# Reality + Hysteria2 二合一 sing-box

## 1. 安装服务端

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/yikkrrtykj/install-singboxhysteria2/main/install.sh)
```

作用：安装 Reality + Hysteria2 服务端、systemd 服务和 `miaomiao` 管理命令。全新安装会自动启用并启动 `sing-box.service`，不使用手工进程。

主机依赖（host dependency）：脚本先保证这些命令在本机可用——`qrencode`、`jq`、`iptables`，以及服务器 Monitor 的 journal 诊断激活所需的 `setfacl` / `getfacl`（package `acl`）与 `runuser`（package `util-linux`）。判定按"命令是否解析"而不是包名（`command -v acl` 证明不了任何事）；全部已满足时一次包管理器都不会调用，安装之后必须重新解析到命令才算成功，仍缺任一命令则带明确诊断中止，绝不假装成功、也不进入后续部署步骤。详见 `monitor-v2/deploy/README.md` §21。

Hysteria2 新安装默认使用 **BBR 拥塞控制**：服务端启用 `ignore_client_bandwidth: true`，服务端和生成的 sing-box / Mihomo 客户端不再设置固定上下行带宽。

BBR 不保证零丢包，也不是公网带宽限速或流量配额控制。需要硬限速或额度时应使用独立机制，不能把 HY2 带宽声明当作硬限速。GitHub 脚本更新不会自动修改旧服务器配置。兼容性、测试范围和手动备份/迁移/回滚步骤见 [HY2 BBR 说明](docs/hysteria2-bbr.md)。

服务端生成的客户端文件：

```text
/root/sbox/mihomo_client.yaml
/root/sbox/sbconfig_client.json
```

## 2. 打开管理菜单

```bash
miaomiao
```

作用：修改服务端配置、显示客户端配置、重启或更新 sing-box、启用 BBR、管理端口跳跃和中转规则。

本仓库使用独立命令 `miaomiao`，Personal 仓库使用 `xun`。旧服务器重新运行本仓库安装脚本后，会创建 `/root/sbox/miaomiao.sh` 和 `/usr/bin/miaomiao`，并仅清理确认指向本仓库的标准旧 `mianyang` 入口；其他来源或自定义的旧入口会保留。两版仍共享配置和服务，不支持靠改名在同机并行部署。

选择 `3. 显示客户端配置和 Linux 安装命令` 后会显示：

- Reality 和 Hysteria2 链接；
- Windows Mihomo/Clash Meta 配置；
- sing-box JSON 配置；
- 可直接复制到 Linux 客户端执行的 3 条安装命令。

把菜单 3 最后显示的命令 1～3依次复制到 Linux 客户端执行即可。

## 3. 服务端检查和重启

```bash
/root/sbox/sing-box check -c /root/sbox/sbconfig_server.json
```

作用：检查服务端配置，成功后才能重启。

```bash
miaomiao
```

作用：进入 `4. sing-box基础操作`。子菜单功能：

1. 检查现有配置，成功后重启 systemd 服务；
2. 安全升级到最新 stable 1.14.x：升级前执行身份/API/配置审计；binary + config 成对备份；重启后验证 Reality、HY2、localhost service.api；失败自动双回滚；
3. 查看 `sing-box.service` 是否正在运行；
4. 持续查看实时日志，按 `Ctrl+C` 退出；
5. 查看完整服务端配置，输出包含 UUID、密码和私钥，不要公开。

`service.api` 仅监听 `127.0.0.1:9091`，不向公网开放。

```bash
systemctl status sing-box --no-pager
```

作用：查看服务状态和启动方式。

```bash
journalctl -u sing-box -n 100 --no-pager
```

作用：查看最近 100 行服务日志。

```bash
jq '.inbounds[] | {tag, listen_port}' /root/sbox/sbconfig_server.json
```

作用：查看 Reality 和 Hysteria2 监听端口。

```bash
jq '.inbounds[] | select(.tag == "hy2-in") | {ignore_client_bandwidth, has_up_mbps:has("up_mbps"), has_down_mbps:has("down_mbps")}' /root/sbox/sbconfig_server.json
```

作用：检查 HY2 协商设置及带宽字段是否存在；旧部署可能仍保留旧带宽声明。

确认状态显示“启动方式: systemd”后，也可以直接执行：

```bash
systemctl restart sing-box
```

作用：直接重启 systemd 管理的 sing-box。

## 3.1 打开服务器 Monitor Web

Monitor Web 只通过服务器本机 `127.0.0.1:9191` 提供访问，不要把 9191 直接开放到公网。

在自己的电脑（Windows PowerShell、Windows Terminal、macOS/Linux 终端均可）建立 SSH 本地端口转发：

```bash
ssh -N -L 9191:127.0.0.1:9191 root@<VPS_IP>
```

如果 SSH 不是默认 22 端口：

```bash
ssh -p <SSH_PORT> -N -L 9191:127.0.0.1:9191 root@<VPS_IP>
```

保持这个 SSH 窗口打开，然后在本机浏览器访问：

```text
http://127.0.0.1:9191/
```

按 `Ctrl+C` 关闭 SSH tunnel。

如果本机的 9191 端口已被占用，可以改用其他本地端口，例如：

```bash
ssh -N -L 19191:127.0.0.1:9191 root@<VPS_IP>
```

然后访问：

```text
http://127.0.0.1:19191/
```

## 3.2 安全基线（S0）

本分支对凭据与 API 边界做了基线加固：

**敏感文件权限**：安装器对以下文件显式执行 `chmod 0600`（不再依赖系统默认 umask）：

- `/root/sbox/sbconfig_server.json`（服务端配置，凭据事实来源）
- `/root/sbox/config`（状态文件）
- `/root/sbox/self-cert/private.key`（自签私钥；`cert.pem` 保持 0644）
- `/root/sbox/monitor-api.secret`（见下）
- 所有 `sbconfig_server.json.bak.*` 备份、客户端 `clients/<名称>/`（目录 0700，`mihomo.yaml` 0600）

老服务器重跑安装器菜单时会先做一次幂等的权限修复；任何 `chmod` 失败都会终止安装（fail-closed）。

**monitor-api 认证 secret**：本机 `service.api`（127.0.0.1:9091）强制 Bearer 认证：

- `sbconfig_server.json` 中 `monitor-api` 的 `secret` 是唯一事实来源；
- `/root/sbox/monitor-api.secret` 是给本机 collector 使用的受控派生文件（root:root，0600）；
- 两者不一致时以配置为准重新生成派生文件（有 warning，但不打印 secret）；
- 已配置的非空 secret 在重跑/升级时永不轮换；老服务器升级到 1.14 时自动补齐 secret（candidate → check → 备份 → 原子替换 → reload → 健康检查，失败自动回滚）。

**认证金丝雀**（升级后建议手动执行一次）：

```bash
bash tests/canary-api-auth.sh --with-collector
```

验证：无凭据/错误凭据必须被拒绝（Unauthenticated），正确凭据可调用，collector 可用 `monitor-api.secret` 建立 SubscribeConnections 流。

**配置锁 fail-closed**：所有配置修改（添加/删除客户端、Phase D 升级）都经过 `/root/sbox/config.lock`；flock 缺失、锁文件打不开或等待超时（默认 15s，可用 `SB_LOCK_TIMEOUT` 调整）都会直接中止，绝不无锁修改配置。删除客户端在锁内也会重新校验名称合法性（`../x`、`a/b` 等一律拒绝）。

## 4. 网络优化

```bash
miaomiao
```

作用：选择菜单 5，启用内核支持的 BBR 和 `fq`，并把 Hysteria2/QUIC UDP 收发缓冲上限提高到至少 16 MiB。配置保存在 `/etc/sysctl.d/99-sing-box-network.conf`，不依赖第三方优化脚本，也不需要更新客户端配置。

## 5. Windows 客户端

```bash
miaomiao
```

作用：选择菜单 3，把显示的 Mihomo/Clash Meta YAML 导入 Windows 客户端。默认选择 Reality，也可以切换到 Hysteria2。

## 6. 从零安装 Linux Mihomo 网关

先在服务端执行：

```bash
miaomiao
```

作用：选择菜单 3，在输出末尾取得当前节点专用的 Linux 客户端命令。

把输出的命令 1～3 依次复制到用作网关的 Linux 主机。各命令的作用如下。

1. 写入 `/tmp/mihomo_client.yaml`；
2. 下载 `install-linux-gateway.sh`；
3. 安装 Mihomo、启用 TUN 网关并开放局域网 9090 UI。

支持：Ubuntu 22.04/24.04、Debian 12、amd64/arm64、systemd、`/dev/net/tun`。

安装器会检查 `53/7897/9090` 端口，安装 Mihomo 和 MetaCubeXD，生成随机 UI 密钥，并在失败时自动恢复。

## 7. Linux 网关常用命令

```bash
cat /etc/mihomo/ui-secret
```

作用：查看 9090 Web UI 密钥。

```text
http://<Linux网关IP>:9090/ui/
```

作用：从可信局域网打开 MetaCubeXD。

```bash
/usr/local/bin/mihomo -t -d /etc/mihomo
```

作用：检查 Mihomo 配置。

```bash
systemctl restart mihomo
```

作用：重启 Linux 网关代理。

```bash
systemctl status mihomo --no-pager
```

作用：查看 Mihomo 状态。

```bash
journalctl -u mihomo -n 100 --no-pager
```

作用：查看 Mihomo 最近 100 行日志。

```bash
ss -lntup | grep mihomo
```

作用：查看 Mihomo 监听端口。

### 其他 Linux 服务器接入同一台 Mihomo 网关

Mihomo 只安装在网关主机上，网关保留自己的上游默认路由。其他服务器按下表接入。只向可信内网开放 DNS `53`、代理 `7897` 和管理面板 `9090`。

| 新服务器的用途 | 接入方式 |
| --- | --- |
| 应用支持 HTTP 代理，只需指定应用经网关出网 | 为该应用配置 Mihomo 的 mixed-port，服务器继续使用原有网关和 DNS。 |
| 同网段的服务器需要透明接入，应用直接建立外网连接 | 将服务器的 IPv4 默认网关和 DNS 都指向 Mihomo，单独保留跨网段管理流量的回程路由。 |
| 服务器和 Mihomo 分属不同 VLAN，需要透明接入 | 在三层网关为指定源地址配置策略路由，确认下一跳可达并验证回程。客户端继续使用本 VLAN 的网关。 |

#### 应用显式代理

假设 Mihomo 网关地址为 `10.70.10.2`，且 mixed-port `7897` 已对客户端所在的可信内网开放。支持 HTTP 代理的应用可以配置 `http://10.70.10.2:7897`。从客户端测试代理和这一次请求的公网出口。

```bash
curl -q -4 -fsS --noproxy '' --max-time 10 \
  --proxy http://10.70.10.2:7897 https://api.ipify.org
echo
```

如果该请求命中代理规则，返回值应为所选节点的公网出口。也用实际业务 URL 检查一次。

#### 同网段服务器透明接入

按现场地址、掩码和网卡名替换示例值。

| 项目 | 示例 |
| --- | --- |
| 客户端 | `10.70.10.20/24`，网卡 `ens160` |
| Mihomo 网关及 DNS | `10.70.10.2` |
| 原网关 | `10.70.10.1` |
| 跨网段 SSH 管理端 | `10.70.99.10` |

修改前确认 Mihomo 网关和客户端位于同一二层网段，网关开启 IPv4 转发并接受来自客户端的 DNS 查询。在现有 SSH 会话里检查管理端的回程。若旧回程经原网关，把对应管理地址或实际管理网段的路由和新默认路由一起配置。

```bash
ip -4 route get 10.70.10.2
ip -4 route get 10.70.99.10
```

##### 临时接入

新服务器使用单网卡、单 IPv4 默认路由，并由 `systemd-resolved` 处理系统 DNS 时，可以直接运行下面的命令。按上表替换变量。`SSH_CLIENT_IP` 填当前 SSH 管理端在服务器看来使用的源地址，`/32` 只保留这个地址经原网关的回程。确认管理回程和网卡后，在新服务器上执行。

```bash
IFACE=ens160
MIHOMO_IP=10.70.10.2
OLD_GATEWAY=10.70.10.1
SSH_CLIENT_IP=10.70.99.10

sudo ip -4 route replace "$SSH_CLIENT_IP/32" via "$OLD_GATEWAY" dev "$IFACE" &&
sudo resolvectl dns "$IFACE" "$MIHOMO_IP" &&
sudo ip -4 route replace default via "$MIHOMO_IP" dev "$IFACE"
```

三条命令依次保留 SSH 回程、设置接口 DNS、切换 IPv4 默认网关。执行后新开一个 SSH 会话，确认可登录，再验证实际业务访问。

```bash
ip -4 route get "$SSH_CLIENT_IP"
ip -4 route get 1.1.1.1
resolvectl dns "$IFACE"
```

预期管理端回程经原网关 `10.70.10.1`，公网目的地址的下一跳和接口 DNS 均为 `10.70.10.2`。这些改动立即生效，重启或网络重新配置后可能恢复原设置。

##### 持久化接入

下面以 Ubuntu 的 Netplan 和静态 IPv4 为例。

备份现有 Netplan 文件，再修改客户端现有网卡配置。保留该接口的其他地址和业务路由，替换原有的 IPv4 默认路由与 DNS。本例给一个固定的管理端保留 `/32` 回程。实际由多个管理地址连接时，使用确认过的管理网段。

```yaml
network:
  version: 2
  renderer: networkd
  ethernets:
    ens160:
      dhcp4: false
      addresses:
        - 10.70.10.20/24
      routes:
        - to: default
          via: 10.70.10.2
        - to: 10.70.99.10/32
          via: 10.70.10.1
      nameservers:
        addresses:
          - 10.70.10.2
```

从控制台或保留着的 SSH 会话试应用。

```bash
sudo netplan generate && sudo netplan try --timeout 120
```

在试用窗口内新开一个 SSH 会话，再检查默认路由、管理回程、系统 DNS 和 HTTPS 出口。

```bash
ip -4 route show default
ip -4 route get 10.70.99.10
getent ahostsv4 api.ipify.org
curl -q -4 -fsS --noproxy '*' --max-time 10 https://api.ipify.org
echo
```

预期默认路由经 `10.70.10.2`，管理回程经 `10.70.10.1`。确认实际业务 URL 可访问、新 SSH 会话正常后，再回到试用窗口确认。试用失败时从控制台检查地址、默认路由和 DNS 是否已恢复，并按需恢复备份的 Netplan 文件。

#### 排查接入问题

- **显式代理可用，透明访问超时。** 先用 `getent ahostsv4 <域名>` 查客户端解析结果，再用 `ip -4 route get <解析地址> ipproto tcp dport 443` 核对下一跳。若用策略路由保留旧默认网关，要为相应业务和 Fake-IP 网段一起规划通往 Mihomo 的路径。仓库默认的 IPv4 Fake-IP 配置在 `198.18.0.0/16` 内，以网关当前配置为准。
- **应用要求 DNS 返回真实公网地址。** 在 Mihomo 的 `dns.fake-ip-filter` 中排除对应域名。若返回 `SERVFAIL`，检查网关的上游解析，必要时用 `dns.nameserver-policy` 为这些域名指定可用的解析器。
- **查出口 IP 正常，Ping 超时。** Ping 使用 ICMP。只匹配 TCP/443 的策略路由无法验证 ICMP、UDP 或 IPv6 的出口。本页的路由示例按 IPv4 配置，IPv6 出口需要单独验收。
- **DNS 和连接日志。** 在客户端查询实际业务域名，在网关用 `journalctl -u mihomo -n 50 --no-pager` 对照时间、匹配规则和出口节点。

[Netplan 试应用](https://netplan.readthedocs.io/en/stable/netplan-try/) · [Mihomo TUN 配置](https://wiki.metacubex.one/en/config/inbound/tun/) · [Mihomo DNS 配置](https://wiki.metacubex.one/en/config/dns/)

## 8. Linux 网关恢复

```bash
ls -1 /var/backups/mihomo-gateway/
```

作用：查看安装器创建的备份。

```bash
mihomo-gateway-installer --restore /var/backups/mihomo-gateway/<备份目录名>
```

作用：恢复安装前的 Mihomo、systemd、DNS 和网络配置。

## License / Code signing policy

本项目自有代码采用 [MIT License](LICENSE)。第三方软件及代码保留其原有许可证和版权声明，不因本项目采用 MIT 而改变。

Windows 客户端面向公司受控设备内部发行，无需申请公众代码签名服务。采用固定内部签名身份和首次受控信任配置的方向；发布状态及边界见 [Code signing policy](docs/p6b2-free-signing.md)。内部正式发布流程仍待实现和验收。
