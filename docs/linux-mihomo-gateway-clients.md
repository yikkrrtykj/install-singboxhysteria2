# Linux 服务器接入共享 Mihomo TUN 网关

按 [Linux 网关安装步骤](../README.md#6-从零安装-linux-mihomo-网关) 部署一台 Mihomo 网关。其余服务器通过应用代理或路由接入，共用网关上的节点和规则。Mihomo 网关使用自己的上游默认路由。

| 新服务器的用途 | 接入方式 |
| --- | --- |
| 应用支持 HTTP 代理，只需指定应用经网关出网 | 为该应用配置 Mihomo 的 mixed-port，服务器继续使用原有网关和 DNS。 |
| 同网段的服务器需要透明接入，应用直接建立外网连接 | 将服务器的 IPv4 默认网关和 DNS 都指向 Mihomo，单独保留跨网段管理流量的回程路由。 |
| 服务器和 Mihomo 分属不同 VLAN，需要透明接入 | 在三层网关为指定源地址配置策略路由，确认下一跳可达并验证回程。客户端继续使用本 VLAN 的网关。 |

## 应用显式代理

假设 Mihomo 网关地址为 `10.70.10.2`，且 mixed-port `7897` 已对客户端所在的可信内网开放。支持 HTTP 代理的应用可以配置 `http://10.70.10.2:7897`。从客户端测试代理和这一次请求的公网出口。

```bash
curl -q -4 -fsS --noproxy '' --max-time 10 \
  --proxy http://10.70.10.2:7897 https://api.ipify.org
echo
```

如果该请求命中代理规则，返回值应为所选节点的公网出口。也用实际业务 URL 检查一次。

## 同网段服务器透明接入

本例使用 Ubuntu 的 Netplan 和静态 IPv4。按现场地址和掩码替换示例值。

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

## 排查接入问题

- **显式代理可用，透明访问超时。** 先用 `getent ahostsv4 <域名>` 查客户端解析结果，再用 `ip -4 route get <解析地址> ipproto tcp dport 443` 核对下一跳。若用策略路由保留旧默认网关，要为相应业务和 Fake-IP 网段一起规划通往 Mihomo 的路径。仓库默认的 IPv4 Fake-IP 配置在 `198.18.0.0/16` 内，以网关当前配置为准。
- **应用要求 DNS 返回真实公网地址。** 在 Mihomo 的 `dns.fake-ip-filter` 中排除对应域名。若返回 `SERVFAIL`，检查网关的上游解析，必要时用 `dns.nameserver-policy` 为这些域名指定可用的解析器。
- **查出口 IP 正常，Ping 超时。** Ping 使用 ICMP。只匹配 TCP/443 的策略路由无法验证 ICMP、UDP 或 IPv6 的出口。本页的路由示例按 IPv4 配置，IPv6 出口需要单独验收。
- **DNS 和连接日志。** 在客户端查询实际业务域名，在网关用 `journalctl -u mihomo -n 50 --no-pager` 对照时间、匹配规则和出口节点。

[Netplan 试应用](https://netplan.readthedocs.io/en/stable/netplan-try/) · [Mihomo TUN 配置](https://wiki.metacubex.one/en/config/inbound/tun/) · [Mihomo DNS 配置](https://wiki.metacubex.one/en/config/dns/)
