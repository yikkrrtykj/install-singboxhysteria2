# Reality + Hysteria2 二合一 sing-box

## 1. 安装服务端

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/yikkrrtykj/install-singboxhysteria2/main/install.sh)
```

作用：安装 Reality + Hysteria2 服务端、systemd 服务和 `mianyang` 管理命令。全新安装会自动启用并启动 `sing-box.service`，不使用手工进程。

主机依赖（host dependency）：脚本先保证这些命令在本机可用——`qrencode`、`jq`、`iptables`，以及服务器 Monitor 的 journal 诊断激活所需的 `setfacl` / `getfacl`（package `acl`）与 `runuser`（package `util-linux`）。判定按"命令是否解析"而不是包名（`command -v acl` 证明不了任何事）；全部已满足时一次包管理器都不会调用，安装之后必须重新解析到命令才算成功，仍缺任一命令则带明确诊断中止，绝不假装成功、也不进入后续部署步骤。详见 `monitor-v2/deploy/README.md` §21。

默认带宽参数：

- Hysteria2 服务端：`1000/1000 Mbps`
- Hysteria2 客户端：`300/300 Mbps`

服务端生成的客户端文件：

```text
/root/sbox/mihomo_client.yaml
/root/sbox/sbconfig_client.json
```

## 2. 打开管理菜单

```bash
mianyang
```

作用：修改服务端配置、显示客户端配置、重启或更新 sing-box、启用 BBR、管理端口跳跃和中转规则。

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
mianyang
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
jq '.inbounds[] | select(.tag == "hy2-in") | {up_mbps, down_mbps}' /root/sbox/sbconfig_server.json
```

作用：查看 Hysteria2 服务端带宽参数。

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
mianyang
```

作用：选择菜单 5，启用内核支持的 BBR 和 `fq`，并把 Hysteria2/QUIC UDP 收发缓冲上限提高到至少 16 MiB。配置保存在 `/etc/sysctl.d/99-sing-box-network.conf`，不依赖第三方优化脚本，也不需要更新客户端配置。

## 5. Windows 客户端

```bash
mianyang
```

作用：选择菜单 3，把显示的 Mihomo/Clash Meta YAML 导入 Windows 客户端。默认选择 Reality，也可以切换到 Hysteria2。

## 6. 从零安装 Linux Mihomo 网关

先在服务端执行：

```bash
mianyang
```

作用：选择菜单 3，在输出末尾取得当前节点专用的 Linux 客户端命令。

然后把输出的命令 1～3依次复制到全新 Linux 客户端。它们的作用分别是：

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

局域网设备需要设置：

- 默认网关：Linux 网关 IP；
- DNS：Linux 网关 IP。

不要把 `53/7897/9090` 直接开放到公网。

## 8. Linux 网关恢复

```bash
ls -1 /var/backups/mihomo-gateway/
```

作用：查看安装器创建的备份。

```bash
mihomo-gateway-installer --restore /var/backups/mihomo-gateway/<备份目录名>
```

作用：恢复安装前的 Mihomo、systemd、DNS 和网络配置。
