# Reality + Hysteria2 二合一 sing-box

本仓库的推荐分工：

- 代理服务端使用 sing-box，同时提供 Reality 和 Hysteria2；
- Linux 透明代理网关使用 Mihomo，并提供 9090 MetaCubeXD Web UI；
- Windows 使用支持 Mihomo/Clash Meta 的图形客户端，直接导入 YAML；
- 不建议在同一台 Linux 网关上同时运行 Mihomo 和 sing-box 客户端。

## 一、安装 sing-box 服务端

建议在全新 Ubuntu/Debian 服务器的 `root` 会话中执行：

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/yikkrrtykj/install-singboxhysteria2/main/install.sh)
```

如果下载 GitHub 必须经过代理，先设置环境变量；下面的地址只有在服务器能够访问该局域网代理时才可使用：

```bash
export HTTP_PROXY=http://192.168.16.18:7897
export HTTPS_PROXY=http://192.168.16.18:7897
export http_proxy="$HTTP_PROXY"
export https_proxy="$HTTPS_PROXY"
```

安装时根据提示设置 Reality 和 Hysteria2 端口，并在云防火墙中放行：

- Reality 的 TCP 端口；
- Hysteria2 的 UDP 端口；
- 启用 Hysteria2 端口跳跃时，还要放行完整的 UDP 跳跃范围。

新安装的 Hysteria2 服务端上下行上限是 `1000/1000 Mbps`，生成的客户端参数是 `300/300 Mbps`。这些值是协议带宽参数，不代表线路一定能够达到该速度。

安装结束后会生成两个客户端文件：

```text
/root/sbox/mihomo_client.yaml      # Windows Mihomo/Clash Meta、Linux Mihomo 网关
/root/sbox/sbconfig_client.json    # 需要 sing-box 客户端时使用
```

两个文件都包含节点密码和密钥，权限会设为 `0600`。不要上传到公开 URL、网盘或聊天群。

以后需要重新生成客户端文件时执行：

```bash
mianyang
```

然后选择“显示客户端配置”。

## 二、服务端修改后怎样重启

先检查配置，成功后再重启服务：

```bash
/root/sbox/sing-box check -c /root/sbox/sbconfig_server.json
systemctl restart sing-box
systemctl status sing-box --no-pager
```

查看最近日志：

```bash
journalctl -u sing-box -n 100 --no-pager
```

也可以进入 `mianyang` 菜单，选择 sing-box 基础操作中的重启功能。脚本会先检查配置，并避免同时启动 systemd 和手工运行的两个实例。

查看 Reality/Hysteria2 实际监听端口：

```bash
jq '.inbounds[] | {tag, listen_port}' /root/sbox/sbconfig_server.json
```

查看 Hysteria2 服务端带宽参数：

```bash
jq '.inbounds[] | select(.tag == "hy2-in") | {up_mbps, down_mbps}' \
  /root/sbox/sbconfig_server.json
```

## 三、Windows 客户端

安装支持 Mihomo/Clash Meta 的 Windows 图形客户端，导入服务端生成的 `/root/sbox/mihomo_client.yaml` 即可。Windows 不需要运行下面的 Linux 网关脚本。

默认节点组优先使用 Reality，也可以在客户端中手工切换到 Hysteria2 或自动测速组。

## 四、从零安装 Linux Mihomo 代理网关

### 适用环境

推荐使用一台专门的全新 Linux 机器：

- Ubuntu 22.04/24.04 或 Debian 12；
- amd64 或 arm64；
- systemd 正常运行；
- `/dev/net/tun` 可用；
- 不要安装在 sing-box 代理服务端本机。

安装器会接管这台机器的路由和 DNS。远程操作时请保留第二个 SSH 会话或服务器控制台，确认网关正常后再关闭。

### 第 1 步：从服务端复制 Mihomo 配置

在 Linux 网关上执行，把 `<服务端IP>` 换成真实地址：

```bash
scp root@<服务端IP>:/root/sbox/mihomo_client.yaml /tmp/mihomo_client.yaml
chmod 600 /tmp/mihomo_client.yaml
```

### 第 2 步：下载安装器

```bash
curl -fsSL -o /tmp/install-linux-gateway.sh \
  https://raw.githubusercontent.com/yikkrrtykj/install-singboxhysteria2/main/install-linux-gateway.sh
chmod 700 /tmp/install-linux-gateway.sh
```

需要使用 `192.168.16.18:7897` 下载时，先执行：

```bash
export HTTP_PROXY=http://192.168.16.18:7897
export HTTPS_PROXY=http://192.168.16.18:7897
export http_proxy="$HTTP_PROXY"
export https_proxy="$HTTPS_PROXY"
```

安装器和它启动的下载命令都会使用这些代理环境变量；Mihomo 的 systemd 服务本身不会写入这个临时下载代理，避免形成自代理循环。

### 第 3 步：安装并启动

如果 9090 只需要通过本机或 SSH 隧道访问，使用安全默认值：

```bash
sudo bash /tmp/install-linux-gateway.sh \
  --config /tmp/mihomo_client.yaml \
  --yes
```

如果这台网关位于可信局域网，需要从局域网浏览器直接打开 9090：

```bash
sudo bash /tmp/install-linux-gateway.sh \
  --config /tmp/mihomo_client.yaml \
  --ui-lan \
  --yes
```

不要对公网放行 9090。安装器不会自动修改 UFW、云防火墙或路由器端口映射。

安装器会完成以下工作：

- 从 MetaCubeX 官方 GitHub 正式版下载当前最新 Mihomo；
- 从 MetaCubeX 官方正式版下载 MetaCubeXD 静态 UI；
- 预先下载 MetaCubeX 官方 `geoip.metadb`，避免首次启动时临时直连下载；
- 使用 GitHub 提供的 SHA-256 摘要校验所有发布资源；
- 检查 systemd、TUN、CPU 架构、现有进程和 `53/7897/9090` 端口；
- 检查服务端生成的 YAML，再生成带随机 API 密钥的最终配置；
- 配置 TUN、自动路由、DNS 劫持和 Linux IP 转发；
- 安装并启用 `mihomo.service`；
- 覆盖已有 Mihomo 前先备份，启动或健康检查失败时自动恢复。

它不会执行第三方仓库中的可变安装脚本，也不会自动安装或替换 sing-box 服务端。

### 第 4 步：打开 9090 Web UI

查看随机生成的 UI 密钥：

```bash
sudo cat /etc/mihomo/ui-secret
```

使用 `--ui-lan` 安装后，在可信局域网浏览器打开：

```text
http://<Linux网关的局域网IP>:9090/ui/
```

如果没有使用 `--ui-lan`，在自己的电脑上建立 SSH 隧道：

```bash
ssh -N -L 9090:127.0.0.1:9090 <用户名>@<Linux网关IP>
```

保持 SSH 窗口运行，再打开 `http://127.0.0.1:9090/ui/`。如果 UI 要求填写控制器，填写当前打开的主机和 `9090` 端口，并输入 `/etc/mihomo/ui-secret` 中的密钥。

### 第 5 步：让局域网设备使用这台网关

在需要代理的局域网设备上设置：

- 默认网关：Linux 网关的局域网 IP；
- DNS：Linux 网关的局域网 IP。

安装器使用的端口如下：

| 端口 | 用途 | 建议访问范围 |
| --- | --- | --- |
| TCP/UDP 53 | Mihomo DNS | 可信局域网 |
| TCP/UDP 7897 | HTTP/SOCKS 混合代理 | 可信局域网 |
| TCP 9090 | API 和 MetaCubeXD UI | 本机、SSH 隧道或可信局域网 |

防火墙只应允许你的内网网段访问这些端口，不能直接暴露到公网。

如果 UFW 已启用，可以把下面的网段换成自己的可信局域网后放行：

```bash
lan_cidr='192.168.16.0/24'
ufw allow from "$lan_cidr" to any port 53 proto tcp
ufw allow from "$lan_cidr" to any port 53 proto udp
ufw allow from "$lan_cidr" to any port 7897 proto tcp
ufw allow from "$lan_cidr" to any port 7897 proto udp
ufw allow from "$lan_cidr" to any port 9090 proto tcp
```

## 五、Linux 网关日常维护

检查配置：

```bash
/usr/local/bin/mihomo -t -d /etc/mihomo
```

检查成功后重新加载配置：

```bash
systemctl reload mihomo
```

更新二进制、UI 或 systemd 配置后使用完整重启：

```bash
systemctl restart mihomo
systemctl status mihomo --no-pager
```

查看日志和监听端口：

```bash
journalctl -u mihomo -n 100 --no-pager
ss -lntup | grep mihomo
```

节点发生变化后，在服务端重新生成并复制 `/root/sbox/mihomo_client.yaml`，再运行一次安装器。安装器会保留原来的 9090 密钥，先备份现状和检查新配置，再更新服务。

安装器每次会把可恢复备份放在：

```text
/var/backups/mihomo-gateway/
```

安装完成时会打印本次备份的准确目录。恢复命令示例：

```bash
sudo mihomo-gateway-installer --restore \
  /var/backups/mihomo-gateway/<安装器打印的目录名>
```

恢复会还原安装前的 Mihomo 二进制、配置、systemd 服务、DNS 和网络参数，并恢复原服务的启用/运行状态。系统软件源安装的基础工具不会卸载。

确认安装稳定后，可以删除 `/tmp/mihomo_client.yaml` 和下载到 `/tmp` 的安装器副本；正式配置和恢复工具已经安装到系统目录。

如果机器原来已经运行 Mihomo，安装器会先备份 `/etc/mihomo`、原二进制、systemd 单元及 `mihomo.service.d` 覆盖配置，然后使用本仓库管理的新单元。已有的自定义 systemd 覆盖不会自动带入新服务，避免旧的自代理环境变量或 `ExecStart` 修改破坏新网关；确实需要时应在安装成功后逐项人工合并。

## 六、常见检查

查看系统、TUN 和服务：

```bash
cat /etc/os-release
uname -m
test -c /dev/net/tun && echo 'TUN 可用' || echo 'TUN 不可用'
systemctl status mihomo --no-pager
```

测试 9090 API（密钥不会出现在命令历史的参数中）：

```bash
secret="$(sudo cat /etc/mihomo/ui-secret)"
curl -H "Authorization: Bearer $secret" http://127.0.0.1:9090/version
unset secret
```

测试本机通过 7897 代理访问：

```bash
curl --proxy http://127.0.0.1:7897 \
  --connect-timeout 10 --max-time 30 \
  https://www.gstatic.com/generate_204 -I
```

服务启动失败时，不要反复覆盖配置，先查看：

```bash
/usr/local/bin/mihomo -t -d /etc/mihomo
journalctl -u mihomo -n 200 --no-pager
ss -lntup | grep -E ':53|:7897|:9090'
```
