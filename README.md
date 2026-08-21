# Reality + Hysteria2 二合一 sing-box

## 1. 安装服务端

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/yikkrrtykj/install-singboxhysteria2/main/install.sh)
```

作用：安装 Reality + Hysteria2 服务端、systemd 服务和 `mianyang` 管理命令。

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

作用：修改服务端配置、显示客户端配置、重启或更新 sing-box、启用 BBR、管理端口跳跃。

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

作用：选择 `4. sing-box基础操作`，再选择 `1. 重启sing-box`；脚本会先检查配置，并阻止手工进程与 systemd 双开。

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

## 4. 把手工进程迁移到 systemd

```bash
mianyang
```

作用：选择 `4. sing-box基础操作`，再选择 `6. 将手工进程迁移到 systemd`。

迁移前会检查配置并要求输入 `MIGRATE`，迁移失败时会尝试恢复手工运行方式。

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
