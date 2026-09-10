# Proxy Monitor

`install.sh` 会在 Reality/Hysteria2 安装成功后自动确保独立监控服务 `sbox-monitor` 存在。它与比赛网络监控完全无关，不安装 Grafana、Prometheus 或数据库，也不会修改代理路由策略。

## 查看

安装结束会打印随机访问 URL。之后可运行：

```bash
sbox-monitor url
sbox-monitor status
sbox-monitor logs
sbox-monitor restart
sbox-monitor update
```

默认监听 TCP `9191`。脚本不会自动开放 UFW 或云安全组；如果需要公网直接打开页面，请只允许你的管理公网 IP 访问该端口。

## 当前能看到什么

- sing-box 是否运行、Reality/Hysteria2 监听端口、HY2 端口跳跃状态
- VPS CPU、RAM、load、uptime、默认出口网卡实时 RX/TX
- VPS 到 `1.1.1.1` / `8.8.8.8` 的周期 ICMP 探测
- Reality 活动客户端公网源 IP、TCP 会话数、**实际 TCP RTT**、最大 RTT、当前上传/下载速率、重传计数
- Hysteria2 活动公网源 IP和当前上传/下载速率（依赖 conntrack accounting）
- 浏览器内保留约 10 分钟趋势：服务器 RX/TX、Reality 最大 RTT

## 为什么暂时按源 IP 显示客户端

当前安装器给所有 Reality 设备使用同一个 UUID，也给所有 Hysteria2 设备使用同一个密码，因此服务端无法从认证信息判断 `vMix-01`、`vMix-02`。第一版按公网源 IP / 会话聚合。

如果多个客户端位于同一个 NAT 后面，它们会合并成一个源 IP。要精确到设备名，需要下一步让安装器给每个客户端生成独立凭据或在客户端运行轻量 agent。

## RTT 说明

Reality 基于 TCP 时，Linux `ss -i` 能直接读取正在承载 Reality 流量的 TCP socket RTT，因此面板显示的是实际业务连接 RTT，而不是服务器反向 ping 客户端。

Hysteria2 使用 QUIC/UDP，Linux TCP socket 没有它的 QUIC RTT。第一版明确显示 `QUIC / N.A.`，不会用不可靠的“服务器 ping NAT 客户端”冒充真实 HY2 RTT。
