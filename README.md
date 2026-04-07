一键安装
```
bash <(curl -fsSL https://raw.githubusercontent.com/yikkrrtykj/install-singboxhysteria2/main/install.sh)
```
----------------------
读取底层配置文件端口
```
cat /root/sbox/sbconfig_server.json | grep listen_port
```
---------------------
如无法访问google

1、拉取并运行 WARP 部署脚本13
```
wget -N https://gitlab.com/fscarmen/warp/-/raw/main/menu.sh && bash menu.sh
```
2、验证隧道连通性
```
curl -x socks5h://127.0.0.1:40000 -I https://www.google.com
```
3、修改 Sing-box 路由与出站配置
在 "outbounds" 数组的最前端，追加一个名为 warp-socks 的 SOCKS5 协议出站接口。
修改后的 "outbounds" 结构示例：
```
"outbounds": [
    {
      "type": "socks",
      "tag": "warp-socks",
      "server": "127.0.0.1",
      "server_port": 40000
    },
    {
      "type": "direct",
      "tag": "direct",
      "domain_resolver": {
        "server": "dns-local",
        "strategy": "ipv4_only"
      }
    }
    // ... 维持原有其他出站配置不变 ...
  ]
```
4、添加策略路由规则
在 "route" 的 "rules" 数组中，追加一条针对 Google 域名的匹配规则，确保该规则的优先级高于默认的全局直连策略。
修改后的 "route" 结构示例：
```
"route": {
    "rules": [
      {
        "action": "sniff"
      },
      {
        "network": "udp",
        "port": 443,
        "action": "reject"
      },
      {
        "domain_suffix": [
          "google.com",
          "google.com.hk",
          "googleapis.com",
          "gstatic.com"
        ],
        "outbound": "warp-socks"
      }
      // ... 维持原有其他匹配规则不变 ...
    ]
  },
```
5、服务重启与状态确认
```
/root/sbox/sing-box check -c /root/sbox/sbconfig_server.json
systemctl restart sing-box
```
