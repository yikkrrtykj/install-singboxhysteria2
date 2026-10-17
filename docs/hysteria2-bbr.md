# Hysteria2 默认 BBR 与现有部署迁移

## 新安装和导出配置

新安装的 HY2 inbound 删除 `up_mbps` / `down_mbps`，设置 `ignore_client_bandwidth: true`。sing-box outbound 删除 `up_mbps` / `down_mbps`，Mihomo 节点删除 `up` / `down`；分享链接原本没有带宽声明，保持不变。使用兼容内核的默认 BBR 协商，不添加较新版本专属的 `bbr_profile` 字段。

这只改变 HY2 的默认带宽协商；Reality、Linux TCP BBR、认证、密钥、TLS/SNI、端口、端口跳跃和路由均不改变。HY2 的 QUIC BBR 与 Linux TCP 拥塞控制是两个不同层面的设置。

BBR 不保证零丢包，也不是公网带宽限速器或流量配额机制。带宽声明不是服务器的硬限速。需要硬限速、按用户限速或月流量额度时，应使用独立的流量整形/配额机制，并单独设计、验证，不能依靠 HY2 的带宽字段。

BBR 是本仓库新部署的默认策略，不保证在所有线路、丢包/时延条件或业务负载下都有相同或更高吞吐。回环兼容性测试不能推出某条公网线路的性能上限；真实线路若出现性能下降，应记录测试条件和数据，按下文步骤决定是否回滚。本变更不能宣称已经修复此前的异常出站流量。

GitHub 脚本更新不会自动修改旧服务器的 HY2 配置；安装入口识别到既有部署后仍按现有菜单流程运行。旧导出客户端文件和已导入的 Clash 配置也不会自行更新。重新导出生成的新文件不再包含固定 HY2 带宽；请手动备份和导入。

多 VPS 合并及质量切换工具同时接受新的无带宽导出和旧的精确 `300 Mbps` 导出形状。显式生成新文件时只移除旧默认带宽，不重写源文件；未知/缺失一半/自定义带宽声明仍拒绝，避免意外接受任意 YAML。

已发布的旧质量切换 EXE 内嵌旧的严格导出解析器，可能拒绝新的无带宽 YAML。使用新导出格式前，应从本 PR 源码重新构建、签名并另行发布 EXE；只更新服务器不能更新旧 EXE。本次仅交付源代码和测试，不替换生产 Windows 下载。旧服务器和旧客户端配置不会自动变更。

## 兼容性与验证边界

- 服务端的 `ignore_client_bandwidth` 自 sing-box 1.11.0 支持。旧版本必须先用其实际内核检查候选配置，检查不通过时停止；本次不自动升级旧内核。
- CI 使用官方 sing-box 1.14.3 服务端，验证 sing-box 1.14.3、1.11.15 客户端及 Mihomo 1.19.31；语法测试另外使用固定摘要的 MaxMind 测试数据库，不以其验证真实分流结果。测试用发行包的版本和 SHA256 固定在 `.github/workflows/hy2-bbr.yml`。
- 1.11.15 只验证最小客户端的 HY2 outbound 协商互通；完整导出的 sing-box 客户端仍遵循原脚本的 1.13+ 配置格式要求，不能据此把完整新 JSON 导入 1.11。
- 真实内核验证完整生成配置、IPv4/IPv6 导出、端口跳跃字段、密码/TLS/SNI和 Reality 字段保留；回环测试验证 HY2 双向传输、旧 300 Mbps 声明客户端仍可连接、错误密码拒绝，以及 Reality 双向传输。回环不证明生产线路无丢包，也不代替生产端口跳跃 NAT 验收。
- 服务端无带宽声明且 `ignore_client_bandwidth: true` 会要求合规客户端使用 BBR；客户端省略带宽也选择 BBR。旧版或修改过的第三方客户端、订阅转换器可能不支持或重新加入带宽参数，需查看最终生效配置并单独验证；本仓库不承诺全部历史客户端兼容。
- 官方定义：[sing-box inbound](https://sing-box.sagernet.org/configuration/inbound/hysteria2/#ignore_client_bandwidth)、[sing-box outbound](https://sing-box.sagernet.org/configuration/outbound/hysteria2/#up_mbps-down_mbps)、[Mihomo HY2](https://wiki.metacubex.one/en/config/proxies/hysteria2/)。

尚未通过受控生产对照证明 Brutal 是流量异常的根因。单看 TX/RX 比例无法区分正常下载与额外重传；迁移前后应使用相同负载、方向、并发和时长对比有效传输量与端口计数。

## 现有 VPS：手动备份、检查和迁移

以下为管理员自行执行的独立步骤，不会因安装或内核更新自动触发。先保持现有 SSH 会话，选择可中断连接的维护时段；重启 sing-box 会断开当前代理连接。不要在两台服务器同时操作，先验证一台。

1. 确认当前服务健康、内核版本，并检查当前完整配置。若不是这里的路径，请先核对实际路径；不要盲目执行。

```bash
/root/sbox/sing-box version
/root/sbox/sing-box check -c /root/sbox/sbconfig_server.json
systemctl is-active sing-box.service
```

2. 在同一个 root Bash 会话中执行下面的准备步骤。备份目录含私密配置，仅本机保管，不上传 GitHub。此阶段不替换生产文件，也不重启。

```bash
set -Eeuo pipefail
cfg=/root/sbox/sbconfig_server.json
bin=/root/sbox/sing-box
[[ $EUID == 0 && -f $cfg && ! -L $cfg && -x $bin ]]
"$bin" check -c "$cfg"
systemctl is-active --quiet sing-box.service
backup=$(mktemp -d /root/sbox/hy2-before-bbr.XXXXXXXX)
chmod 700 "$backup"
cp -a "$cfg" "$backup/server.json"
for file in config sbconfig_client.json mihomo_client.yaml; do
    if [[ -f /root/sbox/$file && ! -L /root/sbox/$file ]]; then
        cp -a "/root/sbox/$file" "$backup/$file"
    fi
done
candidate=$(mktemp /root/sbox/.hy2-bbr.XXXXXXXX)
chmod --reference="$cfg" "$candidate"
chown --reference="$cfg" "$candidate"
jq -e '[.inbounds[] | select(.type == "hysteria2")] | length > 0' "$cfg" >/dev/null
jq '(.inbounds[] | select(.type == "hysteria2")) |= (del(.up_mbps,.down_mbps) + {ignore_client_bandwidth:true})' "$cfg" > "$candidate"
"$bin" check -c "$candidate"
# Compare every other field, including Reality, all users and routing.
filter='(.inbounds[] | select(.type == "hysteria2")) |= del(.up_mbps,.down_mbps,.ignore_client_bandwidth)'
jq -S "$filter" "$cfg" > "$backup/before-other-fields.json"
jq -S "$filter" "$candidate" > "$backup/after-other-fields.json"
cmp "$backup/before-other-fields.json" "$backup/after-other-fields.json"
printf 'Backup: %s\nCandidate: %s\n' "$backup" "$candidate"
```

3. 确认配置检查和比较都成功后，再替换并重启。自动恢复分支只处理本次手动操作失败，不是开机迁移。若准备或检查失败，保留原配置，停止后续步骤。

```bash
# Refuse activation if someone changed production config after preparation.
cmp "$cfg" "$backup/server.json"
mv -f "$candidate" "$cfg"
if ! systemctl restart sing-box.service || ! systemctl is-active --quiet sing-box.service; then
    cp -a "$backup/server.json" /root/sbox/.hy2-bbr-rollback.json
    mv -f /root/sbox/.hy2-bbr-rollback.json "$cfg"
    systemctl restart sing-box.service
    echo 'Activation failed; original config restored. Verify client connections.'
    false
fi
jq -e 'all(.inbounds[] | select(.type == "hysteria2"); .ignore_client_bandwidth == true and (has("up_mbps")|not) and (has("down_mbps")|not))' "$cfg" >/dev/null
```

4. 使用真实客户端分别验证 HY2、Reality 的认证、下载、上传以及原有端口跳跃。`active` 和语法检查不能代替真实连接验收。观察应用卡顿、有效吞吐和端口收发量；不应把 BBR 当作 3 Gbps 端口的限速手段。客户端如需去掉旧声明，先备份，在更新后的脚本中手动导出并核对凭据后再导入；勿覆盖其他用户手改规则。

## 手动回滚

若服务虽运行但真实客户端连接失败、吞吐或其他功能退化，使用准备阶段输出的**实际备份目录**回滚，不能照抄示例目录名。保留原 SSH 会话。

```bash
# Set backup to the exact directory printed in step 2, if this is a new session.
[[ -n ${backup:-} && -f $backup/server.json && ! -L $backup/server.json ]]
/root/sbox/sing-box check -c "$backup/server.json"
cp -a "$backup/server.json" /root/sbox/.hy2-bbr-rollback.json
mv -f /root/sbox/.hy2-bbr-rollback.json /root/sbox/sbconfig_server.json
systemctl restart sing-box.service
systemctl is-active sing-box.service
```

再分别验证 HY2 与 Reality。若更换过客户端配置，也恢复相应客户端的备份；本过程不修改 nftables、端口跳跃规则、证书文件或内核 TCP BBR，因此无需重新创建这些对象。
