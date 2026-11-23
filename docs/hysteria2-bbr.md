# Hysteria2 默认 BBR 与现有部署迁移

## 新安装和导出配置

新安装的 HY2 inbound 删除 `up_mbps` / `down_mbps`，设置 `ignore_client_bandwidth: true`。sing-box outbound 删除 `up_mbps` / `down_mbps`，Mihomo 节点删除 `up` / `down`；分享链接原本没有带宽声明，保持不变。使用兼容内核的默认 BBR 协商，不添加较新版本专属的 `bbr_profile` 字段。

这只改变 HY2 的默认带宽协商；Reality、认证、密钥、TLS/SNI、端口、端口跳跃和路由均不改变。HY2 的 QUIC BBR 与 Linux TCP 拥塞控制是两个不同层面的设置：本节只描述 HY2 QUIC 层；全新的 Linux 安装是否启用内核 TCP BBR / `fq` 由下一节单独描述，旧服务器不会因此自动迁移。

BBR 不保证零丢包，也不是公网带宽限速器或流量配额机制。带宽声明不是服务器的硬限速。需要硬限速、按用户限速或月流量额度时，应使用独立的流量整形/配额机制，并单独设计、验证，不能依靠 HY2 的带宽字段。

BBR 是本仓库新部署的默认策略，不保证在所有线路、丢包/时延条件或业务负载下都有相同或更高吞吐。回环兼容性测试不能推出某条公网线路的性能上限；真实线路若出现性能下降，应记录测试条件和数据，按下文步骤决定是否回滚。本变更不能宣称已经修复此前的异常出站流量。

GitHub 脚本更新不会自动修改旧服务器的 HY2 配置；安装入口识别到既有部署后仍按现有菜单流程运行，也不会自动迁移内核 TCP/qdisc（见下文“只对全新安装生效”）。旧导出客户端文件和已导入的 Clash 配置也不会自行更新。重新导出生成的新文件不再包含固定 HY2 带宽；请手动备份和导入。

多 VPS 合并及质量切换工具同时接受新的无带宽导出和旧的精确 `300 Mbps` 导出形状。显式生成新文件时只移除旧默认带宽，不重写源文件；未知/缺失一半/自定义带宽声明仍拒绝，避免意外接受任意 YAML。

已发布的旧质量切换 EXE 内嵌旧的严格导出解析器，可能拒绝新的无带宽 YAML。使用新导出格式前，应从本 PR 源码重新构建、签名并另行发布 EXE；只更新服务器不能更新旧 EXE。本次仅交付源代码和测试，不替换生产 Windows 下载。旧服务器和旧客户端配置不会自动变更。

## 全新安装的内核 TCP BBR / fq 与 UDP 缓冲默认

真正全新的 Linux 安装（本机不存在任何既有安装标记）会默认尝试：

- 启用内核 TCP BBR：检查 `net.ipv4.tcp_available_congestion_control`，可用时设置 `net.ipv4.tcp_congestion_control=bbr`；不会下载第三方内核脚本、不会自动更换内核。
- 设置默认队列算法 `net.core.default_qdisc=fq`；若主机已有非默认的自定义 qdisc（如 `cake`、`htb`），保留原 qdisc 并明确报告，不强行覆盖。
- 保持 UDP 收发缓冲至少 16 MiB：`net.core.rmem_max` / `net.core.wmem_max` 取“当前值、既有受管文件值、16 MiB”三者最大值，绝不下调更大的已有值。
- 持久化到 `/etc/sysctl.d/99-sing-box-network.conf`：开机由系统 sysctl 服务重新应用；不会重启系统、不会重启或改写 sing-box 服务，也不保证已有 TCP 连接立即切换算法。

### 只对全新安装生效

- 已有安装的更新、脚本重跑、`miaomiao` 菜单操作（包括菜单 1 重新安装）**不会**自动迁移 TCP/qdisc；`FRESH_INSTALL` 在识别到既有安装时即被标记为非全新，网络默认整体跳过。
- 菜单 `5. 启用本地 BBR + 优化 Hysteria2 UDP 缓冲` 仍是显式手动入口：设置 TCP BBR、保留自定义 qdisc、应用 UDP 缓冲下限，并同样记录安装前参数。
- 不需要该默认优化（例如容器/自动化环境）可在安装时显式退出：`SB_SKIP_NETWORK_TUNING=1 bash <(curl -fsSL .../install.sh)`。退出时不会写入任何 TCP/qdisc/UDP 配置。

### 安装前状态记录与失败回滚

- 应用前先读取并记录原始值，并把**原受管文件字节**复制到 `root:root 0700` 的 `/root/sbox/network-tuning.before-install.<时间戳>/`：`state` 记录 `tcp_congestion_control` / `default_qdisc` / `rmem_max` / `wmem_max` / `file_present` / `result`，同目录保存原 `99-sing-box-network.conf`。
- 内核不支持 BBR、`tcp_bbr` 加载失败、权限受限、`sysctl -p` 部分失败或持久化文件写入失败时：恢复安装前的运行时 sysctl 与持久化文件（原文件不存在则删除本次写入），输出原因与实际值，然后**继续正常安装**。BBR/fq 是可选优化，任何失败都不会中断安装，也不会把未生效写成成功。
- 自动恢复不完整时会打印安装前实际值的手动恢复命令与记录路径，不隐藏失败。
- 安装结束的网络摘要会列出实际 `tcp_congestion_control`、`default_qdisc`、`rmem_max`、`wmem_max`，以及“已应用 / 已存在 / 内核不支持 / 已跳过 / 已回滚”的原因。

```bash
# 新安装后核对实际值与持久化文件（只读）
sysctl -n net.ipv4.tcp_congestion_control net.core.default_qdisc \
    net.core.rmem_max net.core.wmem_max
cat /etc/sysctl.d/99-sing-box-network.conf
# 安装前记录（使用实际打印的时间戳目录，勿照抄示例）
ls -1d /root/sbox/network-tuning.before-install.*
```

边界：`net.core.default_qdisc` 不等于现有网卡的即时 qdisc；BBR 不保证零丢包、不保证所有线路吞吐提升，也不是带宽限速或流量额度机制。`/etc/sysctl.conf` 或云厂商 drop-in 可能在开机时覆盖本文件，容器/LXC 可能禁止写入 sysctl；这些情况下以实际 `sysctl` 输出为准。

## 兼容性与验证边界

- 服务端的 `ignore_client_bandwidth` 自 sing-box 1.11.0 支持。旧版本必须先用其实际内核检查候选配置，检查不通过时停止；本次不自动升级旧内核。
- CI 使用官方 sing-box 1.14.3 服务端，验证 sing-box 1.14.3、1.11.15 客户端及 Mihomo 1.19.31；语法测试另外使用固定摘要的 MaxMind 测试数据库，不以其验证真实分流结果。测试用发行包的版本和 SHA256 固定在 `.github/workflows/hy2-bbr.yml`。
- 1.11.15 只验证最小客户端的 HY2 outbound 协商互通；完整导出的 sing-box 客户端仍遵循原脚本的 1.13+ 配置格式要求，不能据此把完整新 JSON 导入 1.11。
- 真实内核验证完整生成配置、IPv4/IPv6 导出、端口跳跃字段、密码/TLS/SNI和 Reality 字段保留；回环测试验证 HY2 双向传输、旧 300 Mbps 声明客户端仍可连接、错误密码拒绝，以及 Reality 双向传输。回环不证明生产线路无丢包，也不代替生产端口跳跃 NAT 验收。
- 内核 TCP BBR/fq 默认由独立回归套件覆盖：CI 在隔离 network namespace 内用真实内核做应用/回滚/持久化重放，并用可注入 mock 覆盖不支持 BBR、部分写入失败、重复安装、旧安装更新跳过等路径；不执行真实重启，也不证明公网线路性能。`/etc/sysctl.conf`、云厂商 drop-in、容器限制等平台差异可能改变开机结果，以实际 `sysctl` 输出为准；`tcp_bbr` 模块加载是主机级副作用，不会卸载。
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

再分别验证 HY2 与 Reality。若更换过客户端配置，也恢复相应客户端的备份；本过程不修改 nftables、端口跳跃规则、证书文件，也不修改内核 TCP/qdisc；若只需回退内核网络默认，使用下一节。

## 手动恢复内核 TCP/qdisc 配置

全新安装的默认优化会自动回滚；如果安装后希望主动退回安装前的内核网络设置，使用安装时实际打印的记录目录（`/root/sbox/network-tuning.before-install.<时间戳>/`），不要照抄示例名。

```bash
# 1. 查看安装前实际值（不要凭记忆填写）
record=/root/sbox/network-tuning.before-install.<实际时间戳>
cat "$record/state"
sed -n 's/^tcp_congestion_control=//p; s/^default_qdisc=//p; s/^rmem_max=//p; s/^wmem_max=//p' "$record/state"

# 2. 恢复持久化文件：安装前存在则恢复原字节，不存在则删除本次写入
if grep -qx 'file_present=TRUE' "$record/state"; then
    install -m 0644 "$record/99-sing-box-network.conf" /etc/sysctl.d/99-sing-box-network.conf
else
    rm -f /etc/sysctl.d/99-sing-box-network.conf
fi
sysctl -p /etc/sysctl.d/99-sing-box-network.conf

# 3. 精确恢复运行时 TCP/qdisc（值来自第 1 步的实际输出）
sysctl -w net.ipv4.tcp_congestion_control=<state 中的原值>
sysctl -w net.core.default_qdisc=<state 中的原值>
sysctl -w net.core.rmem_max=<state 中的原值> net.core.wmem_max=<state 中的原值>
sysctl -n net.ipv4.tcp_congestion_control net.core.default_qdisc
```

说明：恢复受管文件会同时恢复安装前的 UDP 缓冲值（可能低于 16 MiB），这是“恢复原始状态”的预期结果；不需要重启系统或 sing-box。若是菜单 1 重新安装前的备份，另有 `/root/sbox-backup-*/network-sysctl.txt` 记录当时的运行值可交叉核对。`SB_SKIP_NETWORK_TUNING=1` 只影响之后的安装运行，不修改已经生效的设置。
