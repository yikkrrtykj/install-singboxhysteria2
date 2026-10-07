# Monitor 单次登录与闲置退出

2026-10-03 经用户确认，[Issue #67](https://github.com/yikkrrtykj/install-singboxhysteria2/issues/67) 中的单次登录约定取代普通客户端操作和下载的独立 300 秒密码确认。PR #70 仍为 Draft；这不是合并或生产部署授权。

管理员密码登录成功后，同一个会话可管理客户端、登记/撤销设备、下载 YAML、设备配置包和 Windows 程序，无需再次输入密码。删除和撤销仍确认目标，后端仍检查来源、CSRF、实时管理状态、登记证明和审计；未确认的操作不会自动重试。

服务端使用单调时钟与锁内检查实施 900 秒闲置上限和固定 8 小时总期限。仅带有效会话、CSRF 的同源 `POST /api/v1/session/activity`、正文 `{}`，可记录服务器当前活动时间；客户端不能提交时间或期限。过期会话不可恢复。

网页仅在可见页面的真实点击、触摸、键盘或滚动事件后通知活动，每 30 秒最多一次。自动刷新、SSE、计时器、焦点/可见性变化及程序触发的事件均不续期。网页退出时关闭 SSE 与后台监测；服务端会独立拒绝过期请求并停止现有 SSE。

注销、改密、恢复凭据变更、超时和进程重启都会清除会话与管理授权。已通过门禁的请求保留固定审计身份，helper 已开始的持久事务继续到终态。重新登录不自动重放旧操作。

修改管理员密码或恢复凭据本身仍要求原有当前密码证明。旧 `/api/v1/step-up` 为兼容保留，新网页不调用；它不能延长闲置或总期限。旧 `stepup_fp` 字段继续承载密码认证事件的匿名审计指纹，不把密码或会话 token 送入 helper。

本轮不改设备密钥、签名程序包、P6 存储、采集器或分类器。实际 Windows 程序下载/安装与离线、重启、TUN、资源验收仍需独立完成。

The existing E2 regression entry point runs `tests/test_monitor_session.py` and fails if any real HTTP session test fails. CI therefore exercises the session suite without a separate workflow step.
