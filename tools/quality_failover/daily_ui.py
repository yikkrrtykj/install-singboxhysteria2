"""One window: prepare a private profile, observe it, explicitly enable, stop."""
import queue
import threading
from pathlib import Path
from .daily import Session, error_code, prepare_bundle, working_directory
from .policy import GROUP

MODES = {"rule": "规则模式", "global": "全局模式", "direct": "直连模式"}
CHOICE_MESSAGES = {"rule": "请在 Clash 的“节点选择”里选择“质量自动选择”，再点启用。",
                   "global": "请在 Clash 全局代理中选择“质量自动选择”，再点启用。",
                   "direct": "当前是直连模式；切到规则或全局模式并选择“质量自动选择”，才会启用切换。"}
MESSAGES = {"clash_settings": "未找到可用的 Clash Verge 本机设置；请保持 Clash 运行。",
            "clash_controller": "Clash 控制接口必须是带认证的本机地址。",
            "live_profile_not_loaded": "请先在 Clash 导入并启用本窗口生成的新配置。",
            "profile_shape": "当前配置的分组发生变化，已停止接管；请使用本窗口生成的配置。",
            "routing_mode_unavailable": "未能读取 Clash 当前模式，暂不控制；请保持现有设置。",
            "routing_mode_changed": "Clash 模式刚发生变化，等待下一次核对。",
            "already_running": "这份配置已有一个质量窗口正在运行，请使用原窗口。",
            "control_not_ready": "还没有两个协议的有效上传确认；可点“检查上传”并确认 VPS 接收端在线。",
            "manual_choice": "请在 Clash 当前模式中选择“质量自动选择”，再点启用。",
            "control_suspended": "临时选择与本窗口记录不一致，质量控制暂停，请保留现状。",
            "canonical_profile": "原始 YAML 格式不匹配；请选择网页直接下载的文件，避免另存为改变换行。",
            "canonical_name": "请保留原始文件名，例如 test-mihomo.yaml。",
            "probe_ports": "本机检查端口不可用，请保留现状。",
            "bundle_file": "准备文件已被改变，请重新生成一份。",
            "bundle": "准备文件不完整，请重新生成。",
            "working_directory": "工作目录不是本工具的私有目录，请保留现状。",
            "working_permissions": "私有目录权限未设置好，请保留现状。",
            "receiver_info": "接收端连接文件不符合要求。",
            "certificate_file": "接收端证书缺失或格式不符合要求。",
            "certificate_digest": "连接文件与证书不是同一批。",
            "record_unavailable": "本机状态记录未能保存，已请求停止质量窗口；请保留现状。",
            "operation_unavailable": "操作未完成；请核对 Clash、接收端及本机连接状态。"}
REASONS = {"no_evidence": "等待探测", "missing_reachability": "探测记录缺失或过期",
           "reachable_only": "连接可达，未确认上传质量", "upload_confirmed_good": "上传确认正常",
           "upload_confirmed_bad": "多次确认上传变慢", "recovery_pending": "等待稳定恢复",
           "hard_probe_failed": "连接探测失败", "quality_recovered": "稳定恢复"}
STATES = {"UP": "可达", "DEGRADED": "变慢／恢复中", "DOWN": "不可达", "UNKNOWN": "待确认"}


def show(workspace, home, primary_path=None, receiver_info_path=None):
    import tkinter as tk
    from tkinter import filedialog, ttk
    root = tk.Tk()
    root.title("Clash 质量切换 · 接入试用")
    root.geometry("850x630")
    frame = ttk.Frame(root, padding=18)
    frame.pack(fill="both", expand=True)
    ttk.Label(frame, text="生成新配置后，在 Clash 手动导入并启用；原配置保留，可随时切回。\n"
              "窗口先观察，点击启用后只控制新增分组。不会安装服务、设开机自启或改 TUN。\n"
              "接入试用使用已有的7天临时证书，VPS 接收端需要保持运行。", wraplength=800).pack(anchor="w")
    primary, backup, info = (tk.StringVar() for _ in range(3))
    primary.set(primary_path or "")
    info.set(receiver_info_path or "")
    for title, value in (("原始客户端 YAML", primary), ("备用 VPS YAML（可留空）", backup), ("接收端 receiver-info.json", info)):
        row = ttk.Frame(frame)
        row.pack(fill="x", pady=6)
        ttk.Label(row, text=title, width=30).pack(side="left")
        ttk.Entry(row, textvariable=value).pack(side="left", fill="x", expand=True)
        ttk.Button(row, text="选择文件", command=lambda item=value: item.set(filedialog.askopenfilename())).pack(side="right")
    profile_path, status = tk.StringVar(), tk.StringVar(value="选择原始 YAML 和已有连接文件，点“生成配置”。")
    settings = ttk.Frame(frame)
    settings.pack(fill="x", pady=8)
    fail, recover = tk.StringVar(value="4"), tk.StringVar(value="8")
    for title, value in (("上传慢于（Mbps）", fail), ("恢复至少（Mbps）", recover)):
        ttk.Label(settings, text=title).pack(side="left")
        ttk.Entry(settings, textvariable=value, width=6).pack(side="left", padx=(4, 12))
    ttk.Label(settings, text="稳定等待2分钟；仅异常、恢复或主动检查时确认上传。", wraplength=370).pack(side="left")
    ttk.Label(frame, textvariable=status, wraplength=800).pack(anchor="w", pady=10)
    ttk.Entry(frame, textvariable=profile_path, state="readonly").pack(fill="x")
    ttk.Label(frame, text="在 Clash → 配置中导入以上文件并启用，然后点“开始观察”。规则模式在“节点选择”里选“质量自动选择”；全局模式直接选这个分组。",
              wraplength=800).pack(anchor="w", pady=6)
    table = ttk.Treeview(frame, columns=("node", "state", "reason"), show="headings", height=5)
    for name, title in (("node", "协议"), ("state", "状态"), ("reason", "说明")):
        table.heading(name, text=title)
        table.column(name, width=220)
    table.pack(fill="both", expand=True)
    messages, active, bundle = queue.Queue(maxsize=128), [False], [None]
    session, closing, notice = [None], [False], [None]
    root_directory = working_directory(workspace)
    candidates = sorted(root_directory.glob("bundle-*/bundle.json"), key=lambda path: path.stat().st_mtime, reverse=True)
    if candidates:
        bundle[0] = candidates[0]
        from .daily import load_bundle
        try:
            meta, saved = load_bundle(bundle[0], home)
            fail.set(str(saved["paths"][0]["policy"]["fail_mbps"]))
            recover.set(str(saved["paths"][0]["policy"]["recover_mbps"]))
            profile_path.set(str(bundle[0].parent / meta["profile"]))
            status.set("已有准备文件。请确认 Clash 已导入这份配置，再开始观察。")
        except Exception:
            bundle[0] = None

    def emit(value):
        try:
            messages.put_nowait(value)
        except queue.Full:
            if value.get("action") == "stopped":
                try:
                    messages.get_nowait()
                except queue.Empty:
                    pass
                messages.put_nowait(value)

    def prepare():
        if active[0]:
            return
        source = Path(primary.get())
        if not source.name.endswith("-mihomo.yaml"):
            status.set(MESSAGES["canonical_name"])
            return
        # All widget values are captured on the GUI thread.
        try:
            arguments = (str(root_directory), str(source), source.name[:-len("-mihomo.yaml")], info.get(), home,
                         backup.get() or None, float(fail.get()), float(recover.get()))
        except ValueError:
            status.set("阈值请填写数字，并保证恢复值高于变慢值。")
            return
        active[0] = True
        status.set("正在生成私有配置；不会更改 Clash 当前配置。")
        def work():
            try:
                path = prepare_bundle(*arguments)
                emit({"action": "prepared", "bundle_path": str(path)})
            except Exception as exception:
                emit({"action": "prepare_failed", "reason": error_code(exception)})
        threading.Thread(target=work, daemon=False).start()

    def observe():
        if active[0] or bundle[0] is None:
            return
        active[0] = True
        current = Session(bundle[0], home)
        session[0] = current
        status.set("正在核对已导入的配置；先观察，不切换节点。")
        def work():
            try:
                current.start()
                current.loop(emit)
            except Exception as exception:
                emit({"action": "start_failed", "reason": error_code(exception)})
        threading.Thread(target=work, daemon=False).start()

    def enable():
        if session[0] is not None and active[0]:
            notice[0] = None
            session[0].enable()
            status.set("正在检查上传确认与手动选择；满足条件才启用。")

    def confirm():
        if session[0] is not None and active[0]:
            notice[0] = None
            session[0].confirm()
            status.set("请求一次有预算上限的上传确认。")

    def stop():
        if session[0] is not None and active[0]:
            session[0].stop()
            status.set("正在停止；等待当前有时限的请求结束，并撤销本窗口的临时选择。")

    def close():
        if active[0]:
            closing[0] = True
            stop()
        else:
            root.destroy()

    def copy_path():
        if profile_path.get():
            root.clipboard_clear()
            root.clipboard_append(profile_path.get())

    row = ttk.Frame(frame)
    row.pack(fill="x", pady=8)
    for title, command in (("生成配置", prepare), ("复制配置路径", copy_path), ("开始观察", observe),
                           ("检查上传", confirm), ("启用质量切换", enable), ("停止", stop)):
        ttk.Button(row, text=title, command=command).pack(side="left", padx=3)
    ttk.Button(frame, text="关闭", command=close).pack(anchor="e")

    def poll():
        try:
            while True:
                value = messages.get_nowait()
                action = value.get("action")
                if action == "prepared":
                    from .daily import load_bundle
                    bundle[0] = Path(value["bundle_path"])
                    active[0] = False
                    try:
                        meta, _ = load_bundle(bundle[0], home)
                        profile_path.set(str(bundle[0].parent / meta["profile"]))
                        status.set("新配置已生成。请在 Clash 导入并启用，原配置保留。")
                    except Exception as exception:
                        bundle[0] = None
                        profile_path.set("")
                        status.set(MESSAGES.get(error_code(exception), MESSAGES["operation_unavailable"]))
                elif action in ("prepare_failed", "start_failed"):
                    active[0] = False
                    session[0] = None
                    status.set(MESSAGES.get(value.get("reason"), MESSAGES["operation_unavailable"]))
                elif action == "stopped":
                    active[0] = False
                    session[0] = None
                    text = "已停止。" if value["restore_confirmed"] else "已停止；临时选择恢复未确认，请在 Clash 选回“自动选择”。"
                    status.set(text + ("本机状态记录未保存。" if notice[0] == MESSAGES["record_unavailable"] else ""))
                elif "paths" in value:
                    table.delete(*table.get_children())
                    for node, facts in value["paths"].items():
                        table.insert("", "end", values=(node, STATES.get(facts["state"], "待确认"), REASONS.get(facts["reason"], "待确认")))
                    text = {"manual_override": "手动选择优先，质量切换暂停。",
                                "control_suspended": "分组或临时选择发生变化，控制已暂停。",
                                "selected": "已更新质量分组，新连接使用确认过的协议。"}.get(action,
                                "质量切换已启用，正在观察。" if value["mode"] == "control" else "观察中；尚未启用质量切换。")
                    if value["mode"] == "control":
                        notice[0] = None
                    mode = MODES.get(value.get("routing_mode"))
                    status.set(notice[0] or ((mode + "：") if mode else "") + text)
                else:
                    text = MESSAGES.get(action, MESSAGES["operation_unavailable"])
                    if action == "manual_choice":
                        text = CHOICE_MESSAGES.get(value.get("routing_mode"), text)
                    if action in ("control_not_ready", "manual_choice", "record_unavailable", "control_suspended"):
                        notice[0] = text
                    status.set(text)
        except queue.Empty:
            pass
        except Exception:
            status.set("读取准备结果未完成，请保留窗口。")
        if closing[0] and not active[0]:
            root.destroy()
            return
        root.after(200, poll)

    root.protocol("WM_DELETE_WINDOW", close)
    root.after(200, poll)
    root.mainloop()
