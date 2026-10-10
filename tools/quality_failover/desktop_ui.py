"""Recipient UI: no file pickers, no threshold settings, explicit start only."""
import queue
import threading
import time
from pathlib import Path

from .daily import Session, error_code, load_bundle, prepare_bundle
from .daily_ui import MESSAGES, REASONS, STATES
from .policy import NODES


def show(workspace, home, primary, info):
    import os
    import tkinter as tk
    from tkinter import messagebox, ttk
    root = tk.Tk()
    root.title("质量切换")
    root.geometry("780x470")
    root.minsize(650, 420)
    frame = ttk.Frame(root, padding=20)
    frame.pack(fill="both", expand=True)
    ttk.Label(frame, text="网络质量切换", font=("Microsoft YaHei UI", 17, "bold")).pack(anchor="w")
    ttk.Label(frame, text="当前协议正常就保持；确认故障后才换协议，不自动切回。", wraplength=710).pack(anchor="w", pady=(6, 3))
    ttk.Label(frame, text="请保持 Clash 运行。空闲不会触发切换；关闭本窗口后停止质量控制。", wraplength=710).pack(anchor="w")
    status = tk.StringVar(value="点“开启质量切换”开始。首次使用会引导你导入 Clash 配置。")
    ttk.Label(frame, textvariable=status, wraplength=710, font=("Microsoft YaHei UI", 11)).pack(anchor="w", pady=18)
    table = ttk.Treeview(frame, columns=("node", "state", "reason"), show="headings", height=5)
    for name, label, width in (("node", "协议", 120), ("state", "状态", 100), ("reason", "说明", 420)):
        table.heading(name, text=label)
        table.column(name, width=width)
    table.pack(fill="both", expand=True)
    for node in NODES[:2]:
        table.insert("", "end", iid=node, values=(node, "等待检查", "开启后自动检查"))
    bundle, session, busy, closing = [None], [None], [False], [False]
    enable_requested, enable_sent, notice = [False], [False], [None]
    deadline = [0.0]
    restart_after_stop = [False]
    messages = queue.Queue(maxsize=128)
    for candidate in sorted(Path(workspace).glob("bundle-*/bundle.json"), key=lambda p: p.stat().st_mtime, reverse=True):
        try:
            meta, _ = load_bundle(candidate, home)
            if "  - name: 手动选择 · " not in (candidate.parent / meta["profile"]).read_text("utf-8"):
                continue
            bundle[0] = candidate
            break
        except Exception:
            continue

    def emit(value):
        try:
            messages.put_nowait(value)
        except queue.Full:
            if value.get("action") in ("stopped", "failed", "prepared"):
                try:
                    messages.get_nowait()
                except queue.Empty:
                    pass
                messages.put_nowait(value)

    def folder():
        if bundle[0] is not None:
            os.startfile(str(bundle[0].parent))

    def start(pin=None):
        if busy[0]:
            return
        busy[0] = True
        notice[0] = None
        enable_requested[0], enable_sent[0] = True, False
        deadline[0] = time.monotonic() + 95
        start_button.configure(state="disabled")
        if bundle[0] is None:
            status.set("正在准备你的配置，请保持 Clash 打开……")
            def prepare():
                try:
                    path = prepare_bundle(workspace, primary, Path(primary).name[:-len("-mihomo.yaml")], info, home)
                    emit({"action": "prepared", "path": str(path)})
                except Exception as exception:
                    emit({"action": "failed", "reason": error_code(exception)})
            threading.Thread(target=prepare, daemon=False).start()
            return
        current = Session(bundle[0], home)
        session[0] = current
        status.set("正在检查两个协议；通过后开启质量切换……")
        def observe():
            try:
                current.start(acknowledged_pin=pin)
                current.loop(emit)
            except Exception as exception:
                event = {"action": "failed", "reason": error_code(exception)}
                if event["reason"] == "selection_handoff_required" and len(exception.args) == 2 and exception.args[1] in NODES:
                    event["pin"] = exception.args[1]
                emit(event)
        threading.Thread(target=observe, daemon=False).start()

    def retry_enable():
        if session[0] is not None and busy[0]:
            if notice[0] is not None:
                restart_after_stop[0] = True
                session[0].stop()
                status.set("正在重新开始，请稍候……")
                start_button.configure(state="disabled")
                return
            notice[0] = None
            enable_requested[0], enable_sent[0] = True, False
            deadline[0] = time.monotonic() + 95
            session[0].confirm()
            status.set("正在重新核对上传和 Clash 的选择……")
            start_button.configure(state="disabled")
        else:
            start()

    def stop():
        restart_after_stop[0] = False
        enable_requested[0] = False
        if session[0] is not None:
            session[0].stop()
            status.set("正在停止，请稍候……")

    def close():
        if busy[0]:
            closing[0] = True
            stop()
        else:
            root.destroy()

    row = ttk.Frame(frame)
    row.pack(fill="x", pady=(15, 8))
    start_button = ttk.Button(row, text="开启质量切换", command=retry_enable)
    start_button.pack(side="left")
    ttk.Button(row, text="停止", command=stop).pack(side="left", padx=10)
    folder_button = ttk.Button(row, text="打开 Clash 配置文件夹", command=folder)
    folder_button.pack(side="right")
    ttk.Label(frame, text="无需管理员权限，不修改 TUN，不设置开机自启。配置仅供本人使用。", wraplength=710).pack(anchor="w")
    ttk.Button(frame, text="关闭", command=close).pack(anchor="e", pady=(8, 0))

    def import_hint():
        status.set("首次使用：打开配置文件夹，把其中的“" + Path(primary).name.replace("-mihomo.yaml", "-quality.yaml") +
                   "”导入 Clash 并启用。规则模式在“手动选择”中选“质量自动选择”；全局模式直接选“质量自动选择”，然后回来点“开启质量切换”。")

    def poll():
        try:
            while True:
                value = messages.get_nowait()
                action = value.get("action")
                if action == "prepared":
                    bundle[0] = Path(value["path"])
                    busy[0] = False
                    start_button.configure(state="normal")
                    import_hint()
                elif action == "failed":
                    busy[0] = False
                    session[0] = None
                    start_button.configure(state="normal")
                    reason = value.get("reason")
                    if reason == "live_profile_not_loaded":
                        import_hint()
                    else:
                        status.set(MESSAGES.get(reason, MESSAGES["operation_unavailable"]))
                    pin = value.get("pin")
                    if pin in NODES and not closing[0] and messagebox.askyesno("继续使用当前协议",
                            "继续使用 " + pin + "，并开启质量切换吗？", parent=root):
                        start(pin)
                elif action == "stopped":
                    busy[0] = False
                    session[0] = None
                    start_button.configure(state="normal")
                    status.set("已停止，Clash 仍可正常使用。" if value.get("restore_confirmed") else
                               "已停止；请在 Clash 核对所选节点，停止恢复未确认。")
                    if restart_after_stop[0] and not closing[0]:
                        restart_after_stop[0] = False
                        start()
                elif "paths" in value:
                    for node, facts in value["paths"].items():
                        if not table.exists(node):
                            table.insert("", "end", iid=node)
                        table.item(node, values=(node, STATES.get(facts["state"], "待确认"), REASONS.get(facts["reason"], "待确认")))
                    ready = set(value["paths"]) == set(NODES[:2]) and all(facts.get("reason") in ("upload_confirmed_good", "quality_recovered")
                                and facts.get("state") == "UP" for facts in value["paths"].values())
                    if enable_requested[0] and not enable_sent[0] and ready and session[0] is not None:
                        session[0].enable()
                        enable_sent[0] = True
                    if enable_requested[0] and not enable_sent[0] and time.monotonic() > deadline[0]:
                        enable_requested[0] = False
                        notice[0] = "本次未能确认上传质量，尚未开启切换。请检查网络或联系管理员，稍后可再点开启重试。"
                        start_button.configure(state="normal")
                    if action in ("manual_override", "control_suspended"):
                        enable_requested[0] = False
                        notice[0] = "你已手动改变选择，自动控制已暂停。需要恢复时再点“开启质量切换”。"
                        start_button.configure(state="normal")
                    elif value.get("mode") == "control":
                        selected = value.get("owned_selection")
                        status.set("质量切换已开启。" + ("当前协议：" + selected + "。" if selected in NODES else ""))
                    else:
                        status.set(notice[0] or "正在确认上传质量，请稍候；未确认时不会自动切换。")
                    if notice[0]:
                        status.set(notice[0])
                else:
                    if action in ("manual_choice", "control_suspended", "control_not_ready", "record_unavailable"):
                        notice[0] = ("请规则模式在“手动选择”中选“质量自动选择”；全局模式直接选“质量自动选择”，然后回来点“开启质量切换”。"
                                     if action == "manual_choice" else MESSAGES.get(action, MESSAGES["operation_unavailable"]))
                        enable_requested[0] = False
                        start_button.configure(state="normal")
                    status.set(notice[0] or MESSAGES.get(action, MESSAGES["operation_unavailable"]))
        except queue.Empty:
            pass
        if busy[0] and session[0] is not None and enable_requested[0] and not enable_sent[0] and time.monotonic() > deadline[0]:
            enable_requested[0] = False
            notice[0] = "本次未能确认上传质量，尚未开启切换。请检查网络或联系管理员，稍后可再点开启重试。"
            status.set(notice[0])
            start_button.configure(state="normal")
        if closing[0] and not busy[0]:
            root.destroy()
            return
        root.after(200, poll)

    root.protocol("WM_DELETE_WINDOW", close)
    root.after(200, poll)
    root.mainloop()
