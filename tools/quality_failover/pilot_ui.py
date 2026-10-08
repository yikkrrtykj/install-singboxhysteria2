"""Single operator window; no administrator prompt and no live Clash API access."""
import queue
import secrets
import threading
from pathlib import Path
from .pilot import run_pilot, error_code

LABELS = {"baseline": "检查两个协议的正常上传",
          "reality_degraded": "模拟测试连接变慢，检查切换",
          "recovery": "撤销限速，检查稳定恢复",
          "existing_and_new_connections": "检查已有连接与新连接",
          "hy2_hard_failure": "模拟测试 UDP 中断，检查备用协议",
          "hy2_recovery": "恢复测试 UDP，检查协议恢复",
          "manual_override": "检查手动选择优先"}

ERROR_LABELS = {"binary_digest": "测试程序版本与校验记录不一致",
                "binary": "测试程序不存在或格式不符合要求",
                "certificate_digest": "接收端连接文件与证书不是同一批",
                "certificate_file": "接收端证书文件不存在或不符合要求",
                "receiver_info": "接收端连接文件格式不符合要求",
                "canonical_profile": "所选 YAML 不是服务器导出的原始配置",
                "canonical_name": "客户端名称与 YAML 文件名不一致",
                "native_state": "测试节点没有正常、有效的连接探测记录",
                "isolated_core_unavailable": "独立测试进程未能启动",
                "stage_failed": "本阶段未满足通过条件，请查看记录中的协议状态",
                "control_suspended": "测试进程的节点选择发生意外变化",
                "pilot_hopping_too_wide": "此试验版暂不支持超过128个跳跃端口",
                "cleanup_incomplete": "测试进程或临时文件未能完全清理"}


def show(binary, digest, results):
    import tkinter as tk
    from tkinter import filedialog, messagebox, ttk
    root = tk.Tk()
    root.title("协议切换测试")
    root.geometry("760x430")
    frame = ttk.Frame(root, padding=18)
    frame.pack(fill="both", expand=True)
    ttk.Label(frame, text="只运行独立测试进程，不修改日常 Clash、TUN 或开机自启。\n"
              "接收端需提前运行；正常基线不足就停止，不判通过。预计约 5～8 分钟。",
              wraplength=700).pack(anchor="w", pady=(0, 12))
    profile, info = tk.StringVar(), tk.StringVar()
    selectors = []
    for label, variable in (("服务器导出的客户端 YAML", profile), ("接收端连接文件 receiver-info.json", info)):
        row = ttk.Frame(frame)
        row.pack(fill="x", pady=6)
        ttk.Label(row, text=label, width=34).pack(side="left")
        ttk.Entry(row, textvariable=variable).pack(side="left", fill="x", expand=True)
        button = ttk.Button(row, text="选择文件", command=lambda value=variable: value.set(filedialog.askopenfilename()))
        button.pack(side="left", padx=(8, 0))
        selectors.append(button)
    status = tk.StringVar(value="准备好文件后，点一次开始即可。receiver-ca.pem 应与连接文件放在同一文件夹。")
    ttk.Label(frame, textvariable=status, wraplength=700).pack(anchor="w", pady=12)
    timeline = tk.Listbox(frame, height=8)
    timeline.pack(fill="both", expand=True)
    messages, cancelled = queue.Queue(maxsize=128), threading.Event()
    active = [False]

    def publish(record):
        try:
            messages.put_nowait(("progress", record))
        except queue.Full:
            pass

    def worker(arguments):
        try:
            result = run_pilot(*arguments, cancel=cancelled, emit=publish)
            result["result_path"] = arguments[-1]
            messages.put(("complete", result))
        except Exception as exception:
            messages.put(("failed", error_code(exception)))

    def start():
        source, receiver = Path(profile.get()), Path(info.get())
        if not source.name.endswith("-mihomo.yaml") or not receiver.is_file():
            messagebox.showerror("文件未准备好", "请选择原始客户端 YAML 和接收端连接文件。")
            return
        ca = receiver.with_name("receiver-ca.pem")
        if not ca.is_file() or not Path(results).is_dir():
            messagebox.showerror("文件未准备好", "接收端证书或结果文件夹不存在。")
            return
        arguments = (str(source), source.name[:-len("-mihomo.yaml")], str(receiver), str(ca), binary, digest,
                     str(Path(results) / ("pilot-" + secrets.token_hex(8) + ".json")))
        active[0] = True
        cancelled.clear()
        start_button.configure(state="disabled")
        for button in selectors:
            button.configure(state="disabled")
        status.set("正在检查环境。关闭窗口会请求停止并等待测试进程退出。")
        threading.Thread(target=worker, args=(arguments,), daemon=False).start()

    def close():
        if active[0]:
            cancelled.set()
            status.set("正在停止测试并清理，完成后可关闭。")
        else:
            root.destroy()

    def poll():
        try:
            while True:
                kind, value = messages.get_nowait()
                if kind == "progress":
                    label = LABELS.get(value.get("stage"), "检查中")
                    status.set(label)
                    if "passed" in value:
                        timeline.insert("end", ("通过：" if value["passed"] else "未通过：") + label)
                else:
                    active[0] = False
                    if kind == "complete":
                        if value["passed"]:
                            summary = "本轮测试通过，测试进程已退出。"
                        elif value.get("cancelled"):
                            summary = "测试已停止，不判通过。"
                        else:
                            summary = "未通过阶段：" + LABELS.get(value.get("failed_stage"), "环境准备")
                            summary += "；" + ERROR_LABELS.get(value.get("error"), "环境或连接检查未完成，请保留记录")
                        if not value["cleanup_complete"]:
                            summary += "；测试进程或文件清理未完成，请保留记录。"
                        status.set(summary + "\n记录：" + value["result_path"])
                    else:
                        status.set("准备未完成，尚不能判通过。" + ERROR_LABELS.get(value, "请核对文件、证书和程序版本"))
                    for button in selectors:
                        button.configure(state="normal")
                    start_button.configure(state="normal")
        except queue.Empty:
            pass
        root.after(200, poll)

    start_button = ttk.Button(frame, text="开始一轮检查", command=start)
    start_button.pack(side="left", pady=(12, 0))
    ttk.Button(frame, text="停止 / 关闭", command=close).pack(side="right", pady=(12, 0))
    root.protocol("WM_DELETE_WINDOW", close)
    root.after(200, poll)
    root.mainloop()
