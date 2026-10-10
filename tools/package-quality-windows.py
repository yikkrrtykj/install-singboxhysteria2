#!/usr/bin/env python3
"""Administrator-local recipient ZIP builder; no keys are compiled into software."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parent))
from quality_failover.desktop import EXE_NAME, package_inputs

PUBLISHER = "92E0176599764946F7E5AB332A5CEF150355BE9B"


def check_signature(exe):
    if os.name != "nt":
        raise ValueError("native Windows signature verification required")
    # No argument is treated as executable PowerShell text.
    powershell = Path(os.environ["SystemRoot"]) / "System32/WindowsPowerShell/v1.0/powershell.exe"
    script = "$ErrorActionPreference='Stop'; $s=Get-AuthenticodeSignature -LiteralPath $args[0]; if($s.Status -ne 'Valid' -or $s.SignerCertificate.Thumbprint -ne '" + PUBLISHER + "' -or !$s.TimeStamperCertificate){exit 2}"
    # PowerShell 7 module paths are incompatible with native Windows PowerShell.
    environment = {key: value for key, value in os.environ.items() if key.upper() != "PSMODULEPATH"}
    with tempfile.TemporaryDirectory(prefix="quality-signature-") as temporary:
        path = Path(temporary) / "verify.ps1"
        path.write_text(script, encoding="utf-8-sig")
        subprocess.run([str(powershell), "-NoProfile", "-NonInteractive", "-File", str(path), str(exe)],
                       check=True, timeout=30, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                       env=environment, creationflags=0x08000000)


def package(exe, yaml, receiver, output):
    exe, yaml, receiver, output = map(Path, (exe, yaml, receiver, output))
    if output.exists() or output.is_symlink() or exe.is_symlink() or exe.stat().st_size > 64 * 1024 * 1024:
        raise ValueError("package path unavailable")
    check_signature(exe)
    if not yaml.name.endswith("-mihomo.yaml"):
        raise ValueError("original export filename required")
    name = yaml.name[:-len("-mihomo.yaml")]
    files = {yaml.name: yaml.read_bytes(), "receiver-info.json": receiver.read_bytes(),
             "receiver-ca.pem": receiver.with_name("receiver-ca.pem").read_bytes()}
    manifest = {"v": 1, "client": name, "files": {n: hashlib.sha256(raw).hexdigest() for n, raw in files.items()}}
    manifest_raw = json.dumps(manifest, ensure_ascii=False, sort_keys=True).encode()
    # Validate in a private staging directory before emitting any recipient ZIP.
    with tempfile.TemporaryDirectory(prefix="quality-recipient-") as temporary:
        root = Path(temporary)
        for n, raw in dict(files, **{"quality-package.json": manifest_raw}).items():
            path = root / n
            path.write_bytes(raw)
            path.chmod(0o600)
        package_inputs(root)
    readme = ("质量切换使用说明\n\n1. 完整解压本压缩包，双击“质量切换.exe”。\n"
              "2. 保持 Clash Verge 运行，点击“开启质量切换”。\n"
              "3. 首次使用按窗口提示打开配置文件夹，将其中的 -quality.yaml 导入 Clash 并启用，选择“质量自动选择”。\n"
              "4. 回来再点“开启质量切换”。检查通过后自动开启；以后直接打开并点击开启即可。\n\n"
              "空闲不会触发切换。当前协议正常就保持，不自动切回。窗口须保持打开，可最小化。\n"
              "点击停止或关闭窗口就停止质量控制，不影响 Clash 本身运行。无需管理员权限，不改 TUN 或开机自启。\n"
              "本包包含个人连接凭据，请只交给对应使用者，不公开分享；出现问题联系公司管理员。\n"
              "签名由公司内部证书提供；内部签名不能保证首次运行没有 Windows 提示。\n").encode("utf-8-sig")
    fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as stream, zipfile.ZipFile(stream, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.write(exe, EXE_NAME)
            notices = Path(__file__).with_name("quality-windows-notices.txt").read_bytes()
            for n, raw in dict(files, **{"quality-package.json": manifest_raw, "先看这里.txt": readme,
                                        "第三方许可.txt": notices}).items():
                archive.writestr(n, raw)
    except BaseException:
        output.unlink(missing_ok=True)
        raise
    return {"v": 1, "client": name, "publisher": PUBLISHER,
            "archive_sha256": hashlib.sha256(output.read_bytes()).hexdigest(), "exe_sha256": hashlib.sha256(exe.read_bytes()).hexdigest()}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", required=True)
    parser.add_argument("--yaml", required=True)
    parser.add_argument("--receiver-info", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(package(args.exe, args.yaml, args.receiver_info, args.output)))
    except Exception:
        print("[FAIL] Recipient package not produced; verify signature and paired input files", file=sys.stderr)
        raise SystemExit(2)
