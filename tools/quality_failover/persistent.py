"""Explicit persistent sink TLS lifecycle; no Monitor, proxy, trust or firewall writes."""
import hashlib
import http.client
import ipaddress
import json
import os
from pathlib import Path
import secrets
import socket
import ssl
import stat
import subprocess
import tempfile
from .receiver import Server
from .transport import decode_json

ROOT_DAYS = 3650
LEAF_DAYS = 90
RENEW_BEFORE = 20 * 86400
SERVICE = "singbox-quality-receiver.service"


def run_crypto(openssl, *args, required=True):
    result = subprocess.run([openssl, *map(str, args)], stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL, timeout=30)
    if required and result.returncode:
        raise ValueError("certificate_operation")
    return result.returncode == 0


def checked_file(path, maximum=16384):
    path = Path(path)
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        row, link = os.fstat(fd), path.lstat()
        if (not stat.S_ISREG(row.st_mode) or stat.S_ISLNK(link.st_mode)
                or row.st_nlink != 1 or (row.st_dev,row.st_ino) != (link.st_dev,link.st_ino)
                or row.st_size > maximum):
            raise ValueError("state_file")
        if os.name != "nt" and (row.st_uid not in (0,os.geteuid()) or stat.S_IMODE(row.st_mode) & 0o077):
            raise ValueError("state_permissions")
        with os.fdopen(fd, "rb") as handle:
            fd = -1
            data = handle.read(maximum + 1)
        if len(data) > maximum:
            raise ValueError("state_file")
        return data
    finally:
        if fd != -1:
            os.close(fd)


def root_check(root):
    root = Path(root)
    if not root.is_absolute() or root.is_symlink():
        raise ValueError("state_directory")
    row = root.lstat()
    if not stat.S_ISDIR(row.st_mode):
        raise ValueError("state_directory")
    if os.name != "nt" and (row.st_uid not in (0,os.geteuid()) or stat.S_IMODE(row.st_mode) & 0o077):
        raise ValueError("state_permissions")
    return root


def private_write(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(data); handle.flush(); os.fsync(handle.fileno())


def config(root):
    root = root_check(root)
    value = decode_json(checked_file(root / "receiver.json"))
    if (type(value) is not dict or set(value) != {"v","address","port","token","minute_bytes"}
            or type(value["v"]) is not int or value["v"] != 1
            or type(value["port"]) is not int or not 1024 <= value["port"] <= 65535
            or type(value["token"]) is not str or len(value["token"]) != 64
            or any(c not in "0123456789abcdef" for c in value["token"])
            or type(value["minute_bytes"]) is not int or not 32768 <= value["minute_bytes"] <= 4 * 1024 * 1024):
        raise ValueError("receiver_config")
    address = ipaddress.ip_address(value["address"])
    if address.is_unspecified or address.is_multicast:
        raise ValueError("receiver_address")
    return value


def validate_leaf(root, certificate, openssl="openssl"):
    value = config(root)
    for name in ("receiver-ca.pem","server-key.pem"):
        checked_file(root / name)
    checked_file(certificate)
    run_crypto(openssl, "verify", "-CAfile", root / "receiver-ca.pem", "-purpose", "sslserver",
               "-verify_ip", value["address"], certificate)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(str(certificate), str(root / "server-key.pem"))
    return context


def issue_leaf(root, openssl):
    value = config(root)
    checked_file(root / "authority-key.pem")
    checked_file(root / "server-key.pem")
    if not run_crypto(openssl, "x509", "-in", root / "receiver-ca.pem", "-checkend",
                      (LEAF_DAYS + 1) * 86400, "-noout", required=False):
        raise ValueError("authority_needs_replacement")
    paths = []
    try:
        for suffix in (".csr", ".ext", ".pem"):
            fd, name = tempfile.mkstemp(prefix=".renew-", suffix=suffix, dir=root)
            os.close(fd); paths.append(Path(name))
        csr, ext, certificate = paths
        ext.write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\n"
                       "extendedKeyUsage=serverAuth\nsubjectAltName=IP:" + value["address"] + "\n", encoding="ascii")
        run_crypto(openssl,"req","-new","-key",root / "server-key.pem","-out",csr,
                   "-subj","/CN=singbox-quality-receiver")
        run_crypto(openssl,"x509","-req","-in",csr,"-CA",root / "receiver-ca.pem",
                   "-CAkey",root / "authority-key.pem","-set_serial","0x" + secrets.token_hex(16),
                   "-out",certificate,"-days",LEAF_DAYS,"-sha256","-extfile",ext)
        certificate.chmod(0o600)
        validate_leaf(root, certificate, openssl)
        return certificate.read_bytes()
    finally:
        for path in paths:
            path.unlink(missing_ok=True)


def init(root, address, port=8449, openssl="openssl"):
    address = str(ipaddress.ip_address(address))
    if ipaddress.ip_address(address).is_unspecified or ipaddress.ip_address(address).is_multicast:
        raise ValueError("receiver_address")
    if type(port) is not int or not 1024 <= port <= 65535:
        raise ValueError("receiver_port")
    root = Path(root)
    if not root.is_absolute() or root.exists() or root.is_symlink():
        raise ValueError("state_exists")
    root.mkdir(mode=0o700)
    previous = os.umask(0o077)
    try:
        cfg = {"v":1,"address":address,"port":port,"token":secrets.token_hex(32),"minute_bytes":4194304}
        private_write(root / "receiver.json", json.dumps(cfg).encode())
        run_crypto(openssl,"req","-x509","-newkey","rsa:2048","-nodes",
                   "-keyout",root / "authority-key.pem","-out",root / "receiver-ca.pem",
                   "-days",ROOT_DAYS,"-subj","/CN=singbox-quality-private-authority",
                   "-addext","basicConstraints=critical,CA:TRUE,pathlen:0",
                   "-addext","keyUsage=critical,keyCertSign,cRLSign")
        run_crypto(openssl,"genpkey","-algorithm","RSA","-pkeyopt","rsa_keygen_bits:2048",
                   "-out",root / "server-key.pem")
        for name in ("authority-key.pem","receiver-ca.pem","server-key.pem"):
            (root / name).chmod(0o600)
        private_write(root / "server-cert.pem", issue_leaf(root,openssl))
        authority = (root / "receiver-ca.pem").read_bytes()
        host = "[" + address + "]" if ":" in address else address
        info = {"v":1,"endpoint":"https://%s:%d" % (host,port),"token":cfg["token"],
                "certificate_sha256":hashlib.sha256(authority).hexdigest()}
        private_write(root / "receiver-info.json",json.dumps(info).encode())
        private_write(root / "installation.json",json.dumps({"v":1,"kind":"quality-receiver-service",
                      "address":address,"port":port,"authority_sha256":info["certificate_sha256"]}).encode())
    finally:
        os.umask(previous)
    return {"prepared":True,"root_days":ROOT_DAYS,"server_certificate_days":LEAF_DAYS,"started":False}


def renew(root, openssl="openssl", force=False, restart=None):
    root = root_check(root)
    install = decode_json(checked_file(root / "installation.json"))
    value = config(root)
    if install != {"v":1,"kind":"quality-receiver-service","address":value["address"],"port":value["port"],
                   "authority_sha256":hashlib.sha256(checked_file(root / "receiver-ca.pem")).hexdigest()}:
        raise ValueError("installation_identity")
    # Serialize manual/timer renewal on the receiver host. No locking is needed
    # in Windows hermetic tests; this CLI is deployed only on systemd/Linux.
    import contextlib
    with contextlib.ExitStack() as lock:
        if os.name == "posix":
            import fcntl
            fd = os.open(root / "renew.lock",os.O_WRONLY|os.O_CREAT|getattr(os,"O_NOFOLLOW",0),0o600)
            lock.callback(os.close,fd)
            row=os.fstat(fd)
            if not stat.S_ISREG(row.st_mode) or row.st_nlink != 1 or row.st_uid != os.geteuid():
                raise ValueError("renew_lock")
            fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        marker = root / "restart-needed"
        marker_bytes = b"quality-receiver-restart-v1\n"
        if marker.exists() or marker.is_symlink():
            if checked_file(marker) != marker_bytes:
                raise ValueError("restart_marker")
        def completed(result):
            if restart is not None and marker.exists():
                restart() # failed restarts leave a durable retry for the next timer run
                marker.unlink()
            return result
        checked_file(root / "server-cert.pem")
        if not force and run_crypto(openssl,"x509","-in",root / "server-cert.pem","-checkend",
                                     RENEW_BEFORE,"-noout",required=False):
            validate_leaf(root, root / "server-cert.pem", openssl)
            return completed({"renewed":False})
        data = issue_leaf(root,openssl)
        # Mark before publication so a crash or failed restart cannot strand an
        # old in-memory certificate until the next renewal threshold.
        if not marker.exists():
            private_write(marker, marker_bytes)
        fd,name=tempfile.mkstemp(prefix=".published-",dir=root)
        temporary=Path(name)
        try:
            with os.fdopen(fd,"wb") as handle:
                handle.write(data);handle.flush();os.fsync(handle.fileno())
            os.replace(temporary,root / "server-cert.pem")
        finally:
            temporary.unlink(missing_ok=True)
        # CA bytes, token, port and client info never rotate on ordinary renewal.
        return completed({"renewed":True,"server_certificate_days":LEAF_DAYS})


def serve(credentials, openssl="openssl"):
    root=root_check(credentials); value=config(root)
    context=validate_leaf(root,root / "server-cert.pem",openssl)
    listen="::" if ":" in value["address"] else "0.0.0.0"
    with Server((listen,value["port"]),value["token"],context,value["minute_bytes"]) as server:
        print('{"receiver":"ready","mode":"persistent"}',flush=True)
        server.serve_forever()


def check(root):
    root=root_check(root);value=config(root)
    context=ssl.create_default_context(cafile=str(root / "receiver-ca.pem"))
    loopback="::1" if ":" in value["address"] else "127.0.0.1"
    nonce=secrets.token_hex(16)
    with socket.create_connection((loopback,value["port"]),timeout=3) as connection:
        with context.wrap_socket(connection,server_hostname=value["address"]) as tls:
            tls.settimeout(3)
            header="GET /quality-v1/ready HTTP/1.1\r\nHost: receiver\r\nAuthorization: Bearer " + value["token"]
            tls.sendall((header+"\r\nX-Probe-Nonce: "+nonce+"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").encode())
            response=http.client.HTTPResponse(tls);response.begin()
            result=decode_json(response.read(1025))
            if response.status!=200 or result!={"v":1,"nonce":nonce,"bytes":0,
                    "sha256":hashlib.sha256(b"").hexdigest(),"measured_bytes":0,"upload_seconds":0}:
                raise ValueError("readiness_receipt")
    return {"receiver_tls_and_token_verified":True}
