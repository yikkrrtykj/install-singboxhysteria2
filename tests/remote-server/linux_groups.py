#!/usr/bin/env python3
"""Fail-closed Linux authority gates. Must run as root with real sboxweb."""
import grp
import hashlib
import os
import stat
import sys
from unittest.mock import patch

import server_groups as h
from web.remote_registry import RemoteRegistry
from web.remote_store import RemoteStore


def main():
    if sys.platform != "linux" or os.geteuid() != 0:
        raise SystemExit("Linux authority gates require real Linux root; no SKIP/PASS fallback")
    gid = grp.getgrnam("sboxweb").gr_gid
    out = {}
    for case in ("config_uid", "config_gid", "config_mode", "config_symlink", "config_fifo",
                 "key_uid", "key_gid", "key_mode", "key_symlink", "key_fifo", "key_directory",
                 "dir_uid", "dir_gid", "dir_mode", "dir_symlink", "binary_key", "oversized_key"):
        cfg,kd = h.registry_fixture(configs={h.PROBE:(True,"site-a","path-a"),h.PROBE_B:(True,"site-b","path-b")})
        root = os.path.dirname(cfg)
        key = os.path.join(kd,h.PROBE+".key")
        obj = cfg if case.startswith("config_") else kd if case.startswith("dir_") else key
        try:
            if case.endswith("_uid"):
                os.chown(obj,1,gid)
            elif case.endswith("_gid"):
                os.chown(obj,0,gid+1)
            elif case.endswith("_mode"):
                os.chmod(obj,0o777)
            elif case.endswith("_symlink"):
                os.rename(obj,obj+".real")
                os.symlink(obj+".real",obj)
            elif case.endswith("_fifo"):
                os.unlink(obj)
                os.mkfifo(obj,0o640)
                os.chown(obj,0,gid)
            elif case == "key_directory":
                os.unlink(key)
                os.mkdir(key)
            elif case == "binary_key":
                with open(key,"wb") as f:
                    f.write(b'\xff'*64)
            else:
                with open(key,"wb") as f:
                    f.write(b' '*4096+h.KEY_HEX.encode())
            registry = RemoteRegistry(cfg,kd)
            rejected = registry.lookup(h.PROBE) is None and registry.health() == (
                "degraded","remote_config_invalid")
            if case.startswith("key_") or case in ("binary_key","oversized_key"):
                rejected = rejected and registry.lookup(h.PROBE_B) is not None
            out[case+"_contained"] = rejected
            if case == "binary_key":
                factory = RemoteRegistry
                with patch("web.remote_registry.RemoteRegistry",side_effect=lambda:factory(cfg,kd)):
                    plane = h.RemoteIngest(root,clock=lambda:h.NOW)
                try:
                    out["binary_key_remote_startup_contained"] = (
                        plane.status()["subcode"] == "remote_config_invalid"
                        and plane.registry.lookup(h.PROBE_B) is not None)
                finally:
                    plane.close()
        finally:
            h.clean(root)
    # Real rename races exercise same-object checks without bypassing ownership.
    for case in ("config_swap","key_swap","directory_swap"):
        cfg,kd = h.registry_fixture()
        key = os.path.join(kd,h.PROBE+".key")
        original_open = os.open
        target = cfg if case == "config_swap" else kd if case == "directory_swap" else h.PROBE+".key"
        changed = [False]
        def swapping_open(path,*args,**kwargs):
            if path == target and not changed[0]:
                changed[0] = True
                absolute = key if case == "key_swap" else target
                os.rename(absolute,absolute+".old")
                if case == "directory_swap":
                    os.mkdir(absolute,0o750)
                else:
                    with open(absolute+".old","rb") as f:
                        data = f.read()
                    with open(absolute,"wb") as f:
                        f.write(data)
                    os.chmod(absolute,0o640)
                os.chown(absolute,0,gid)
            return original_open(path,*args,**kwargs)
        try:
            with patch("web.remote_registry.os.open",side_effect=swapping_open):
                registry = RemoteRegistry(cfg,kd)
            out[case+"_same_object_refused"] = changed[0] and registry.lookup(h.PROBE) is None
        finally:
            h.clean(os.path.dirname(cfg))
    root = h.temp_dir()
    store = RemoteStore(root,clock=lambda:h.NOW).open()
    try:
        out["store_real_0700_and_0600"] = stat.S_IMODE(os.stat(store.directory).st_mode) == 0o700 and stat.S_IMODE(os.stat(store.db_path).st_mode) == 0o600
        store.close()
        original = open(store.db_path,"rb").read()
        os.rename(store.db_path,store.db_path+".real")
        os.symlink(store.db_path+".real",store.db_path)
        from store_groups import refused
        from web.remote_store import RemoteStoreError
        out["store_symlink_db_refused_without_target_mutation"] = refused(
            lambda:RemoteStore(root).open(),RemoteStoreError) and open(store.db_path+".real","rb").read() == original
        os.unlink(store.db_path)
        os.rename(store.db_path+".real",store.db_path)
        os.rename(store.directory,store.directory+".real")
        os.symlink(store.directory+".real",store.directory)
        out["store_symlink_directory_refused"] = refused(lambda:RemoteStore(root).open(),RemoteStoreError)
        os.unlink(store.directory)
        os.rename(store.directory+".real",store.directory)
    finally:
        store.close()
        h.clean(root)
    passed = 0
    for name,verdict in sorted(out.items()):
        print(("PASS" if verdict else "FAIL")+" linux/"+name)
        passed += verdict is True
    print("Linux authority checks: %d passed, %d failed (expected 24)" % (passed,len(out)-passed))
    return 0 if passed == len(out) == 24 else 1


if __name__ == "__main__":
    sys.exit(main())
