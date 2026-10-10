#!/usr/bin/env python3
"""Manual persistent receiver administration; private values never appear in output."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
sys.path.insert(0,str(Path(__file__).resolve().parent))
from quality_failover import persistent


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("mode",choices=("init","renew","serve","check"))
    parser.add_argument("--root",default="/etc/singbox-quality-receiver")
    parser.add_argument("--address")
    parser.add_argument("--port",type=int,default=8449)
    parser.add_argument("--restart",action="store_true")
    args=parser.parse_args()
    try:
        if args.mode != "serve" and (not hasattr(os,"geteuid") or os.geteuid()!=0):
            raise ValueError("root_required")
        if args.mode=="init":
            if not args.address or args.restart: raise ValueError("usage")
            result=persistent.init(Path(args.root),args.address,args.port)
        elif args.mode=="renew":
            def restart():
                subprocess.run(["/bin/systemctl","try-restart",persistent.SERVICE],check=True,timeout=30,
                               stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            result=persistent.renew(Path(args.root),restart=restart if args.restart else None)
        elif args.mode=="check":
            if args.restart: raise ValueError("usage")
            result=persistent.check(Path(args.root))
        else:
            if args.restart: raise ValueError("usage")
            credentials=os.environ.get("CREDENTIALS_DIRECTORY")
            if not credentials: raise ValueError("credentials_missing")
            persistent.serve(Path(credentials));return 0
        print(json.dumps(result),flush=True);return 0
    except Exception:
        print('[FAIL] Receiver operation incomplete; private data not displayed',file=sys.stderr);return 1


if __name__=="__main__":
    raise SystemExit(main())
