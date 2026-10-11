#!/usr/bin/env python3
"""Windows signature-gated generic software input for the root publisher."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('quality_packager',ROOT/'tools/package-quality-windows.py')
packager=importlib.util.module_from_spec(spec);spec.loader.exec_module(packager)


def build(exe, output):
    exe,output=Path(exe),Path(output)
    if exe.is_symlink() or not exe.is_file() or not 1024 <= exe.stat().st_size <= 16*1024*1024:
        raise ValueError('software')
    packager.check_signature(exe)
    raw=exe.read_bytes()
    notices=(ROOT/'tools/quality-windows-notices.txt').read_bytes()
    record=lambda value:{'sha256':hashlib.sha256(value).hexdigest(),'size':len(value)}
    manifest={'v':1,'publisher':packager.PUBLISHER,'software':record(raw),'notices':record(notices)}
    output.mkdir(exist_ok=False)
    for name,value in (('quality.exe',raw),('notices.txt',notices),('software.json',json.dumps(manifest,sort_keys=True,separators=(',',':')).encode())):
        with (output/name).open('xb') as stream:stream.write(value)
    return {'prepared':True,'signature_verified':True,'publisher':packager.PUBLISHER,'software_sha256':record(raw)['sha256']}


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--exe',required=True);parser.add_argument('--output',required=True)
    args=parser.parse_args()
    print(json.dumps(build(args.exe,args.output)))
