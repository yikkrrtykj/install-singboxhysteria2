#!/usr/bin/env python3
"""Generate a SYNTHETIC Phase A evidence set, used only by tests/selftest.sh.

This is not runtime data and is not a claim about real sing-box behaviour:

* every generated file carries a "_fixture" marker and lib/analyze.py ignores
  such files unless --fixture-mode is passed;
* the Hysteria2 connections deliberately carry **no** user field so the negative
  ("NO") path can be exercised. That says nothing about what the real API
  returns -- only a run against a real server can answer that;
* the ``-closed`` snapshots deliberately report zeroed counters with no
  connections, so a regression that starts using them for byte math would show up
  as a failing direction verdict instead of silently passing.

Usage:
    make-synthetic.py --out DIR [--variant consistent|inverted]

  consistent  client downloads grow the download-ish counter (the ordinary case)
  inverted    client downloads grow the upload-ish counter, which must make the
              analyzer report that field naming is opposite to the client view
"""

import argparse
import json
import os

MARK = "SYNTHETIC - NOT RUNTIME DATA (tests/fixtures/make-synthetic.py)"
N = 67108864
QUARTER = N // 4
HALF = N // 2
PUBLIC_SOURCE_IP = "203.0.113.9"


def connection(cid, proto, user, upload, download, source_ip="127.0.0.1"):
    metadata = {
        "network": "udp" if proto == "hy2" else "tcp",
        "type": "hysteria2" if proto == "hy2" else "vless",
        "sourceIP": source_ip,
        "sourcePort": "51000",
        "destinationIP": "127.0.0.1",
        "destinationPort": "18080",
        "host": "",
        "inbound": "hysteria2/probe-hy2-in" if proto == "hy2" else "vless/probe-reality-in",
        "rule": "final",
        "rulePayload": "",
    }
    if user:
        metadata["inboundUser"] = user
    return {
        "id": cid,
        "upload": upload,
        "download": download,
        "start": "2026-09-11T00:00:00Z",
        "chains": ["direct"],
        "metadata": metadata,
    }


def write_json(path, payload):
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", required=True)
    parser.add_argument("--variant", choices=("consistent", "inverted"), default="consistent")
    args = parser.parse_args()
    out = args.out
    os.makedirs(out, exist_ok=True)
    inverted = args.variant == "inverted"

    def snap(label, connections, upload_total, download_total):
        write_json(os.path.join(out, "%s.connections.json" % label),
                   {"_fixture": MARK, "uploadTotal": upload_total,
                    "downloadTotal": download_total, "connections": connections})

    def curl(label, mode, requested):
        key = "bytes_downloaded" if mode == "download" else "bytes_uploaded"
        write_json(os.path.join(out, "%s-curl.json" % label),
                   {"_fixture": MARK, "mode": mode, "requested_bytes": requested,
                    key: requested, "speed_bps": 4194304, "http_code": 200})
        # Same three-file evidence contract as the runtime collector:
        # machine-readable JSON + stderr + exit code, all persistent.
        with open(os.path.join(out, "%s-curl.err" % label), "w", encoding="utf-8") as handle:
            handle.write("")
        with open(os.path.join(out, "%s-curl.rc" % label), "w", encoding="utf-8") as handle:
            handle.write("0\n")

    for proto in ("reality", "hy2"):
        user = None if proto == "hy2" else "probe-a"
        tag = "r" if proto == "reality" else "h"
        dl_grow = "upload" if inverted else "download"
        ul_grow = "download" if inverted else "upload"

        def grow(counter, amount):
            return (amount if counter == "upload" else 0, amount if counter == "download" else 0)

        # --- single-direction download test ---------------------------------
        snap("%s-dl-pre" % proto, [], 0, 0)
        for step, amount in enumerate((QUARTER, HALF, N), start=1):
            pos_up, pos_down = grow(dl_grow, amount)
            snap("%s-dl-s%02d" % (proto, step),
                 [connection("%s-dl" % tag, proto, user, pos_up, pos_down)], pos_up, pos_down)
        # No connections left and zeroed counters: must never be used for byte math.
        snap("%s-dl-closed" % proto, [], 0, 0)
        curl("%s-dl" % proto, "download", N)

        # --- single-direction upload test -----------------------------------
        base_up, base_down = grow(dl_grow, N)
        snap("%s-ul-pre" % proto, [], base_up, base_down)
        for step, amount in enumerate((QUARTER, HALF, N), start=1):
            up, down = grow(ul_grow, amount)
            snap("%s-ul-s%02d" % (proto, step),
                 [connection("%s-ul" % tag, proto, user, up, down)],
                 base_up + up, base_down + down)
        snap("%s-ul-closed" % proto, [], 0, 0)
        curl("%s-ul" % proto, "upload", N)

        # --- concurrent two-user attribution test (half payload each) -------
        up, down = grow(ul_grow, N)
        base_up, base_down = base_up + up, base_down + down
        snap("%s-ab-pre" % proto, [], base_up, base_down)
        for step, amount in enumerate((QUARTER, HALF), start=1):
            conns = [
                connection("%s-ab-a" % tag, proto, "probe-a" if proto == "reality" else None, 0, amount),
                connection("%s-ab-b" % tag, proto, "probe-b" if proto == "reality" else None, 0, amount),
            ]
            snap("%s-ab-s%02d" % (proto, step), conns, base_up, base_down + amount * 2)
        snap("%s-ab-closed" % proto, [], base_up, base_down + HALF * 2)
        curl("%s-ab-a" % proto, "download", HALF)
        curl("%s-ab-b" % proto, "download", HALF)

    # An extra snapshot, as produced by `collect` after external clients ran, so the
    # analyzer's non-loopback source-IP path gets exercised for Reality only.
    snap("reality-external", [connection("r-ext", "reality", "probe-a", 0, 1024,
                                         source_ip=PUBLIC_SOURCE_IP)], 0, 1024)

    snap("version-prep", [], 0, 0)
    write_json(os.path.join(out, "version-prep.traffic.json"), {"_fixture": MARK, "up": 1234, "down": 5678})
    write_json(os.path.join(out, "version-prep.memory.json"), {"_fixture": MARK, "inuse": 1, "oslimit": 2})
    write_json(os.path.join(out, "00-api-version.json"),
               {"_fixture": MARK, "version": "1.14.0-synthetic", "meta": True})
    write_json(os.path.join(out, "meta.json"), {
        "collected_at": "2026-09-11T00:00:00+00:00",
        "production_version": "1.14.0-synthetic",
        "expose": 1,
        "reality_port": 18443,
        "hy2_port": 18444,
        "clash_api": "127.0.0.1:19090",
        "reality_tag": "probe-reality-in",
        "hy2_tag": "probe-hy2-in",
        "user_a": "probe-a",
        "user_b": "probe-b",
        "payload_bytes": N,
        "transfer_rate_bps": 4194304,
    })
    baseline = [
        "version: 1.14.0-synthetic",
        "service_state: active",
        "main_pid: 4242",
        "sha256 /root/sbox/sbconfig_server.json: deadbeef",
        "sha256 /root/sbox/config: cafe",
        "sha256 /root/sbox/sing-box: 1234",
        "hy_hopping(sed): FALSE",
    ]
    with open(os.path.join(out, "00-production-before.txt"), "w", encoding="utf-8") as handle:
        handle.write("\n".join(baseline + ["listening_ports:", "  0.0.0.0:443"]) + "\n")
    with open(os.path.join(out, "90-production-after.txt"), "w", encoding="utf-8") as handle:
        # the probe legitimately adds listeners, so the port list differs on purpose
        handle.write("\n".join(baseline + ["listening_ports:", "  0.0.0.0:443", "  0.0.0.0:18443"]) + "\n")
    print("synthetic fixture set written to %s (variant=%s)" % (out, args.variant))


if __name__ == "__main__":
    main()
