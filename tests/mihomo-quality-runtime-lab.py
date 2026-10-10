#!/usr/bin/env python3
"""Opt-in loopback lab: pinned Mihomo, generated groups/listeners, real TLS uploads.
SOCKS relays model protocol paths. No real Reality/HY2 or ISP outage is claimed.
"""
import argparse
import hashlib
import http.client
import http.server
import importlib.util
import os
from pathlib import Path
import socket
import socketserver
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/"tools"))
from quality_failover.controller import Controller
from quality_failover.policy import AUTO, GROUP, OUTER, Engine, Policy, Ownership, Confirmation
from quality_failover.receiver import Server
from quality_failover.transport import Probe


def load(path, name):
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module); return module


fixtures=load(ROOT/"tests/test_quality_failover.py","quality_fixtures")


def port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1",0)); return sock.getsockname()[1]


class Relay(socketserver.ThreadingTCPServer):
    allow_reuse_address=True
    daemon_threads=True

    def __init__(self, allowed):
        self.allowed, self.up, self.rate, self.connects = allowed, True, 0, 0
        self.targets, self.route_map, self.name = {}, {}, ""
        super().__init__(("127.0.0.1",0),RelayHandler)

    def handle_error(self,*args):
        pass


class RelayHandler(socketserver.BaseRequestHandler):
    def exact(self,n):
        body=b""
        while len(body)<n:
            chunk=self.request.recv(n-len(body))
            if not chunk: raise OSError()
            body+=chunk
        return body

    def handle(self):
        sock=self.request
        try:
            sock.settimeout(4)
            head=self.exact(2); self.exact(head[1]); sock.sendall(b"\x05\x00")
            request=self.exact(4)
            if request[:3]!=b"\x05\x01\x00": return
            if request[3]==1: host=socket.inet_ntoa(self.exact(4))
            elif request[3]==3: host=self.exact(self.exact(1)[0]).decode()
            else: return
            target=(host,struct.unpack(">H",self.exact(2))[0])
            if target not in self.server.allowed or not self.server.up:
                sock.sendall(b"\x05\x01\x00\x01"+b"\0"*6); return
            upstream=socket.create_connection(target,timeout=3)
            self.server.connects+=1
            self.server.targets[target]=self.server.targets.get(target,0)+1
            self.server.route_map[upstream.getsockname()[1]]=self.server.name
            sock.sendall(b"\x05\x00\x00\x01"+b"\0"*6)
            sock.settimeout(10); upstream.settimeout(10)
            def pump(src,dst,rate=0):
                try:
                    while True:
                        data=src.recv(8192)
                        if not data: break
                        if rate: time.sleep(len(data)*8/rate/1e6)
                        dst.sendall(data)
                except OSError: pass
                finally:
                    try: dst.shutdown(socket.SHUT_WR)
                    except OSError: pass
            sender=threading.Thread(target=pump,args=(sock,upstream,self.server.rate),daemon=True)
            sender.start(); pump(upstream,sock); sender.join(timeout=10); upstream.close()
        except OSError: pass


class Origin(http.server.BaseHTTPRequestHandler):
    def log_message(self,*args): pass

    def do_HEAD(self):
        self.send_response(204); self.send_header("Content-Length","0"); self.end_headers()

    def do_GET(self):
        if self.path=="/hold":
            self.send_response(200); self.send_header("Content-Length","9"); self.end_headers()
            self.wfile.write(b"begin"); self.wfile.flush()
            self.server.release.wait(15)
            self.wfile.write(b"done")
        else:
            body=self.server.route_map.get(self.client_address[1], "direct").encode()
            self.send_response(200); self.send_header("Content-Length",str(len(body))); self.end_headers()
            self.wfile.write(body)


def wait(fn, timeout=15):
    end=time.monotonic()+timeout
    while time.monotonic()<end:
        if fn(): return
        time.sleep(.2)
    raise AssertionError("lab deadline")


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--mihomo",required=True)
    parser.add_argument("--expect-sha256",required=True)
    parser.add_argument("--openssl",required=True)
    args=parser.parse_args()
    binary=Path(args.mihomo).resolve()
    if hashlib.sha256(binary.read_bytes()).hexdigest()!=args.expect_sha256:
        raise SystemExit("lab: binary digest mismatch")
    checks=[]
    def check(name,condition):
        if not condition: raise AssertionError(name)
        checks.append(name); print("PASS "+name,flush=True)
    with tempfile.TemporaryDirectory(prefix="quality-loopback-") as directory:
        base=Path(directory); certificate,key=base/"cert.pem",base/"key.pem"
        subprocess.run([args.openssl,"req","-x509","-newkey","rsa:2048","-nodes",
            "-keyout",str(key),"-out",str(certificate),"-days","1","-subj","/CN=127.0.0.1",
            "-addext","subjectAltName=IP:127.0.0.1"],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        key.chmod(0o600)
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); context.load_cert_chain(certificate,key)
        sink=Server(("127.0.0.1",0),"a"*32,context,minute_bytes=4*1024*1024)
        origin=http.server.ThreadingHTTPServer(("127.0.0.1",0),Origin)
        origin.daemon_threads=True; origin.release=threading.Event()
        allowed={sink.server_address,origin.server_address}
        relays=[Relay(allowed),Relay(allowed)]
        origin.route_map={}
        for name, relay in zip(("Reality","Hysteria2"),relays):
            relay.name, relay.route_map=name,origin.route_map
        for server in [sink,origin,*relays]:
            threading.Thread(target=server.serve_forever,daemon=True).start()
        controller_port,mixed_port=port(),port()
        cfg=fixtures.configuration()
        cfg["controller"]=f"http://127.0.0.1:{controller_port}"
        for item in cfg["paths"]:
            item.update(listener_port=port(),endpoint=f"https://127.0.0.1:{sink.server_port}",
                        ca_file=str(certificate),payload_bytes=262144,rate_mbps=12)
        export=base/"event-mihomo.yaml"; fixtures.export(export,hopping=True)
        prepared=base/"quality.yaml"
        fixtures.CLI.prepare("event",str(export),None,str(prepared),cfg)
        text=prepared.read_text(encoding="utf-8")
        listeners=text[text.index("listeners:"):text.index("proxies:\n")]
        groups=text[text.index("proxy-groups:"):text.index("rules:\n")]
        groups=groups.replace('https://www.gstatic.com/generate_204',
                             f"http://127.0.0.1:{origin.server_port}/hc").replace(
                                 "    interval: 60","    interval: 1").replace(
                                 "    timeout: 5000","    timeout: 500")
        lab=[f"mixed-port: {mixed_port}","allow-lan: false","mode: rule","log-level: silent",
             f"external-controller: 127.0.0.1:{controller_port}",'secret: "synthetic-controller-secret-only"',
             "profile:","  store-selected: true",listeners,"proxies:"]
        for name,relay in zip(("Reality","Hysteria2"),relays):
            lab.extend([f"  - name: {name}","    type: socks5","    server: 127.0.0.1",
                        f"    port: {relay.server_address[1]}"])
        lab.extend([groups,"rules:","  - MATCH,节点选择",""])
        labfile=base/"lab.yaml"; labfile.write_text("\n".join(lab),encoding="utf-8")
        (base/"data").mkdir()
        process=None
        try:
            subprocess.run([str(binary),"-t","-d",str(base/"data"),"-f",str(labfile)],
                           check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=20)
            check("generated quality groups and forced SOCKS listeners parse in pinned core",True)
            process=subprocess.Popen([str(binary),"-d",str(base/"data"),"-f",str(labfile)],
                                     stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            controller=Controller(cfg["controller"],cfg["controller_secret"])
            def ready():
                try:
                    return controller.proxies().get("Reality",{}).get("alive") is True
                except (OSError,ValueError): return False
            wait(ready)
            proxies=controller.proxies()
            check("fresh profile preserves legacy automatic default",proxies[OUTER]["now"]==AUTO)
            check("quality group hidden with automatic starting point",proxies[GROUP]["hidden"] is True
                  and proxies[GROUP]["fixed"]=="")
            controller.request("PUT","/proxies/%E8%8A%82%E7%82%B9%E9%80%89%E6%8B%A9",{"name":GROUP})
            owner=Ownership(("Reality","Hysteria2"))
            check("core exposes fixed-selection ownership discriminator",owner.permitted(controller.proxies()))
            probes={entry["name"]:Probe(entry["endpoint"],entry["token"],entry["ca_file"],
                entry["payload_bytes"],entry["rate_mbps"],entry["timeout_seconds"]) for entry in cfg["paths"]}
            ports={entry["name"]:entry["listener_port"] for entry in cfg["paths"]}
            def measure(name):
                index=list(probes).index(name)
                probe=probes[name]
                return probe.measure(ports[name],verifier=lambda source_port: controller.confirm_route(
                    name,"quality-probe-%d"%index,source_port,probe.host,probe.port))
            engine=Engine({name:Policy(4,8,hold_seconds=30) for name in probes})
            relays[0].rate=1
            for at in (0,30):
                real=measure("Reality")
                hy=measure("Hysteria2")
                check(f"TLS upload confirms Reality poor while HY2 good sample {at}",
                      real.endpoint_ready and real.mbps is not None and real.mbps<4
                      and hy.endpoint_ready and hy.mbps>=8)
                engine.update(at,{"Reality":(True,real),"Hysteria2":(True,hy)})
            check("tiny reachability remains healthy on upload-shaped Reality",
                  controller.proxies()["Reality"]["alive"] is True)
            check("quality policy selects HY2 despite passing liveness",
                  engine.target(30,"Reality")=="Hysteria2")
            check("only dedicated group changed",controller.select("Hysteria2",owner)
                  and controller.proxies()[GROUP]["now"]=="Hysteria2"
                  and controller.proxies()[AUTO]["fixed"]=="")
            # Force Reality probe while ordinary traffic is pinned elsewhere.
            controller.request("PUT","/proxies/%E8%8A%82%E7%82%B9%E9%80%89%E6%8B%A9",{"name":"DIRECT"})
            previous=[r.targets.get(sink.server_address,0) for r in relays]
            measure("Reality")
            check("forced upload cannot fall through DIRECT or HY2",
                  relays[0].targets.get(sink.server_address,0)>previous[0]
                  and relays[1].targets.get(sink.server_address,0)==previous[1])
            check("outer manual selection blocks control",not controller.select("Reality",owner)
                  and controller.proxies()[OUTER]["now"]=="DIRECT")
            controller.restore(owner)
            check("stop restores owned default and preserves outer manual choice",
                  controller.proxies()[GROUP]["fixed"]=="" and controller.proxies()[OUTER]["now"]=="DIRECT")
            relays[0].rate=0
            for at in (60,90,120):
                sample=measure("Reality")
                engine.update(at,{"Reality":(True,sample),"Hysteria2":(True,None)})
            check("recovery makes primary available without displacing healthy HY2",engine.paths["Reality"].state=="UP" and engine.target(120,"Hysteria2") is None)
            controller.request("PUT","/proxies/%E8%8A%82%E7%82%B9%E9%80%89%E6%8B%A9",{"name":GROUP})
            check("recovered path selected in dedicated group",controller.select("Reality",owner))
            from quality_failover.transport import socks_connect
            hold=socks_connect(mixed_port,"127.0.0.1",origin.server_port,time.monotonic()+3)
            hold.sendall(b"GET /hold HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            held=http.client.HTTPResponse(hold); held.begin()
            check("established flow began on Reality",held.read(5)==b"begin")
            check("live owned group switch succeeds",controller.select("Hysteria2",owner))
            connections=controller.request("GET","/connections")["connections"]
            check("existing flow keeps its Reality chain",any(
                item.get("metadata",{}).get("destinationPort")==str(origin.server_port)
                and "Reality" in item.get("chains",[]) for item in connections))
            fresh=socks_connect(mixed_port,"127.0.0.1",origin.server_port,time.monotonic()+3)
            fresh.sendall(b"GET /who HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            newer=http.client.HTTPResponse(fresh); newer.begin()
            check("new flow follows HY2 selection",newer.read()==b"Hysteria2")
            fresh.close(); origin.release.set()
            check("established connection completes without migration",held.read()==b"done")
            hold.close()
            controller.restore(owner)
            process.terminate(); process.wait(timeout=5)
            process=subprocess.Popen([str(binary),"-d",str(base/"data"),"-f",str(labfile)],
                                     stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            wait(ready)
            check("normal stop/restart leaves owned group automatic",controller.proxies()[GROUP]["fixed"]=="")
            check("outer quality opt-in survives ordinary core restart",controller.proxies()[OUTER]["now"]==GROUP)
            controller.select("Hysteria2", owner)
            relays[1].up=False
            wait(lambda: controller.proxies()[GROUP]["now"] == "Reality")
            check("native hard fallback works without quality worker intervention",
                  controller.proxies()[GROUP]["now"] == "Reality"
                  and controller.proxies()[GROUP]["fixed"] == "")
            wait(lambda: controller.proxies()["Hysteria2"]["alive"] is False)
            real=measure("Reality")
            other=Engine({name:Policy(4,8,hold_seconds=30) for name in probes})
            other.update(0,{"Reality":(True,real),"Hysteria2":(False,None)})
            check("opposite case never sends healthy Reality to broken HY2",
                  other.paths["Hysteria2"].state=="DOWN" and other.target(0,"Reality") is None)
            check("hopping bytes preserved before lab substitutions",
                  "    ports: 40000-40100" in text and "    hop-interval: 30" in text)
            print(f"lab: PASS {len(checks)} checks; loopback mock paths only",flush=True)
        finally:
            origin.release.set()
            if process is not None:
                process.terminate()
                try: process.wait(timeout=5)
                except subprocess.TimeoutExpired: process.kill(); process.wait(timeout=5)
            for server in [sink,origin,*relays]:
                server.shutdown(); server.server_close()


if __name__=="__main__":
    main()
