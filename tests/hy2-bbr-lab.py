#!/usr/bin/env python3
"""Execute real installer templates and loopback HY2 interoperability; no host installs."""
import argparse
import copy
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import time
from urllib.parse import parse_qs, urlsplit
import yaml

ROOT=Path(__file__).resolve().parents[1]


def run(args, **kwargs):
    result=subprocess.run([str(x) for x in args],capture_output=True,text=True,timeout=60,**kwargs)
    if result.returncode:raise AssertionError((args,result.stdout[-3000:],result.stderr[-3000:]))
    return result.stdout


def port(kind=socket.SOCK_STREAM):
    with socket.socket(socket.AF_INET,kind) as sock:
        sock.bind(('127.0.0.1',0));return sock.getsockname()[1]


def wait_port(number, process):
    for _ in range(100):
        if process.poll() is not None:raise AssertionError('test process exited before readiness')
        try:
            with socket.create_connection(('127.0.0.1',number),timeout=.1):return
        except OSError:time.sleep(.1)
    raise AssertionError('loopback readiness timed out')


def templates(home, binary, bash, mihomo, geoip=None):
    text=(ROOT/'install.sh').read_text()
    block=re.search(r'#generate singbox server config\n(.*?\nEOF\n)',text,re.S).group(1)
    fn=text.split('show_client_configuration() {',1)[1]
    end='# >>> phase-c client-management >>>' if (ROOT/'lib/client-management.sh').exists() else 'NETWORK_SYSCTL_FILE='
    fn='show_client_configuration() {'+fn.split(end,1)[0]
    def exported_function(name):
        start=text.index(name+'() {')
        stop=re.search(r'^}\s*$',text[start:],re.M).end()+start
        return text[start:stop]+'\n'
    keys=run([binary,'generate','reality-keypair'])
    private=re.search(r'PrivateKey:\s*(\S+)',keys).group(1)
    public=re.search(r'PublicKey:\s*(\S+)',keys).group(1)
    fixtures={'reality_port':str(port()),'hy_port':str(port(socket.SOCK_DGRAM)),
              'reality_uuid':run([binary,'generate','uuid']).strip(),'private_key':private,'public_key':public,
              'short_id':'0123456789abcdef','hy_password':'synthetic-hy2-password',
              'reality_server_name':'localhost','hy_server_name':'localhost','monitor_api_secret':'synthetic-local-api-secret'}
    (home/'self-cert').mkdir()
    run(['openssl','req','-x509','-newkey','ec','-pkeyopt','ec_paramgen_curve:prime256v1','-nodes','-days','1',
         '-keyout',home/'self-cert/private.key','-out',home/'self-cert/cert.pem','-subj','/CN=localhost'])
    prefix='set -eo pipefail\n'+''.join(k+'='+shlex.quote(v)+'\n' for k,v in fixtures.items())
    script=home/'generate.sh';script.write_text(prefix+block.replace('/root/sbox',home.as_posix()))
    run([bash,script.as_posix()])
    original=json.loads((home/'sbconfig_server.json').read_bytes())
    assert [x['type'] for x in original['inbounds']]==['vless','hysteria2']
    hy=original['inbounds'][1]
    assert hy['ignore_client_bandwidth'] is True and not {'up_mbps','down_mbps'}&hy.keys()
    assert hy['listen_port']==int(fixtures['hy_port']) and hy['users'][0]['password']==fixtures['hy_password']
    reality=original['inbounds'][0]
    assert reality['listen_port']==int(fixtures['reality_port'])
    assert reality['users'][0]['uuid']==fixtures['reality_uuid']
    assert reality['tls']['reality']['private_key']==private
    assert reality['tls']['reality']['short_id']==[fixtures['short_id']]
    run([binary,'check','-c',home/'sbconfig_server.json'])
    # The documented opt-in jq migration changes only the intended HY2 fields.
    legacy=copy.deepcopy(original)
    legacy_hy=legacy['inbounds'][1]
    legacy_hy.pop('ignore_client_bandwidth');legacy_hy.update(up_mbps=1000,down_mbps=1000)
    old_file=home/'old-server.json';old_file.write_text(json.dumps(legacy))
    migrated=json.loads(run(['jq','(.inbounds[] | select(.type == "hysteria2")) |= (del(.up_mbps,.down_mbps) + {ignore_client_bandwidth:true})',old_file]))
    assert migrated==original,'manual migration changed unrelated config'
    helper='info() { :; }; hint() { :; }; warning() { :; }; show_notice() { :; }; qrencode() { :; }; error() { echo "$*" >&2; return 1; }\n'
    if (ROOT/'lib/client-management.sh').exists():
        helper+='export SB_SERVER_CONFIG='+shlex.quote(str(home/'sbconfig_server.json'))+'\nexport SB_STATE_FILE='+shlex.quote(str(home/'config'))+'\n'
        helper+='source '+shlex.quote((ROOT/'lib/client-management.sh').as_posix())+'\n'+exported_function('write_mihomo_template')
    if geoip:
        (home/'yaml-check').mkdir()
        shutil.copyfile(geoip,home/'yaml-check/geoip.metadb')
    variants=[]
    for ipv6 in (False,True):
        for hopping in (False,True):
            address='::1' if ipv6 else '127.0.0.1'
            (home/'config').write_text(f"SERVER_IP='{address}'\nPUBLIC_KEY='{public}'\nHY_SERVER_NAME='localhost'\nHY_HOPPING={'TRUE' if hopping else 'FALSE'}\nHY_HOPPING_START=20000\nHY_HOPPING_END=20010\n")
            script.write_text('set -eo pipefail\nPERSONAL_REPO_RAW_URL=https://example.invalid\n'+helper+fn.replace('/root/sbox',home.as_posix())+'\nshow_client_configuration\n')
            output=run([bash,script.as_posix()])
            client=json.loads((home/'sbconfig_client.json').read_bytes())
            clash=yaml.safe_load((home/'mihomo_client.yaml').read_text())
            node=next(x for x in client['outbounds'] if x['type']=='hysteria2')
            cnode=next(x for x in clash['proxies'] if x['type']=='hysteria2')
            assert not {'up_mbps','down_mbps'}&node.keys() and not {'up','down'}&cnode.keys()
            assert node['password']==cnode['password']==hy['users'][0]['password']
            assert node['tls']['server_name']==cnode['sni']=='localhost'
            assert cnode['name']=='Hysteria2' and cnode['server']==address
            assert (node.get('server_ports')==['20000:20010']) if hopping else node['server_port']==hy['listen_port']
            assert cnode.get('ports')=='20000-20010' if hopping else cnode['port']==hy['listen_port']
            reality=next(x for x in clash['proxies'] if x['type']=='vless')
            assert reality['uuid']==fixtures['reality_uuid'] and reality['reality-opts']['public-key']==public
            links=re.findall(r'hysteria2://[^\s\x1b]+',output)
            assert links and not any({'up','down','up_mbps','down_mbps','bandwidth'}&parse_qs(urlsplit(link).query).keys() for link in links)
            assert any('mport=' in link for link in links)==hopping
            run([binary,'check','-c',home/'sbconfig_client.json'])
            run([mihomo,'-t','-d',home/'yaml-check','-f',home/'mihomo_client.yaml'])
            variants.append((copy.deepcopy(client),copy.deepcopy(clash)))
    assert json.loads((home/'sbconfig_server.json').read_bytes())==original,'export mutated server'
    # Ordinary and hopping exports must preserve all unrelated settings and Reality.
    a,b=copy.deepcopy(variants[0]),copy.deepcopy(variants[1])
    for client,clash in (a,b):
        node=next(x for x in client['outbounds'] if x['type']=='hysteria2')
        for key in ('server_port','server_ports','hop_interval'):node.pop(key,None)
        node=next(x for x in clash['proxies'] if x['type']=='hysteria2')
        for key in ('port','ports','hop-interval'):node.pop(key,None)
    assert a==b,'hopping changed unrelated fields'
    return original,variants[0],fixtures


class Echo(BaseHTTPRequestHandler):
    payload=b'loopback-download-'*32768
    def log_message(self,*args):pass
    def do_GET(self):
        self.send_response(200);self.send_header('Content-Length',str(len(self.payload)));self.end_headers();self.wfile.write(self.payload)
    def do_POST(self):
        raw=self.rfile.read(int(self.headers['Content-Length']))
        body=hashlib.sha256(raw).hexdigest().encode()
        self.send_response(200);self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)


def transfer(socks, target):
    # curl's explicit proxy prevents inherited system/Clash proxy settings from affecting this test.
    common=['curl','-q','--proxy',f'socks5h://127.0.0.1:{socks}','--noproxy','','--connect-timeout','2','--max-time','8','-fsS']
    url=f'http://127.0.0.1:{target}'
    for _ in range(3):
        try:
            data=subprocess.run(common+[url],capture_output=True,timeout=10,check=True).stdout
            assert data==Echo.payload
            payload=b'loopback-upload-'*32768
            result=subprocess.run(common+['--data-binary','@-',url],input=payload,capture_output=True,timeout=10,check=True)
            assert result.stdout==hashlib.sha256(payload).hexdigest().encode()
            return
        except subprocess.CalledProcessError:time.sleep(.3)
    raise AssertionError('HY2 download/upload did not complete')


def live(home,server,pair,fixture,binary,mihomo,legacy_binary=None):
    # Only synthetic loopback inbounds/outbounds; no TUN, external API, route installation or production hosts.
    inbound=copy.deepcopy(server['inbounds'][1]);inbound['listen']='127.0.0.1'
    config={'log':{'level':'debug'},'inbounds':[inbound],'outbounds':[{'type':'direct','tag':'direct'}]}
    (home/'live-server.json').write_text(json.dumps(config))
    with (home/'server.log').open('w') as logfile:
        proc=subprocess.Popen([str(binary),'run','-c',str(home/'live-server.json')],stdout=logfile,stderr=logfile)
        http=ThreadingHTTPServer(('127.0.0.1',0),Echo);thread=threading.Thread(target=http.serve_forever,daemon=True);thread.start()
        try:
            kinds=['sing-box','mihomo','sing-box-legacy-bandwidth','mihomo-legacy-bandwidth']
            if legacy_binary:kinds.append('sing-box-1.11')
            for kind in kinds:
                socks=port();client,clash=pair
                if kind.startswith('sing-box'):
                    outbound=copy.deepcopy(next(n for n in client['outbounds'] if n['type']=='hysteria2'))
                    if kind.endswith('legacy-bandwidth'):outbound.update(up_mbps=300,down_mbps=300)
                    cfg={'inbounds':[{'type':'socks','listen':'127.0.0.1','listen_port':socks}],'outbounds':[outbound]}
                    file=home/'live-client.json';file.write_text(json.dumps(cfg));command=[str(legacy_binary if kind=='sing-box-1.11' else binary),'run','-c',str(file)]
                else:
                    outbound=copy.deepcopy(next(n for n in clash['proxies'] if n['type']=='hysteria2'))
                    if kind.endswith('legacy-bandwidth'):outbound.update(up='300 Mbps',down='300 Mbps')
                    cfg={'socks-port':socks,'allow-lan':False,'bind-address':'127.0.0.1','mode':'rule','proxies':[outbound],'rules':['MATCH,Hysteria2']}
                    file=home/'live-client.yaml';file.write_text(yaml.safe_dump(cfg));command=[str(mihomo),'-d',str(home/'mihomo'),'-f',str(file)]
                    run([mihomo,'-t','-d',home/'mihomo','-f',file])
                with (home/(kind+'.log')).open('w') as log:
                    cp=subprocess.Popen(command,stdout=log,stderr=log)
                    try:
                        wait_port(socks,cp);transfer(socks,http.server_port)
                    finally:cp.terminate();cp.wait(timeout=10)
                print('PASS: '+kind+' HY2 authenticates and transfers both directions over loopback')
            log=(home/'server.log').read_text(errors='replace').lower()
            assert 'brutal' not in log,'unexpected Brutal selection'
            # An invalid HY2 credential must not reach the origin.
            socks=port();outbound=copy.deepcopy(next(n for n in pair[0]['outbounds'] if n['type']=='hysteria2'));outbound['password']='invalid-synthetic-password'
            cfg={'inbounds':[{'type':'socks','listen':'127.0.0.1','listen_port':socks}],'outbounds':[outbound]}
            file=home/'bad-auth.json';file.write_text(json.dumps(cfg))
            with (home/'bad-auth.log').open('w') as log:
                cp=subprocess.Popen([str(binary),'run','-c',str(file)],stdout=log,stderr=log)
                try:
                    wait_port(socks,cp)
                    rejected=subprocess.run(['curl','-q','--proxy',f'socks5h://127.0.0.1:{socks}','--noproxy','','--max-time','3','-fsS',f'http://127.0.0.1:{http.server_port}'],capture_output=True,timeout=5)
                    assert rejected.returncode!=0 and not rejected.stdout,'invalid HY2 password accepted'
                finally:cp.terminate();cp.wait(timeout=10)
            print('PASS: invalid HY2 password rejected')
        finally:
            http.shutdown();http.server_close();thread.join(2);proc.terminate();proc.wait(timeout=10)


def reality_live(home,server,pair,binary):
    handshake=ThreadingHTTPServer(('127.0.0.1',0),Echo)
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(home/'self-cert/cert.pem'),str(home/'self-cert/private.key'))
    handshake.socket=context.wrap_socket(handshake.socket,server_side=True)
    thread=threading.Thread(target=handshake.serve_forever,daemon=True);thread.start()
    origin=ThreadingHTTPServer(('127.0.0.1',0),Echo)
    ot=threading.Thread(target=origin.serve_forever,daemon=True);ot.start()
    inbound=copy.deepcopy(server['inbounds'][0]);inbound['listen']='127.0.0.1'
    inbound['tls']['reality']['handshake']={'server':'127.0.0.1','server_port':handshake.server_port}
    socks=port();outbound=copy.deepcopy(next(n for n in pair[0]['outbounds'] if n['type']=='vless'))
    configs=[{'inbounds':[inbound],'outbounds':[{'type':'direct'}]},
             {'inbounds':[{'type':'socks','listen':'127.0.0.1','listen_port':socks}],'outbounds':[outbound]}]
    processes=[]
    try:
        for i,cfg in enumerate(configs):
            file=home/('reality-%d.json'%i);file.write_text(json.dumps(cfg))
            log=(home/('reality-%d.log'%i)).open('w')
            processes.append((subprocess.Popen([str(binary),'run','-c',str(file)],stdout=log,stderr=log),log))
        wait_port(inbound['listen_port'],processes[0][0]);wait_port(socks,processes[1][0])
        transfer(socks,origin.server_port)
        print('PASS: Reality credentials authenticate and transfer both directions over loopback')
    finally:
        for proc,log in reversed(processes):proc.terminate();proc.wait(timeout=10);log.close()
        origin.shutdown();origin.server_close();ot.join(2)
        handshake.shutdown();handshake.server_close();thread.join(2)


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--sing-box',required=True,type=Path);parser.add_argument('--mihomo',required=True,type=Path);parser.add_argument('--bash',default='bash');parser.add_argument('--legacy-sing-box',type=Path);parser.add_argument('--geoip',type=Path)
    args=parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='hy2-bbr-') as temporary:
        home=Path(temporary);server,pair,fixture=templates(home,args.sing_box.resolve(),args.bash,args.mihomo.resolve(),args.geoip.resolve() if args.geoip else None)
        live(home,server,pair,fixture,args.sing_box.resolve(),args.mihomo.resolve(),args.legacy_sing_box.resolve() if args.legacy_sing_box else None)
        reality_live(home,server,pair,args.sing_box.resolve())
    print('PASS: fresh server + IPv4/IPv6 and hopping exports omit fixed HY2 bandwidth; Reality unchanged')


if __name__=='__main__':main()
