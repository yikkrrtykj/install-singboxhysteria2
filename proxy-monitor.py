#!/usr/bin/env python3
import json, os, re, shutil, subprocess, threading, time, secrets
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

CFG='/root/sbox/sbconfig_server.json'; STATE='/root/sbox/config'; TOKEN='/root/sbox/monitor-token'
HIST=deque(maxlen=300); LOCK=threading.Lock(); SNAP={}; PREV_NET=None; PREV_CONN={}; PREV_CPU=None
RTT=re.compile(r'\brtt:([0-9.]+)/([0-9.]+)'); SENT=re.compile(r'\bbytes_sent:(\d+)'); RECV=re.compile(r'\bbytes_received:(\d+)'); RETR=re.compile(r'\bretrans:(?:\d+/)?(\d+)')


def run(cmd, timeout=3):
    try:
        p=subprocess.run(cmd,text=True,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=timeout)
        return p.stdout if p.returncode==0 else ''
    except Exception:return ''

def load_cfg():
    try:c=json.load(open(CFG,encoding='utf-8'))
    except Exception:c={}
    state={}
    try:
        for raw in open(STATE,encoding='utf-8'):
            if '=' in raw and not raw.lstrip().startswith('#'):
                k,v=raw.strip().split('=',1); state[k]=v.strip("'\"")
    except Exception:pass
    rp=hp=0
    for x in c.get('inbounds',[]):
        if x.get('tag')=='vless-in':rp=int(x.get('listen_port',0) or 0)
        if x.get('tag')=='hy2-in':hp=int(x.get('listen_port',0) or 0)
    def n(k):
        try:return int(state.get(k,'') or 0)
        except:return 0
    return {'ip':state.get('SERVER_IP',''),'reality':rp,'hy2':hp,'hop':state.get('HY_HOPPING')=='TRUE','hs':n('HY_HOPPING_START'),'he':n('HY_HOPPING_END')}

def iface():
    m=re.search(r'\bdev\s+(\S+)',run(['ip','route','show','default']))
    return m.group(1) if m else ''

def netbytes(dev):
    try:
        for l in open('/proc/net/dev'):
            if ':' in l and l.split(':',1)[0].strip()==dev:
                f=l.split(':',1)[1].split(); return int(f[0]),int(f[8])
    except:pass
    return 0,0

def cpu():
    try:
        n=[int(x) for x in open('/proc/stat').readline().split()[1:]]; idle=n[3]+(n[4] if len(n)>4 else 0); return sum(n),idle
    except:return 0,0

def mem():
    d={}
    try:
        for l in open('/proc/meminfo'):
            k,v=l.split(':',1); d[k]=int(v.split()[0])*1024
    except:return {'pct':0}
    t=d.get('MemTotal',0); a=d.get('MemAvailable',d.get('MemFree',0)); return {'pct':round((t-a)*100/t,1) if t else 0}

def parse_reality(port):
    if not port:return []
    out=run(['ss','-Htin','state','established']); rows=[]; cur=None
    ep=re.compile(r'(\[[^]]+\]|[^\s:]+):(\d+)')
    for l in out.splitlines():
        if l and not l[0].isspace():
            m=ep.findall(l)
            if len(m)<2:cur=None;continue
            (lh,lp),(ph,pp)=m[-2],m[-1]
            if int(lp)!=port:cur=None;continue
            cur={'key':f'{ph}:{pp}','ip':ph.strip('[]'),'sessions':1,'sent':0,'recv':0,'rtt':None,'retrans':0}; rows.append(cur)
        elif cur:
            m=RTT.search(l); cur['rtt']=float(m.group(1)) if m else cur['rtt']
            m=SENT.search(l); cur['sent']=int(m.group(1)) if m else cur['sent']
            m=RECV.search(l); cur['recv']=int(m.group(1)) if m else cur['recv']
            m=RETR.search(l); cur['retrans']=int(m.group(1)) if m else cur['retrans']
    return rows

def parse_hy2(port,hs,he):
    if not port or not shutil.which('conntrack'):return []
    rows=[]
    for l in run(['conntrack','-L','-p','udp','-o','extended']).splitlines():
        src=re.findall(r'\bsrc=([^ ]+)',l); sport=re.findall(r'\bsport=(\d+)',l); dport=re.findall(r'\bdport=(\d+)',l); bs=[int(x) for x in re.findall(r'\bbytes=(\d+)',l)]
        if len(src)<2 or len(sport)<2 or len(dport)<2:continue
        dp=int(dport[0]); ok=dp==port or (hs and he and hs<=dp<=he)
        if not ok:continue
        rows.append({'key':f'{src[0]}:{sport[0]}:{dp}','ip':src[0],'sessions':1,'sent':bs[0] if bs else 0,'recv':bs[1] if len(bs)>1 else 0,'rtt':None,'retrans':0})
    return rows

def aggregate(proto,rows,now):
    global PREV_CONN
    out={}; live=set()
    for r in rows:
        k=(proto,r['key']); live.add(k); old=PREV_CONN.get(k); up=down=0
        if old and r['sent']>=old[0] and r['recv']>=old[1]:
            dt=max(.2,now-old[2]); up=(r['sent']-old[0])*8/dt; down=(r['recv']-old[1])*8/dt
        PREV_CONN[k]=(r['sent'],r['recv'],now)
        x=out.setdefault(r['ip'],{'ip':r['ip'],'sessions':0,'up':0,'down':0,'rtts':[],'retrans':0})
        x['sessions']+=1;x['up']+=up;x['down']+=down;x['retrans']+=r['retrans']
        if r['rtt'] is not None:x['rtts'].append(r['rtt'])
    for k in list(PREV_CONN):
        if k[0]==proto and k not in live:PREV_CONN.pop(k,None)
    ans=[]
    for x in out.values():
        a=x.pop('rtts');x['rtt']=round(sum(a)/len(a),1) if a else None;x['max_rtt']=round(max(a),1) if a else None;x['up']=round(x['up']);x['down']=round(x['down']);ans.append(x)
    return sorted(ans,key=lambda z:-(z['up']+z['down']))

def ping(host):
    o=run(['ping','-n','-c','3','-W','1',host],5); r=None;loss=100.0
    m=re.search(r'([0-9.]+)% packet loss',o); loss=float(m.group(1)) if m else loss
    m=re.search(r'=\s*[0-9.]+/([0-9.]+)/',o); r=float(m.group(1)) if m else None
    return {'target':host,'rtt':r,'loss':loss}

def sample():
    global SNAP,PREV_NET,PREV_CPU
    now=time.time(); c=load_cfg(); dev=iface(); rx,tx=netbytes(dev); rb=tb=0
    if PREV_NET:
        pr,pt,ts=PREV_NET;dt=max(.2,now-ts);rb=(rx-pr)*8/dt if rx>=pr else 0;tb=(tx-pt)*8/dt if tx>=pt else 0
    PREV_NET=(rx,tx,now)
    ct,ci=cpu();cp=0
    if PREV_CPU:
        pt,pi=PREV_CPU;d=ct-pt;cp=round(max(0,min(100,(d-(ci-pi))*100/d)),1) if d>0 else 0
    PREV_CPU=(ct,ci)
    r=aggregate('r',parse_reality(c['reality']),now);h=aggregate('h',parse_hy2(c['hy2'],c['hs'],c['he']),now)
    maxr=max([x['max_rtt'] for x in r if x['max_rtt'] is not None],default=None)
    s={'time':int(now),'server':{'ip':c['ip'],'iface':dev,'cpu':cp,'ram':mem()['pct'],'rx':round(rb),'tx':round(tb),'singbox':run(['systemctl','is-active','sing-box']).strip()=='active' or bool(run(['pgrep','-x','sing-box']).strip())},'proxy':{'reality_port':c['reality'],'hy2_port':c['hy2'],'hop':c['hop'],'hs':c['hs'],'he':c['he'],'reality':r,'hy2':h,'maxrtt':maxr,'conntrack':bool(shutil.which('conntrack'))},'probes':[ping('1.1.1.1'),ping('8.8.8.8')]}
    HIST.append({'t':int(now),'rx':s['server']['rx'],'tx':s['server']['tx'],'rtt':maxr})
    s['history']=list(HIST)
    with LOCK:SNAP=s

def worker():
    while True:
        try:sample()
        except Exception as e:
            with LOCK:SNAP.update({'error':str(e),'time':int(time.time())})
        time.sleep(2)

def gettoken():
    try:t=open(TOKEN).read().strip()
    except:t=''
    if not re.fullmatch(r'[A-Za-z0-9_-]{16,128}',t):
        t=secrets.token_urlsafe(24);os.makedirs(os.path.dirname(TOKEN),exist_ok=True);open(TOKEN,'w').write(t+'\n');os.chmod(TOKEN,0o600)
    return t

HTML='''<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Proxy Monitor</title><style>body{margin:0;background:#0b1020;color:#e8eef9;font:14px system-ui}.w{max-width:1200px;margin:auto;padding:18px}.g{display:grid;grid-template-columns:repeat(4,1fr);gap:10px}.c{background:#121a2b;border:1px solid #28344c;border-radius:12px;padding:13px}.full{grid-column:1/-1}.v{font-size:23px;font-weight:750}.m{color:#91a0b8}.ok{color:#39d98a}.bad{color:#ff6b6b}.warn{color:#ffc857}table{width:100%;border-collapse:collapse}td,th{padding:8px;border-bottom:1px solid #263148;text-align:left}th{color:#91a0b8}.scroll{overflow:auto}@media(max-width:700px){.g{grid-template-columns:1fr 1fr}}@media(max-width:460px){.g{grid-template-columns:1fr}}</style><div class=w><h2>Sing-box Proxy Monitor</h2><div id=meta class=m>loading…</div><div class=g style="margin-top:12px"><div class=c><div class=m>RX</div><div id=rx class=v>—</div></div><div class=c><div class=m>TX</div><div id=tx class=v>—</div></div><div class=c><div class=m>CPU</div><div id=cpu class=v>—</div></div><div class=c><div class=m>RAM</div><div id=ram class=v>—</div></div><div class="c full"><b>入口 / 探测</b><div id=ports></div></div><div class="c full scroll"><b>Reality 客户端（公网源 IP 聚合）</b><table><thead><tr><th>IP</th><th>会话</th><th>RTT</th><th>最大 RTT</th><th>上传</th><th>下载</th><th>Retrans</th></tr></thead><tbody id=r></tbody></table></div><div class="c full scroll"><b>Hysteria2 客户端（公网源 IP 聚合）</b><table><thead><tr><th>IP</th><th>UDP Flow</th><th>RTT</th><th>上传</th><th>下载</th></tr></thead><tbody id=h></tbody></table><p class=m>HY2 是 QUIC/UDP，Linux TCP socket 没有可直接读取的业务 RTT，所以这里不伪造 RTT。</p></div></div></div><script>const $=x=>document.getElementById(x),rate=x=>x>=1e9?(x/1e9).toFixed(2)+' Gbps':x>=1e6?(x/1e6).toFixed(2)+' Mbps':x>=1e3?(x/1e3).toFixed(1)+' Kbps':Math.round(x||0)+' bps',rt=x=>x==null?'—':`<span class=${x<80?'ok':x<150?'warn':'bad'}>${x.toFixed(1)} ms</span>`;function rr(a){return a.length?a.map(x=>`<tr><td>${x.ip}</td><td>${x.sessions}</td><td>${rt(x.rtt)}</td><td>${rt(x.max_rtt)}</td><td>${rate(x.up)}</td><td>${rate(x.down)}</td><td>${x.retrans}</td></tr>`).join(''):'<tr><td colspan=7 class=m>无活动连接</td></tr>'}function hh(a){return a.length?a.map(x=>`<tr><td>${x.ip}</td><td>${x.sessions}</td><td class=m>QUIC / N.A.</td><td>${rate(x.up)}</td><td>${rate(x.down)}</td></tr>`).join(''):'<tr><td colspan=5 class=m>无活动连接</td></tr>'}async function go(){try{let d=await(await fetch('api/status',{cache:'no-store'})).json(),s=d.server,p=d.proxy;$('meta').innerHTML=`<span class=${s.singbox?'ok':'bad'}>${s.singbox?'● Online':'● Offline'}</span> · ${s.ip||'server'} · ${s.iface}`;$('rx').textContent=rate(s.rx);$('tx').textContent=rate(s.tx);$('cpu').textContent=s.cpu+'%';$('ram').textContent=s.ram+'%';$('ports').innerHTML=`<p>Reality TCP: <b>${p.reality_port}</b> · Hysteria2 UDP: <b>${p.hy2_port}</b> · HY2 hopping: <b>${p.hop?p.hs+'-'+p.he:'关闭'}</b></p>`+d.probes.map(x=>`${x.target}: ${rt(x.rtt)} · loss ${x.loss}%`).join('<br>');$('r').innerHTML=rr(p.reality);$('h').innerHTML=hh(p.hy2)}catch(e){$('meta').textContent=e}}go();setInterval(go,2000)</script>'''

class H(BaseHTTPRequestHandler):
    def log_message(self,*a):pass
    def do_GET(self):
        p=urlparse(self.path).path; base='/'+self.server.token+'/'
        if p=='/health':self.send_response(200);self.end_headers();self.wfile.write(b'ok\n');return
        if not p.startswith(base):self.send_response(404);self.end_headers();return
        rel=p[len(base):]
        if rel in ('','index.html'):b=HTML.encode();ct='text/html; charset=utf-8'
        elif rel=='api/status':
            with LOCK:b=json.dumps(SNAP,separators=(',',':')).encode()
            ct='application/json'
        else:self.send_response(404);self.end_headers();return
        self.send_response(200);self.send_header('Content-Type',ct);self.send_header('Cache-Control','no-store');self.send_header('X-Frame-Options','DENY');self.end_headers();self.wfile.write(b)

if __name__=='__main__':
    import argparse
    a=argparse.ArgumentParser();a.add_argument('--listen',default='0.0.0.0');a.add_argument('--port',type=int,default=9191);o=a.parse_args();
    sample();threading.Thread(target=worker,daemon=True).start();srv=ThreadingHTTPServer((o.listen,o.port),H);srv.token=gettoken();print(f'Proxy monitor: http://0.0.0.0:{o.port}/{srv.token}/',flush=True);srv.serve_forever()
