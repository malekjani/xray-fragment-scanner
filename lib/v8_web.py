#!/usr/bin/env python3
"""Loopback-only, token-protected V8 dashboard; no remote binding or third-party assets."""
from __future__ import annotations

import argparse
import csv
import copy
import json
import os
from pathlib import Path
import secrets
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Event, Lock, Thread
from urllib.parse import parse_qs, urlsplit

from v8_engine import ROOT_RESULTS, PARAM_HELP, matrix, run, settings, utc
from share_codec import link_to_config
from v8_table import project, best_three

STATIC = Path(__file__).resolve().parent.parent / 'web'

class Job:
    def __init__(self):
        self.lock=Lock();self.stop=Event()
        self.state={'status':'idle','events':[],'summary':None,'folder':None,'updated':utc()}
    def event(self, item):
        # Deliberately never log private link/config/URI in frontend event payloads.
        if not isinstance(item,dict):return
        with self.lock:
            self.state['events']=(self.state['events']+[item])[-40:]
            self.state['updated']=utc()
    def snapshot(self):
        with self.lock:return copy.deepcopy(self.state)
    def start(self,link,spec,dry_run):
        with self.lock:
            if self.state['status'] in {'running','stopping'}:
                return False
            self.stop=Event()
            folder=ROOT_RESULTS/('scan-'+utc().replace(':','').replace('+','-').replace('-',''))
            self.state={'status':'running','events':[],'summary':None,'folder':str(folder),'updated':utc()}
        def worker():
            try:
                summary=run(link,spec,folder,dry_run=dry_run,stop=self.stop,callback=self.event)
                with self.lock:
                    self.state['status']='stopped' if self.stop.is_set() else 'finished'
                    self.state['summary']=summary
                    self.state['updated']=utc()
            except Exception as exc:
                with self.lock:
                    # Do not return raw exception text: might contain credentials.
                    self.state['status']='failed'
                    self.state['error_code']=type(exc).__name__
                    self.state['updated']=utc()
        Thread(target=worker,daemon=True,name='v8-scan').start()
        return True


def serve(host='127.0.0.1',port=8765):
    if host!='127.0.0.1':
        raise ValueError('V8 deliberately binds ONLY to 127.0.0.1; use SSH port forwarding')
    token=secrets.token_urlsafe(32)
    job=Job()
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            # No request paths or sensitive payloads go to console or server logs.
            return
        def respond(self,obj,status=200):
            data=json.dumps(obj,ensure_ascii=False).encode('utf-8')
            self.send_response(status)
            self.send_header('Content-Type','application/json; charset=utf-8')
            self.send_header('Cache-Control','no-store')
            self.send_header('X-Content-Type-Options','nosniff')
            self.send_header('Content-Length',str(len(data)))
            self.end_headers();self.wfile.write(data)
        def valid_host(self):
            return self.headers.get('Host') in (f'127.0.0.1:{port}',f'localhost:{port}')
        def authorized(self):
            return self.headers.get('X-V8-Token')==token
        def serve_asset(self,name):
            allowed={'/':'index.html','/style.css':'style.css','/app.js':'app.js'}
            if name not in allowed:
                self.send_error(404);return
            data=(STATIC/allowed[name]).read_bytes()
            if name=='/':data=data.replace(b'__CSRF_TOKEN__',token.encode())
            mime='text/html' if name=='/' else 'text/css' if name.endswith('.css') else 'application/javascript'
            self.send_response(200);self.send_header('Content-Type',mime+'; charset=utf-8')
            self.send_header('Cache-Control','no-store')
            self.send_header('X-Frame-Options','DENY')
            self.send_header('Referrer-Policy','no-referrer')
            self.send_header('X-Content-Type-Options','nosniff')
            self.send_header('Content-Security-Policy',"default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
            self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data)
        def do_GET(self):
            if not self.valid_host():return self.respond({'error':'invalid-host'},403)
            path=urlsplit(self.path).path
            if path in ('/','/style.css','/app.js'):
                return self.serve_asset(path)
            if not self.authorized():return self.respond({'error':'unauthorized'},403)
            if path=='/api/state':return self.respond(job.snapshot())
            if path=='/api/params':return self.respond(PARAM_HELP)
            if path=='/api/results':
                state=job.snapshot()
                scan=Path(state.get('folder') or '').name
                source=ROOT_RESULTS/scan/'ranked.csv' if scan.startswith('scan-') else None
                public=[]
                table_rows=[]
                if source and source.is_file():
                    with source.open(encoding='utf-8',newline='') as f:
                        table_rows=list(csv.DictReader(f))[:500]
                        for row in table_rows:
                            public.append({k:row.get(k) for k in ('id','rank','profile','status','success_rate','median_ms',
                                'p95_ms','avg_ms','successes','requests','jitter_ms','wilson_lower95','discovery_success_rate',
                                'verification_success_rate','packets','lengths','delays','maxSplit','changes',
                                'finalmask_json','fingerprint','ech_value','sni',
                                'compatibility_status','generated_changes','core_validation','runtime_effect',
                                'throughput_bytes_per_sec','throughput_samples')})
                table_rows.sort(key=lambda r:r.get('id',''))
                return self.respond({'candidates':public,
                                     'instances':[project(r) for r in table_rows],
                                     'top_three':[project(r) for r in best_three(table_rows)]})
            if path=='/api/history':
                folders=[]
                if ROOT_RESULTS.exists():
                    for folder in sorted(ROOT_RESULTS.glob('scan-*'),reverse=True)[:30]:
                        doc=folder/'summary.json'
                        if doc.is_file():
                            try:
                                s=json.loads(doc.read_text())
                                folders.append({'scan':folder.name,'completed':s.get('completed'),
                                                'candidates':s.get('candidates'),'verified':s.get('verified'),
                                                'best_id':s.get('best_id')})
                            except (OSError,ValueError):pass
                return self.respond({'history':folders})
            if path=='/api/export':
                query=parse_qs(urlsplit(self.path).query)
                name=query.get('name',[''])[0]
                scan=query.get('scan',[''])[0]
                allowed={'results.csv','ranked.csv','links.csv','links.txt','probes.csv','summary.json',
                         'finalmask-instances.csv','top-three-lowest-average.csv','finalmask-table.txt',
                         'manifest.jsonl','diffs.jsonl','verified-links.txt','provisional-links.txt','excluded.json'}
                if name not in allowed or not (scan.startswith('scan-') and scan.replace('-','').replace('_','').isalnum()):
                    return self.respond({'error':'invalid-export'},400)
                path=ROOT_RESULTS/scan/name
                if not path.is_file():return self.respond({'error':'not-found'},404)
                content=path.read_bytes()
                self.send_response(200)
                self.send_header('Content-Type','application/octet-stream')
                self.send_header('Content-Disposition',f'attachment; filename="{name}"')
                self.send_header('Cache-Control','no-store')
                self.send_header('Content-Length',str(len(content)))
                self.end_headers();self.wfile.write(content)
                return
            return self.respond({'error':'not-found'},404)
        def do_POST(self):
            if not self.valid_host() or not self.authorized():
                return self.respond({'error':'forbidden'},403)
            origin=self.headers.get('Origin')
            if origin and origin not in (f'http://127.0.0.1:{port}',f'http://localhost:{port}'):
                return self.respond({'error':'invalid-origin'},403)
            length=self.headers.get('Content-Length','')
            if not length.isdigit() or not 0<=int(length)<=262144:
                return self.respond({'error':'invalid-length'},413)
            try:
                body=json.loads(self.rfile.read(int(length)) or b'{}')
                if not isinstance(body,dict):raise ValueError('bad-json')
            except (ValueError,UnicodeError):return self.respond({'error':'invalid-json'},400)
            route=urlsplit(self.path).path
            if route=='/api/stop':
                job.stop.set()
                with job.lock:
                    if job.state['status']=='running':job.state['status']='stopping'
                return self.respond({'stopping':True})
            if route not in ('/api/preview','/api/start'):return self.respond({'error':'not-found'},404)
            link=body.get('link','')
            raw=body.get('settings') or {}
            if not isinstance(link,str) or len(link)>12000 or not isinstance(raw,dict):
                return self.respond({'error':'invalid-input'},400)
            try:
                link_to_config(link)
                spec=settings(raw)
                # Preview is offline, and may be approximate in AUTO mode until a live baseline is recorded.
                c,excluded=matrix(link,spec)
            except Exception as exc:
                # Never print raw exceptions; they can contain private URI tokens.
                return self.respond({'error':'invalid-combination','category':type(exc).__name__},400)
            if route=='/api/preview':
                return self.respond({'total':len(c),'excluded':len(excluded),'profiles':[
                    {'id':v['id'],'name':v['profile'],'changes':v['changes'],
                     'address':v['config']['outbounds'][0]['settings'].get('address'),
                     'fingerprint':v['config']['outbounds'][0]['streamSettings'].get('tlsSettings',{}).get('fingerprint'),
                     'ech_enabled':bool(v['config']['outbounds'][0]['streamSettings'].get('tlsSettings',{}).get('echConfigList')),
                     'finalmask':v['config']['outbounds'][0]['streamSettings'].get('finalmask'),
                     'ech_value':v['config']['outbounds'][0]['streamSettings'].get('tlsSettings',{}).get('echConfigList'),
                     'mask_types':[layer.get('type') for layer in
                                   (v['config']['outbounds'][0]['streamSettings'].get('finalmask') or {}).get('tcp',[])],
                     'warnings':[x for x in v['compatibility']['findings'] if x['severity']=='WARN'],
                     'compatibility_status':v['compatibility']['status'],
                     'core_version':v['compatibility']['core_version'],
                     'effective_diff':v['effective_diff']}
                    for v in c[:150]], 'note':'Auto matrix may change after preflight baseline; core validation happens in LIVE mode.'})
            if not job.start(link,spec,bool(body.get('dry_run',False))):return self.respond({'error':'scan-already-running'},409)
            return self.respond({'started':True,'status':'running'})
    server=ThreadingHTTPServer((host,port),Handler)
    server.daemon_threads=True
    print(f'V8 dashboard (local only): http://{host}:{port}/',flush=True)
    print('Open on this Debian machine, or forward over SSH: ssh -L 8765:127.0.0.1:8765 user@debian',flush=True)
    try:server.serve_forever(poll_interval=.2)
    except KeyboardInterrupt:pass
    finally:server.server_close()

if __name__=='__main__':
    parser=argparse.ArgumentParser(description='Local-only V8 web dashboard')
    parser.add_argument('--host',default='127.0.0.1')
    parser.add_argument('--port',type=int,default=8765)
    args=parser.parse_args()
    serve(args.host,args.port)
