#!/usr/bin/env python3
"""V8: fixed-budget Expert matrix and baseline-aware two-stage measurements.

No progressive search. No privileged operations. No privileged operations or progressive search.
"""
from __future__ import annotations

import argparse
import copy
import csv
import hashlib
import itertools
import json
import math
import os
from pathlib import Path
import random
import shutil
import signal
import socket
import sqlite3
import statistics
import subprocess
import sys
import tempfile
import threading
import time
from datetime import datetime, timezone

from core_manager import CoreError, core_identity, resolve_core
from network_scan import free_port, proxy, validate_address, write_private_json
from optimize import fragment, safe_csv, safe_text_file, percentile95
from share_codec import link_to_config, scheme_and_encoding
from network_scan import export_candidate_link
from v8_compat import safe_summary, effective_preview
from v8_table import text_report, best_three, project
from xray_errors import classify as classify_xray_error, write_first_error

DEFAULT_TARGETS = ["https://www.gstatic.com/generate_204", "https://www.cloudflare.com/cdn-cgi/trace"]
ROOT_RESULTS = Path.home() / '.local/share/xray-finalmask-scanner/v8'
PARAM_HELP = {
    "packets": {"fa": "محدودهٔ عملیات نوشتن TCP یا tlshello؛ همیشه با مسیر TLS یکسان رفتار نمی‌کند.", "en": "TCP write range or tlshello target; effect depends on transport."},
    "lengths": {"fa": "آرایهٔ اندازه‌های قطعات به بایت؛ عضو آخر برای قطعات بعدی تکرار می‌شود.", "en": "Byte-size fragment array; last entry repeats for later pieces."},
    "delays": {"fa": "آرایهٔ مکث‌های میلی‌ثانیه‌ای بین قطعات Fragment.", "en": "Millisecond delays between successive fragments."},
    "maxSplit": {"fa": "سقف تعداد تقسیم‌ها؛ صفر یعنی بدون سقف.", "en": "Maximum splits; zero means unlimited."},
    "ECH": {"fa": "Encrypted Client Hello؛ باید با سرور و تنظیمات TLS سازگار باشد.", "en": "Encrypted Client Hello, subject to TLS/server compatibility."},
    "fingerprint": {"fa": "شبیه‌سازی ClientHello توسط uTLS؛ بعضی فیلدهای TLS را بی‌اثر می‌کند.", "en": "uTLS ClientHello impersonation; may override TLS fields."},
    "header-custom": {"fa": "لایهٔ Header-Custom در FinalMask TCP؛ با هدر WebSocket تفاوت دارد.", "en": "TCP FinalMask Header-Custom layer; not a WebSocket HTTP header."},
    "baseline": {"fa": "آزمون کانفیگ اصلیِ تغییرنیافته برای کنترل اثر تغییرات شبکه.", "en": "Unmodified original link measured repeatedly as a network control."},
    "objective": {"fa": "معیار رتبه‌بندی پس از گذر از آستانهٔ اتصال: سرعت/تأخیر، پایداری، تعادل یا تأخیر پایین.", "en": "Ranking objective after reliability gate: performance, reliability, balanced or low latency."},
    "Experimental": {"fa": "ترکیب یا نسخهٔ Core هنوز روی شبکه تأیید نشده؛ در پیش‌نمایش امکان آزمایش ساختار وجود دارد.", "en": "A combination or core version not yet proven by runtime evidence."},
    "core_validation": {"fa": "قبول‌شدن توسط xray run -test تنها نشان می‌دهد Core کانفیگ را می‌پذیرد؛ اتصال تضمین نمی‌شود.", "en": "Acceptance by xray run -test means only core schema/config validation."},
    "effective_diff": {"fa": "سه سطح: تغییر درخواستی، تفاوت کانفیگ ساخته‌شده و اثر تأییدشده؛ موارد مشاهده‌نشده صریح مشخص می‌شوند.", "en": "Requested vs generated config changes vs independently observed runtime effects."},
    "Browser Dialer": {"fa": "مرورگر واقعی TLS را مدیریت می‌کند؛ Xray TLS/ECH/Fingerprint در این حالت اثر ادعاشده ندارند. تست خودکار غیرفعال است.", "en": "Real-browser TLS path; Xray TLS/ECH/fingerprint may be ineffective. Automatic benchmarking disabled."},
    "throughput": {"fa": "سرعت انتقال پاسخ HTTPS حجیم؛ جدا از درخواست کوچک و فقط هنگام داشتن دادهٔ واقعی وارد رتبه‌بندی می‌شود.", "en": "Observed bulk download speed; not inferred from small connectivity probes."},
}


def utc():
    return datetime.now(timezone.utc).isoformat(timespec='seconds')


def sha_text(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def ensure_private_dir(path: Path):
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path, 0o700)


def private_json(path: Path, obj):
    write_private_json(path, obj)
    os.chmod(path, 0o600)


def settings(spec=None):
    s = dict(spec or {})
    defaults = {'mode': 'auto', 'stage1_requests': 5, 'stage2_requests': 25,
                'verify_top': 5, 'baseline_every': 5, 'min_success': .90,
                'timeout': 8, 'max_candidates': 60, 'seed': 2026, 'targets': DEFAULT_TARGETS,
                'browser_dialer': False, 'throughput_url': None, 'objective':'best-performance'}
    for k,v in defaults.items():
        s.setdefault(k,v)
    if s['objective'] not in ('best-performance','max-reliability','balanced','lowest-latency'):
        raise ValueError('objective must be best-performance, max-reliability, balanced or lowest-latency')
    if s['mode'] not in ('auto','expert'):
        raise ValueError('mode must be auto or expert')
    for key,low,high in [('stage1_requests',1,50),('stage2_requests',1,150),
                         ('verify_top',1,25),('baseline_every',1,100),
                         ('max_candidates',1,500),('seed',0,2**31-1)]:
        if not isinstance(s[key],int) or not low<=s[key]<=high:
            raise ValueError(f'{key} must be an integer in {low}..{high}')
    if not 0 < float(s['min_success']) <= 1 or not 0.5<=float(s['timeout'])<=120:
        raise ValueError('Invalid min_success or timeout')
    if not isinstance(s['targets'],list) or not s['targets'] or len(s['targets'])>5:
        raise ValueError('targets must be 1..5 HTTPS URLs')
    for target in list(s['targets']) + ([s['throughput_url']] if s['throughput_url'] else []):
        if not isinstance(target,str) or not target.startswith('https://') or len(target)>1024 or '\n' in target:
            raise ValueError('Only HTTPS probe URLs are supported')
    if not isinstance(s.get('network_label',''),str) or len(s.get('network_label',''))>80:
        raise ValueError('network_label max 80 characters')
    if s.get('browser_dialer'):
        raise ValueError('Browser Dialer is not automatically benchmarked in V8; use manual validation')
    return s


def auto_masks(baseline_success=None, baseline_median_ms=None, baseline_jitter_ms=None):
    # One fixed matrix selected ONCE from initial baseline: no adaptive expansion.
    # Compare unmodified baseline to modest, distinct fragment patterns.
    combos = [ ('tlshello', '6,98,1', '0', '0'), ('tlshello','20-40,70-110','1-3','3'),
               ('1-2','50-100','0','0') ]
    if (baseline_success is None or baseline_success < .8 or
            (baseline_median_ms is not None and baseline_median_ms > 1000) or
            (baseline_jitter_ms is not None and baseline_jitter_ms > 500)):
        combos += [('tlshello','0,104,1','0','0'),('tlshello','3-5,6-8,10-20','3-6','5')]
    variants = [{'name':f'auto-{i}', 'layers':[fragment(*item)]} for i,item in enumerate(combos,1)]
    variants.append({'name':'auto-two-layer','layers':[
        fragment('tlshello','6,98,1','0','0'), fragment('1-1','114,1','1','11')]})
    return variants


def apply_mask(cfg, profile):
    if profile == 'original':
        return
    layers=profile.get('layers')
    if not isinstance(layers,list) or not layers or len(layers)>8:
        raise ValueError('Each mask profile must have 1..8 ordered TCP layers')
    newtypes={x.get('type') for x in layers if isinstance(x,dict)}
    if not newtypes.issubset({'fragment','header-custom'}):
        raise ValueError('Expert mask profiles support fragment and header-custom layers in V8')
    if any(not isinstance(x,dict) or not isinstance(x.get('settings'),dict) for x in layers):
        raise ValueError('Invalid FinalMask layer')
    for item in layers:
        if item['type']=='fragment':
            st=item['settings']
            replacement=fragment(st.get('packets','tlshello'), ','.join(st.get('lengths',[])),
                                 ','.join(st.get('delays',[])), st.get('maxSplit','0'))
            item['settings']=replacement['settings']
    stream=proxy(cfg)['streamSettings']
    old=copy.deepcopy(stream.get('finalmask') or {})
    tcp=old.get('tcp',[])
    if not isinstance(tcp,list):
        raise ValueError('Original finalmask.tcp is not an array')
    first=next((i for i,x in enumerate(tcp) if x.get('type') in newtypes),len(tcp))
    keep=[x for x in tcp if x.get('type') not in newtypes]
    keep[min(first,len(keep)):min(first,len(keep))]=copy.deepcopy(layers)
    old['tcp']=keep
    stream['finalmask']=old


def matrix(link, spec, *, baseline_success=None, baseline_median_ms=None, baseline_jitter_ms=None,
           core_version=None):
    """Fully enumerate a bounded, fixed matrix; never silently trim candidates."""
    spec=settings(spec)
    original=link_to_config(link)
    source_scheme,source_encoding=scheme_and_encoding(link)
    def selections(key):
        values=spec.get(key,['original'])
        if not isinstance(values,list) or not values or len(values)>30:
            raise ValueError(f'{key}: supply 1..30 values')
        return values
    addresses=selections('addresses')
    fps=selections('fingerprints')
    eches=selections('ech_values')
    masks=spec.get('mask_profiles')
    if masks is None:
        masks=['original'] + auto_masks(baseline_success, baseline_median_ms, baseline_jitter_ms) if spec['mode']=='auto' else ['original']
    if not isinstance(masks,list) or not masks or len(masks)>30:
        raise ValueError('mask_profiles must contain 1..30 items')
    possible=len(addresses)*len(fps)*len(eches)*len(masks)
    if possible>spec['max_candidates']+1:
        raise ValueError(f'{possible} requested combinations exceed max_candidates={spec["max_candidates"]}; narrow matrix explicitly')
    results=[]; excluded=[]; seen=set()
    # Baseline always first; not repeated link variants.
    def add(cfg, label, changes, *, baseline=False):
        verdict=safe_summary(cfg,browser_dialer=spec['browser_dialer'],core_version=core_version)
        if not verdict['allowed']:
            excluded.append({'profile':label, 'why':verdict['findings']})
            return
        out=proxy(cfg)
        sig=sha_text(json.dumps({'settings':out['settings'], 'streamSettings':out['streamSettings']},sort_keys=True))
        if sig in seen:
            return
        seen.add(sig)
        cid=f'V8-{len(results)+1:04d}'
        uri=export_candidate_link(link,cfg,cid,baseline=baseline)
        results.append({'id':cid,'config':cfg,'link':uri,'sha256':sha_text(uri),
                        'config_sha256':sig,'profile':label,'changes':changes,'compatibility':verdict,
                        'effective_diff':effective_preview(original,cfg,changes)})
    add(copy.deepcopy(original),'baseline',[],baseline=True)
    for address,fp,ech,mask in itertools.product(addresses,fps,eches,masks):
        cfg=copy.deepcopy(original)
        out=proxy(cfg)
        tls=out['streamSettings'].get('tlsSettings',{})
        changes=[]
        if address!='original':
            out['settings']['address']=validate_address(address);changes.append('address')
        if fp!='original':
            if out['streamSettings'].get('security')!='tls':
                excluded.append({'profile':'fingerprint','why':'TLS fingerprint requires tls'}); continue
            tls['fingerprint']=fp;changes.append('fingerprint')
        if ech!='original':
            if out['streamSettings'].get('security')!='tls':
                excluded.append({'profile':'ECH','why':'ECH requires tls'}); continue
            if ech=='none':
                tls.pop('echConfigList',None)
            else: tls['echConfigList']=ech
            changes.append('ech')
        if mask!='original':
            profile=copy.deepcopy(mask)
            apply_mask(cfg,profile)
            changes.append('finalmask.tcp')
            label=profile.get('name','custom')
        else: label='original-mask'
        add(cfg,label,changes)
    if len(results)>spec['max_candidates']:
        raise ValueError('Unique candidate count exceeds max_candidates')
    return results,excluded


def classify_curl(rc, http_code=0):
    if rc==0 and 200<=http_code<400: return 'OK'
    return {5:'PROXY_DNS',6:'DNS',7:'TCP_CONNECT',28:'TIMEOUT',35:'TLS',
            51:'CERTIFICATE',60:'CERTIFICATE',52:'EMPTY_REPLY',56:'RECEIVE',
            18:'PARTIAL_TRANSFER',23:'WRITE_ERROR',63:'SIZE_LIMIT'}.get(rc,'HTTP_ERROR' if rc==0 else f'CURL_{rc}')


def probe(port,url,timeout,*,download=False):
    fmt='%{http_code}\t%{time_namelookup}\t%{time_connect}\t%{time_appconnect}\t%{time_starttransfer}\t%{time_total}\t%{size_download}\t%{speed_download}'
    args=['curl','--silent','--show-error','--location','--max-redirs','2',
          '--max-time',str(timeout),'--connect-timeout',str(min(5,timeout)),
          '--noproxy','','--proxy',f'http://127.0.0.1:{port}',
          '--output',os.devnull,'--write-out',fmt]
    if download: args+=['--max-filesize','5242880']
    args.append(url)
    try:
        p=subprocess.run(args,capture_output=True,text=True,timeout=timeout+3)
        parts=p.stdout.strip().split('\t')
        values=[float(x) for x in parts] if len(parts)==8 else [0.0]*8
        status=int(values[0]); classification=classify_curl(p.returncode,status)
        return {'ok':classification=='OK','reason':classification,'http_code':status,
                'dns_ms':round(values[1]*1000,2),'tcp_ms':round(values[2]*1000,2),
                'tls_ms':round(values[3]*1000,2),'ttfb_ms':round(values[4]*1000,2),
                'total_ms':round(values[5]*1000,2),'bytes':int(values[6]),
                'bytes_per_second':round(values[7],1)}
    except (OSError,subprocess.TimeoutExpired,ValueError):
        return {'ok':False,'reason':'PROBE_ERROR','http_code':0,'dns_ms':0,'tcp_ms':0,
                'tls_ms':0,'ttfb_ms':0,'total_ms':0,'bytes':0,'bytes_per_second':0}


def wilson_lower(successes,total,z=1.96):
    if not total: return 0.0
    p=successes/total; zz=z*z
    return max(0,(p+zz/(2*total)-z*math.sqrt((p*(1-p)+zz/(4*total))/total))/(1+zz/total))


def aggregate(samples):
    success=[v for v in samples if v['ok']]
    ms=[x['total_ms'] for x in success]
    return {'successes':len(success),'requests':len(samples),
            'success_rate':round(len(success)/len(samples),5) if samples else 0,
            'wilson_lower95':round(wilson_lower(len(success),len(samples)),5),
            'median_ms':round(statistics.median(ms),2) if ms else None,
            'avg_ms':round(statistics.mean(ms),2) if ms else None,
            'p95_ms':percentile95(ms),
            'jitter_ms':round(statistics.pstdev(ms),2) if len(ms)>1 else None,
            'throughput_bytes_per_sec':round(statistics.mean([x['bytes_per_second'] for x in success if x.get('bytes',0)>=65536]),1)
            if any(x.get('bytes',0)>=65536 for x in success) else None,
            'errors':{kind:sum(x['reason']==kind for x in samples if not x['ok'])
                      for kind in sorted({x['reason'] for x in samples if not x['ok']})}}


def quality(score):
    # Hard reliability priority, with latency as tie-breaker; no arbitrary weighted winner.
    return (-score['success_rate'], -score['wilson_lower95'],
            score['p95_ms'] if score['p95_ms'] is not None else float('inf'),
            score['median_ms'] if score['median_ms'] is not None else float('inf'))


def exec_candidate(xray,cfg,folder,urls,requests,timeout,*,stop=None,throughput_url=None):
    path=folder/'.v8-candidate.json'
    cfg=copy.deepcopy(cfg)
    cfg['inbounds'][0]['port']=free_port()
    write_private_json(path,cfg)
    stage_results=[]
    try:
        child_env=os.environ.copy()
        child_env.pop('XRAY_BROWSER_DIALER',None)  # Never inherit an accidental browser-side transport override.
        try:
            test=subprocess.run([xray,'run','-test','-c',str(path)],capture_output=True,text=True,
                                timeout=15,env=child_env)
        except subprocess.TimeoutExpired:
            return [{'ok':False,'reason':'INVALID_CONFIG:validation-timeout','http_code':0,'total_ms':0} for _ in range(requests)]
        except OSError:
            return [{'ok':False,'reason':'START_FAILED:xray-unavailable','http_code':0,'total_ms':0} for _ in range(requests)]
        if test.returncode:
            message=(test.stderr or '')+'\n'+(test.stdout or '')
            write_first_error(folder,message)
            return [{'ok':False,'reason':'INVALID_CONFIG:'+classify_xray_error(message),'http_code':0,'total_ms':0} for _ in range(requests)]
        with open(os.devnull,'wb') as devnull:
            process=subprocess.Popen([xray,'run','-c',str(path)], stdout=devnull, stderr=devnull,
                                     start_new_session=True,env=child_env)
            try:
                started=False
                for i in range(40):
                    if process.poll() is not None: break
                    try:
                        with socket.create_connection(('127.0.0.1',cfg['inbounds'][0]['port']),timeout=.15):
                            started=True;break
                    except OSError: time.sleep(.1)
                if not started:
                    return [{'ok':False,'reason':'START_FAILED','http_code':0,'total_ms':0} for _ in range(requests)]
                for i in range(requests):
                    if stop and stop.is_set(): break
                    url=urls[i%len(urls)]
                    item=probe(cfg['inbounds'][0]['port'],url,timeout)
                    item['target_index']=i%len(urls)
                    item['time']=utc()
                    stage_results.append(item)
                if throughput_url and not (stop and stop.is_set()):
                    t=probe(cfg['inbounds'][0]['port'],throughput_url,timeout,download=True)
                    t['target_index']='throughput';t['time']=utc()
                    # Throughput is kept separate from success-rate denominator.
                    stage_results.append(t)
            finally:
                if process.poll() is None:
                    try: os.killpg(process.pid,signal.SIGTERM);process.wait(timeout=2)
                    except (OSError,subprocess.TimeoutExpired):
                        os.killpg(process.pid,signal.SIGKILL);process.wait()
    finally:
        path.unlink(missing_ok=True)
    return stage_results


class Results:
    def __init__(self,folder,metadata):
        self.objective=metadata.get('spec',{}).get('objective','best-performance')
        ensure_private_dir(folder)
        self.folder=folder
        path=folder/'history.sqlite3'
        original_umask=os.umask(0o077)
        try:
            self.db=sqlite3.connect(path,check_same_thread=False)
        finally:
            os.umask(original_umask)
        os.chmod(path,0o600)
        self.db.executescript('''CREATE TABLE IF NOT EXISTS metadata(key TEXT PRIMARY KEY,value TEXT);
        CREATE TABLE IF NOT EXISTS candidates(id TEXT PRIMARY KEY, profile TEXT, config_sha256 TEXT, link_sha256 TEXT, link TEXT, config_json TEXT, changes_json TEXT, compatibility_json TEXT);
        CREATE TABLE IF NOT EXISTS measurements(id INTEGER PRIMARY KEY AUTOINCREMENT,candidate_id TEXT,stage TEXT,timestamp TEXT,result_json TEXT);
        CREATE INDEX IF NOT EXISTS measurements_candidate ON measurements(candidate_id,stage);''')
        for key,value in metadata.items():
            self.db.execute('INSERT OR REPLACE INTO metadata VALUES (?,?)',(key,json.dumps(value,ensure_ascii=False)))
        self.db.commit()
    def add_candidates(self,candidates):
        for c in candidates:
            self.db.execute('INSERT OR REPLACE INTO candidates VALUES (?,?,?,?,?,?,?,?)',
                            (c['id'],c['profile'],c['config_sha256'],c['sha256'],c['link'],
                             json.dumps(c['config'],ensure_ascii=False),json.dumps(c['changes']),
                             json.dumps(c['compatibility'],ensure_ascii=False)))
        self.db.commit()
    def measure(self,cid,stage,rows):
        for row in rows:
            self.db.execute('INSERT INTO measurements (candidate_id,stage,timestamp,result_json) VALUES (?,?,?,?)',
                            (cid,stage,row.get('time',utc()),json.dumps(row)))
        self.db.commit()
    def all_measurements(self):
        return self.db.execute('SELECT candidate_id,stage,timestamp,result_json FROM measurements ORDER BY id').fetchall()
    def export(self,candidates,excluded,*,min_success=.90,complete=False,core=None):
        probes=self.all_measurements()
        data={}
        for cid,stage,when,row in probes:
            data.setdefault((cid,stage),[]).append(json.loads(row))
        rows=[]
        for c in candidates:
            s1=data.get((c['id'],'discovery'),[])
            if c['id']==candidates[0]['id']:
                s1=sum((data.get((c['id'],tag),[]) for tag in ('baseline-start','baseline-mid','baseline-end')),[])
            s2=data.get((c['id'],'verification'),[])
            phase=s2 or s1
            quality_stats=aggregate([x for x in phase if x.get('target_index')!='throughput'])
            # Separate actual download throughput from small connectivity probes.
            downloads=[x for x in s2 if x.get('target_index')=='throughput' and
                       x.get('ok') and x.get('bytes',0)>=65536]
            quality_stats['throughput_bytes_per_sec']=(round(statistics.mean(
                x['bytes_per_second'] for x in downloads),1) if downloads else None)
            quality_stats['throughput_samples']=len(downloads)
            verified=(bool(s2) and len([x for x in s2 if x.get('target_index')!='throughput'])>=20
                      and quality_stats['success_rate']>=min_success and complete)
            status=('VERIFIED' if verified else
                    'PROVISIONAL' if s2 and quality_stats['successes'] and not complete else
                    'REJECTED' if s2 else
                    'SCREENED' if quality_stats['successes'] else
                    'UNTESTED' if not phase else 'FAILED')
            mask=proxy(c['config'])['streamSettings'].get('finalmask') or {}
            tls=proxy(c['config'])['streamSettings'].get('tlsSettings') or {}
            r={'id':c['id'],'status':status,'profile':c['profile'],
               'address':proxy(c['config'])['settings'].get('address'),
               'fingerprint':tls.get('fingerprint'),'ech_enabled':bool(tls.get('echConfigList')),
               'ech_value':tls.get('echConfigList'),'sni':tls.get('serverName'),
               'changes':json.dumps(c['changes']),
               'compatibility_status':c['compatibility']['status'],
               'generated_changes':c['effective_diff']['generated_count'],
               'core_validation':('PENDING' if not phase else
                 'REJECTED' if any(x.get('reason','').startswith('INVALID_CONFIG') for x in phase) else
                 'CORE_ACCEPTED' if any(x.get('reason','') not in ('START_FAILED',) and not x.get('reason','').startswith('START_FAILED') for x in phase) else 'NOT_STARTED'),
               'runtime_effect':'NOT_PROVEN', 'packets':json.dumps([x.get('settings',{}).get('packets') for x in mask.get('tcp',[]) if x.get('type')=='fragment']),
               'lengths':json.dumps([x.get('settings',{}).get('lengths') for x in mask.get('tcp',[]) if x.get('type')=='fragment']),
               'delays':json.dumps([x.get('settings',{}).get('delays') for x in mask.get('tcp',[]) if x.get('type')=='fragment']),
               'maxSplit':json.dumps([x.get('settings',{}).get('maxSplit') for x in mask.get('tcp',[]) if x.get('type')=='fragment']),
               'finalmask_json':json.dumps(mask,ensure_ascii=False,sort_keys=True),
               'discovery_success_rate':aggregate([x for x in s1 if x.get('target_index')!='throughput'])['success_rate'],
               'verification_success_rate':aggregate([x for x in s2 if x.get('target_index')!='throughput'])['success_rate'] if s2 else '',
               **quality_stats,'link_sha256':c['sha256'],'config_sha256':c['config_sha256']}
            rows.append(r)
        objective=self.objective
        def decision(r):
            priority=0 if r['status']=='VERIFIED' else 1 if r['status']=='PROVISIONAL' else 2
            gate=0 if r['success_rate']>=min_success else 1
            latency=r['p95_ms'] if r['p95_ms'] is not None else 1e12
            median=r['median_ms'] if r['median_ms'] is not None else 1e12
            jitter=r['jitter_ms'] if r['jitter_ms'] is not None else 1e12
            bps=r.get('throughput_bytes_per_sec')
            throughput=-bps if bps is not None else 1e12
            if objective=='max-reliability':
                detail=(-r['success_rate'],-r['wilson_lower95'],latency,jitter)
            elif objective=='lowest-latency':
                detail=(latency,median,-r['success_rate'],jitter)
            elif objective=='balanced':
                detail=(latency,jitter,-r['success_rate'],throughput)
            else:  # Best Performance: throughput measured on the same specified target.
                detail=(throughput,latency,jitter,-r['success_rate']) if bps is not None else (latency,median,jitter,-r['success_rate'])
            return (priority,gate,*detail,r['id'])
        ranking=sorted(rows,key=decision)
        for i,r in enumerate(ranking,1):r['rank']=i
        fields=list(ranking[0]) if ranking else []
        if fields:
            safe_csv(self.folder/'results.csv',fields,rows)
            safe_csv(self.folder/'ranked.csv',fields,ranking)
        safe_csv(self.folder/'finalmask-instances.csv',list(project(rows[0])) if rows else [],[project(r) for r in rows])
        safe_csv(self.folder/'top-three-lowest-average.csv',list(project(rows[0])) if rows else [],[project(r) for r in best_three(rows)])
        safe_text_file(self.folder/'finalmask-table.txt',text_report(rows).splitlines())
        safe_csv(self.folder/'links.csv',['id','link'],[{'id':x['id'],'link':x['link']} for x in candidates])
        safe_text_file(self.folder/'links.txt',[x['link'] for x in candidates])
        safe_text_file(self.folder/'verified-links.txt',[x['link'] for x in candidates if next(r for r in rows if r['id']==x['id'])['status']=='VERIFIED'])
        safe_text_file(self.folder/'provisional-links.txt',[x['link'] for x in candidates if next(r for r in rows if r['id']==x['id'])['status']=='PROVISIONAL'])
        safe_csv(self.folder/'probes.csv',['id','stage','timestamp','result_json'],
                 [{'id':cid,'stage':stage,'timestamp':when,'result_json':raw} for cid,stage,when,raw in probes])
        safe_text_file(self.folder/'manifest.jsonl',[json.dumps({'id':c['id'],'sha256':c['sha256'],
                                                                 'config_sha256':c['config_sha256'],
                                                                 'profile':c['profile'],'changes':c['changes'],
                                                                 'compatibility':c['compatibility'],
                                                                 'effective_diff':c['effective_diff'],
                                                                 'finalmask':proxy(c['config'])['streamSettings'].get('finalmask')},ensure_ascii=False)
                                                       for c in candidates])
        safe_text_file(self.folder/'diffs.jsonl',[json.dumps({'id':c['id'],
            'sha256':c['sha256'],'diff':c['effective_diff'],
            'compatibility':c['compatibility']},ensure_ascii=False) for c in candidates])
        private_json(self.folder/'excluded.json',excluded)
        best=next((r for r in ranking if r['status']=='VERIFIED'),None)
        if best:
            safe_text_file(self.folder/'best-link.txt',[next(c['link'] for c in candidates if c['id']==best['id'])])
        else:
            (self.folder/'best-link.txt').unlink(missing_ok=True)
        start_baseline=aggregate(data.get((candidates[0]['id'],'baseline-start'),[])) if candidates else aggregate([])
        end_baseline=aggregate(data.get((candidates[0]['id'],'baseline-end'),[])) if candidates else aggregate([])
        drift={'initial_success_rate':start_baseline['success_rate'],
               'end_success_rate':end_baseline['success_rate'],
               'success_delta':round(end_baseline['success_rate']-start_baseline['success_rate'],4)
               if start_baseline['requests'] and end_baseline['requests'] else None,
               'median_delta_ms':round(end_baseline['median_ms']-start_baseline['median_ms'],2)
               if start_baseline['median_ms'] is not None and end_baseline['median_ms'] is not None else None}
        explanation=None
        if best:
            explanation={'fa':'این کاندیدا آستانهٔ موفقیت مرحلهٔ تأیید را گذرانده و با نرخ موفقیت و سپس P95 رتبه‌بندی شده است. افزایش عملکرد تضمین‌شده نیست.',
                         'en':'Candidate passed the verification success threshold; ordered by success and P95. Improvement is not guaranteed.',
                         'baseline_comparison':'unavailable or incomplete' if start_baseline['median_ms'] is None or best['median_ms'] is None else
                         {'median_delta_ms':round(best['median_ms']-start_baseline['median_ms'],2),
                          'success_delta':round(best['success_rate']-start_baseline['success_rate'],5)}}
        summary={'completed':complete,'core':core, 'created_at':utc(), 'candidates':len(candidates),
                 'objective':self.objective,
                 'baseline_drift':drift,'why_winner':explanation,
                 'excluded':len(excluded), 'verified':sum(r['status']=='VERIFIED' for r in rows),
                 'compatibility_statuses':{state:sum(c['compatibility']['status']==state for c in candidates)
                   for state in ('BLOCKED','EXPERIMENTAL','DOCUMENTED_UNVERIFIED')},
                 'best_id':best['id'] if best else None,
                 'note':'VERIFIED means this configured test passed its threshold; not proof of permanent connectivity.',
                 'rows':[{'id':r['id'],'status':r['status'],'success_rate':r['success_rate'],
                          'p95_ms':r['p95_ms'],'median_ms':r['median_ms'],'rank':r.get('rank')} for r in ranking]}
        summary['top_three_lowest_average']=[{'id':r['id'],'avg_ms':r['avg_ms'],'status':r['status']} for r in best_three(rows)]
        private_json(self.folder/'summary.json',summary)
        return summary


def run(link, raw_spec, folder, *, dry_run=False, override_core=None, stop=None, callback=None):
    spec=settings(raw_spec)
    ensure_private_dir(folder)
    core=None;binary='';binary_sha=''
    if not dry_run:
        binary=resolve_core(override_core,dry_run=False)
        binary_sha=hashlib.sha256(Path(binary).read_bytes()).hexdigest()
        core=core_identity(binary)
    else: core='DRY_RUN_NO_CORE'
    store=Results(folder, {'spec':{k:v for k,v in spec.items() if k!='link'},'core':core,
                           'binary_sha256':binary_sha,'seed':spec['seed'],'start_time':utc(),
                           'dry_run':dry_run})
    prior_samples=[]
    original=link_to_config(link)
    # Adapt preset set ONCE, based on the initial original-link probe.
    if not dry_run:
        prior_samples=exec_candidate(binary,original,folder,spec['targets'],spec['stage1_requests'],spec['timeout'],stop=stop)
    baseline_rate=aggregate(prior_samples)['success_rate'] if prior_samples else None
    baseline_metrics=aggregate(prior_samples) if prior_samples else {}
    candidates,excluded=matrix(link,spec,baseline_success=baseline_rate,
                               baseline_median_ms=baseline_metrics.get('median_ms'),
                               baseline_jitter_ms=baseline_metrics.get('jitter_ms'), core_version=core)
    store.add_candidates(candidates)
    orig=candidates[0]
    if prior_samples:store.measure(orig['id'],'baseline-start',prior_samples)
    def tick(message):
        if callback:callback(message)
    tick({'event':'ready','candidates':len(candidates),'excluded':len(excluded),'core':core})
    if dry_run:
        summary=store.export(candidates,excluded,min_success=spec['min_success'],core=core)
        tick({'event':'complete','summary':summary});store.db.close();return summary
    shuffled=candidates[1:]
    random.Random(spec['seed']).shuffle(shuffled)
    for i,c in enumerate(shuffled,1):
        if stop and stop.is_set():break
        rs=exec_candidate(binary,c['config'],folder,spec['targets'],spec['stage1_requests'],spec['timeout'],stop=stop)
        store.measure(c['id'],'discovery',rs)
        tick({'event':'discovery','completed':i,'total':len(shuffled),'id':c['id'], 'stats':aggregate(rs)})
        if i%spec['baseline_every']==0:
            b=exec_candidate(binary,orig['config'],folder,spec['targets'],spec['stage1_requests'],spec['timeout'],stop=stop)
            store.measure(orig['id'],'baseline-mid',b)
        store.export(candidates,excluded,min_success=spec['min_success'],core=core)
    completed=not(stop and stop.is_set())
    if completed:
        b=exec_candidate(binary,orig['config'],folder,spec['targets'],spec['stage1_requests'],spec['timeout'],stop=stop)
        store.measure(orig['id'],'baseline-end',b)
        # Include baseline as a candidate eligible for verification.
        stage1={c['id']:([json.loads(x[3]) for x in store.all_measurements() if x[0]==c['id'] and
                              (x[1]=='discovery' or (c['id']==orig['id'] and x[1]=='baseline-start'))]) for c in candidates}
        choices=sorted(candidates,key=lambda c:quality(aggregate(stage1[c['id']])))
        candidates_to_verify=[c for c in choices if aggregate(stage1[c['id']])['successes']>0][:spec['verify_top']]
        for i,c in enumerate(candidates_to_verify,1):
            if stop and stop.is_set():break
            samples=exec_candidate(binary,c['config'],folder,spec['targets'],spec['stage2_requests'],spec['timeout'],
                                   stop=stop,throughput_url=spec['throughput_url'])
            store.measure(c['id'],'verification',samples)
            tick({'event':'verification','completed':i,'total':len(candidates_to_verify),'id':c['id'], 'stats':aggregate([x for x in samples if x.get('target_index')!='throughput'])})
            store.export(candidates,excluded,min_success=spec['min_success'],core=core)
    completed=completed and not(stop and stop.is_set())
    result=store.export(candidates,excluded,min_success=spec['min_success'],complete=completed,core=core)
    store.db.close()
    tick({'event':'complete','summary':result})
    return result


def main(argv=None):
    p=argparse.ArgumentParser(description='V8 fixed-matrix Expert/Auto benchmark (not progressive)')
    p.add_argument('--link-file',type=Path,required=True,help='private one-line VLESS/VMess/Trojan link (chmod 600)')
    p.add_argument('--spec',type=Path,help='Expert/Auto scan parameters JSON')
    p.add_argument('--output',type=Path)
    p.add_argument('--dry-run',action='store_true')
    p.add_argument('--xray',help='explicit override; else latest verified prerelease')
    args=p.parse_args(argv)
    link=args.link_file.read_text(encoding='utf-8').strip()
    spec=json.loads(args.spec.read_text(encoding='utf-8')) if args.spec else {}
    folder=(args.output or (ROOT_RESULTS/('scan-'+datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')))).expanduser()
    def on_event(event):
        kind=event.get('event')
        if kind in ('discovery','verification'):
            m=event.get('stats',{})
            print(f"[{kind}] {event.get('completed')}/{event.get('total')}  {event.get('id')}  "
                  f"success={m.get('successes',0)}/{m.get('requests',0)} "
                  f"avg={m.get('avg_ms') if m.get('avg_ms') is not None else '-'} ms", flush=True)
        elif kind=='ready':
            print(f"[ready] {event.get('candidates')} instances; excluded={event.get('excluded')}",flush=True)
    result=run(link,spec,folder,dry_run=args.dry_run,override_core=args.xray,
               callback=on_event)
    print((folder/'finalmask-table.txt').read_text(encoding='utf-8'))
    print('Results:',folder)
    print('Best verified:',result.get('best_id') or '(none)')
    return 0

if __name__=='__main__':
    try:sys.exit(main())
    except (OSError, ValueError, json.JSONDecodeError, CoreError) as exc:
        print(f'V8: {type(exc).__name__}: {str(exc)[:180]}',file=sys.stderr)
        sys.exit(2)
