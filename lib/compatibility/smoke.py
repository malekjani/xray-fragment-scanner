#!/usr/bin/env python3
"""Run private, *non-network* Xray-core compatibility tests for V8 Expert masks.

Actual `xray run -test` is used against the selected (locked) executable. Results
are for core/schema acceptance only, NEVER proof of connection or mask behavior.
No live traffic, root privileges, or public uploads.
"""
from __future__ import annotations
import argparse
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from core_manager import resolve_core, core_identity
from network_scan import proxy, write_private_json
from v8_engine import matrix, settings, ensure_private_dir, private_json, sha_text
from xray_errors import classify


def presets():
    base={'type':'fragment','settings':{'packets':'tlshello',
        'lengths':['6','98','1'],'delays':['0'],'maxSplit':'0'}}
    header={'type':'header-custom','settings':{
        'clients':[[{'delay':0,'rand':8,'randRange':'0-255'}]],
        'servers':[],'errors':[]}}
    return ['original',
        {'name':'fragment-only','layers':[base]},
        {'name':'header-only','layers':[header]},
        {'name':'header-then-fragment','layers':[header,base]},
        {'name':'fragment-then-header','layers':[base,header]}]


def check(link: str, binary: str, folder: Path):
    ensure_private_dir(folder)
    identity=core_identity(binary)
    spec=settings({'mode':'expert','max_candidates':40,
        'ech_values':['original','none'],
        'fingerprints':['original','chrome'],
        'addresses':['original'],'mask_profiles':presets()})
    candidates,excluded=matrix(link,spec,core_version=identity)
    records=[]
    for c in candidates:
        with tempfile.TemporaryDirectory(prefix='xray-v8-compat-') as td:
            cfg=copy.deepcopy(c['config']);cfg['inbounds'][0]['port']=0
            path=Path(td)/'candidate.json'
            write_private_json(path,cfg)
            try:
                result=subprocess.run([binary,'run','-test','-c',str(path)],
                       capture_output=True,text=True,timeout=20)
                outcome='CORE_VALID' if result.returncode==0 else 'CORE_REJECTED'
                reason='accepted' if result.returncode==0 else classify((result.stderr or '')+'\n'+(result.stdout or ''))
            except subprocess.TimeoutExpired:
                outcome,reason='TIMEOUT','core-validation-timeout'
            except OSError:
                outcome,reason='ERROR','core-executable-unavailable'
            records.append({'id':c['id'],'profile':c['profile'],
                'config_sha256':c['config_sha256'],
                'compatibility_status':c['compatibility']['status'],
                'outcome':outcome,'reason':reason,
                'note':'CORE_VALID does NOT establish network success or observable effects'})
    report={'core':identity,'binary_sha256':__import__('hashlib').sha256(Path(binary).read_bytes()).hexdigest(),
            'schema':'V8 private core-compatibility matrix',
            'results':records,'excluded_count':len(excluded),
            'warnings':['Browser Dialer requires manual browser tests; it is not included in this automated check',
                        'Unknown future Xray behavior remains experimental until tested']}
    private_json(folder/'compatibility-matrix.json',report)
    return report


def main(argv=None):
    ap=argparse.ArgumentParser(description='Offline schema compatibility checks with real Xray prerelease; no network probes')
    ap.add_argument('--link-file',type=Path,required=True)
    ap.add_argument('--core',help='Explicit local Xray binary; default auto-verified latest prerelease')
    ap.add_argument('--output',type=Path,default=Path.home()/'.local/share/xray-finalmask-scanner/v8-compatibility')
    args=ap.parse_args(argv)
    link=args.link_file.read_text(encoding='utf-8').strip()
    binary=resolve_core(args.core,dry_run=False)
    report=check(link,binary,args.output.expanduser())
    print('Core:',report['core'])
    print('Checked:',len(report['results']))
    print('Accepted:',sum(x['outcome']=='CORE_VALID' for x in report['results']))
    print('Rejected:',sum(x['outcome']!='CORE_VALID' for x in report['results']))
    print('Private report:',args.output.expanduser()/'compatibility-matrix.json')
    return 0

if __name__=='__main__':
    try:sys.exit(main())
    except (ValueError,OSError) as exc:
        print('Compatibility check failed:',type(exc).__name__,file=sys.stderr)
        sys.exit(2)
