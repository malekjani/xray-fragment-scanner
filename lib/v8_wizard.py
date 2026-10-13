"""V8 interactive terminal flow; all output uses v8_table like the dashboard."""
from __future__ import annotations

import getpass
import json
from datetime import datetime, timezone
from pathlib import Path
import sys

from v8_engine import ROOT_RESULTS, run
from v8_table import text_report

EXAMPLE = Path(__file__).resolve().parent.parent / 'examples' / 'v8-finalmask-only.json'


def ask(prompt, default):
    value=input(f'{prompt} [{default}]: ').strip()
    return value or str(default)


def main():
    print('\nXray V8 — FinalMask Scanner | Console + Web use one results table')
    print('Credentials are read privately; never paste your URI as a command argument.')
    link=getpass.getpass('VLESS / VMess / Trojan URI (hidden): ').strip()
    if not link:
        raise ValueError('An original link is required')
    print('\nScan scope: 1) FinalMask ONLY (recommended), 2) Auto, 3) Expert spec from JSON')
    choice=ask('Select', '1')
    if choice=='1':
        spec=json.loads(EXAMPLE.read_text(encoding='utf-8'))
        print(f"FinalMask-only: {len(spec['mask_profiles'])-1} fragment profiles plus unchanged baseline")
    elif choice=='2':
        spec={'mode':'auto'}
    elif choice=='3':
        spec_file=Path(input('Expert spec JSON path: ').strip()).expanduser()
        spec=json.loads(spec_file.read_text(encoding='utf-8'))
    else:
        raise ValueError('Unknown scan scope')
    spec['stage1_requests']=int(ask('Discovery HTTPS requests per instance',spec.get('stage1_requests',5)))
    spec['stage2_requests']=int(ask('Verification HTTPS requests per top candidate',spec.get('stage2_requests',25)))
    spec['verify_top']=int(ask('Top candidates to verify',spec.get('verify_top',5)))
    spec['timeout']=float(ask('Request timeout in seconds',spec.get('timeout',8)))
    spec['max_candidates']=int(ask('Maximum candidate budget',spec.get('max_candidates',60)))
    dry=ask('Run live test? y/N','n').lower() in {'yes','y'}
    folder=ROOT_RESULTS/('scan-'+datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S'))
    print('\nEach test preserves its exact FinalMask JSON, share link and stable Instance ID.')
    print('Average Response means proxied HTTPS time, NOT ping. No verified winner in dry-run.')
    if ask('Start? Y/n','y').lower() not in ('y','yes'):return 0
    def tick(event):
        if event.get('event') in ('discovery','verification'):
            s=event.get('stats') or {}
            print(f"{event['event']}: {event.get('id')} "
                  f"{s.get('successes',0)}/{s.get('requests',0)} "
                  f"avg={s.get('avg_ms') if s.get('avg_ms') is not None else '—'} ms",flush=True)
    summary=run(link,spec,folder,dry_run=not dry,callback=tick)
    print((folder/'finalmask-table.txt').read_text(encoding='utf-8'))
    print('Results:',folder)
    print('Best VERIFIED:',summary.get('best_id') or 'none')
    return 0

if __name__=='__main__':
    try:sys.exit(main())
    except (KeyboardInterrupt,EOFError):print('\nCancelled',file=sys.stderr);sys.exit(130)
    except (ValueError,OSError) as exc:print('V8 wizard:',type(exc).__name__,file=sys.stderr);sys.exit(2)
