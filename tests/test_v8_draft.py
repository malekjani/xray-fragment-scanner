"""Offline coverage for V8 draft. No real provider, user link or live network."""
import csv
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'lib'))
from v8_engine import matrix,run,aggregate,wilson_lower,settings,auto_masks
from v8_compat import validate,safe_summary
from share_codec import link_to_config
from network_scan import proxy

LINK='vless://12345678-1234-4234-8234-123456789abc@origin.example.net:2053?security=tls&type=ws&host=origin.example.net&path=%2Fws&fp=firefox&ech=cloudflare-ech.com%2Budp%3A%2F%2F1.1.1.1&encryption=none#node'
F={'type':'fragment','settings':{'packets':'tlshello','lengths':['6','98','1'],'delays':['0'],'maxSplit':'0'}}
H={'type':'header-custom','settings':{'clients':[[{'type':'str','packet':'HELLO\\r\\n','delay':0}]],'servers':[],'errors':[]}}
SPEC={'mode':'expert','fingerprints':['original','chrome'],'ech_values':['original','none'],
      'mask_profiles':['original',{'name':'f','layers':[F]},{'name':'combo','layers':[H,F]}],
      'max_candidates':30,'targets':['https://www.gstatic.com/generate_204']}

class DraftV8Tests(unittest.TestCase):
    def test_expert_matrix_has_unique_id_sha_links_and_effective_changes(self):
        a,excluded=matrix(LINK,SPEC)
        self.assertEqual(len(a),12)
        self.assertEqual(excluded,[])
        for c in a:
            other=link_to_config(c['link'])
            self.assertEqual(proxy(other)['settings'],proxy(c['config'])['settings'])
            self.assertEqual(proxy(other)['streamSettings'],proxy(c['config'])['streamSettings'])
            self.assertTrue(c['sha256'])
            self.assertEqual(proxy(other)['streamSettings']['wsSettings']['path'],'/ws')
        self.assertEqual(a[0]['link'],LINK)
        self.assertEqual([x['type'] for x in proxy(a[2]['config'])['streamSettings']['finalmask']['tcp']],['header-custom','fragment'])
        self.assertNotIn('echConfigList',proxy(a[3]['config'])['streamSettings']['tlsSettings'])

    def test_browser_dialer_and_other_invalid_combinations_blocked(self):
        orig=link_to_config(LINK)
        proxy(orig)['streamSettings']['tlsSettings']['serverName']='different.example.net'
        labels=[f.code for f in validate(orig,browser_dialer=True)]
        self.assertIn('browser-host-sni',labels)
        self.assertIn('browser-runtime',labels)
        blocked=link_to_config(LINK)
        proxy(blocked)['streamSettings']['network']='hysteria'
        proxy(blocked)['streamSettings']['finalmask']={'tcp':[F]}
        self.assertFalse(safe_summary(blocked)['allowed'])
        orig=link_to_config(LINK)
        proxy(orig)['streamSettings']['finalmask']={'tcp':[{'type':'fragment','settings':{'packets':'tlshello','lengths':['0'],'delays':['0'],'maxSplit':'0'}}]}
        self.assertFalse(safe_summary(orig)['allowed'])

    def test_explicit_matrix_limit_never_silently_samplers(self):
        oversized={**SPEC,'max_candidates':5}
        with self.assertRaisesRegex(ValueError,'exceed max_candidates'):
            matrix(LINK,oversized)

    def test_temporary_offline_export_and_private_sqlite(self):
        with tempfile.TemporaryDirectory() as td:
            out=Path(td)/'out'
            result=run(LINK,SPEC,out,dry_run=True)
            self.assertEqual(result['candidates'],12)
            self.assertEqual(result['verified'],0)
            self.assertIsNone(result['best_id'])
            self.assertFalse((out/'best-link.txt').exists())
            for name in ('ranked.csv','links.csv','links.txt','manifest.jsonl','probes.csv','summary.json','excluded.json','history.sqlite3'):
                self.assertTrue((out/name).is_file(),name)
                self.assertEqual(os.stat(out/name).st_mode & 0o777,0o600)
            self.assertEqual(os.stat(out).st_mode & 0o777,0o700)
            with (out/'links.csv').open() as fh: links=list(csv.DictReader(fh))
            with (out/'results.csv').open() as fh: rows=list(csv.DictReader(fh))
            self.assertEqual([x['id'] for x in links],[x['id'] for x in rows])
            self.assertEqual(len(rows),12)
            self.assertTrue(all(x['status']=='UNTESTED' for x in rows))

    def test_auto_network_preflight_selects_fixed_profile_set(self):
        good=auto_masks(1,50,10)
        bad=auto_masks(0,1500,650)
        self.assertGreater(len(bad),len(good))
        with self.assertRaisesRegex(ValueError,'Browser Dialer'):
            settings({'browser_dialer':True})

    def test_wilson_interval_does_not_claim_100_percent_certainty(self):
        self.assertLess(wilson_lower(30,30),.9)
        a=aggregate([{'ok':True,'reason':'OK','total_ms':20}]*5)
        self.assertEqual(a['p95_ms'],20)
        self.assertLess(a['wilson_lower95'],1)
        self.assertEqual(a['requests'],5)

    def test_live_mock_two_stage_baseline_drift_and_verified_links(self):
        # No real Xray/curl required; verify control scheduling and reporting logic.
        with tempfile.TemporaryDirectory() as td:
            exe=Path(td)/'fake-xray';exe.write_text('fake')
            spec={'mode':'expert','mask_profiles':['original',{'name':'f','layers':[F]}],
                  'max_candidates':3,'targets':['https://www.gstatic.com/generate_204'],
                  'stage1_requests':3,'stage2_requests':20,'verify_top':2,'baseline_every':1}
            calls=[]
            def fake(_exe,cfg,_dir,urls,count,_timeout,*,stop=None,throughput_url=None):
                selected=bool(proxy(cfg)['streamSettings'].get('finalmask'))
                calls.append(('mask' if selected else 'original',count))
                return [{'ok':True,'reason':'OK','http_code':204,'total_ms':10 if selected else 100,
                         'bytes':0,'bytes_per_second':0,'target_index':0} for _ in range(count)]
            with patch('v8_engine.resolve_core',return_value=str(exe)), patch('v8_engine.core_identity',return_value='Xray TEST'),patch('v8_engine.exec_candidate',side_effect=fake):
                result=run(LINK,spec,Path(td)/'output',dry_run=False)
            self.assertTrue(result['completed'])
            self.assertEqual(result['verified'],2)
            self.assertIsNotNone(result['best_id'])
            self.assertGreater(len(calls),4)
            self.assertEqual(result['baseline_drift']['initial_success_rate'],1)
            self.assertTrue((Path(td)/'output'/'best-link.txt').exists())
            self.assertIsNotNone(result['why_winner'])

if __name__=='__main__':unittest.main()
