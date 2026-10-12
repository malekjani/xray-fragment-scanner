import csv
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from urllib.parse import parse_qs, urlsplit, urlencode

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'lib'))
from optimize import (fragment, merge_fragments, make_candidates, parse_array,
                      parse_range, share_link, summarize_parameters, ranking)
from network_scan import vless_to_config, proxy
from unittest.mock import patch
from optimize import main as optimize_main

UUID = '12345678-1234-4234-8234-123456789abc'
TOK = 'mlkem768x25519plus.native.0rtt.' + 'abcDEF_-' * 120
ORIGINAL_MASK = {
    'udp': [{'type':'noise','settings': {'reset': '28','noise':[{'rand':'1200-1230','delay':'10'}]}}],
    'tcp': [{'type':'header-custom', 'settings': {'clients':[[{'delay':0,'type':'str','packet':'HELLO'}]],'servers':[],'errors':[]}},
            {'type':'fragment','settings':{'packets':'1-2','lengths':['2'],'delays':['5'],'maxSplit':'3'}}],
    'quicParams': {'congestion': 'force-brutal'},
}
PARAMS = {
    'encryption': TOK, 'security':'tls', 'sni':'domain.example.org', 'fp':'firefox',
    'alpn':'h2', 'ech':'cloudflarestaging.com+udp://1.1.1.1',
    'type':'ws', 'host':'domain.example.org', 'path':'/a7f3c9?ed=2566',
    'pcs': '6a5f' * 16, 'vcn':'domain.example.org',
    'fm': '"finalmask":'+json.dumps(ORIGINAL_MASK),
}
URL = f'vless://{UUID}@cf1.baran24.net:2053?' + urlencode(PARAMS) + '#DE%20test'


class OptimizeTests(unittest.TestCase):
    def test_lengths_and_delays_range_validation(self):
        self.assertEqual(parse_array('0,104,1', final_nonzero=True), ['0','104','1'])
        self.assertEqual(parse_array('5-10,20,1', final_nonzero=True), ['5-10','20','1'])
        self.assertEqual(parse_range('0'), '0')
        for bad in ('-1','1-0','hi','2147483648','0-'):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                parse_range(bad)
        with self.assertRaises(ValueError):
            parse_array('104,0', final_nonzero=True)

    def test_merged_preserves_non_fragment_mask_components(self):
        result = merge_fragments(ORIGINAL_MASK, [fragment('tlshello','0,104,1','0','0')])
        self.assertEqual(result['udp'], ORIGINAL_MASK['udp'])
        self.assertEqual(result['quicParams'], ORIGINAL_MASK['quicParams'])
        self.assertEqual(result['tcp'][0], ORIGINAL_MASK['tcp'][0])
        self.assertEqual(result['tcp'][1]['settings']['lengths'], ['0', '104', '1'])
        self.assertEqual(ORIGINAL_MASK['tcp'][1]['settings']['lengths'], ['2'])

    def test_all_candidates_link_roundtrip_preserves_ech_fp_pq_and_ws(self):
        source = vless_to_config(URL)
        candidates = list(make_candidates(source, 'both', 'cf1.baran24.net',
                                          ['tlshello'], ['0,104,1'], ['0'], ['0'],
                                          ('1-1','114,1','1','11')))
        self.assertGreaterEqual(len(candidates), 5)
        for i, (mode, preset, x) in enumerate(candidates, 1):
            link = share_link(URL, x, 'OPT-000' + str(i), baseline=mode=='baseline')
            reverse = vless_to_config(link)
            self.assertEqual(proxy(x)['settings'], proxy(reverse)['settings'])
            self.assertEqual(proxy(x)['streamSettings'], proxy(reverse)['streamSettings'])
            original_query = parse_qs(urlsplit(URL).query)
            query = parse_qs(urlsplit(link).query)
            for key in original_query:
                if key != 'fm':
                    self.assertEqual(query[key], original_query[key], key)
            self.assertEqual(proxy(reverse)['streamSettings']['tlsSettings']['fingerprint'], 'firefox')
            self.assertEqual(proxy(reverse)['streamSettings']['tlsSettings']['echConfigList'], PARAMS['ech'])
            self.assertEqual(proxy(reverse)['settings']['encryption'], TOK)
            self.assertEqual(proxy(reverse)['streamSettings']['wsSettings']['path'], PARAMS['path'])
            if mode != 'baseline':
                self.assertIn('fm', query)
                self.assertTrue(query['fm'][0].startswith('"finalmask":{'))

    def test_new_address_changes_only_address(self):
        original = vless_to_config(URL)
        mode,preset,x = next(c for c in make_candidates(original, 'fragment', '188.114.97.4',
                                                          ['1-2'],['5-10'],['1-5'],['2-4']) if c[0] != 'baseline')
        link = share_link(URL, x, 'OPT-0002')
        self.assertEqual(urlsplit(link).hostname, '188.114.97.4')
        self.assertEqual(proxy(vless_to_config(link))['streamSettings']['tlsSettings']['serverName'], PARAMS['sni'])
        self.assertEqual(proxy(vless_to_config(link))['streamSettings']['finalmask'],
                         proxy(x)['streamSettings']['finalmask'])

    def test_full_tabular_export_hash_join_permissions_and_no_false_winner(self):
        with tempfile.TemporaryDirectory() as temp:
            temp = Path(temp)
            lf = temp/'secret-vless.txt'
            lf.write_text(URL)
            output = temp/'out'
            script = ROOT/'bin/xray-finalmask-scanner'
            p = subprocess.run(['bash',str(script),'--method','optimize',
                  '--link-file', str(lf), '--scan','both', '--packets','tlshello',
                  '--lengths','0,104,1','--delays','0', '--max-split','0',
                  '--layer2-lengths','114,1','--all','--dry-run','--output',str(output)],
                  capture_output=True,text=True)
            self.assertEqual(p.returncode,0,p.stderr)
            with (output/'results.csv').open() as f:
                results=list(csv.DictReader(f))
            with (output/'ranked.csv').open() as f:
                ranked=list(csv.DictReader(f))
            with (output/'links.csv').open() as f:
                links=list(csv.DictReader(f))
            manifest=[json.loads(x) for x in (output/'manifest.jsonl').read_text().splitlines()]
            self.assertEqual(len(results),len(ranked))
            self.assertEqual(len(results),len(links))
            self.assertEqual(len(results),len(manifest))
            self.assertGreaterEqual(len(results), 5)
            self.assertEqual([r['id'] for r in results], [x['id'] for x in links])
            for row, lk, m in zip(results, links, manifest):
                self.assertEqual(row['id'],m['id'])
                self.assertEqual(row['link_sha256'],hashlib.sha256(lk['link'].encode()).hexdigest())
                self.assertEqual(row['link_sha256'],m['link_sha256'])
                self.assertEqual(json.loads(row['fragment_layers']),m['fragment_layers'])
                self.assertEqual(json.loads(row['finalmask_json']) if row['finalmask_json'] else None,m['finalmask'])
                self.assertEqual(row['status'],'DRY_RUN')
                self.assertEqual(row['rank'],'')
                self.assertEqual(row['avg_ms'],'')
                self.assertEqual(row['p95_ms'],'')
            self.assertNotIn(UUID,(output/'results.csv').read_text())
            self.assertNotIn(UUID,p.stdout)
            self.assertEqual(os.stat(output).st_mode & 0o777, 0o700)
            self.assertEqual(os.stat(output/'links.csv').st_mode & 0o777, 0o600)
            self.assertFalse((output/'best-vless.txt').exists())
            self.assertFalse((output/'best-config.json').exists())
            self.assertEqual(len((output/'links.txt').read_text().splitlines()),len(results))

    def test_full_success_chooses_best_and_writes_matching_link(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            lf = root / 'input.txt'
            lf.write_text(URL)
            out = root/'results'
            def fake_run(_xray, cfg, _path, _url, requests, _timeout, times_out=None):
                # Real API shape: return successful results and observed request timings.
                fm = proxy(cfg)['streamSettings'].get('finalmask', {})
                is_fragment = any(e.get('type') == 'fragment' and e.get('settings', {}).get('lengths') == ['0','104','1'] for e in fm.get('tcp', []))
                latencies = [22.0, 28.0, 25.0] if is_fragment else [75.0, 80.0, 90.0]
                times_out.extend(latencies)
                return ('OK',requests, round(sum(latencies)/len(latencies),2), '')
            with patch('optimize.shutil.which', return_value='/usr/bin/curl'), patch('optimize.run_candidate', side_effect=fake_run):
                rc = optimize_main(['--link-file',str(lf), '--scan','fragment', '--packets','tlshello',
                                    '--lengths','0,104,1', '--delays','0', '--max-split','0',
                                    '--all', '--requests','3', '--output', str(out), '--xray',sys.executable])
            self.assertEqual(rc, 0)
            with (out/'ranked.csv').open() as f:
                ranked=list(csv.DictReader(f))
            with (out/'links.csv').open() as f:
                links={r['id']:r['link'] for r in csv.DictReader(f)}
            self.assertEqual(ranked[0]['mode'], 'fragment')
            self.assertEqual(ranked[0]['p95_ms'], '28.0')
            self.assertEqual(ranked[0]['rank'], '1')
            self.assertEqual((out/'best-vless.txt').read_text().strip(),links[ranked[0]['id']])
            self.assertEqual(vless_to_config(links[ranked[0]['id']])['outbounds'][0]['streamSettings']['finalmask'],
                             json.loads((out/'best-config.json').read_text())['outbounds'][0]['streamSettings']['finalmask'])

    def test_reject_unmapped_link_fields_and_no_silent_testing(self):
        with tempfile.TemporaryDirectory() as d:
            linkfile=Path(d)/'input.txt'
            linkfile.write_text(URL+'&extra-param=unmodelled')  # deliberately after #, therefore harmless fragment
            url=URL.replace('#DE%20test','&extra-param=unmodelled#DE%20test')
            linkfile.write_text(url)
            proc=subprocess.run([sys.executable, str(ROOT/'lib/optimize.py'),
                 '--link-file',str(linkfile),'--dry-run'],capture_output=True,text=True)
            self.assertNotEqual(proc.returncode,0)
            self.assertIn('unmapped fields',proc.stderr)
            self.assertNotIn(UUID,proc.stderr)


if __name__ == '__main__':
    unittest.main()
