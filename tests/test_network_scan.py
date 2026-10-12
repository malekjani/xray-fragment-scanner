import copy
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from urllib.parse import urlencode

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'lib'))
from network_scan import (CF_IPS, ECH_DNS, ZERO_FREE_MASK, build_candidates,
                          vless_to_config, balanced_sample, extract_finalmask)

USER = '12345678-1234-4234-8234-123456789abc'
FM = '"finalmask": {"tcp":[{"type":"fragment","settings":{"packets":"1-2","length":"1-3","delay":"1-5","maxSplit":"2-4"}}]},'
QUERY = {'encryption': 'mlkem768x25519plus.native.0rtt.example', 'security': 'tls',
         'sni': 'edge.example.org', 'fp': 'firefox', 'alpn': 'h2',
         'ech': 'cloudflarestaging.com+udp://1.1.1.1', 'fm': FM,
         'type': 'ws', 'host': 'edge.example.org', 'path': '/abcd?ed=2566'}
URL = f'vless://{USER}@original.example:2053?' + urlencode(QUERY) + '#tag'

class NetworkScanTests(unittest.TestCase):
    def setUp(self):
        self.config = vless_to_config(URL)

    def test_full_vless_parameters_preserved(self):
        o = self.config['outbounds'][0]
        self.assertEqual(o['settings']['encryption'], QUERY['encryption'])
        self.assertEqual(o['settings']['address'], 'original.example')
        self.assertEqual(o['streamSettings']['wsSettings']['path'], QUERY['path'])
        self.assertEqual(o['streamSettings']['tlsSettings']['serverName'], QUERY['sni'])
        self.assertEqual(o['streamSettings']['tlsSettings']['echConfigList'], QUERY['ech'])
        self.assertEqual(o['streamSettings']['finalmask']['tcp'][0]['settings']['maxSplit'], '2-4')

    def test_full_ech_matrix(self):
        cands = list(build_candidates(self.config, 'ech'))
        self.assertEqual(len(cands), 7 * 18 + 1)
        ip, dns, kind, cfg = cands[1]
        st = cfg['outbounds'][0]['streamSettings']
        self.assertEqual(ip, CF_IPS[0])
        self.assertEqual(dns, ECH_DNS[0])
        self.assertEqual(cfg['outbounds'][0]['settings']['address'], ip)
        self.assertEqual(st['tlsSettings']['serverName'], QUERY['sni'])
        self.assertEqual(st['wsSettings']['headers']['Host'], QUERY['host'])
        self.assertEqual(st['tlsSettings']['fingerprint'], 'chrome')
        self.assertEqual(st['tlsSettings']['echConfigList'], 'cloudflare-ech.com+udp://1.1.1.1')
        self.assertNotIn('finalmask', st)
        self.assertIn('finalmask', self.config['outbounds'][0]['streamSettings'])

    def test_irancell_has_native_tls_and_zero_free_mask(self):
        cands = list(build_candidates(self.config, 'irancell'))
        self.assertEqual(len(cands), 7 * 2 * 2 + 1)
        ip, mask, cipher, cfg = cands[1]
        st = cfg['outbounds'][0]['streamSettings']
        self.assertEqual(st['tlsSettings']['fingerprint'], 'unsafe')
        self.assertNotIn('echConfigList', st['tlsSettings'])
        self.assertEqual(st['finalmask'], ZERO_FREE_MASK)
        self.assertFalse(any('0' in m['settings'].get('lengths', [])
                             for m in st['finalmask']['tcp']))
        self.assertEqual(st['tlsSettings']['serverName'], QUERY['sni'])

    def test_optional_pattng_exports(self):
        custom = {'tcp':[{'type':'fragment','settings':{'packets':'1-1','lengths':['13'],'delays':['2']}}]}
        cands = list(build_candidates(self.config, 'irancell', custom_mask=custom,
                                       custom_ciphers='TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256'))
        self.assertTrue(any(c[1]=='custom-pattng' and c[2]=='custom-pattng' for c in cands))

    def test_sample_ip_diversity(self):
        candidates = list(build_candidates(self.config, 'ech'))
        sampled = balanced_sample(candidates, 15, 42)
        self.assertEqual(len(sampled), 15)
        self.assertEqual(sampled[0][0], 'original')
        self.assertEqual(set(c[0] for c in sampled[1:]), set(CF_IPS))

    def test_validation(self):
        with self.assertRaises(ValueError):
            vless_to_config('https://example.com')
        with self.assertRaises(ValueError):
            extract_finalmask('true')
        with self.assertRaises(ValueError):
            list(build_candidates(vless_to_config('vless://'+USER+'@foo:443?security=none'), 'ech'))

    def test_cli_dry_run_no_xray_and_safe_outputs(self):
        with tempfile.TemporaryDirectory() as d:
            wd = Path(d)
            link = wd / 'secret.txt'
            link.write_text(URL)
            out = wd / 'result'
            proc = subprocess.run([sys.executable, str(ROOT/'lib/network_scan.py'),
                '--method', 'ech', '--link-file', str(link), '--dry-run',
                '--limit', '5', '--output', str(out)], capture_output=True, text=True)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertTrue((out/'results.csv').exists())
            self.assertTrue((out/'example-config.json').exists())
            self.assertFalse((out/'best-config.json').exists())
            self.assertEqual((out/'results.csv').read_text().count('DRY_RUN'), 5)
            self.assertNotIn(USER, (out/'results.csv').read_text())
            self.assertNotIn(USER, proc.stdout)
            self.assertEqual(os.stat(out/'example-config.json').st_mode & 0o777, 0o600)

if __name__ == '__main__':
    unittest.main()
