import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from urllib.parse import urlencode

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'lib'))
from network_scan import (
    CF_IPS, ECH_DNS, PATTNG_TLSHELLO_ZERO, PATTNG_TLSHELLO,
    PATTNG_REAL_FIREFOX_CIPHERS, ZERO_FREE_MASK, build_candidates,
    vless_to_config, balanced_sample, extract_finalmask, make_ech_values,
    expand_addresses, parse_args, resolve_candidate_inputs, split_ech,
)

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

    def test_ech_derived_from_link_and_original_baseline(self):
        cands = list(build_candidates(self.config, 'ech'))
        self.assertEqual(len(cands), 1 + len(CF_IPS))
        ip, expr, _, cfg = cands[1]
        st = cfg['outbounds'][0]['streamSettings']
        self.assertEqual(ip, CF_IPS[0])
        self.assertEqual(expr, QUERY['ech'])
        self.assertEqual(cfg['outbounds'][0]['settings']['address'], ip)
        self.assertEqual(st['tlsSettings']['serverName'], QUERY['sni'])
        self.assertEqual(st['wsSettings']['headers']['Host'], QUERY['host'])
        self.assertEqual(st['tlsSettings']['fingerprint'], 'firefox')
        self.assertEqual(st['tlsSettings']['echConfigList'], QUERY['ech'])
        self.assertEqual(st['finalmask'], self.config['outbounds'][0]['streamSettings']['finalmask'])
        self.assertIn('finalmask', cands[0][-1]['outbounds'][0]['streamSettings'])

    def test_explicit_ech_values_can_use_different_domains_and_protocols(self):
        values = make_ech_values(QUERY['ech'], supplied=[
            'another.example+https://1.1.1.1/dns-query',
            'udp://9.9.9.9'])
        self.assertEqual(len(values), 3)
        cands = list(build_candidates(self.config, 'ech', ips=['192.0.2.4', '2001:db8::1'],
                                      ech_values=values))
        self.assertEqual(len(cands), 7)
        self.assertEqual(cands[-1][-1]['outbounds'][0]['settings']['address'], '2001:db8::1')
        self.assertEqual(cands[-1][-1]['outbounds'][0]['streamSettings']['tlsSettings']['echConfigList'],
                         'udp://9.9.9.9')

    def test_user_custom_domain_and_resolver_cross_product(self):
        values = make_ech_values(QUERY['ech'], domains=['cloudflare-ech.com', 'api.example.org'],
                                  resolvers=['udp://8.8.8.8', 'https://1.1.1.1/dns-query'])
        self.assertEqual(len(values), 5)
        self.assertIn('api.example.org+https://1.1.1.1/dns-query', values)
        self.assertEqual(split_ech('cloudflarestaging.com+udp://1.1.1.1'),
                         ('cloudflarestaging.com', 'udp://1.1.1.1'))
        self.assertEqual(split_ech('udp://1.1.1.1'), ('', 'udp://1.1.1.1'))
        self.assertEqual(split_ech('BASE64+ECHCONFIG'), (None, None))

    def test_examples_are_opt_in_and_follow_link_domain(self):
        values = make_ech_values(QUERY['ech'], include_examples=True)
        self.assertEqual(len(values), len(ECH_DNS))
        self.assertIn('cloudflarestaging.com+udp://9.9.9.9', values)
        self.assertNotIn('cloudflare-ech.com+udp://9.9.9.9', values)
        self.assertEqual(len(list(build_candidates(self.config, 'ech', ech_values=values))),
                         1 + len(CF_IPS) * len(ECH_DNS))

    def test_cli_default_uses_source_hostname_not_historical_samples(self):
        for method in ('ech', 'irancell'):
            args = parse_args(['--method', method, '--no-prompt'])
            ips, _ = resolve_candidate_inputs(args, self.config)
            self.assertEqual(ips, ['original.example'])
            args.example_ips = True
            ips, _ = resolve_candidate_inputs(args, self.config)
            self.assertEqual(ips, CF_IPS)

    def test_custom_ip_cidr_file_and_security_validation(self):
        self.assertEqual(expand_addresses(['192.0.2.0/30', 'example.net,2001:db8::1']),
                         ['192.0.2.1', '192.0.2.2', 'example.net', '2001:db8::1'])
        for item in ('0.0.0.0/0', 'not a hostname', '192.0.2.999/24'):
            with self.assertRaises(ValueError):
                expand_addresses([item])
        with tempfile.TemporaryDirectory() as d:
            ips = Path(d) / 'ips.txt'
            ech = Path(d) / 'ech.txt'
            ips.write_text('# comment\n192.0.2.3\n192.0.2.4\n')
            ech.write_text('# ECH alternatives\nexample.org+udp://1.0.0.1\n')
            args = parse_args(['--method', 'ech', '--ip-file', str(ips),
                               '--ech-file', str(ech), '--ech-resolver', '8.8.8.8',
                               '--no-prompt'])
            addresses, values = resolve_candidate_inputs(args, self.config)
            self.assertEqual(addresses, ['192.0.2.3', '192.0.2.4'])
            self.assertIn('example.org+udp://1.0.0.1', values)
            self.assertIn('cloudflarestaging.com+udp://8.8.8.8', values)

    def test_pattng_exact_finalmask_and_ciphers(self):
        self.assertEqual(PATTNG_TLSHELLO_ZERO['tcp'][0]['settings']['lengths'], ['0', '104', '1'])
        self.assertEqual(PATTNG_TLSHELLO_ZERO['tcp'][0]['settings']['delays'], ['0'])
        self.assertEqual(PATTNG_TLSHELLO_ZERO['tcp'][1]['settings']['lengths'], ['114', '1'])
        self.assertEqual(PATTNG_TLSHELLO['tcp'][0]['settings']['lengths'], ['6', '98', '1'])
        self.assertEqual(PATTNG_TLSHELLO_ZERO,
                         json.loads((ROOT/'profiles/pattng-tlshello-0-len.json').read_text()))
        self.assertEqual(PATTNG_TLSHELLO,
                         json.loads((ROOT/'profiles/pattng-tlshello.json').read_text()))
        self.assertEqual(PATTNG_REAL_FIREFOX_CIPHERS,
                         (ROOT/'profiles/pattng-real-firefox-cipherSuites.txt').read_text().strip())
        self.assertEqual(len(PATTNG_REAL_FIREFOX_CIPHERS.split(':')), 12)

    def test_irancell_default_preserves_original_tls_and_ech(self):
        cands = list(build_candidates(self.config, 'irancell'))
        self.assertEqual(len(cands), len(CF_IPS) * 4 + 1)
        original_st = self.config['outbounds'][0]['streamSettings']
        ip, mask, cipher, cfg = cands[1]
        st = cfg['outbounds'][0]['streamSettings']
        self.assertEqual(st['tlsSettings'], original_st['tlsSettings'])
        self.assertEqual(st['wsSettings'], original_st['wsSettings'])
        self.assertEqual(st['security'], original_st['security'])
        self.assertEqual(st['finalmask'], PATTNG_TLSHELLO_ZERO)
        self.assertEqual(mask, 'pattng-tlshello-0-len')
        self.assertEqual(cipher, 'original-TLS')
        self.assertTrue(all(c[-1]['outbounds'][0]['streamSettings']['tlsSettings'] == original_st['tlsSettings'] for c in cands))

    def test_irancell_opt_in_unsafe_keeps_ech(self):
        cands = list(build_candidates(self.config, 'irancell', tls_profile='pattng-unsafe'))
        self.assertEqual(len(cands), len(CF_IPS) * 4 * 2 + 1)
        st = cands[1][-1]['outbounds'][0]['streamSettings']
        self.assertEqual(st['tlsSettings']['fingerprint'], 'unsafe')
        self.assertEqual(st['tlsSettings']['echConfigList'], QUERY['ech'])
        self.assertEqual(st['tlsSettings']['serverName'], QUERY['sni'])
        self.assertTrue(any(c[2]=='pattng-real-firefox' and
                            c[-1]['outbounds'][0]['streamSettings']['tlsSettings']['cipherSuites'] == PATTNG_REAL_FIREFOX_CIPHERS
                            for c in cands))

    def test_irancell_preserves_non_fragment_finalmask_layers(self):
        import copy
        cfg = copy.deepcopy(self.config)
        mask = cfg['outbounds'][0]['streamSettings']['finalmask']
        mask['tcp'].insert(0, {'type': 'sudoku', 'settings': {'password': 'not-a-secret'}})
        mask['udp'] = [{'type': 'noise', 'settings': {'reset': '28'}}]
        mask['quicParams'] = {'congestion': 'bbr'}
        cands = list(build_candidates(cfg, 'irancell', ips=['192.0.2.4']))
        for _, profile, _, candidate in cands[1:]:
            modified = candidate['outbounds'][0]['streamSettings']['finalmask']
            self.assertEqual(modified['udp'], mask['udp'])
            self.assertEqual(modified['quicParams'], mask['quicParams'])
            self.assertEqual(modified['tcp'][0], mask['tcp'][0])
            if profile == 'none':
                self.assertEqual(len(modified['tcp']), 1)
        self.assertEqual(mask['tcp'][1]['settings']['length'], '1-3')

    def test_optional_custom_mask_and_cipher(self):
        custom = {'tcp':[{'type':'fragment','settings':{'packets':'1-1','lengths':['13'],'delays':['2']}}]}
        with self.assertRaises(ValueError):
            list(build_candidates(self.config, 'irancell', custom_ciphers='TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256'))
        cands = list(build_candidates(self.config, 'irancell', custom_mask=custom,
                                       custom_ciphers='TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
                                       tls_profile='pattng-unsafe'))
        self.assertTrue(any(c[1]=='custom' and c[2]=='custom' for c in cands))

    def test_ech_chrome_is_explicit(self):
        c = next(x for x in build_candidates(self.config, 'ech', ech_chrome=True) if x[0] != 'original')
        st = c[-1]['outbounds'][0]['streamSettings']
        self.assertEqual(st['tlsSettings']['fingerprint'], 'chrome')
        self.assertIn('finalmask', st)

    def test_sample_diversity(self):
        values = make_ech_values(QUERY['ech'], include_examples=True)
        candidates = list(build_candidates(self.config, 'ech', ech_values=values))
        sampled = balanced_sample(candidates, 15, 42)
        self.assertEqual(len(sampled), 15)
        self.assertEqual(sampled[0][0], 'original')
        self.assertEqual(set(c[0] for c in sampled[1:]), set(CF_IPS))

    def test_invalid_configuration_inputs(self):
        with self.assertRaises(ValueError):
            vless_to_config('https://example.com')
        with self.assertRaises(ValueError):
            extract_finalmask('true')
        with self.assertRaises(ValueError):
            list(build_candidates(vless_to_config('vless://'+USER+'@foo:443?security=none'), 'ech'))

    def test_cli_dry_run_credentials_private_and_custom_matrix(self):
        with tempfile.TemporaryDirectory() as d:
            wd = Path(d)
            link = wd / 'secret.txt'
            link.write_text(URL)
            out = wd / 'result'
            proc = subprocess.run([sys.executable, str(ROOT/'lib/network_scan.py'),
                '--method', 'ech', '--link-file', str(link), '--ip', '192.0.2.4',
                '--ech', 'example.com+https://1.1.1.1/dns-query', '--dry-run',
                '--all', '--no-prompt', '--output', str(out)], capture_output=True, text=True)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertTrue((out/'results.csv').exists())
            self.assertTrue((out/'example-config.json').exists())
            self.assertFalse((out/'best-config.json').exists())
            self.assertEqual((out/'results.csv').read_text().count('DRY_RUN'), 3)
            self.assertNotIn(USER, (out/'results.csv').read_text())
            self.assertNotIn(USER, proc.stdout)
            self.assertEqual(os.stat(out/'example-config.json').st_mode & 0o777, 0o600)


if __name__ == '__main__':
    unittest.main()
