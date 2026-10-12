import os
import json
import sys
import subprocess
import tempfile
import unittest
from pathlib import Path
from urllib.parse import urlencode

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'lib'))
from network_scan import (CF_IPS, ECH_DNS, vless_to_config, build_candidates,
    make_ech_values, expand_addresses, parse_args, resolve_candidate_inputs,
    PATTNG_TLSHELLO_ZERO, PATTNG_TLSHELLO, PATTNG_REAL_FIREFOX_CIPHERS,
    balanced_sample)

UUID="12345678-1234-4234-8234-123456789abc"
Q={"security":"tls","type":"ws","sni":"example.org","host":"example.org",
   "path":"/test?ed=1000","alpn":"h2","fp":"firefox",
   "encryption":"mlkem768x25519plus.native.0rtt.test",
   "ech":"cloudflarestaging.com+udp://1.1.1.1"}
URL=f"vless://{UUID}@origin.example:2053?"+urlencode(Q)
class ScannerTests(unittest.TestCase):
    def setUp(self):
        self.cfg=vless_to_config(URL)
    def test_preserves_link(self):
        out=self.cfg['outbounds'][0]
        self.assertEqual(out['settings']['encryption'],Q['encryption'])
        self.assertEqual(out['streamSettings']['tlsSettings']['echConfigList'],Q['ech'])
        self.assertEqual(out['streamSettings']['wsSettings']['path'],Q['path'])
    def test_ech_defaults_to_link(self):
        rows=list(build_candidates(self.cfg,'ech'))
        self.assertEqual(len(rows),1+len(CF_IPS))
        self.assertEqual(rows[1][1],Q['ech'])
        self.assertEqual(rows[1][3]['outbounds'][0]['streamSettings']['tlsSettings']['serverName'],Q['sni'])
    def test_sample_ech_is_optional(self):
        values=make_ech_values(Q['ech'],include_examples=True)
        self.assertEqual(len(values),len(ECH_DNS))
        self.assertIn('cloudflarestaging.com+udp://9.9.9.9',values)
        rows=list(build_candidates(self.cfg,'ech',ech_values=values))
        self.assertEqual(len(rows),1+len(CF_IPS)*len(ECH_DNS))
    def test_custom_ech_and_domains(self):
        values=make_ech_values(Q['ech'],domains=['crypto.cloudflare.com'],
            resolvers=['https://1.1.1.1/dns-query','udp://8.8.8.8'],
            supplied=['udp://1.0.0.1'])
        self.assertIn('crypto.cloudflare.com+https://1.1.1.1/dns-query',values)
        self.assertIn('udp://1.0.0.1',values)
    def test_ip_and_cidr_input(self):
        self.assertEqual(expand_addresses(['192.0.2.0/30','2001:db8::1,example.org']),
             ['192.0.2.1','192.0.2.2','2001:db8::1','example.org'])
        with self.assertRaises(ValueError):
            expand_addresses(['0.0.0.0/0'])
    def test_exact_pattng_fixtures(self):
        self.assertEqual(PATTNG_TLSHELLO_ZERO,json.loads((ROOT/'profiles/pattng-tlshello-0-len.json').read_text()))
        self.assertEqual(PATTNG_TLSHELLO,json.loads((ROOT/'profiles/pattng-tlshello.json').read_text()))
        self.assertEqual(PATTNG_REAL_FIREFOX_CIPHERS,(ROOT/'profiles/pattng-real-firefox-cipherSuites.txt').read_text().strip())
        self.assertEqual(len(PATTNG_REAL_FIREFOX_CIPHERS.split(':')),12)
    def test_irancell_presets(self):
        rows=list(build_candidates(self.cfg,'irancell',ips=['192.0.2.4']))
        self.assertEqual(len(rows),9)
        self.assertEqual(rows[1][1],'pattng-tlshello-0-len')
        self.assertEqual(rows[1][3]['outbounds'][0]['streamSettings']['tlsSettings']['fingerprint'],'unsafe')
        self.assertNotIn('echConfigList',rows[1][3]['outbounds'][0]['streamSettings']['tlsSettings'])
    def test_cli_file_inputs_and_private_dry_run(self):
        with tempfile.TemporaryDirectory() as d:
            base=Path(d); url=base/'private.txt'; url.write_text(URL)
            out=base/'out'; ipfile=base/'ip.txt'; ipfile.write_text('192.0.2.4\n')
            echfile=base/'ech.txt'; echfile.write_text('api.example.org+udp://1.0.0.1\n')
            args=parse_args(['--method','ech','--ip-file',str(ipfile),
                             '--ech-file',str(echfile),'--no-prompt'])
            ips,values=resolve_candidate_inputs(args,self.cfg)
            self.assertEqual(ips,['192.0.2.4'])
            self.assertIn('api.example.org+udp://1.0.0.1',values)
            process=subprocess.run([sys.executable,str(ROOT/'lib/network_scan.py'),
                     '--method','ech','--link-file',str(url),'--ip','192.0.2.4',
                     '--dry-run','--all','--no-prompt','--output',str(out)],
                     capture_output=True,text=True)
            self.assertEqual(process.returncode,0,process.stderr)
            self.assertNotIn(UUID,process.stdout)
            self.assertNotIn(UUID,(out/'results.csv').read_text())
            self.assertFalse((out/'best-config.json').exists())
            self.assertEqual(os.stat(out/'example-config.json').st_mode & 0o777,0o600)
    def test_balanced_sample(self):
        values=make_ech_values(Q['ech'],include_examples=True)
        rows=balanced_sample(list(build_candidates(self.cfg,'ech',ech_values=values)),15,42)
        self.assertEqual(len(rows),15)
        self.assertEqual(set(row[0] for row in rows[1:]),set(CF_IPS))

if __name__=='__main__':
    unittest.main()
