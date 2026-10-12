import csv
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
from network_scan import export_candidate_link, build_candidates, vless_to_config
from share_codec import link_to_config

UUID = '12345678-1234-4234-8234-123456789abc'
QUERY = {'security':'tls', 'encryption':'mlkem768x25519plus.native.0rtt.payload',
         'type':'ws', 'host':'ws.example.com', 'path':'/ws?ed=2566',
         'sni':'ws.example.com', 'fp':'firefox', 'alpn':'h2',
         'ech':'cloudflarestaging.com+udp://1.1.1.1'}
URL = f'vless://{UUID}@example.net:2053?' + urlencode(QUERY) + '#config'

class LiveExportTests(unittest.TestCase):
    def test_default_irancell_export_roundtrip(self):
        source = vless_to_config(URL)
        for i, (_, _, _, x) in enumerate(build_candidates(source, 'irancell', ips=['188.114.97.2'])):
            link = export_candidate_link(URL, x, 'NET-'+str(i), baseline=(i==0))
            self.assertEqual(link_to_config(link)['outbounds'][0]['streamSettings'],
                             x['outbounds'][0]['streamSettings'])
            self.assertEqual(x['outbounds'][0]['streamSettings']['tlsSettings']['fingerprint'], 'firefox')
            self.assertEqual(x['outbounds'][0]['streamSettings']['tlsSettings']['echConfigList'], QUERY['ech'])

    def test_opt_in_unsafe_and_custom_ciphers_serialized_not_dropped(self):
        source = vless_to_config(URL)
        for i, (_, _, _, x) in enumerate(build_candidates(source, 'irancell',
                                    ips=['188.114.97.2'], tls_profile='pattng-unsafe')):
            link = export_candidate_link(URL, x, 'NET-'+str(i), baseline=(i==0))
            got = link_to_config(link)['outbounds'][0]
            self.assertEqual(got['streamSettings'], x['outbounds'][0]['streamSettings'])
            self.assertEqual(got['settings'], x['outbounds'][0]['settings'])

    def test_ech_changed_export_has_only_selected_variant(self):
        source = vless_to_config(URL)
        x = list(build_candidates(source, 'ech', ips=['188.114.97.2'],
                     ech_values=['cloudflare-ech.com+udp://9.9.9.9'], ech_chrome=True))[1][-1]
        link = export_candidate_link(URL, x, 'NET-ECH')
        got = link_to_config(link)['outbounds'][0]['streamSettings']
        self.assertEqual(got, x['outbounds'][0]['streamSettings'])
        self.assertEqual(got['tlsSettings']['echConfigList'], 'cloudflare-ech.com+udp://9.9.9.9')

    def test_private_dry_run_results_and_share_links(self):
        for extra in ([], ['--tls-profile', 'pattng-unsafe']):
            with self.subTest(extra=extra), tempfile.TemporaryDirectory() as td:
                folder=Path(td)
                link_file=folder/'input.txt'; link_file.write_text(URL)
                output=folder/'out'
                p=subprocess.run([sys.executable,str(ROOT/'lib/network_scan.py'),
                      '--method','irancell','--link-file',str(link_file),'--ip','188.114.97.2',
                      '--limit','6','--requests','3','--dry-run','--no-prompt',
                      '--output',str(output),*extra],capture_output=True,text=True)
                self.assertEqual(p.returncode,0,p.stderr)
                with (output/'results.csv').open() as f:
                    rows=list(csv.DictReader(f))
                with (output/'links.csv').open() as f:
                    links=list(csv.DictReader(f))
                manifest=[json.loads(row) for row in (output/'manifest.jsonl').read_text().splitlines()]
                self.assertEqual(len(rows),len(links))
                self.assertEqual(len(rows),len(manifest))
                self.assertEqual([r['id'] for r in rows],[r['id'] for r in links])
                self.assertTrue(all(r['status']=='DRY_RUN' for r in rows))
                self.assertFalse((output/'best-link.txt').exists())
                self.assertEqual(os.stat(output/'links.csv').st_mode & 0o777,0o600)
                self.assertNotIn(UUID,(output/'results.csv').read_text())
                for result, item in zip(rows,links):
                    cfg=link_to_config(item['link'])
                    st=cfg['outbounds'][0]['streamSettings']
                    self.assertEqual(st['tlsSettings']['echConfigList'], QUERY['ech'])
                    self.assertEqual(json.loads(result['finalmask_json']) if result['finalmask_json'] else None,
                                     st.get('finalmask'))
                    self.assertEqual(result['fragment_layers'],json.dumps([layer['settings'] for layer in st.get('finalmask',{}).get('tcp',[]) if layer.get('type')=='fragment'],separators=(',',':')))

if __name__=='__main__':
    unittest.main()
