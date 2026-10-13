import base64
import csv
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import urlencode, urlsplit, parse_qs

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'lib'))
from share_codec import legacy_to_aead, link_to_config, normalize_link, scheme_and_encoding
from optimize import make_candidates, share_link
from network_scan import proxy

UUID = '12345678-1234-4234-8234-123456789abc'
SHARED = {'type':'ws','security':'tls','sni':'ssl.example.net','fp':'firefox',
          'ech':'cloudflare-ech.com+udp://1.1.1.1','host':'ssl.example.net',
          'path':'/ws?ed=2566','alpn':'h2'}
VLESS = f'vless://{UUID}@origin.example.net:2053?' + urlencode({**SHARED,'encryption':'none','flow':'xtls-rprx-vision'}) + '#node'
VMESS = f'vmess://{UUID}@origin.example.net:2053?' + urlencode({**SHARED,'encryption':'auto'}) + '#node'
TROJAN = 'trojan://p%40ss%3Aword@origin.example.net:2053?' + urlencode(SHARED) + '#node'
LEGACY = {'v':'2','ps':'legacy QR', 'add':'origin.example.net','port':'2053','id':UUID,
          'aid':'0','scy':'auto','net':'ws','type':'none','host':'ssl.example.net',
          'path':'/ws?ed=2566','tls':'tls','sni':'ssl.example.net','alpn':'h2',
          'fp':'firefox','ech':'cloudflare-ech.com+udp://1.1.1.1'}
QR = 'vmess://' + base64.urlsafe_b64encode(json.dumps(LEGACY).encode()).decode().rstrip('=')

class ShareAndWizardTests(unittest.TestCase):
    def test_codec_all_formats(self):
        for link, expected in ((VLESS,'vless'),(VMESS,'vmess'),(TROJAN,'trojan'),(QR,'vmess')):
            with self.subTest(protocol=expected, legacy=link==QR):
                cfg=link_to_config(link)
                self.assertEqual(proxy(cfg)['protocol'], expected)
                self.assertEqual(proxy(cfg)['streamSettings']['tlsSettings']['echConfigList'], SHARED['ech'])
                self.assertEqual(proxy(cfg)['streamSettings']['wsSettings']['path'],SHARED['path'])
                self.assertEqual(proxy(cfg)['settings']['address'],'origin.example.net')
                self.assertEqual(proxy(cfg)['settings']['port'],2053)
        self.assertEqual(proxy(link_to_config(VLESS))['settings']['flow'],'xtls-rprx-vision')
        self.assertEqual(proxy(link_to_config(VMESS))['settings']['security'],'auto')
        self.assertEqual(proxy(link_to_config(TROJAN))['settings']['password'],'p@ss:word')
        self.assertEqual(scheme_and_encoding(QR),('vmess','legacy-qr'))
        self.assertEqual(parse_qs(urlsplit(legacy_to_aead(QR)).query)['security'], ['tls'])

    def test_fragment_roundtrips_all_formats_preserving_settings(self):
        for link in (VMESS, TROJAN, QR, VLESS):
            with self.subTest(protocol=link[:8]):
                cfg=link_to_config(link)
                cand=next(x for x in make_candidates(cfg,'fragment','188.114.97.2',
                           ['tlshello'],['0,104,1'],['0'],['0']) if x[0]!='baseline')[-1]
                generated=share_link(link,cand,'OPT-0002')
                actual=link_to_config(generated)
                self.assertEqual(proxy(cand)['settings'],proxy(actual)['settings'])
                self.assertEqual(proxy(cand)['streamSettings'],proxy(actual)['streamSettings'])
                self.assertEqual(urlsplit(generated).scheme,proxy(cfg)['protocol'])
                self.assertEqual(urlsplit(generated).hostname,'188.114.97.2')
                self.assertIn('fm',parse_qs(urlsplit(generated).query))
                if link==QR:
                    self.assertIn('@',generated)

    def test_invalid_fields_and_insecure_trojan_fail_closed(self):
        legacy = dict(LEGACY, aid='1')
        bad_qr='vmess://'+base64.b64encode(json.dumps(legacy).encode()).decode()
        for value in (bad_qr, TROJAN.replace('security=tls','security=none'),
                      VLESS.replace('#node','&someNewField=lost#node'),
                      'vmess://junk!!!'):
            with self.subTest(link_type=value[:10]), self.assertRaises(ValueError):
                link_to_config(value)

    def test_export_files_all_types_offline(self):
        for protocol, link in (('vless',VLESS),('vmess',VMESS),('trojan',TROJAN),('vmess',QR)):
            with self.subTest(protocol=protocol, qr=link==QR), tempfile.TemporaryDirectory() as d:
                folder=Path(d)
                (folder/'link.txt').write_text(link)
                output=folder/'out'
                p=subprocess.run([sys.executable,str(ROOT/'lib/optimize.py'),
                    '--link-file',str(folder/'link.txt'), '--scan','fragment',
                    '--packets','tlshello','--lengths','0,104,1','--delays','0',
                    '--max-split','0','--dry-run','--all','--output',str(output)],
                    capture_output=True,text=True)
                self.assertEqual(p.returncode,0,p.stderr)
                with (output/'results.csv').open() as rf, (output/'links.csv').open() as lf:
                    results=list(csv.DictReader(rf))
                    links=list(csv.DictReader(lf))
                self.assertEqual(len(results),2)
                self.assertEqual(len(links),2)
                self.assertTrue(all(x['protocol']==protocol for x in results))
                self.assertEqual((output/'links.txt').read_text().splitlines(),[x['link'] for x in links])
                self.assertEqual(proxy(link_to_config(links[1]['link']))['streamSettings']['finalmask'],
                                 json.loads(results[1]['finalmask_json']))
                self.assertNotIn('p@ss:word',p.stdout)

    def test_wizard_collects_link_and_step_inputs_then_creates_tables(self):
        # no TTY -> accepts one link as first line; defaults at each step
        with tempfile.TemporaryDirectory() as d:
            p=subprocess.run(['bash',str(ROOT/'bin/xray-finalmask-scanner'),'--v7-wizard'],
             input='\n'.join([VMESS,'3','n','1','n','n','3','1','3','y','y'])+'\n',
             capture_output=True,text=True,env={**__import__('os').environ,'HOME':d})
            self.assertEqual(p.returncode,0,p.stderr+'\n'+p.stdout)
            self.assertIn('Detected: VMESS',p.stdout)
            paths=list((Path(d)/'.local/share/xray-finalmask-scanner').glob('optimize-*'))
            self.assertEqual(len(paths),1)
            self.assertTrue((paths[0]/'links.csv').exists())
            self.assertTrue((paths[0]/'manifest.jsonl').exists())
            self.assertNotIn(UUID,p.stdout)

if __name__=='__main__':
    unittest.main()
