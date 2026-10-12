import csv
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
import unittest
from urllib.parse import urlencode

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))
from network_scan import run_candidate, vless_to_config
from xray_errors import classify, write_first_error

UUID = "12345678-1234-4234-8234-123456789abc"
URL = "vless://" + UUID + "@example.com:2053?" + urlencode({
    "encryption": "none", "security": "tls", "sni": "ws.example.com",
    "ech": "cloudflarestaging.com+udp://1.1.1.1", "type": "ws", "host": "ws.example.com", "path": "/ws"
})
MASK = '{"tcp":[{"type":"fragment","settings":{"packets":"tlshello","lengths":["6","98","1"],"delays":["0"],"maxSplit":"0"}}]}'
MASK_URL = URL + "&fm=" + __import__('urllib.parse', fromlist=['quote']).quote('"finalmask":' + MASK, safe='')


def xray_stub(path):
    path.write_text(textwrap.dedent('''\
        #!/usr/bin/env python3
        import json,sys
        if len(sys.argv)>1 and sys.argv[1]=='version':
            print('Xray 25.1.0 test-build')
            sys.exit(0)
        config=json.load(open(sys.argv[-1]))
        if 'finalmask' in config['outbounds'][0]['streamSettings']:
            print('unknown field finalmask; secret-credentials-would-go-here',file=sys.stderr)
            sys.exit(3)
        sys.exit(0)
    '''), encoding="utf-8")
    path.chmod(0o700)


class DiagnoseTests(unittest.TestCase):
    def test_classifications_do_not_echo_raw_data(self):
        self.assertEqual(classify("UNKNOWN FIELD finalmask, UUID 123"),
                         "finalmask-unsupported-or-outdated-core")
        self.assertEqual(classify("finalmask settings reject value"),"finalmask-config-rejected")
        self.assertEqual(classify("unknown field whatever"),"unknown-json-field")

    def test_first_error_file_is_private_and_not_overwritten(self):
        with tempfile.TemporaryDirectory() as d:
            p=write_first_error(Path(d),"original diagnostic")
            write_first_error(Path(d),"different diagnostic")
            self.assertEqual(p.read_text(),"original diagnostic")
            self.assertEqual(p.stat().st_mode & 0o777,0o600)

    def test_diagnose_existing_results_without_url_print(self):
        with tempfile.TemporaryDirectory() as tmp:
            td=Path(tmp)
            fake=td/'xray'
            xray_stub(fake)
            result=td/'results'; result.mkdir()
            with (result/'links.csv').open('w',newline='') as fh:
                w=csv.DictWriter(fh,fieldnames=['id','link'])
                w.writeheader()
                w.writerows([{'id':'OPT-0001','link':URL},{'id':'OPT-0002','link':MASK_URL}])
            p=subprocess.run(['bash',str(ROOT/'bin/xray-finalmask-scanner'),
                              '--diagnose',str(result),'--xray',str(fake)],
                             capture_output=True,text=True)
            self.assertEqual(p.returncode,0,p.stderr)
            self.assertIn('OPT-0001: VALID',p.stdout)
            self.assertIn('OPT-0002: INVALID / finalmask-unsupported-or-outdated-core',p.stdout)
            self.assertNotIn(UUID,p.stdout+p.stderr)
            self.assertNotIn('secret-credentials-would-go-here',p.stdout+p.stderr)
            report=result/'xray-diagnose.log'
            self.assertEqual(report.stat().st_mode & 0o777,0o600)
            self.assertIn('unknown field finalmask',report.read_text())

    def test_real_scan_reports_reason_and_private_error(self):
        with tempfile.TemporaryDirectory() as d:
            td=Path(d)
            fake=td/'xray'; xray_stub(fake)
            cfg=vless_to_config(MASK_URL)
            config=td/'candidate.json'
            config.write_text(__import__('json').dumps(cfg))
            status,count,avg,reason=run_candidate(str(fake),cfg,config,'https://example.com',1,2)
            self.assertEqual(status,'INVALID_CONFIG')
            self.assertEqual(reason,'finalmask-unsupported-or-outdated-core')
            report=td/'xray-validation-error.log'
            self.assertIn('unknown field finalmask',report.read_text())
            self.assertEqual(report.stat().st_mode & 0o777,0o600)


if __name__=='__main__':
    unittest.main()
