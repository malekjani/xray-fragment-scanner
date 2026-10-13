"""Contract tests for version-gated combinations, redacted effective diff and core smoke harness."""
from pathlib import Path
import json
import os
import sys
import tempfile
import unittest
from unittest.mock import patch
from subprocess import CompletedProcess
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'lib'))
from compatibility import core_capabilities, parse_xray_version, effective_preview, safe_summary
from compatibility.smoke import check
from share_codec import link_to_config
from v8_engine import matrix
from network_scan import proxy

URL='vless://12345678-1234-4234-8234-123456789abc@origin.example.net:443?security=tls&type=ws&host=origin.example.net&path=%2Fws&fp=firefox&ech=cloudflare-ech.com%2Budp%3A%2F%2F1.1.1.1&encryption=none#node'
fragment={'type':'fragment','settings':{'packets':'tlshello','lengths':['6','98','1'],'delays':['0'],'maxSplit':'0'}}

class CompatibilityContractTests(unittest.TestCase):
    def test_actual_known_core_versions(self):
        self.assertEqual(parse_xray_version('Xray 26.3.27 (Xray)'),(26,3,27))
        self.assertEqual(core_capabilities('Xray 26.10.10')['fragment_arrays'],'documented-runtime-validation-required')
        self.assertEqual(core_capabilities('Xray 26.3.27')['fragment_arrays'],'unsupported-known-old-core')
        self.assertEqual(core_capabilities('Xray TEST')['fragment_arrays'],'unverified')

    def test_version_gate_protects_fragment_and_other_options_still_preview(self):
        spec={'mode':'expert','mask_profiles':['original',{'name':'f','layers':[fragment]}],
              'max_candidates':10}
        new,_=matrix(URL,spec,core_version='Xray 26.10.10')
        old,excluded=matrix(URL,spec,core_version='Xray 26.3.27')
        self.assertEqual(len(new),2)
        self.assertEqual(len(old),1)
        self.assertTrue(excluded)
        self.assertEqual(old[0]['compatibility']['status'],'DOCUMENTED_UNVERIFIED')
        self.assertIn(new[1]['compatibility']['status'],('DOCUMENTED_UNVERIFIED','EXPERIMENTAL'))

    def test_redacted_diff_and_no_claim_of_observed_effect(self):
        config=link_to_config(URL)
        changed=link_to_config(URL)
        out=proxy(changed)
        out['streamSettings']['tlsSettings']['echConfigList']='SENSITIVE-ECH-CONFIG'
        out['streamSettings']['finalmask']={'tcp':[fragment]}
        diff=effective_preview(config,changed,['ech','finalmask.tcp'])
        body=json.dumps(diff)
        self.assertNotIn('SENSITIVE-ECH-CONFIG',body)
        self.assertNotIn('12345678-',body)
        self.assertEqual(diff['runtime_effect'],'NOT_OBSERVED')
        self.assertIn('ech',['ech','finalmask.tcp'])
        self.assertGreater(diff['generated_count'],0)

    def test_real_core_harness_mock_retains_no_credentials(self):
        with tempfile.TemporaryDirectory() as t:
            binary=Path(t)/'xray';binary.write_bytes(b'test-core')
            def fake(cmd,**kwargs):return CompletedProcess(cmd,0,stdout='Configuration OK.\n',stderr='')
            with patch('compatibility.smoke.core_identity',return_value='Xray 26.10.10'),\
                 patch('compatibility.smoke.subprocess.run',side_effect=fake):
                r=check(URL,str(binary),Path(t)/'results')
            self.assertGreater(len(r['results']),0)
            self.assertTrue(all(x['outcome']=='CORE_VALID' for x in r['results']))
            saved=Path(t)/'results'/'compatibility-matrix.json'
            self.assertEqual(os.stat(saved).st_mode & 0o777,0o600)
            self.assertNotIn('12345678-',saved.read_text())

if __name__=='__main__':unittest.main()
