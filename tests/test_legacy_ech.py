"""Offline assurance that the original Bash legacy-fragment path preserves TLS/ECH."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from urllib.parse import urlencode

ROOT = Path(__file__).resolve().parents[1]
USER = '12345678-1234-4234-8234-123456789abc'
PARAMS = {
    'encryption': 'mlkem768x25519plus.native.0rtt.longpayload',
    'security': 'tls', 'type': 'ws', 'host': 'example.com',
    'sni': 'example.com', 'path': '/abc?ed=2566', 'fp': 'firefox', 'alpn': 'h2',
    'ech': 'cloudflarestaging.com+udp://1.1.1.1',
    'cs': 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
    'pcs': 'example-base64-certificate-pin',
    'vcn': 'example.com',
    'fm': '"finalmask":{"tcp":[{"type":"fragment","settings":{"packets":"tlshello","lengths":["0","104","1"],"delays":["0"],"maxSplit":"0"}}]}',
}
URL = 'vless://' + USER + '@example.net:2053?' + urlencode(PARAMS) + '#node'


class LegacyECHTests(unittest.TestCase):
    def test_legacy_freedom_fragment_keeps_tls_ech_and_existing_finalmask(self):
        for mode in ('legacy', 'finalmask_fragment'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temp:
                outfile = Path(temp) / 'private-config.json'
                script = f'''source "{ROOT}/lib/config.sh"
choose_scan_mode() {{ SCAN_MODE="{mode}"; }}
generate_config_from_vless_link
'''
                env = dict(os.environ, CONFIG_PATH=str(outfile))
                result = subprocess.run(['bash', '-c', script], input=URL + '\n',
                                        capture_output=True, text=True, env=env)
                self.assertEqual(result.returncode, 0, result.stderr)
                config = json.loads(outfile.read_text())
                out = next(o for o in config['outbounds'] if o['tag'] == 'proxy')
                stream = out['streamSettings']
                tls = stream['tlsSettings']
                self.assertEqual(tls['echConfigList'], PARAMS['ech'])
                self.assertEqual(tls['fingerprint'], PARAMS['fp'])
                self.assertEqual(tls['cipherSuites'], PARAMS['cs'])
                self.assertEqual(tls['pinnedPeerCertSha256'], PARAMS['pcs'])
                self.assertEqual(tls['verifyPeerCertByName'], PARAMS['vcn'])
                self.assertEqual(stream['wsSettings']['path'], PARAMS['path'])
                self.assertEqual(out['settings']['encryption'], PARAMS['encryption'])
                if mode == 'legacy':
                    self.assertEqual(stream['finalmask']['tcp'][0]['settings']['lengths'], ['0','104','1'])
                if mode == 'legacy':
                    self.assertEqual(stream['sockopt']['dialerProxy'], 'fragment')
                    self.assertTrue(any(o['tag']=='fragment' for o in config['outbounds']))
                else:
                    self.assertNotIn('dialerProxy', stream['sockopt'])
                    self.assertEqual(len(stream['finalmask']['tcp']), 1)

    def test_ech_percent_sequences_decode_only_once(self):
        # Keep a literal percent-encoded sequence in the ECH value after one URI decode.
        p = dict(PARAMS, ech='cloudflare-ech.com+https://dns.example/dns-query@address=%41')
        with tempfile.TemporaryDirectory() as temp:
            outfile = Path(temp) / 'config.json'
            script = f'''source "{ROOT}/lib/config.sh"; choose_scan_mode() {{ SCAN_MODE="legacy"; }}; generate_config_from_vless_link'''
            result = subprocess.run(['bash', '-c', script],
                                    input='vless://'+USER+'@example.net:2053?'+urlencode(p)+'\n',
                                    capture_output=True, text=True,
                                    env=dict(os.environ, CONFIG_PATH=str(outfile)))
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(outfile.read_text())['outbounds'][0]['streamSettings']['tlsSettings']['echConfigList'],
                             p['ech'])


if __name__ == '__main__':
    unittest.main()
