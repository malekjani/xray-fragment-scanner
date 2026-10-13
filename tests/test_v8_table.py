"""FinalMask screenshot-inspired table spec, including multi-layer and privacy."""
import csv
import io
import sys
from pathlib import Path
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'lib'))
from v8_table import project,best_three,text_report,csv_text
from v8_engine import run
from test_v8_draft import LINK,F,SPEC


def row(cid,avg,status='VERIFIED',success=10,requests=10,mask=None):
    import json
    return {'id':cid, 'avg_ms':avg,'status':status,'successes':success,
            'requests':requests,'profile':'test',
            'finalmask_json':json.dumps(mask or {'tcp':[F]})}

class FinalMaskResultsTests(unittest.TestCase):
    def test_columns_and_sorted_top_three_match_legacy_table(self):
        data=[row('V8-0001',360.84),row('V8-0002',736.46),row('V8-0003',303.34),
              row('V8-0004',299.15),row('V8-0005',867.86),row('V8-0006',689.83),
              row('V8-0007',726.62),row('V8-0008',476.34),row('V8-0009',827.56),
              row('V8-0010',511.02),row('V8-0011',3065.52),row('V8-0012',390.41),
              row('V8-0013',203.06),row('V8-0014',623.92),row('V8-0015',739.11)]
        top=best_three(data)
        self.assertEqual([r['id'] for r in top],['V8-0013','V8-0004','V8-0003'])
        p=project(top[0]);self.assertEqual(p['packets'],'tlshello')
        self.assertEqual(p['length'],'6,98,1')
        self.assertEqual(p['average_response_ms'],'203.06')
        t=text_report(data)
        self.assertIn('Average Response (ms)',t)
        self.assertIn('NOT ICMP ping',t)
        self.assertIn('V8-0013',t)
        self.assertEqual(len(list(csv.DictReader(io.StringIO(csv_text(data))))),15)

    def test_multi_layer_order_is_preserved_in_table(self):
        from copy import deepcopy
        f2=deepcopy(F);f2['settings']['lengths']=['114','1']
        r=row('V8-0002',120.4,mask={'tcp':[F,f2]})
        p=project(r)
        self.assertEqual(p['length'],'6,98,1 / 114,1')
        self.assertEqual(p['packets'],'tlshello / tlshello')
        self.assertEqual(p['success'],'10/10')

    def test_no_ping_or_winner_when_unmeasured(self):
        rows=[row('V8-0001',None,status='UNTESTED',success=0,requests=0)]
        self.assertEqual(best_three(rows),[])
        self.assertIn('No successful HTTPS measurements',text_report(rows))

    def test_offline_generates_privately_protected_matching_tables(self):
        with tempfile.TemporaryDirectory() as d:
            out=Path(d)/'v8'
            result=run(LINK,SPEC,out,dry_run=True)
            self.assertEqual(result['top_three_lowest_average'],[])
            for name in ('finalmask-instances.csv','top-three-lowest-average.csv','finalmask-table.txt'):
                self.assertTrue((out/name).is_file())
                self.assertEqual((out/name).stat().st_mode & 0o777,0o600)
            with (out/'results.csv').open() as f: base=list(csv.DictReader(f))
            with (out/'finalmask-instances.csv').open() as f: table=list(csv.DictReader(f))
            self.assertEqual([x['id'] for x in base],[x['instance'] for x in table])
            self.assertTrue(all(x['average_response_ms']=='—' for x in table))

if __name__=='__main__':unittest.main()
