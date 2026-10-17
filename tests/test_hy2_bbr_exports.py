"""Canonical new exports and exact historical defaults; no source rewrites."""
from pathlib import Path
import tempfile
import unittest
from test_quality_failover import MERGE, export
class BbrExports(unittest.TestCase):
    def parse(self,path):return MERGE.parse_export(path,lambda:ValueError('canonical'))
    def test_new_and_legacy_inputs_only_change_hy2_default_bandwidth_in_output(self):
        for hopping in (False,True):
            with self.subTest(hopping=hopping),tempfile.TemporaryDirectory() as directory:
                p=Path(directory)/'event-mihomo.yaml';export(p,hopping=hopping);new=p.read_bytes()
                self.assertEqual(MERGE.build_output(self.parse(p),None),new)
                export(p,hopping=hopping,legacy_bandwidth=True);legacy=p.read_bytes()
                self.assertEqual(MERGE.build_output(self.parse(p),None),new)
                self.assertEqual(p.read_bytes(),legacy)
    def test_mixed_new_and_legacy_dual_sources_keep_credentials_without_bandwidth(self):
        with tempfile.TemporaryDirectory() as directory:
            p=Path(directory)/'primary.yaml';b=Path(directory)/'backup.yaml'
            export(p,legacy_bandwidth=True);export(b,backup=True,hopping=True)
            a,z=p.read_bytes(),b.read_bytes();primary,backup=self.parse(p),self.parse(b)
            out=MERGE.build_output(primary,backup)
            self.assertNotIn(b'    up:',out);self.assertNotIn(b'    down:',out)
            self.assertIn(primary.reality['uuid'].encode(),out);self.assertIn(backup.hysteria['password'].encode(),out)
            self.assertIn(b'    ports: 40000-40100',out)
            self.assertEqual((p.read_bytes(),b.read_bytes()),(a,z))
    def test_partial_custom_or_duplicate_bandwidth_declarations_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            p=Path(directory)/'event.yaml';export(p,legacy_bandwidth=True);raw=p.read_bytes()
            for value in (raw.replace(b'    down: "300 Mbps"\n',b''),raw.replace(b'    up: "300 Mbps"\n',b''),raw.replace(b'300 Mbps',b'301 Mbps'),raw.replace(b'    up: "300 Mbps"\n',b'    up: "300 Mbps"\n    up: "300 Mbps"\n')):
                with self.subTest(value=value):
                    p.write_bytes(value)
                    with self.assertRaises(ValueError):self.parse(p)
if __name__=='__main__':unittest.main()
