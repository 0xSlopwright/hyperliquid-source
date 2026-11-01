"""Digest-bound static evidence and negative controls; never execute the target."""
import sys
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import action_delay_fma_rust as a
from elf_index import sections

class ActionDelayFmaRustTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data=a.TARGET.read_bytes()
        cls.sections=sections(cls.data)
    def mutate(self,va):
        sec=next(s for s in self.sections if s['type']!=8 and s['address']<=va<s['address']+s['size'])
        off=sec['offset']+va-sec['address'];d=bytearray(self.data);d[off]^=1
        return bytes(d)
    def test_exact_target_and_retained_results(self):
        evidence,cells,vectors,_=a.generated()
        self.assertEqual(evidence['corpus_cases'],332)
        self.assertEqual(evidence['dispatch_cells'],57)
        self.assertEqual((a.CRATE/'dispatch.tsv').read_text(),cells)
        self.assertEqual((a.CRATE/'target-vectors.tsv').read_text(),vectors)
    def test_bad_identity(self):
        with self.assertRaisesRegex(ValueError,'size/SHA'):a.static_evidence(self.data[:-1])
        with self.assertRaisesRegex(ValueError,'size/SHA'):a.static_evidence(self.mutate(0x392fab3))
    def test_structural_corruption(self):
        # Bypass only the outer identity gate to exercise deeper checks.
        for va in [0x392fab3,0x392facd,0x565fd20,0x20a550,0x20a830]:
            with self.subTest(va=hex(va)),self.assertRaises(ValueError):a.check_structure(self.mutate(va))
    def test_relocation_corruption(self):
        import struct
        sec=next(s for s in self.sections if s['name']=='.rela.dyn')
        for o in range(sec['offset'],sec['offset']+sec['size'],24):
            if struct.unpack_from('<Q',self.data,o)[0]==0x57882e8:
                d=bytearray(self.data);d[o+16]^=1;break
        else:self.fail('missing relocation')
        with self.assertRaisesRegex(ValueError,'relative slot'):a.check_structure(bytes(d))
    def test_fma_rounding_is_observable(self):
        x=0.0004
        self.assertNotEqual(a.bits(a.exact_fma(x,10000.0,-4.0)),a.bits(x*10000.0-4.0))
        self.assertEqual(a.rule(1,0),('default20',False))
        self.assertEqual(a.rule(1,-1),('default20',True))

if __name__=='__main__':unittest.main()
