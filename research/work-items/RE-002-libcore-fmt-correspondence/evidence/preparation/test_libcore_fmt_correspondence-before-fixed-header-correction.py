"""Independent ar/ELF/typed-relocation controls, never object execution.

Tiny parser fixtures are synthetic and claim no original function identity.
Actual correspondence expectations were frozen from prior admitted artifacts
before the new producer was inspected. Actual archive qualification can skip
only when that exact installed input is absent; skips do not qualify it.
"""
import copy
import hashlib
import os
from pathlib import Path
import struct
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import libcore_fmt_correspondence as subject

ARCHIVE = Path(os.environ.get('HL_LIBCORE_ARCHIVE',
    '/tmp/hl-rem-rust-1.94.1-20261031/prefix/lib/rustlib/x86_64-unknown-linux-gnu/lib/libcore-e60dd2ab51fbc7de.rlib'))
TARGET = ROOT / 'artifacts/node/94/hl-node'
EXPECTED = {'parent': (390,36,354,354,[]),
            'adapter': (622,4,618,616,[464,467]),
            'decimal': (444,36,408,408,[])}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def ar_entry(label, payload):
    header = (label.encode().ljust(16) + b'0'.ljust(12) + b'0'.ljust(6)
              + b'0'.ljust(6) + b'100644'.ljust(8) + str(len(payload)).encode().ljust(10) + b'`\n')
    assert len(header) == 60
    return header + payload + (b'\n' if len(payload) & 1 else b'')


def tiny_elf(kind=1, relative_rows=None):
    """Own 8-byte text fixture, not a fabricated captured function size.

    The target variant has one congruent PT_LOAD and an actual .rela.dyn.
    It is used only for parser/link counterfactuals, not artifact admission.
    """
    names = b'\0.text\0.data\0.rela.text\0.rela.dyn\0.symtab\0.strtab\0.shstrtab\0'
    strings = b'\0fixture\0other\0'
    rows = [(2, (2 << 32) | 2, -4)] if kind == 1 else (
        relative_rows if relative_rows is not None else [(0x400120, 8, 0x400100)])
    raw = bytearray(0x280 + 7 * 64)
    raw[:7] = b'\x7fELF\x02\x01\x01'
    struct.pack_into('<HHIQQQIHHHHHH', raw, 16, kind,62,1,0,64 if kind == 3 else 0,
                     0x280,0,64,56 if kind == 3 else 0,1 if kind == 3 else 0,64,7,6)
    if kind == 3:
        struct.pack_into('<IIQQQQQQ', raw,64,1,7,0,0x400000,0x400000,len(raw),len(raw),0x1000)
    raw[0x100:0x108] = b'\x90' * 8
    raw[0x120:0x130] = bytes(16)
    for i,row in enumerate(rows):struct.pack_into('<QQq',raw,0x140+i*24,*row)
    struct.pack_into('<IBBHQQ',raw,0x180+24,1,18,0,1,0,8)
    struct.pack_into('<IBBHQQ',raw,0x180+48,9,17,0,2,0,16)
    raw[0x1e0:0x1e0+len(strings)] = strings
    raw[0x200:0x200+len(names)] = names
    def section(index,name,typ,flags,address,offset,size,link=0,info=0,align=1,entry=0):
        struct.pack_into('<IIQQQQIIQQ',raw,0x280+index*64,names.index(name) if name else 0,
                         typ,flags,address,offset,size,link,info,align,entry)
    section(0,b'',0,0,0,0,0)
    section(1,b'.text',1,6,0x400100 if kind==3 else 0,0x100,8,align=16)
    section(2,b'.data',1,3,0x400120 if kind==3 else 0,0x120,16,align=8)
    section(3,b'.rela.text' if kind==1 else b'.rela.dyn',4,0,0,0x140,len(rows)*24,4,1 if kind==1 else 0,8,24)
    section(4,b'.symtab',2,0,0,0x180,72,5,1,8,24)
    section(5,b'.strtab',3,0,0,0x1e0,len(strings))
    section(6,b'.shstrtab',3,0,0,0x200,len(names))
    return bytes(raw)


class ContainerAndRelationControls(unittest.TestCase):
    def test_actual_gnu_ar_names_padding_and_malformed_boundaries(self):
        normal = b'!<arch>\n' + ar_entry('sample.o/',b'odd')
        long = b'very-long-selected-name.o/\n'
        named = b'!<arch>\n' + ar_entry('//',long) + ar_entry('/0',b'abc')
        self.assertEqual(subject.ar_members(normal), {'sample.o': b'odd'})
        self.assertEqual(subject.ar_members(named), {'very-long-selected-name.o': b'abc'})
        oversized = bytearray(normal); oversized[8+48:8+58] = b'99'.ljust(10)
        malformed = [b'?'+normal[1:],b'!<arch>\n'+bytes(59),bytes(oversized),
                     b'!<arch>\n'+ar_entry('sample.o/',b'a')+ar_entry('sample.o/',b'b'),
                     b'!<arch>\n'+ar_entry('//',long)+ar_entry('/999',b'a'),
                     b'!<arch>\n'+ar_entry('//',b'unterminated')+ar_entry('/0',b'a'),normal[:-1]]
        for i,data in enumerate(malformed):
            with self.subTest(control=i), self.assertRaises(ValueError):subject.ar_members(data)

    def test_tiny_elf_structural_headers_and_actual_rela_metadata(self):
        good = tiny_elf(); elf = subject.Elf(good,1)
        self.assertEqual((elf.function(1,'fixture')['size'],len(elf.section_bytes(1))), (8,8))
        self.assertEqual(elf.relocations(1)[0]['kind'],2)
        variants = []
        for offset,fmt,value in [(0,'B',0),(4,'B',1),(5,'B',2),(16,'H',3),(18,'H',183),(40,'Q',len(good)+1)]:
            data=bytearray(good);struct.pack_into('<'+fmt,data,offset,value);variants.append(bytes(data))
        for data in variants:
            with self.subTest(header=digest(data)), self.assertRaises(ValueError):subject.Elf(data,1)
        # Real serialized sh_entsize/sh_link/sh_info and r_info corruptions.
        for offset,fmt,value in [(0x280+3*64+56,'Q',16),(0x280+3*64+40,'I',5),
                                 (0x140+8,'Q',(99<<32)|2)]:
            data=bytearray(good);struct.pack_into('<'+fmt,data,offset,value)
            with self.subTest(field=offset), self.assertRaises(ValueError):subject.Elf(bytes(data),1).relocations(1)
        data=bytearray(good);struct.pack_into('<I',data,0x280+3*64+44,99)
        parsed=subject.Elf(bytes(data),1)
        with self.assertRaises(ValueError):parsed.relocations(99)

    def test_selected_func_uses_actual_type_value_size_and_section(self):
        good=tiny_elf()
        for offset,fmt,value in [(0x180+24+8,'Q',1),(0x180+24+16,'Q',0),
                                 (0x180+24+16,'Q',7),(0x180+24+4,'B',16),(0x180+24+6,'H',2)]:
            data=bytearray(good);struct.pack_into('<'+fmt,data,offset,value);elf=subject.Elf(bytes(data),1)
            if offset==0x180+24+4:self.assertEqual(elf.symbols(4)[1]['info']&15,0)
            with self.subTest(field=offset,value=value), self.assertRaises(ValueError):elf.function(1,'fixture')

    def test_typed_code_fields_derive_width_and_refuse_bounds_overlap_addend(self):
        source=b'\x90'*8; base={'offset':2,'kind':2,'addend':-4,'symbol':{}}
        result=subject.compare_code(source,source,[{**base,'width':99}])
        self.assertEqual((result['actual_RELA_field_bytes'],result['relocations'][0]['width']), (4,4))
        invalid = [[{**base,'kind':1}], [{**base,'offset':-1}], [{**base,'offset':5}],
                   [base,{**base,'offset':3}], [{**base,'addend':-8}]]
        for rows in invalid:
            with self.subTest(rows=rows), self.assertRaises(ValueError):subject.compare_code(source,source,rows)
        with self.assertRaises(ValueError):subject.compare_code(source,source[:-1],[base])

    def test_target_relative_requires_unique_kind_symbol_and_real_mapping(self):
        self.assertEqual(subject.Elf(tiny_elf(3),3).relative(0x400120)['addend'],0x400100)
        for rows in [[(0x400120,8,0x400100)]*2,[(0x400120,1,0x400100)],
                     [(0x400120,(1<<32)|8,0x400100)],[(0x400120,8,0x500000)]]:
            with self.subTest(rows=rows), self.assertRaises(ValueError):
                subject.Elf(tiny_elf(3,rows),3).relative(0x400120)
        with self.assertRaises(ValueError):subject.Elf(tiny_elf(3),3).relative(0x40012c)

    def test_small_path_replacement_cannot_change_an_admitted_snapshot(self):
        original=b'!<arch>\n'+ar_entry('sample.o/',b'admitted')
        with tempfile.TemporaryDirectory(prefix='core-fmt-snapshot-',dir='/tmp') as temp:
            path=Path(temp)/'input.a';path.write_bytes(original)
            snapshot=subject.admit_file(path,digest(original))
            replacement=Path(temp)/'replacement';replacement.write_bytes(b'replaced');replacement.replace(path)
            self.assertIs(type(snapshot),bytes)
            self.assertEqual(subject.ar_members(snapshot),{'sample.o':b'admitted'})
            with self.assertRaises(ValueError):subject.admit_file(path,digest(original))

    def test_prior_output_and_wrong_inputs_do_not_publish(self):
        with tempfile.TemporaryDirectory(prefix='core-fmt-output-',dir='/tmp') as temp:
            root=Path(temp);old=root/'old';old.mkdir();marker=old/'retained';marker.write_bytes(b'preserve\n')
            with self.assertRaisesRegex(ValueError,'Output already exists'):
                subject.collect(root/'missing-target',root/'missing-core',old)
            self.assertEqual(marker.read_bytes(),b'preserve\n')
            bad=root/'wrong';bad.write_bytes(b'not the captured artifact')
            new=root/'new'
            with self.assertRaises(ValueError):subject.collect(bad,bad,new)
            self.assertFalse(new.exists())


class ActualArtifactCorrespondence(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not ARCHIVE.is_file():
            raise unittest.SkipTest('Exact published libcore archive absent; actual artifact correspondence unqualified')
        cls.target=subject.admit_file(TARGET,subject.TARGET_SHA256)
        cls.archive=subject.admit_file(ARCHIVE,subject.CORE_SHA256)
        cls.member=subject.ar_members(cls.archive)[subject.MEMBER]
        cls.source=subject.Elf(cls.member,1)
        cls.report,cls.exports=subject.analyze(cls.target,cls.archive)
        cls.bodies={row['role']:row for row in cls.report['bodies']}

    def test_actual_full_symbols_typed_fields_raw_differences_and_gaps(self):
        counts=self.report['counts']
        self.assertEqual([counts[k] for k in ('selected_code_bytes','actual_code_RELA_fields','actual_code_RELA_bytes',
                          'non_RELA_bytes','equal_non_RELA_bytes','non_RELA_gap_bytes','raw_differing_code_bytes')],
                         [1456,19,76,1380,1378,2,78])
        for role,(size,fields,complement,equal,gaps) in EXPECTED.items():
            with self.subTest(role=role):
                row=self.bodies[role];symbol=row['source_symbol'];comparison=row['comparison']
                self.assertEqual((symbol['info']&15,symbol['value'],symbol['size']), (2,0,size))
                self.assertEqual(symbol['info'],2 if role=='decimal' else 18)
                self.assertEqual((comparison['bytes'],comparison['actual_RELA_field_bytes'],
                                  comparison['non_RELA_bytes'],comparison['equal_non_RELA_bytes']),
                                 (size,fields,complement,equal))
                self.assertEqual(comparison['non_RELA_difference_offsets'],gaps)
                self.assertTrue(all(r['width']==4 and r['kind'] in (2,9) and r['addend']==-4
                                    for r in comparison['relocations']))
        adapter=self.bodies['adapter']['comparison']
        self.assertFalse(adapter['raw_equal'])
        self.assertEqual((self.exports['official/adapter.bin'][464:468],
                          self.exports['captured/adapter.bin'][464:468]),
                         (bytes.fromhex('4d8d2437'),bytes.fromhex('4e8d243e')))
        self.assertEqual(adapter['non_RELA_difference_offsets'],[464,467])

    def test_actual_nonrela_and_terminal_source_changes_remain_visible(self):
        for role,offset,gaps in [('parent',0,[0]),('adapter',621,[464,467,621])]:
            with self.subTest(role=role):
                official=bytearray(self.exports['official/'+role+'.bin']);official[offset]^=1
                got=subject.compare_code(bytes(official),self.exports['captured/'+role+'.bin'],
                                         self.source.relocations(self.bodies[role]['source_section']['index']))
                self.assertEqual(got['non_RELA_difference_offsets'],gaps)
                self.assertEqual(got['raw_difference_count'],self.bodies[role]['comparison']['raw_difference_count']+1)

    def test_real_serialized_inbounds_source_symbol_changes_break_named_adapter_links(self):
        expected=self.source.function(883)
        wrong=self.source.function(111)
        self.assertNotEqual(wrong['index'],expected['index'])
        for section_index,field in [(381,294),(381,324),(1113,24)]:
            with self.subTest(section=section_index,field=field):
                table=next(s for s in self.source.sections if s['type']==4 and s['info']==section_index)
                original_rows=self.source.relocations(section_index)
                ordinal=next(i for i,row in enumerate(original_rows) if row['offset']==field)
                old=original_rows[ordinal]
                changed=bytearray(self.member)
                struct.pack_into('<Q',changed,table['offset']+24*ordinal+8,(wrong['index']<<32)|old['kind'])
                parsed=subject.Elf(bytes(changed),1);row=parsed.relocations(section_index)[ordinal]
                self.assertEqual((row['kind'],row['addend'],row['symbol']['section'],row['symbol']['size']),
                                 (old['kind'],old['addend'],111,444))
                self.assertEqual(parsed.function(111),row['symbol'])
                with self.assertRaisesRegex(ValueError,'compared official function'):
                    subject.bind_symbol(row['symbol'],expected)

    def test_actual_referenced_data_changes_cannot_be_trimmed_or_masked(self):
        # Select actual licensed data exports from the analysis that consumes
        # them. Pointer identity still requires separate typed RELA bindings.
        names=[name for name in self.exports if name.startswith('official/data-')]
        selected=[]
        for size in (200,24,48,4,2):
            selected.append(next(name for name in names if len(self.exports[name])==size))
        selected.append('official/num-source-path.bin')
        for name in selected:
            with self.subTest(data=name):
                original=self.exports[name]
                self.assertTrue(subject.compare_data(original,original)['raw_equal'])
                changed=bytearray(original);changed[-1]^=1
                with self.assertRaises(ValueError):subject.compare_data(bytes(changed),original)
                with self.assertRaises(ValueError):subject.compare_data(original+b'\0',original)
        self.assertEqual(len(self.exports['official/num-source-path.bin']),75)
        self.assertEqual((self.report['location_path']['length'],self.report['location_path']['line'],
                          self.report['location_path']['column']), (75,599,5))
        self.assertEqual((self.report['layout']['fixed_bytes'],self.report['layout']['actual_pointer_RELA_bytes']), (24,24))

    def test_actual_supporting_fde_boundary_and_ambiguity_are_separate_from1456(self):
        support=self.report['supporting_callee'];fde=support['target_FDE'];start=fde['start']
        self.assertEqual(fde['end']-start,61)
        self.assertFalse(support['counted_in_primary_denominator'])
        self.assertEqual((support['comparison']['actual_RELA_field_bytes'],support['comparison']['non_RELA_bytes']), (12,49))
        self.assertEqual(subject.unique_fde([fde],start,61),fde)
        wrong=copy.deepcopy(fde);wrong['end']-=1
        with self.assertRaises(ValueError):subject.unique_fde([wrong],start,61)
        with self.assertRaises(ValueError):subject.unique_fde([fde,copy.deepcopy(fde)],start,61)

    def test_same_two_immutable_inputs_reproduce_every_report_and_tiny_export(self):
        report,exports=subject.analyze(self.target,self.archive)
        self.assertEqual(report,self.report)
        self.assertEqual(exports,self.exports)
        self.assertEqual(report['inputs']['core_member_sha256'],subject.MEMBER_SHA256)
        self.assertFalse(report['supporting_callee']['counted_in_primary_denominator'])


if __name__=='__main__':unittest.main()
