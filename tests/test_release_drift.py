from pathlib import Path
import os
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
sys.path.insert(0, str(ROOT / 'research/work-items/RE-014-release-drift'))
from release_drift import classify, fingerprint, monotonic_anchors, normalize, path_strings, require_pie_without_textrel, tsv_bytes
import mutation_controls

PLT, STARTS = (0x900, 0x980), {0x2000}


def norm(text, start=0x1000, end=0x1100):
    return normalize(text, start, end, STARTS, PLT)


def row(start, raw, masked, size=16, callees=(), masks=None):
    return {'start': start, 'size': size, 'raw': raw, 'norm': masked, 'callees': list(callees),
            'masks': {'rip': 1} if masks is None else masks}


class MutationControls(unittest.TestCase):
    """Pure-Python mutation controls — no objdump required."""

    def test_each_mutation_gets_its_expected_class(self):
        for name, mutation, expected in mutation_controls.CASES:
            with self.subTest(name):
                self.assertEqual(mutation_controls.classes(**mutation), expected)


class Normalize(unittest.TestCase):
    def test_masks_only_address_like_operands(self):
        self.assertEqual(norm('call   2000 <foo>'), ('call @fde', ('annot_symbol', 'branch_fde'), 0x2000))
        self.assertEqual(norm('call   910 <x@plt>'), ('call @plt', ('annot_symbol', 'branch_plt'), None))
        self.assertEqual(norm('jmp    3000'), ('jmp @unknown', ('branch_unknown',), None))
        self.assertEqual(norm('jne    1010'), ('jne +0x10', ('branch_intra',), None))
        self.assertEqual(norm('lea    0x1234(%rip),%rax        # 5678 <bar>'), ('lea RIP,%rax', ('annot_comment', 'rip'), None))

    def test_negative_control_immediates_and_displacements_are_never_masked(self):
        # PIE without text relocations: an immediate that falls inside the image range is still a constant.
        self.assertEqual(norm('mov    $0x2000,%edi')[0], 'mov $0x2000,%edi')
        self.assertNotEqual(norm('sub    $0x348,%rsp')[0], norm('sub    $0x3d8,%rsp')[0])
        self.assertNotEqual(norm('movb   $0x0,0x340(%rsp)')[0], norm('movb   $0x0,0x3c8(%rsp)')[0])
        self.assertEqual(norm('mov    $0x2a,%eax')[0], 'mov $0x2a,%eax')
        self.assertEqual(norm('mov    0x18(%rsp),%rax')[0], 'mov 0x18(%rsp),%rax')
        self.assertNotEqual(norm('mov    $0x2a,%eax')[0], norm('mov    $0x2b,%eax')[0])
        self.assertNotEqual(norm('call   2000')[0], norm('call   910')[0])

    def test_intra_function_branch_offsets_are_compared(self):
        self.assertNotEqual(norm('jmp    1010')[0], norm('jmp    1020')[0])


GNU_244 = {  # verbatim GNU objdump 2.44 `-d --no-show-raw-insn -w` text for each byte sequence
    'ff e0': 'jmp    *%rax',
    '3e ff e0': 'notrack jmp *%rax',
    'f2 ff e0': 'bnd jmp *%rax',
}


def one_insn(hexbytes, text, start=0x1000):
    code = bytes.fromhex(hexbytes.replace(' ', ''))
    rows = fingerprint([(start, start + len(code))], lambda s, e: code, [f'    {start:x}:\t{text}\n'], PLT)
    return rows[0]


class PrefixesAreKept(unittest.TestCase):
    """Closed #37: normalize stripped `notrack `/`bnd ` silently, so these three had one digest."""

    def test_three_jmp_rax_encodings_have_distinct_masked_digests(self):
        rows = {h: one_insn(h, t) for h, t in GNU_244.items()}
        self.assertEqual(len({r['norm'] for r in rows.values()}), 3)
        self.assertEqual(len({r['raw'] for r in rows.values()}), 3)
        for r in rows.values():
            self.assertEqual(dict(r['masks']), {})
        for a in GNU_244:
            for b in GNU_244:
                if a != b:
                    with self.subTest(a=a, b=b):
                        self.assertEqual(sorted(r[0] for r in classify([dict(rows[a], start=0x10)],
                                                                         [dict(rows[b], start=0x110)])),
                                         ['unmatched_115', 'unmatched_94'])
                        from release_drift import verdict
                        self.assertEqual(verdict(rows[a], rows[b]), 'changed')

    def test_negative_control_same_bytes_same_text_is_identical(self):
        from release_drift import verdict
        for h, t in GNU_244.items():
            with self.subTest(h):
                a, b = one_insn(h, t), one_insn(h, t, start=0x5000)
                self.assertEqual((a['raw'], a['norm']), (b['raw'], b['norm']))
                self.assertEqual(verdict(a, b), 'identical')

    def test_prefix_mnemonics_stay_in_masked_text(self):
        for text in ('notrack jmp *%rax', 'bnd jmp *%rax', 'repz ret', 'bnd ret', 'ds mov %eax,%ebx',
                     'cs nopw 0x0(%rax,%rax,1)', 'lock add %eax,(%rbx)', 'rep movsb %ds:(%rsi),%es:(%rdi)',
                     'repnz movsb %ds:(%rsi),%es:(%rdi)', 'data16 xchg %ax,%ax', 'rex mov %eax,%ebx',
                     'rex.WRXB mov %r8,%r11', 'mov    %eax,(%ebx)'):
            with self.subTest(text):
                self.assertEqual(norm(text), (' '.join(text.split()), (), None))

    def test_prefixed_direct_branches_keep_prefix_and_are_still_masked(self):
        self.assertEqual(norm('bnd call 2000 <foo>'), ('bnd call @fde', ('annot_symbol', 'branch_fde'), 0x2000))
        self.assertEqual(norm('ds call 2000'), ('ds call @fde', ('branch_fde',), 0x2000))
        self.assertEqual(norm('bnd jmp 910 <x@plt>'), ('bnd jmp @plt', ('annot_symbol', 'branch_plt'), None))
        self.assertEqual(norm('notrack bnd jmp 3000'), ('notrack bnd jmp @unknown', ('branch_unknown',), None))
        self.assertEqual(norm('bnd jne 1010'), ('bnd jne +0x10', ('branch_intra',), None))
        self.assertEqual(norm('addr32 call 2000'), ('addr32 call @fde', ('branch_fde',), 0x2000))
        self.assertEqual(norm('addr32 nop'), ('addr32 nop', (), None))
        self.assertNotEqual(norm('bnd call 2000')[0], norm('call   2000')[0])
        self.assertNotEqual(norm('ds call 2000')[0], norm('call   2000')[0])

    def test_branch_hint_suffix_is_kept_and_target_masked(self):
        # 3e 75 xx / 2e 75 xx print as jne,pt / jne,pn; #37 left these targets unmasked.
        self.assertEqual(norm('jne,pt 3000'), ('jne,pt @unknown', ('branch_unknown',), None))
        self.assertEqual(norm('jne,pn 1010'), ('jne,pn +0x10', ('branch_intra',), None))
        self.assertNotEqual(norm('jne,pt 1010')[0], norm('jne    1010')[0])

    def test_instruction_length_is_part_of_the_masked_digest(self):
        # eb 00 and e9 00000000 both print `jmp <next>`; 66 90 and 90 differ only in length+text.
        short = fingerprint([(0x1000, 0x1002)], lambda s, e: b'\xeb\x00', ['    1000:\tjmp    1002\n'], PLT)[0]
        near = fingerprint([(0x1000, 0x1005)], lambda s, e: b'\xe9' + bytes(4), ['    1000:\tjmp    1005\n'], PLT)[0]
        self.assertNotEqual(short['norm'], near['norm'])

    def test_unlabelled_text_equality_is_not_a_move(self):
        # 01 c3 and 03 d8 both print `add %eax,%ebx` at equal length: no address mask explains the
        # byte difference, so verdict() says changed, not moved_only.
        from release_drift import verdict
        a = one_insn('01 c3', 'add    %eax,%ebx')
        b = one_insn('03 d8', 'add    %eax,%ebx')
        self.assertEqual(a['norm'], b['norm'])
        self.assertNotEqual(a['raw'], b['raw'])
        self.assertEqual(verdict(a, b), 'changed')

    def test_every_rewrite_is_labelled(self):
        self.assertEqual(norm('nop # comment')[1], ('annot_comment',))
        self.assertEqual(norm('mov    %eax,%ebx')[1], ())


class Fingerprint(unittest.TestCase):
    LINES = ['\n', '    1000:\tpush   %rbp\n', '    1001:\tcall   1010 <f>\n', '    1006:\tret\n',
             '    1010:\tret\n']

    def run_fp(self, spans, lines=None):
        return fingerprint(spans, lambda s, e: bytes(e - s), lines or self.LINES, PLT)

    def test_records_call_sites_and_masks(self):
        rows = self.run_fp([(0x1000, 0x1007), (0x1010, 0x1011)])
        self.assertEqual([r['insns'] for r in rows], [3, 1])
        self.assertEqual(rows[0]['callees'], [0x1010])
        self.assertEqual(dict(rows[0]['masks']), {'annot_symbol': 1, 'branch_fde': 1})

    def test_fails_closed_on_an_extent_with_no_decoded_instructions(self):
        with self.assertRaisesRegex(ValueError, 'No instructions decoded inside extent 0x1020'):
            self.run_fp([(0x1000, 0x1007), (0x1020, 0x1030)])


class Classify(unittest.TestCase):
    def test_raw_and_masked_verdicts_are_reported_separately(self):
        old = [row(0x10, 'r1', 'm1'), row(0x20, 'r2', 'm2')]
        new = [row(0x110, 'r1', 'm1'), row(0x120, 'r9', 'm2')]
        table = classify(old, new)
        self.assertEqual([r[:3] for r in table], [['identical', 'true', 'true'], ['moved_only', 'false', 'true']])

    def test_negative_control_duplicate_hashes_never_get_a_hash_match_class(self):
        old = [row(0x10, 'a', 'm'), row(0x20, 'b', 'm')]
        new = [row(0x110, 'c', 'm'), row(0x120, 'd', 'm'), row(0x130, 'e', 'x')]
        rows = classify(old, new)
        self.assertEqual(sorted(r[0] for r in rows), ['duplicate_ordered', 'duplicate_ordered', 'unmatched_115'])
        self.assertTrue(all(r[7].startswith('duplicate-order-gap-') for r in rows if r[0] == 'duplicate_ordered'))
        three = classify(old + [row(0x30, 'f', 'm')], new)
        self.assertEqual(sorted(r[0] for r in three), ['equivalent_unpaired'] * 5 + ['unmatched_115'])

    def test_callee_position_pairs_changed_code_only_within_size_bound(self):
        old = [row(0x10, 'p', 'P', callees=[0x20]), row(0x20, 'x', 'X', size=100)]
        near = [row(0x110, 'p', 'P', callees=[0x120]), row(0x120, 'y', 'Y', size=150)]
        far = [row(0x110, 'p', 'P', callees=[0x120]), row(0x120, 'y', 'Y', size=201)]
        self.assertEqual([r[0] for r in classify(old, near)], ['identical', 'changed'])
        self.assertEqual([r[0] for r in classify(old, far)], ['unmatched_115', 'identical', 'unmatched_94'])

    def test_negative_control_callee_position_never_claims_a_body_with_a_twin(self):
        old = [row(0x10, 'p', 'P', callees=[0x20]), row(0x20, 'x', 'X')]
        new = [row(0x110, 'p', 'P', callees=[0x120]), row(0x120, 'y', 'Y'), row(0x130, 'x2', 'X'), row(0x140, 'q', 'X')]
        self.assertEqual([r[0] for r in classify(old, new)],
                         ['unmatched_115', 'equivalent_unpaired', 'equivalent_unpaired', 'identical', 'equivalent_unpaired'])

    def test_duplicates_pair_by_order_only_within_one_anchor_gap(self):
        anchors_old = [row(0x10, 'a', 'A'), row(0x100, 'b', 'B')]
        anchors_new = [row(0x110, 'a', 'A'), row(0x200, 'b', 'B')]
        old = anchors_old + [row(0x20, 'd', 'D'), row(0x30, 'd', 'D')]
        new = anchors_new + [row(0x150, 'd', 'D'), row(0x160, 'd', 'D')]
        rows = {r[3]: r for r in classify(old, new)}
        self.assertEqual(rows['0x20'][0], 'duplicate_ordered')
        self.assertEqual(rows['0x20'][5], '0x150')
        self.assertEqual(rows['0x30'][5], '0x160')
        self.assertEqual(rows['0x20'][1:3], ['true', 'true'])

    def test_negative_control_duplicates_split_across_gaps_stay_unpaired(self):
        old = [row(0x10, 'a', 'A'), row(0x100, 'b', 'B'), row(0x20, 'd', 'D'), row(0x30, 'd', 'D')]
        new = [row(0x110, 'a', 'A'), row(0x200, 'b', 'B'), row(0x150, 'd', 'D'), row(0x250, 'd', 'D')]
        self.assertEqual(sorted(r[0] for r in classify(old, new))[:2], ['equivalent_unpaired'] * 2)
        self.assertNotIn('duplicate_ordered', [r[0] for r in classify(old, new)])

    def test_a_leftover_copy_of_a_paired_body_is_equivalent_not_unmatched(self):
        old = [row(0x10, 'x1', 'X'), row(0x20, 'x2', 'X')]
        new = [row(0x110, 'x1', 'X'), row(0x120, 'y', 'Y')]
        self.assertEqual([r[0] for r in classify(old, new)], ['unmatched_115', 'identical', 'equivalent_unpaired'])

    def test_anchor_chain_drops_crossing_pairs(self):
        pairs = {0x10: (0x110, ''), 0x20: (0x300, ''), 0x30: (0x120, ''), 0x40: (0x130, '')}
        self.assertEqual(monotonic_anchors(pairs), [(0x10, 0x110), (0x30, 0x120), (0x40, 0x130)])

    def test_output_is_independent_of_input_order(self):
        old = [row(0x10, 'p', 'P', callees=[0x20, 0x30]), row(0x20, 'x', 'X'), row(0x30, 'z', 'Z')]
        new = [row(0x110, 'p', 'P', callees=[0x120, 0x130]), row(0x120, 'y', 'Y'), row(0x130, 'z2', 'Z')]
        self.assertEqual(tsv_bytes(classify(old, new)), tsv_bytes(classify(old[::-1], new[::-1])))


class Reconcile(unittest.TestCase):
    @staticmethod
    def module():
        import importlib.util
        path = Path(__file__).resolve().parents[1] / 'research/work-items/RE-014-release-drift/reconcile.py'
        spec = importlib.util.spec_from_file_location('reconcile', path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod

    def test_cross_tab_separates_partner_and_norm_agreement(self):
        ours = {0x10: ('moved_only', 0x110), 0x20: ('moved_only', 0x120), 0x30: ('unmatched_94', None)}
        theirs = {0x10: ('moved', 0x110), 0x20: ('moved', 0x130), 0x30: ('removed', None)}
        norms = ({0x10: 'a', 0x20: 'b', 0x30: 'c'}, {0x110: 'a', 0x120: 'b', 0x130: 'b'})
        cells = self.module().reconcile(ours, theirs, norms)['cells']
        self.assertEqual(cells['moved_only|moved'], {'rows': 2, 'same_partner': 1, 'other_partner': 1,
                                                     'our_pair_their_norm_equal': 2, 'our_pair_their_norm_differs': 0})
        self.assertEqual(cells['unmatched_94|removed']['rows'], 1)

    def test_fails_closed_when_the_94_rows_differ(self):
        with self.assertRaises(SystemExit):
            self.module().reconcile({0x10: ('identical', 0x110)}, {0x20: ('moved', 0x120)})


class PieGuard(unittest.TestCase):
    @staticmethod
    def elf(e_type, dynamic):
        data = bytearray(b'\x7fELF\x02\x01' + bytes(58) + dynamic)
        data[16:18] = e_type.to_bytes(2, 'little')
        return bytes(data), {'.dynamic': {'offset': 64, 'size': len(dynamic)}}

    @staticmethod
    def dyn(*entries):
        return b''.join(t.to_bytes(8, 'little') + v.to_bytes(8, 'little') for t, v in entries)

    def test_accepts_pie_without_text_relocations(self):
        require_pie_without_textrel(*self.elf(3, self.dyn((30, 8), (0, 0))))

    def test_fails_closed_on_non_pie_or_text_relocations(self):
        for e_type, dynamic in ((2, self.dyn((0, 0))), (3, self.dyn((22, 0), (0, 0))), (3, self.dyn((30, 4), (0, 0))),
                                (3, self.dyn((30, 8)))):
            with self.subTest(e_type=e_type, dynamic=dynamic.hex()):
                with self.assertRaises(ValueError):
                    require_pie_without_textrel(*self.elf(e_type, dynamic))


class PathStrings(unittest.TestCase):
    def test_matches_only_at_a_path_boundary(self):
        datas = {'94': b'\0/srv/u/code/l1/src/time.rs\0', '115': b'\0/rustc/x/library/std/src/time.rs\0xl1/src/time.rs'}
        out = path_strings(datas, {'absent115': ['l1/time.rs'], 'added115': []})
        self.assertEqual(out, [{'catalogue_list': 'absent115', 'path': 'l1/time.rs',
                                'string_in_94': True, 'string_in_115': False}])


class Determinism(unittest.TestCase):
    def test_classification_bytes_do_not_depend_on_hash_seed(self):
        code = ('import sys; sys.path[:0] = [sys.argv[1]]; from test_release_drift import Classify, row; '
                'from release_drift import classify, tsv_bytes; import hashlib; '
                'old = [row(i, f"r{i}", f"m{i % 7}", callees=[i + 1]) for i in range(60)]; '
                'new = [row(i + 5, f"s{i}", f"m{i % 7}", callees=[i + 6]) for i in range(60)]; '
                'print(hashlib.sha256(tsv_bytes(classify(old, new))).hexdigest())')
        outs = {subprocess.run([sys.executable, '-c', code, str(ROOT / 'tests')], capture_output=True, text=True,
                               check=True, env={**os.environ, 'PYTHONHASHSEED': seed}).stdout for seed in ('0', '1', '4242')}
        self.assertEqual(len(outs), 1)


class GnuObjdumpDetection(unittest.TestCase):
    def test_gnu_objdump_helper_reports_reason_not_a_pass(self):
        from release_drift import gnu_objdump
        path, info = gnu_objdump()
        # On this box we expect GNU; the helper must never return a truthy path for non-GNU.
        if path:
            self.assertIn("GNU", info)
        else:
            self.assertIsInstance(info, str)
            self.assertTrue(info)



class VerifyObjdumpVersionGate(unittest.TestCase):
    """verify.py SKIPPED exit 2 when GNU objdump version is not exactly 2.44.

    No real objdump required: version strings are fed through parse_objdump_version
    and a monkeypatched gnu_objdump().
    """

    PINNED_LINE = "GNU objdump (GNU Binutils for Debian) 2.44"

    def test_parse_objdump_version_tokens(self):
        import verify as re014_verify
        self.assertEqual(re014_verify.parse_objdump_version(self.PINNED_LINE), "2.44")
        self.assertEqual(
            re014_verify.parse_objdump_version("GNU objdump (GNU Binutils) 2.46.1"),
            "2.46.1",
        )
        self.assertEqual(re014_verify.parse_objdump_version("GNU objdump 2.4"), "2.4")
        self.assertEqual(re014_verify.parse_objdump_version("GNU objdump 2.440"), "2.440")
        self.assertIsNone(re014_verify.parse_objdump_version(""))
        self.assertIsNone(re014_verify.parse_objdump_version("(empty --version)"))
        self.assertIsNone(re014_verify.parse_objdump_version("GNU objdump (no version)"))

    def test_negative_control_nearby_versions_are_not_2_44(self):
        import verify as re014_verify
        for line in (
            "GNU objdump (GNU Binutils) 2.4",
            "GNU objdump (GNU Binutils) 2.440",
            "GNU objdump (GNU Binutils for Debian) 2.43",
            "GNU objdump (GNU Binutils) 2.44.0",
        ):
            with self.subTest(line=line):
                ver = re014_verify.parse_objdump_version(line)
                self.assertIsNotNone(ver)
                self.assertNotEqual(ver, "2.44")

    def _run_main_with_objdump_line(self, line, path="/usr/bin/objdump"):
        import io
        import contextlib
        import release_drift
        import verify as re014_verify
        original = release_drift.gnu_objdump
        release_drift.gnu_objdump = lambda: (path, line)
        buf = io.StringIO()
        try:
            with contextlib.redirect_stdout(buf):
                re014_verify.main()
        except SystemExit as exc:
            return exc.code, buf.getvalue()
        finally:
            release_drift.gnu_objdump = original
        return 0, buf.getvalue()

    def test_version_2_46_1_skipped_exit_2(self):
        code, out = self._run_main_with_objdump_line(
            "GNU objdump (GNU Binutils) 2.46.1"
        )
        self.assertEqual(code, 2)
        self.assertIn("SKIPPED (not a PASS)", out)
        self.assertIn("2.44", out)
        self.assertIn("2.46.1", out)

    def test_unparseable_version_skipped_exit_2(self):
        code, out = self._run_main_with_objdump_line("GNU objdump (weird build)")
        self.assertEqual(code, 2)
        self.assertIn("SKIPPED (not a PASS)", out)
        self.assertIn("could not parse version", out)

    def test_version_2_44_gate_allows_pinned_line_through(self):
        """2.44 with the exact pinned branding must not SKIP at the version gate.

        Stops before the expensive rebuild by making the pinned-line check fail
        with a distinct non-2 exit (existing behaviour for branding mismatch is
        unrelated; here we only prove the version gate lets 2.44 through).
        """
        # Use a 2.44 line that is NOT the Debian pinned string: version gate
        # passes, then the existing exact-line check raises SystemExit(str) -> 1.
        code, out = self._run_main_with_objdump_line(
            "GNU objdump (GNU Binutils) 2.44"
        )
        self.assertNotEqual(code, 2)
        self.assertNotIn("SKIPPED (not a PASS)", out)
        # Existing exact-match failure: SystemExit(str) — process exit is 1;
        # unittest sees the message string as the exception code.
        self.assertIsInstance(code, str)
        self.assertIn("needs", code)
        self.assertIn("found", code)

    def test_negative_2_4_and_2_440_skipped_not_treated_as_2_44(self):
        for ver in ("2.4", "2.440"):
            with self.subTest(ver=ver):
                code, out = self._run_main_with_objdump_line(
                    f"GNU objdump (GNU Binutils) {ver}"
                )
                self.assertEqual(code, 2)
                self.assertIn("SKIPPED (not a PASS)", out)
                self.assertIn(ver, out)




class CrosscheckMnemonicControl(unittest.TestCase):
    def test_broad_mask_preserves_mnemonics_and_prefixes(self):
        import importlib.util
        path = ROOT / 'research/work-items/RE-014-release-drift/crosscheck.py'
        spec = importlib.util.spec_from_file_location('review_crosscheck', path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        for prefix in ('', 'lock ', 'cs ', 'data16 cs ', 'rex.W '):
            for left, right in (('add', 'adc'), ('add', 'dec')):
                self.assertNotEqual(module.mask_operands(prefix + left + ' %eax,%ebx'),
                                    module.mask_operands(prefix + right + ' %eax,%ebx'))
        self.assertNotEqual(module.mask_operands('notrack jmp *%rax'),
                            module.mask_operands('bnd jmp *%rax'))
        self.assertEqual(module.mask_operands('bnd call abcdef'), 'bnd call N')
        self.assertEqual(module.mask_operands('mov $0x1234,0x5678(%rip)'), 'mov $N,N(%rip)')
        self.assertEqual(module.mask_operands('add %eax,%ebx'), 'add %eax,%ebx')

if __name__ == '__main__':
    unittest.main()
