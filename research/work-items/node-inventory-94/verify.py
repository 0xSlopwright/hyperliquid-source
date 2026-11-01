#!/usr/bin/env python3
"""Stdlib-only whitelist, manifest, target facts and regeneration (MIT)."""
import hashlib
import importlib.util
import mmap
from pathlib import Path
import re
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
MANIFEST = frozenset({'README.md', 'RESULT.md', 'inventory.json', 'instructions.json', 'verify.py'})
EXPECTED_LOCATIONS = (('0x5692ce0', 756, 102),
 ('0x5692cf8', 241, 65),
 ('0x5692d10', 244, 112),
 ('0x569e678', 217, 48),
 ('0x569e690', 204, 7),
 ('0x569e6a8', 230, 48),
 ('0x569e6c0', 241, 65),
 ('0x569e6d8', 244, 112),
 ('0x569e6f0', 254, 13),
 ('0x569e708', 249, 83),
 ('0x569e720', 305, 96),
 ('0x569e738', 304, 52),
 ('0x569e750', 301, 18),
 ('0x569e768', 94, 45),
 ('0x569e780', 99, 109),
 ('0x569e798', 129, 13),
 ('0x569e7b0', 130, 18),
 ('0x569e7c8', 160, 47),
 ('0x56a6d20', 140, 25),
 ('0x56a6d38', 146, 108),
 ('0x571cfb8', 794, 46),
 ('0x571cfd0', 738, 25),
 ('0x571cfe8', 748, 41),
 ('0x571ff88', 801, 25),
 ('0x571ffa0', 820, 37),
 ('0x572ed48', 572, 37),
 ('0x572ed70', 617, 49),
 ('0x572eda0', 622, 21),
 ('0x572edb8', 622, 90),
 ('0x572edd0', 792, 37),
 ('0x572ede8', 794, 46),
 ('0x572ee00', 362, 25),
 ('0x572ee18', 433, 45))
EXPECTED_FDES = (('0x1fd4570', '0x1fd5b28'),
 ('0x20432b0', '0x2043ad7'),
 ('0x226c2d0', '0x22713e1'),
 ('0x2275a10', '0x227a0db'),
 ('0x22c05a0', '0x22c0b4c'),
 ('0x23ecd70', '0x23ed020'),
 ('0x432e930', '0x432f30a'),
 ('0x43955c0', '0x4395bd9'),
 ('0x4523700', '0x4523df3'),
 ('0x4677fd0', '0x46798ac'),
 ('0x474a4f0', '0x474abdd'),
 ('0x474b140', '0x474ba81'),
 ('0x474bfa0', '0x474e1a1'),
 ('0x47b1c60', '0x47b1ee8'))
EXPECTED_EDGES = (('0x227691b', '0x2275a10', '0x226c2d0'),
 ('0x4395978', '0x43955c0', '0x4523700'),
 ('0x47b1dc1', '0x47b1c60', '0x4523700'))
EXPECTED_METRICS = {'constants_bound': 0,
 'constants_unresolved': 4,
 'counted_fragment_anchors': 3,
 'decoded_instructions': 13336,
 'diagnostics_absent': 0,
 'diagnostics_bound': 11,
 'diagnostics_probed': 18,
 'diagnostics_unresolved': 7,
 'indirect_calls_unresolved': 753,
 'indirect_jumps_unresolved': 24,
 'internal_rel32_calls': 0,
 'internal_rel32_jumps': 465,
 'location_leas': 40,
 'locations': 33,
 'pointer_length_anchors': 10,
 'scoped_fde_bytes': 74384,
 'scoped_fdes': 14,
 'scoped_rel32_calls': 3,
 'scoped_rel32_jumps': 0,
 'unique_line_column': 30,
 'unresolved_external_rel32_calls': 456,
 'unresolved_external_rel32_jumps': 0}
EXPECTED_SEEDS = (('0x1fd4570', True, True),
 ('0x20432b0', True, True),
 ('0x226c2d0', True, True),
 ('0x2275a10', True, True),
 ('0x22c05a0', True, True),
 ('0x23ecd70', True, True),
 ('0x432e930', True, True),
 ('0x43955c0', True, True),
 ('0x4523700', True, True),
 ('0x4677fd0', True, True),
 ('0x474a4f0', True, True),
 ('0x474b140', True, True),
 ('0x474bfa0', True, True),
 ('0x47b1c60', True, True))
EXPECTED_DIAGNOSTICS = (('node_fast', 'bound', ('0x474bfcc',)),
 ('node_disabler', 'bound', ('0x4395968', '0x474b28c', '0x47b1db1')),
 ('slow abci block', 'present-but-unbound', ()),
 ('node slow abci_state driver', 'present-but-unbound', ()),
 ('node_slow_abci_engine', 'bound', ('0x474a95b',)),
 ('run_node_apply_abci_block', 'present-but-unbound', ()),
 ('run_node_send_execution_state', 'present-but-unbound', ()),
 ('replica_cmds', 'present-but-unbound', ()),
 ('visor_abci_states', 'bound', ('0x432e94e',)),
 ('@@ serializing abci state for greeting @@', 'bound', ('0x4678ee9',)),
 ('@@ serialized abci state for greeting @@', 'bound', ('0x46791e1',)),
 ('visor lag increased', 'bound', ('0x432ef8f',)),
 ('Could not get home public ip', 'bound', ('0x474b794',)),
 ('connection_checks', 'present-but-unbound', ()),
 ('error checking connection', 'present-but-unbound', ()),
 ('node_startup_validator_config', 'bound', ('0x226cc2a',)),
 ('new_validator_get_wallet', 'bound', ('0x226cd60',)),
 ('validator_gossip_priority', 'bound', ('0x226d125',)))

def check(condition, message):
    if not condition:
        raise ValueError(message)


def verify_manifest(here):
    actual = set()
    for path in here.iterdir():
        check(not path.is_symlink(), f'symlink in packet: {path.name}')
        # Python import cache is transient and contains no packet evidence.
        if path.name == '__pycache__' and path.is_dir():
            check(all(p.is_file() and not p.is_symlink() and p.suffix == '.pyc' for p in path.iterdir()),
                  'unexpected import cache contents')
            continue
        check(path.is_file(), f'unexpected directory: {path.name}')
        actual.add(path.name)
    check(actual == MANIFEST | {'MANIFEST.sha256'}, 'packet file whitelist differs')
    raw = (here/'MANIFEST.sha256').read_text(encoding='ascii')
    check(raw.endswith('\n'), 'manifest lacks final newline')
    entries = {}
    for line in raw.splitlines():
        match = re.fullmatch(r'([0-9a-f]{64})  ([A-Za-z0-9_.-]+)', line)
        check(match is not None, 'malformed manifest entry')
        digest, name = match.groups()
        check(name in MANIFEST and name not in entries, 'unexpected or duplicate manifest member')
        entries[name] = digest
    check(set(entries) == MANIFEST, 'manifest omits required file')
    for name, digest in entries.items():
        check(hashlib.sha256((here/name).read_bytes()).hexdigest() == digest, f'manifest mismatch: {name}')


def load_tool():
    spec = importlib.util.spec_from_file_location('node_inventory', ROOT/'tools/node_inventory.py')
    tool = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(tool)
    return tool


def verify_docs(here, tool, evidence):
    tables = tool.evidence_tables(evidence)
    expected = {'README.md': ('METRICS', 'LOCATIONS', 'FDES'),
                'RESULT.md': ('METRICS', 'LITERALS', 'ANCHORS', 'EDGES', 'CONSTANTS')}
    for name, tags in expected.items():
        text = (here/name).read_text(encoding='utf-8')
        blocks = re.findall(r'<!-- BEGIN GENERATED ([A-Z]+) -->.*?<!-- END GENERATED \1 -->', text, re.S)
        check(blocks == list(tags), f'derived report blocks differ: {name}')
        for tag in tags:
            blocks = re.findall(f'<!-- BEGIN GENERATED {tag} -->.*?<!-- END GENERATED {tag} -->', text, re.S)
            check(blocks == [tables[tag]], f'derived metrics/facts differ: {name}/{tag}')


def tool_seeds():
    return load_tool().SEEDS


def verify_facts(evidence):
    actual = tuple((x['va'], x['line'], x['column']) for x in evidence['locations'])
    check(actual == EXPECTED_LOCATIONS, 'pinned Location layout differs')
    check(evidence['scope_rule'] == 'node/src/node.rs', 'scope differs')
    check(evidence['metrics'] == EXPECTED_METRICS, 'pinned counts differ')
    check(tuple((f['start'], f['end_exclusive']) for f in evidence['fdes']) == EXPECTED_FDES,
          'pinned FDE ranges differ')
    check(tuple((e['instruction']['va'], e['caller'], e['callee']) for e in evidence['call_edges']) == EXPECTED_EDGES,
          'pinned call edges differ')
    check(tuple((x['address'], x['fde_start'], x['references_scoped_location'])
                for x in evidence['seed_checks']) == EXPECTED_SEEDS, 'seed checks differ')
    check(tuple((x['probe'], x['status'], tuple(a['lea']['va'] for a in x['anchors']))
                for x in evidence['diagnostics']) == EXPECTED_DIAGNOSTICS, 'diagnostic anchors differ')
    check(evidence['method']['all_fde_records_checked'] == 121299, 'FDE inventory differs')
    for edge in evidence['call_edges']:
        check(edge['caller'] in {f['start'] for f in evidence['fdes']} and
              edge['callee'] in {f['start'] for f in evidence['fdes']}, 'edge endpoint differs')


def verify_outputs(here, tool, result):
    for name in tool.OUTPUTS:
        check(tool.render(result[name]) == (here/name).read_bytes(), f'regeneration differs: {name}')
    verify_facts(result['inventory.json'])
    verify_docs(here, tool, result['inventory.json'])


def main():
    verify_manifest(HERE)
    tool = load_tool()
    with (ROOT/tool.TARGET).open('rb') as handle, mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ) as data:
        result = tool.build(data)
    verify_outputs(HERE, tool, result)
    print('PASS: whitelist, manifest, node #94 digest, exact regeneration, target facts and derived report counts')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError) as exc:
        sys.exit(f'FAIL: {exc}')
