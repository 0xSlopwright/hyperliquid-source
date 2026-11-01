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
EXPECTED_LOCATIONS = (('0x5692da0', 271, 17),
 ('0x569ea98', 57, 38),
 ('0x569eab0', 57, 64),
 ('0x569eac8', 57, 22),
 ('0x569eae0', 54, 15),
 ('0x569eaf8', 64, 13),
 ('0x569eb10', 73, 17),
 ('0x569eb28', 73, 43),
 ('0x569eb40', 70, 41),
 ('0x569eb58', 82, 50),
 ('0x569eb70', 94, 22),
 ('0x569eb88', 162, 33),
 ('0x569eba0', 190, 71),
 ('0x569ebb8', 148, 29),
 ('0x569ebd0', 192, 56),
 ('0x569ebe8', 211, 29),
 ('0x569ec00', 273, 49),
 ('0x569ec18', 39, 15),
 ('0x569ec30', 282, 15),
 ('0x569ec48', 296, 17),
 ('0x5729e28', 305, 19),
 ('0x5729e40', 317, 21),
 ('0x5729e58', 325, 19))
EXPECTED_FDES = (('0x2017c80', '0x2018ded'),
 ('0x226c2d0', '0x22713e1'),
 ('0x227a0e0', '0x227bceb'),
 ('0x227bcf0', '0x227bd39'),
 ('0x22b47c0', '0x22b649a'),
 ('0x4546c60', '0x4546fc2'),
 ('0x4546fd0', '0x4547689'))
EXPECTED_EDGES = (('0x226c756', '0x226c2d0', '0x22b47c0'),
 ('0x226c860', '0x226c2d0', '0x227a0e0'),
 ('0x227b728', '0x227a0e0', '0x227bcf0'),
 ('0x22b51b4', '0x22b47c0', '0x227a0e0'))
EXPECTED_METRICS = {'constants_bound': 0,
 'constants_unresolved': 7,
 'counted_fragment_anchors': 0,
 'decoded_instructions': 7473,
 'diagnostics_absent': 0,
 'diagnostics_bound': 7,
 'diagnostics_probed': 8,
 'diagnostics_unresolved': 1,
 'indirect_calls_unresolved': 474,
 'indirect_jumps_unresolved': 16,
 'internal_rel32_calls': 0,
 'internal_rel32_jumps': 302,
 'location_leas': 28,
 'locations': 23,
 'pointer_length_anchors': 7,
 'scoped_fde_bytes': 42439,
 'scoped_fdes': 7,
 'scoped_rel32_calls': 4,
 'scoped_rel32_jumps': 0,
 'unique_line_column': 23,
 'unresolved_external_rel32_calls': 290,
 'unresolved_external_rel32_jumps': 0}
EXPECTED_SEEDS = (('0x2017c80', True, True),
 ('0x226c2d0', True, True),
 ('0x227a0e0', True, True),
 ('0x227bcf0', True, True),
 ('0x22b47c0', True, True),
 ('0x4546c60', True, True),
 ('0x4546fd0', True, True))
EXPECTED_DIAGNOSTICS = (('firewall_ips', 'bound', ('0x226c62b',)),
 ('failed to load firewall ips', 'bound', ('0x226ff06',)),
 ('failed to load node config', 'bound', ('0x227019f',)),
 ('node_gossip_priority_config', 'bound', ('0x226efef',)),
 ('node_config.json', 'present-but-unbound', ()),
 ('home_node_public_ip', 'bound', ('0x226ee9e',)),
 ('listen_get_home_node_ip', 'bound', ('0x226e40e',)),
 ('initial_slow_state_for_join', 'bound', ('0x22b5597',)))

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
    spec = importlib.util.spec_from_file_location('startup_inventory', ROOT/'tools/startup_inventory.py')
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
    check(evidence['scope_rule'] == 'node/src/startup.rs', 'scope differs')
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
