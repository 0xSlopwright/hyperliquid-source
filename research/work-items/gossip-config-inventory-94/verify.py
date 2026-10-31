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
EXPECTED_LOCATIONS = (('0x569e4f8', 260, 35),
 ('0x569e510', 167, 98),
 ('0x569e528', 205, 21),
 ('0x569e540', 133, 98),
 ('0x569e558', 140, 17),
 ('0x569e570', 299, 35),
 ('0x569e588', 340, 33),
 ('0x569e5a0', 381, 102),
 ('0x571ce38', 260, 35),
 ('0x571ce50', 167, 98),
 ('0x571ce68', 205, 21),
 ('0x571ce80', 146, 98),
 ('0x571ce98', 161, 17),
 ('0x571ceb0', 299, 35),
 ('0x571cec8', 340, 33),
 ('0x571cee0', 381, 102),
 ('0x572eba8', 106, 32),
 ('0x572ebc0', 89, 13),
 ('0x572ebd8', 90, 13),
 ('0x572ebf0', 260, 35),
 ('0x572ec08', 167, 98),
 ('0x572ec20', 205, 21),
 ('0x572ec38', 146, 98),
 ('0x572ec50', 161, 17),
 ('0x572ec68', 299, 35),
 ('0x572ec80', 421, 9),
 ('0x572ec98', 340, 33),
 ('0x572ecb0', 381, 102),
 ('0x572ecc8', 377, 13),
 ('0x572ece0', 470, 21),
 ('0x57384a8', 260, 35),
 ('0x57384c0', 167, 98),
 ('0x57384d8', 205, 21),
 ('0x57384f0', 146, 98),
 ('0x5738508', 161, 17),
 ('0x5738520', 299, 35),
 ('0x5738538', 340, 33),
 ('0x5738550', 381, 102))
EXPECTED_FDES = (('0x22615b0', '0x22689f0'),
 ('0x227a0e0', '0x227bceb'),
 ('0x4356c90', '0x435cb15'),
 ('0x439baf0', '0x439ec8d'),
 ('0x4741210', '0x4741694'),
 ('0x4741dc0', '0x4742cb1'),
 ('0x4743490', '0x4744152'),
 ('0x4744160', '0x474822f'),
 ('0x4759970', '0x47604b0'),
 ('0x4b29760', '0x4b2fd98'),
 ('0x4b3c880', '0x4b3f36c'))
EXPECTED_EDGES = (('0x227a6d9', '0x227a0e0', '0x22615b0'),
 ('0x439c15e', '0x439baf0', '0x4741210'),
 ('0x439c4ac', '0x439baf0', '0x4356c90'),
 ('0x475bde9', '0x4759970', '0x4741210'),
 ('0x475dd93', '0x4759970', '0x4744160'),
 ('0x4b3cb57', '0x4b3c880', '0x4741210'),
 ('0x4b3ce98', '0x4b3c880', '0x4b29760'))
EXPECTED_METRICS = {'constants_bound': 0,
 'constants_unresolved': 3,
 'counted_fragment_anchors': 2,
 'decoded_instructions': 27776,
 'diagnostics_absent': 0,
 'diagnostics_bound': 3,
 'diagnostics_probed': 7,
 'diagnostics_unresolved': 4,
 'indirect_calls_unresolved': 1571,
 'indirect_jumps_unresolved': 95,
 'internal_rel32_calls': 0,
 'internal_rel32_jumps': 1377,
 'location_leas': 59,
 'locations': 38,
 'pointer_length_anchors': 1,
 'scoped_fde_bytes': 163287,
 'scoped_fdes': 11,
 'scoped_rel32_calls': 7,
 'scoped_rel32_jumps': 0,
 'unique_line_column': 16,
 'unresolved_external_rel32_calls': 850,
 'unresolved_external_rel32_jumps': 0}
EXPECTED_SEEDS = (('0x22615b0', True, True),
 ('0x227a0e0', True, True),
 ('0x4356c90', True, True),
 ('0x439baf0', True, True),
 ('0x4741210', True, True),
 ('0x4741dc0', True, True),
 ('0x4743490', True, True),
 ('0x4744160', True, True),
 ('0x4759970', True, True),
 ('0x4b29760', True, True),
 ('0x4b3c880', True, True))
EXPECTED_DIAGNOSTICS = (('override_gossip_config.json', 'present-but-unbound', ()),
 ('assertion failed: !res.read().root_node_ips.is_empty()', 'bound', ('0x4742a75',)),
 ('non-testing local chain', 'present-but-unbound', ()),
 ('failed to load gossip config file at ', 'bound', ('0x4741ff8',)),
 ('using gossip config (', 'bound', ('0x4742559',)),
 ('n_gossip_peers clipped to', 'present-but-unbound', ()),
 ('GossipConfigInner', 'present-but-unbound', ()))


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
    spec = importlib.util.spec_from_file_location('gossip_config_inventory', ROOT/'tools/gossip_config_inventory.py')
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
    check(evidence['scope_rule'] == 'node/src/gossip_config.rs', 'scope differs')
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
