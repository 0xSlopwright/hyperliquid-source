"""New transport CLIs reject ambiguous/missing artifact identities before reads."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
MODULES = ('tcp_frame_write', 'node_port', 'socket_calls', 'gossip_rpc_timeouts',
           'local_abci_gates', 'height_retry', 'gossip_peer_cap', 'gossip_override_timing',
           'gossip_connect_stagger', 'firewall_mismatch', 'firewall_update_cycle',
           'connections_accept_loop', 'connections_accept_metrics', 'abci_latency_sampler',
           'lz4_stats_report', 'channel_locations', 'consensus_config')


class TransportManifestIntegration(unittest.TestCase):
    def test_ambiguous_or_missing_identity_precedes_artifact_access(self):
        entry = {'path': 'artifacts/node/94/hl-node', 'size': 91774280,
                 'sha256': '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'}
        for name in MODULES:
            spec = importlib.util.spec_from_file_location('review_' + name, ROOT / 'tools' / (name + '_static.py'))
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            for manifest, message in (({'files': [entry, entry]}, 'Duplicate path'),
                                      ({'files': []}, 'No provenance/artifacts.json entry')):
                with self.subTest(tool=name, error=message), tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    (root / 'provenance').mkdir()
                    (root / 'provenance/artifacts.json').write_text(json.dumps(manifest))
                    with mock.patch.object(module, 'ROOT', root), mock.patch.object(module, 'check') as check:
                        with self.assertRaisesRegex(ValueError, message):
                            module.main([])
                        check.assert_not_called()
