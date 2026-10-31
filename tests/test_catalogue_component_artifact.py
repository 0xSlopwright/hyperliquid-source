import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from catalogue import validate_progress


def _progress(component_id):
    return {'gates': {g: False for g in ('mapped', 'built', 'behavior', 'identity')}, 'components': {component_id: {
        'gates': {g: False for g in ('mapped', 'built', 'behavior', 'identity')}, 'evidence': [], 'raw_equal_bodies': 0,
        'normalized_only_bodies': 0, 'total_function_windows': None}}}


class CatalogueComponentArtifactTests(unittest.TestCase):
    def test_missing_component_artifact_rejected(self):
        components = [{**{'name': 'Exchange', 'scope': 'Spot', 'first_task': 'Fixture', 'depends_on': []}, 'id': 'exchange', 'name': 'Exchange', 'scope': 'Spot',
                       'depends_on': []}]
        with self.assertRaises(ValueError):
            validate_progress(components, _progress('exchange'), Path('.'))

    def test_artifact_component_accepted(self):
        components = [{**{'name': 'Exchange', 'scope': 'Spot', 'artifact': 'node94', 'first_task': 'Fixture', 'depends_on': []}, 'id': 'exchange', 'name': 'Exchange', 'scope': 'Spot',
                       'artifact': 'hl-node', 'depends_on': []}]
        validate_progress(components, _progress('exchange'), Path('.'))


if __name__ == '__main__':
    unittest.main()
