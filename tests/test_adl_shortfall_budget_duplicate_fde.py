"""adl Image must refuse duplicate FDE starts.

Sibling of open #1102 (fees_schedule_admission): that tool built its
FDE lookup straight from the unvalidated `eh_frame_records` walker,
bypassing the validated `fde_extents` path whose unwind index rejects
duplicate starts. adl_shortfall_budget does the same bypass in a
different shape: Image() sorts the raw records into a list and
fde_of() bisects it with bisect_right, so two records naming the same
pc_begin are both kept and the wider one always wins — the sorted order
puts the narrow record first and bisect_right lands on the last
duplicate, so the narrow range is never returned. fde_of()'s end is
used as authority downstream (e.g. the spill scan in dispatch_block
reads fde[0]..fde[1] and fails closed only on a mismatch against the
wide range), so the shadowed record's range is never seen, with no
error and no count.

No target binary is needed: the fixture is the repo's own
tests/test_fde_extents.build() builder, exactly as #1102's
reproduction uses it.
"""

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tests'))
sys.path.insert(0, str(ROOT / 'tools'))

import test_fde_extents as tfe  # noqa: E402
import adl_shortfall_budget as adl  # noqa: E402


def image(functions):
    data, _ = tfe.build(functions)
    return adl.Image(bytes(data))


class DuplicateFdeStartTests(unittest.TestCase):
    def test_duplicate_starts_rejected(self):
        with self.assertRaisesRegex(adl.ToolError, 'duplicate FDE start'):
            image([(0x1000, 0x10, None, 'zR'),
                   (0x1000, 0x40, None, 'zR'),
                   (0x1020, 0x10, None, 'zR')])

    def test_duplicate_starts_rejected_regardless_of_record_order(self):
        with self.assertRaisesRegex(adl.ToolError, 'duplicate FDE start'):
            image([(0x1000, 0x40, None, 'zR'),
                   (0x1000, 0x10, None, 'zR'),
                   (0x1020, 0x10, None, 'zR')])

    def test_distinct_starts_still_resolve(self):
        img = image([(0x1000, 0x10, None, 'zR'),
                     (0x1020, 0x10, None, 'zR')])
        self.assertEqual(img.fde_of(0x1008), (0x1000, 0x1010))
        self.assertEqual(img.fde_of(0x1028), (0x1020, 0x1030))


if __name__ == '__main__':
    unittest.main()
