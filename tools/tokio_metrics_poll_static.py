#!/usr/bin/env python3
"""Static node #94 traffic-recorder seed `0x3d13cd0`: tokio-metrics 0.3.1 `Instrumented<F>::poll`, not a byte drain.

Question: what does the `net_utils/tcp/traffic_recorder.rs` seed `0x3d13cd0`
account?  The can1357 lead calls it a "per-recorder async poll/update path"
that "atomically drains the pending byte counter with `xchg(0)`" and
"initializes a one-shot first-sample flag".  Closed PR 585 kept that reading
and treated the drained value as a byte count.

In the binary:

* `0x3d13cd0` and `0x3d14390` are two copies of tokio-metrics 0.3.1
  `instrument_poll` (`Instrumented<F>::poll`).  Both reference the Location
  `tokio-metrics-0.3.1/src/task.rs:2483:23`, the overflow-checked
  `woke_at - *idled_at`, and both build the same waker vtable `0x5718a40`,
  whose `wake_by_ref` (`0x3d0a2e0`) is `State::on_wake`: it stores
  `instrumented_at.elapsed()` in nanoseconds into `State+0` with
  `cmpxchg(0, woke_at)`.
* The value swapped out of `State+0` (ArcInner +0x10) is `woke_at`, the wake
  instant in nanoseconds since `instrumented_at`, not a byte count.  The
  "first-sample flag" is `did_poll_once`; the "budget" is `idled_at`.
* The scheduled delay is `poll_start - (instrumented_at + woke_at ns)`,
  saturating at zero; at or above `long_delay_threshold` it goes to the long
  bucket, below it to the short bucket, and always to the scheduled total.
  The inner poll time goes to the slow or fast bucket against
  `slow_poll_threshold`.  Each step matches the 0.3.1 source; the RawMetrics
  and State offsets are recorded in FIELDS and STATE.
* In `0x3d13cd0` the instrumented future is inlined: the
  `traffic_recorder.rs:62:47` async block, a loop that polls a 30.0 s sleep
  and logs.  Its only return is `Poll::Pending`.  `0x3d14390` calls its
  future `0x3d21520`, whose resume panic is `base/src/lu.rs:199:21`, so the
  second copy is not the traffic recorder.  The other seed, `0x3d21670`, is
  the same `traffic_recorder.rs:62:47` block out of line; its one direct
  caller is in a third copy, `0x3d13840`.  (The LZ4 report loop `0x3d21990`
  is likewise called from the copy `0x3d12f20`.)

Only the Python standard library is used.  Every fact is an exact byte window
at a fixed VA inside a parsed .eh_frame FDE; call, branch and RIP-relative
targets, strings, Locations, the waker vtable and a whole-`.text` census of
references are decoded here.  Nothing from the binary is executed.
"""
import argparse
import json
import re
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from artifacts import ROOT, check  # noqa: E402
from elf_index import sections  # noqa: E402
from fde_extents import eh_frame_records  # noqa: E402

TARGET = 'artifacts/node/94/hl-node'
TM_PATH_VA = 0x1ea69a
TM_PATH = (b'/home/ubuntu/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/'
           b'tokio-metrics-0.3.1/src/task.rs')
TR_PATH_VA = 0x1e0680
TR_PATH = b'/home/ubuntu/hl/code_Mainnet/net_utils/src/tcp/traffic_recorder.rs'
LU_PATH_VA = 0x1e4dcc
LU_PATH = b'/home/ubuntu/hl/code_Mainnet/base/src/lu.rs'
# every Location whose file is task.rs: Location -> (line, col)
TM_LOCATIONS = {0x566d448: (2483, 23), 0x5691708: (2483, 23), 0x5718a60: (2483, 23),
                0x571c688: (2483, 23), 0x5756030: (1888, 32)}
IDLE_SUB_LOCATION = 0x5718a60
TR_LOCATIONS = {0x5718be8: (62, 47), 0x57193f8: (62, 47)}
LU_RESUME_LOCATION = (0x57192b0, 199, 21)
INSTANT_ADD = (0x7ce45a, b'overflow when adding duration to instant', 0x5753120)

POLL_TRAFFIC, POLL_LU = 0x3d13cd0, 0x3d14390
ON_WAKE, WAKE, DROP_WAKER, CLONE_WAKER = 0x3d0a2e0, 0x3d0a2d0, 0x3d0a2b0, 0x3d0dff0
INSTANT_NOW, SUB_TIMESPEC = 0x4ee3800, 0x4ee3730
SLEEP_POLL, LU_FUTURE, TRAFFIC_FUTURE, LZ4_FUTURE = 0x3d0eee0, 0x3d21520, 0x3d21670, 0x3d21990
WAKER_VTABLE = 0x5718a40
VTABLE = (CLONE_WAKER, WAKE, ON_WAKE, DROP_WAKER)  # clone, wake, wake_by_ref, drop
CLOCK_GETTIME_SLOT = 0x576ea88
SUB_OVERFLOW_SLOT, PANIC_SLOT = 0x576e150, 0x576e468
THIRTY_SECONDS = 0x403e000000000000  # f64 30.0
NS = 1_000_000_000
NS_MAGIC = 0x44b82fa09b5a53  # (x >> 9) * NS_MAGIC >> 75 == x // 10**9

# RawMetrics fields touched by instrument_poll, as offsets from the ArcInner pointer at State+0x20
FIELDS = {
    0x18: 'first_poll_count', 0x20: 'total_idled_count', 0x28: 'total_scheduled_count',
    0x30: 'total_fast_poll_count', 0x38: 'total_slow_poll_count',
    0x40: 'total_long_delay_count', 0x48: 'total_short_delay_count',
    0x58: 'total_first_poll_delay_ns', 0x60: 'total_idle_duration_ns', 0x68: 'total_scheduled_duration_ns',
    0x70: 'total_fast_poll_duration_ns', 0x78: 'total_slow_poll_duration',
    0x80: 'total_short_delay_duration_ns', 0x88: 'total_long_delay_duration_ns',
    0x90: 'slow_poll_threshold', 0xa0: 'long_delay_threshold',
}
# State fields as offsets from its ArcInner pointer (the waker data pointer is ArcInner + 0x10)
STATE = {0x10: 'woke_at', 0x18: 'waker.vtable', 0x20: 'waker.data', 0x28: 'waker.state',
         0x30: 'metrics', 0x38: 'instrumented_at.secs', 0x40: 'instrumented_at.nanos'}
# per copy: where Instrumented keeps its Arc<State>, idled_at and did_poll_once
COPIES = {'poll_traffic': dict(fde=POLL_TRAFFIC, state=0x0, idled_at=0x160, did_poll_once=0x168),
          'poll_lu': dict(fde=POLL_LU, state=0xd8, idled_at=0xe0, did_poll_once=0xe8)}

WINDOWS = {
    'poll_traffic': (0x3d13cd0, 0x3d13cd0,
        '554157415641554154534881ec980000004889fb4c8b3ebf01000000e80ffb1c014989c689d54c8b2b498b4538488944'
        '2460418b45408944240480bb68010000004c89e8757cc68368010000014c89742408896c2410488b4424604889442468'
        '8b44240489442470488d7c2420488d742408488d542468e8e4f91c01b800ca9a3b48f76424288b4c24304801c84883d2'
        '0031c948f7daba000000004819d24809c2807c242000480f45d1498b4530f048015058488b03488b4030f048ff401848'
        '8b0331c94887481048398b600100007324498b4530f048ff40204889c8482b83600100000f8256020000498b5530f048'
        '014260eb094885c90f8403010000498b4530f048ff40284889c848c1e80949bc535a9ba02fb8440049f7e448c1ea0b48'
        '8b4424604801d00f80ed0100004869d200ca9a3b4829d1034c240481f900ca9a3b720f48ffc00f80ce01000081c10036'
        '65c44c89742408896c24104889442468894c2470488d7c2420488d742408488d542468e8e8f81c01b800ca9a3b48f764'
        '24288b4c24304801c84883d20031f648f7dab9000000004819c94809c1807c242000480f45ce4889c848c1e80949f7e4'
        '48c1ea0b498b4530483b90a000000075214869d200ca9a3b4889ce4829d639b0a8000000760eba80000000be48000000'
        'eb0c72f2ba88000000be40000000f048ff0430f048010c10498b4530f048014868488b2bb90100000031c0f0480fb14d'
        '284883f80274354885c00f858d000000488b4d18498b074885c9742c498b7f084839c1752748397d20752131c9b80100'
        '0000f0480fb14d287541eb61498b07498b7f08ff5010eb55498b7f08ff104989c44989d6488b45184885c07407488b7d'
        '20ff50184c8965184c89752031c9b801000000f0480fb14d287422488b4518488b7d2048c74518000000004885c00f84'
        '8f00000031c948874d28ff50084c8d7308488b034883c010488d0db14aa00148898c2488000000488984249000000048'
        '8d8424880000004889442468488944247048c744247800000000bf01000000e83cf81c014989c789d50fb68358010000'
        '85c00f845301000083f8037450488d3d044ca001ff154eb0a501488d3d69a4abfc488d1528f1a301be28000000ff1565'
        'a4a501488d3dee6a9601ff1560a4a501488d3d494aa001ff1533a1a5014c8965184c8975204889c7e8e3c09401488dbb'
        'b8000000488d742468e8a2aeffff84c00f850201000080bb5001000003751580bb4801000003750c488dbbd0000000e8'
        'acb6ffff8b054e24a70185c00f85fb010000b10131c0f00fb00d0224a7010f8529020000488b05fd23a701488b0dfe23'
        'a7014801c148ffc1660f6f00660fd7d0f7d2488b35f723a70148894424204883c010488944242848894c243066895424'
        '384889742440488d7c2408488d742420e8db76010031c9b001f00fb00d9f23a7010f85dd010000488b7c2410488b7424'
        '18488d44245048894424204883fe020f83d3010000488b44241848894424300f104424080f29442420488d7c2450488d'
        '5424204c89f6e82599000048b80000000000003e40488983b8000000c6835001000000e9e5feffffc6835801000003bf'
        '01000000e8a7f61c014989c64189d4488944245089542458488b44246048894424088b44240489442410488d7c242048'
        '8d742450488d542408e8a2f51c01b800ca9a3b48f76424288b4c24304801c84883d2004c89fe4531ff48f7dab9000000'
        '004819c94809c1807c242000490f45cf48898b600100004c8974245044896424584889742408896c2410488d7c242048'
        '8d742450488d542408e842f51c01807c242000b800000000750a448b7c2430488b442428498b4d30483b819000000075'
        '15443bb998000000730ebe70000000bf30000000eb0c72f2be78000000bf38000000ba00ca9a3b48f7e24589f84901c0'
        '4883d20031c048f7da4819c04c09c0f048ff0439f048010431b0014881c4980000005b415c415d415e415f5dc3488d05'
        '0c22a7014889442450488d4424504889442420488d3d2e22a701488d0d4f48a0014c8d050848a001488d542420be0100'
        '0000ff1510a6a501e9c5fdffff488d3dcc21a701ba00ca9a3bff1571aca501e9c0fdffff488d3db521a70131f6ff1565'
        'aca501e90ffeffff4883fe157314488d4c2420ba01000000e8e31b0000e913feffff488d542420ff153322a601e903fe'
        'ffffeb004989c7488b7424084885f6745f488b7c241048c1e60431d2ff15ee9ca501eb4ceb24eb224989c731c9b001f0'
        '0fb00d4921a7017437488d3d4021a70131f6ff15f0aba501eb264989c7eb214989c780bb5001000003751580bb480100'
        '0003750c488dbbd0000000e8a0b3ffff4c89f7e888b4ffffc68358010000024c89ffe889bd9401ff159b9da501'),
    'poll_lu': (0x3d14390, 0x3d14390,
        '554157415641554154534881ec880000004889fb4c8b26bf01000000e84ff41c014989c64189d7488babd8000000488b'
        '453848894424388b45408944240c80bbe8000000004889e80f8585000000c683e8000000014c8974241044897c241848'
        '8b44243848894424208b44240c89442428488d7c2440488d742410488d542420e81bf31c01b800ca9a3b48f76424488b'
        '4c24504801c84883d20031c948f7daba000000004819d24809c2807c244000480f45d1488b4530f048015058488b83d8'
        '000000488b4030f048ff4018488b83d800000031c94887481048398be00000007324488b4530f048ff40204889c8482b'
        '83e00000000f8271030000488b5530f048014260eb094885c90f8404010000488b4530f048ff40284889c848c1e80949'
        'bd535a9ba02fb8440049f7e548c1ea0b488b4424384801d00f80080300004869d200ca9a3b4829d1034c240c81f900ca'
        '9a3b720f48ffc00f80e902000081c1003665c44c8974241044897c24184889442420894c2428488d7c2440488d742410'
        '488d542420e816f21c01b800ca9a3b48f76424488b4c24504801c84883d20031f648f7dab9000000004819c94809c180'
        '7c244000480f45ce4889c848c1e80949f7e548c1ea0b488b4530483b90a000000075214869d200ca9a3b4889ce4829d6'
        '39b0a8000000760eba80000000be48000000eb0c72f2ba88000000be40000000f048ff0430f048010c10488b4530f048'
        '0148684c8babd8000000b90100000031c0f0490fb14d284883f80274374885c00f8592000000498b4d18498b04244885'
        'c9742f498b7c24084839c1752a49397d20752431c9b801000000f0490fb14d287544eb64498b0424498b7c2408ff5010'
        'eb56498b7c2408ff104989c74989d6498b45184885c07407498b7d20ff50184d897d184d89752031c9b801000000f049'
        '0fb14d287422498b4518498b7d2049c74518000000004885c00f84a001000031c949874d28ff500848896c2470488b83'
        'd80000004883c010488d0dd143a00148894c24784889842480000000488d4424784889442440488944244848c7442450'
        '00000000bf01000000e862f11c014989c64189d7488d7424404889dfe86fce00008844240bbf01000000e841f11c0149'
        '89c44189d5488944246089542468488b44243848894424108b44240c89442418488d7c2420488d742460488d542410e8'
        '3cf01c01b800ca9a3b48f76424288b4c24304801c84883d20031ed48f7dab9000000004819c94809c1807c242000480f'
        '45cd48898be00000004c8964246044896c24684c8974241044897c2418488d7c2420488d742460488d542410e8dfef1c'
        '01807c242000b80000000075098b6c2430488b442428488b4c2470488b4930483b819000000075143ba998000000730e'
        'be70000000bf30000000eb0c72f2be78000000bf38000000ba00ca9a3b48f7e24189e84901c04883d20031c048f7da48'
        '19c04c09c0f048ff0439f0480104310fb644240b4881c4880000005b415c415d415e415f5dc3488d3d7d9cabfc488d15'
        '3ce9a301be28000000ff15799ca501488d3d02639601ff15749ca501488d3d5d42a001ff154799a5014d897d184d8975'
        '204889c7e8f7b89401'),
    'on_wake': (0x3d0a2e0, 0x3d0a2e0,
        '534883ec404889fbbf01000000e80e951d01488b4b288b733048894424088954241048894c241889742420488d7c2428'
        '488d742408488d542418e811941d01b800ca9a3b48f76424304889c18b4424384801c14883d20031c0807c242800480f'
        '45c8480f45d04885d2750731c0f0480fb10b488b4318662e0f1f8400000000004889c14883c902f0480fb14b1875f148'
        '85c074064883c4405bc3488b4308488b7b1048c7430800000000f048836318fd4885c074df4883c4405bff6008'),
    'wake': (0x3d0a2d0, 0x3d0a2d0,
        '4883c7f0ff25c64fa601'),
    'drop_waker': (0x3d0a2b0, 0x3d0a2b0,
        '50488d47f048890424f048ff4ff075094889e7ff15bf43a60158c3'),
    'instant_now': (0x4ee3800, 0x4ee3800,
        '554889e5534883ec18488d75e0ff1575b2880083f8ff7449488b55e84881fa00ca9a3b730b488b45e04883c4185b5dc3'),
    'sub_timespec': (0x4ee3730, 0x4ee3730,
        '554889e5534883ec184889f04889fb488b36488b0a448b40088b7a084531c94139f8410f93c14531d24839ce410f9dc2'
        '450f44d14584d2744a418d8000ca9a3b4889ca48f7da4139f848f7d1410f43c0480f43ca4801f129f83d00ca9a3b720e'
        '4883f9ff744c48ffc105003665c448894b0889431048c703000000004883c4185b5dc3488d7de04889d64889c2e86eff'
        'ffff488b45e0488b4de88b55f04883f00148894b088953104889034883c4185b5dc3488d3dfaa58efb488d15b0f18600'
        'be19000000ff156dac8800'),
    'lu_future_panic': (0x3d21520, 0x3d21571,
        '488d3d387d9f01ff15badaa401'),
    'traffic_future_panic': (0x3d21670, 0x3d216ca,
        '488d3d277d9f01ff1561d9a401'),
}

OPERANDS = {
    0x3d0a2be: (2, 0x3d0a2c9),  # drop_waker: jne
    0x3d0a2c3: (6, 0x576e688),  # drop_waker: call
    0x3d0a2d4: (6, 0x576f2a0),  # wake: jmp
    0x3d0a2ed: (5, 0x4ee3800),  # on_wake: call
    0x3d0a31a: (5, 0x4ee3730),  # on_wake: call
    0x3d0a349: (2, 0x3d0a352),  # on_wake: jne
    0x3d0a36d: (2, 0x3d0a360),  # on_wake: jne
    0x3d0a372: (2, 0x3d0a37a),  # on_wake: je
    0x3d0a393: (2, 0x3d0a374),  # on_wake: je
    0x3d13cec: (5, 0x4ee3800),  # poll_traffic: call
    0x3d13d14: (2, 0x3d13d92),  # poll_traffic: jne
    0x3d13d47: (5, 0x4ee3730),  # poll_traffic: call
    0x3d13d9f: (2, 0x3d13dc5),  # poll_traffic: jae
    0x3d13db4: (6, 0x3d14010),  # poll_traffic: jb
    0x3d13dc3: (2, 0x3d13dce),  # poll_traffic: jmp
    0x3d13dc8: (6, 0x3d13ed1),  # poll_traffic: je
    0x3d13df7: (6, 0x3d13fea),  # poll_traffic: jo
    0x3d13e11: (2, 0x3d13e22),  # poll_traffic: jb
    0x3d13e16: (6, 0x3d13fea),  # poll_traffic: jo
    0x3d13e43: (5, 0x4ee3730),  # poll_traffic: call
    0x3d13e8f: (2, 0x3d13eb2),  # poll_traffic: jne
    0x3d13ea4: (2, 0x3d13eb4),  # poll_traffic: jbe
    0x3d13eb0: (2, 0x3d13ebe),  # poll_traffic: jmp
    0x3d13eb2: (2, 0x3d13ea6),  # poll_traffic: jb
    0x3d13ee5: (2, 0x3d13f1c),  # poll_traffic: je
    0x3d13eea: (6, 0x3d13f7d),  # poll_traffic: jne
    0x3d13efa: (2, 0x3d13f28),  # poll_traffic: je
    0x3d13f03: (2, 0x3d13f2c),  # poll_traffic: jne
    0x3d13f09: (2, 0x3d13f2c),  # poll_traffic: jne
    0x3d13f18: (2, 0x3d13f5b),  # poll_traffic: jne
    0x3d13f1a: (2, 0x3d13f7d),  # poll_traffic: jmp
    0x3d13f26: (2, 0x3d13f7d),  # poll_traffic: jmp
    0x3d13f3b: (2, 0x3d13f44),  # poll_traffic: je
    0x3d13f59: (2, 0x3d13f7d),  # poll_traffic: je
    0x3d13f6e: (6, 0x3d14003),  # poll_traffic: je
    0x3d13f88: (7, 0x5718a40),  # poll_traffic: lea
    0x3d13fbf: (5, 0x4ee3800),  # poll_traffic: call
    0x3d13fd2: (6, 0x3d1412b),  # poll_traffic: je
    0x3d13fdb: (2, 0x3d1402d),  # poll_traffic: je
    0x3d13fdd: (7, 0x5718be8),  # poll_traffic: lea
    0x3d13fe4: (6, 0x576f038),  # poll_traffic: call
    0x3d13fea: (7, 0x7ce45a),  # poll_traffic: lea
    0x3d13ff1: (7, 0x5753120),  # poll_traffic: lea
    0x3d13ffd: (6, 0x576e468),  # poll_traffic: call
    0x3d14003: (7, 0x567aaf8),  # poll_traffic: lea
    0x3d1400a: (6, 0x576e470),  # poll_traffic: call
    0x3d14010: (7, 0x5718a60),  # poll_traffic: lea
    0x3d14017: (6, 0x576e150),  # poll_traffic: call
    0x3d14028: (5, 0x5660110),  # poll_traffic: call
    0x3d14039: (5, 0x3d0eee0),  # poll_traffic: call
    0x3d14040: (6, 0x3d14148),  # poll_traffic: jne
    0x3d1404d: (2, 0x3d14064),  # poll_traffic: jne
    0x3d14056: (2, 0x3d14064),  # poll_traffic: jne
    0x3d1405f: (5, 0x3d0f710),  # poll_traffic: call
    0x3d14064: (6, 0x57864b8),  # poll_traffic: mov
    0x3d1406c: (6, 0x3d1426d),  # poll_traffic: jne
    0x3d14076: (8, 0x5786480),  # poll_traffic: lock
    0x3d1407e: (6, 0x3d142ad),  # poll_traffic: jne
    0x3d14084: (7, 0x5786488),  # poll_traffic: mov
    0x3d1408b: (7, 0x5786490),  # poll_traffic: mov
    0x3d140a2: (7, 0x57864a0),  # poll_traffic: mov
    0x3d140d0: (5, 0x3d2b7b0),  # poll_traffic: call
    0x3d140d9: (8, 0x5786480),  # poll_traffic: lock
    0x3d140e1: (6, 0x3d142c4),  # poll_traffic: jne
    0x3d140ff: (6, 0x3d142d8),  # poll_traffic: jae
    0x3d14126: (5, 0x3d1da50),  # poll_traffic: call
    0x3d14143: (5, 0x3d1402d),  # poll_traffic: jmp
    0x3d14154: (5, 0x4ee3800),  # poll_traffic: call
    0x3d14189: (5, 0x4ee3730),  # poll_traffic: call
    0x3d141e9: (5, 0x4ee3730),  # poll_traffic: call
    0x3d141f8: (2, 0x3d14204),  # poll_traffic: jne
    0x3d1420f: (2, 0x3d14226),  # poll_traffic: jne
    0x3d14218: (2, 0x3d14228),  # poll_traffic: jae
    0x3d14224: (2, 0x3d14232),  # poll_traffic: jmp
    0x3d14226: (2, 0x3d1421a),  # poll_traffic: jb
    0x3d1426d: (7, 0x5786480),  # poll_traffic: lea
    0x3d14283: (7, 0x57864b8),  # poll_traffic: lea
    0x3d1428a: (7, 0x5718ae0),  # poll_traffic: lea
    0x3d14291: (7, 0x5718aa0),  # poll_traffic: lea
    0x3d142a2: (6, 0x576e8b8),  # poll_traffic: call
    0x3d142a8: (5, 0x3d14072),  # poll_traffic: jmp
    0x3d142ad: (7, 0x5786480),  # poll_traffic: lea
    0x3d142b9: (6, 0x576ef30),  # poll_traffic: call
    0x3d142bf: (5, 0x3d14084),  # poll_traffic: jmp
    0x3d142c4: (7, 0x5786480),  # poll_traffic: lea
    0x3d142cd: (6, 0x576ef38),  # poll_traffic: call
    0x3d142d3: (5, 0x3d140e7),  # poll_traffic: jmp
    0x3d142dc: (2, 0x3d142f2),  # poll_traffic: jae
    0x3d142e8: (5, 0x3d15ed0),  # poll_traffic: call
    0x3d142ed: (5, 0x3d14105),  # poll_traffic: jmp
    0x3d142f7: (6, 0x5776530),  # poll_traffic: call
    0x3d142fd: (5, 0x3d14105),  # poll_traffic: jmp
    0x3d14302: (2, 0x3d14304),  # poll_traffic: jmp
    0x3d1430f: (2, 0x3d14370),  # poll_traffic: je
    0x3d1431c: (6, 0x576e010),  # poll_traffic: call
    0x3d14322: (2, 0x3d14370),  # poll_traffic: jmp
    0x3d14324: (2, 0x3d1434a),  # poll_traffic: jmp
    0x3d14326: (2, 0x3d1434a),  # poll_traffic: jmp
    0x3d1432f: (8, 0x5786480),  # poll_traffic: lock
    0x3d14337: (2, 0x3d14370),  # poll_traffic: je
    0x3d14339: (7, 0x5786480),  # poll_traffic: lea
    0x3d14342: (6, 0x576ef38),  # poll_traffic: call
    0x3d14348: (2, 0x3d14370),  # poll_traffic: jmp
    0x3d1434d: (2, 0x3d14370),  # poll_traffic: jmp
    0x3d14359: (2, 0x3d14370),  # poll_traffic: jne
    0x3d14362: (2, 0x3d14370),  # poll_traffic: jne
    0x3d1436b: (5, 0x3d0f710),  # poll_traffic: call
    0x3d14373: (5, 0x3d0f800),  # poll_traffic: call
    0x3d14382: (5, 0x5660110),  # poll_traffic: call
    0x3d14387: (6, 0x576e128),  # poll_traffic: call
    0x3d143ac: (5, 0x4ee3800),  # poll_lu: call
    0x3d143d8: (6, 0x3d14463),  # poll_lu: jne
    0x3d14410: (5, 0x4ee3730),  # poll_lu: call
    0x3d14470: (2, 0x3d14496),  # poll_lu: jae
    0x3d14485: (6, 0x3d147fc),  # poll_lu: jb
    0x3d14494: (2, 0x3d1449f),  # poll_lu: jmp
    0x3d14499: (6, 0x3d145a3),  # poll_lu: je
    0x3d144c8: (6, 0x3d147d6),  # poll_lu: jo
    0x3d144e2: (2, 0x3d144f3),  # poll_lu: jb
    0x3d144e7: (6, 0x3d147d6),  # poll_lu: jo
    0x3d14515: (5, 0x4ee3730),  # poll_lu: call
    0x3d14561: (2, 0x3d14584),  # poll_lu: jne
    0x3d14576: (2, 0x3d14586),  # poll_lu: jbe
    0x3d14582: (2, 0x3d14590),  # poll_lu: jmp
    0x3d14584: (2, 0x3d14578),  # poll_lu: jb
    0x3d145bb: (2, 0x3d145f4),  # poll_lu: je
    0x3d145c0: (6, 0x3d14658),  # poll_lu: jne
    0x3d145d1: (2, 0x3d14602),  # poll_lu: je
    0x3d145db: (2, 0x3d14607),  # poll_lu: jne
    0x3d145e1: (2, 0x3d14607),  # poll_lu: jne
    0x3d145f0: (2, 0x3d14636),  # poll_lu: jne
    0x3d145f2: (2, 0x3d14658),  # poll_lu: jmp
    0x3d14600: (2, 0x3d14658),  # poll_lu: jmp
    0x3d14616: (2, 0x3d1461f),  # poll_lu: je
    0x3d14634: (2, 0x3d14658),  # poll_lu: je
    0x3d14649: (6, 0x3d147ef),  # poll_lu: je
    0x3d14668: (7, 0x5718a40),  # poll_lu: lea
    0x3d14699: (5, 0x4ee3800),  # poll_lu: call
    0x3d146ac: (5, 0x3d21520),  # poll_lu: call
    0x3d146ba: (5, 0x4ee3800),  # poll_lu: call
    0x3d146ef: (5, 0x4ee3730),  # poll_lu: call
    0x3d1474c: (5, 0x4ee3730),  # poll_lu: call
    0x3d1475b: (2, 0x3d14766),  # poll_lu: jne
    0x3d14776: (2, 0x3d1478c),  # poll_lu: jne
    0x3d1477e: (2, 0x3d1478e),  # poll_lu: jae
    0x3d1478a: (2, 0x3d14798),  # poll_lu: jmp
    0x3d1478c: (2, 0x3d14780),  # poll_lu: jb
    0x3d147d6: (7, 0x7ce45a),  # poll_lu: lea
    0x3d147dd: (7, 0x5753120),  # poll_lu: lea
    0x3d147e9: (6, 0x576e468),  # poll_lu: call
    0x3d147ef: (7, 0x567aaf8),  # poll_lu: lea
    0x3d147f6: (6, 0x576e470),  # poll_lu: call
    0x3d147fc: (7, 0x5718a60),  # poll_lu: lea
    0x3d14803: (6, 0x576e150),  # poll_lu: call
    0x3d14814: (5, 0x5660110),  # poll_lu: call
    0x3d21571: (7, 0x57192b0),  # lu_future_panic: lea
    0x3d21578: (6, 0x576f038),  # lu_future_panic: call
    0x3d216ca: (7, 0x57193f8),  # traffic_future_panic: lea
    0x3d216d1: (6, 0x576f038),  # traffic_future_panic: call
    0x4ee3767: (2, 0x4ee37b3),  # sub_timespec: je
    0x4ee378e: (2, 0x4ee379e),  # sub_timespec: jb
    0x4ee3794: (2, 0x4ee37e2),  # sub_timespec: je
    0x4ee37bd: (5, 0x4ee3730),  # sub_timespec: call
    0x4ee37e2: (7, 0x7cdde3),  # sub_timespec: lea
    0x4ee37e9: (7, 0x57529a0),  # sub_timespec: lea
    0x4ee37f5: (6, 0x576e468),  # sub_timespec: call
    0x4ee380d: (6, 0x576ea88),  # instant_now: call
    0x4ee3816: (2, 0x4ee3861),  # instant_now: je
    0x4ee3823: (2, 0x4ee3830),  # instant_now: jae
}


class EvidenceError(RuntimeError):
    pass


def require(ok, message):
    if not ok:
        raise EvidenceError(message)


class Image:
    def __init__(self, data):
        self.data = data
        self.secs = sections(data)
        rela = next((s for s in self.secs if s['name'] == '.rela.dyn' and s['type'] == 4), None)
        require(rela is not None and rela['size'] % 24 == 0, 'no well-formed .rela.dyn')
        dynsym = next((s for s in self.secs if s['name'] == '.dynsym'), None)
        dynstr = next((s for s in self.secs if s['name'] == '.dynstr'), None)
        require(dynsym is not None and dynstr is not None, 'no .dynsym/.dynstr')
        self.relative, self.glob_dat = {}, {}
        for pos in range(rela['offset'], rela['offset'] + rela['size'], 24):
            where, info, addend = struct.unpack_from('<QQq', data, pos)
            if info & 0xffffffff == 8:
                self.relative[where] = addend
            elif info & 0xffffffff == 6:
                name = dynstr['offset'] + struct.unpack_from('<I', data, dynsym['offset'] + 24 * (info >> 32))[0]
                self.glob_dat[where] = data[name:data.index(b'\0', name)].decode()
        _, fdes = eh_frame_records(data, self.secs)
        self.fdes = sorted((f['start'], f['end']) for f in fdes)
        text = [s for s in self.secs if s['name'] == '.text']
        require(len(text) == 1, 'no single .text section')
        self.text = text[0]

    def offset(self, va, size=1):
        hits = [s for s in self.secs if s['type'] != 8 and s['address'] and
                s['address'] <= va and va + size <= s['address'] + s['size']]
        require(len(hits) == 1, f'VA {va:#x}+{size} is not in exactly one file-backed section')
        return hits[0]['offset'] + va - hits[0]['address']

    def read(self, va, size):
        off = self.offset(va, size)
        return self.data[off:off + size]

    def fde(self, start):
        hits = [f for f in self.fdes if f[0] == start]
        require(len(hits) == 1, f'{start:#x} is not exactly one FDE start')
        return hits[0]

    def target(self, va, length):
        if length == 2:
            return va + 2 + struct.unpack('<b', self.read(va + 1, 1))[0]
        return va + length + struct.unpack('<i', self.read(va + length - 4, 4))[0]


def windows(img):
    out = {}
    for name, (fde, va, hexs) in WINDOWS.items():
        raw = bytes.fromhex(hexs)
        start, end = img.fde(fde)
        require(start <= va and va + len(raw) <= end, f'{name} window {va:#x} is outside FDE {fde:#x}')
        require(img.read(va, len(raw)) == raw, f'{name} at {va:#x}: bytes changed')
        out[name] = [hex(va), hex(va + len(raw))]
    return out


def windowed(va, size):
    return any(va >= w[1] and va + size <= w[1] + len(bytes.fromhex(w[2])) for w in WINDOWS.values())


def window_of(va):
    hits = [n for n, w in WINDOWS.items() if w[1] <= va < w[1] + len(bytes.fromhex(w[2]))]
    require(len(hits) == 1, f'{va:#x} is not in exactly one window')
    return hits[0]


def check_operands(img):
    out = {}
    for va, (n, want) in OPERANDS.items():
        require(windowed(va, n), f'operand at {va:#x} is outside every window')
        got = img.target(va, n)
        require(got == want, f'operand at {va:#x} goes to {got:#x}, not {want:#x}')
        out[hex(va)] = hex(got)
    return out


def op(img, va, prefix, target):
    """An instruction `prefix` + rel32/disp32 (or rel8 for a 1-byte prefix) at `va` whose target must be `target`."""
    raw = bytes.fromhex(prefix)
    n = 2 if len(raw) == 1 and raw[0] in range(0x70, 0x80) or raw == b'\xeb' else len(raw) + 4
    require(windowed(va, n), f'instruction at {va:#x} is outside every window')
    require(img.read(va, len(raw)) == raw, f'instruction at {va:#x} is not {prefix}')
    require(OPERANDS.get(va) == (n, target), f'operand table at {va:#x} does not pin {target:#x}')
    got = img.target(va, n)
    require(got == target, f'operand at {va:#x} goes to {got:#x}, not {target:#x}')


def exact(img, va, hexs):
    raw = bytes.fromhex(hexs)
    require(windowed(va, len(raw)), f'instruction at {va:#x} is outside every window')
    require(img.read(va, len(raw)) == raw, f'instruction at {va:#x} is not {hexs}')


def text_at(img, va, n):
    s = img.read(va, n)
    require(all(0x20 <= c < 0x7f for c in s), f'{va:#x} is not text')
    return s


def location(img, va):
    ptr = img.relative.get(va)
    require(ptr is not None, f'Location {va:#x} has no RELATIVE file pointer')
    n, line, col = struct.unpack('<QII', img.read(va + 8, 16))
    require(0 < n < 256, f'Location {va:#x} has length {n}')
    return text_at(img, ptr, n), line, col


def check_strings(img):
    out = {}
    for va, path, key in ((TM_PATH_VA, TM_PATH, 'task.rs'), (TR_PATH_VA, TR_PATH, 'traffic_recorder.rs'),
                          (LU_PATH_VA, LU_PATH, 'lu.rs')):
        require(img.read(va, len(path)) == path, f'path string at {va:#x} changed')
        out[key] = path.decode()
    found = {}
    for va in (TM_PATH_VA, TR_PATH_VA):
        path = TM_PATH if va == TM_PATH_VA else TR_PATH
        for slot, addend in img.relative.items():
            if addend == va:
                got, line, col = location(img, slot)
                require(got == path, f'Location {slot:#x} has a different length or path')
                found[slot] = (line, col)
    want = {**TM_LOCATIONS, **TR_LOCATIONS}
    require(found == want, f'task.rs / traffic_recorder.rs Locations are {sorted((hex(k), v) for k, v in found.items())}')
    loc, line, col = LU_RESUME_LOCATION
    require(location(img, loc) == (LU_PATH, line, col), f'lu.rs Location {loc:#x} changed')
    va, msg, std_loc = INSTANT_ADD
    require(img.read(va, len(msg)) == msg, 'instant-add overflow message changed')
    got = location(img, std_loc)
    require(got[0].endswith(b'/library/std/src/time.rs') and got[1:] == (429, 33),
            f'std time.rs Location {std_loc:#x} changed')
    vt = tuple(img.relative.get(WAKER_VTABLE + 8 * i) for i in range(4))
    require(vt == VTABLE, f'waker vtable {WAKER_VTABLE:#x} is {[hex(x or 0) for x in vt]}')
    require(img.glob_dat.get(CLOCK_GETTIME_SLOT) == 'clock_gettime', 'clock_gettime GOT slot changed')
    out['locations'] = {hex(k): f'{v[0]}:{v[1]}' for k, v in sorted(want.items())}
    out['waker_vtable'] = dict(zip(('clone', 'wake', 'wake_by_ref', 'drop'), map(hex, VTABLE)))
    return out


def census(img):
    """References to the Locations and the vtable, and the e8 callers of the functions."""
    t = img.text
    raw = img.read(t['address'], t['size'])
    base = t['address']
    wanted = set(TM_LOCATIONS) | set(TR_LOCATIONS) | {WAKER_VTABLE}
    refs = {w: [] for w in wanted}
    for m in re.finditer(rb'[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]', raw):
        p = m.start() + 1
        if p < 3 or p + 4 > len(raw):
            continue
        tgt = base + p + 4 + struct.unpack_from('<i', raw, p)[0]
        if tgt in refs and raw[p - 3] in (0x48, 0x4c) and raw[p - 2] == 0x8d:
            refs[tgt].append(base + p - 3)
    fns = (POLL_TRAFFIC, POLL_LU, ON_WAKE, LU_FUTURE, TRAFFIC_FUTURE, LZ4_FUTURE)
    calls = {f: [] for f in fns}
    for m in re.finditer(rb'\xe8', raw):
        p = m.start()
        if p + 5 > len(raw):
            continue
        tgt = base + p + 5 + struct.unpack_from('<i', raw, p + 1)[0]
        if tgt in calls:
            calls[tgt].append(base + p)

    def fde_of(va):
        hits = [f[0] for f in img.fdes if f[0] <= va < f[1]]
        require(len(hits) == 1, f'{va:#x} is not in exactly one FDE')
        return hits[0]

    require(len(refs[IDLE_SUB_LOCATION]) == 6,
            f'task.rs:2483:23 at {IDLE_SUB_LOCATION:#x} has {len(refs[IDLE_SUB_LOCATION])} references')
    idle_fdes = sorted({fde_of(r) for r in refs[IDLE_SUB_LOCATION]})
    copies = sorted({fde_of(r) for loc, (line, _) in TM_LOCATIONS.items() if line == 2483 for r in refs[loc]})
    require(idle_fdes == [0x3d12780, 0x3d12f20, 0x3d133b0, 0x3d13840, POLL_TRAFFIC, POLL_LU],
            f'FDEs using {IDLE_SUB_LOCATION:#x} are {[hex(f) for f in idle_fdes]}')
    require(len(copies) == 66, f'{len(copies)} FDEs reference a task.rs:2483:23 Location')
    require(refs[0x5718be8] == [0x3d13fdd] and refs[0x57193f8] == [0x3d216ca],
            'traffic_recorder.rs:62:47 references changed')
    vt_fdes = sorted(fde_of(r) for r in refs[WAKER_VTABLE])
    require(vt_fdes == sorted([CLONE_WAKER] + idle_fdes), f'vtable {WAKER_VTABLE:#x} users are {[hex(f) for f in vt_fdes]}')
    held = sorted(hex(s) for s, a in img.relative.items() if a in fns)
    require(held == [hex(WAKER_VTABLE + 0x10)], f'RELATIVE slots holding the functions are {held}')
    want = {POLL_TRAFFIC: [0x3cfd416], POLL_LU: [0x3cfddf4], ON_WAKE: [],
            LU_FUTURE: [0x3d136cc, 0x3d146ac], TRAFFIC_FUTURE: [0x3d13b5c], LZ4_FUTURE: [0x3d1323c]}
    require(calls == want, f'direct callers are {({hex(k): [hex(x) for x in v] for k, v in calls.items()})}')
    return dict(task_rs_2483_fdes=len(copies), idle_location_fdes=[hex(f) for f in idle_fdes],
                waker_vtable_fdes=[hex(f) for f in vt_fdes],
                traffic_recorder_location_refs={hex(k): [hex(r) for r in refs[k]] for k in sorted(TR_LOCATIONS)},
                direct_callers={hex(k): [hex(x) for x in v] for k, v in calls.items()})


def check_poll_traffic(img):
    """0x3d13cd0, Instrumented at rbx: Arc<State> +0, future +8, idled_at +0x160, did_poll_once +0x168."""
    exact(img, 0x3d13ce1, '4889fb')                                   # rbx = self
    exact(img, 0x3d13ce7, 'bf01000000')                               # edi = 1 (CLOCK_MONOTONIC)
    op(img, 0x3d13cec, 'e8', INSTANT_NOW)                             # poll_start
    exact(img, 0x3d13cf6, '4c8b2b')                                   # r13 = State ArcInner
    exact(img, 0x3d13cf9, '498b4538')                                 # instrumented_at.secs
    exact(img, 0x3d13d02, '418b4540')                                 # instrumented_at.nanos
    # first poll: did_poll_once, first_poll_delay, first_poll_count
    exact(img, 0x3d13d0a, '80bb6801000000')                           # cmp did_poll_once, 0
    op(img, 0x3d13d14, '75', 0x3d13d92)                               # polled before: skip
    exact(img, 0x3d13d16, 'c6836801000001')                           # did_poll_once = true
    op(img, 0x3d13d47, 'e8', SUB_TIMESPEC)                            # poll_start - instrumented_at
    exact(img, 0x3d13d4c, 'b800ca9a3b')                               # secs * 1e9
    exact(img, 0x3d13d51, '48f7642428')
    exact(img, 0x3d13d63, '48f7da')                                   # high word -> u64::MAX
    exact(img, 0x3d13d6b, '4819d2')
    exact(img, 0x3d13d6e, '4809c2')
    exact(img, 0x3d13d71, '807c242000')                               # Err -> 0
    exact(img, 0x3d13d76, '480f45d1')
    exact(img, 0x3d13d7a, '498b4530')                                 # metrics = State.metrics
    exact(img, 0x3d13d7e, 'f048015058')                               # total_first_poll_delay_ns +=
    exact(img, 0x3d13d8a, 'f048ff4018')                               # first_poll_count += 1
    # woke_at = State.woke_at.swap(0)
    exact(img, 0x3d13d92, '31c9')
    exact(img, 0x3d13d94, '48874810')
    # idle: idled_at < woke_at
    exact(img, 0x3d13d98, '48398b60010000')                           # cmp idled_at, woke_at
    op(img, 0x3d13d9f, '73', 0x3d13dc5)                               # idled_at >= woke_at: no idle
    exact(img, 0x3d13da5, 'f048ff4020')                               # total_idled_count += 1
    exact(img, 0x3d13dad, '482b8360010000')                           # woke_at - idled_at
    op(img, 0x3d13db4, '0f82', 0x3d14010)                             # checked: task.rs:2483:23
    exact(img, 0x3d13dbe, 'f048014260')                               # total_idle_duration_ns +=
    exact(img, 0x3d13dc5, '4885c9')                                   # woke_at == 0: not scheduled
    op(img, 0x3d13dc8, '0f84', 0x3d13ed1)
    # scheduled: woke_instant = instrumented_at + from_nanos(woke_at)
    exact(img, 0x3d13dd2, 'f048ff4028')                               # total_scheduled_count += 1
    exact(img, 0x3d13dda, '48c1e809')                                 # woke_at / 1e9
    exact(img, 0x3d13dde, '49bc535a9ba02fb84400')
    exact(img, 0x3d13deb, '48c1ea0b')
    exact(img, 0x3d13df4, '4801d0')                                   # secs + instrumented_at.secs
    op(img, 0x3d13df7, '0f80', 0x3d13fea)                             # overflow when adding duration to instant
    exact(img, 0x3d13dfd, '4869d200ca9a3b')                           # remainder nanos
    exact(img, 0x3d13e04, '4829d1')
    exact(img, 0x3d13e07, '034c2404')                                 # + instrumented_at.nanos
    exact(img, 0x3d13e0b, '81f900ca9a3b')
    exact(img, 0x3d13e13, '48ffc0')                                   # carry
    op(img, 0x3d13e16, '0f80', 0x3d13fea)
    exact(img, 0x3d13e1c, '81c1003665c4')
    exact(img, 0x3d13e22, '4c89742408')                               # lhs = poll_start
    exact(img, 0x3d13e2b, '4889442468')                               # rhs = woke_instant
    op(img, 0x3d13e43, 'e8', SUB_TIMESPEC)
    exact(img, 0x3d13e72, '480f45ce')                                 # Err -> 0 (saturating)
    exact(img, 0x3d13e79, '48c1e809')                                 # scheduled = from_nanos(scheduled_ns)
    exact(img, 0x3d13e80, '48c1ea0b')
    exact(img, 0x3d13e88, '483b90a0000000')                           # cmp secs, long_delay_threshold.secs
    op(img, 0x3d13e8f, '75', 0x3d13eb2)
    exact(img, 0x3d13e9e, '39b0a8000000')                             # cmp long_delay_threshold.nanos, nanos
    op(img, 0x3d13ea4, '76', 0x3d13eb4)                               # threshold <= scheduled: long
    exact(img, 0x3d13ea6, 'ba80000000')                               # short: total_short_delay_duration_ns
    exact(img, 0x3d13eab, 'be48000000')                               # short: total_short_delay_count
    op(img, 0x3d13eb2, '72', 0x3d13ea6)                               # secs below threshold: short
    exact(img, 0x3d13eb4, 'ba88000000')                               # long: total_long_delay_duration_ns
    exact(img, 0x3d13eb9, 'be40000000')                               # long: total_long_delay_count
    exact(img, 0x3d13ebe, 'f048ff0430')                               # count += 1
    exact(img, 0x3d13ec3, 'f048010c10')                               # duration += scheduled_ns
    exact(img, 0x3d13ecc, 'f048014868')                               # total_scheduled_duration_ns +=
    # AtomicWaker::register, then the instrumented waker (State ArcInner + 0x10, vtable 0x5718a40)
    exact(img, 0x3d13ed1, '488b2b')
    exact(img, 0x3d13ed4, 'b901000000')                               # REGISTERING
    exact(img, 0x3d13edb, 'f0480fb14d28')
    exact(img, 0x3d13f84, '4883c010')
    op(img, 0x3d13f88, '488d0d', WAKER_VTABLE)
    exact(img, 0x3d13fba, 'bf01000000')
    op(img, 0x3d13fbf, 'e8', INSTANT_NOW)                             # inner_poll_start
    exact(img, 0x3d13fc4, '4989c7')
    exact(img, 0x3d13fc7, '89d5')
    # the inlined traffic_recorder.rs:62:47 future: state byte +0x158, 30.0 s sleep at +0xb8
    exact(img, 0x3d13fc9, '0fb68358010000')
    op(img, 0x3d13fdd, '488d3d', 0x5718be8)                           # resumed in a bad state
    op(img, 0x3d14039, 'e8', SLEEP_POLL)
    exact(img, 0x3d1403e, '84c0')
    op(img, 0x3d14040, '0f85', 0x3d14148)                             # sleep pending: Pending
    exact(img, 0x3d1412b, '48b80000000000003e40')                     # 30.0
    exact(img, 0x3d14135, '488983b8000000')
    op(img, 0x3d14143, 'e9', 0x3d1402d)                               # loop: poll the sleep again
    # Pending: idled_at = inner_poll_end - instrumented_at; poll time against slow_poll_threshold
    exact(img, 0x3d14148, 'c6835801000003')                           # future state = 3 (suspended)
    op(img, 0x3d14154, 'e8', INSTANT_NOW)                             # inner_poll_end
    exact(img, 0x3d1416d, '4889442408')                               # rhs = instrumented_at
    op(img, 0x3d14189, 'e8', SUB_TIMESPEC)
    exact(img, 0x3d141bc, '490f45cf')
    exact(img, 0x3d141c0, '48898b60010000')                           # idled_at =
    exact(img, 0x3d141a3, '4c89fe')                                   # rhs = inner_poll_start
    exact(img, 0x3d141d1, '4889742408')
    exact(img, 0x3d141d6, '896c2410')
    op(img, 0x3d141e9, 'e8', SUB_TIMESPEC)
    exact(img, 0x3d14208, '483b8190000000')                           # cmp secs, slow_poll_threshold.secs
    op(img, 0x3d1420f, '75', 0x3d14226)
    exact(img, 0x3d14211, '443bb998000000')                           # cmp nanos, slow_poll_threshold.nanos
    op(img, 0x3d14218, '73', 0x3d14228)                               # nanos >= threshold: slow
    exact(img, 0x3d1421a, 'be70000000')                               # fast: total_fast_poll_duration_ns
    exact(img, 0x3d1421f, 'bf30000000')                               # fast: total_fast_poll_count
    op(img, 0x3d14226, '72', 0x3d1421a)                               # secs below threshold: fast
    exact(img, 0x3d14228, 'be78000000')                               # slow: total_slow_poll_duration
    exact(img, 0x3d1422d, 'bf38000000')                               # slow: total_slow_poll_count
    exact(img, 0x3d1424f, 'f048ff0439')
    exact(img, 0x3d14254, 'f048010431')
    exact(img, 0x3d14259, 'b001')                                     # return Poll::Pending
    exact(img, 0x3d1426c, 'c3')                                       # the only ret in the FDE
    # panics
    op(img, 0x3d13fea, '488d3d', INSTANT_ADD[0])
    op(img, 0x3d13ff1, '488d15', INSTANT_ADD[2])
    op(img, 0x3d13ffd, 'ff15', PANIC_SLOT)
    op(img, 0x3d14010, '488d3d', IDLE_SUB_LOCATION)
    op(img, 0x3d14017, 'ff15', SUB_OVERFLOW_SLOT)
    return dict(COPIES['poll_traffic'], fde=hex(POLL_TRAFFIC), future='inlined traffic_recorder.rs:62:47 loop',
                returns='Poll::Pending only', idled_at=hex(0x160), did_poll_once=hex(0x168))


def check_poll_lu(img):
    """0x3d14390, Instrumented at rbx: future +0, Arc<State> +0xd8, idled_at +0xe0, did_poll_once +0xe8."""
    op(img, 0x3d143ac, 'e8', INSTANT_NOW)
    exact(img, 0x3d143b7, '488babd8000000')                           # rbp = State ArcInner
    exact(img, 0x3d143be, '488b4538')
    exact(img, 0x3d143c7, '8b4540')
    exact(img, 0x3d143ce, '80bbe800000000')                           # did_poll_once
    op(img, 0x3d143d8, '0f85', 0x3d14463)
    exact(img, 0x3d143de, 'c683e800000001')
    op(img, 0x3d14410, 'e8', SUB_TIMESPEC)
    exact(img, 0x3d14447, 'f048015058')                               # total_first_poll_delay_ns +=
    exact(img, 0x3d14457, 'f048ff4018')                               # first_poll_count += 1
    exact(img, 0x3d14465, '48874810')                                 # woke_at swap
    exact(img, 0x3d14469, '48398be0000000')                           # cmp idled_at, woke_at
    op(img, 0x3d14470, '73', 0x3d14496)
    exact(img, 0x3d14476, 'f048ff4020')                               # total_idled_count
    exact(img, 0x3d1447e, '482b83e0000000')
    op(img, 0x3d14485, '0f82', 0x3d147fc)
    exact(img, 0x3d1448f, 'f048014260')                               # total_idle_duration_ns
    op(img, 0x3d14499, '0f84', 0x3d145a3)
    exact(img, 0x3d144a3, 'f048ff4028')                               # total_scheduled_count
    exact(img, 0x3d144af, '49bd535a9ba02fb84400')
    op(img, 0x3d144c8, '0f80', 0x3d147d6)
    op(img, 0x3d14515, 'e8', SUB_TIMESPEC)
    exact(img, 0x3d14544, '480f45ce')
    exact(img, 0x3d1455a, '483b90a0000000')                           # long_delay_threshold.secs
    op(img, 0x3d14561, '75', 0x3d14584)
    exact(img, 0x3d14570, '39b0a8000000')                             # long_delay_threshold.nanos
    op(img, 0x3d14576, '76', 0x3d14586)
    exact(img, 0x3d14578, 'ba80000000')
    exact(img, 0x3d1457d, 'be48000000')
    op(img, 0x3d14584, '72', 0x3d14578)
    exact(img, 0x3d14586, 'ba88000000')
    exact(img, 0x3d1458b, 'be40000000')
    exact(img, 0x3d14590, 'f048ff0430')
    exact(img, 0x3d14595, 'f048010c10')
    exact(img, 0x3d1459e, 'f048014868')                               # total_scheduled_duration_ns
    exact(img, 0x3d145b1, 'f0490fb14d28')                             # AtomicWaker::register
    exact(img, 0x3d14664, '4883c010')
    op(img, 0x3d14668, '488d0d', WAKER_VTABLE)
    op(img, 0x3d14699, 'e8', INSTANT_NOW)                             # inner_poll_start
    exact(img, 0x3d146a9, '4889df')                                   # rdi = future at +0
    op(img, 0x3d146ac, 'e8', LU_FUTURE)
    exact(img, 0x3d146b1, '8844240b')                                 # keep the Poll byte
    op(img, 0x3d146ba, 'e8', INSTANT_NOW)                             # inner_poll_end
    op(img, 0x3d146ef, 'e8', SUB_TIMESPEC)
    exact(img, 0x3d14722, '48898be0000000')                           # idled_at =
    op(img, 0x3d1474c, 'e8', SUB_TIMESPEC)
    exact(img, 0x3d1476f, '483b8190000000')                           # slow_poll_threshold.secs
    op(img, 0x3d14776, '75', 0x3d1478c)
    exact(img, 0x3d14778, '3ba998000000')                             # slow_poll_threshold.nanos
    op(img, 0x3d1477e, '73', 0x3d1478e)
    exact(img, 0x3d14780, 'be70000000')
    exact(img, 0x3d14785, 'bf30000000')
    op(img, 0x3d1478c, '72', 0x3d14780)
    exact(img, 0x3d1478e, 'be78000000')
    exact(img, 0x3d14793, 'bf38000000')
    exact(img, 0x3d147b5, 'f048ff0439')
    exact(img, 0x3d147ba, 'f048010431')
    exact(img, 0x3d147bf, '0fb644240b')                               # return the inner Poll
    exact(img, 0x3d147d5, 'c3')
    op(img, 0x3d147d6, '488d3d', INSTANT_ADD[0])
    op(img, 0x3d147dd, '488d15', INSTANT_ADD[2])
    op(img, 0x3d147fc, '488d3d', IDLE_SUB_LOCATION)
    op(img, 0x3d14803, 'ff15', SUB_OVERFLOW_SLOT)
    op(img, 0x3d21571, '488d3d', LU_RESUME_LOCATION[0])               # the future is lu.rs:199:21
    op(img, 0x3d216ca, '488d3d', 0x57193f8)                           # 0x3d21670 is traffic_recorder.rs:62:47
    return dict(COPIES['poll_lu'], fde=hex(POLL_LU), future=f'{LU_FUTURE:#x} (base/src/lu.rs:199:21)',
                returns='the inner Poll', idled_at=hex(0xe0), did_poll_once=hex(0xe8))


def check_wakers(img):
    """State::on_wake (wake_by_ref), wake by value, drop, Instant::now and Timespec::sub_timespec."""
    exact(img, 0x3d0a2e5, '4889fb')                                   # rbx = State (ArcInner + 0x10)
    exact(img, 0x3d0a2e8, 'bf01000000')
    op(img, 0x3d0a2ed, 'e8', INSTANT_NOW)
    exact(img, 0x3d0a2f2, '488b4b28')                                 # instrumented_at = State+0x28
    exact(img, 0x3d0a2f6, '8b7330')
    op(img, 0x3d0a31a, 'e8', SUB_TIMESPEC)                            # elapsed()
    exact(img, 0x3d0a33e, '480f45c8')                                 # saturating
    exact(img, 0x3d0a342, '480f45d0')
    exact(img, 0x3d0a346, '4885d2')                                   # does not fit u64: return
    op(img, 0x3d0a349, '75', 0x3d0a352)
    exact(img, 0x3d0a34b, '31c0')
    exact(img, 0x3d0a34d, 'f0480fb10b')                               # woke_at.compare_exchange(0, ns)
    exact(img, 0x3d0a363, '4883c902')                                 # AtomicWaker::wake: state |= WAKING
    exact(img, 0x3d0a367, 'f0480fb14b18')
    exact(img, 0x3d0a37a, '488b4308')
    exact(img, 0x3d0a382, '48c7430800000000')
    exact(img, 0x3d0a38a, 'f048836318fd')
    exact(img, 0x3d0a39a, 'ff6008')                                   # waker.wake()
    exact(img, 0x3d0a2d0, '4883c7f0')                                 # wake: back to the ArcInner
    exact(img, 0x3d0a2b9, 'f048ff4ff0')                               # drop: strong count -= 1
    exact(img, 0x4ee3809, '488d75e0')
    op(img, 0x4ee380d, 'ff15', CLOCK_GETTIME_SLOT)
    exact(img, 0x4ee381c, '4881fa00ca9a3b')
    exact(img, 0x4ee374f, '4139f8')                                   # nanos >= other.nanos
    exact(img, 0x4ee3759, '4839ce')                                   # secs >= other.secs
    exact(img, 0x4ee3760, '450f44d1')
    exact(img, 0x4ee37a5, '48c70300000000')                           # Ok
    op(img, 0x4ee37bd, 'e8', SUB_TIMESPEC)                            # Err(other - self)
    exact(img, 0x4ee37cd, '4883f001')
    return dict(on_wake=hex(ON_WAKE), woke_at='State+0 (ArcInner+0x10)', instrumented_at='State+0x28',
                atomic_waker_state='State+0x18')


# ---- models -------------------------------------------------------------------------------------------------

U64 = (1 << 64) - 1


def sub(a, b):
    """`Instant - Instant` on (secs, nanos): saturating at zero, as the cmov after every sub_timespec."""
    if a < b:
        return (0, 0)
    secs, nanos = a[0] - b[0], a[1] - b[1]
    if nanos < 0:
        secs, nanos = secs - 1, nanos + NS
    return (secs, nanos)


def as_ns(d):
    return min(d[0] * NS + d[1], U64)


def from_ns(n):
    q = (n >> 9) * NS_MAGIC >> 75
    return (q, n - q * NS)


def add(i, d):
    secs, nanos = i[0] + d[0], i[1] + d[1]
    if nanos >= NS:
        secs, nanos = secs + 1, nanos - NS
    if secs >= 1 << 63:
        raise OverflowError(INSTANT_ADD[1].decode())
    return (secs, nanos)


def instrument_poll(*, instrumented_at, woke_at, idled_at, did_poll_once, poll_start, inner_start, inner_end,
                    slow_poll_threshold, long_delay_threshold):
    """One `instrument_poll` that returns Pending: RawMetrics additions by field name, and the new idled_at."""
    m = {}

    def bump(field, n):
        m[field] = m.get(field, 0) + n

    if not did_poll_once:
        bump('total_first_poll_delay_ns', as_ns(sub(poll_start, instrumented_at)))
        bump('first_poll_count', 1)
    if idled_at < woke_at:
        bump('total_idled_count', 1)
        bump('total_idle_duration_ns', woke_at - idled_at)
    if woke_at > 0:
        bump('total_scheduled_count', 1)
        scheduled_ns = as_ns(sub(poll_start, add(instrumented_at, from_ns(woke_at))))
        long = from_ns(scheduled_ns) >= long_delay_threshold
        bump('total_long_delay_count' if long else 'total_short_delay_count', 1)
        bump('total_long_delay_duration_ns' if long else 'total_short_delay_duration_ns', scheduled_ns)
        bump('total_scheduled_duration_ns', scheduled_ns)
    new_idled_at = as_ns(sub(inner_end, instrumented_at))
    poll = sub(inner_end, inner_start)
    slow = poll >= slow_poll_threshold
    bump('total_slow_poll_count' if slow else 'total_fast_poll_count', 1)
    bump('total_slow_poll_duration' if slow else 'total_fast_poll_duration_ns', as_ns(poll))
    return m, new_idled_at


def on_wake(instrumented_at, now, woke_at):
    """`State::on_wake`: only the first wake after a poll sets woke_at."""
    elapsed = sub(now, instrumented_at)
    ns = elapsed[0] * NS + elapsed[1]
    if ns > U64:
        return woke_at
    return ns if woke_at == 0 else woke_at


def byte_reading(drained):
    """Closed PR 585: the drained word is a byte count, and that count is what +0x80 / +0x88 accumulate."""
    return drained


def analyse(data):
    img = Image(data)
    wins = windows(img)
    ops = check_operands(img)
    return dict(
        target=TARGET,
        strings=check_strings(img),
        census=census(img),
        poll_traffic=check_poll_traffic(img),
        poll_lu=check_poll_lu(img),
        wakers=check_wakers(img),
        raw_metrics={hex(k): v for k, v in FIELDS.items()},
        state={hex(k): v for k, v in STATE.items()},
        windows=wins,
        operands=ops,
    )


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument('--json', action='store_true')
    a = p.parse_args(argv)
    identity = next(i for i in json.loads((ROOT / 'provenance/artifacts.json').read_text())['files']
                    if i['path'] == TARGET)
    path = ROOT / TARGET
    check(path, identity)
    rec = dict(analyse(path.read_bytes()), target_sha256=identity['sha256'])
    if a.json:
        print(json.dumps(rec, indent=2, sort_keys=True))
        return 0
    print(f'{POLL_TRAFFIC:#x}, {POLL_LU:#x}: tokio-metrics 0.3.1 instrument_poll; '
          f'{rec["census"]["task_rs_2483_fdes"]} FDEs reference task.rs:2483:23')
    print(f'{ON_WAKE:#x}: State::on_wake; the xchg(0) word is woke_at (ns since instrumented_at), not bytes')
    return 0


if __name__ == '__main__':
    sys.exit(main())
