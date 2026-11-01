#!/usr/bin/env python3
"""Static node #94 `node/stream_msg.rs` codecs: a MessagePack encoder and two bincode enum decoders.

Question: what do the `node/stream_msg.rs` seeds encode and decode?  The
can1357 lead (`node/stream_msg.rs`) says `0x466e3f0` is a "bincode decode +
`Result::unwrap` for a 24-byte payload" wrapped in an `Arc`, that
`0x4674820` decodes `AbciStreamGreeting` (six tags) and `0x466e750` decodes
`GreetingHash` (three tags), and that `GreetingHash` tag 1 holds a nested
hash "with 32- or 80-byte arms".

In the binary:

* `0x466e3f0` encodes, it does not decode.  It starts an empty `Vec<u8>`,
  passes it with a serializer config whose struct-map byte is 1 to
  `0x459d4f0`, and on the Ok value moves the Vec into a 0x28-byte
  `ArcInner` (strong 1, weak 1).  Otherwise it calls `Result::unwrap`'s
  failure at `stream_msg.rs:43:48`, the only `stream_msg.rs` Location.  It is
  reached only through the RELATIVE slot `0x5776ac8`, called once, from
  `0x474bfa0`.
* `0x459d4f0` writes MessagePack: a 2-entry map (or array when the config
  byte is 0) with `abci_block` -> a 6-entry map of `time`,
  `signed_action_bundles`, `round`, `parent_round`, `hardfork`, `proposer`,
  then `resps` (tag 2 at `+0x58` takes the None path).  The header and str
  writers emit the MessagePack fix / 8 / 16 / 32 markers.
* `0x4674820` reads a varint u32 tag and dispatches six tags through a jump
  table, as the lead says; a larger tag returns error kind 5 with the type
  name `AbciStreamGreeting` and the range 0..=5.
* `0x466e750` handles three tags.  Tag 1 calls `0x49784e0`, which returns a
  `Result`: tag 0 with 80 bytes, or tag 1 with a 32-byte error.  The 32-byte
  shape becomes `GreetingHash`'s own error value 3, so there is one 80-byte
  arm, not a 32-byte one.

Only the Python standard library is used.  Every fact is an exact byte window
at a fixed VA inside a parsed .eh_frame FDE; call, branch and RIP-relative
targets, the strings, the jump table, the Location, the RELATIVE slots and a
whole-`.text` census of references are decoded here.  Nothing from the binary
is executed.
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
PATH_VA = 0x1ec0f1
PATH = b'/home/ubuntu/hl/code_Mainnet/node/src/stream_msg.rs'
UNWRAP_LOCATION = (0x572d6f0, 43, 48)
UNWRAP_MESSAGE = (0x6f7dd2, b'called `Result::unwrap()` on an `Err` value')
ENCODE_ARC, SERIALIZE, PROPOSER = 0x466e3f0, 0x459d4f0, 0x4670030
GREETING, GREETING_HASH, CONSENSUS_HASH = 0x4674820, 0x466e750, 0x49784e0
CALLER = 0x474bfa0
ENCODE_SLOT = 0x5776ac8
SLOTS = {ENCODE_SLOT: ENCODE_ARC, 0x576e048: 0x157aa10, 0x576dfd8: 0x54c06b0, 0x5773120: 0x29ed380}
UNWRAP_SLOT, ALLOC_SLOT, HEX_SLOT = 0x576e048, 0x576dfd8, 0x5773120
MAP_HEADER, ARRAY_HEADER, STR_HEADER, MARKER_BYTE = 0x4ae9900, 0x4aea420, 0x4aeb170, 0x4aed5a0
U32_TAG, U64 = 0x466bc10, 0x466bd10
OK_STATUS = 0x12
ENCODE_OK = 0x8000000000000004
# (name lea, name, mov edx length, value call, target) in write order
FIELDS = [
    ('abci_block', 0x459d56c, 0x6f73f2, 0x459d573, None, None),
    ('time', 0x459d5db, 0x209d88, 0x459d5e2, 0x459d619, 0x43e3470),
    ('signed_action_bundles', 0x459d638, 0x6f73cc, 0x459d63f, 0x459d661, 0x4407ea0),
    ('round', 0x459d67b, 0x6f73e1, 0x459d682, 0x459d6a5, 0x4aeca50),
    ('parent_round', 0x459d6c0, 0x6f73e6, 0x459d6c7, 0x459d6ea, 0x4aeca50),
    ('hardfork', 0x459d705, 0x20a618, 0x459d70c, 0x459d72f, 0x4c13760),
    ('proposer', 0x4670051, 0x20af88, 0x467005b, 0x459d74a, PROPOSER),
    ('resps', 0x459d760, 0x6f73fc, 0x459d767, None, None),
]
TYPE_NAMES = {GREETING: (0x6f878b, b'AbciStreamGreeting', 0x203580, 5),
              GREETING_HASH: (0x6f877f, b'GreetingHash', 0x209410, 2)}
JUMP_TABLE = 0x6f700c
# AbciStreamGreeting tag -> (jump target, discriminant stored at [rbx])
GREETING_ARMS = {0: (0x467486c, None), 1: (0x4674966, 3), 2: (0x4674954, 4), 3: (0x467495d, 5),
                 4: (0x467494b, 6), 5: (0x46749db, 7)}
GREETING_ERR = 8
GREETING_HASH_ERR = 3

WINDOWS = {
    'encode_arc': (0x466e3f0, 0x466e3f0,
        '41574156534883ec404889fe48c704240000000048c74424080100000048c7442410000000004889e04889442430c744'
        '243800040001c644243c00488d7c2418488d542430e8b6f0f2ff488b5c241848b804000000000000804839c375554c8b'
        '34244c8b7c2408488b5c2410bf28000000ff1571fb0f014885c0742548c7000100000048c74008010000004c8970104c'
        '897818488958204883c4405b415e415fc3bf08000000be28000000ff157ffb0f01eb544c8b7424204c8b7c2428488b34'
        '244885f6740d488b7c240831d2ff154dfb0f0148895c24184c897424204c897c2428488d3df99808fc488d0df8cc0b01'
        '4c8d0509f20b01488d542418be2b000000ff1551fb0f010f0b'),
    'abci_block_serialize': (0x459d4f0, 0x459d4f0,
        '4157415641554154534883ec304989d64989f74889fb49bc0000000000000080807a0b007432488d7c24084c89f6ba02'
        '000000e8d8c35400488b4424084883f8027432488b4c24104c89234889430848894b10e96a020000488d7c24084c89f6'
        'ba02000000e8c6ce5400488b4424084883f80275ce41807e0b007447488d357f9e15fcba0a0000004c89f7e8f0db5400'
        '4883f8020f851d02000041807e0b007422488d7c24084c89f6ba06000000e85dc35400488b4424084883f8027426e9e0'
        '010000488d7c24084c89f6ba06000000e85bce5400488b4424084883f8020f85bf01000041807e0b01751e488d35a6c7'
        'c6fbba040000004c89f7e881db54004883f8020f85ae010000498d47384889442420488d4424204889442428488d7c24'
        '08488d5424284c89f6e8525ee4ff488b4c24084d8d6c24044c39e90f856901000041807e0b01751e488d358d9d15fcba'
        '150000004c89f7e824db54004883f8020f8551010000488d7c24084c89f64c89fae83aa8e6ff488b4c24084c39e90f85'
        '2601000041807e0b01751e488d355f9d15fcba050000004c89f7e8e1da54004883f8020f850e010000498b5718488d7c'
        '24084c89f6e8a6f35400488b4424084883f8020f85da00000041807e0b01751e488d351f9d15fcba0c0000004c89f7e8'
        '9cda54004883f8020f85c9000000498b5720488d7c24084c89f6e861f35400488b4424084883f8020f85950000004180'
        '7e0b01751e488d350ccfc6fbba080000004c89f7e857da54004883f8020f8584000000498d7728488d7c24084c89f2e8'
        '2c606700488b4c24084c39e9755c498d5744488d7c24084c89f6e8e1280d00488b4c24084c39e9754141807e0b00741a'
        '488d35959c15fcba050000004c89f7e8fcd954004883f80275654983c75841803f02753f488d7c24084c89f6e83f7ee9'
        'ffeb40488b542410eb0d488b442410488b5424184989cc4c892348894308488953104889d84883c4305b415c415d415e'
        '415fc3488d7c24084c89fe4c89f2e81d0300004c396c240875144c892bebd34c8964240848894424104889542418488b'
        '44241848894310488b442408488903'),
    'proposer_serialize': (0x4670030, 0x4670030,
        '415741564154534883ec384989f64889fb49bf0000000000000080807e0b007423488d3530afb9fb4989d4ba08000000'
        '4c89f7e808b147004889d14c89e24883f802754e0f57c00f1144241a0f294424100f2904244889e7be2a000000b91400'
        '00004531c0ff15853010014c89f74889c6e8cab047004883f80275094983c7044c893beb1848894308488953104c893b'
        'eb0b4c893b4889430848894b104883c4385b415c415e415fc3'),
    'marker_byte': (0x4aed5a0, 0x4aed5a0,
        '89f80fb6c88d9140ffffff83fa207301c381f98f0000007e1b81f990000000742281f9a000000075084080e61f4080ce'
        'a089f0c385c974f94080e60f4080ce8089f0c34080e60f4080ce9089f0c3'),
    'map_header': (0x4ae9900, 0x4ae9900,
        '554157415641554154534883ec2881fa000001000f92c034df83fa100fb6c0bd800000000f43e8'),
    'array_header': (0x4aea420, 0x4aea420,
        '554157415641554154534883ec2881fa000001000f92c034dd83fa100fb6c0bd900000000f43e8'),
    'str_header': (0x4aeb170, 0x4aeb170,
        '554157415641554154534883ec284889742420488b1f83fa20731440b5a04c8b234c8b6b104d39ec753fe90a03000081'
        'fa00010000731440b5d94c8b234c8b6b104d39ec7523e9ee02000081fa00000100400f92c54080f5db4c8b234c8b6b10'
        '4d39ec0f84d0020000440fb6f548895424180fb6f24489f7e8b3230000'),
    'indirect_call': (0x474bfa0, 0x474cbfb,
        '488dbc24f0030000ff15bf9e0201'),
    'greeting_decode': (0x4674820, 0x4674820,
        '554157415641554154534881ec880000004989f64889fb488d7c2408e8cf73ffff0fb64424083c120f85b40000008b44'
        '240c4883f8050f878b010000488d0da92708fc486304814801c8ffe0488d153d73ffff488d7c24084c89f6e8b051f1ff'
        '0fb64424083c120f85840100004c8b7c24104c8b6424184c8b6c2420488d7c24084c89f6e86774ffff0fb64424083c12'
        '0f85e6010000488b6c2410488d7c24084c89f6e8889effff488b4424080f104424100f294424600f104424200f294424'
        '704883f8030f85f70100000f284424600f284c24700f114b180f114308e9bd0100000fb64c240b884b0b0fb74c240966'
        '894b098b4c240c488b542420488953200f104424100f114310884308894b0c48c703080000004889d84881c488000000'
        '5b415c415d415e415f5dc348c70306000000ebe248c70304000000ebd948c70305000000ebd0488d7c24084c89f6e89d'
        '73ffff0fb64424083c120f85b90000004c8b7c2410488d7c24084c89f6e87e73ffff0fb64424083c120f85c00000004c'
        '8b642410488d7c24084c89f6e85f73ffff0fb64424083c120f85a1000000488b44241048c703030000004c8963084889'
        '43104c897b18e95bffffff48c70307000000e94fffffffc643080589430c488d05963d08fc4889431048c74318120000'
        '00488d0578ebb8fb48894320e91effffff8b4c24098b54240c89530c894b090f10442410488b4c24200f11431048894b'
        '20884308e9f6feffff8b4c24098b54240c89530c894b09488b4c24100f104424180f114318884308b810000000eb348b'
        '4c24098b54240c89542463894c24600f10442410488b4c24208b5424608b74246389730c8953098843080f114310b820'
        '00000048890c03e993feffff8b4c24098b54240c89530c894b09488b4c24100f104424180f11431888430848894b1048'
        'c703080000004d85ff0f8467feffff4c89e74c89fe31d2ff1533950f01e954feffff0f104424300f104c24400f105424'
        '500f1153480f114b380f1143280f284424600f284c24700f114b180f1143084c897b584c8963604c896b684889034889'
        '6b70e90ffeffff'),
    'greeting_hash_decode': (0x466e750, 0x466e750,
        '55415741564154534881ec500100004989f64889fb488d7c2478e8a1d4ffff0fb64424783c12754d8b44247c85c00f84'
        'cd00000083f8010f848200000083f8020f8504010000488d7c24784c89f6e8fdd21e000fb64424783c120f8574010000'
        '488b84248000000048c7030200000048894308eb3a0fb64c247b884b0b0fb74c247966894b098b4c247c488b94249000'
        '0000488953200f108424800000000f114310884308894b0c48c703030000004881c4500100005b415c415e415f5dc34c'
        '8d7c24784c89ff4c89f6e8c19c3000488d4308807c2478000f8496000000410f104708410f104f180f298c24f0000000'
        '0f298424e00000000f1148100f1100eba741833e017521498b5620b0024883fadf0f87f9020000498b76084883c22049'
        '8956204839f27718498b46184883f81f0f87cc000000b9200000004829c131c048894c2438e951020000c64308058943'
        '0c488d05d79e08fc4889431048c743180c000000488d0555abb9fb48894320e934ffffff410f1047480f298424200100'
        '00410f104f08410f105718410f105f28410f1067380f29a424100100000f299c24000100000f299424f00000000f298c'
        '24e00000000f1140400f1160300f1158200f1150100f110848c70301000000e9dbfeffff8b4c24798b54247c89530c89'
        '4b09488b8c24800000000f108424880000000f11431888430848894b10e9a6feffff498b4e10488d51204883c0e04989'
        '5610498946180fb6290fb7410566894424348b410189442430440fb679078b410b8944244b8b4108894424484c8b610f'
        '488b41170fb6491f888c24d800000048898424d0000000488d7c24784c89f6e8bc0230000fb64424783c120f85d20000'
        '00488b8424900000000f108424800000000f294424604889442470488943380f1143288b442430894424080fb74c2434'
        '66894c240c8b5424488b74244b895424388974243b488b9424d000000048895424200fb69424d8000000885424284c89'
        '64243f66894c24048904244c89642457488b44243848894424500fb644242888442418488b442420488944241040886b'
        '088b04248943090fb74424046689430d44887b0f488b442450488b4c24574889431048894b17488b4424104889431f0f'
        'b644241888432748c70300000000e96cfdffff0fb74c247d66894c240c8b4c2479894c24080fb64c247f488b94249000'
        '00000f108424800000000f294424604889542470488b542460488b742467488974243f48895424380fb6542477885424'
        '28488b54246f48895424208b5424088914240fb754240c6689542404488b542438488b74243f48895424504889742457'
        '488b54242048895424100fb6542428885424188843088b04248943090fb74424046689430d884b0f488b442450488b4c'
        '24574889431048894b17488b4424104889431f0fb6442418884327e998fcffff48894c2438eb84'),
    'consensus_hash_decode': (0x49784e0, 0x49784e0,
        '41574156534881ec800100004989f64889fb488d7c2408e8b43ccfff807c240801752e0f104424100f104c24200f1184'
        '24570100000f118c24670100000f114b180f11430848c70301000000e9920200000f104424090f104c24190f29842450'
        '0100000f298c2460010000488d7c24084c89f6e8186effff0fb64424083c120f850d010000488b4424200f104424100f'
        '118424c700000048898424d70000000f298424a000000048898424b0000000488d7c24084c89f6e8946affff0fb64424'
        '083c120f8532010000488d8424c7000000488b4c24200f104424100f118424e700000048898c24f70000000f11842438'
        '01000048898c24480100000f288424500100000f288c24600100000f298c24100100000f298424000100000f10000f29'
        '842420010000488b40104889842430010000488b84244001000048894348488b842448010000488943500f2884240001'
        '00000f288c24100100000f28942420010000488b84243001000048894338488b842438010000488943400f1153280f11'
        '4b180f11430848c70300000000e9510100000f104424090f104c24180f114c247f0f294424700f284424700f29442450'
        '0f1044247f0f1144245f0f284424500f298424c00000000f1044245f0f118424cf0000000f108424cf0000000f114318'
        '0f288424c00000000f11430988430848c70301000000e9e80000000f104424090f104c24180f114c247f0f294424700f'
        '284424700f294424500f1044247f0f1144245f0f284424500f298424e00000000f1044245f0f118424ef0000000f1084'
        '24ef0000000f1143180f288424e00000000f11430988430848c70301000000488b8c24a00000004885c9743d488b9424'
        'a8000000488b8424b000000048c74424100000000048894c2418488954242048c74424300000000048894c2438488954'
        '2440b901000000eb0431c931c048894c240848894c242848894424484c8d7424704c8d7c2408662e0f1f840000000000'
        '4c89f74c89fee8855dfdff48837c24700075ed4889d84881c4800100005b415e415fc3'),
}

OPERANDS = {
    0x459d514: (2, 0x459d548),  # abci_block_serialize: je
    0x459d523: (5, 0x4ae9900),  # abci_block_serialize: call
    0x459d531: (2, 0x459d565),  # abci_block_serialize: je
    0x459d543: (5, 0x459d7b2),  # abci_block_serialize: jmp
    0x459d555: (5, 0x4aea420),  # abci_block_serialize: call
    0x459d563: (2, 0x459d533),  # abci_block_serialize: jne
    0x459d56a: (2, 0x459d5b3),  # abci_block_serialize: je
    0x459d56c: (7, 0x6f73f2),  # abci_block_serialize: lea
    0x459d57b: (5, 0x4aeb170),  # abci_block_serialize: call
    0x459d584: (6, 0x459d7a7),  # abci_block_serialize: jne
    0x459d58f: (2, 0x459d5b3),  # abci_block_serialize: je
    0x459d59e: (5, 0x4ae9900),  # abci_block_serialize: call
    0x459d5ac: (2, 0x459d5d4),  # abci_block_serialize: je
    0x459d5ae: (5, 0x459d793),  # abci_block_serialize: jmp
    0x459d5c0: (5, 0x4aea420),  # abci_block_serialize: call
    0x459d5ce: (6, 0x459d793),  # abci_block_serialize: jne
    0x459d5d9: (2, 0x459d5f9),  # abci_block_serialize: jne
    0x459d5db: (7, 0x209d88),  # abci_block_serialize: lea
    0x459d5ea: (5, 0x4aeb170),  # abci_block_serialize: call
    0x459d5f3: (6, 0x459d7a7),  # abci_block_serialize: jne
    0x459d619: (5, 0x43e3470),  # abci_block_serialize: call
    0x459d62b: (6, 0x459d79a),  # abci_block_serialize: jne
    0x459d636: (2, 0x459d656),  # abci_block_serialize: jne
    0x459d638: (7, 0x6f73cc),  # abci_block_serialize: lea
    0x459d647: (5, 0x4aeb170),  # abci_block_serialize: call
    0x459d650: (6, 0x459d7a7),  # abci_block_serialize: jne
    0x459d661: (5, 0x4407ea0),  # abci_block_serialize: call
    0x459d66e: (6, 0x459d79a),  # abci_block_serialize: jne
    0x459d679: (2, 0x459d699),  # abci_block_serialize: jne
    0x459d67b: (7, 0x6f73e1),  # abci_block_serialize: lea
    0x459d68a: (5, 0x4aeb170),  # abci_block_serialize: call
    0x459d693: (6, 0x459d7a7),  # abci_block_serialize: jne
    0x459d6a5: (5, 0x4aeca50),  # abci_block_serialize: call
    0x459d6b3: (6, 0x459d793),  # abci_block_serialize: jne
    0x459d6be: (2, 0x459d6de),  # abci_block_serialize: jne
    0x459d6c0: (7, 0x6f73e6),  # abci_block_serialize: lea
    0x459d6cf: (5, 0x4aeb170),  # abci_block_serialize: call
    0x459d6d8: (6, 0x459d7a7),  # abci_block_serialize: jne
    0x459d6ea: (5, 0x4aeca50),  # abci_block_serialize: call
    0x459d6f8: (6, 0x459d793),  # abci_block_serialize: jne
    0x459d703: (2, 0x459d723),  # abci_block_serialize: jne
    0x459d705: (7, 0x20a618),  # abci_block_serialize: lea
    0x459d714: (5, 0x4aeb170),  # abci_block_serialize: call
    0x459d71d: (6, 0x459d7a7),  # abci_block_serialize: jne
    0x459d72f: (5, 0x4c13760),  # abci_block_serialize: call
    0x459d73c: (2, 0x459d79a),  # abci_block_serialize: jne
    0x459d74a: (5, 0x4670030),  # abci_block_serialize: call
    0x459d757: (2, 0x459d79a),  # abci_block_serialize: jne
    0x459d75e: (2, 0x459d77a),  # abci_block_serialize: je
    0x459d760: (7, 0x6f73fc),  # abci_block_serialize: lea
    0x459d76f: (5, 0x4aeb170),  # abci_block_serialize: call
    0x459d778: (2, 0x459d7df),  # abci_block_serialize: jne
    0x459d782: (2, 0x459d7c3),  # abci_block_serialize: jne
    0x459d78c: (5, 0x44355d0),  # abci_block_serialize: call
    0x459d791: (2, 0x459d7d3),  # abci_block_serialize: jmp
    0x459d798: (2, 0x459d7a7),  # abci_block_serialize: jmp
    0x459d7ce: (5, 0x459daf0),  # abci_block_serialize: call
    0x459d7d8: (2, 0x459d7ee),  # abci_block_serialize: jne
    0x459d7dd: (2, 0x459d7b2),  # abci_block_serialize: jmp
    0x466e435: (5, 0x459d4f0),  # encode_arc: call
    0x466e44c: (2, 0x466e4a3),  # encode_arc: jne
    0x466e461: (6, 0x576dfd8),  # encode_arc: call
    0x466e46a: (2, 0x466e491),  # encode_arc: je
    0x466e49b: (6, 0x576e020),  # encode_arc: call
    0x466e4a1: (2, 0x466e4f7),  # encode_arc: jmp
    0x466e4b4: (2, 0x466e4c3),  # encode_arc: je
    0x466e4bd: (6, 0x576e010),  # encode_arc: call
    0x466e4d2: (7, 0x6f7dd2),  # encode_arc: lea
    0x466e4d9: (7, 0x572b1d8),  # encode_arc: lea
    0x466e4e0: (7, 0x572d6f0),  # encode_arc: lea
    0x466e4f1: (6, 0x576e048),  # encode_arc: call
    0x466e76a: (5, 0x466bc10),  # greeting_hash_decode: call
    0x466e776: (2, 0x466e7c5),  # greeting_hash_decode: jne
    0x466e77e: (6, 0x466e851),  # greeting_hash_decode: je
    0x466e787: (6, 0x466e80f),  # greeting_hash_decode: je
    0x466e790: (6, 0x466e89a),  # greeting_hash_decode: jne
    0x466e79e: (5, 0x485baa0),  # greeting_hash_decode: call
    0x466e7aa: (6, 0x466e924),  # greeting_hash_decode: jne
    0x466e7c3: (2, 0x466e7ff),  # greeting_hash_decode: jmp
    0x466e81a: (5, 0x49784e0),  # greeting_hash_decode: call
    0x466e828: (6, 0x466e8c4),  # greeting_hash_decode: je
    0x466e84f: (2, 0x466e7f8),  # greeting_hash_decode: jmp
    0x466e855: (2, 0x466e878),  # greeting_hash_decode: jne
    0x466e861: (6, 0x466eb60),  # greeting_hash_decode: ja
    0x466e876: (2, 0x466e890),  # greeting_hash_decode: ja
    0x466e880: (6, 0x466e952),  # greeting_hash_decode: ja
    0x466e895: (5, 0x466eaeb),  # greeting_hash_decode: jmp
    0x466e8a1: (7, 0x6f877f),  # greeting_hash_decode: lea
    0x466e8b4: (7, 0x209410),  # greeting_hash_decode: lea
    0x466e8bf: (5, 0x466e7f8),  # greeting_hash_decode: jmp
    0x466e91f: (5, 0x466e7ff),  # greeting_hash_decode: jmp
    0x466e94d: (5, 0x466e7f8),  # greeting_hash_decode: jmp
    0x466e9af: (5, 0x496ec70),  # greeting_hash_decode: call
    0x466e9bb: (6, 0x466ea93),  # greeting_hash_decode: jne
    0x466ea8e: (5, 0x466e7ff),  # greeting_hash_decode: jmp
    0x466eb5b: (5, 0x466e7f8),  # greeting_hash_decode: jmp
    0x466eb65: (2, 0x466eaeb),  # greeting_hash_decode: jmp
    0x467004f: (2, 0x4670074),  # proposer_serialize: je
    0x4670051: (7, 0x20af88),  # proposer_serialize: lea
    0x4670063: (5, 0x4aeb170),  # proposer_serialize: call
    0x4670072: (2, 0x46700c2),  # proposer_serialize: jne
    0x4670095: (6, 0x5773120),  # proposer_serialize: call
    0x46700a1: (5, 0x4aeb170),  # proposer_serialize: call
    0x46700aa: (2, 0x46700b5),  # proposer_serialize: jne
    0x46700b3: (2, 0x46700cd),  # proposer_serialize: jmp
    0x46700c0: (2, 0x46700cd),  # proposer_serialize: jmp
    0x467483c: (5, 0x466bc10),  # greeting_decode: call
    0x4674848: (6, 0x4674902),  # greeting_decode: jne
    0x4674856: (6, 0x46749e7),  # greeting_decode: ja
    0x467485c: (7, 0x6f700c),  # greeting_decode: lea
    0x467486c: (7, 0x466bbb0),  # greeting_decode: lea
    0x467487b: (5, 0x4589a30),  # greeting_decode: call
    0x4674887: (6, 0x4674a11),  # greeting_decode: jne
    0x46748a4: (5, 0x466bd10),  # greeting_decode: call
    0x46748b0: (6, 0x4674a9c),  # greeting_decode: jne
    0x46748c3: (5, 0x466e750),  # greeting_decode: call
    0x46748e5: (6, 0x4674ae2),  # greeting_decode: jne
    0x46748fd: (5, 0x4674abf),  # greeting_decode: jmp
    0x4674952: (2, 0x4674936),  # greeting_decode: jmp
    0x467495b: (2, 0x4674936),  # greeting_decode: jmp
    0x4674964: (2, 0x4674936),  # greeting_decode: jmp
    0x467496e: (5, 0x466bd10),  # greeting_decode: call
    0x467497a: (6, 0x4674a39),  # greeting_decode: jne
    0x467498d: (5, 0x466bd10),  # greeting_decode: call
    0x4674999: (6, 0x4674a5f),  # greeting_decode: jne
    0x46749ac: (5, 0x466bd10),  # greeting_decode: call
    0x46749b8: (6, 0x4674a5f),  # greeting_decode: jne
    0x46749d6: (5, 0x4674936),  # greeting_decode: jmp
    0x46749e2: (5, 0x4674936),  # greeting_decode: jmp
    0x46749ee: (7, 0x6f878b),  # greeting_decode: lea
    0x4674a01: (7, 0x203580),  # greeting_decode: lea
    0x4674a0c: (5, 0x467492f),  # greeting_decode: jmp
    0x4674a34: (5, 0x467492f),  # greeting_decode: jmp
    0x4674a5d: (2, 0x4674a93),  # greeting_decode: jmp
    0x4674a97: (5, 0x467492f),  # greeting_decode: jmp
    0x4674ac9: (6, 0x4674936),  # greeting_decode: je
    0x4674ad7: (6, 0x576e010),  # greeting_decode: call
    0x4674add: (5, 0x4674936),  # greeting_decode: jmp
    0x4674b22: (5, 0x4674936),  # greeting_decode: jmp
    0x474cc03: (6, 0x5776ac8),  # indirect_call: call
    0x49784f7: (5, 0x466c1b0),  # consensus_hash_decode: call
    0x4978501: (2, 0x4978531),  # consensus_hash_decode: jne
    0x497852c: (5, 0x49787c3),  # consensus_hash_decode: jmp
    0x4978553: (5, 0x496f370),  # consensus_hash_decode: call
    0x497855f: (6, 0x4978672),  # consensus_hash_decode: jne
    0x4978597: (5, 0x496f030),  # consensus_hash_decode: call
    0x49785a3: (6, 0x49786db),  # consensus_hash_decode: jne
    0x497866d: (5, 0x49787c3),  # consensus_hash_decode: jmp
    0x49786d6: (5, 0x49787c3),  # consensus_hash_decode: jmp
    0x497874a: (2, 0x4978789),  # consensus_hash_decode: je
    0x4978787: (2, 0x497878d),  # consensus_hash_decode: jmp
    0x49787b6: (5, 0x494e540),  # consensus_hash_decode: call
    0x49787c1: (2, 0x49787b0),  # consensus_hash_decode: jne
    0x4aeb189: (2, 0x4aeb19f),  # str_header: jae
    0x4aeb198: (2, 0x4aeb1d9),  # str_header: jne
    0x4aeb19a: (5, 0x4aeb4a9),  # str_header: jmp
    0x4aeb1a5: (2, 0x4aeb1bb),  # str_header: jae
    0x4aeb1b4: (2, 0x4aeb1d9),  # str_header: jne
    0x4aeb1b6: (5, 0x4aeb4a9),  # str_header: jmp
    0x4aeb1d3: (6, 0x4aeb4a9),  # str_header: je
    0x4aeb1e8: (5, 0x4aed5a0),  # str_header: call
    0x4aed5ae: (2, 0x4aed5b1),  # marker_byte: jae
    0x4aed5b7: (2, 0x4aed5d4),  # marker_byte: jle
    0x4aed5bf: (2, 0x4aed5e3),  # marker_byte: je
    0x4aed5c7: (2, 0x4aed5d1),  # marker_byte: jne
    0x4aed5d6: (2, 0x4aed5d1),  # marker_byte: je
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
    require(img.data.count(PATH[PATH.index(b'/node/src/'):]) == 1, 'stream_msg.rs path is not unique in the file')
    require(img.read(PATH_VA, len(PATH)) == PATH, f'path string at {PATH_VA:#x} changed')
    found = {}
    for slot, addend in img.relative.items():
        if addend == PATH_VA:
            path, line, col = location(img, slot)
            require(path == PATH, f'Location {slot:#x} has a different length or path')
            found[slot] = (line, col)
    loc, line, col = UNWRAP_LOCATION
    require(found == {loc: (line, col)}, f'stream_msg.rs Locations are {sorted((hex(k), v) for k, v in found.items())}')
    va, msg = UNWRAP_MESSAGE
    require(img.read(va, len(msg)) == msg, 'unwrap message changed')
    for name, _, sva, _, _, _ in FIELDS:
        require(img.read(sva, len(name)) == name.encode(), f'field name {name} at {sva:#x} changed')
    ranges = {}
    for fn, (nva, name, rva, hi) in TYPE_NAMES.items():
        require(img.read(nva, len(name)) == name, f'type name at {nva:#x} changed')
        tag, lo, top = struct.unpack('<QII', img.read(rva, 16))
        require((tag, lo, top) == (0, 0, hi), f'allowed variants at {rva:#x} are ({tag}, {lo}, {top})')
        ranges[name.decode()] = f'{lo}..={top}'
    for slot, want in SLOTS.items():
        require(img.relative.get(slot) == want, f'slot {slot:#x} no longer holds {want:#x}')
    return dict(path=PATH.decode(), location=f'{line}:{col}', fields=[f[0] for f in FIELDS], allowed=ranges)


def census(img):
    """The Location's references, the e8 callers of the five functions, and the callers of the encoder slot."""
    t = img.text
    raw = img.read(t['address'], t['size'])
    base = t['address']
    loc_refs = []
    for m in re.finditer(rb'[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]', raw):
        p = m.start() + 1
        if p < 3 or p + 4 > len(raw):
            continue
        if base + p + 4 + struct.unpack_from('<i', raw, p)[0] == UNWRAP_LOCATION[0]:
            loc_refs.append(base + p - 3)
    fns = (ENCODE_ARC, SERIALIZE, GREETING, GREETING_HASH, CONSENSUS_HASH)
    calls = {f: [] for f in fns}
    for m in re.finditer(rb'\xe8', raw):
        p = m.start()
        if p + 5 > len(raw):
            continue
        tgt = base + p + 5 + struct.unpack_from('<i', raw, p + 1)[0]
        if tgt in calls:
            calls[tgt].append(base + p)
    slot_calls = [base + m.start() for m in re.finditer(rb'\xff\x15', raw)
                  if m.start() + 6 <= len(raw) and
                  base + m.start() + 6 + struct.unpack_from('<i', raw, m.start() + 2)[0] == ENCODE_SLOT]
    held = sorted(hex(s) for s, a in img.relative.items() if a in fns)
    require(held == [hex(ENCODE_SLOT)], f'RELATIVE slots holding the functions are {held}')
    require(loc_refs == [0x466e4e0], f'stream_msg.rs:43:48 references are {[hex(r) for r in loc_refs]}')
    require(slot_calls == [0x474cc03], f'calls through {ENCODE_SLOT:#x} are {[hex(c) for c in slot_calls]}')
    want = {ENCODE_ARC: [], SERIALIZE: [0x466e435], GREETING: [0x471b967, 0x471baa9, 0x471bcbe],
            GREETING_HASH: [0x46748c3], CONSENSUS_HASH: [0x466e81a]}
    require(calls == want, f'direct callers are {({hex(k): [hex(x) for x in v] for k, v in calls.items()})}')
    return dict(location_refs=[hex(r) for r in loc_refs], encode_slot_calls=[hex(c) for c in slot_calls],
                direct_callers={hex(k): [hex(x) for x in v] for k, v in calls.items()})


def check_encode_arc(img):
    exact(img, 0x466e3f9, '4889fe')                                      # rsi = value
    exact(img, 0x466e3fc, '48c7042400000000')                                      # Vec cap 0
    exact(img, 0x466e404, '48c744240801000000')                                      # Vec ptr 1 (dangling)
    exact(img, 0x466e40d, '48c744241000000000')                                      # Vec len 0
    exact(img, 0x466e416, '4889e0')
    exact(img, 0x466e419, '4889442430')                                      # config +0 = &Vec
    exact(img, 0x466e41e, 'c744243800040001')                                      # config +8..+0xc: 00 04 00 01
    exact(img, 0x466e426, 'c644243c00')
    exact(img, 0x466e430, '488d542430')                                      # rdx = config
    op(img, 0x466e435, 'e8', SERIALIZE)
    exact(img, 0x466e43f, '48b80400000000000080')                                      # Ok value
    op(img, 0x466e44c, '75', 0x466e4a3)
    exact(img, 0x466e45c, 'bf28000000')                                      # 0x28 bytes
    op(img, 0x466e461, 'ff15', ALLOC_SLOT)
    exact(img, 0x466e46c, '48c70001000000')                                      # strong 1
    exact(img, 0x466e473, '48c7400801000000')                                      # weak 1
    exact(img, 0x466e47b, '4c897010')
    exact(img, 0x466e47f, '4c897818')
    exact(img, 0x466e483, '48895820')                                      # the Vec
    op(img, 0x466e4d2, '488d3d', UNWRAP_MESSAGE[0])
    op(img, 0x466e4e0, '4c8d05', UNWRAP_LOCATION[0])
    exact(img, 0x466e4ec, 'be2b000000')                                      # message length 0x2b
    op(img, 0x466e4f1, 'ff15', UNWRAP_SLOT)
    exact(img, 0x466e4f7, '0f0b')
    op(img, 0x474cc03, 'ff15', ENCODE_SLOT)
    exact(img, 0x474cbfb, '488dbc24f0030000')
    return dict(vec_new='cap 0, ptr 1, len 0', config_bytes='+8..+0xc = 00 04 00 01 00 (struct-map byte +0xb = 1)',
                ok=hex(ENCODE_OK), arc_inner='0x28: strong 1, weak 1, Vec', unwrap='stream_msg.rs:43:48',
                caller=f'{CALLER:#x} at 0x474cc03 through {ENCODE_SLOT:#x}')


def check_serialize(img):
    exact(img, 0x459d4fd, '4989d6')                                      # r14 = config
    exact(img, 0x459d500, '4989f7')                                      # r15 = value
    exact(img, 0x459d510, '807a0b00')                                      # struct-map byte
    op(img, 0x459d514, '74', 0x459d548)
    exact(img, 0x459d51e, 'ba02000000')                                      # 2 entries
    op(img, 0x459d523, 'e8', MAP_HEADER)
    exact(img, 0x459d550, 'ba02000000')
    op(img, 0x459d555, 'e8', ARRAY_HEADER)
    exact(img, 0x459d599, 'ba06000000')                                      # 6 entries
    op(img, 0x459d59e, 'e8', MAP_HEADER)
    exact(img, 0x459d5bb, 'ba06000000')
    op(img, 0x459d5c0, 'e8', ARRAY_HEADER)
    order = []
    for name, lea, sva, ln, call, tgt in FIELDS:
        op(img, lea, '488d35', sva)
        exact(img, ln, 'ba' + struct.pack('<I', len(name)).hex())
        if call:
            op(img, call, 'e8', tgt)
        order.append(name)
    for va in (0x459d578, 0x459d5e7, 0x459d644, 0x459d687, 0x459d6cc, 0x459d711, 0x459d76c):
        op(img, va + 3, 'e8', STR_HEADER)
    exact(img, 0x459d65e, '4c89fa')                                 # signed_action_bundles = +0x0
    exact(img, 0x459d699, '498b5718')                                      # round = +0x18
    exact(img, 0x459d6de, '498b5720')                                      # parent_round = +0x20
    exact(img, 0x459d5f9, '498d4738')                                      # time = +0x38
    exact(img, 0x459d723, '498d7728')                                      # hardfork = +0x28
    exact(img, 0x459d73e, '498d5744')                                      # proposer = +0x44
    exact(img, 0x459d77a, '4983c758')
    exact(img, 0x459d77e, '41803f02')                                      # resps tag 2
    op(img, 0x459d782, '75', 0x459d7c3)
    op(img, 0x459d78c, 'e8', 0x44355d0)
    op(img, 0x459d7ce, 'e8', 0x459daf0)
    exact(img, 0x4670041, '49bf0000000000000080')
    exact(img, 0x467004b, '807e0b00')
    op(img, 0x467004f, '74', 0x4670074)
    exact(img, 0x4670088, 'be2a000000')                                      # 42-byte buffer
    exact(img, 0x467008d, 'b914000000')                                      # 20 input bytes
    op(img, 0x4670095, 'ff15', HEX_SLOT)
    op(img, 0x46700a1, 'e8', STR_HEADER)
    return dict(outer='2 entries: abci_block, resps', abci_block='6 entries', order=order,
                offsets={'signed_action_bundles': '+0x0', 'round': '+0x18', 'parent_round': '+0x20', 'hardfork': '+0x28',
                         'time': '+0x38', 'proposer': '+0x44 (20 bytes, written as a 42-byte str)',
                         'resps': '+0x58 (tag 2: 0x44355d0, else 0x459daf0)'},
                names='written only when the struct-map byte is set; array headers otherwise')


def check_markers(img):
    exact(img, MARKER_BYTE, '89f80fb6c88d9140ffffff83fa207301c381f98f0000007e1b81f990000000742281f9a000000075084080e61f4080cea089f0c385c974f94080e60f4080ce8089f0c34080e60f4080ce9089f0c3')
    exact(img, MAP_HEADER + 0xe, '81fa000001000f92c034df83fa100fb6c0bd800000000f43e8')
    exact(img, ARRAY_HEADER + 0xe, '81fa000001000f92c034dd83fa100fb6c0bd900000000f43e8')
    exact(img, STR_HEADER + 0x16, '83fa20731440b5a04c8b234c8b6b104d39ec753fe90a03000081fa00010000731440b5d94c8b234c8b6b104d39ec7523e9ee02000081fa00000100400f92c54080f5db')
    return dict(map='< 16: 0x80 | n; < 0x10000: 0xde; else 0xdf', array='< 16: 0x90 | n; < 0x10000: 0xdc; else 0xdd',
                str='< 32: 0xa0 | n; < 0x100: 0xd9; < 0x10000: 0xda; else 0xdb')


def check_greeting(img):
    op(img, 0x467483c, 'e8', U32_TAG)
    exact(img, 0x4674846, '3c12')
    op(img, 0x4674848, '0f85', 0x4674902)
    exact(img, 0x4674852, '4883f805')                                      # tag <= 5
    op(img, 0x4674856, '0f87', 0x46749e7)
    op(img, 0x467485c, '488d0d', JUMP_TABLE)
    arms = {}
    for tag, (tgt, disc) in GREETING_ARMS.items():
        got = JUMP_TABLE + struct.unpack('<i', img.read(JUMP_TABLE + 4 * tag, 4))[0]
        require(got == tgt, f'jump table entry {tag} goes to {got:#x}, not {tgt:#x}')
        arms[tag] = hex(got)
    op(img, 0x467486c, '488d15', 0x466bbb0)                         # element decoder
    op(img, 0x467487b, 'e8', 0x4589a30)
    op(img, 0x46748a4, 'e8', U64)
    op(img, 0x46748c3, 'e8', GREETING_HASH)
    exact(img, 0x46748e1, '4883f803')                                      # GreetingHash error 3
    op(img, 0x46748e5, '0f85', 0x4674ae2)
    for va in (0x467496e, 0x467498d, 0x46749ac):
        op(img, va, 'e8', U64)
    for tgt, disc in list(GREETING_ARMS.values())[1:]:
        va = 0x46749c3 if disc == 3 else tgt
        exact(img, va, '48c703' + struct.pack('<I', disc).hex())
    exact(img, 0x46749e7, 'c6430805')                                      # error kind 5
    exact(img, 0x46749eb, '89430c')                                      # found tag
    nva, name, rva, _ = TYPE_NAMES[GREETING]
    op(img, 0x46749ee, '488d05', nva)
    exact(img, 0x46749f9, '48c74318' + struct.pack('<I', len(name)).hex())
    op(img, 0x4674a01, '488d05', rva)
    exact(img, 0x467492f, '48c703' + struct.pack('<I', GREETING_ERR).hex())
    return dict(tag_decoder=hex(U32_TAG), ok_status=OK_STATUS, jump_table=hex(JUMP_TABLE), arms=arms,
                tag0=f'0x4589a30 (element 0x466bbb0), {U64:#x}, {GREETING_HASH:#x}', tag1='three u64 (0x466bd10)',
                discriminants={str(t): d for t, (_, d) in GREETING_ARMS.items() if d}, error=GREETING_ERR,
                bad_tag='error kind 5, found tag, AbciStreamGreeting, 0..=5')


def check_greeting_hash(img):
    op(img, 0x466e76a, 'e8', U32_TAG)
    exact(img, 0x466e774, '3c12')
    exact(img, 0x466e77c, '85c0')
    op(img, 0x466e77e, '0f84', 0x466e851)                           # tag 0
    exact(img, 0x466e784, '83f801')
    op(img, 0x466e787, '0f84', 0x466e80f)                           # tag 1
    exact(img, 0x466e78d, '83f802')
    op(img, 0x466e790, '0f85', 0x466e89a)                           # tag > 2
    op(img, 0x466e79e, 'e8', 0x485baa0)                             # tag 2
    exact(img, 0x466e7b8, '48c70302000000')
    exact(img, 0x466e7bf, '48894308')
    exact(img, 0x466e7f8, '48c703' + struct.pack('<I', GREETING_HASH_ERR).hex())
    # tag 0: 32 raw bytes, limit counted first, then the bytes left
    exact(img, 0x466e851, '41833e01')                                      # limit enabled
    exact(img, 0x466e85b, 'b002')                                      # error kind 2
    exact(img, 0x466e86b, '4883c220')                                      # counter += 32
    exact(img, 0x466e873, '4839f2')
    op(img, 0x466e876, '77', 0x466e890)                             # over the limit
    exact(img, 0x466e87c, '4883f81f')                                      # remaining > 31
    op(img, 0x466e880, '0f87', 0x466e952)
    exact(img, 0x466e886, 'b920000000')
    exact(img, 0x466e88b, '4829c1')                                      # additional = 32 - remaining
    exact(img, 0x466e88e, '31c0')                                      # error kind 0
    exact(img, 0x466e956, '488d5120')                                      # cursor += 32
    exact(img, 0x466e95a, '4883c0e0')                                      # remaining -= 32
    op(img, 0x466e9af, 'e8', 0x496ec70)
    exact(img, 0x466e9db, '48894338')
    exact(img, 0x466e9df, '0f114328')                                      # 24 bytes at +0x28
    exact(img, 0x466ea87, '48c70300000000')                                      # discriminant 0
    # tag 1: 0x49784e0 Result
    op(img, 0x466e81a, 'e8', CONSENSUS_HASH)
    exact(img, 0x466e823, '807c247800')
    op(img, 0x466e828, '0f84', 0x466e8c4)                           # Ok
    op(img, 0x466e84f, 'eb', 0x466e7f8)                             # Err -> 3
    exact(img, 0x466e905, '0f114040')                                      # 80 bytes: +0x40 of rbx+8
    exact(img, 0x466e918, '48c70301000000')                                      # discriminant 1
    # bad tag
    exact(img, 0x466e89a, 'c6430805')
    exact(img, 0x466e89e, '89430c')
    nva, name, rva, _ = TYPE_NAMES[GREETING_HASH]
    op(img, 0x466e8a1, '488d05', nva)
    exact(img, 0x466e8ac, '48c74318' + struct.pack('<I', len(name)).hex())
    op(img, 0x466e8b4, '488d05', rva)
    op(img, 0x466e8bf, 'e9', 0x466e7f8)
    return dict(tag0='32 raw bytes, then 0x496ec70 (24 bytes at +0x28); discriminant 0',
                tag0_errors='limit enabled: counter + 32 over the limit -> kind 2; fewer than 32 left -> kind 0 with 32 - remaining',
                tag1='0x49784e0: tag 0 -> 80 bytes, discriminant 1; otherwise its 32-byte error -> 3',
                tag2='0x485baa0 u64 at +0x8; discriminant 2', error=GREETING_HASH_ERR,
                bad_tag='error kind 5, found tag, GreetingHash, 0..=2')


def check_consensus_hash(img):
    op(img, 0x49784f7, 'e8', 0x466c1b0)
    exact(img, 0x49784fc, '807c240801')
    op(img, 0x4978501, '75', 0x4978531)
    exact(img, 0x4978521, '0f114308')
    exact(img, 0x4978525, '48c70301000000')                                      # Err: 1 + 32 bytes
    op(img, 0x4978553, 'e8', 0x496f370)
    exact(img, 0x497855d, '3c12')
    op(img, 0x497855f, '0f85', 0x4978672)
    op(img, 0x4978597, 'e8', 0x496f030)
    exact(img, 0x49785a1, '3c12')
    op(img, 0x49785a3, '0f85', 0x49786db)
    exact(img, 0x4978626, '48894350')                                      # last qword at +0x50
    exact(img, 0x4978666, '48c70300000000')                                      # Ok: 0
    exact(img, 0x49786cf, '48c70301000000')
    exact(img, 0x4978738, '48c70301000000')
    return dict(parts='0x466c1b0 32 bytes (its tag 1 is an error), 0x496f370 24 bytes, 0x496f030 24 bytes', ok='tag 0, 80 bytes at +0x8..+0x58',
                err='tag 1, 32 bytes at +0x8')


# ---- models -------------------------------------------------------------------------------------------------


def header(kind, n):
    base = {'map': (0x80, 16, 0xde, 0xdf), 'array': (0x90, 16, 0xdc, 0xdd)}
    if kind == 'str':
        if n < 32:
            return bytes([0xa0 | n])
        if n < 0x100:
            return bytes([0xd9, n])
        return bytes([0xda]) + n.to_bytes(2, 'big') if n < 0x10000 else bytes([0xdb]) + n.to_bytes(4, 'big')
    fix, lim, m16, m32 = base[kind]
    if n < lim:
        return bytes([fix | n])
    return bytes([m16]) + n.to_bytes(2, 'big') if n < 0x10000 else bytes([m32]) + n.to_bytes(4, 'big')


def skeleton(named=True):
    """The headers and names 0x459d4f0 writes around the field values (values elided as '<name>')."""
    kind = 'map' if named else 'array'
    out = [header(kind, 2)]
    if named:
        out += [header('str', 10), b'abci_block']
    out.append(header(kind, 6))
    for name, *_ in FIELDS[1:7]:
        if named:
            out += [header('str', len(name)), name.encode()]
        out.append(f'<{name}>'.encode())
    if named:
        out += [header('str', 5), b'resps']
    out.append(b'<resps>')
    return b''.join(out)


def greeting(tag):
    if tag > 5:
        return ('error', 5, tag, 'AbciStreamGreeting')
    return ('Full', None) if tag == 0 else ('discriminant', GREETING_ARMS[tag][1])


def greeting_hash(tag, inner_ok=True):
    if tag > 2:
        return ('error', 5, tag, 'GreetingHash')
    if tag == 1:
        return ('arm', 1, 80) if inner_ok else ('error', 'inner 32-byte error', GREETING_HASH_ERR)
    return ('arm', tag)


def read_hash32(remaining, limit=None, counted=0):
    if limit is not None and counted + 32 > limit:
        return ('error', 2)
    if remaining < 32:
        return ('error', 0, 32 - remaining)
    return ('ok', 32)


def lead_greeting_hash(tag, inner_len):
    """The lead: tag 1 is Compact([u8; 32]) or Full([u8; 80])."""
    if tag == 1:
        return ('arm', 'Compact' if inner_len == 32 else 'Full', inner_len)
    return ('arm', tag)


def analyse(data):
    img = Image(data)
    wins = windows(img)
    ops = check_operands(img)
    return dict(
        target=TARGET,
        strings=check_strings(img),
        census=census(img),
        encode_arc=check_encode_arc(img),
        abci_block_serialize=check_serialize(img),
        msgpack_markers=check_markers(img),
        abci_stream_greeting=check_greeting(img),
        greeting_hash=check_greeting_hash(img),
        consensus_hash=check_consensus_hash(img),
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
    print(f'{ENCODE_ARC:#x}: MessagePack encode of {{abci_block: 6 fields, resps}} into Arc<Vec<u8>>, unwrap at '
          f'stream_msg.rs:{UNWRAP_LOCATION[1]}:{UNWRAP_LOCATION[2]}')
    print(f'{GREETING:#x}: AbciStreamGreeting tags 0..=5; {GREETING_HASH:#x}: GreetingHash tags 0..=2, tag 1 one 80-byte arm')
    return 0


if __name__ == '__main__':
    sys.exit(main())
