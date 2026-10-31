#!/usr/bin/env python3
"""Static node #94 local abci_state startup gates, checked from authenticated bytes.

Question: when node #94 starts from a local abci_state, which constants decide
(a) that the local height is "too far behind" or "from stale hardfork",
(b) the `tolerance` value it logs, and (c) the abci_state freshness check
behind `use an abci state within ... seconds`?  Where does the can1357 lead
(`node/local_abci_state.rs`, `node/startup.rs`) differ?

Only the Python standard library is used.  Every fact is an exact byte window
at a fixed VA inside a parsed .eh_frame FDE; immediates, RIP-relative LEA /
movsd / call targets, rustc format templates and the panic Location are
decoded here, with relocations taken from .rela.dyn.  Nothing from the binary
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
STARTUP_FDE = 0x22689f0
FRESH_FDE = 0x2271d00
PANIC_SHIM = 0x157b810
ORCHESTRATOR_FDE = 0x22ae8a0
POLL_TABLE = 0x3d5f10
FUTURE_STRINGS = {0x2271f1e: b'check_reachability_firewall_ips', 0x22722c1: b'failed to load firewall ips'}

WINDOWS = {
    'gate': (STARTUP_FDE, 0x226ab0a,
             '488b8424d8000000' '483de0b1ffff' '7238' '4889c2' '4881c2204e0000' '48c7c1ffffffff' '480f43ca'
             '488db388000000' '483b8c24d0000000' '772a' '4989ee' '41bd1e000000' '488d2d62ce16fe' 'eb36'
             '488d88204e0000' '488db388000000' '483b8c24d0000000' '76d6' '483b8424c8000000' '0f8339020000'
             '4989ee' '41bd23000000' '488d2d07ce16fe'),
    'peer_loop_head': (STARTUP_FDE, 0x2269c63, '488b83303c0000488b00488983c8490000488d8bda49000048898c24a8000000c683da49000000488d8b703c000048898c24b000000048c783b04900000000000048c783c049000000000000488b08488b4108488b4910488d0c894801c1488983703c000048898b783c00004839c80f8442070000488d480548898b703c00008b08898bd04900000fb640048883d4490000488d7c2420ff15a04b5003'),
    'query_log': (STARTUP_FDE, 0x2269d00, '4c8db3d04900008b4424208984246c010000c784246001000001000000488b44242448898424640100004c89a42420010000488d05c9d616fe488984244001000048c78424480100001600000048c78424500100000800000048c7842458010000000000008b05fd0d510385c00f8509120000660f1005dd0d5103660f118424007700004c89742408488d84242001000048898424103c0000488d054013710048898424183c0000488d84240077000048898424203c0000488d05d1d5f4ff48898424283c0000488d44240848898424303c0000488d058509440048898424383c0000488d3d823bf7fd488db424103c0000ff15704b5003'),
    'query_call': (STARTUP_FDE, 0x2269e1a, '8b8bd04900000fb693d4490000488d83d54900008893d9490000898bd5490000488983803c0000488d8ba849000048898c2480000000c683a84900000048c783883c000002000000488983a03c0000c683a049000000488db3883c0000488dbc2420010000488b9424c0000000e8941c00004c8bbc2420010000498d4424414939c70f841a0a0000488bac24280100004c8bac2430010000488b84243801000048894424184c8ba424400100000f108424480100000f298424103c0000660f10842458010000660f298424203c0000488b84246801000048898424303c000080bba049000003753b0fb68398490000bf0801000085c0741e83f80375260fb6839249000083f8030f849a020000bf1005000085c0750d4803bc2498000000e8134bfdff'),
    'reply_dispatch': (STARTUP_FDE, 0x2269f3d, '48b800000000000000804883c0404939c70f85a602000048896c24204c896c2428488b44241848894424304c896424384883fd02757e488b842480000000c60001660f28842400770000660f288c2410770000660f29442450660f294c2460488b842420770000488944247041f6c5010f8498000000488db3b04900008b83d04900008b93d449000048c1e2204809c2488dbc2420010000488b4c24184d89e0e8ce835e0049bc0000000000000080e912040000bf1e000000ff15dc3f50034885c00f846d1100004989c6488d7c24280f1005e9d916fe0f11400e660f1005cfd916fe660f11004885ed49bf00000000000000800f84500100004883fd010f8556010000e8aa976400e961010000'),
    'no_heights_log': (STARTUP_FDE, 0x226a04b, '488d7c2420ff154a4850038b4424208984246c010000c784246001000001000000488b442424488984246401000049bc00000000000000804c89a42420010000488d0570d316fe488984244001000048c78424480100001600000048c78424500100000800000048c7842458010000000000008b05a40a510385c04c8db424200100000f85340f0000660f10057c0a5103660f11842400770000488d83d049000048894424084c89b424103c0000488d05e00f710048898424183c0000488d84240077000048898424203c0000488d0571d2f4ff48898424283c0000488d44240848898424303c0000488d052506440048898424383c0000488d3d6c1cf8fd488db424103c0000ff1510485003488bb424200100004c39e60f849a0200004885f60f8491020000488bbc242801000031d2ff158e3e5003e97c020000'),
    'query_error': (STARTUP_FDE, 0x226a1ac, '4983c72bb81e0000004889442418bd1e000000eb704c8db318450000488dbb90450000e87c48fdff4c89f7e8743afeffc683914900000048b800000000000000804883c0404939c70f845afdffff660f288424103c0000660f288c24203c0000660f29842400770000660f298c2410770000488b8424303c000048898424207700004d89ee488b842480000000c60001660f28842400770000660f288c2410770000660f29442450660f294c2460488b84242077000048894424704c89bc24103c00004889ac24183c00004c89b424203c0000488b4c241848898c24283c00004c89a424303c0000660f118424383c0000660f118c24483c000048898424583c0000488d7c2408ff15e74550038b4424088984246c010000c784246001000001000000488b44240c488984246401000049bc00000000000000804c89a42420010000488d050dd116fe488984244001000048c78424480100001600000048c78424500100000800000048c7842458010000000000008b054108510385c04c8db424200100000f85ff0b0000660f100519085103660f11442420488d83d049000048894424484c89b42400770000488d05800d71004889842408770000488d4424204889842410770000488d0514d0f4ff4889842418770000488d8424103c00004889842420770000488b05659250034889842428770000488d4424484889842430770000488d05a90344004889842438770000488d3d9141f8fd488db42400770000ff1594455003488bb424200100004c39e674154885f67410488bbc242801000031d2ff151a3c5003488dbc24103c0000e86d0bfeff488b83703c0000488b8b783c00004839c80f85bef8ffff'),
    'got_heights_log': (STARTUP_FDE, 0x226a4a2, '4c8dabb04900004c896c2408488d84242001000048898424103c0000488d051b0c710048898424183c0000488d84240077000048898424203c0000488d2daccef4ff4889ac24283c0000488d44240848898424303c0000488d05f00b440048898424383c0000488d3d32d1f7fd488db424103c0000ff154b445003488bb424200100004c39e674154885f67410488bbc242801000031d2ff15d13a5003'),
    'select_guard_loop': (STARTUP_FDE, 0x226a53f, '488b83c04900004883f8014c896c2418771b0f857b010000488b8bc8490000488b0948837910010f8566010000488b8bb0490000488b93b849000031f64885c9400f95c6480f44c14889b424103c000048c78424183c00000000000048898c24203c000048899424283c00004889b424303c000048c78424383c00000000000048898c24403c000048899424483c000048898424503c0000488dbc24103c0000e80c4f57004885c00f84730b00004885d20f846a0b00004c8b3a4c8b7208488b8424503c00004889842460010000660f108424103c0000660f108c24203c00000f109424303c00000f109c24403c00000f299c24500100000f29942440010000660f298c2430010000660f29842420010000488dbc2420010000e8924e57004885c00f94c04885d20f94c108c1754a4c8da42420010000662e0f1f840000000000488b2a4c8b6a084c89e7e8614e570031c94d39ee0f97c131f64939ef400f97c60f44f14084f64c0f44fd4d0f44f54885c074054885d275c848b800000000000000804c8d684041b401488d2dc0ccf4ffeb47'),
    'select_error': (STARTUP_FDE, 0x226a6d2, '41bf2b000000bf2b000000ff15f53850034885c00f849b0a00004989c60f100589d216fe0f11401b0f100573d216fe0f114010660f100557d216fe660f11004d8d6c242b4531e4488b7c2418e8cd906400c683da490000014c89abd83b00004c89bbe03b00004c89b3e83b000048c783f03b00002b0000004584e40f85bf010000'),
    'select_retry': (STARTUP_FDE, 0x226a753, '488d83d83b0000488d8b883c00000f1040400f1183c83c0000660f1000660f1048100f1050200f1058300f119bb83c00000f1193a83c0000660f118b983c0000660f1183883c0000488b83303c00004883c008488d93583c000048898424200100004889ac24280100004889942430010000488b05c4385003488984243801000048898c2440010000488b051d8e50034889842448010000488d35647af8fd488dbc24103c0000488d942420010000ff153838500349bc0000000000000080488b8424203c0000488b8c24b0000000488941100f108424103c00000f1101c683683c0000000f1001488b411048898424300100000f298424200100004c8db3403c0000488bb3403c00004c39e674144885f6740f488bbb483c000031d2ff159a375003c683693c000001488b842430010000498946100f28842420010000410f1106488b83303c0000f20f104020f20f1183d83c00004c8db3703d0000c683703d000000e910f3ffff'),
    'select_ok': (STARTUP_FDE, 0x226a912, '488bb3403c000049bc00000000000000804c39e674144885f6740f488bbb483c000031d2ff15d4365003c683693c00000031ed488b8424a0000000c60001488bbc2498000000e86300feff4084ed0f85e8060000c683e049000001c683e849000001'),
    'status_log': (STARTUP_FDE, 0x226a974, '4c89bc24c80000004c89b424d0000000488b83b000000048898424d80000004c8d7c24504c89ffff15ff3e50038b4424508984245c3c0000c78424503c000001000000488b44245448898424543c00004c89a424103c0000488d052fca16fe48898424303c000048c78424383c00001600000048c78424403c00000800000048c78424483c0000000000008b056301510385c00f8576060000660f100543015103660f11842400770000488d8424d80000004889442448488d8424c80000004889442408488d8424d00000004889442420488d8424103c00004889842420010000488d2d840671004889ac2428010000488d84240077000048898424300100004c8d3515c9f4ff4c89b42438010000488d4424484889842440010000488d05790844004889842448010000488d4c240848898c245001000048898424580100004c8d6424204c89a424600100004889842468010000488d3d0d4cf8fd488db42420010000ff158a3e5003488bb424103c000048b800000000000000804839c674154885f67410488bbc24183c000031d2ff1506355003'),
    'select_540': (STARTUP_FDE, 0x226900c,
                   'f20f1005c413fafd' '83bb180c000001' '0f8543010000' '483983200c0000' '0f8232070000' '0f8530010000'),
    'hardfork_log': (STARTUP_FDE, 0x226911b, '488d3d1440f8fd' '488db424103c0000' 'ff1538585003'),
    'select_840': (STARTUP_FDE, 0x226915c, 'f20f1005cc10fafd' '488d4360' 'f20f118424e0000000'),
    'tolerance_log': (STARTUP_FDE, 0x226928a,
                      '488d8424e0000000' '4889442448' '48895c2408' '4c89742420' '4c89bc2420010000'
                      '488d05301e7100' '4889842428010000' '488d842400770000' '4889842430010000'
                      '488d05c1e0f4ff' '4889842438010000' '488d442448' '4889842440010000'
                      '488d0565134400' '4889842448010000' '488d442408' '4889842450010000'
                      '488d05d91c4400' '4889842458010000' '488d4c2420' '48898c2460010000' '4889842468010000'
                      '488d3dfdc0f8fd' '488db42420010000' 'ff152f565003'),
    'stale_gate': (STARTUP_FDE, 0x2269171,
                   '8b4808898c2428010000488b0048898424200100004c8dbc24103c0000488db424200100004c89ffff15195e5003'
                   '448ba424103c0000448bb424143c00008bac24183c0000488dbc2420010000ff15dc565003443ba424200100000f9dc0'
                   '0f85dc010000443bb424240100000f93c00f85cb0100003bac242801000049bc00000000000000800f82c6010000'),
    'fresh_head': (STARTUP_FDE, 0x22691fd,
                   '488d7c2450ff15985650038b4424508984245c3c0000c78424503c000001000000488b44245448898424543c00004c89a4'
                   '24103c0000488d05c8e116fe48898424303c000048c78424383c00001600000048c78424403c00000800000048c78424'
                   '483c0000000000008b05fc18510385c04c8b7424180f8505050000660f1005d7185103660f11842400770000'),
    'fresh_exit': (STARTUP_FDE, 0x2269339,
                   '488bb424103c00004c39e674154885f67410488bbc24183c000031d2ff15b54c5003c683f049000000488dbc2420010000'
                   'bae83a00004c89f6ff15684c5003bfe83a0000ff15554c50034885c00f84470400004989c6488db42420010000bae83a00'
                   '004889c7ff153b4c5003c683f049000000e9d3190000'),
    'gate_branch': (STARTUP_FDE, 0x22693b1, '84c049bc00000000000000800f853afeffff4c8db3703b0000'),
    'stale_exit': (STARTUP_FDE, 0x22696e2, '488b84241077000049894610660f1084240077000066410f1106' '4c89b3883b0000488d83e84900004889842490000000c683e849000000e961f4ffff'),
    'once_init': (STARTUP_FDE, 0x226977e,
                  '488d05cb1351034889442420488d4424204889842420010000488d3dca135103488d0dc30740034c8d05a4074003488d94'
                  '2420010000be01000000ff15f950500349bc00000000000000804c8b742418e9a6faffff'),
    'peer_record': (STARTUP_FDE, 0x2268b7f,
                    '488d83903b00004c89b3903b0000488d8b983b0000488983983b0000488d05b1ed16fe488983a03b000048c783a83b0000'
                    '1100000048c783b03b00000a00000048b80000000000000040488983b83b000048898bc03b0000488d83e0490000488984'
                    '2488000000c683e049000000eb2d'),
    'peer_record_init': (STARTUP_FDE, 0x2268c1c,
                         '48c783283c0000ffffffff48898b603c0000488d836a3c000048898424a0000000c6836a3c000000488d83c83b0000'
                         '488984249800000048c7c0ffffffff66c783683c0000000148898b303c0000488983383c0000'),
    'entry': (STARTUP_FDE, 0x2268a18,
              '4881ece801000048899424c00000004889f34889bc24b800000049bc00000000000000800fb686f1490000488d0d2ad316fe'
              '486304814801c8ffe0'),
    'state0_file': (STARTUP_FDE, 0x2268a53,
                    'c683f0490000004c8bbb80000000488d059c3718fe48898424103c000048c78424183c0000030000004c8b35a55e5003'
                    '418b465085c00f858f0c00004983c6184c89b42420010000488d05fe2537004889842428010000488d058f5043034889'
                    '842430010000488d0dd0e8f4ff48898c2438010000488d8424103c0000488984244001000048898c2448010000488d35'
                    '2298f8fd488d7c2450488d942420010000ff1546555003488b6c24584c8b7424604889ef4c89f6ff15d85e500384c00f'
                    '849a020000488d0de15a4303488dbc24200100004889ee4c89f2e87e0b680083bc2420010000020f85db010000488bbc'
                    '2428010000488b07ff10e960020000'),
    'decode': (STARTUP_FDE, 0x2268d1b,
               '488dbc24103c0000488db42420010000bac81f0000ff15aa5250034c8bb424383c0000488dbc2400770000e845d231ff48'
               '8dbc2420010000488db424007700004c89f2e8ed8866004c8ba4242001000048b800000000000000804939c40f852e010000'),
    'no_state_return': (STARTUP_FDE, 0x2268da8,
                        '49bc0000000000000080488b7424504885f6740b4889ef31d2ff15495250034983c402c683f049000000e9ad1f0000'),
    'pending_return': (STARTUP_FDE, 0x226a8bc,
                       '488b842480000000c60003488b8424a8000000c60003b003eb0641c60603b004488b8c24a00000008801488b8424880000'
                       '00c60003488b842490000000c600034983c403488b8424b80000004c8920b003e987040000'),
    'gate_reject': (STARTUP_FDE, 0x226ab88,
                    'c683f049000000488dbc2400770000bae83a0000ff153e34500348896c24204c896c2428488d7c2408ff15e93c50038b44'
                    '24088984246c010000c784246001000001000000488b44240c488984246401000048b800000000000000804889842420'
                    '010000488d050fc816fe488984244001000048c78424480100001600000048c78424500100000800000048c784245801'
                    '0000000000008b0543ff500385c00f859c0400004c8dab703b0000660f10051cff5003660f114424504c89a424e80000'
                    '004c896c2448488d84242001000048898424103c00004c89b424183c00004c89bc24203c0000488d051ac7f4ff488984'
                    '24283c0000488d8424e800000048898424303c0000488d05ab09440048898424383c0000488d44244848898424403c00'
                    '00488d051f02440048898424483c0000488d3d6c93f8fd488db424103c0000ff159a3c5003488bb4242001000048b800'
                    '000000000000804839c674154885f67410488bbc242801000031d2ff15163350034c8ba3783b0000488b83803b00004c'
                    '8d3c804889c54885c074244c89ffff15bb3250034989c64885c07519bf010000004c89feff1585325003e992eeffff41'
                    'be010000004c89f74c89e64c89faff1593325003488dbc2400770000e856f6feff4c8dbbf04900004989ec498b450048'
                    '85c07413488bbb783b0000488d348031d2ff159032500341c60700'),
    'return_block': (STARTUP_FDE, 0x226ad84,
                     '488b8424b80000004c89204c8970084c896010b0018883f14900004881c4e8b100005b415c415d415e415f5dc3'),
    'gate_pass': (STARTUP_FDE, 0x226adb1,
                  'c683f049000000488dbc24007700004c8b2d19325003bae83a00004989f741ffd5488dbc24103c0000bae83a00004c89fe'
                  '41ffd5488d7c2408ff15b03a50038b4424088984246c010000c784246001000001000000488b44240c488984246401000048'
                  'b800000000000000804889842420010000488d05d6c516fe488984244001000048c78424480100001600000048c78424500100'
                  '000800000048c7842458010000000000008b050afd500385c00f85a4020000660f1005eafc5003660f11442420488d842420'
                  '010000488944245048896c24584c896424604c89742468488d3d4ce9f7fd488d742450ff15c63a5003488bb4242001000049'
                  'bc00000000000000804c39e674154885f67410488bbc242801000031d2ff1542315003488dbc2420010000488db424007700'
                  '00bae83a0000ff15f7305003bfe83a0000ff15e43050034885c00f844e0200004989c64c8dbbf04900004c8dab703b000048'
                  '8db42400770000bae83a00004889c7ff15bc305003498b45004885c00f853cfeffffe94afeffff'),
    'reject_once': (STARTUP_FDE, 0x226b0c9,
                    '488d0580fa500348894424504c89bc24103c0000488d3d84fa5003488d0d7dee3f034c8d055eee3f03488d9424103c00'
                    '00be01000000ff15b3375003e923fbffff'),
    'pass_once': (STARTUP_FDE, 0x226b10a,
                  '488d053ffa500348894424204d89e74c89642450488d3d43fa5003488d0d3cee3f034c8d051dee3f03488d542450be0100'
                  '0000ff15753750034d89fce91bfdffff'),
    'caller_a_call': (0x227a0e0, 0x227a23e,
                      '4c8d6b60488dbc24980200004c89ee4c89e2e89be7feff48b80000000000000080488d4803b00348398c24980200000f84'
                      'f2040000'),
    'caller_a_log': (0x227a0e0, 0x227a330,
                     '4c8d7b38660f10051c085003660f11842410010000498b074889c14c31e14885c0b801000000480f48c1488d0d37e015fe'
                     '488b0cc1488d1544e015fe486304824801d048898424e03e000048898c24e83e0000488d8424f803000048898424c87900'
                     '00488d05460d700048898424d07900004c8db424100100004c89b424d8790000488d05d7cff3ff48898424e0790000488d'
                     '8c24e03e000048898c24e879000048898424f0790000488d3ddcfdf7fd488db424c8790000ff157a454f03'),
    'caller_a_fresh': (0x227a0e0, 0x227a410,
                       '48b8000000000000008049390748896c24087533c64359004c8b7340488dbc24c8790000bae83a00004c89f6ff159e3b4f'
                       '03bee83a00004c89f731d2ff15be3b4f03e96f060000'),
    'caller_b_call': (0x22b47c0, 0x22b48ff,
                      '488dab283b0000488dbc24b00000004889ee4c897424184c89f2e8d240fbff49be0000000000000080488b9424b0000000'
                      '498d460348895424084839c20f855c010000b003e9010d0000'),
    'caller_b_dispatch': (0x22b47c0, 0x22b4a9e,
                          '488b8424b800000048894424284c8bac24c00000004889efe81555f8ff488b4424084889c14c31f14885c0b80100'
                          '0000480f48c14885c074714883f8020f85a2000000c6831c3b0000014c89742408e955050000'),
    'caller_b_stale': (0x22b47c0, 0x22b4b83, 'c6831c3b000001e9b8040000'),
    'caller_b_bootstrap': (0x22b47c0, 0x22b5047,
                           '488dbc2440fa0000ff154b984b038b842440fa0000898424fc000000c78424f000000001000000488b842444fa0000'
                           '48898424f40000004c89b424b0000000488d05752312fe48898424d000000048c78424d80000001600000048c78424'
                           'e00000000800000048c78424e8000000000000008b05a95a4c0385c0488b6c24280f85620a00000f1005855a4c030f'
                           '11842460bf0000488d8424b00000004889842450420000488d05ee5f6c004889842458420000488d842460bf000048'
                           '89842460420000488d057f22f0ff4889842468420000488d3d09f0f3fd488db42450420000ff153a984b03'),
    'caller_b_once': (0x22b47c0, 0x22b5b2e,
                      '488d051b504c034889842418350100488d8424183501004889842450420000488d3d14504c03488d0d0d443b034c8d05ee'
                      '433b03488d942450420000be01000000ff15438d4b03e952f5ffff'),
    'validator_collect': (0x3994ea0, 0x3994ea0,
                          '4156534883ec584989f64889fb89d7ff1533e4dd01488b084885c9740b0f104008b801000000eb050f57c031c048'
                          '8944240848c74424100000000048894c24180f13442420488944242848c74424300000000048894c24380f1144'
                          '24404c89742450488d7424084889dfe8d17d21004889d84883c4585b415ec3'),
    'chain_static': (0x33de620, 0x33de620,
                     '534883ec10400fb6c7488d0d84c01afd486304814801c8ffe08b05b17b3a0285c07570488d058e7b3a024883c4105bc38b'
                     '05da7b3a0285c0753d488d05b77b3a024883c4105bc38b05a37b3a0285c0755e488d05807b3a024883c4105bc3488d3d45'
                     'db1afd488d15ecc23002be1b000000ff1501fa3802488d1d7a7b3a0248891c244889e04889442408488d3d7f7b3a02eb36'
                     '488d1d1e7b3a0248891c244889e04889442408488d3d237b3a02eb1a488d1d227b3a0248891c244889e04889442408488d'
                     '3d277b3a02488d0da8b630024c8d0539b63002488d542408be01000000ff15b10139024889d84883c4105bc3'),
    'is_file': (0x144a710, 0x144a710,
                '55415741564154534881ecc00000004889f34989feff15e54e320484c07436488d7c24104c89f64889daff15d84e3204837c'
                '24100275224c8b6424188b054604330485c00f85900000004489e083e00383f801742831edeb12b800f00000234424483d00'
                '800000400f94c589e84881c4c00000005b415c415e415f5dc3'),
    'exhausted_r15': (STARTUP_FDE, 0x2268e95, 'e8563c62004989c7c683693c00000040b501e9991a0000'),
    'linked_state': (STARTUP_FDE, 0x2268f3f,
                     '488dbb880000004c8da42400770000488d8c24f000000048897c24184c89ee4c89e2ff1541ab5003c683f04900000148'
                     '8b7424504885f649be00000000000000804d89fd740b4889ef31d2ff1580505003488b83e8000000488943608b83f000'
                     '0000894368'),
    'root_ips': (STARTUP_FDE, 0x22693ca,
                 '4d85ed0f84080200004c89efff15e4a650034889c54989d5488984242001000048899424280100004c8dbc24200100004c'
                 '89ffff15c5a650034883c0104c8da424007700004c89e74889c6e896532e004885ed751b48c7c0f0fffffff0490fc14500'
                 '4883e0f24883f8120f84ae030000488d7c2420ff155b5450038b4424208984246c010000c784246001000001000000488b'
                 '442424488984246401000048b800000000000000804889842420010000488d0581df16fe488984244001000048c7842448'
                 '0100001600000048c78424500100000800000048c784245801000000000000ff15cd5f5003488944245048895424584c89'
                 '6424084c89bc24103c0000488d050f1c710048898424183c0000488d44245048898424203c0000488d05a3def4ff488984'
                 '24283c0000488d44240848898424303c0000488d05c719440048898424383c0000488d3d882cf9fd488db424103c0000ff'
                 '1542545003488bb4242001000049bc0000000000000080e98b010000'),
    'validator_ips': (STARTUP_FDE, 0x22695db,
                      '488db3800900000fb6937a090000488dbc2400770000ff15d9a45003488d7c2420ff159e5250038b4424208984246c01'
                      '0000c784246001000001000000488b44242448898424640100004c89a42420010000488d05cedd16fe48898424400100'
                      '0048c78424480100001600000048c78424500100000800000048c784245801000000000000ff151a5e50034889442450'
                      '4889542458488d84242001000048898424103c0000488d05591a710048898424183c0000488d44245048898424203c00'
                      '00488d05eddcf4ff48898424283c0000488d3d20cff7fd488db424103c0000ff15a8525003488bb424200100004c39e6'
                      '74154885f67410488bbc242801000031d2ff152e495003'),
    'vec5_clone': (0x254e7b0, 0x254e7b0,
                   '41574156415453504889fb4c8b7e084c8b66104f8d34a44d85e4741f4c89f7ff1503f821034889c74885c07513bf0100'
                   '00004c89f6ff15cdf72103bf010000004c892348897b084c89fe4c89f2ff15ddf721034c8963104889d84883c4085b415c'
                   '415e415fc3'),
    'add_secs_f64': (0x1459ca0, 0x1459ca0,
                     '534883ec304889fb8b460889442408488b0648890424f20f59056205dbfe66480f7ec148b8ffffffffffffff7f4821c1'
                     '660f57c948baffffffffffffef7f4839d17f2ef20f1015cd0fdbfe660f2ed07710660f2e05f70adbfe7706660f28c8eb10'
                     'f20f5fd0f20f100de30adbfef20f5dcaf2480f2cc9660f2e0daa05dbfe480f47c831f6660f2ec9480f4bf148b9b394d626'
                     'e80b2e114889f048f7e94889d048c1e83f48c1fa1a4801c24869c200ca9a3b4829c64889f148c1f93f4801ca81e100ca9a'
                     '3b01f1488d742404488d7c2410ff15324b3104488b44241848b9000000004057ffff4801c148ba81aefeff7faefeff4839'
                     'd17247f20f10442410660f294424208b3c2448b9572951cea0c8451848f7e94889d648c1ee3f48c1ea0d01d6ff15ea4a31'
                     '0485c0741489030f284424200f1343044889d84883c4305bc3488d3d3a02dcfe488d152c112104be26000000ff15714631'
                     '04'),
    'freshness': (FRESH_FDE, 0x2271d52,
                  '4c8bbb40070000' '48b80000000000c08240' '4889842438010000' '498b4760' '4889842440010000'
                  '418b4768' '89842448010000' '418b4768' '898424c8000000' '498b4760' '48898424c0000000'
                  '488db424c4000000' '488d7c2410' 'ba58020000' '31c9' 'ff15f5ca4f03' '488b442418'
                  '48b9000000004057ffff' '4801c1' '48ba81aefeff7faefeff' '4839d1' '0f8295050000'
                  '448b642410' '448b742414' '8bbc24c0000000' '48b9572951cea0c8451848' 'f7e9' '4889d6'
                  '48c1ee3f' '48c1ea0d' '01d6' 'ff15a7ca4f03' '89c5' '85c0' '0f845a050000' '488d7c2410'
                  'ff1582ca4f03' '3b6c2410' '0f9dc0' '7561' '443b642414' '0f93c0' '7557' '443b742418' '7354'
                  '488d842438010000' '4889442410' '488b05cccb4f03' '4889442418' '488d842440010000'
                  '4889442420' '488b05c3d64f03' '4889442428' '488d3d23b3f7fd' '488d15d0ca4203' '488d742410'
                  'ff1515c24f03' 'e9b5090000' '84c0' '74ac'),
    'poll_entry': (FRESH_FDE, 0x2271d17,
                   '49bd0000000000000080' '0fb68756070000' '488d0de14116fe' '48630481' '4801c8' 'ffe0'
                   '4889ac2430010000' 'c6835407000000' '0fb68355070000' '8844240f'),
    'after_panic': (FRESH_FDE, 0x227283d, '0f0b'),
    'call_a': (ORCHESTRATOR_FDE, 0x22aef54, '4c89ee' '4c8db5f8210000' '4c89f7' 'e89a2dfcff' '84c0' '7409' 'b001' 'b10a' 'e96a130000'),
    'call_b': (ORCHESTRATOR_FDE, 0x22affbf,
               '0fb685e8010000' '48899d70290000' '888585290000' 'c6858629000000' '4c8db530220000' '4c89f7' '4989f5'
               'e8141dfcff' '84c0' '7409' 'b001' 'b10b' 'e9e4020000'),
    'panic_shim': (PANIC_SHIM, PANIC_SHIM,
                   '55' '4889e5' '4883ec30' '48897df0' '488975f8' '488d45f0' '488945d8' '488955e0'
                   '66c745e80100' '488d7dd8' 'ff15a44e1f04'),
}
MESSAGES = {'too_far_behind': b'local height is too far behind', 'stale_hardfork': b'local height is from stale hardfork'}
TEMPLATE_MARKERS = {
    'hardfork': b' @@ applying hardfork to frozen local abci_state @@ [abci_state.height(): ',
    'tolerance': b' @@ initializing with local abci_state @@ [tolerance: ',
    'freshness': b'use an abci state within ',
}
LOCATION_FILE = b'/home/ubuntu/hl/code_Mainnet/node/src/hl_node.rs'
TOLERANCES = (540.0, 840.0)
STATUS_TEMPLATE = 0x1ef6dd
GOT_HEIGHTS_TEMPLATE = 0x1e7641
# (branch VA, instruction length, expected target)
SELECT_BRANCHES = {
    'len_gt_1_to_loop': (0x226a54f, 2, 0x226a56c), 'len_0_to_error': (0x226a551, 6, 0x226a6d2),
    'single_other_not_1_to_error': (0x226a566, 6, 0x226a6d2), 'loop_back': (0x226a6b6, 2, 0x226a680),
    'ok_to_result': (0x226a6d0, 2, 0x226a719), 'ok_to_slots': (0x226a74d, 6, 0x226a912),
    'error_retry_back': (0x226a8b7, 5, 0x2269bcc),
}
ITER_NEXT = 0x27df4f0
# (branch or call VA, instruction length, expected target)
QUERY_FLOW = {
    'empty_list_to_got_heights': (0x2269cd2, 6, 0x226a41a), 'request_call': (0x2269e87, 5, 0x226bb20),
    'pending_to_yield': (0x2269e9c, 6, 0x226a8bc), 'not_ok_to_error': (0x2269f4e, 6, 0x226a1fa),
    'variant_not_2_to_error': (0x2269f71, 2, 0x2269ff1), 'none_to_no_heights': (0x2269fad, 6, 0x226a04b),
    'insert_call': (0x2269fdd, 5, 0x28523b0), 'insert_to_next': (0x2269fec, 5, 0x226a403),
    'no_heights_to_next': (0x226a182, 5, 0x226a403), 'variant_error_to_log': (0x226a1bf, 2, 0x226a231),
    'next_peer': (0x226a414, 6, 0x2269cd8),
}
QUERY_TEMPLATES = {0x2269de3: (0x1dd96c, b' @@ querying height @@ [rpc_ip: '),
                   0x226a143: (0x1ebdb6, b' @@ no heights from node @@ [rpc_ip: '),
                   0x226a3bf: (0x1ee557, b' @@ unable to query height: '),
                   0x226a508: (GOT_HEIGHTS_TEMPLATE, b' @@ got heights @@ [ip_to_heights: ')}
REQUEST_FDE, RPC_TIMEOUT_WINDOW = 0x226bb20, 0x226bb82
VARIANT_ERROR = b'incorrect rpc response variant'
LOOP_RANGE = (0x2269cd8, 0x226a41a)
BACK_EDGE_R12 = (0x2269fe2, 0x226a079, 0x226a2dc)
ITER_CALLS = (0x226a5df, 0x226a659, 0x226a68a)
SELECT_ERROR = b'unable to find at least 2 valid rpc heights'
RETRY_TEMPLATE = 0x1f2256
# argument k of the status log -> (slot, pointer-to-slot store, argument-array store)
STATUS_ARGS = {
    2: ('[rsp+0xd8]', '488d8424d8000000' '4889442448', '488d442448' '4889842440010000'),
    3: ('[rsp+0xc8]', '488d8424c8000000' '4889442408', '488d4c2408' '48898c2450010000'),
    4: ('[rsp+0xd0]', '488d8424d0000000' '4889442420', '4c8d642420' '4c89a42460010000'),
}
SLOT_REFS = {0xc8: ['0x226a976', '0x226aa2d', '0x226ab6c'], 0xd0: ['0x226a97e', '0x226aa3a', '0x226ab38', '0x226ab62'],
             0xd8: ['0x226a98d', '0x226aa20', '0x226ab0c']}
ADD_SECS_FDE = 0x1459ca0
ADD_SECS_OVERFLOW = b'`NaiveDateTime + TimeDelta` overflowed'
STATE_BYTES = 0x3ae8
# (branch VA, instruction length, expected target)
STALE_FLOW = {
    'first_field_differs': (0x22691cf, 6, 0x22693b1), 'second_field_differs': (0x22691e0, 6, 0x22693b1),
    'third_field_below_now': (0x22691f7, 6, 0x22693c3), 'not_below_to_fresh': (0x22693bd, 6, 0x22691fd),
    'once_detour': (0x2269273, 6, 0x226977e), 'once_return': (0x22697ce, 5, 0x2269279),
    'alloc_failed': (0x2269386, 6, 0x22697d3), 'fresh_return': (0x22693ac, 5, 0x226ad84),
    'stale_to_retry': (0x2269719, 5, 0x2268b7f), 'record_to_init': (0x2268bed, 2, 0x2268c1c),
}
# ModRM VAs of every [rbx+disp32] operand in the startup FDE, per displacement
RECORD_REFS = {0x3b88: ['0x2268b7a', '0x22696fe'], 0x3b90: ['0x2268b81', '0x2268b88'],
               0x3b98: ['0x2268b8f', '0x2268b96'], 0x3bc0: ['0x2268bd2', '0x2268c17'],
               0x3c30: ['0x2268c65', '0x2269c65', '0x226a79d', '0x226a897'],
               0x49c8: ['0x2269574', '0x2269c6f', '0x226a559']}
RECORD_DESC = b'gossip rpc height'
OUTCOME_FLOW = {
    'not_file_to_none': (0x2268b12, 6, 0x2268db2), 'read_ok_to_decode': (0x2268b3a, 6, 0x2268d1b),
    'read_err_to_none': (0x2268b4d, 5, 0x2268db2), 'decode_ok': (0x2268d78, 6, 0x2268eac),
    'none_to_return': (0x2268dd2, 5, 0x226ad84), 'height_ok_to_pass': (0x226ab72, 6, 0x226adb1),
    'reject_once': (0x226ac27, 6, 0x226b0c9), 'reject_once_back': (0x226b105, 5, 0x226ac2d),
    'reject_alloc_failed': (0x226ad33, 5, 0x2269bca), 'reject_drop_state': (0x226ad55, 5, 0x225a3b0),
    'pass_once': (0x226ae60, 6, 0x226b10a), 'pass_once_back': (0x226b146, 5, 0x226ae66),
    'pass_alloc_failed': (0x226aef7, 6, 0x226b14b), 'pass_to_free': (0x226af2b, 6, 0x226ad6d),
    'pass_to_clear': (0x226af31, 5, 0x226ad80), 'pending_to_epilogue': (0x226a90d, 5, 0x226ad99),
}
RETURN_ENTRIES = {0x226ad84: ['0x2268dd2', '0x22693ac'], 0x226ad80: ['0x226ad6b', '0x226af31'],
                  0x226ad6d: ['0x226af2b']}
# lea VA -> (template, exact pieces)
OUTCOME_TEMPLATES = {
    0x2268ae0: (0x1f2309, [None, b'/hyperliquid_data/', None, b'.', None]),
    0x226acb9: (0x1f402c, [None, b' WARN >>> ', None, b' @@ considering local abci state as stale @@ [stale_reason: ',
                           None, b'] @ [node_ips: ', None, b']\n\n']),
    0x226ae90: (0x1e97e3, [None, b' WARN >>> ', None, b' @@ initializing with local abci_state\n\n']),
}
CONSUMER_FLOW = {
    'a_call': (0x227a250, 5, STARTUP_FDE), 'a_pending': (0x227a26d, 6, 0x227a765),
    'a_not_fresh': (0x227a422, 2, 0x227a457), 'a_fresh_done': (0x227a452, 5, 0x227aac6),
    'b_call': (0x22b4919, 5, STARTUP_FDE), 'b_ready': (0x22b493c, 6, 0x22b4a9e),
    'b_fresh': (0x22b4ad5, 2, 0x22b4b48), 'b_not_missing': (0x22b4adb, 6, 0x22b4b83),
    'b_missing_to_bootstrap': (0x22b4aed, 5, 0x22b5047), 'b_stale_to_bootstrap': (0x22b4b8a, 5, 0x22b5047),
    'b_once': (0x22b50c6, 6, 0x22b5b2e), 'b_once_back': (0x22b5b75, 5, 0x22b50cc),
}
VARIANT_NAMES = (b'fresh', b'stale', b'missing')
CONSUMER_TEMPLATES = {
    0x227a3d9: (0x1fa1bc, [None, b' WARN >>> ', None, b' @@ using local AbciState: ', None, b'\n\n']),
    0x22b5119: (0x1f4129, [None, b' WARN >>> ', None,
                           b' @@ running non-validator to get initial abci state for consensus\n\n']),
}
NODE_IP_FLOW = {
    'no_root_to_validator': (0x22693cd, 6, 0x22695db), 'clone_call': (0x2269415, 5, 0x254e7b0),
    'unlock_wake': (0x2269434, 6, 0x22697e8), 'root_to_tail': (0x2269538, 5, 0x22696c8),
    'exhausted_exit': (0x2268ea7, 5, 0x226a945),
}
# call VA -> (RELATIVE slot, target)
NODE_IP_SLOTS = {0x22693d6: (0x5773ac0, 0x4742cc0), 0x22693fd: (0x5773ac8, 0x4779e30),
                 0x22695f1: (0x5773ad0, 0x3994ea0), 0x2268f61: (0x5773aa8, 0x3751e80)}
NODE_IP_TEMPLATES = {0x2269511: (0x1fc1a0, b' @@ using root node ips @@ [root_node_ips: '),
                     0x22696ab: (0x1e65d2, b' @@ using validator node ips\n\n')}
RSP_E0 = re.compile(rb'[\x84\x8c\x94\x9c\xa4\xac\xb4\xbc]\x24\xe0\x00\x00\x00')


class EvidenceError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise EvidenceError(message)


class Image:
    def __init__(self, data):
        self.data = data
        self.secs = sections(data)
        rela = next((s for s in self.secs if s['name'] == '.rela.dyn' and s['type'] == 4), None)
        require(rela is not None and rela['size'] % 24 == 0, 'no well-formed .rela.dyn')
        self.relative = {}
        for pos in range(rela['offset'], rela['offset'] + rela['size'], 24):
            where, info, addend = struct.unpack_from('<QQq', data, pos)
            if info & 0xffffffff == 8:
                self.relative[where] = addend
        _, fdes = eh_frame_records(data, self.secs)
        self.fdes = sorted((f['start'], f['end']) for f in fdes)

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

    def rip(self, va, length):
        return va + length + struct.unpack('<i', self.read(va + length - 4, 4))[0]

    def f64(self, va):
        return struct.unpack('<d', self.read(va, 8))[0]

    def i32(self, va):
        return struct.unpack('<i', self.read(va, 4))[0]


def windows(img):
    """Check every window's bytes and FDE containment; return VA -> bytes."""
    out = {}
    for name, (fde, va, hexs) in WINDOWS.items():
        raw = bytes.fromhex(hexs)
        start, end = img.fde(fde)
        require(start <= va and va + len(raw) <= end, f'{name} window {va:#x} is outside FDE {fde:#x}')
        require(img.read(va, len(raw)) == raw, f'{name} at {va:#x}: bytes changed')
        out[name] = va
    return out


def template(img, va):
    """Decode a rustc packed format template: literal-length bytes and 0xc0 placeholders, ending at 0x00."""
    pieces, pos = [], va
    for _ in range(64):
        b = img.read(pos, 1)[0]
        if b == 0xc0:
            pieces.append(None)
            n = img.read(pos + 1, 1)[0]
            pos += 2
        elif b == 0:
            return pieces
        elif b < 0x80:
            n = b
            pos += 1
        else:
            raise EvidenceError(f'template {va:#x}: unexpected byte {b:#x} at {pos:#x}')
        if n:
            lit = img.read(pos, n)
            require(all(0x20 <= c < 0x7f or c == 0x0a for c in lit), f'template {va:#x}: literal at {pos:#x} not text')
            pieces.append(lit)
            pos += n
        elif pieces and pieces[-1] is None and img.read(pos, 1)[0] != 0xc0:
            return pieces
    raise EvidenceError(f'template {va:#x}: no terminator')


def placeholder_before(pieces, literal):
    """Index of the placeholder immediately preceding `literal`."""
    idx = 0
    for i, p in enumerate(pieces):
        if p is None:
            idx += 1
        elif p == literal:
            require(i > 0 and pieces[i - 1] is None, f'literal {literal!r} is not preceded by a placeholder')
            return idx - 1
    raise EvidenceError(f'literal {literal!r} not in template')


def flow_target(img, va, n):
    return va + 2 + struct.unpack('<b', img.read(va + 1, 1))[0] if n == 2 else img.rip(va, n)


def check_queries(img):
    for name, (va, n, want) in QUERY_FLOW.items():
        got = flow_target(img, va, n)
        require(got == want, f'{name} at {va:#x} goes to {got:#x}')
    for lea, (want, literal) in QUERY_TEMPLATES.items():
        tpl = img.rip(lea, 7)
        require(tpl == want and literal in template(img, tpl), f'template at LEA {lea:#x} changed')
    require(img.i32(0x2269e57 + 7) == 2, 'request tag is not 2')
    start, end = img.fde(REQUEST_FDE)
    require(start < RPC_TIMEOUT_WINDOW < end, f'0x226bb82 is not inside FDE {REQUEST_FDE:#x}')
    pieces = {0x0e: img.rip(0x226a00d, 7), 0x00: img.rip(0x226a018, 8)}
    buf = bytearray(30)
    for off, src in sorted(pieces.items(), reverse=True):
        buf[off:off + 16] = img.read(src, 16)
    require(bytes(buf) == VARIANT_ERROR and img.i32(0x2269ff1 + 1) == 30, f'variant error rebuilt as {bytes(buf)!r}')
    for va in BACK_EDGE_R12:
        require(img.read(va, 10) == bytes.fromhex('49bc0000000000000080'), f'r12 reset at {va:#x} changed')
    lo, hi = LOOP_RANGE
    code = img.read(lo, hi - lo)
    local = [hex(lo + i - 1) for i in range(1, len(code) - 4)
             if code[i] & 0xc7 == 0x83 and code[i + 1:i + 5] == b'\xb0\x00\x00\x00']
    require(not local, f'[rbx+0xb0] operands in the query loop: {local}')
    return dict(peer_list='[[rbx+0x3c30]] stored to [rbx+0x49c8]; data [+0x8], length [+0x10], 5-byte entries',
                current_peer='[rbx+0x49d0] (4 bytes) and [rbx+0x49d4] (1 byte)', request_tag=2,
                request_fde=[hex(start), hex(end)], ok_reply_variant=2,
                insert='[rsp+0x138], [rsp+0x140] into [rbx+0x49b0] keyed by the current peer, when [rsp+0x130] bit 0 is set',
                variant_error=dict(text=VARIANT_ERROR.decode(), pieces={hex(k): hex(v) for k, v in pieces.items()}),
                templates={hex(k): hex(v[0]) for k, v in QUERY_TEMPLATES.items()},
                flow={k: hex(v[2]) for k, v in QUERY_FLOW.items()},
                local_height_operands_in_loop=0, r12_reset_on_back_edges=[hex(v) for v in BACK_EDGE_R12])


def check_selection(img):
    for name, (va, n, want) in SELECT_BRANCHES.items():
        got = img.rip(va, n) if n != 2 else va + 2 + struct.unpack('<b', img.read(va + 1, 1))[0]
        require(got == want, f'{name} branch at {va:#x} goes to {got:#x}')
    for va in ITER_CALLS:
        require(img.rip(va, 5) == ITER_NEXT, f'iterator call at {va:#x} changed')
    err = WINDOWS['select_error'][1]
    loads = {0x1b: img.rip(err + 0x1d, 7), 0x10: img.rip(err + 0x28, 7), 0x00: img.rip(err + 0x33, 8)}
    buf = bytearray(43)
    for off, src in sorted(loads.items()):
        buf[off:off + 16] = img.read(src, 16)
    require(bytes(buf) == SELECT_ERROR and img.i32(err + 2) == len(SELECT_ERROR),
            f'error string rebuilt as {bytes(buf)!r}')
    got = template(img, GOT_HEIGHTS_TEMPLATE)
    require(b' @@ got heights @@ [ip_to_heights: ' in got, 'got-heights template changed')
    retry = WINDOWS['select_retry'][1]
    retry_raw = bytes.fromhex(WINDOWS['select_retry'][2])
    lea = retry + retry_raw.index(bytes.fromhex('488d35'))
    tpl = img.rip(lea, 7)
    require(tpl == RETRY_TEMPLATE and img.read(tpl + 1, 29) == b'AsyncSleepRetry::retry desc=[',
            f'retry template at {tpl:#x} changed')
    return dict(map='[rbx+0x49b0] (root, height, len at +0x10)', got_heights_template=hex(GOT_HEIGHTS_TEMPLATE),
                proceed_when='len > 1, or len == 1 and the queried peer list length [[[rbx+0x49c8]]+0x10] == 1',
                iterator_next=hex(ITER_NEXT), value_fields={'+0x0': 'initial_height (r15)', '+0x8': 'latest_height (r14)'},
                keep='lexicographic max of (initial_height, latest_height); a later equal pair replaces',
                error=dict(text=SELECT_ERROR.decode(), len=len(SELECT_ERROR), pieces={hex(k): hex(v) for k, v in loads.items()}),
                retry_template=hex(tpl), retry_template_lea=hex(lea),
                branches={k: hex(v[2]) for k, v in SELECT_BRANCHES.items()})


def check_status_log(img):
    va = WINDOWS['status_log'][1]
    raw = bytes.fromhex(WINDOWS['status_log'][2])
    require(va + len(raw) == WINDOWS['gate'][1], 'status log window does not end at the gate')
    require(raw.count(bytes.fromhex('488d3d')) == 1, 'status log template LEA is not unique')
    tpl = img.rip(va + raw.index(bytes.fromhex('488d3d')), 7)
    require(tpl == STATUS_TEMPLATE, f'status template is {tpl:#x}')
    pieces = template(img, tpl)
    names = {}
    for k, (slot, ptr, arg) in STATUS_ARGS.items():
        require(raw.count(bytes.fromhex(ptr)) == 1 and raw.count(bytes.fromhex(arg)) == 1,
                f'argument {k} is not a pointer to {slot}')
        before = [i for i, p in enumerate(pieces) if p is None]
        require(len(before) > k and before[k] > 0 and pieces[before[k] - 1] is not None, f'placeholder {k} has no label')
        label = pieces[before[k] - 1].decode()
        m = re.search(r'\[(\w+): $', label)
        require(m is not None, f'placeholder {k} label {label!r} is not a [name: ] field')
        names[slot] = m.group(1)
    start, end = img.fde(STARTUP_FDE)
    body = img.read(start, end - start)
    refs = {}
    for disp, want in SLOT_REFS.items():
        got = [hex(start + m.start()) for m in re.finditer(rb'[\x84\x8c\x94\x9c\xa4\xac\xb4\xbc]\x24' + bytes([disp]) + rb'\x00\x00\x00', body)]
        require(got == want, f'[rsp+{disp:#x}] references are {got}')
        refs[f'[rsp+{disp:#x}]'] = got
    return dict(window=hex(va), template=hex(tpl), fields=names, slot_refs=refs,
                local_source='[rbx+0xb0]', initial_source='r15', latest_source='r14')


def check_gate(img):
    va = WINDOWS['gate'][1]
    add = img.i32(va + 0x16)
    require(add == 0x4e20, f'saturating add constant is {add:#x}')
    require(img.i32(va + 0x0a) == -add, 'saturation guard is not -add')
    require(img.i32(va + 0x4b) == add, 'non-saturating add is not the same constant')
    msgs = {}
    for key, len_at, lea_at in (('too_far_behind', va + 0x3b, va + 0x3f), ('stale_hardfork', va + 0x73, va + 0x77)):
        length = img.i32(len_at)
        target = img.rip(lea_at, 7)
        text = img.read(target, length)
        require(text == MESSAGES[key], f'{key} message at {target:#x} is {text!r}')
        msgs[key] = dict(lea=hex(lea_at), va=hex(target), len=length, text=text.decode())
    return dict(fde=hex(STARTUP_FDE), window=hex(va), local='[rsp+0xd8]', target='[rsp+0xd0]',
                initial='[rsp+0xc8]', tolerance=add, saturating=True, messages=msgs,
                ok_branch=hex(img.rip(va + 0x68, 6)))


def branches_into(img, target):
    """Every jcc/jmp rel8 or rel32 encoding in the startup FDE whose target is `target`."""
    start, end = img.fde(STARTUP_FDE)
    body = img.read(start, end - start)
    hits = []
    for m in re.finditer(rb'\x0f[\x80-\x8f]|\xe9', body):
        o = m.start()
        n = 2 if body[o] == 0x0f else 1
        if o + n + 4 <= len(body) and start + o + n + 4 + struct.unpack_from('<i', body, o + n)[0] == target:
            hits.append(hex(start + o))
    for m in re.finditer(rb'[\x70-\x7f\xeb]', body):
        o = m.start()
        if o + 2 <= len(body) and start + o + 2 + struct.unpack_from('<b', body, o + 1)[0] == target:
            hits.append(hex(start + o))
    return sorted(hits)


def check_tolerance(img):
    start, end = img.fde(STARTUP_FDE)
    body = img.read(start, end - start)
    v540 = img.rip(WINDOWS['select_540'][1], 8)
    v840 = img.rip(WINDOWS['select_840'][1], 8)
    join = WINDOWS['select_840'][1] + 8
    require((img.f64(v540), img.f64(v840)) == TOLERANCES, f'tolerance constants are {img.f64(v540)}, {img.f64(v840)}')
    branches = [img.rip(WINDOWS['select_540'][1] + off, 6) for off in (0x0f, 0x22)]
    require(branches == [join, join], f'540 branches go to {[hex(b) for b in branches]}, not the join {join:#x}')
    into_join = branches_into(img, join)
    want = [hex(WINDOWS['select_540'][1] + 0x0f), hex(WINDOWS['select_540'][1] + 0x22)]
    require(sorted(into_join) == want, f'branches into join {join:#x}: {sorted(into_join)}')
    slot_refs = [hex(start + m.start()) for m in RSP_E0.finditer(body)]
    require(slot_refs == ['0x226916b', '0x226928c'], f'[rsp+0xe0] references are {slot_refs}')
    hf = img.rip(WINDOWS['hardfork_log'][1], 7)
    hf_pieces = template(img, hf)
    require(TEMPLATE_MARKERS['hardfork'] in hf_pieces, f'hardfork template {hf:#x} changed')
    log = WINDOWS['tolerance_log'][1]
    tpl = img.rip(log + 0x9a, 7)
    pieces = template(img, tpl)
    tol_index = placeholder_before(pieces, b'] @ [pre_fork_context: ')
    require(TEMPLATE_MARKERS['tolerance'] in pieces, f'log template {tpl:#x} changed')
    require(pieces[pieces.index(TEMPLATE_MARKERS['tolerance']) + 1] is None, 'tolerance literal not followed by a placeholder')
    # argument array at [rsp+0x120]: (value ptr, formatter) pairs, 16 bytes each; arg 2's value is [rsp+0x48] -> [rsp+0xe0]
    require(img.read(log + 0x4d, 13) == bytes.fromhex('488d442448' '4889842440010000'), 'argument 2 is not &[rsp+0x48]')
    return dict(fde=hex(STARTUP_FDE), slot='[rsp+0xe0]', default=img.f64(v540), default_const=hex(v540),
                hardfork=img.f64(v840), hardfork_const=hex(v840), join=hex(join), branches_into_join=sorted(into_join),
                slot_refs=slot_refs, hardfork_template=hex(hf), log_template=hex(tpl),
                log_placeholders=sum(p is None for p in pieces), tolerance_arg_index=tol_index,
                hardfork_condition='[rbx+0xc18] == 1 and [rbx+0xc20] == rax (jb -> 0x2269760)')


def days_86400(x):
    """The 0x2271de9 sequence on signed 64-bit x: imul by M; esi = (rdx >> 63) + (rdx >> 13), low 32 bits."""
    m = 0x1845c8a0ce512957
    rdx = ((x * m) >> 64) & (2 ** 64 - 1)
    return ((rdx >> 63) + (rdx >> 13)) & 0xffffffff


def check_freshness(img):
    va = WINDOWS['freshness'][1]
    secs_f64 = struct.unpack('<d', img.read(va + 9, 8))[0]
    add_secs = struct.unpack('<I', img.read(va + 0x55, 4))[0]
    require(secs_f64 == float(add_secs), f'message seconds {secs_f64} != added seconds {add_secs}')
    magic = struct.unpack('<q', img.read(va + 0x99, 8))[0]
    require(magic == 0x1845c8a0ce512957, 'day-division multiplier changed')
    slots = {}
    for name, at in (('add_time', va + 0x5b), ('add_days', va + 0xb1), ('now', va + 0xc6), ('panic', va + 0x12b)):
        slot = img.rip(at, 6)
        require(slot in img.relative, f'{name} slot {slot:#x} has no RELATIVE entry')
        slots[name] = (hex(slot), hex(img.relative[slot]))
    require(int(slots['panic'][1], 16) == PANIC_SHIM, 'panic slot does not reach the panic shim')
    tpl = img.rip(va + 0x118, 7)
    pieces = template(img, tpl)
    require(pieces[0] == TEMPLATE_MARKERS['freshness'] and sum(p is None for p in pieces) == 2,
            f'freshness template {tpl:#x} changed')
    loc = img.rip(va + 0x11f, 7)
    require(loc in img.relative, f'Location {loc:#x} has no RELATIVE file pointer')
    flen, line, col = struct.unpack('<QII', img.read(loc + 8, 16))
    file_ = img.read(img.relative[loc], flen)
    require(file_ == LOCATION_FILE, f'Location file is {file_!r}')
    after = img.rip(va + 0x131, 5)
    require(after == WINDOWS['after_panic'][1], f'jump after the panic call goes to {after:#x}')
    shim = img.rip(PANIC_SHIM + 0x26, 6)
    require(img.fde(PANIC_SHIM)[1] == PANIC_SHIM + 0x2c, 'panic shim FDE does not end at its slot call')
    require(shim in img.relative, 'panic shim slot has no RELATIVE entry')
    return dict(fde=hex(FRESH_FDE), state_time='[[rbx+0x740]+0x60] (12 bytes)', added_seconds=add_secs,
                message_seconds=secs_f64, day_divisor=86400, slots={k: list(v) for k, v in slots.items()},
                template=hex(tpl), template_placeholders=2, location=hex(loc), location_file=file_.decode(),
                location_line=line, location_column=col, after_panic=hex(after), panic_shim=hex(PANIC_SHIM),
                panic_shim_slot=hex(shim), panic_shim_target=hex(img.relative[shim]),
                compare='panic iff (date, secs, frac) of state_time + 600 s < now (lexicographic)')


def check_stale_gate(img, fresh_slots):
    require(WINDOWS['select_840'][1] + len(bytes.fromhex(WINDOWS['select_840'][2])) == WINDOWS['stale_gate'][1],
            'stale_gate does not continue the tolerance join')
    for name, (va, n, want) in STALE_FLOW.items():
        got = flow_target(img, va, n)
        require(got == want, f'{name} at {va:#x} goes to {got:#x}, not {want:#x}')
    add_slot, now_slot = img.rip(0x2269199, 6), img.rip(0x22691be, 6)
    require(img.relative.get(add_slot) == ADD_SECS_FDE, f'tolerance add slot {add_slot:#x} does not reach {ADD_SECS_FDE:#x}')
    require(hex(now_slot) == fresh_slots['now'][0], f'clock slot {now_slot:#x} differs from the freshness clock')
    img.fde(ADD_SECS_FDE)
    scale = img.f64(img.rip(0x1459cb6, 8))
    require(scale == 1e9, f'tolerance scale is {scale}')
    clamp = (img.f64(img.rip(0x1459ce3, 8)), img.f64(img.rip(0x1459cf1, 8)), img.f64(img.rip(0x1459d05, 8)))
    require(clamp == (-2.0 ** 63, 2.0 ** 63, 2.0 ** 63), f'nanosecond clamp is {clamp}')
    top = img.f64(img.rip(0x1459d16, 8))
    require(top == 9.223372036854775e18, f'i64::MAX cut-over is {top}')
    require(struct.unpack('<q', img.read(0x1459d2e, 8))[0] == 0x112e0be826d694b3, 'nanosecond divisor changed')
    require(struct.unpack('<I', img.read(0x1459d4d, 4))[0] == 1_000_000_000, 'nanosecond multiplier changed')
    require(struct.unpack('<q', img.read(0x1459da8, 8))[0] == 0x1845c8a0ce512957, 'day divisor changed')
    helper = {'add_time': hex(img.rip(0x1459d70, 6)), 'add_days': hex(img.rip(0x1459dc0, 6))}
    require(helper == {k: fresh_slots[k][0] for k in helper}, f'helper slots {helper} differ from the freshness add')
    msg, mlen = img.rip(0x1459dde, 7), img.read(0x1459ded, 1)[0]
    require(img.read(msg, mlen) == ADD_SECS_OVERFLOW, f'helper panic text at {msg:#x} changed')
    copies = [m.start() for m in re.finditer(re.escape(struct.pack('<I', STATE_BYTES)),
                                              bytes.fromhex(WINDOWS['fresh_exit'][2]))]
    require(len(copies) == 3, f'fresh_exit has {len(copies)} {STATE_BYTES:#x} immediates')
    desc = img.rip(0x2268b9b, 7)
    require(img.read(desc, len(RECORD_DESC)) == RECORD_DESC, f'record descriptor at {desc:#x} changed')
    start, end = img.fde(STARTUP_FDE)
    body = img.read(start, end - start)
    refs = {}
    for disp in RECORD_REFS:
        pat, hits, i = struct.pack('<I', disp), [], 0
        while (i := body.find(pat, i + 1)) != -1:
            if body[i - 1] & 0xc7 == 0x83:
                hits.append(hex(start + i - 1))
        require(hits == RECORD_REFS[disp], f'[rbx+{disp:#x}] operands are {hits}')
        refs[hex(disp)] = hits
    return dict(fde=hex(STARTUP_FDE), state_time='[rbx+0x60] (12 bytes)', tolerance_reg='xmm0',
                add_slot=hex(add_slot), add_helper=hex(ADD_SECS_FDE), scale=scale, clamp=list(clamp),
                helper_slots=helper, helper_panic=ADD_SECS_OVERFLOW.decode(), clock_slot=hex(now_slot),
                flow={k: hex(v[2]) for k, v in STALE_FLOW.items()}, fresh_state_bytes=hex(STATE_BYTES),
                stale_peer_vec='[rbx+0x3b70] -> [rbx+0x3b88]', record_desc=hex(desc), record_refs=refs,
                peer_chain='[rbx+0x3c30] = &[rbx+0x3b98]; [rbx+0x3b98] = &[rbx+0x3b90]; [rbx+0x3b90] = &[rbx+0x3b70]',
                compare='local iff (date, secs, frac) of state_time + tolerance s >= now (lexicographic); else query peers')


def check_node_ips(img):
    for name, (va, n, want) in NODE_IP_FLOW.items():
        got = flow_target(img, va, n)
        require(got == want, f'{name} at {va:#x} goes to {got:#x}, not {want:#x}')
    slots = {}
    for va, (slot, target) in NODE_IP_SLOTS.items():
        got = img.rip(va, 6)
        require(got == slot and slot in img.relative, f'call at {va:#x} uses slot {got:#x}')
        require(img.relative[slot] == target, f'slot {slot:#x} reaches {img.relative[slot]:#x}')
        slots[hex(va)] = [hex(slot), hex(img.relative[slot])]
    templates = {}
    for va, (tpl, marker) in NODE_IP_TEMPLATES.items():
        got = img.rip(va, 7)
        pieces = template(img, got)
        require(got == tpl and marker in pieces, f'node-ip template at {va:#x} is {got:#x} {pieces!r}')
        templates[hex(va)] = dict(template=hex(tpl), placeholders=sum(p is None for p in pieces),
                                  marker_index=pieces.index(marker))
    root = bytes.fromhex(WINDOWS['root_ips'][2])
    require(root.count(bytes.fromhex('488d442408' '48898424303c0000')) == 1, 'root_node_ips argument is not &[rsp+0x8]')
    require(root.count(bytes.fromhex('4c896424 08'.replace(' ', ''))) == 1, '[rsp+0x8] is not the clone destination r12')
    start, end = img.fde(0x254e7b0)
    require(img.read(0x254e7c3, 4) == bytes.fromhex('4f8d34a4'), 'clone element size is not 5')
    return dict(selector='r13 (r15 = [rbx+0x80] on the state-0 path)', flow={k: hex(v[2]) for k, v in NODE_IP_FLOW.items()},
                slots=slots, templates=templates, clone=hex(start), clone_element_bytes=5,
                validator_source='&[rbx+0x980], byte [rbx+0x97a]', linked_state='[rbx+0x88] (built via slot 0x5773aa8)',
                state_time_copy={'[rbx+0x60]': '[rbx+0xe8]', '[rbx+0x68]': '[rbx+0xf0]'})


def check_outcomes(img):
    for name, (va, n, want) in OUTCOME_FLOW.items():
        got = flow_target(img, va, n)
        require(got == want, f'{name} at {va:#x} goes to {got:#x}, not {want:#x}')
    templates = {}
    for va, (tpl, pieces) in OUTCOME_TEMPLATES.items():
        got = img.rip(va, 7)
        dec = template(img, got)
        require(got == tpl and dec == pieces, f'outcome template at {va:#x} is {got:#x} {dec!r}')
        templates[hex(va)] = hex(tpl)
    ext = img.rip(0x2268a61, 7)
    require(img.read(ext, 3) == b'rmp' and img.read(0x2268a78, 4) == struct.pack('<I', 3), 'file extension is not "rmp"')
    stem_ref = img.rip(0x2268aaa, 7)
    stem_len = struct.unpack('<Q', img.read(stem_ref + 8, 8))[0]
    require(stem_ref in img.relative and img.read(img.relative[stem_ref], stem_len) == b'abci_state',
            f'file stem at {stem_ref:#x} is not "abci_state"')
    slot = img.rip(0x2268b0a, 6)
    require(img.relative.get(slot) == 0x144a710, f'file check slot {slot:#x} does not reach 0x144a710')
    require(img.read(0x144a769, 18) == bytes.fromhex('b800f00000' '23442448' '3d00800000' '400f94c5'),
            'is_file mode test is not (st_mode & 0xf000) == 0x8000')
    niches = {'local_state': 0, 'no_local_state': img.read(0x2268dca, 1)[0], 'pending': img.read(0x226a8ff, 1)[0]}
    require(img.read(0x2268a32, 10) == bytes.fromhex('49bc0000000000000080') and niches['no_local_state'] == 2
            and niches['pending'] == 3, f'outcome niches are {niches}')
    require(img.read(0x226aab4, 5) == bytes.fromhex('4c8d642420'), 'r12 is not &[rsp+0x20] before the gate')
    entries = {hex(t): branches_into(img, t) for t in RETURN_ENTRIES}
    require(entries == {hex(t): v for t, v in RETURN_ENTRIES.items()}, f'branches into the return block: {entries}')
    return dict(output='[[rsp+0xb8]] (rdi at entry): 3 words, written at 0x226ad8c/0x226ad8f/0x226ad93',
                file_template=templates['0x2268ae0'], file='{}/hyperliquid_data/abci_state.rmp',
                file_check=hex(0x144a710), flow={k: hex(v[2]) for k, v in OUTCOME_FLOW.items()},
                templates=templates, niches={k: hex(2 ** 63 + v) for k, v in niches.items()}, return_entries=entries,
                stale_reason_arg='&[rsp+0xe8] = r12 = &[rsp+0x20] = (message ptr rbp, len r13)',
                node_ips_arg='&[rsp+0x48] = &[rbx+0x3b70]',
                stale_return='{len, ptr, len} clone of the 5-byte peer Vec; local state copy dropped via 0x225a3b0')


def check_consumers(img):
    for name, (va, n, want) in CONSUMER_FLOW.items():
        got = flow_target(img, va, n)
        require(got == want, f'{name} at {va:#x} goes to {got:#x}, not {want:#x}')
    for va in (0x227a25f, 0x22b4930):
        require(img.read(va, 4)[-1] == 3, f'pending test at {va:#x} is not niche + 3')
    lens, offs = img.rip(0x227a35a, 7), img.rip(0x227a365, 7)
    names = []
    for i in range(len(VARIANT_NAMES)):
        n = struct.unpack('<Q', img.read(lens + 8 * i, 8))[0]
        names.append(img.read(offs + img.i32(offs + 4 * i), n))
    require(tuple(names) == VARIANT_NAMES, f'variant names are {names}')
    templates = {}
    for va, (tpl, pieces) in CONSUMER_TEMPLATES.items():
        got = img.rip(va, 7)
        dec = template(img, got)
        require(got == tpl and dec == pieces, f'consumer template at {va:#x} is {got:#x} {dec!r}')
        templates[hex(va)] = hex(tpl)
    calls = direct_calls(img, STARTUP_FDE)
    require(calls == [hex(CONSUMER_FLOW['a_call'][0]), hex(CONSUMER_FLOW['b_call'][0])],
            f'direct calls to {STARTUP_FDE:#x}: {calls}')
    fresh = bytes.fromhex(WINDOWS['caller_a_fresh'][2])
    require(fresh.count(struct.pack('<I', STATE_BYTES)) == 2, 'caller_a fresh path does not move and free 0x3ae8 bytes')
    return dict(callers=[hex(0x227a0e0), hex(0x22b47c0)], direct_calls=calls, flow={k: hex(v[2]) for k, v in CONSUMER_FLOW.items()},
                name_lengths=hex(lens), name_offsets=hex(offs), names=[x.decode() for x in names],
                index='word0 ^ 2**63 if word0 < 0 (signed) else 1', templates=templates,
                missing_and_stale_flag='[rbx+0x3b1c] = 1 in 0x22b47c0')


def startup_outcome(word0):
    """Decode word 0 of the 0x22689f0 output."""
    if word0 < 2 ** 63:
        return 'node_ips'
    return {0: 'local_state', 2: 'no_local_state', 3: 'pending'}.get(word0 - 2 ** 63, 'unobserved')


CHAIN_STATIC_FDE, CHAIN_TABLE = 0x33de620, 0x58a6b4
# chain byte -> (arm, lea VA of the returned static, static)
CHAIN_ARMS = {1: (0x33de639, 0x33de643, 0x57861d8), 2: (0x33de667, 0x33de671, 0x57861f8),
              3: (0x33de650, 0x33de65a, 0x5786218)}
CHAIN_LOCATION_FILE = b'/home/ubuntu/hl/code_Mainnet/l1/src/chain_ext.rs'


def check_chain_static(img):
    slot = img.rip(0x3994eaf, 6)
    require(slot == 0x57732e8 and img.relative.get(slot) == CHAIN_STATIC_FDE,
            f'validator helper slot {slot:#x} does not reach {CHAIN_STATIC_FDE:#x}')
    require(flow_target(img, 0x3994f0a, 5) == 0x3bacce0, 'validator helper does not call 0x3bacce0')
    require(img.rip(0x33de629, 7) == CHAIN_TABLE, 'chain jump table moved')
    arms = [CHAIN_TABLE + img.i32(CHAIN_TABLE + 4 * i) for i in range(4)]
    require(arms[1:] == [CHAIN_ARMS[i][0] for i in (1, 2, 3)] and arms[0] == 0x33de67e, f'chain arms are {arms}')
    statics = {}
    for chain, (_, lea, static) in CHAIN_ARMS.items():
        require(img.rip(lea, 7) == static, f'chain {chain} arm returns {img.rip(lea, 7):#x}')
        statics[chain] = hex(static)
    msg, packed = img.rip(0x33de67e, 7), struct.unpack('<I', img.read(0x33de68d, 4))[0]
    require(packed & 1 and img.read(msg, packed >> 1) == b'invalid chain', f'chain 0 panic text at {msg:#x} changed')
    loc = img.rip(0x33de685, 7)
    flen, line, col = struct.unpack('<QII', img.read(loc + 8, 16))
    require(loc in img.relative and img.read(img.relative[loc], flen) == CHAIN_LOCATION_FILE,
            f'chain Location {loc:#x} file changed')
    return dict(slot=hex(slot), accessor=hex(CHAIN_STATIC_FDE), table=hex(CHAIN_TABLE), arms=[hex(a) for a in arms],
                statics=statics, chain0_panic='invalid chain', packed_len=hex(packed),
                location=f'{CHAIN_LOCATION_FILE.decode()}:{line}:{col}', collect=hex(0x3bacce0),
                collect_args='rdi = out, rsi = &{iterator over the static, &state+0x8f8}')


def tolerance_nanos(x):
    """0x1459cb6..0x1459d28: f64 seconds * 1e9, clamped to +-2**63, truncated to i64 (NaN -> 0)."""
    v = x * 1e9
    if v != v:
        return 0
    if v > 9.223372036854775e18:
        return 2 ** 63 - 1
    return int(max(v, -2.0 ** 63))


def nanos_split(n):
    """The 0x1459d2c..0x1459d64 sequence on signed 64-bit n: imul by M, sar 26 + sign, then floor fix-up."""
    rdx = (n * 0x112e0be826d694b3) >> 64
    q = (rdx >> 26) + ((rdx >> 63) & 1)
    r = n - q * 1_000_000_000
    if r < 0:
        q, r = q - 1, r + 1_000_000_000
    return q, r


def uses_local_state(deadline, now):
    return not deadline < now


def direct_calls(img, target):
    """Every e8/e9 rel32 encoding in .text whose target is `target`."""
    text = next(x for x in img.secs if x['name'] == '.text' and x['type'] != 8)
    body = img.data[text['offset']:text['offset'] + text['size']]
    calls = []
    for m in re.finditer(rb'[\xe8\xe9]', body):
        o = m.start()
        if o + 5 <= len(body) and text['address'] + o + 5 + struct.unpack_from('<i', body, o + 1)[0] == target:
            calls.append(hex(text['address'] + o))
    return calls


def check_callers(img):
    entry = WINDOWS['poll_entry'][1]
    require(img.rip(entry + 0x11, 7) == POLL_TABLE, 'poll dispatch table moved')
    arm0 = POLL_TABLE + img.i32(POLL_TABLE)
    require(arm0 == entry + 0x21, f'state-0 arm is {arm0:#x}')
    require(entry + len(bytes.fromhex(WINDOWS['poll_entry'][2])) == WINDOWS['freshness'][1],
            'state-0 arm does not run straight into the freshness window')
    calls = direct_calls(img, FRESH_FDE)
    want = [hex(WINDOWS['call_a'][1] + 0x0d), hex(WINDOWS['call_b'][1] + 0x28)]
    require(calls == want, f'direct calls to {FRESH_FDE:#x}: {calls}')
    states = [img.read(WINDOWS['call_a'][1] + 0x19, 1)[0], img.read(WINDOWS['call_b'][1] + 0x34, 1)[0]]
    strings = {}
    for lea, text_ in FUTURE_STRINGS.items():
        start, end = img.fde(FRESH_FDE)
        require(start <= lea < end, f'LEA {lea:#x} outside {FRESH_FDE:#x}')
        target = img.rip(lea, 7)
        require(img.read(target, len(text_)) == text_, f'string at {target:#x} is not {text_!r}')
        strings[hex(lea)] = text_.decode()
    return dict(poll_table=hex(POLL_TABLE), state0_arm=hex(arm0), direct_calls=calls, caller_fde=hex(ORCHESTRATOR_FDE),
                caller_states_when_al_set=states, future_strings=strings)


def collect_heights(replies):
    """The 0x2269cd8 loop: replies is [(peer, reply)], reply None for an RPC error, else (variant, heights or None)."""
    out = {}
    for peer, reply in replies:
        if reply is None or reply[0] != 2 or reply[1] is None:
            continue
        out[peer] = reply[1]
    return out


def select_heights(values, other_len=0):
    """The 0x226a53f loop: None for the error path, else the kept (initial, latest)."""
    if not (len(values) > 1 or (len(values) == 1 and other_len == 1)):
        return None
    cur = values[0]
    for new in values[1:]:
        keep_cur = cur[0] > new[0] if cur[0] != new[0] else cur[1] > new[1]
        if not keep_cur:
            cur = new
    return cur


def too_far_behind(local, target):
    return min(local + 0x4e20, 2 ** 64 - 1) <= target


def freshness_panics(deadline, now):
    return deadline < now


def analyse(data):
    img = Image(data)
    wins = windows(img)
    fresh = check_freshness(img)
    return dict(target=TARGET, windows={k: hex(v) for k, v in wins.items()},
                peer_queries=check_queries(img), height_selection=check_selection(img), status_log=check_status_log(img), height_gate=check_gate(img), tolerance_log=check_tolerance(img), freshness=fresh,
                stale_gate=check_stale_gate(img, fresh['slots']), node_ips=check_node_ips(img), outcomes=check_outcomes(img), consumers=check_consumers(img), chain_static=check_chain_static(img), callers=check_callers(img))


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument('--json', action='store_true')
    a = p.parse_args(argv)
    identity = next(i for i in json.loads((ROOT / 'provenance/artifacts.json').read_text())['files']
                    if i['path'] == TARGET)
    path = ROOT / TARGET
    check(path, identity)
    result = dict(analyse(path.read_bytes()), target_sha256=identity['sha256'])
    if a.json:
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    g, t, f = result['height_gate'], result['tolerance_log'], result['freshness']
    print('status log fields: ' + ', '.join(f'{k}={v}' for k, v in sorted(result['status_log']['fields'].items())))
    print(f"height gate: too far behind iff local_height.saturating_add({g['tolerance']}) <= latest_height; "
          f"else stale hardfork iff local_height < initial_height")
    print(f"logged tolerance: {t['default']} (default) / {t['hardfork']} (after hardfork branch)")
    print("stale gate: use local abci_state iff state_time + tolerance s >= now; else query peer heights")
    print(f"freshness: panic at {f['location_file']}:{f['location_line']}:{f['location_column']} "
          f"iff state_time + {f['added_seconds']} s < now")
    return 0


if __name__ == '__main__':
    sys.exit(main())
