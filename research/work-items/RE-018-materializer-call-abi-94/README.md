# RE-018-materializer-call-abi-94

Standalone packet. `tools/materializer_call_abi.py` builds `materializer-call-abi.json` from node #94 bytes (Python standard library only): a whole-section `ff15` pass for GOT slot 0x5773aa8, the FDE start of each site, and — for the five contested callers outside 0x3273810 — the pinned lea/mov/call/post bytes plus a [-0x40,+6) window hash. `verify.py` regenerates the JSON and checks the exact pins. `independent_verify.py` imports nothing from tools/: it checks 39 key VAs byte by byte, re-derives 5 call targets, re-hashes 5 windows, re-runs the caller pass (6 sites), and reports PASS, FAIL or INCONCLUSIVE. `tests/test_materializer_call_abi.py` holds the pins, seed/-O checks, negative controls and tamper tests. See EVIDENCE.md.

Finding (bytes only): each of 0x226685a, 0x2268f61, 0x4359d34, 0x4746097 and 0x4b2c8e2 loads four pointers into rdi/rsi/rdx/rcx and calls `[0x5773aa8]`. The sixth site 0x3273920 is cited from RE-017, not re-owned.

## Rerun

```
python3 -I -B research/work-items/RE-018-materializer-call-abi-94/verify.py
python3 -O -B research/work-items/RE-018-materializer-call-abi-94/verify.py
python3 -B research/work-items/RE-018-materializer-call-abi-94/independent_verify.py
python3 -B -m unittest tests.test_materializer_call_abi
for s in 0 7 99; do PYTHONHASHSEED=$s python3 -B tools/materializer_call_abi.py | sha256sum; done
```

## File hashes

- EVIDENCE.md 0e36377a5a6f81fc01f61f8a0f46f55d4931c4b379fadd0a874d1a3369f21d90
- materializer-call-abi.json b679a68f47442a68cc5235095b1fd8a94cc92cb57dc4c53a0c89b89d2ce4415e
- verify.py 703cfdfa254c206ae9ceb49dc04ca1b71d0b69d44497077464327d64b2b4ced7
- independent_verify.py dd93229aa6e71e33ae167271521ac088991c39d039147ed607ec13b8a7e68b23
- tools/materializer_call_abi.py 61e9e2d518f076e072fe1c63ad865017ad05e94d34824bb57e00437954b95c86
- tests/test_materializer_call_abi.py f6264ee5553a6c2003ac2067d863b91b183006e82df991548b5f2314f5dccff3

## What this does not claim

- It does not claim that the four pointers match RE-017's buffer roles, or what the post-call flag bytes mean. Those are inference.
- It does not claim what 0x3751e80 does (RE-016) or re-analyse 0x3273920 (RE-017).
- It does not claim whole-FDE hashes or the transport/RocksDB/timeout facts already claimed by open PRs and RE-009 inside these FDEs.
- The caller pass covers `ff15` only, in .text/.init/.fini/.plt.
- Node #115 and other releases are not covered.
