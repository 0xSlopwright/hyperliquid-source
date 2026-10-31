# RE-019-rmp-json-loader-94

Standalone packet. `tools/rmp_json_loader.py` builds `rmp-json-loader.json` from node #94 bytes (Python standard library only): the FDE extent of 0x3c155a0, a whole-section e8 caller pass, the case-folded `.rmp` format gate, the two decode arms (rmp_serde::from_slice via 0x2e0db40 vs serde_json::from_str via 0x2fe2fe0), Ok length 0x1fc8 / Err tag 2, five diagnostic labels, and two Location records. `verify.py` regenerates the JSON and checks the exact pins. `independent_verify.py` imports nothing from tools/: it checks 41 key VAs byte by byte, re-derives targets, re-runs the caller pass (3 sites), checks labels and Locations, and reports PASS, FAIL or INCONCLUSIVE. `tests/test_rmp_json_loader.py` holds the pins, seed/-O checks, negative controls and tamper tests. See EVIDENCE.md.

Finding (bytes only): 0x3c155a0 rejects absolute `/` and `..`, gates on a case-folded `.rmp` extension, and loads via MessagePack or JSON accordingly; exactly three e8 sites call it, each passing a state.rs Location.

## Rerun

```
python3 -I -B research/work-items/RE-019-rmp-json-loader-94/verify.py
python3 -O -B research/work-items/RE-019-rmp-json-loader-94/verify.py
python3 -B research/work-items/RE-019-rmp-json-loader-94/independent_verify.py
python3 -B -m unittest tests.test_rmp_json_loader
for s in 0 7 99; do PYTHONHASHSEED=$s python3 -B tools/rmp_json_loader.py | sha256sum; done
```

## File hashes

- EVIDENCE.md c02eebf1cc7b880f96606d9f7e23a6c658b2f3f54eb389160a5bac9e8457cf1f
- rmp-json-loader.json d434acc77db5a0e8636833b1fab0d009416a9548b16d7ac49a4866d894fb472d
- verify.py bcf7b57fe6c8f67f4cd3cca13f02cae4f519c4318bca4fa5b8a9b32cabd27d14
- independent_verify.py 23c6d16a367bfd9f973a758ec88121035d3a2b4d2ebc09a1b949fef068b922ab
- tools/rmp_json_loader.py a6f66b18c7e03be351cff4e2ddc104ed0d56b816e61d5a2b93085291b588f3eb
- tests/test_rmp_json_loader.py 54499ab7ee11650544abe9d44e57822bbba65d4d62c53eb2aeab37d7d5642887

## What this does not claim

- It does not claim that Result tag 2 is a Rust `Err` discriminant, or what the 0x1fc8-byte Ok payload means at each caller. Those are inference.
- It does not claim the body of 0x3273810 / 0x3273920 (RE-017), the GOT chain through 0x5773aa8, or what 0x3751e80 does (RE-016).
- It does not claim exclusive ownership of the shared `serde_json::from_str:` diagnostic string at 0x1fd0ce (#365 cites the same string).
- The caller pass covers `e8` only, in .text/.init/.fini/.plt.
- Node #115 and other releases are not covered.
