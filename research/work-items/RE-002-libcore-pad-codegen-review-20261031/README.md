# RE-002 PadAdapter code-generation review

PR #1145 exact head `a0eba12f84a25861d314d6ab88b9c7b80133a107` supplies a bounded build-only probe. All24 original changed blobs are archived unchanged; all23 original manifest entries authenticate. No production source, recipe, budget, provider pins or original evidence was rewritten.

Target94 SHA-256 is `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`. An independent FDE parser and176 authenticated native instructions establish the full622-byte adapter at `0x157d000..0x157d26e`, body SHA-256 `d62080d0724a750e0162d6a0563c7a056ae76e2212fd48310f89bcf8809dfde4`.

The independently authenticated official Rust1.94.1 archive supplies libcore SHA-256 `ca804049dc84fa29d47c1ceb7012c7688a6848b5c858bd598ba484a0652ab256`, and GNU ar extracts the pinned member SHA-256 `57ca580737b890eebfb33d5d66c6a24e3e6d6e8c7d71ac11695252d6f0032d13`. Its actual symbol/RELA evidence permits only the four-byte PC32 field558..561 to be excluded. The two real LEA byte gaps464 and467 remain:616/618 non-RELA bytes equal the target. The four-space referent is separately bounded and raw compared. The captured and original-native fixtures equal their independently read full bodies. The submitted generated622 excerpt differs from the target only at the actual PC32 field; that fixture alone does not authenticate its historical build origin.

All13 portable tests pass with actual Python3.10 in normal and optimized modes. These include synthetic ELF containers and malformed symbol/RELA/extent controls; their fixture nature is explicit. Actual3.10 source compile and `make verify catalogue-check reproduce` pass. Original negative control outcomes remain intact.

## Supplemental provider experiment

The official rustc1.94.1 Linux archive was obtained using the already authenticated signed release manifest. Its78,645,148 bytes hash to `0a6b16ca476461c6238f48efcb74a7aa08a3983e61adf587f208ba48504d87e1`; detached signature validates with Rust signing fingerprint `108F66205EAEB0AAA8DD5E1C85AB96E6FA1BE5FE`. The release key and manifest hashes are retained in acquisition evidence. No installer or global toolchain change occurred. All103 extracted compiler-prefix records match the submitted pins.

The independent provider is the existing local amd64 Ubuntu22.04 container image `sha256:8144280bbd87f8901942da5f7c941627d8bd2f595390c907990f66276a7dd6d5`, running via Podman Rosetta. It uses a read-only root/prefix/source/driver, disabled networking,3GiB memory,128 PID limit and CPU0 affinity.24 of30 original system records differ, including seven missing original paths; six match. The host compiler is gcc11 rather than the original gcc14, and strace is absent. No successful-read trace or exact original Debian host provenance is claimed.

The first independent experiment preserved the submitted60-second recipe bound: default completed in18.637s, while ThinLTO stopped with SIGTERM at60.291s and no compiler diagnostic. Its partial outputs are retained in ignored work with hashes and excluded from acceptance. The original recipe/budget/pins remain unchanged. A separately declared fresh experiment uses a fixed300-second Rosetta-only ThinLTO bound with identical compiler/source/flags and reuses only the completed default result. The declaration precedes that run; it does not relabel the original stopped attempt.

## Reproduction scope

The original `tools/libcore_pad_codegen.py build` command still requires all original provider pins, finite cgroup memory and strace. The supplemental scripts accept `--repo`, `--prefix`, `--out` and, for the separate ThinLTO experiment, `--default-dir`. They create fresh output only and reject changed official prefix/source inputs. Run them in the same explicitly pinned offline container with the original code and authenticated private prefix. The original two compiler recipes differ only by `-Clto=thin`; the supplemental timing/provider changes are declared independently. Produced objects are statically parsed and never loaded or executed.

This research does not identify the original node compiler/flags/fork/ABI, prove Rust-source regeneration of libcore, transfer helper behavior, establish whole-ELF equivalence, or close any reconstruction gate. Published LLVM bitcode and independently authored wrapper builds remain distinct. Source artifact terms remain in the original packet.

For a fresh supplemental experiment, let `REPO` be this checkout, `PREFIX` the authenticated private compiler prefix, and `OUTPUT` a new writable output directory. Mount all inputs read-only; the output mount is the sole persistent writable directory. For example, the separately declared ThinLTO run after the successful default result uses:

```sh
podman run --rm --pull=never --network=none --read-only --memory=3g --pids-limit=128 \
  --volume "$PREFIX:/provider:ro" --volume "$REPO:/review:ro" \
  --volume "$REPO/research/work-items/RE-002-libcore-pad-codegen-review-20261031/supplemental/supplemental_thin300.py:/driver.py:ro" \
  --volume "$OUTPUT:/results:rw" --tmpfs /tmp:rw,size=16m \
  --entrypoint /usr/bin/python3 \
  8144280bbd87f8901942da5f7c941627d8bd2f595390c907990f66276a7dd6d5 \
  -B /driver.py --repo /review --prefix /provider \
  --out /results/thin300 --default-dir /results/build/default
```

The successful default output and its `build-result.json` must already exist at the shown location. This command makes no downloads and runs no captured or generated object. Portable tests remain:

```sh
python3 -B -m unittest discover -s tests -p test_libcore_pad_codegen.py -v
python3 -O -B -m unittest discover -s tests -p test_libcore_pad_codegen.py -v
```

## Completed supplemental result

The separately declared300-second experiment completed ThinLTO in111.959s, exit0, with minimum measured cgroup headroom2,449,129,472 bytes. The exact compiler prefix and system records were unchanged before/after. Its saved ET_REL622-byte adapter equals the submitted generated fixture byte-for-byte, SHA-256 `ab7fc88e156c3ef084ae3db3f3de8bbbccfbcf711365c253d3bb4251e8196086`;618/618 non-RELA bytes equal the captured body, with only the actual PC32 field excluded. Both linked artifacts remain raw-only comparisons: default retains the two LEA gaps plus its four displacement bytes, while ThinLTO differs only in the four displacement bytes. All one default and two ThinLTO candidates are reported, without selecting a best match.

This independently corroborates the bounded code-generation observation on a different provider. It does not reproduce the original60-second exact-Debian-host execution or its strace evidence. The original stopped attempt stays failed/excluded. The independently authored wrapper, original compiler flags and all production pins were unchanged. Full generated objects/raw outputs remain in ignored work; their sizes/hashes and the full symbol/RELA-derived candidate comparisons are retained here. No captured or produced object was executed.

A fresh actual-Python3.10 `inspect` of the completed outputs reproduces every base report field exactly. Its `build_provenance` remains `UNQUALIFIED`, as required for existing-output inspection; supplemental acquisition, controlled-run and provider-difference evidence is recorded separately. No incomplete object is used in this final inspection.

New review receipts apply exact literal substitutions only to local checkout/cache/output/home paths. `path-redactions.json` records token scope and raw/published SHA-256 values; raw files remain in ignored review output. These masks do not change native bytes, compiler hashes, relocation fields, observed differences or original24 archived PR blobs.
