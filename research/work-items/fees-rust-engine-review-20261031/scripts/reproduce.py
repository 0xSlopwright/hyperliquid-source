"""Repeat the reviewed, finite synthetic fee corpus from the repository root.

Runs local Python interpreters, GNU static disassembly, and independently built
Rust source. Does not launch the captured target or use the network. Run without
Python -O: the retained packet evaluators use assertions as validation checks.
"""

from pathlib import Path
import hashlib
import json
import os
import subprocess
import sys
import time


def main():
    if not __debug__:
        raise SystemExit("validation requires assertions; omit -O")
    root = Path.cwd()
    packet = Path(__file__).resolve().parent.parent
    scripts = packet / "scripts"
    out = root / "work/fees-engine-1150-reproduction"
    out.mkdir(parents=True, exist_ok=True)
    for relative, expected in json.loads((packet / "source-pins.json").read_text()).items():
        actual = hashlib.sha256((root / relative).read_bytes()).hexdigest()
        if actual != expected:
            raise SystemExit(f"review input changed: {relative}")
    target_hash = hashlib.sha256((root / "artifacts/node/94/hl-node").read_bytes()).hexdigest()
    if target_hash != "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f":
        raise SystemExit("wrong node #94 artifact")
    env = dict(os.environ, CARGO_NET_OFFLINE="true", CARGO_TARGET_DIR=str(out / "target"))
    results = []

    def run(label, args, seconds=900):
        start = time.monotonic()
        with (out / f"{label}.log").open("w") as log:
            result = subprocess.run(args, cwd=root, env=env, stdout=log,
                                    stderr=subprocess.STDOUT, timeout=seconds)
        results.append({"name": label, "command": args, "returncode": result.returncode,
                        "seconds": time.monotonic() - start, "timeout_seconds": seconds})
        (out / "commands.json").write_text(json.dumps(results, indent=2) + "\n")
        if result.returncode:
            raise SystemExit(f"{label} failed; see {out / (label + '.log')}")

    python = [sys.executable, "-I", "-S", "-B"]
    run("native", python + [str(scripts / "native_audit.py"), str(out)])
    for name in ("trade_fee", "fill_ledger", "fee_scale", "rate_grid", "unit_conversion"):
        run(name, python + [str(scripts / "bounded_evaluate.py"), name, str(out)])
    run("build", ["cargo", "+1.94.1", "build", "--offline", "--locked",
                  "--manifest-path", "src/node94-fees/Cargo.toml"])
    run("driver-build", ["rustc", "+1.94.1", "--edition=2024", "-O",
                         str(scripts / "compare_driver.rs"), "--extern",
                         f"node94_fees={out / 'target/debug/libnode94_fees.rlib'}",
                         "-o", str(out / "compare-driver")])
    run("corpus", python + [str(scripts / "compare_corpus.py"), str(out)], 120)
    print((out / "corpus-comparison.json").read_text())


if __name__ == "__main__":
    main()
