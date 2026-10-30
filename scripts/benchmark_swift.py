#!/usr/bin/env python3
"""Compile and validate a synthetic Swift fixture; never reads customer code."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("cloneguard", ROOT / "skills/cloneguard/scripts/cloneguard.py")
cg = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = cg
spec.loader.exec_module(cg)

SOURCE = """// Synthetic fixture: no application secrets or customer logic.
func netPrice(_ cents: Int, _ tier: Int) -> Int {
    let discount = tier == 2 ? 15 : 5
    return cents * (100 - discount) / 100
}
let arguments = CommandLine.arguments.dropFirst().compactMap(Int.init)
if arguments.count == 2 {
    print(netPrice(arguments[0], arguments[1]))
} else {
    print("CloneGuard synthetic pricing fixture")
}
"""


def run(keep_dir=None):
    swiftc = shutil.which("swiftc")
    if not swiftc:
        return {"schema": "cloneguard.swift-benchmark.v1", "status": "skipped", "reason": "swiftc unavailable"}
    temporary = tempfile.TemporaryDirectory(prefix="cloneguard-swift-") if not keep_dir else None
    base = Path(temporary.name if temporary else keep_dir).resolve()
    base.mkdir(parents=True, exist_ok=True)
    try:
        src = base / "main.swift"
        cg.create_file(src, SOURCE.encode())
        cache = base / "module-cache"
        debug, release = base / "fixture-debug", base / "fixture-release"
        compiler_version = subprocess.run([swiftc, "--version"], capture_output=True, text=True, timeout=60).stdout.strip()
        for target, flags in [(debug, ["-Onone", "-g"]), (release, ["-O"])]:
            subprocess.run([swiftc, "-module-cache-path", str(cache), *flags, str(src), "-o", str(target)], check=True, capture_output=True, timeout=120)
        vectors = [(0, 1), (1, 2), (99, 1), (10000, 2), (10000, 1), (12345, 2)]
        observations = []
        for cents, tier in vectors:
            outputs = [subprocess.run([str(binary), str(cents), str(tier)], check=True, capture_output=True, text=True, timeout=10).stdout.strip() for binary in (debug, release)]
            expected = str(cents * (85 if tier == 2 else 95) // 100)
            observations.append({"cents": cents, "tier": tier, "debug": outputs[0], "release": outputs[1], "expected": expected, "matches": outputs[0] == outputs[1] == expected})
        receipt = base / "receipt.json"
        cg.manifest(release, receipt)
        intact = cg.verify(release, receipt)["matches"]
        original = release.read_bytes()
        with release.open("ab") as stream:
            stream.write(b"\x00synthetic-tamper")
        detects = not cg.verify(release, receipt)["matches"]
        release.write_bytes(original)
        signature = {"status": "unrun"}
        if shutil.which("codesign"):
            result = subprocess.run(["codesign", "--verify", "--strict", str(release)], capture_output=True, text=True, timeout=30)
            signature = {"status": "passed" if result.returncode == 0 else "failed", "returncode": result.returncode,
                         "meaning": "Local toolchain fixture signature only; no notarization, device or App Store assertion."}
        return {"schema": "cloneguard.swift-benchmark.v1", "status": "completed", "generated_utc": cg.utc_now(),
                "environment": {"system": platform.system(), "machine": platform.machine(), "compiler": compiler_version},
                "source_sha256": hashlib.sha256(SOURCE.encode()).hexdigest(), "flags": {"debug": ["-Onone", "-g"], "release": ["-O"]},
                "debug_bytes": debug.stat().st_size, "release_bytes": release.stat().st_size,
                "behavior_vectors": observations, "manifest_matches": intact, "tamper_detected": detects, "signature": signature,
                "passed": all(x["matches"] for x in observations) and intact and detects,
                "unmeasured": ["clone resistance", "Swift symbol obfuscation", "real application/device compatibility", "notarization", "attestation"]}
    finally:
        if temporary:
            temporary.cleanup()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out")
    parser.add_argument("--keep-dir", help="New/empty local directory for reproducible inspection of synthetic binaries")
    args = parser.parse_args()
    try:
        result = run(args.keep_dir)
    except (subprocess.SubprocessError, OSError) as exc:
        result = {"schema": "cloneguard.swift-benchmark.v1", "status": "failed", "error": type(exc).__name__}
    if args.out:
        cg.write_json(args.out, result)
    print(json.dumps(result, indent=2))
    sys.exit(0 if result.get("passed") or result["status"] == "skipped" else 1)
