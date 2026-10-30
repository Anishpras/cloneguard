#!/usr/bin/env python3
"""Reproducible synthetic release-screening benchmark; no LLM cost estimates."""
import argparse
import importlib.util
import json
from pathlib import Path
import platform
import plistlib
import statistics
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("cloneguard", ROOT / "skills/cloneguard/scripts/cloneguard.py")
cg = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = cg
spec.loader.exec_module(cg)


def run():
    with tempfile.TemporaryDirectory(prefix="cloneguard-benchmark-") as temporary:
        base = Path(temporary)
        root = base / "web-dist"
        root.mkdir()
        (root / "app.js").write_text("export const calculate = (a, b) => a + b;\n")
        (root / "index.html").write_text('<main><h1>CloneGuard fixture</h1></main>\n')
        (root / "app.js.map").write_text(json.dumps({"version": 3, "sourcesContent": ["privateImplementation()"]}))
        (root / ".env").write_text("EXAMPLE_ONLY=synthetic\n")
        durations = []
        for _ in range(7):
            start = time.perf_counter()
            before = cg.Auditor().run(root)
            durations.append((time.perf_counter() - start) * 1000)
        public = base / "public"
        start = time.perf_counter()
        staging = cg.stage(root, public)
        stage_ms = (time.perf_counter() - start) * 1000
        after = cg.Auditor().run(public)
        retained_equal = all((public / path.name).read_bytes() == path.read_bytes() for path in root.iterdir() if (public / path.name).exists())
        receipt = base / "receipt.json"
        cg.manifest(public, receipt)
        intact = cg.verify(public, receipt)["matches"]
        (public / "app.js").write_text("changed")
        tamper_detected = not cg.verify(public, receipt)["matches"]
        valid = plistlib.dumps({"CFBundleIdentifier": "example.cloneguard.fixture"}, fmt=plistlib.FMT_BINARY)
        invalid_rejected = False
        try:
            plistlib.loads(valid + b"\0synthetic-unrecognized-trailer\0")
        except plistlib.InvalidFileException:
            invalid_rejected = True
        assertions = {"complete_before": before["complete"], "complete_after": after["complete"],
                      "high_findings_removed": not cg.fails(after, "high"), "retained_bytes_identical": retained_equal,
                      "original_map_retained_privately": (root / "app.js.map").exists(), "manifest_intact_passes": intact,
                      "tamper_detected": tamper_detected, "binary_plist_trailer_rejected": invalid_rejected}
        return {"schema": "cloneguard.benchmark.v1", "version": cg.VERSION, "generated_utc": cg.utc_now(),
                "environment": {"python": platform.python_version(), "system": platform.system(), "machine": platform.machine()},
                "fixture": "synthetic loose web release; 4 files; no customer code",
                "measured": {"audit_runs": 7, "audit_median_ms": round(statistics.median(durations), 3), "stage_ms": round(stage_ms, 3),
                             "before_bytes": before["bytes_screened"], "after_bytes": after["bytes_screened"],
                             "before_high_or_critical": sum(cg.RANK[x["severity"]] >= 2 for x in before["findings"]),
                             "after_high_or_critical": sum(cg.RANK[x["severity"]] >= 2 for x in after["findings"]),
                             "omitted_files": len(staging["omitted"])},
                "checks": assertions, "passed": all(assertions.values()),
                "unmeasured": ["LLM reconstruction success", "attacker token/cost multiplier", "signed mobile app compatibility", "production throughput"]}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out")
    args = parser.parse_args()
    result = run()
    if args.out:
        cg.write_json(args.out, result)
    print(json.dumps(result, indent=2))
    sys.exit(0 if result["passed"] else 1)
