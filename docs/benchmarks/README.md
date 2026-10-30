# Benchmark methodology

`python3 scripts/benchmark.py --out /new/path/result.json` creates isolated synthetic assets, runs seven screening iterations, stages a separate release, compares retained bytes, verifies a receipt, modifies a file and checks rejection. It also checks that appending a synthetic trailer invalidates a binary plist for Python's plist parser. Wall times are local observations, not a production throughput claim.

Use the machine-readable result for the exact environment and counts. Each run uses fresh temporary data and never includes customer source. Existing output files are not overwritten. The benchmark does not call a model or measure reconstruction resistance.

## Native trial

`python3 scripts/benchmark_swift.py --out /new/path/swift.json` compiles a synthetic Swift program with debug/release profiles when the Apple toolchain is available. It compares outputs on fixed input vectors, records sizes, seals the optimized executable and checks a modification is detected. Optional signature checks are reported separately. This is a fixture compatibility check, not App Store/device coverage or obfuscation efficacy.

## Reconstruction trial requirements

For a real anti-cloning claim, record:

1. Exact original/control/protected hashes and publicly shareable fixture source.
2. Pinned analyzer, OS, compiler, model, prompt, tools and resource budgets.
3. A fixed reconstruction task and behavior tests hidden from the reconstructing agent.
4. Multiple trials, untreated controls, failures, completed cases and confidence intervals.
5. Actual input/output tokens, model billing basis, elapsed time and tool failures.
6. Release byte/startup/runtime overhead plus signature, accessibility and behavior compatibility.
7. Alternative analysis paths, including simple extraction that bypasses the targeted analyzer.

A parser refusing an oversized input is one outcome for one analyzer. It does not establish that an agent cannot recover behavior through screenshots, runtime tracing, a different parser or a small patch to the analyzer. Do not equate heuristic cost estimates with observed bills.
