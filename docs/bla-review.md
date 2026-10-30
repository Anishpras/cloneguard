# BLA source review and local reproduction

Reviewed on 30 October 2026. BLA: [`b2d643600774d62e562081129e55b13b0d9e8a80`](https://github.com/qybaihe/bla/tree/b2d643600774d62e562081129e55b13b0d9e8a80), package 1.5.1. REA: [`250dc81cd6b887f41a4078b65ca7a78628d1c541`](https://github.com/morluto/rea/tree/250dc81cd6b887f41a4078b65ca7a78628d1c541), package 6.8.0.

This is a source review and synthetic-fixture reproduction, not a comprehensive security audit. BLA is MIT licensed. CloneGuard is independently implemented and does not include BLA source.

## What BLA implements

The agent skill invokes a TypeScript CLI/MCP engine. The engine discovers release files, identifies formats, applies format-specific transformations and evaluates its output. JavaScript uses Babel transformations; other handlers add or change metadata, decoys or analyzer-budget payloads. Bundler adapters integrate with Vite/Rollup, Webpack/Rspack and esbuild.

BLA's main advantage over CloneGuard v0.1 is breadth of implemented artifact transformations and an in-tree harness invoking real REA modules. CloneGuard does not offer equivalent obfuscation, archive rewriting or budget-exhaustion transformations.

Relevant source: [skill](https://github.com/qybaihe/bla/blob/b2d643600774d62e562081129e55b13b0d9e8a80/.agents/skills/blind-llm-agents/SKILL.md), [protector](https://github.com/qybaihe/bla/blob/b2d643600774d62e562081129e55b13b0d9e8a80/src/engine/protector.ts), [bundler integrations](https://github.com/qybaihe/bla/blob/b2d643600774d62e562081129e55b13b0d9e8a80/src/bundler/index.ts).

## Claims and measurements need different labels

The [cost estimator](https://github.com/qybaihe/bla/blob/b2d643600774d62e562081129e55b13b0d9e8a80/src/core/token-estimator.ts) derives token, latency, price and outcome estimates from local analysis/simulation. These are not measured LLM sessions. The generic [verifier](https://github.com/qybaihe/bla/blob/b2d643600774d62e562081129e55b13b0d9e8a80/src/engine/verifier.ts) uses those derived signals and does not establish whole-program runtime equivalence.

BLA's README distinguishes its estimator showcase from its empirical REA harness; that distinction is useful. Its runtime-deception implementation also explicitly labels its client-side objects non-authoritative rather than a real debugger/secret boundary. CloneGuard preserves those distinctions in this comparison.

## Tests run locally

The first BLA run passed 218/219 tests; the packaging test failed because npm tried writing to a restricted default cache. Re-running the affected 14-test file with `npm_config_cache` set to the temporary cache passed all 14. No BLA code change was needed. This means every test passed across those runs; it is not a claim that the initial full run was green.

The 14-case BLA showcase completed with `functionalCheckPassed` reported true for its fixtures. Its token/cost multipliers remain estimates. Fixtures vary in the depth of their functional checks; this is not proof for arbitrary real applications.

The real-REA harness ran under temporary Node 24.22.1. PCAP was skipped because the harness could not find tshark. PTX completed without a budget hit. Several other probes hit actual analyzer limits. Flutter used the harness's faithful local projection, EVM approached an input cap, and WASM reported a projected representation limit without a configured Wabt executable. Those are narrower than complete tool-backed reconstruction failures. See the machine-readable comparison for exact statuses and byte growth.

## Apple compatibility observations

We compiled a synthetic Swift 6.2 pricing fixture in debug/release configurations on Apple silicon. Six input/output vectors matched, the optimized executable was 53,840 bytes, and its local toolchain signature passed strict `codesign` validation.

Applying BLA's `protectNativeBinary` at `bankrupt` intensity grew that fixture to 1,220,127 bytes. The protected executable still returned `8500` for the tested pricing input, but strict signature validation returned exit 1. This is evidence that post-sign transformation requires a deliberate re-signing/distribution workflow, not that all BLA/native packaging is broken. We did not test notarization, App Store distribution, or decompilation with Hopper/Ghidra.

BLA's [binary-plist handler](https://github.com/qybaihe/bla/blob/b2d643600774d62e562081129e55b13b0d9e8a80/src/shields/formats/apple-plist.ts) appends records to an existing binary plist. A 96-byte synthetic plist was valid in Apple `plutil` and Python `plistlib` before transformation. The resulting 8,134-byte plist failed both parsers. This directly contradicts the handler comment's assumption that the appended bytes are ignored by Apple's parser for this fixture. XML plist behavior is a different path and was not established by this test.

CloneGuard therefore leaves native binaries/plists unchanged, uses native build controls before signing and manifests the finalized output. It does not treat a metadata trailer as protection for Swift business logic.

## Reproduction

Use isolated temporary checkouts of the pinned revisions. Inspect third-party scripts before executing them. Locked dependency installs were performed with lifecycle scripts disabled; optional REA native packages were omitted. The REA source was compiled using its installed TypeScript 6 fallback, then BLA's harness imported those compiled modules.

```sh
# Inside the temporary BLA checkout, after its locked install:
node node_modules/typescript/bin/tsc -p tsconfig.build.json
npm_config_cache=/tmp/bla-npm-cache node node_modules/vitest/vitest.mjs run
node dist/cli.js benchmark --json

# Inside the temporary REA checkout, using its compatible Node runtime:
node node_modules/typescript6/bin/tsc -p tsconfig.build.json

# Back in this repo; outputs must not already exist:
python3 scripts/benchmark_swift.py --keep-dir /tmp/new-swift-fixture --out /tmp/new-swift-result.json
```

Create `plist-original.bin` with Python `plistlib.dumps` in binary format, using only `CFBundleIdentifier: example.cloneguard.fixture`, inside that fixture directory. Then run the optional comparison helper:

```sh
node scripts/compare_bla.mjs --bla-root /tmp/pinned-bla --rea-root /tmp/pinned-rea \
  --swift-dir /tmp/new-swift-fixture --run-rea --out /tmp/new-comparison.json
```

The helper deliberately executes the supplied third-party BLA implementation and its harness. It does not download tools, access accounts, attach to private processes or call a model. Use synthetic fixtures and temporary checkouts, not signed customer releases. Native tools absent on a platform return an unrun/null result rather than a pass.

These observations say nothing about who first conceived the product idea, and cannot establish legal ownership or infringement.
