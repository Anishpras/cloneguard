---
name: cloneguard
description: Reduce software cloning exposure by auditing releases, applying platform-native hardening, and verifying artifact provenance. Use for anti-cloning or reverse-engineering defense across web/API, Swift/Apple, Android, Electron, native, and managed applications.
---

# CloneGuard

Protect software the user owns or is authorized to assess. Work toward measurable reduction in exposed implementation details and unauthorized API access. A publicly observable workflow remains observable, and distributed code remains inspectable.

## Start with the distribution surface

Locate project instructions, manifests, release configuration, and the artifacts customers receive. Identify valuable logic, online/offline requirements, public interfaces, and signing order. In a mixed repo, route each component separately; a Swift frontend and a Go API have different trust boundaries.

Run the bundled helper relative to **this skill's directory**, not the inspected repo:

```sh
python3 <skill-dir>/scripts/cloneguard.py plan <project> --scope source
python3 <skill-dir>/scripts/cloneguard.py audit <release-dir> --scope release
```

The scanner only reads local paths. It never runs build scripts, executes binaries, follows symlinks, extracts archives, or uploads code. Exit codes: `0` (screening completed below threshold), `1` (findings or manifest mismatch), `2` (error/incomplete). Source mode lists excluded caches; release mode has no such exclusions. Report skipped surfaces explicitly. `complete` describes bounded byte screening, not a comprehensive security review.

## Choose platform guidance

Read only the references that match the project:

| Surface | Reference | Preferred controls |
| --- | --- | --- |
| Swift, SwiftUI, Objective-C, iOS/macOS | [Apple/Swift](references/apple-swift.md) | Release settings, private dSYMs, signing, server-verified attestation |
| Browser, Node, API, WASM | [Web/API](references/web-api.md) | Private maps, server trust boundaries, scoped access and quotas |
| Android, JVM, Flutter, React Native | [Android/JVM](references/android-jvm.md) | R8/keep rules, private mapping files, integrity verification |
| Electron, Tauri, Rust, Go, C/C++, .NET, Python | [Native/desktop](references/native-desktop.md) | Native packaging, private symbols, signing, documented runtime boundaries |
| Markers, manifests, suspected copying | [Evidence](references/evidence.md) | Hashes, HMAC receipts, controlled observations, competing explanations |
| Legal or product-claim questions | [Claims](references/claims.md) | Separate implemented features, experiments, and legal judgments |

For other stacks, trace build, packaging, signing and server authorization boundaries directly. Generic byte screening and manifests work without language support; semantic hardening requires the actual toolchain. Do not invent a compiler adapter.

## Apply controls and preserve behavior

Make targeted source/build changes with native tools. Keep exports, reflection, serializers, FFI/JNI/Obj-C selectors, and customer-required automation working. Retain private crash symbols and rollback artifacts. Keep credentials and proprietary authorization decisions off the client.

For a loose web release, preview and stage a separate public tree:

```sh
python3 <skill-dir>/scripts/cloneguard.py stage <dist> --out <new-public-dir> --dry-run
python3 <skill-dir>/scripts/cloneguard.py stage <dist> --out <new-public-dir>
```

This omits known private maps, symbols, environment/key files and VCS metadata. Retained files are copied byte-for-byte; originals remain. It rejects containers, native executables, source files, signed bundles, unresolved high findings, and incomplete scans. It does not remove inline maps or rewrite sourcemap directives: fix bundler settings and rebuild.

For native apps, use their packaging flow; never append bytes to signed executables or plists. Transform before signing, verify the signed export, then manifest the final artifact outside the release tree:

```sh
python3 <skill-dir>/scripts/cloneguard.py manifest <release> --out <private-receipt.json>
python3 <skill-dir>/scripts/cloneguard.py verify <release> --manifest <private-receipt.json>
```

Optional `keygen` and `--key-file` add shared-key HMAC authentication. Keep keys outside the project and release. Plain hashes detect changes relative to a trusted receipt; they do not authenticate its author. Neither option independently timestamps the release.

## Validate the result

Run existing tests and relevant release checks. For native changes, verify signatures, install/launch, exported symbols, crash symbolication and target architectures. For browser changes, check accessibility, screenshots, hydration, startup size/time and supported customer automation. For backend changes, test unauthorized/cross-tenant/replay/expired requests and legitimate fallback behavior.

Hash equality demonstrates retained-byte equality, not runtime equivalence of a transformed app. A format parser failing demonstrates a parser limit, not universal resistance to AI cloning. Mark unavailable native tools, devices or agent-harness checks unrun.

For reconstruction benchmarks, use synthetic or authorized fixtures, pinned tools/models, fixed task and budgets, repeated trials, behavior tests, measured tokens/time/bytes and untreated controls. Separate build overhead from clone success. Never derive a dollar multiplier from marker counts.

## Finish

Deliver observed findings with file locations, implemented changes, passing checks, remaining exposure and rollback instructions. Keep source, keys, customer evidence, and unpublished marker registries out of public reports. Do not claim an infringement verdict from marker matches, an automatic DMCA violation, an enforcement warranty, guaranteed hallucination, or an unreadable client.

User-requested adversarial experiments belong in an isolated opt-in harness with resource and compatibility limits; they are not baseline access controls. Preserve semantic HTML and accessibility rather than concealing instructions in ARIA or user-visible data.
