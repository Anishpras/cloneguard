# Native, desktop and managed adapter

Find the build/export/package/sign/update flow. Keep private PDB/DWARF/dSYM/mapping data for crash support and minimize public debug data using native compiler/linker settings. Preserve exports, FFI, reflection and plugin contracts. Distributed binaries remain inspectable; obfuscation is a cost control, not authorization.

Manifest finalized artifacts unchanged. Signing checks/runtime equivalence require native tools; hashes establish neither. Run official platform verification on the actual packaging output.

## Electron

Inspect main/preload/renderer boundaries, context isolation, sandboxing, node integration and IPC sender/argument authorization. Use supported packaging-time fuses **before signing**. Review RunAsNode, NODE_OPTIONS, CLI inspect arguments and the combination of embedded ASAR integrity with onlyLoadAppFromAsar for the installed Electron/platform versions. Preserve required workflows.

ASAR is an archive, not encryption. CloneGuard marks its contents unassessed: inspect with installed Electron tools in an isolated copy. It does not append oversized headers or counterfeit fuse sentinels.

## Tauri / Rust / C / C++

Review frontend maps and native command capabilities separately. Use optimized release profiles. Rust strip/debug profile settings and C/C++ visibility/linker settings reduce debug exposure; preserve dynamic linking symbols and private crash diagnostics. Custom LLVM obfuscation requires a maintained toolchain and compatibility tests.

## Go

Use supported release flags compatible with diagnostics. Go `-s` omits symbol/debug data and implies `-w`; verify current behavior. `-trimpath` removes recorded build paths. Neither removes all runtime metadata nor conceals business logic. Do not patch buildinfo/pclntab just to break an analyzer.

## .NET

Inspect publishing settings, PDBs, reflection, serializers, trimming warnings and plugin ABI. Trimming/NativeAOT can reduce metadata in compatible apps but are not universal obfuscators. Resolve warnings and test published output. Do not rename metadata after strong-name/Authenticode signing.

## Python

`.pyc`, zipapps, frozen executables and compiled extensions remain inspectable. Remove accidental credentials; move proprietary online decisions to a service where feasible. C extensions require a real build/tests and do not make embedded shared keys secret. Sign updates and use authenticated entitlements instead of trusting the client.

Sources: [Electron fuses](https://www.electronjs.org/docs/latest/tutorial/fuses), [Rust profiles](https://doc.rust-lang.org/cargo/reference/profiles.html), [Go linker](https://pkg.go.dev/cmd/link).
