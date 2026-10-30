# Apple / Swift adapter

Find `Package.swift`, `.xcodeproj/project.pbxproj`, workspaces, `.xcconfig`, entitlements, bridging headers and distribution scripts. Distinguish Swift Package release builds from Xcode archives. An `.xcarchive` contains private symbols and is not the customer-facing export.

Inspect resolved settings for the scheme/configuration/SDK with `xcodebuild -showBuildSettings`. A file setting may be overridden. Record signing identity, platform minimums, architectures and application/library distribution.

## Build controls

- Use the existing optimized Release profile. Review `SWIFT_OPTIMIZATION_LEVEL`, `SWIFT_COMPILATION_MODE`, `ENABLE_TESTABILITY`, `DEAD_CODE_STRIPPING`, `COPY_PHASE_STRIP`, `STRIP_INSTALLED_PRODUCT`, `DEPLOYMENT_POSTPROCESSING` and `DEBUG_INFORMATION_FORMAT` against the product and current Xcode documentation. Avoid blind global replacements.
- Keep dSYMs for private symbolication. Remove them from public downloads, not internal crash tooling. Match binary/dSYM UUIDs with `dwarfdump --uuid` where applicable.
- Review release `get-task-allow`, hardened runtime and entitlements in the signed product. Preserve required capabilities. Simulator/developer builds do not test distribution controls.
- Preserve ABI, library-evolution `.swiftinterface` contracts, Codable keys, reflection, `@objc` selectors, KVC/KVO, storyboard/nib references and plugin identifiers. Renaming requires compiler-aware transformation and regression tests; text replacement is unsuitable.
- Review compiled strings for credentials. Keychain protects stored credentials; it does not make an embedded application-wide secret confidential from someone controlling the client.

## Backend boundary

Authorize valuable online operations on the server. When supported by the deployment targets, App Attest provides an integrity signal. Check `DCAppAttestService.isSupported`; implement documented server validation of attestation/assertions, challenge, app identity, signature and counters. Bind assertions to the intended request; consume challenges and track counters transactionally. A client boolean is not attestation validation.

Define reinstall/key-rotation handling and a monitored fallback for unsupported devices or temporary failures. Attestation does not prevent screenshots, user-authorized automation, or copying observable behavior. Offline entitlements still run on an inspectable machine.

## Signing order and validation

Source/build controls → native build/strip → package → sign → notarize/export as applicable → verify final artifact → CloneGuard manifest.

Read-only checks on a macOS application can include:

```sh
codesign --verify --deep --strict --verbose=2 /path/Example.app
codesign -d --entitlements :- /path/Example.app
spctl --assess --type execute --verbose=2 /path/Example.app
```

These checks have different meanings; ad-hoc signing does not prove notarization or App Store eligibility. Do not re-sign with an invented identity. Real signing, devices and store review require the customer's distribution environment.

Manifest symlink-free final packages (`.ipa`, `.pkg`, `.dmg`, ZIP or actual executable) if bundle symlinks make directory inventory incomplete. CloneGuard does not follow framework symlinks, strip Mach-O code, alter bplists or patch Swift metadata.

Sources: [Xcode settings](https://developer.apple.com/documentation/xcode/build-settings-reference), [App integrity](https://developer.apple.com/documentation/devicecheck/establishing-your-app-s-integrity), [Server validation](https://developer.apple.com/documentation/devicecheck/validating-apps-that-connect-to-your-server). Verify SDK availability per target.
