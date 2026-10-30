# Android, JVM, Flutter and React Native adapter

## Android / Kotlin / Java

Inspect Gradle modules, release variants, manifests, generated code and keep rules. Enable R8/resource shrinking through the project's supported Android Gradle Plugin configuration. Add narrow rules for reflection, serialization, JNI, SDK callbacks and annotations rather than keeping the whole app. Keep mapping/seeds/crash resources private and retain them for diagnostics.

Inspect the merged release manifest for debuggability, exported components, permissions and backup behavior. Test optimized releases on target devices, including dynamically loaded code and startup-sensitive SDKs. Transform before signing; do not patch signed DEX/APK bytes. Verify the final APK/AAB using native tooling.

Play Integrity is a server-validated risk signal: follow current request binding, freshness, backend verification and failure handling. Define supported distribution channels and fallback; not every customer uses Google Play. It does not hide observable behavior.

## Flutter

Use supported release obfuscation/private split-debug-info where appropriate, retaining artifacts for symbolication. Name obfuscation is not secret storage. Native plugin/JNI and reflection boundaries still require Android/Apple checks. Do not patch snapshots or append metadata after signing.

## React Native

Inspect JavaScript/Hermes bundles, sourcemaps and native shells separately. Keep Metro/Hermes maps private; native R8/Apple settings do not remove JS exposure. Preserve bridge registration and serialized keys. Rebuild and test both native targets after shared-code changes.

## JVM servers/libraries

Distributed JARs and bytecode remain inspectable. Obfuscation requires keep rules for frameworks, reflection and public APIs. Keep server-only code off customer machines when the deployment permits it. Public API renaming can break downstream consumers; ABI compatibility is a separate check.

CloneGuard screens bounded ZIP members inside APK/AAB/JAR/IPA inputs without extraction. This does not verify signatures, DEX semantics, device integrity or store acceptance.

Sources: [R8 optimization](https://developer.android.com/build/shrink-code), [Play Integrity](https://developer.android.com/google/play/integrity/overview).
