# Evidence and canaries

`manifest` records SHA-256, size, relative path and executable bit for regular files. `verify` detects additions, removals and changes. It excludes empty directories, ownership, extended attributes, ACLs and independent creation time. Unix executable bits may not survive Windows transfer; this is a mismatch, not normalized away. Native signatures require platform checks.

## Optional shared-key authentication

```sh
python3 <skill-dir>/scripts/cloneguard.py keygen --out /private/location/receipt.key
python3 <skill-dir>/scripts/cloneguard.py manifest <release> --out /private/location/release.json --key-file /private/location/receipt.key
python3 <skill-dir>/scripts/cloneguard.py verify <release> --manifest /private/location/release.json --key-file /private/location/receipt.key
```

HMAC is not a public signature: any key holder can create a receipt. Use organizational signing/transparency/timestamping when third parties must independently verify origin/time. A receipt created today cannot prove an idea existed before another product's release.

## Harmless markers

```sh
python3 <skill-dir>/scripts/cloneguard.py canary --app example --release build-42 --key-file /private/location/receipt.key --out /private/location/marker.json
python3 <skill-dir>/scripts/cloneguard.py find-canary <authorized-local-artifact> --marker /private/location/marker.json
```

The marker is a deterministic, domain-separated HMAC of app/release labels. It grants no access. Integrate explicitly as a harmless resource **before** signing, then check the final build retained it. Screening can miss transformed/encoded/compressed/removed markers. Zero matches in an incomplete scan is inconclusive. A match proves token presence, not who copied it or whether AI was involved.

Do not alter rounding, timing, money, entitlements or customer behavior to create a trap. Behavioral variants require a controlled non-user-facing experiment, competing implementations, false-match measurements and statistical review.

Keep exact specimen hashes, release history, private marker registry, logs, collection times/method and competing explanations. UI overlap, feature similarity and public-marker matches alone do not prove infringement. Do not probe private competitor endpoints or bypass authentication. Automated allegations/takedowns are outside the helper's capability.
